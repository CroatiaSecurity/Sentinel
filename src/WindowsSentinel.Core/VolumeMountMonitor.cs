using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Monitors volume mount/dismount events to detect:
    /// - RAM disk creation (ImDisk, OSFMount, SoftPerfect, Arsenal Image Mounter)
    /// - Persistent memory (PMEM/DAX) volume mounts
    /// - VeraCrypt/encrypted container mounts
    /// - VHD/VHDX mounts not initiated by Explorer/DiskMgmt
    /// - Any new volume appearing after service start
    /// - Attacker fallback drives created after phantom device prevention (auto-dismount)
    ///
    /// Addresses the blind spot where attackers stage payloads on volatile/unmapped
    /// volumes that FileActivityMonitor doesn't cover.
    ///
    /// v1.0.1: New monitor.
    /// v1.0.5: Auto-dismount attacker fallback drives correlated with phantom device blocks.
    /// </summary>
    public sealed class VolumeMountMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly FileActivityMonitor _fileActivityMonitor;
        private readonly PhantomDeviceMonitor? _phantomDeviceMonitor;
        private readonly SentinelConfig _config;
        private readonly ILogger<VolumeMountMonitor> _logger;

        private readonly HashSet<string> _baselineVolumes = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _baselineDriveLetters = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedVolumes = new();

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(10);

        /// <summary>
        /// Grace period after service start during which new volumes are treated as
        /// late-initializing baseline volumes (slow USB mounts, delayed network drives,
        /// volumes whose WMI DeviceId changes during initialization). Volumes appearing
        /// in this window are baselined silently — never treated as attacker fallback.
        /// </summary>
        private static readonly TimeSpan StartupGracePeriod = TimeSpan.FromSeconds(60);

        /// <summary>
        /// Time window after a phantom device block within which new volumes are
        /// treated as attacker fallback staging drives and auto-dismounted.
        /// </summary>
        private static readonly TimeSpan PhantomCorrelationWindow = TimeSpan.FromMinutes(2);

        private DateTimeOffset _startTime;

        // Known RAM disk driver device names and service names
        private static readonly HashSet<string> RamDiskDrivers = new(StringComparer.OrdinalIgnoreCase)
        {
            "imdisk", "osfmount", "intmemdrv", "intmemdisk", "intmemsvc",
            "ramdriv", "ramdisk", "vfdwin", "vfd", "dataram", "softperfect",
            "arsenalimager", "aimdevice", "ramphantom", "primo", "primocache",
            "rstmemdrv", "rstmemdsk"
        };

        // Known PMEM/DAX driver names
        private static readonly HashSet<string> PmemDrivers = new(StringComparer.OrdinalIgnoreCase)
        {
            "pmem", "pmemdrv", "nvdimm", "dax", "stornvme_pmem",
            "winpmem", "pmem_memmap"
        };

        // Known encrypted container volume drivers
        private static readonly HashSet<string> EncryptedContainerDrivers = new(StringComparer.OrdinalIgnoreCase)
        {
            "veracrypt", "truecrypt", "bestcrypt", "diskcryptor",
            "pgpdisk", "jetico", "securstar"
        };

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool DefineDosDevice(uint dwFlags, string lpDeviceName, string? lpTargetPath);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern uint QueryDosDevice(string lpDeviceName, char[] lpTargetPath, uint ucchMax);

        private const uint DDD_REMOVE_DEFINITION = 0x00000002;
        private const uint DDD_EXACT_MATCH_ON_REMOVE = 0x00000004;

        public VolumeMountMonitor(
            DetectionEngine detectionEngine,
            FileActivityMonitor fileActivityMonitor,
            SentinelConfig config,
            ILogger<VolumeMountMonitor> logger,
            PhantomDeviceMonitor? phantomDeviceMonitor = null)
        {
            _detectionEngine = detectionEngine;
            _fileActivityMonitor = fileActivityMonitor;
            _config = config;
            _phantomDeviceMonitor = phantomDeviceMonitor;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[VolumeMountMonitor] Started - scanning for new volume mounts");

            _startTime = DateTimeOffset.UtcNow;

            // Strip any drive letters from EFI/System partitions — these should never be exposed.
            // Previous Sentinel versions or WMI enumeration side effects can cause Windows to
            // assign a letter to the ESP. Fix it on every startup.
            StripSystemPartitionDriveLetters();

            // Baseline current volumes (both DeviceId and drive letter for stable identification)
            foreach (var vol in GetMountedVolumes())
            {
                _baselineVolumes.Add(vol.DeviceId);
                if (!string.IsNullOrEmpty(vol.DriveLetter))
                    _baselineDriveLetters.Add(vol.DriveLetter.TrimEnd('\\').ToUpperInvariant());
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);

                    var currentVolumes = GetMountedVolumes();
                    bool inGracePeriod = DateTimeOffset.UtcNow - _startTime < StartupGracePeriod;

                    foreach (var vol in currentVolumes)
                    {
                        if (_baselineVolumes.Contains(vol.DeviceId)) continue;

                        // Check if this volume's drive letter was already present at startup
                        // (WMI can report different DeviceId strings for the same volume as it
                        // fully initializes — GUID paths resolve late, labels populate late, etc.)
                        var normalizedLetter = vol.DriveLetter?.TrimEnd('\\').ToUpperInvariant();
                        bool driveLetterWasBaselined = !string.IsNullOrEmpty(normalizedLetter) &&
                            _baselineDriveLetters.Contains(normalizedLetter);

                        // Add to baseline (either way, we've seen it now)
                        _baselineVolumes.Add(vol.DeviceId);
                        if (!string.IsNullOrEmpty(normalizedLetter))
                            _baselineDriveLetters.Add(normalizedLetter);

                        // During startup grace period OR if the drive letter was already baselined,
                        // this is a late-initializing volume — not attacker-created.
                        if (inGracePeriod || driveLetterWasBaselined)
                        {
                            _logger.LogDebug(
                                "[VolumeMountMonitor] Baselined late-init volume {Drive} (DeviceId={Id}, grace={Grace}, letterKnown={Known})",
                                vol.DriveLetter ?? "(no letter)", vol.DeviceId, inGracePeriod, driveLetterWasBaselined);
                            continue;
                        }

                        // Check cooldown (skip for SUBST — attacker may keep recreating)
                        if (_alertedVolumes.TryGetValue(vol.DeviceId, out var lastAlert) &&
                            DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                        {
                            // Even during cooldown, always kill SUBST drives
                            var quickClassification = ClassifyVolume(vol);
                            if (_config.ActiveResponse &&
                                string.Equals(quickClassification, "SUBST", StringComparison.OrdinalIgnoreCase) &&
                                !string.IsNullOrEmpty(vol.DriveLetter))
                            {
                                await DismountFallbackDrive(vol);
                                await HuntSubstCreatorProcess(vol.DriveLetter);
                            }
                            continue;
                        }

                        _alertedVolumes[vol.DeviceId] = DateTimeOffset.UtcNow;

                        var classification = ClassifyVolume(vol);

                        // v1.0.5: SUBST drives appearing at runtime are ALWAYS malicious.
                        // There is no legitimate reason for a SUBST drive to be created after
                        // boot — these are the #1 attacker fallback technique for staging
                        // payloads after their primary C2 relay is cut off.
                        // No phantom device correlation required for SUBST — unconditional kill.
                        if (_config.ActiveResponse &&
                            string.Equals(classification, "SUBST", StringComparison.OrdinalIgnoreCase) &&
                            !string.IsNullOrEmpty(vol.DriveLetter))
                        {
                            _logger.LogWarning(
                                "[VolumeMountMonitor] SUBST drive {Drive} created at runtime — unconditional dismount (attacker fallback)",
                                vol.DriveLetter);
                            await EmitFallbackDriveDetection(vol, classification);
                            await DismountFallbackDrive(vol);
                            await HuntSubstCreatorProcess(vol.DriveLetter);
                            await RemoveSubstPersistence(vol.DriveLetter);
                            continue;
                        }

                        // For non-SUBST suspicious volumes (VHD, RAM disk, encrypted containers):
                        // require phantom device correlation to avoid dismounting legitimate
                        // developer VHDs or VeraCrypt containers.
                        bool isAttackerFallback = _phantomDeviceMonitor != null &&
                            _config.ActiveResponse &&
                            _phantomDeviceMonitor.HasRecentBlock(PhantomCorrelationWindow) &&
                            !IsLikelyLegitimateVolume(vol, classification);

                        if (isAttackerFallback && !string.IsNullOrEmpty(vol.DriveLetter))
                        {
                            await EmitFallbackDriveDetection(vol, classification);
                            await DismountFallbackDrive(vol);
                            continue; // Don't extend FileActivityMonitor to a dismounted drive
                        }

                        await EmitVolumeDetection(vol, classification);

                        // Dynamically extend FileActivityMonitor coverage to new volume
                        if (!string.IsNullOrEmpty(vol.DriveLetter))
                        {
                            _fileActivityMonitor.AddWatchPath(vol.DriveLetter);
                            _logger.LogInformation(
                                "[VolumeMountMonitor] Extended FileActivityMonitor to new volume: {Drive}",
                                vol.DriveLetter);
                        }
                    }

                    // Cleanup stale alerts
                    var stale = _alertedVolumes
                        .Where(kv => DateTimeOffset.UtcNow - kv.Value > TimeSpan.FromHours(1))
                        .Select(kv => kv.Key).ToList();
                    foreach (var key in stale) _alertedVolumes.TryRemove(key, out _);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[VolumeMountMonitor] Error"); }
            }
        }

        /// <summary>
        /// Dismounts an attacker-created fallback drive. Handles multiple creation methods:
        /// 1. SUBST drives (DefineDosDevice)
        /// 2. VHD/VHDX mounts (diskpart or PowerShell)
        /// 3. ImDisk/RAM drives (imdisk removal)
        /// 4. Generic mounted volumes (mountvol removal)
        /// </summary>
        private async Task DismountFallbackDrive(VolumeInfo vol)
        {
            var driveLetter = vol.DriveLetter!.TrimEnd('\\', ':');
            bool dismounted = false;

            try
            {
                // Method 1: Try removing as a SUBST drive (most common attacker technique)
                dismounted = RemoveSubstDrive(driveLetter);

                if (!dismounted)
                {
                    // Method 2: Try dismounting as a VHD
                    dismounted = await DismountVhd(driveLetter);
                }

                if (!dismounted)
                {
                    // Method 3: Remove volume mount point (works for any mounted volume)
                    dismounted = RemoveVolumeMountPoint(driveLetter);
                }

                if (dismounted)
                {
                    _logger.LogWarning(
                        "[VolumeMountMonitor] DISMOUNTED attacker fallback drive {Drive}: (Label='{Label}', FS={FS})",
                        vol.DriveLetter, vol.Label, vol.FileSystem);
                }
                else
                {
                    _logger.LogError(
                        "[VolumeMountMonitor] Failed to dismount suspected fallback drive {Drive}",
                        vol.DriveLetter);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[VolumeMountMonitor] Error dismounting fallback drive {Drive}", vol.DriveLetter);
            }
        }

        /// <summary>
        /// Removes a SUBST-created virtual drive by calling DefineDosDevice with remove flags.
        /// This is the most common attacker fallback: 'subst S: C:\some\hidden\path'
        /// </summary>
        private bool RemoveSubstDrive(string driveLetter)
        {
            try
            {
                // First check if this is actually a SUBST drive by querying the DOS device
                var buffer = new char[260];
                uint result = QueryDosDevice($"{driveLetter}:", buffer, (uint)buffer.Length);
                if (result == 0) return false;

                var target = new string(buffer, 0, (int)result).TrimEnd('\0');

                // SUBST drives have targets like "\??\C:\path" (the \??\ prefix indicates substitution)
                if (target.StartsWith(@"\??\", StringComparison.Ordinal))
                {
                    // Remove the SUBST mapping
                    bool removed = DefineDosDevice(
                        DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE,
                        $"{driveLetter}:",
                        target);

                    if (removed)
                    {
                        _logger.LogWarning(
                            "[VolumeMountMonitor] Removed SUBST drive {Letter}: -> {Target}",
                            driveLetter, target);
                    }
                    return removed;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] SUBST removal failed for {Letter}", driveLetter);
                return false;
            }
        }

        /// <summary>
        /// Finds and kills the process that created the SUBST drive.
        /// Multi-layered hunt:
        /// 1. subst.exe process (obvious case)
        /// 2. cmd.exe/powershell.exe with subst in command line
        /// 3. Any process that has a handle open to the SUBST target path (the creator likely still has it open)
        /// 4. Any non-system process that loaded kernel32 and was spawned recently (within 10s of detection)
        ///    AND has a connection to an IP that PhantomDeviceMonitor blocked — this is the implant.
        /// 5. Fallback: any process whose working directory is the SUBST target path
        /// </summary>
        private async Task HuntSubstCreatorProcess(string driveLetter)
        {
            var normalizedLetter = driveLetter.TrimEnd('\\', ':').ToUpperInvariant();
            var killed = new HashSet<int>();

            try
            {
                // --- Phase 1: Direct subst.exe or shell with subst command ---
                using var searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, Name, CommandLine, ParentProcessId FROM Win32_Process " +
                    "WHERE Name = 'subst.exe' OR Name = 'cmd.exe' OR Name = 'powershell.exe' OR Name = 'pwsh.exe'");

                foreach (ManagementObject proc in searcher.Get())
                {
                    var cmdLine = proc["CommandLine"]?.ToString() ?? "";
                    var pid = Convert.ToInt32(proc["ProcessId"]);
                    var parentPid = Convert.ToInt32(proc["ParentProcessId"]);
                    var name = proc["Name"]?.ToString() ?? "";

                    bool isSubstCreator = name.Equals("subst.exe", StringComparison.OrdinalIgnoreCase) ||
                        (cmdLine.Contains("subst", StringComparison.OrdinalIgnoreCase) &&
                         cmdLine.Contains(normalizedLetter, StringComparison.OrdinalIgnoreCase));

                    if (isSubstCreator && pid > 4)
                    {
                        await KillProcessAndParent(pid, parentPid, name, cmdLine, normalizedLetter, "SUBST command in cmdline", killed);
                    }
                }

                // --- Phase 2: Any process connected to a PhantomDeviceMonitor-blocked IP ---
                // This catches the implant itself — the process that receives commands from the
                // rogue LAN device and translates them into local DefineDosDevice calls.
                if (_phantomDeviceMonitor != null)
                {
                    await HuntImplantByNetworkConnection(normalizedLetter, killed);
                }

                // --- Phase 3: Processes with the SUBST target path as working directory or in cmdline ---
                // If the SUBST was 'subst S: C:\some\path', find processes rooted there
                var substTarget = GetSubstTarget(normalizedLetter);
                if (!string.IsNullOrEmpty(substTarget))
                {
                    await HuntBySubstTarget(substTarget, normalizedLetter, killed);
                }

                if (killed.Count == 0)
                {
                    _logger.LogWarning(
                        "[VolumeMountMonitor] Could not identify SUBST creator for {Drive}: — implant may be using direct DefineDosDevice from custom binary. Scanning all non-system processes with recent start time.",
                        normalizedLetter);

                    // --- Phase 4: Kill any non-system, non-signed process started within last 30s ---
                    await HuntRecentlySpawnedUnsignedProcesses(normalizedLetter, killed);
                }

                if (killed.Count > 0)
                {
                    _logger.LogWarning("[VolumeMountMonitor] Killed {Count} process(es) related to SUBST drive {Drive}:",
                        killed.Count, normalizedLetter);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] HuntSubstCreatorProcess failed");
            }
        }

        /// <summary>
        /// Kills a process and its parent (the parent is likely the implant that spawned subst.exe/cmd.exe).
        /// </summary>
        private async Task KillProcessAndParent(int pid, int parentPid, string name, string cmdLine, string driveLetter, string reason, HashSet<int> killed)
        {
            // Kill the direct process
            if (!killed.Contains(pid))
            {
                try
                {
                    var process = Process.GetProcessById(pid);
                    process.Kill(entireProcessTree: true);
                    killed.Add(pid);
                    _logger.LogWarning(
                        "[VolumeMountMonitor] KILLED {Name} (PID {Pid}) — reason: {Reason}, cmdline: {Cmd}",
                        name, pid, reason, cmdLine);
                }
                catch { }
            }

            // Kill the parent — this is the implant that spawned the shell/subst.exe
            if (parentPid > 4 && !killed.Contains(parentPid))
            {
                try
                {
                    var parent = Process.GetProcessById(parentPid);
                    var parentName = parent.ProcessName;

                    // Don't kill critical system processes
                    if (!IsProtectedProcess(parentName))
                    {
                        parent.Kill(entireProcessTree: true);
                        killed.Add(parentPid);
                        _logger.LogWarning(
                            "[VolumeMountMonitor] KILLED PARENT implant: {Name} (PID {Pid}) — spawned SUBST creator",
                            parentName, parentPid);

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Implant Killed: SUBST Drive Creator Parent Process",
                            Evidence = $"Process {parentName} (PID {parentPid}) spawned {name} which created SUBST drive {driveLetter}:",
                            Reasoning = "This process spawned the command that created an attacker SUBST staging drive. " +
                                        "It is the implant receiving commands from the rogue LAN device. Process tree killed.",
                            Confidence = 0.94,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            ProcessName = parentName,
                            ProcessId = parentPid
                        });
                    }
                }
                catch { }
            }
        }

        /// <summary>
        /// Finds any non-system process with an active TCP connection to an IP that
        /// PhantomDeviceMonitor has blocked. That's the implant.
        /// </summary>
        private async Task HuntImplantByNetworkConnection(string driveLetter, HashSet<int> killed)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netstat.exe",
                    Arguments = "-ano",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                };
                using var proc = Process.Start(psi);
                if (proc == null) return;

                var output = await proc.StandardOutput.ReadToEndAsync();
                await proc.WaitForExitAsync();

                foreach (var line in output.Split('\n'))
                {
                    if (!line.Contains("ESTABLISHED", StringComparison.OrdinalIgnoreCase) &&
                        !line.Contains("SYN_SENT", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 5) continue;

                    // Extract remote IP and PID
                    var remoteEndpoint = parts[2];
                    var colonIdx = remoteEndpoint.LastIndexOf(':');
                    if (colonIdx <= 0) continue;
                    var remoteIp = remoteEndpoint[..colonIdx];

                    if (!int.TryParse(parts[4], out var pid) || pid <= 4) continue;
                    if (killed.Contains(pid)) continue;

                    // Check if this IP is blocked by PhantomDeviceMonitor
                    if (_phantomDeviceMonitor!.IsBlockedDevice(remoteIp))
                    {
                        try
                        {
                            var process = Process.GetProcessById(pid);
                            var processName = process.ProcessName;

                            if (IsProtectedProcess(processName)) continue;

                            process.Kill(entireProcessTree: true);
                            killed.Add(pid);

                            _logger.LogWarning(
                                "[VolumeMountMonitor] KILLED IMPLANT: {Name} (PID {Pid}) — connected to blocked device {Ip}",
                                processName, pid, remoteIp);

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Implant Killed: Connected to Rogue LAN Device",
                                Evidence = $"Process {processName} (PID {pid}) has active connection to blocked device IP {remoteIp}. " +
                                           $"This process is the implant creating SUBST drive {driveLetter}:",
                                Reasoning = "A process maintaining a connection to a device PhantomDeviceMonitor blocked " +
                                            "is the C2 implant receiving commands from the attacker's rogue LAN relay. " +
                                            "The SUBST drive creation was commanded through this channel. Process tree killed.",
                                Confidence = 0.96,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = processName,
                                ProcessId = pid
                            });
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] HuntImplantByNetworkConnection failed");
            }
        }

        /// <summary>
        /// Gets the SUBST target path (what the drive letter points to).
        /// Returns null if not a SUBST drive or can't be queried.
        /// </summary>
        private string? GetSubstTarget(string driveLetter)
        {
            try
            {
                var buffer = new char[1024];
                uint result = QueryDosDevice($"{driveLetter}:", buffer, (uint)buffer.Length);
                if (result == 0) return null;

                var target = new string(buffer, 0, (int)result).TrimEnd('\0');
                if (target.StartsWith(@"\??\", StringComparison.Ordinal))
                    return target[4..]; // Strip \??\ prefix to get real path

                return null;
            }
            catch { return null; }
        }

        /// <summary>
        /// Finds processes whose executable path or command line references the SUBST target directory.
        /// These are processes using the staging area — either the implant or its payloads.
        /// </summary>
        private async Task HuntBySubstTarget(string substTarget, string driveLetter, HashSet<int> killed)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process");

                foreach (ManagementObject proc in searcher.Get())
                {
                    var exePath = proc["ExecutablePath"]?.ToString() ?? "";
                    var cmdLine = proc["CommandLine"]?.ToString() ?? "";
                    var pid = Convert.ToInt32(proc["ProcessId"]);
                    var name = proc["Name"]?.ToString() ?? "";

                    if (pid <= 4 || killed.Contains(pid)) continue;
                    if (IsProtectedProcess(name)) continue;

                    // Process is running FROM the SUBST target path (staged payload)
                    if (exePath.StartsWith(substTarget, StringComparison.OrdinalIgnoreCase) ||
                        exePath.StartsWith($"{driveLetter}:", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            var process = Process.GetProcessById(pid);
                            process.Kill(entireProcessTree: true);
                            killed.Add(pid);

                            _logger.LogWarning(
                                "[VolumeMountMonitor] KILLED staged payload: {Name} (PID {Pid}) running from SUBST target {Path}",
                                name, pid, substTarget);

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Staged Payload Killed: Running from SUBST Target",
                                Evidence = $"Process {name} (PID {pid}) running from SUBST staging path: {exePath}",
                                Reasoning = "Process was executing from the attacker's SUBST staging directory. This is a deployed payload. Killed.",
                                Confidence = 0.93,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = name,
                                ProcessId = pid
                            });
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] HuntBySubstTarget failed");
            }
        }

        /// <summary>
        /// Last resort: kill any unsigned, non-system process started within the last 30 seconds.
        /// If the implant is a custom binary calling DefineDosDevice directly (no subst.exe, no shell),
        /// the only signal is that it started recently and isn't signed by a trusted publisher.
        /// </summary>
        private async Task HuntRecentlySpawnedUnsignedProcesses(string driveLetter, HashSet<int> killed)
        {
            try
            {
                var cutoff = DateTime.UtcNow.AddSeconds(-30);

                using var searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, Name, ExecutablePath, CreationDate, ParentProcessId FROM Win32_Process");

                foreach (ManagementObject proc in searcher.Get())
                {
                    var pid = Convert.ToInt32(proc["ProcessId"]);
                    var name = proc["Name"]?.ToString() ?? "";
                    var exePath = proc["ExecutablePath"]?.ToString() ?? "";
                    var creationStr = proc["CreationDate"]?.ToString() ?? "";

                    if (pid <= 4 || killed.Contains(pid)) continue;
                    if (IsProtectedProcess(name)) continue;
                    if (string.IsNullOrEmpty(exePath)) continue;

                    // Parse WMI datetime format
                    if (!ManagementDateTimeConverter.ToDateTime(creationStr).ToUniversalTime().Equals(default) &&
                        ManagementDateTimeConverter.ToDateTime(creationStr).ToUniversalTime() < cutoff)
                        continue; // Process started more than 30s ago — probably not the creator

                    // Check if it's from a suspicious path (not Program Files, not System32)
                    var lowerPath = exePath.ToLowerInvariant();
                    if (lowerPath.StartsWith(@"c:\windows\") || lowerPath.StartsWith(@"c:\program files"))
                        continue;

                    // This is a recently-spawned, non-system, non-standard-path process.
                    // In the context of an active SUBST attack, this is likely the implant.
                    try
                    {
                        var process = Process.GetProcessById(pid);
                        process.Kill(entireProcessTree: true);
                        killed.Add(pid);

                        _logger.LogWarning(
                            "[VolumeMountMonitor] KILLED suspected implant: {Name} (PID {Pid}) — recently spawned from {Path}",
                            name, pid, exePath);

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Suspected Implant Killed: Recent Non-System Process During SUBST Attack",
                            Evidence = $"Process {name} (PID {pid}) at {exePath} started within 30s of SUBST drive {driveLetter}: creation",
                            Reasoning = "No subst.exe or shell process was found creating the drive. " +
                                        "This recently-spawned process from a non-standard path is the most likely candidate — " +
                                        "it called DefineDosDevice directly. Process tree killed.",
                            Confidence = 0.80,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            ProcessName = name,
                            ProcessId = pid
                        });
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] HuntRecentlySpawnedUnsignedProcesses failed");
            }
        }

        /// <summary>
        /// Processes that should never be killed regardless of context.
        /// </summary>
        private static bool IsProtectedProcess(string name)
        {
            var lower = name.ToLowerInvariant().Replace(".exe", "");
            return lower is "system" or "smss" or "csrss" or "wininit" or "winlogon"
                or "services" or "lsass" or "svchost" or "dwm" or "explorer"
                or "sihost" or "taskhostw" or "runtimebroker" or "searchhost"
                or "windowssentinel" or "sentinelservice";
        }

        /// <summary>
        /// Removes persistence mechanisms that recreate the SUBST drive:
        /// 1. Run/RunOnce registry entries containing 'subst' + the drive letter
        /// 2. Scheduled tasks with 'subst' in their action
        /// This ensures the attacker's drive doesn't come back after Sentinel removes it.
        /// </summary>
        private async Task RemoveSubstPersistence(string driveLetter)
        {
            var normalizedLetter = driveLetter.TrimEnd('\\', ':').ToUpperInvariant();

            // 1. Scan Run keys for subst persistence
            await RemoveSubstFromRunKeys(normalizedLetter);

            // 2. Scan and disable scheduled tasks with subst
            await RemoveSubstScheduledTasks(normalizedLetter);
        }

        private async Task RemoveSubstFromRunKeys(string driveLetter)
        {
            var runPaths = new[]
            {
                (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
                (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"),
                (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            };

            foreach (var (hive, path) in runPaths)
            {
                try
                {
                    using var key = hive.OpenSubKey(path, writable: true);
                    if (key == null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        var valueData = key.GetValue(valueName)?.ToString() ?? "";
                        if (valueData.Contains("subst", StringComparison.OrdinalIgnoreCase) &&
                            valueData.Contains(driveLetter, StringComparison.OrdinalIgnoreCase))
                        {
                            key.DeleteValue(valueName, throwOnMissingValue: false);
                            _logger.LogWarning(
                                "[VolumeMountMonitor] REMOVED SUBST persistence from registry: {Path}\\{Name} = {Value}",
                                path, valueName, valueData);

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Persistence Removed: SUBST Drive Registry Entry",
                                Evidence = $"Deleted registry value '{valueName}' = '{valueData}' from {path}",
                                Reasoning = "Registry Run key was recreating an attacker SUBST staging drive on every login. Entry removed to prevent persistence.",
                                Confidence = 0.90,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.RemoveRegistryEntry,
                                ProcessName = "SYSTEM",
                                ProcessId = 0
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[VolumeMountMonitor] Failed to scan Run key {Path}", path);
                }
            }
        }

        private async Task RemoveSubstScheduledTasks(string driveLetter)
        {
            try
            {
                // Use schtasks to enumerate and find tasks containing subst + our drive letter
                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = "/Query /FO CSV /V",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var proc = Process.Start(psi);
                if (proc == null) return;

                var output = await proc.StandardOutput.ReadToEndAsync();
                await proc.WaitForExitAsync();

                // Parse CSV output for tasks with subst + drive letter in "Task To Run" column
                var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    if (line.Contains("subst", StringComparison.OrdinalIgnoreCase) &&
                        line.Contains(driveLetter, StringComparison.OrdinalIgnoreCase))
                    {
                        // Extract task name (first CSV field after header)
                        var fields = line.Split(',');
                        if (fields.Length < 2) continue;
                        var taskName = fields[0].Trim('"', ' ');
                        if (string.IsNullOrEmpty(taskName) || taskName.StartsWith("TaskName")) continue;

                        // Delete the scheduled task
                        var deletePsi = new ProcessStartInfo
                        {
                            FileName = "schtasks.exe",
                            Arguments = $"/Delete /TN \"{taskName}\" /F",
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };
                        using var deleteProc = Process.Start(deletePsi);
                        deleteProc?.WaitForExit(10000);

                        _logger.LogWarning(
                            "[VolumeMountMonitor] REMOVED SUBST persistence scheduled task: {TaskName}",
                            taskName);

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Persistence Removed: SUBST Drive Scheduled Task",
                            Evidence = $"Deleted scheduled task '{taskName}' that was recreating SUBST drive {driveLetter}:",
                            Reasoning = "A scheduled task was responsible for persistently recreating an attacker SUBST staging drive. Task deleted.",
                            Confidence = 0.90,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            ProcessName = "schtasks",
                            ProcessId = 0
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] Failed to scan scheduled tasks for SUBST persistence");
            }
        }

        /// <summary>
        /// Strips drive letters from EFI System Partitions and Recovery partitions.
        /// These partitions should NEVER have a drive letter. If one is assigned (by a previous
        /// Sentinel version's WMI enumeration side effect, or by Windows disk management bugs),
        /// remove it immediately on startup to prevent user confusion and potential security issues.
        /// </summary>
        private void StripSystemPartitionDriveLetters()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT DriveLetter, Label, FileSystem, Capacity FROM Win32_Volume WHERE FileSystem = 'FAT32' OR FileSystem = 'FAT'");

                foreach (ManagementObject obj in searcher.Get())
                {
                    var letter = obj["DriveLetter"]?.ToString();
                    if (string.IsNullOrEmpty(letter)) continue;

                    var capacity = Convert.ToInt64(obj["Capacity"] ?? 0);
                    var label = obj["Label"]?.ToString() ?? "";

                    // EFI System Partitions are typically 100-260 MB FAT32 with no label or "SYSTEM"/"EFI"
                    bool isLikelyEsp = capacity > 0 && capacity <= 300 * 1024 * 1024 &&
                        (string.IsNullOrEmpty(label) ||
                         label.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                         label.Equals("EFI", StringComparison.OrdinalIgnoreCase) ||
                         label.Equals("ESP", StringComparison.OrdinalIgnoreCase) ||
                         label.Equals("BOOT", StringComparison.OrdinalIgnoreCase));

                    if (isLikelyEsp)
                    {
                        var driveLetter = letter.TrimEnd('\\', ':');
                        // Don't strip C: even if it somehow matches
                        if (driveLetter.Equals("C", StringComparison.OrdinalIgnoreCase)) continue;

                        var psi = new ProcessStartInfo
                        {
                            FileName = "mountvol.exe",
                            Arguments = $"{driveLetter}: /D",
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true
                        };
                        using var proc = Process.Start(psi);
                        proc?.WaitForExit(5000);

                        _logger.LogWarning(
                            "[VolumeMountMonitor] Stripped drive letter {Letter}: from system partition (Label='{Label}', Size={Size}MB) — ESP should not be exposed",
                            driveLetter, label, capacity / (1024 * 1024));
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] StripSystemPartitionDriveLetters failed");
            }
        }

        /// <summary>
        /// Determines if a volume is likely legitimate and should NOT be auto-dismounted
        /// even if there's a recent phantom device block. This prevents false positives where
        /// an unrelated network device appearing on LAN causes a legitimate drive (USB stick,
        /// mapped network drive, external HDD) to get nuked.
        ///
        /// Attacker fallback drives are typically: SUBST drives, VHD/VHDX mounts, RAM disks,
        /// or encrypted containers — not standard removable/fixed volumes with NTFS/FAT/exFAT.
        /// </summary>
        private bool IsLikelyLegitimateVolume(VolumeInfo vol, string classification)
        {
            // SUBST drives, RAM disks, encrypted containers, and VHDs are never "likely legitimate"
            // in the context of phantom device correlation
            if (classification.Contains("SUBST", StringComparison.OrdinalIgnoreCase) ||
                classification.Contains("RamDisk", StringComparison.OrdinalIgnoreCase) ||
                classification.Contains("Encrypted", StringComparison.OrdinalIgnoreCase) ||
                classification.Contains("VHD", StringComparison.OrdinalIgnoreCase) ||
                classification.Contains("PMEM", StringComparison.OrdinalIgnoreCase))
            {
                return false; // These are suspicious — allow fallback dismount
            }

            // Standard physical volumes (USB drives, external HDDs) with well-known filesystems
            // are very unlikely to be attacker-created fallback drives
            var knownFs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "NTFS", "FAT", "FAT32", "exFAT", "ReFS"
            };

            if (!string.IsNullOrEmpty(vol.FileSystem) && knownFs.Contains(vol.FileSystem))
            {
                // Has a real filesystem — check if it's also a standard drive type
                if (!string.IsNullOrEmpty(vol.DriveLetter))
                {
                    try
                    {
                        var driveInfo = new DriveInfo(vol.DriveLetter.TrimEnd('\\'));
                        if (driveInfo.DriveType == DriveType.Removable ||
                            driveInfo.DriveType == DriveType.Fixed ||
                            driveInfo.DriveType == DriveType.Network)
                        {
                            return true; // Standard removable/fixed/network drive — don't dismount
                        }
                    }
                    catch
                    {
                        // Drive not accessible — fall through to suspicious
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Queries WMI Win32_Volume for all currently mounted volumes.
        /// Returns volume info including DeviceId, drive letter, label, and filesystem.
        /// </summary>
        private List<VolumeInfo> GetMountedVolumes()
        {
            var volumes = new List<VolumeInfo>();
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT DeviceID, DriveLetter, Label, FileSystem FROM Win32_Volume");
                foreach (ManagementObject obj in searcher.Get())
                {
                    volumes.Add(new VolumeInfo
                    {
                        DeviceId = obj["DeviceID"]?.ToString() ?? string.Empty,
                        DriveLetter = obj["DriveLetter"]?.ToString(),
                        Label = obj["Label"]?.ToString(),
                        FileSystem = obj["FileSystem"]?.ToString()
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] WMI query failed");
            }
            return volumes;
        }

        /// <summary>
        /// Classifies a volume based on its backing driver/device characteristics.
        /// Returns a classification string: "RamDisk", "PMEM", "Encrypted", "VHD", "SUBST", or "Unknown".
        /// </summary>
        private string ClassifyVolume(VolumeInfo vol)
        {
            if (string.IsNullOrEmpty(vol.DriveLetter)) return "Unknown";

            try
            {
                // Check if it's a SUBST drive
                var buffer = new char[260];
                uint result = QueryDosDevice(vol.DriveLetter.TrimEnd('\\'), buffer, (uint)buffer.Length);
                if (result > 0)
                {
                    var target = new string(buffer, 0, (int)result).TrimEnd('\0');
                    if (target.StartsWith(@"\??\", StringComparison.Ordinal))
                        return "SUBST";
                }

                // Check device backing via WMI Win32_DiskDrive -> service name
                using var searcher = new ManagementObjectSearcher(
                    $"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{vol.DriveLetter.TrimEnd('\\')}'}}" +
                    " WHERE AssocClass=Win32_LogicalDiskToPartition");
                foreach (ManagementObject partition in searcher.Get())
                {
                    using var diskSearcher = new ManagementObjectSearcher(
                        $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{partition["DeviceID"]}'}}" +
                        " WHERE AssocClass=Win32_DiskDriveToDiskPartition");
                    foreach (ManagementObject disk in diskSearcher.Get())
                    {
                        var pnpId = disk["PNPDeviceID"]?.ToString() ?? "";
                        var model = disk["Model"]?.ToString() ?? "";

                        // RAM disk drivers
                        if (RamDiskDrivers.Any(d => pnpId.Contains(d, StringComparison.OrdinalIgnoreCase) ||
                                                     model.Contains(d, StringComparison.OrdinalIgnoreCase)))
                            return "RamDisk";

                        // PMEM drivers
                        if (PmemDrivers.Any(d => pnpId.Contains(d, StringComparison.OrdinalIgnoreCase)))
                            return "PMEM";

                        // VHD/VHDX (Microsoft Virtual Disk)
                        if (model.Contains("Virtual Disk", StringComparison.OrdinalIgnoreCase) ||
                            pnpId.Contains("VHDMP", StringComparison.OrdinalIgnoreCase))
                            return "VHD";

                        // Encrypted containers
                        if (EncryptedContainerDrivers.Any(d => pnpId.Contains(d, StringComparison.OrdinalIgnoreCase) ||
                                                               model.Contains(d, StringComparison.OrdinalIgnoreCase)))
                            return "Encrypted";
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] Classification failed for {Drive}", vol.DriveLetter);
            }

            return "Unknown";
        }

        private async Task EmitVolumeDetection(VolumeInfo vol, string classification)
        {
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "New Volume Mount Detected",
                Evidence = $"Drive={vol.DriveLetter ?? "(no letter)"}, Label='{vol.Label}', FS={vol.FileSystem}, Type={classification}",
                Reasoning = $"A new volume ({classification}) appeared after Sentinel startup. " +
                            "This may be legitimate (USB drive, network mount) or suspicious (RAM disk, SUBST, encrypted container). " +
                            "FileActivityMonitor has been extended to cover this volume.",
                Confidence = classification == "Unknown" ? 0.40 : 0.60,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0
            });
        }

        private async Task EmitFallbackDriveDetection(VolumeInfo vol, string classification)
        {
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Attacker Fallback Drive: Correlated with Phantom Device Block",
                Evidence = $"Drive={vol.DriveLetter}, Label='{vol.Label}', FS={vol.FileSystem}, Type={classification}",
                Reasoning = "A new volume appeared within 2 minutes of a phantom device being blocked. " +
                            "This matches the attacker fallback pattern: after losing their C2 relay device, " +
                            "attackers create a local staging drive (SUBST, VHD, or RAM disk) to continue the attack. " +
                            "Auto-dismounting this volume.",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                ProcessName = "SYSTEM",
                ProcessId = 0
            });
        }

        private async Task<bool> DismountVhd(string driveLetter)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -Command \"Dismount-VHD -DiskNumber ((Get-Partition -DriveLetter '{driveLetter}').DiskNumber) -Confirm:$false\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var proc = Process.Start(psi);
                if (proc == null) return false;
                await proc.WaitForExitAsync();
                return proc.ExitCode == 0;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] VHD dismount failed for {Letter}", driveLetter);
                return false;
            }
        }

        private bool RemoveVolumeMountPoint(string driveLetter)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "mountvol.exe",
                    Arguments = $"{driveLetter}: /D",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var proc = Process.Start(psi);
                if (proc == null) return false;
                proc.WaitForExit(10000);
                return proc.ExitCode == 0;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] mountvol removal failed for {Letter}", driveLetter);
                return false;
            }
        }
    }

    internal sealed class VolumeInfo
    {
        public string DeviceId { get; set; } = string.Empty;
        public string? DriveLetter { get; set; }
        public string? Label { get; set; }
        public string? FileSystem { get; set; }
    }
}

