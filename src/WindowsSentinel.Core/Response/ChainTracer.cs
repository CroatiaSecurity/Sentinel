using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Quarantine;

namespace WindowsSentinel.Core.Response;

/// <summary>
/// Chain Tracer - Traces attack chains to their root and eliminates entire threat trees.
/// When malicious behavior is detected, traces back to the attack origin and kills the entire chain.
/// </summary>
public sealed class ChainTracer
{
    private readonly IEventLogger _eventLogger;
    private readonly ILogger<ChainTracer> _logger;
    private readonly ScoringEngine _scoringEngine;
    private readonly YaraEngine? _yaraEngine;
    
    // System binaries that should never be quarantined (only killed if running malicious code)
    private static readonly HashSet<string> SystemBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "explorer.exe", "svchost.exe", "lsass.exe", "csrss.exe", "services.exe",
        "smss.exe", "wininit.exe", "winlogon.exe", "dwm.exe", "taskhostw.exe",
        "sihost.exe", "fontdrvhost.exe", "RuntimeBroker.exe", "SearchIndexer.exe",
        "SecurityHealthService.exe", "MsMpEng.exe", "conhost.exe", "dllhost.exe",
        "regsvr32.exe", "rundll32.exe", "msiexec.exe", "werfault.exe"
    };

    // Paths that indicate system binaries
    private static readonly string[] SystemPaths = new[]
    {
        @"C:\Windows\System32",
        @"C:\Windows\SysWOW64",
        @"C:\Windows\WinSxS"
    };

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    private static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] char[] lpFilename, uint nSize);

    [DllImport("kernel32.dll")]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, [Out] char[] lpExeName, ref uint lpdwSize);

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_TERMINATE = 0x0001;

    public ChainTracer(
        IEventLogger eventLogger,
        ILogger<ChainTracer> logger,
        ScoringEngine scoringEngine,
        YaraEngine? yaraEngine = null)
    {
        _eventLogger = eventLogger;
        _logger = logger;
        _scoringEngine = scoringEngine;
        _yaraEngine = yaraEngine;
    }

    /// <summary>
    /// Traces and eliminates an attack chain starting from a detected malicious process.
    /// Only the detected process and its descendants are killed — we do NOT walk up the
    /// parent chain and kill ancestors, because that risks killing legitimate processes
    /// (e.g. explorer.exe, svchost.exe) that happened to spawn the malicious child.
    /// The parent chain is walked for forensic evidence only.
    /// </summary>
    public async Task<ChainTraceResult> TraceAndEliminateAsync(
        DetectionEvent detection, 
        ThreatScore score,
        CancellationToken cancellationToken)
    {
        _logger.LogCritical(
            "ChainTracer: Tracing attack chain from PID {Pid} ({Process}) - {Verdict}",
            detection.ProcessId, detection.ProcessName, score.Verdict);

        var result = new ChainTraceResult
        {
            RootDetection = detection,
            Score = score,
            StartTime = DateTimeOffset.UtcNow
        };

        try
        {
            // Step 1: Walk parent chain for FORENSIC EVIDENCE ONLY — do not kill ancestors
            _logger.LogInformation("ChainTracer: Step 1 - Walking parent chain (forensic only)...");
            var parentChain = await WalkParentChainAsync(detection.ProcessId, cancellationToken);
            result.ParentChain = parentChain;

            // Attack root for logging purposes only — we kill from the detected PID downward
            result.AttackRoot = new ProcessNode
            {
                ProcessId   = detection.ProcessId,
                ProcessName = detection.ProcessName
            };

            _logger.LogInformation(
                "ChainTracer: Parent chain (forensic): {Chain}",
                string.Join(" ← ", parentChain.Select(p => $"{p.ProcessName}({p.ProcessId})")));

            // Step 2: Collect the detected process + all its descendants
            _logger.LogInformation("ChainTracer: Step 2 - Collecting descendants of PID {Pid}...", detection.ProcessId);
            var descendants = await CollectDescendantsAsync(detection.ProcessId, cancellationToken);
            result.AllChainProcesses = descendants;

            _logger.LogInformation(
                "ChainTracer: Collected {Count} processes to terminate (detected + descendants)",
                descendants.Count);

            // Step 3: Kill the detected process tree (leaves first)
            _logger.LogInformation("ChainTracer: Step 3 - Terminating processes...");
            var killedProcesses = await KillProcessTreeAsync(descendants, cancellationToken);
            result.KilledProcesses = killedProcesses;

            _logger.LogCritical(
                "ChainTracer: Successfully terminated {Count}/{Total} processes",
                killedProcesses.Count, descendants.Count);

            // Step 4: Quarantine attacker executables (skip system binaries)
            _logger.LogInformation("ChainTracer: Step 4 - Quarantining files...");
            var quarantinedFiles = await QuarantineAttackerFilesAsync(descendants, cancellationToken);
            result.QuarantinedFiles = quarantinedFiles;

            _logger.LogCritical(
                "ChainTracer: Quarantined {Count} files",
                quarantinedFiles.Count);

            // Step 5: Hunt and remove persistence only for quarantined files
            _logger.LogInformation("ChainTracer: Step 5 - Hunting persistence...");
            var persistenceRemoved = await HuntPersistenceAsync(quarantinedFiles, cancellationToken);
            result.PersistenceRemoved = persistenceRemoved;

            // Step 6: Block attacker IPs (only if a RemoteAddress is in the detection metadata)
            _logger.LogInformation("ChainTracer: Step 6 - Blocking network...");
            var blockedIps = await BlockAttackerIpsAsync(detection, descendants, cancellationToken);
            result.BlockedIps = blockedIps;

            result.EndTime = DateTimeOffset.UtcNow;
            result.Success = true;

            await LogChainTraceResultAsync(result, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ChainTracer: Error during chain trace");
            result.Success = false;
            result.ErrorMessage = ex.Message;
        }

        return result;
    }

    /// <summary>
    /// Walks the parent process chain up to 20 levels.
    /// </summary>
    private async Task<List<ProcessNode>> WalkParentChainAsync(int startPid, CancellationToken cancellationToken)
    {
        var chain = new List<ProcessNode>();
        var currentPid = startPid;
        var visitedPids = new HashSet<int>();
        var maxDepth = 20;

        while (currentPid != 0 && !visitedPids.Contains(currentPid) && chain.Count < maxDepth)
        {
            cancellationToken.ThrowIfCancellationRequested();
            visitedPids.Add(currentPid);

            try
            {
                using var process = Process.GetProcessById(currentPid);
                var parentPid = GetParentProcessId(currentPid);
                var imagePath = GetProcessImagePath(currentPid);
                var isSystemBinary = IsSystemBinary(imagePath, process.ProcessName);

                var node = new ProcessNode
                {
                    ProcessId = currentPid,
                    ProcessName = process.ProcessName,
                    ImagePath = imagePath,
                    IsSystemBinary = isSystemBinary,
                    CommandLine = GetCommandLine(currentPid),
                    ParentProcessId = parentPid,
                    StartTime = process.StartTime
                };

                chain.Add(node);

                // Move to parent
                currentPid = parentPid;
            }
            catch (ArgumentException)
            {
                // Process no longer exists
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "ChainTracer: Error getting process info for PID {Pid}", currentPid);
                break;
            }

            await Task.Delay(10, cancellationToken); // Small delay to prevent CPU spike
        }

        return chain;
    }

    /// <summary>
    /// Finds the attack root - the first non-system ancestor in the chain.
    /// </summary>
    private ProcessNode? FindAttackRoot(List<ProcessNode> chain)
    {
        // Walk from current process (index 0) up to find first non-system binary
        foreach (var node in chain)
        {
            if (!node.IsSystemBinary && !IsLegitimateParent(node.ProcessName))
            {
                return node;
            }
        }

        // If all are system-ish, return the highest level non-explorer process
        return chain.LastOrDefault(p => p.ProcessName.ToLowerInvariant() != "explorer.exe");
    }

    /// <summary>
    /// Collects all descendant processes of the attack root.
    /// </summary>
    private async Task<List<ProcessNode>> CollectDescendantsAsync(int rootPid, CancellationToken cancellationToken)
    {
        var allProcesses = new List<ProcessNode>();
        var visited = new HashSet<int>();

        // Add the root process first
        try
        {
            using var rootProcess = Process.GetProcessById(rootPid);
            allProcesses.Add(new ProcessNode
            {
                ProcessId = rootPid,
                ProcessName = rootProcess.ProcessName,
                ImagePath = GetProcessImagePath(rootPid),
                IsSystemBinary = IsSystemBinary(GetProcessImagePath(rootPid), rootProcess.ProcessName),
                CommandLine = GetCommandLine(rootPid),
                StartTime = rootProcess.StartTime
            });
            visited.Add(rootPid);
        }
        catch { }

        // Find all children recursively
        await CollectChildrenRecursiveAsync(rootPid, allProcesses, visited, 0, cancellationToken);

        return allProcesses;
    }

    private async Task CollectChildrenRecursiveAsync(
        int parentPid, 
        List<ProcessNode> allProcesses, 
        HashSet<int> visited,
        int depth,
        CancellationToken cancellationToken)
    {
        if (depth > 10) return; // Limit recursion depth

        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var allSystemProcesses = Process.GetProcesses();
            
            foreach (var process in allSystemProcesses)
            {
                try
                {
                    if (visited.Contains(process.Id)) continue;

                    var ppid = GetParentProcessId(process.Id);
                    if (ppid == parentPid)
                    {
                        var imagePath = GetProcessImagePath(process.Id);
                        var node = new ProcessNode
                        {
                            ProcessId = process.Id,
                            ProcessName = process.ProcessName,
                            ImagePath = imagePath,
                            IsSystemBinary = IsSystemBinary(imagePath, process.ProcessName),
                            CommandLine = GetCommandLine(process.Id),
                            ParentProcessId = parentPid,
                            StartTime = process.StartTime
                        };

                        allProcesses.Add(node);
                        visited.Add(process.Id);

                        // Recursively collect this process's children
                        await CollectChildrenRecursiveAsync(process.Id, allProcesses, visited, depth + 1, cancellationToken);
                    }
                }
                catch { /* Process may have exited */ }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ChainTracer: Error collecting children for PID {Pid}", parentPid);
        }

        await Task.Delay(5, cancellationToken);
    }

    /// <summary>
    /// Kills processes in the correct order (leaves first, root last).
    /// </summary>
    private async Task<List<KilledProcessInfo>> KillProcessTreeAsync(List<ProcessNode> processes, CancellationToken cancellationToken)
    {
        var killed = new List<KilledProcessInfo>();
        var selfPid = Environment.ProcessId;

        // Sort by start time descending (newest first - likely the malicious leaf processes)
        // We want to kill leaves first to prevent reinfection
        var sortedProcesses = processes
            .OrderByDescending(p => p.StartTime)
            .ToList();

        foreach (var process in sortedProcesses)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // SECURITY: Never kill our own process or parent service process.
            // This prevents injected code from weaponizing chain-trace against Sentinel.
            if (process.ProcessId == selfPid)
            {
                _logger.LogCritical(
                    "ChainTracer: BLOCKED SELF-KILL attempt on PID {Pid}. " +
                    "Injected code may be trying to weaponize Sentinel against itself.",
                    process.ProcessId);
                continue;
            }

            // Skip protected system processes
            if (IsCriticalSystemProcess(process.ProcessName))
            {
                _logger.LogWarning(
                    "ChainTracer: SKIPPING protected process PID {Pid} ({Name})",
                    process.ProcessId, process.ProcessName);
                continue;
            }

            try
            {
                using var proc = Process.GetProcessById(process.ProcessId);
                if (!proc.HasExited)
                {
                    proc.Kill(true); // Kill entire process tree
                    
                    killed.Add(new KilledProcessInfo
                    {
                        ProcessId = process.ProcessId,
                        ProcessName = process.ProcessName,
                        ImagePath = process.ImagePath,
                        IsSystemBinary = process.IsSystemBinary,
                        KillTime = DateTimeOffset.UtcNow
                    });

                    _logger.LogCritical(
                        "ChainTracer: KILLED PID {Pid} ({Name})",
                        process.ProcessId, process.ProcessName);

                    await Task.Delay(100, cancellationToken); // Brief delay between kills
                }
            }
            catch (ArgumentException)
            {
                // Already exited
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "ChainTracer: Failed to kill PID {Pid} ({Name})",
                    process.ProcessId, process.ProcessName);
            }
        }

        return killed;
    }

    /// <summary>
    /// Quarantines attacker files. System binaries are not quarantined.
    /// </summary>
    private async Task<List<QuarantinedFileInfo>> QuarantineAttackerFilesAsync(
        List<ProcessNode> processes, 
        CancellationToken cancellationToken)
    {
        var quarantined = new List<QuarantinedFileInfo>();
        // Use ProgramData — the service runs as SYSTEM and %LocalAppData% for SYSTEM
        // resolves to a hidden system profile folder, not the user's AppData.
        var quarantineDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "WindowsSentinel", "Quarantine");

        Directory.CreateDirectory(quarantineDir);

        // Get unique executables from processes (excluding system binaries)
        var uniqueExecutables = processes
            .Where(p => !string.IsNullOrEmpty(p.ImagePath) 
                && File.Exists(p.ImagePath) 
                && !p.IsSystemBinary
                && !IsSystemBinary(p.ImagePath!, p.ProcessName))
            .GroupBy(p => p.ImagePath!.ToLowerInvariant())
            .Select(g => g.First())
            .ToList();

        foreach (var process in uniqueExecutables)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                // ImagePath is already validated as non-null in the Where clause, but compiler needs assurance
                if (string.IsNullOrEmpty(process.ImagePath))
                    continue;

                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                var originalName = Path.GetFileName(process.ImagePath);
                var quarantineName = $"{timestamp}_{process.ProcessId}_{originalName}.quarantined";
                var quarantinePath = Path.Combine(quarantineDir, quarantineName);

                // Calculate hash before moving
                var fileHash = await ComputeFileHashAsync(process.ImagePath, cancellationToken);

                // SECURITY: Encrypt file with DPAPI before writing to quarantine.
                // This ensures raw malware bytes are never stored on disk in the
                // Defender-excluded quarantine folder.
                var rawBytes = await File.ReadAllBytesAsync(process.ImagePath, cancellationToken);
                var encryptedBytes = QuarantineManager.EncryptForQuarantine(rawBytes);
                await File.WriteAllBytesAsync(quarantinePath, encryptedBytes, cancellationToken);
                
                // Try to delete original
                try
                {
                    File.Delete(process.ImagePath);
                }
                catch (UnauthorizedAccessException)
                {
                    // File is read-only or on read-only media (ISO, CD-ROM, write-protected VHD)
                    // Attempt to dismount the volume to prevent re-execution
                    _logger.LogWarning(
                        "ChainTracer: File {Path} is on read-only media — attempting volume dismount",
                        process.ImagePath);
                    TryDismountVolume(process.ImagePath);
                }
                catch (IOException)
                {
                    // File in use or on read-only filesystem — try dismount
                    _logger.LogWarning(
                        "ChainTracer: Could not delete {Path} (IOException) — attempting volume dismount",
                        process.ImagePath);
                    TryDismountVolume(process.ImagePath);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex,
                        "ChainTracer: Could not delete original file {Path} - file may be in use or read-only",
                        process.ImagePath);
                    TryDismountVolume(process.ImagePath);
                }

                quarantined.Add(new QuarantinedFileInfo
                {
                    OriginalPath = process.ImagePath,
                    QuarantinePath = quarantinePath,
                    ProcessId = process.ProcessId,
                    ProcessName = process.ProcessName,
                    QuarantineTime = DateTimeOffset.UtcNow,
                    FileHash = fileHash
                });

                _logger.LogCritical(
                    "ChainTracer: QUARANTINED {Original} -> {Quarantine}",
                    process.ImagePath, quarantinePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "ChainTracer: Failed to quarantine {Path}",
                    process.ImagePath);
            }
        }

        return quarantined;
    }

    /// <summary>
    /// Attempts to dismount the volume containing the given file path.
    /// Used when a malicious file cannot be deleted because it's on read-only media
    /// (mounted ISO, CD-ROM, write-protected VHD, VeraCrypt read-only volume).
    /// Dismounting prevents the malware from being re-launched from that volume.
    /// </summary>
    private void TryDismountVolume(string filePath)
    {
        try
        {
            if (string.IsNullOrEmpty(filePath) || filePath.Length < 3) return;

            var driveLetter = filePath[..3]; // e.g. "E:\"
            var driveInfo = new DriveInfo(driveLetter);

            // Only dismount removable/CD-ROM drives — never dismount C: or fixed drives
            if (driveInfo.DriveType != DriveType.CDRom &&
                driveInfo.DriveType != DriveType.Removable &&
                driveInfo.DriveType != DriveType.Network)
            {
                // For fixed drives (could be a mounted VHD), try to dismount via DeviceIoControl
                // but only if it's NOT the system drive
                if (driveLetter.StartsWith("C", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning(
                        "ChainTracer: Cannot dismount system drive C: — malware file persists at {Path}",
                        filePath);
                    return;
                }

                // Attempt VHD dismount for non-system fixed drives
                TryDismountVhd(driveLetter);
                return;
            }

            // For CD-ROM / removable: use DeviceIoControl to eject/dismount
            var volumePath = $@"\\.\{driveLetter[..2]}"; // \\.\E:
            var handle = CreateFileW(
                volumePath,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero);

            if (handle == INVALID_HANDLE_VALUE)
            {
                // Try read-only access (sufficient for FSCTL_DISMOUNT_VOLUME)
                handle = CreateFileW(
                    volumePath,
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    0,
                    IntPtr.Zero);
            }

            if (handle == INVALID_HANDLE_VALUE)
            {
                _logger.LogWarning(
                    "ChainTracer: Cannot open volume {Volume} for dismount",
                    volumePath);
                return;
            }

            try
            {
                // Lock the volume
                DeviceIoControl(handle, FSCTL_LOCK_VOLUME, IntPtr.Zero, 0,
                    IntPtr.Zero, 0, out _, IntPtr.Zero);

                // Dismount
                bool dismounted = DeviceIoControl(handle, FSCTL_DISMOUNT_VOLUME, IntPtr.Zero, 0,
                    IntPtr.Zero, 0, out _, IntPtr.Zero);

                if (dismounted)
                {
                    _logger.LogCritical(
                        "ChainTracer: DISMOUNTED volume {Drive} — malware on read-only media neutralized",
                        driveLetter);

                    // Also try to eject (for CD-ROM / USB)
                    DeviceIoControl(handle, IOCTL_STORAGE_EJECT_MEDIA, IntPtr.Zero, 0,
                        IntPtr.Zero, 0, out _, IntPtr.Zero);
                }
                else
                {
                    _logger.LogWarning(
                        "ChainTracer: Failed to dismount volume {Drive} — malware file may persist",
                        driveLetter);
                }
            }
            finally
            {
                CloseHandle(handle);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "ChainTracer: Error attempting volume dismount for {Path}",
                filePath);
        }
    }

    /// <summary>
    /// Attempts to dismount a VHD/VHDX by detaching it via WMI.
    /// </summary>
    private void TryDismountVhd(string driveLetter)
    {
        try
        {
            // Use PowerShell's Dismount-DiskImage equivalent via WMI/CIM
            // Find the disk image associated with this drive letter
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT * FROM Win32_Volume WHERE DriveLetter = '{driveLetter[..2]}'");
            using var results = searcher.Get();

            foreach (System.Management.ManagementObject vol in results)
            {
                using (vol)
                {
                    var deviceId = vol["DeviceID"] as string;
                    if (deviceId == null) continue;

                    // Try to dismount via the volume's Dismount method
                    try
                    {
                        vol.InvokeMethod("Dismount", new object[] { true, false });
                        _logger.LogCritical(
                            "ChainTracer: DISMOUNTED VHD volume {Drive} — malware on virtual disk neutralized",
                            driveLetter);
                        return;
                    }
                    catch { /* Method may not be available */ }
                }
            }

            // Fallback: try FSCTL_DISMOUNT_VOLUME on the drive
            var volumePath = $@"\\.\{driveLetter[..2]}";
            var handle = CreateFileW(volumePath, GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

            if (handle != INVALID_HANDLE_VALUE)
            {
                try
                {
                    DeviceIoControl(handle, FSCTL_LOCK_VOLUME, IntPtr.Zero, 0,
                        IntPtr.Zero, 0, out _, IntPtr.Zero);
                    bool ok = DeviceIoControl(handle, FSCTL_DISMOUNT_VOLUME, IntPtr.Zero, 0,
                        IntPtr.Zero, 0, out _, IntPtr.Zero);

                    if (ok)
                    {
                        _logger.LogCritical(
                            "ChainTracer: DISMOUNTED volume {Drive} via FSCTL — malware neutralized",
                            driveLetter);
                    }
                }
                finally { CloseHandle(handle); }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "ChainTracer: Failed to dismount VHD at {Drive}",
                driveLetter);
        }
    }

    // P/Invoke for volume dismount
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        IntPtr hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private const uint FSCTL_LOCK_VOLUME = 0x00090018;
    private const uint FSCTL_DISMOUNT_VOLUME = 0x00090020;
    private const uint IOCTL_STORAGE_EJECT_MEDIA = 0x002D4808;

    /// <summary>
    /// Hunts for and removes persistence mechanisms pointing to quarantined files.
    /// </summary>
    private Task<List<PersistenceInfo>> HuntPersistenceAsync(
        List<QuarantinedFileInfo> quarantinedFiles, 
        CancellationToken cancellationToken)
    {
        var removed = new List<PersistenceInfo>();
        var quarantinedPaths = quarantinedFiles.Select(q => q.OriginalPath.ToLowerInvariant()).ToHashSet();

        try
        {
            // Check Run keys
            var runKeys = new[]
            {
                (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
            };

            foreach (var (hive, keyPath) in runKeys)
            {
                try
                {
                    using var key = hive.OpenSubKey(keyPath, writable: true);
                    if (key != null)
                    {
                        foreach (var valueName in key.GetValueNames())
                        {
                            var value = key.GetValue(valueName)?.ToString() ?? "";
                            if (quarantinedPaths.Any(q => value.ToLowerInvariant().Contains(q)))
                            {
                                key.DeleteValue(valueName);
                                removed.Add(new PersistenceInfo
                                {
                                    Type = "Registry Run Key",
                                    Location = $"{hive.Name}\\{keyPath}",
                                    Name = valueName,
                                    Value = value,
                                    Removed = true
                                });
                                _logger.LogCritical(
                                    "ChainTracer: REMOVED persistence: {Key}\\{Name}",
                                    keyPath, valueName);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "ChainTracer: Error checking registry key {Key}", keyPath);
                }
            }

            // Check Startup folders
            var startupFolders = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
            };

            foreach (var folder in startupFolders.Where(Directory.Exists))
            {
                var shortcuts = Directory.GetFiles(folder, "*.lnk")
                    .Concat(Directory.GetFiles(folder, "*.exe"));

                foreach (var file in shortcuts)
                {
                    try
                    {
                        // For .lnk files, would need to resolve target (simplified here)
                        if (quarantinedPaths.Any(q => file.ToLowerInvariant().Contains(Path.GetFileNameWithoutExtension(q).ToLowerInvariant())))
                        {
                            File.Delete(file);
                            removed.Add(new PersistenceInfo
                            {
                                Type = "Startup Folder",
                                Location = folder,
                                Name = Path.GetFileName(file),
                                Value = file,
                                Removed = true
                            });
                            _logger.LogCritical(
                                "ChainTracer: REMOVED startup item: {File}",
                                file);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "ChainTracer: Error checking startup file {File}", file);
                    }
                }
            }

            // Scheduled tasks pointing to quarantined files
            try
            {
                removed.AddRange(RemoveMaliciousScheduledTasks(quarantinedPaths));
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "ChainTracer: Error checking scheduled tasks");
            }

            // Services pointing to quarantined files
            try
            {
                removed.AddRange(RemoveMaliciousServices(quarantinedPaths));
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "ChainTracer: Error checking services");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ChainTracer: Error hunting persistence");
        }

        return Task.FromResult(removed);
    }

    /// <summary>
    /// Finds and removes scheduled tasks whose actions reference quarantined file paths.
    /// Fallback chain: WMI → Registry direct → skip gracefully.
    /// No LOLBin dependency (schtasks.exe not used).
    /// </summary>
    private List<PersistenceInfo> RemoveMaliciousScheduledTasks(HashSet<string> quarantinedPaths)
    {
        var removed = new List<PersistenceInfo>();

        // Attempt 1: WMI (most reliable on standard Windows)
        try
        {
            removed = RemoveScheduledTasksViaWmi(quarantinedPaths);
            if (removed.Count > 0) return removed;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ChainTracer: WMI task scheduler unavailable, trying registry fallback");
        }

        // Attempt 2: Direct registry deletion (works on stripped Windows without WMI)
        try
        {
            removed = RemoveScheduledTasksViaRegistry(quarantinedPaths);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ChainTracer: Registry task removal also failed — skipping task cleanup");
        }

        return removed;
    }

    private List<PersistenceInfo> RemoveScheduledTasksViaWmi(HashSet<string> quarantinedPaths)
    {
        var removed = new List<PersistenceInfo>();

        using var searcher = new System.Management.ManagementObjectSearcher(
            "root\\Microsoft\\Windows\\TaskScheduler",
            "SELECT TaskName, TaskPath, XML FROM MSFT_ScheduledTask");

        foreach (var obj in searcher.Get())
        {
            try
            {
                var taskName = obj["TaskName"]?.ToString();
                var taskPath = obj["TaskPath"]?.ToString();
                if (string.IsNullOrEmpty(taskName)) continue;

                // Skip Microsoft system tasks
                if (taskPath?.StartsWith("\\Microsoft\\", StringComparison.OrdinalIgnoreCase) == true) continue;

                var xml = obj["XML"]?.ToString() ?? "";
                var xmlLower = xml.ToLowerInvariant();

                bool isMatch = quarantinedPaths.Any(q =>
                {
                    var fileName = Path.GetFileName(q);
                    return !string.IsNullOrEmpty(fileName) && xmlLower.Contains(fileName);
                });

                if (!isMatch) continue;

                var fullPath = (taskPath ?? "\\") + taskName;

                // Unregister via WMI method invocation
                ((System.Management.ManagementObject)obj).InvokeMethod("Unregister", null);

                removed.Add(new PersistenceInfo
                {
                    Type = "Scheduled Task",
                    Location = "Task Scheduler",
                    Name = fullPath,
                    Value = "Referenced quarantined file (removed via WMI)",
                    Removed = true
                });
                _logger.LogCritical("ChainTracer: REMOVED scheduled task: {Task}", fullPath);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "ChainTracer: Error processing individual task");
            }
        }

        return removed;
    }

    private List<PersistenceInfo> RemoveScheduledTasksViaRegistry(HashSet<string> quarantinedPaths)
    {
        var removed = new List<PersistenceInfo>();
        const string tasksRoot = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks";
        const string treeRoot = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";

        using var tasksKey = Registry.LocalMachine.OpenSubKey(tasksRoot);
        if (tasksKey == null) return removed;

        foreach (var taskGuid in tasksKey.GetSubKeyNames())
        {
            try
            {
                using var taskKey = tasksKey.OpenSubKey(taskGuid);
                if (taskKey == null) continue;

                var path = taskKey.GetValue("Path")?.ToString();
                var actions = taskKey.GetValue("Actions") as byte[];
                if (string.IsNullOrEmpty(path) || actions == null) continue;

                // Skip Microsoft tasks
                if (path.StartsWith("\\Microsoft\\", StringComparison.OrdinalIgnoreCase)) continue;

                // Check if actions blob references quarantined files
                var actionsText = System.Text.Encoding.Unicode.GetString(actions).ToLowerInvariant();
                bool isMatch = quarantinedPaths.Any(q =>
                {
                    var fileName = Path.GetFileName(q);
                    return !string.IsNullOrEmpty(fileName) && actionsText.Contains(fileName);
                });

                if (!isMatch) continue;

                // Delete from TaskCache\Tasks
                using var writableTasksKey = Registry.LocalMachine.OpenSubKey(tasksRoot, writable: true);
                writableTasksKey?.DeleteSubKeyTree(taskGuid, throwOnMissingSubKey: false);

                // Also delete from TaskCache\Tree
                var treePath = treeRoot + path.Replace("/", "\\");
                var treeParent = Path.GetDirectoryName(treePath)?.Replace(Path.DirectorySeparatorChar, '\\');
                var treeName = Path.GetFileName(treePath);
                if (!string.IsNullOrEmpty(treeParent) && !string.IsNullOrEmpty(treeName))
                {
                    using var treeKey = Registry.LocalMachine.OpenSubKey(
                        treeParent.Replace("HKEY_LOCAL_MACHINE\\", ""), writable: true);
                    treeKey?.DeleteSubKeyTree(treeName, throwOnMissingSubKey: false);
                }

                removed.Add(new PersistenceInfo
                {
                    Type = "Scheduled Task",
                    Location = "Task Scheduler (registry)",
                    Name = path,
                    Value = "Referenced quarantined file (removed via registry)",
                    Removed = true
                });
                _logger.LogCritical("ChainTracer: REMOVED scheduled task via registry: {Task}", path);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "ChainTracer: Error processing task GUID {Guid}", taskGuid);
            }
        }

        return removed;
    }

    /// <summary>
    /// Finds and removes Windows services whose binary path references quarantined files.
    /// Fallback chain: ServiceController API → Registry direct disable/delete → skip gracefully.
    /// No LOLBin dependency (sc.exe not used).
    /// </summary>
    private List<PersistenceInfo> RemoveMaliciousServices(HashSet<string> quarantinedPaths)
    {
        var removed = new List<PersistenceInfo>();

        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesKey == null) return removed;

            foreach (var serviceName in servicesKey.GetSubKeyNames())
            {
                try
                {
                    using var svcKey = servicesKey.OpenSubKey(serviceName);
                    if (svcKey == null) continue;

                    var imagePath = svcKey.GetValue("ImagePath")?.ToString();
                    if (string.IsNullOrEmpty(imagePath)) continue;

                    var imagePathLower = imagePath.ToLowerInvariant();

                    bool isMatch = quarantinedPaths.Any(q =>
                        imagePathLower.Contains(Path.GetFileName(q)));

                    if (!isMatch) continue;
                    if (IsCriticalService(serviceName)) continue;

                    // Attempt 1: Stop via ServiceController (clean API approach)
                    bool stopped = false;
                    try
                    {
                        using var sc = new System.ServiceProcess.ServiceController(serviceName);
                        if (sc.Status != System.ServiceProcess.ServiceControllerStatus.Stopped &&
                            sc.Status != System.ServiceProcess.ServiceControllerStatus.StopPending)
                        {
                            sc.Stop();
                            sc.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
                        }
                        stopped = true;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "ChainTracer: ServiceController stop failed for {Service}, using registry disable", serviceName);
                    }

                    // Attempt 2: Disable + delete via registry (works even if SCM is unresponsive)
                    try
                    {
                        using var writeKey = Registry.LocalMachine.OpenSubKey(
                            $@"SYSTEM\CurrentControlSet\Services\{serviceName}", writable: true);
                        if (writeKey != null)
                        {
                            // Disable immediately (Start = 4)
                            writeKey.SetValue("Start", 4, Microsoft.Win32.RegistryValueKind.DWord);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "ChainTracer: Could not disable service {Service} via registry", serviceName);
                    }

                    // Attempt 3: Delete the service registry key entirely (if stopped)
                    bool deleted = false;
                    if (stopped)
                    {
                        try
                        {
                            Registry.LocalMachine.DeleteSubKeyTree(
                                $@"SYSTEM\CurrentControlSet\Services\{serviceName}", throwOnMissingSubKey: false);
                            deleted = true;
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug(ex, "ChainTracer: Could not delete service key {Service}", serviceName);
                        }
                    }

                    removed.Add(new PersistenceInfo
                    {
                        Type = deleted ? "Windows Service (Deleted)" : "Windows Service (Disabled)",
                        Location = "SCM",
                        Name = serviceName,
                        Value = imagePath,
                        Removed = true
                    });
                    _logger.LogCritical("ChainTracer: {Action} malicious service: {Service} ({Path})",
                        deleted ? "REMOVED" : "DISABLED", serviceName, imagePath);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "ChainTracer: Error checking service {Service}", serviceName);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ChainTracer: Service enumeration error");
        }

        return removed;
    }

    /// <summary>
    /// Services that must NEVER be touched regardless of what they reference.
    /// </summary>
    private static bool IsCriticalService(string serviceName)
    {
        var critical = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "wuauserv", "WinDefend", "MpsSvc", "BFE", "EventLog", "Dnscache",
            "LanmanServer", "LanmanWorkstation", "RpcSs", "RpcEptMapper",
            "Dhcp", "nsi", "Netlogon", "SamSs", "LSM", "Schedule",
            "PlugPlay", "Power", "Winmgmt", "CryptSvc", "TrustedInstaller",
            "BITS", "AppIDSvc", "gpsvc", "Spooler", "AudioSrv", "Audiosrv",
            "Windows Sentinel" // Never kill ourselves
        };
        return critical.Contains(serviceName);
    }

    /// <summary>
    /// Blocks attacker IPs via Windows Firewall.
    /// Fallback chain: COM API (HNetCfg) → Registry direct → skip gracefully.
    /// No LOLBin dependency (netsh.exe not used).
    /// </summary>
    private Task<List<BlockedIpInfo>> BlockAttackerIpsAsync(
        DetectionEvent detection, 
        List<ProcessNode> chainProcesses,
        CancellationToken cancellationToken)
    {
        var blocked = new List<BlockedIpInfo>();

        if (!detection.Metadata.TryGetValue("RemoteAddress", out var remoteAddress) ||
            string.IsNullOrEmpty(remoteAddress))
        {
            return Task.FromResult(blocked);
        }

        if (!IsValidIpAddress(remoteAddress))
        {
            _logger.LogWarning("ChainTracer: Invalid IP address format '{IP}' - skipping firewall block", remoteAddress);
            return Task.FromResult(blocked);
        }

        var ruleName = $"Sentinel_Block_{Guid.NewGuid():N}";

        // Attempt 1: Windows Firewall COM API (works on standard Windows)
        try
        {
            var fwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            var fwRuleType = Type.GetTypeFromProgID("HNetCfg.FWRule");

            if (fwPolicyType != null && fwRuleType != null)
            {
                var firewallPolicy = (dynamic)Activator.CreateInstance(fwPolicyType)!;
                var firewallRule = (dynamic)Activator.CreateInstance(fwRuleType)!;

                firewallRule.Name = ruleName;
                firewallRule.Description = $"Sentinel: Blocked attacker IP {remoteAddress} (PID {detection.ProcessId})";
                firewallRule.Protocol = 256; // NET_FW_IP_PROTOCOL_ANY
                firewallRule.Direction = 2;  // NET_FW_RULE_DIR_OUT
                firewallRule.Action = 0;     // NET_FW_ACTION_BLOCK
                firewallRule.RemoteAddresses = remoteAddress;
                firewallRule.Enabled = true;
                firewallRule.Profiles = 0x7FFFFFFF; // All profiles

                firewallPolicy.Rules.Add(firewallRule);

                blocked.Add(new BlockedIpInfo
                {
                    IpAddress = remoteAddress,
                    RuleName = ruleName,
                    BlockTime = DateTimeOffset.UtcNow,
                    RelatedProcessId = detection.ProcessId
                });

                _logger.LogCritical("ChainTracer: BLOCKED outbound to {IP} via firewall COM API", remoteAddress);
                return Task.FromResult(blocked);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ChainTracer: Firewall COM API unavailable, trying registry fallback");
        }

        // Attempt 2: Direct registry write to firewall rules (works on stripped Windows)
        try
        {
            var fwRulesKey = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
            using var key = Registry.LocalMachine.OpenSubKey(fwRulesKey, writable: true);
            if (key != null)
            {
                // Windows Firewall rule format in registry:
                // v2.33|Action=Block|Active=TRUE|Dir=Out|RA4={ip}|Name={name}|
                var ruleValue = $"v2.33|Action=Block|Active=TRUE|Dir=Out|RA4={remoteAddress}|Name={ruleName}|Desc=Sentinel blocked attacker IP|";
                key.SetValue(ruleName, ruleValue, Microsoft.Win32.RegistryValueKind.String);

                blocked.Add(new BlockedIpInfo
                {
                    IpAddress = remoteAddress,
                    RuleName = ruleName,
                    BlockTime = DateTimeOffset.UtcNow,
                    RelatedProcessId = detection.ProcessId
                });

                _logger.LogCritical("ChainTracer: BLOCKED outbound to {IP} via firewall registry", remoteAddress);
                return Task.FromResult(blocked);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ChainTracer: Firewall registry write also failed");
        }

        _logger.LogWarning("ChainTracer: Could not block IP {IP} — no firewall API available", remoteAddress);
        return Task.FromResult(blocked);
    }

    /// <summary>
    /// Validates IP address format to prevent command injection.
    /// </summary>
    private static bool IsValidIpAddress(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
            return false;

        // Check for dangerous characters that could be used for command injection
        var dangerousChars = new[] { ';', '&', '|', '<', '>', '`', '$', '(', ')', '{', '}', '\'', '"', ' ', '\t', '\n', '\r' };
        if (dangerousChars.Any(c => ip.Contains(c)))
            return false;

        // Must be valid IPv4 or IPv6 address
        return System.Net.IPAddress.TryParse(ip, out _);
    }

    private async Task LogChainTraceResultAsync(ChainTraceResult result, CancellationToken cancellationToken)
    {
        var evidence = $@"
=== CHAIN TRACE RESULT ===
Detection: {result.RootDetection.RuleName} (PID {result.RootDetection.ProcessId})
Verdict: {result.Score.Verdict} (Score: {result.Score.Score})
Start Time: {result.StartTime:yyyy-MM-dd HH:mm:ss}
End Time: {result.EndTime:yyyy-MM-dd HH:mm:ss}
Duration: {(result.EndTime - result.StartTime).TotalSeconds:F1}s

Attack Root: {result.AttackRoot?.ProcessName ?? "Unknown"} (PID {result.AttackRoot?.ProcessId ?? 0})
Chain Length: {result.AllChainProcesses.Count} processes

Parent Chain:
{string.Join("\n", result.ParentChain.Select((p, i) => $"  [{i}] PID {p.ProcessId} {p.ProcessName} {(p.IsSystemBinary ? "[SYSTEM]" : "")}"))}

Killed Processes ({result.KilledProcesses.Count}):
{string.Join("\n", result.KilledProcesses.Select(k => $"  - PID {k.ProcessId} {k.ProcessName} (was system binary: {k.IsSystemBinary})"))}

Quarantined Files ({result.QuarantinedFiles.Count}):
{string.Join("\n", result.QuarantinedFiles.Select(q => $"  - {q.OriginalPath} -> {q.QuarantinePath}"))}

Persistence Removed ({result.PersistenceRemoved.Count}):
{string.Join("\n", result.PersistenceRemoved.Select(p => $"  - {p.Type}: {p.Location}\\{p.Name}"))}

Blocked IPs ({result.BlockedIps.Count}):
{string.Join("\n", result.BlockedIps.Select(b => $"  - {b.IpAddress} (rule: {b.RuleName})"))}

=== END CHAIN TRACE ===
";

        _logger.LogCritical(evidence);

        // Emit as a composite detection event
        await _eventLogger.LogResponseAsync(new ResponseAction
        {
            Kind = ResponseActionKind.KillProcess,
            TriggerEvent = result.RootDetection,
            Timestamp = DateTimeOffset.UtcNow,
            Notes = $"Chain trace completed: {result.KilledProcesses.Count} processes killed, {result.QuarantinedFiles.Count} files quarantined, {result.PersistenceRemoved.Count} persistence items removed"
        }, cancellationToken);
    }

    // Helper methods
    /// <summary>
    /// Gets the parent process ID using WMI with proper parameter validation.
    /// SECURITY FIX: Uses parameterized query approach to prevent WMI injection.
    /// </summary>
    private int GetParentProcessId(int pid)
    {
        // SECURITY FIX: Validate PID is within valid range
        if (pid <= 0 || pid > 999999)
            return 0;

        try
        {
            // SECURITY FIX: Use ObjectQuery with proper escaping instead of string interpolation
            // WMI query injection is possible if user-controlled data is used in queries
            var query = new System.Management.ObjectQuery(
                "SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = " + pid.ToString(System.Globalization.CultureInfo.InvariantCulture));
            using var searcher = new System.Management.ManagementObjectSearcher(query);
            foreach (var obj in searcher.Get())
            {
                return Convert.ToInt32(obj["ParentProcessId"]);
            }
        }
        catch { }
        return 0;
    }

    /// <summary>
    /// Gets the process image path.
    /// </summary>
    private string GetProcessImagePath(int pid)
    {
        // SECURITY FIX: Validate PID is within valid range
        if (pid <= 0 || pid > 999999)
            return "";

        try
        {
            using var process = Process.GetProcessById(pid);
            return process.MainModule?.FileName ?? "";
        }
        catch { }
        return "";
    }

    /// <summary>
    /// Gets the command line for a process using WMI with proper validation.
    /// SECURITY FIX: Uses ObjectQuery with proper escaping to prevent WMI injection.
    /// </summary>
    private string GetCommandLine(int pid)
    {
        // SECURITY FIX: Validate PID is within valid range
        if (pid <= 0 || pid > 999999)
            return "";

        try
        {
            // SECURITY FIX: Use ObjectQuery with proper escaping instead of string interpolation
            var query = new System.Management.ObjectQuery(
                "SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + pid.ToString(System.Globalization.CultureInfo.InvariantCulture));
            using var searcher = new System.Management.ManagementObjectSearcher(query);
            foreach (var obj in searcher.Get())
            {
                return obj["CommandLine"]?.ToString() ?? "";
            }
        }
        catch { }
        return "";
    }

    private bool IsSystemBinary(string? imagePath, string processName)
    {
        if (string.IsNullOrEmpty(imagePath))
            return SystemBinaries.Contains(processName);

        if (SystemBinaries.Contains(processName))
            return true;

        return SystemPaths.Any(sp => 
            imagePath.StartsWith(sp, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsLegitimateParent(string processName)
    {
        var legitimateParents = new[] { "explorer.exe", "services.exe", "winlogon.exe" };
        return legitimateParents.Contains(processName.ToLowerInvariant());
    }

    private bool IsCriticalSystemProcess(string processName)
    {
        var critical = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // Kernel / session
            "system", "registry", "smss", "csrss", "wininit", "services", "lsass", "svchost",
            // Desktop / shell (killing these crashes the user session)
            "explorer", "dwm", "sihost", "fontdrvhost", "winlogon",
            // User-facing apps that must never be killed by overlay/capture heuristics
            "msedge", "chrome", "firefox", "brave", "opera", "vivaldi",
            "code", "kiro", "devenv", "rider64", "idea64",
            "teams", "ms-teams", "zoom", "slack", "discord",
            "windowsterminal", "wt",
        };
        return critical.Contains(processName.Replace(".exe", ""));
    }

    private async Task<string> ComputeFileHashAsync(string filePath, CancellationToken cancellationToken)
    {
        using var sha256 = SHA256.Create();
        await using var stream = File.OpenRead(filePath);
        var hash = await sha256.ComputeHashAsync(stream, cancellationToken);
        return Convert.ToHexString(hash);
    }
}

/// <summary>
/// Represents a node in the process chain.
/// </summary>
public sealed class ProcessNode
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string? ImagePath { get; set; }
    public bool IsSystemBinary { get; set; }
    public string? CommandLine { get; set; }
    public int ParentProcessId { get; set; }
    public DateTime StartTime { get; set; }
}

/// <summary>
/// Represents a killed process.
/// </summary>
public sealed class KilledProcessInfo
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string? ImagePath { get; set; }
    public bool IsSystemBinary { get; set; }
    public DateTimeOffset KillTime { get; set; }
}

/// <summary>
/// Represents a quarantined file.
/// </summary>
public sealed class QuarantinedFileInfo
{
    public string OriginalPath { get; set; } = "";
    public string QuarantinePath { get; set; } = "";
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public DateTimeOffset QuarantineTime { get; set; }
    public string FileHash { get; set; } = "";
}

/// <summary>
/// Represents removed persistence.
/// </summary>
public sealed class PersistenceInfo
{
    public string Type { get; set; } = "";
    public string Location { get; set; } = "";
    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
    public bool Removed { get; set; }
}

/// <summary>
/// Represents a blocked IP.
/// </summary>
public sealed class BlockedIpInfo
{
    public string IpAddress { get; set; } = "";
    public string RuleName { get; set; } = "";
    public DateTimeOffset BlockTime { get; set; }
    public int RelatedProcessId { get; set; }
}

/// <summary>
/// Result of a chain trace operation.
/// </summary>
public sealed class ChainTraceResult
{
    public DetectionEvent RootDetection { get; set; } = null!;
    public ThreatScore Score { get; set; } = null!;
    public DateTimeOffset StartTime { get; set; }
    public DateTimeOffset EndTime { get; set; }
    public List<ProcessNode> ParentChain { get; set; } = new();
    public ProcessNode? AttackRoot { get; set; }
    public List<ProcessNode> AllChainProcesses { get; set; } = new();
    public List<KilledProcessInfo> KilledProcesses { get; set; } = new();
    public List<QuarantinedFileInfo> QuarantinedFiles { get; set; } = new();
    public List<PersistenceInfo> PersistenceRemoved { get; set; } = new();
    public List<BlockedIpInfo> BlockedIps { get; set; } = new();
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
}


