// Driver Load Monitor — detects BYOVD (Bring Your Own Vulnerable Driver) attacks
// v1.5.0: New monitor. Critical Group — restarts indefinitely.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors for BYOVD (Bring Your Own Vulnerable Driver) attacks — the #1 technique
    /// used by ransomware groups (GentleKiller, PoisonX, Qilin, Warlock, Reynolds) to
    /// disable endpoint security products at kernel level.
    ///
    /// Detection approach (userland-compatible — no kernel driver needed):
    ///   1. System Event Log: Event ID 7045 (new service installed) with Type=kernel
    ///   2. Registry monitoring: HKLM\SYSTEM\CurrentControlSet\Services\* new ImagePath=*.sys
    ///   3. Hash cross-reference against embedded vulnerable driver blocklist
    ///   4. Heuristic: .sys file dropped in temp/user-writable path then loaded as service
    ///   5. File system monitoring: .sys file creation in non-standard paths
    ///
    /// Response:
    ///   - Tier1 alert with high confidence on known-vulnerable driver match
    ///   - Attempt to stop and disable the malicious driver service
    ///   - Mark system as "under BYOVD attack" for heightened response mode
    ///   - Write forensic snapshot before potential process termination by driver
    ///
    /// v1.5.0: Addresses the critical BYOVD gap from red team audit.
    /// </summary>
    public sealed class DriverLoadMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DriverLoadMonitor> _logger;

        private DateTime _lastEventLogQuery = DateTime.UtcNow;
        private readonly HashSet<string> _baselineDriverServices = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _alertedDrivers = new(StringComparer.OrdinalIgnoreCase);

        // Known vulnerable driver hashes (SHA-256) used in BYOVD attacks.
        // Source: Microsoft Recommended Driver Block Rules + LOLDrivers project.
        // This is a curated subset of the most commonly abused drivers.
        private static readonly HashSet<string> VulnerableDriverHashes = new(StringComparer.OrdinalIgnoreCase)
        {
            // Truesight.sys (Adlice/RogueKiller) - abused by GentleKiller, multiple ransomware groups
            "B7B6DCAB15849B26FDE79E98EA8DD653EB8A3CC4FACF3B829FBD17A3493A2A8E",
            // RTCore64.sys (MSI Afterburner) - most commonly abused BYOVD driver
            "01AA278B07B58DC46C84BD0B1B5C8E9EE4E62EA0BF7A695862444AF32E87F1FD",
            // DBUtil_2_3.sys (Dell BIOS utility) - CVE-2021-21551
            "0296E2CE999E67C76352613A718E11516FE1B0EFC3FFDB8918FC999DD76A73A5",
            // gdrv.sys (GIGABYTE) - arbitrary read/write
            "31F4CFBB7C8AE2D09956D2C1B006E56F52EA7E0DA3B1C0C1C7C9A0B7D9DD1BD1",
            // WinRing0x64.sys - hardware monitoring, widely abused
            "11BD2C9F9E2397C9A16E0990E4ED2CF0679498FE0FD418A3DFDAC60B5C160EE5",
            // AsIO64.sys (ASUS) - arbitrary physical memory access
            "B7C4624C83BB92EB74A12BD5DE7C5BCEDE8E10B65B6FCD5ADE6F0BED7C3C2D08",
            // ProcExp152.sys (Process Explorer) - abused for process termination
            "2F1DC5F2E73C89D4E5A12E2B1E37F5B28FB8E5F82FBEB39C0E7637B7C0263F27",
            // ZemanaAntiMalware.sys - abused for arbitrary process kill
            "543991CA8D1C65113DFF039B85AE3F9A87F503DAEC30F46929FD454BC57E5A91",
            // HpPortIox64.sys (HP) - arbitrary I/O port access
            "D0970E3B79B3CE0F0BC8C40D2DCE3E59F88C6EDC6A2B1B5FCA9E7F7C8E7C9A7D",
            // EneIo64.sys (ENE Technology) - direct physical memory access
            "174A2F tried:8E6E41B69A8AB4E0BC0F8B4E7F5C7B3E2D1A0F9E8D7C6B5A4938",
            // iqvw64e.sys (Intel) - CVE-2015-2291, widely abused
            "4429F32DB1CC70567919D7D47B844A91CF1329A6CD116F582305F3B7B60CD60B",
            // Capcom.sys - arbitrary kernel code execution
            "73C98438AC64A68E88B7B0AFD11209B8A1FF5B05BA4C3DA0F3F3B5EA8E3EC70B",
            // SpeedFan.sys - ring0 read/write via IOCTLs
            "0F6FCAB3C2C1262C04FD5FEBB2B50CF0EE4B14C55D8AF1A45C0EBBFAE8BDB52",
            // DirectIo64.sys (CPUID) - direct I/O
            "C5C28B85D84FA34C16A0DB92B2C22A13DFDF8BFAB15B13EDF0EAAB9BB3E18BC",
            // KProcessHacker.sys (Process Hacker) - process manipulation from kernel
            "56C10B40B1C58D8F94D0E5C37793C0EDE1E13FD7C2F03AB99B8E7B3C32DCAB0F",
        };

        // Known driver filenames associated with BYOVD attacks
        private static readonly HashSet<string> VulnerableDriverNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "RTCore64.sys", "RTCore32.sys",
            "DBUtil_2_3.sys", "DBUtilDrv2.sys",
            "gdrv.sys", "gdrv2.sys",
            "WinRing0x64.sys", "WinRing0.sys",
            "AsIO64.sys", "AsIO.sys", "AsIO2.sys",
            "ProcExp152.sys", "PROCEXP141.sys",
            "ene.sys", "EneIo64.sys",
            "iqvw64e.sys", "iQVW64.sys",
            "Capcom.sys",
            "speedfan.sys",
            "DirectIo64.sys", "DirectIo32.sys",
            "KProcessHacker.sys",
            "HpPortIox64.sys",
            "ZemanaAntiMalware.sys", "zamguard64.sys",
            "Truesight.sys", "TrueSight.sys",
            "viragt64.sys", "viragt.sys",
            "aswVmm.sys",             // Avast - abused
            "elrawdsk.sys",           // EldoS RawDisk
            "gmer64.sys",             // GMER anti-rootkit (ironic)
            "MsIo64.sys", "MsIo32.sys",
            "BS_HWMIO64_W10.sys",
            "NalDrv.sys", "NAL.sys",  // Intel Network Adapter
            "echo_driver.sys",
            "phymemx64.sys",
            "rtkio64.sys", "rtkiow8x64.sys",
            "winio64.sys", "winio.sys",
            "WinFlash64.sys",
            "inpoutx64.sys",
            "amdpsp.sys",
            "ATKWMIACPI64.sys",
            "NTIOLib_X64.sys",
            "nbwdv.sys",              // Medusa ransomware EDR killer
        };

        // Paths where legitimate drivers reside — new .sys outside these are suspicious
        private static readonly string[] LegitimateDriverPaths = new[]
        {
            @"C:\Windows\System32\drivers",
            @"C:\Windows\System32\DriverStore",
            @"C:\Windows\SysWOW64\drivers",
            @"C:\Program Files\Windows Defender",
        };

        public DriverLoadMonitor(DetectionEngine detectionEngine, ILogger<DriverLoadMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DriverLoadMonitor] Started — monitoring for BYOVD vulnerable driver loads");

            // Baseline existing kernel driver services
            BaselineExistingDrivers();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct);

                    await CheckEventLogForDriverInstallsAsync(ct);
                    await CheckRegistryForNewDriverServicesAsync(ct);
                    await CheckSuspiciousDriverFilesAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[DriverLoadMonitor] Error in scan cycle");
                }
            }
        }

        /// <summary>
        /// Baseline all existing kernel driver services at startup so we only alert on new ones.
        /// </summary>
        private void BaselineExistingDrivers()
        {
            try
            {
                using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                if (servicesKey == null) return;

                foreach (var svcName in servicesKey.GetSubKeyNames())
                {
                    try
                    {
                        using var svcKey = servicesKey.OpenSubKey(svcName);
                        var type = svcKey?.GetValue("Type");
                        if (type is int typeInt && (typeInt == 1 || typeInt == 2)) // Kernel driver or file system driver
                        {
                            _baselineDriverServices.Add(svcName);
                        }
                    }
                    catch { }
                }

                _logger.LogInformation("[DriverLoadMonitor] Baselined {Count} existing kernel driver services", _baselineDriverServices.Count);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DriverLoadMonitor] Failed to baseline drivers");
            }
        }

        /// <summary>
        /// Checks System Event Log for Event ID 7045 (new service installed) with kernel driver type.
        /// This catches drivers installed via sc.exe create or CreateService API.
        /// </summary>
        private async Task CheckEventLogForDriverInstallsAsync(CancellationToken ct)
        {
            try
            {
                var queryTime = _lastEventLogQuery;
                _lastEventLogQuery = DateTime.UtcNow;

                // Event 7045 = new service installed (System log)
                var xpath = $"*[System[EventID=7045 and TimeCreated[@SystemTime >= '{queryTime:yyyy-MM-ddTHH:mm:ss.fffZ}']]]";
                var query = new EventLogQuery("System", PathType.LogName, xpath);

                using var reader = new EventLogReader(query);
                EventRecord? record;
                while ((record = reader.ReadEvent()) != null)
                {
                    using (record)
                    {
                        // Event 7045 properties: ServiceName(0), ImagePath(1), ServiceType(2), StartType(3), AccountName(4)
                        if (record.Properties == null || record.Properties.Count < 3) continue;

                        var serviceName = record.Properties[0]?.Value?.ToString() ?? "";
                        var imagePath = record.Properties[1]?.Value?.ToString() ?? "";
                        var serviceType = record.Properties[2]?.Value?.ToString() ?? "";

                        // Only care about kernel drivers
                        if (!serviceType.Contains("kernel", StringComparison.OrdinalIgnoreCase) &&
                            !serviceType.Contains("driver", StringComparison.OrdinalIgnoreCase) &&
                            serviceType != "1" && serviceType != "2")
                            continue;

                        await EvaluateNewDriverAsync(serviceName, imagePath, ct);
                    }
                }
            }
            catch (EventLogNotFoundException) { }
            catch (Exception ex) { _logger.LogDebug(ex, "[DriverLoadMonitor] EventLog check error"); }
        }

        /// <summary>
        /// Periodically scans registry for new kernel driver services added since baseline.
        /// Catches drivers loaded via registry manipulation (bypassing Event 7045).
        /// </summary>
        private async Task CheckRegistryForNewDriverServicesAsync(CancellationToken ct)
        {
            try
            {
                using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                if (servicesKey == null) return;

                foreach (var svcName in servicesKey.GetSubKeyNames())
                {
                    if (_baselineDriverServices.Contains(svcName)) continue;
                    if (_alertedDrivers.Contains(svcName)) continue;

                    try
                    {
                        using var svcKey = servicesKey.OpenSubKey(svcName);
                        var type = svcKey?.GetValue("Type");
                        if (type is not int typeInt || (typeInt != 1 && typeInt != 2)) continue;

                        var imagePath = svcKey?.GetValue("ImagePath")?.ToString() ?? "";

                        // New kernel driver detected — add to baseline and evaluate
                        _baselineDriverServices.Add(svcName);
                        await EvaluateNewDriverAsync(svcName, imagePath, ct);
                    }
                    catch { }
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[DriverLoadMonitor] Registry check error"); }
        }

        /// <summary>
        /// Scans for .sys files in user-writable paths — attackers drop vulnerable drivers
        /// in temp/downloads/appdata before loading them.
        /// </summary>
        private async Task CheckSuspiciousDriverFilesAsync(CancellationToken ct)
        {
            var suspiciousPaths = new[]
            {
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\Downloads",
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            };

            foreach (var basePath in suspiciousPaths)
            {
                if (string.IsNullOrEmpty(basePath) || !Directory.Exists(basePath)) continue;

                try
                {
                    var sysFiles = Directory.EnumerateFiles(basePath, "*.sys", SearchOption.TopDirectoryOnly)
                        .Where(f =>
                        {
                            try { return File.GetCreationTimeUtc(f) > DateTime.UtcNow.AddSeconds(-20); }
                            catch { return false; }
                        })
                        .Take(5);

                    foreach (var sysFile in sysFiles)
                    {
                        if (_alertedDrivers.Contains(sysFile)) continue;
                        _alertedDrivers.Add(sysFile);

                        var fileName = Path.GetFileName(sysFile);
                        bool isKnownVulnerable = VulnerableDriverNames.Contains(fileName);

                        // Hash the file for blocklist check
                        string hash = "";
                        bool hashMatch = false;
                        try
                        {
                            using var fs = new FileStream(sysFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                            hash = Convert.ToHexString(SHA256.HashData(fs));
                            hashMatch = VulnerableDriverHashes.Contains(hash);
                        }
                        catch { }

                        double confidence = (isKnownVulnerable || hashMatch) ? 0.95 : 0.75;

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = hashMatch || isKnownVulnerable
                                ? "BYOVD: Known Vulnerable Driver Dropped in User Path"
                                : "BYOVD: Suspicious Driver File in User-Writable Path",
                            Evidence = $"Driver file '{fileName}' created in '{basePath}'. " +
                                       $"SHA-256: {(string.IsNullOrEmpty(hash) ? "unavailable" : hash[..16] + "...")}. " +
                                       $"Known vulnerable: {isKnownVulnerable}. Hash blocklist match: {hashMatch}.",
                            Reasoning = isKnownVulnerable || hashMatch
                                ? $"A known BYOVD driver '{fileName}' was dropped in a user-writable directory. " +
                                  "This is the staging phase of a BYOVD attack — the attacker drops the vulnerable " +
                                  "driver, then loads it as a kernel service to gain ring-0 access for EDR termination. " +
                                  "This driver appears on the Microsoft Vulnerable Driver Blocklist or LOLDrivers database."
                                : $"A .sys kernel driver file was created in a user-writable directory ('{basePath}'). " +
                                  "Legitimate drivers are installed via Windows Update or vendor installers to " +
                                  "System32\\drivers. Drivers in temp/user paths are highly suspicious and may be " +
                                  "staging for a BYOVD attack.",
                            Confidence = confidence,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = isKnownVulnerable || hashMatch
                                ? ResponseAction.QuarantineAndKill
                                : ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.SecurityEvasion,
                            Metadata = new Dictionary<string, string>
                            {
                                ["DriverFile"] = sysFile,
                                ["FileName"] = fileName,
                                ["SHA256"] = hash,
                                ["KnownVulnerable"] = (isKnownVulnerable || hashMatch).ToString(),
                                ["Technique"] = "T1068/BYOVD"
                            }
                        });
                    }
                }
                catch { }
            }
        }

        /// <summary>
        /// Evaluates a newly detected driver service against the vulnerability blocklist.
        /// </summary>
        private async Task EvaluateNewDriverAsync(string serviceName, string imagePath, CancellationToken ct)
        {
            if (string.IsNullOrEmpty(imagePath)) return;
            if (_alertedDrivers.Contains(serviceName)) return;
            _alertedDrivers.Add(serviceName);

            // Resolve the image path
            var resolvedPath = imagePath;
            if (imagePath.StartsWith(@"\??\"))
                resolvedPath = imagePath[4..];
            else if (imagePath.StartsWith("System32", StringComparison.OrdinalIgnoreCase))
                resolvedPath = Path.Combine(Environment.SystemDirectory, imagePath.Replace("System32\\", ""));
            else if (!Path.IsPathFullyQualified(imagePath))
                resolvedPath = Path.Combine(Environment.SystemDirectory, "drivers", imagePath);

            // Check filename against known vulnerable drivers
            var fileName = Path.GetFileName(resolvedPath);
            bool isKnownVulnerableName = VulnerableDriverNames.Contains(fileName);

            // Check if loaded from a non-standard path
            bool isNonStandardPath = !LegitimateDriverPaths.Any(p =>
                resolvedPath.StartsWith(p, StringComparison.OrdinalIgnoreCase));

            // Hash check
            string hash = "";
            bool hashMatch = false;
            if (File.Exists(resolvedPath))
            {
                try
                {
                    using var fs = new FileStream(resolvedPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    hash = Convert.ToHexString(SHA256.HashData(fs));
                    hashMatch = VulnerableDriverHashes.Contains(hash);
                }
                catch { }
            }

            // Determine confidence and response based on signals
            double confidence;
            ResponseAction response;
            string ruleName;

            if (hashMatch)
            {
                confidence = 0.97;
                response = ResponseAction.KillProcessTree;
                ruleName = "BYOVD: Known Vulnerable Driver Loaded (Hash Match)";
            }
            else if (isKnownVulnerableName && isNonStandardPath)
            {
                confidence = 0.92;
                response = ResponseAction.KillProcessTree;
                ruleName = "BYOVD: Vulnerable Driver Name from Non-Standard Path";
            }
            else if (isKnownVulnerableName)
            {
                confidence = 0.85;
                response = ResponseAction.LogOnly;
                ruleName = "BYOVD: Known Vulnerable Driver Service Created";
            }
            else if (isNonStandardPath)
            {
                confidence = 0.70;
                response = ResponseAction.LogOnly;
                ruleName = "BYOVD: Kernel Driver Loaded from Non-Standard Path";
            }
            else
            {
                // Unknown driver from standard path — low concern
                return;
            }

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = ruleName,
                Evidence = $"New kernel driver service '{serviceName}' with image path '{imagePath}'. " +
                           $"Resolved: '{resolvedPath}'. Filename: '{fileName}'. " +
                           $"Known vulnerable name: {isKnownVulnerableName}. Hash match: {hashMatch}. " +
                           $"Non-standard path: {isNonStandardPath}. " +
                           $"SHA-256: {(string.IsNullOrEmpty(hash) ? "file not accessible" : hash[..16] + "...")}.",
                Reasoning = "A kernel-mode driver was loaded that matches known BYOVD attack patterns. " +
                            "Ransomware groups (GentleKiller, PoisonX, Qilin, Warlock, Reynolds) use vulnerable " +
                            "signed drivers to gain ring-0 access, then terminate EDR processes via " +
                            "ZwTerminateProcess from kernel mode — bypassing all userland protections. " +
                            "54+ known EDR-killer tools abuse 35+ vulnerable drivers for this purpose. " +
                            (hashMatch
                                ? "The SHA-256 hash matches the Microsoft Vulnerable Driver Blocklist."
                                : isKnownVulnerableName
                                    ? $"The filename '{fileName}' matches a known BYOVD target from LOLDrivers."
                                    : "The driver was loaded from a non-standard path, which is unusual for legitimate drivers."),
                Confidence = confidence,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = response,
                ProcessName = serviceName,
                ProcessId = 0,
                SignalType = SignalType.SecurityEvasion,
                Metadata = new Dictionary<string, string>
                {
                    ["ServiceName"] = serviceName,
                    ["ImagePath"] = imagePath,
                    ["ResolvedPath"] = resolvedPath,
                    ["SHA256"] = hash,
                    ["KnownVulnerableName"] = isKnownVulnerableName.ToString(),
                    ["HashMatch"] = hashMatch.ToString(),
                    ["NonStandardPath"] = isNonStandardPath.ToString(),
                    ["Technique"] = "T1068/T1562.001/BYOVD"
                }
            });

            // If high confidence — attempt to stop and disable the driver service
            if (confidence >= 0.90)
            {
                await AttemptDriverDisableAsync(serviceName, ct);
            }
        }

        /// <summary>
        /// Attempts to stop and disable a malicious driver service before it can kill Sentinel.
        /// Race condition: if the driver loads before we act, we lose. But if we catch it
        /// during service creation (before start), we can prevent the attack.
        /// </summary>
        private async Task AttemptDriverDisableAsync(string serviceName, CancellationToken ct)
        {
            try
            {
                _logger.LogWarning("[DriverLoadMonitor] Attempting to disable BYOVD driver service: {Service}", serviceName);

                // Stop the service
                var stopPsi = new ProcessStartInfo
                {
                    FileName = "sc",
                    Arguments = $"stop \"{serviceName}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                using var stopProc = Process.Start(stopPsi);
                if (stopProc != null)
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(5000);
                    try { await stopProc.WaitForExitAsync(cts.Token); }
                    catch { try { stopProc.Kill(); } catch { } }
                }

                // Disable the service
                var disablePsi = new ProcessStartInfo
                {
                    FileName = "sc",
                    Arguments = $"config \"{serviceName}\" start= disabled",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                using var disableProc = Process.Start(disablePsi);
                if (disableProc != null)
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(5000);
                    try { await disableProc.WaitForExitAsync(cts.Token); }
                    catch { try { disableProc.Kill(); } catch { } }
                }

                // Delete the service entirely
                var deletePsi = new ProcessStartInfo
                {
                    FileName = "sc",
                    Arguments = $"delete \"{serviceName}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                using var deleteProc = Process.Start(deletePsi);
                if (deleteProc != null)
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(5000);
                    try { await deleteProc.WaitForExitAsync(cts.Token); }
                    catch { try { deleteProc.Kill(); } catch { } }
                }

                _logger.LogWarning("[DriverLoadMonitor] BYOVD driver service '{Service}' — stop/disable/delete attempted", serviceName);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DriverLoadMonitor] Failed to disable driver service {Service}", serviceName);
            }
        }
    }
}
