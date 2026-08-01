using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// System-wide + per-process DLL sideload defense.
    ///
    /// Design (AV-safe + anti-cheat-safe):
    /// - Detection is <b>disk-path based</b>: known system DLL names planted next to
    ///   an application executable (Windows DLL search-order hijack, T1574.001).
    /// - Never uses Process.Modules / PROCESS_VM_READ (kills Denuvo games; AV FPs).
    /// - Never uses CreateRemoteThread / QueueUserAPC FreeLibrary (Sophos Mal/MSIL-AZ).
    /// - "Unload" = terminate host process (releases the module mapping) + quarantine
    ///   the planted DLL from disk + place a lock file so it cannot be re-dropped.
    ///
    /// Coverage:
    /// 1. Per-process: <see cref="CheckAndUnloadAsync"/> on each PID (timer + response).
    /// 2. System-wide: driven by MemoryBehaviorAnalyzer over all processes +
    ///    <see cref="OnSideloadDllDroppedAsync"/> from FileActivityMonitor on create/write.
    /// 3. Response path: <see cref="UnloadInjectedDllAsync"/> after Tier1 injection alerts.
    /// </summary>
    public sealed class DllUnloadEngine : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly QuarantineManager _quarantineManager;
        private readonly SignerTrustService _signerTrust;
        private readonly ILogger<DllUnloadEngine> _logger;
        private readonly ConcurrentDictionary<string, DateTimeOffset> _remediationHistory = new();
        private int _remediationsThisMinute;
        private DateTimeOffset _minuteStart = DateTimeOffset.UtcNow;
        private readonly object _rateLock = new();

        private const int MaxRemediationsPerMinute = 20;

        private static readonly HashSet<string> ProtectedProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "system", "smss", "csrss", "wininit", "services", "lsass", "svchost",
            "explorer", "dwm", "winlogon", "MsMpEng", "NisSrv",
            "Sentinel.Service", "Sentinel.Agent",
        };

        /// <summary>
        /// Classic DLL search-order hijack targets (system DLL names planted in app folders).
        /// </summary>
        public static readonly HashSet<string> SideloadTargets = new(StringComparer.OrdinalIgnoreCase)
        {
            "dbghelp.dll", "version.dll", "winmm.dll", "dwrite.dll",
            "cryptsp.dll", "userenv.dll", "profapi.dll", "wtsapi32.dll",
            "dhcpcsvc.dll", "iphlpapi.dll", "msasn1.dll", "netapi32.dll",
            "samcli.dll", "sspicli.dll", "crypt32.dll", "textshaping.dll",
            "winhttp.dll", "urlmon.dll", "propsys.dll", "dwmapi.dll",
        };

        public DllUnloadEngine(
            DetectionEngine de,
            QuarantineManager qm,
            ILogger<DllUnloadEngine> l,
            SignerTrustService? signerTrust = null)
        {
            _detectionEngine = de;
            _quarantineManager = qm;
            _logger = l;
            _signerTrust = signerTrust ?? new SignerTrustService(
                new Microsoft.Extensions.Logging.Abstractions.NullLogger<SignerTrustService>());
        }

        /// <summary>
        /// Per-process check: inspect the process image directory on disk for planted
        /// sideload-target DLLs. If found and hostile, unload (kill host) + quarantine.
        /// Safe for anti-cheat (QUERY_LIMITED path only).
        /// </summary>
        public async Task<DllUnloadResult> CheckAndUnloadAsync(int processId, string processName)
        {
            var result = new DllUnloadResult { ProcessId = processId, ProcessName = processName ?? "" };
            if (processId <= 4) return result;

            try
            {
                var imagePath = SecurityValidation.GetProcessImagePath(processId);
                if (string.IsNullOrEmpty(imagePath)) return result;

                if (SecurityValidation.IsGameOrAntiCheatPath(imagePath))
                    return result;

                var name = string.IsNullOrEmpty(processName)
                    ? (Path.GetFileNameWithoutExtension(imagePath) ?? "")
                    : processName;
                result.ProcessName = name;

                if (ProtectedProcessNames.Contains(name) && IsProtectedPath(imagePath))
                    return result;

                var procDir = Path.GetDirectoryName(imagePath);
                if (string.IsNullOrEmpty(procDir) || IsWindowsSystemDirectory(procDir))
                    return result;

                var hostile = FindHostileSideloadDlls(procDir);
                if (hostile.Count == 0) return result;

                return await RemediateProcessAndDllsAsync(processId, name, imagePath, hostile, "PerProcessScan");
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DllUnloadEngine] CheckAndUnload failed for PID {Pid}", processId);
                return result;
            }
        }

        /// <summary>
        /// Response-path remediation after an independent injection/sideload detection.
        /// Same disk-based unload model; never opens process memory.
        /// </summary>
        public async Task<DllUnloadResult> UnloadInjectedDllAsync(int targetPid)
        {
            try
            {
                using var proc = Process.GetProcessById(targetPid);
                return await CheckAndUnloadAsync(targetPid, proc.ProcessName);
            }
            catch
            {
                return await CheckAndUnloadAsync(targetPid, "");
            }
        }

        /// <summary>
        /// System-wide file-drop path: a known sideload-target DLL was written/created.
        /// Quarantines the DLL and kills any process whose image lives in that directory.
        /// </summary>
        public async Task<DllUnloadResult> OnSideloadDllDroppedAsync(string dllPath, int writerPid = 0, string? writerName = null)
        {
            var result = new DllUnloadResult { ProcessId = writerPid, ProcessName = writerName ?? "" };
            if (string.IsNullOrEmpty(dllPath) || !File.Exists(dllPath)) return result;

            try
            {
                var fileName = Path.GetFileName(dllPath);
                if (!SideloadTargets.Contains(fileName)) return result;

                var dir = Path.GetDirectoryName(dllPath);
                if (string.IsNullOrEmpty(dir) || IsWindowsSystemDirectory(dir)) return result;
                if (SecurityValidation.IsGameOrAntiCheatPath(dllPath)) return result;

                if (!IsHostileSideloadDll(dllPath)) return result;

                var key = $"drop:{dllPath.ToLowerInvariant()}";
                if (_remediationHistory.ContainsKey(key)) return result;
                if (!TryConsumeRateLimit()) return result;
                _remediationHistory[key] = DateTimeOffset.UtcNow;

                // Kill any process running from this directory (likely the sideload host)
                var killed = KillProcessesFromDirectory(dir);
                result.ProcessId = writerPid > 0 ? writerPid : (killed.FirstOrDefault());
                result.ProcessName = writerName ?? "";

                await RemediateDroppedDll(dllPath, result.ProcessName, result.ProcessId);
                result.UnloadedDlls.Add(dllPath);
                result.Success = true;

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "DLL Sideloading: Hostile System-DLL Plant Detected",
                    Evidence = $"Sideload-target DLL '{fileName}' written to '{dllPath}' " +
                               $"(writer='{writerName}' PID {writerPid}). " +
                               $"Quarantined; killed {killed.Count} host process(es) from '{dir}'.",
                    Reasoning = "Attackers plant system-named DLLs beside applications so Windows loads " +
                                "the local copy instead of System32 (T1574.001). The host process was " +
                                "terminated to unload the mapping and the plant was quarantined.",
                    Confidence = 0.90,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly, // already remediated
                    ProcessName = writerName ?? "unknown",
                    ProcessId = writerPid,
                    SignalType = SignalType.ProcessInjection,
                    Metadata = new Dictionary<string, string>
                    {
                        ["DllPath"] = dllPath,
                        ["Directory"] = dir,
                        ["KilledPids"] = string.Join(",", killed),
                        ["Action"] = "KILL_HOST_AND_QUARANTINE"
                    }
                });

                _logger.LogWarning(
                    "[DllUnloadEngine] System-wide plant remediated: {Dll} (writer PID {Pid})",
                    dllPath, writerPid);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DllUnloadEngine] OnSideloadDllDropped failed for {Path}", dllPath);
            }

            return result;
        }

        /// <summary>
        /// True if the file name is a classic sideload target (for FileActivityMonitor gate).
        /// </summary>
        public static bool IsSideloadTargetFileName(string? pathOrName)
        {
            if (string.IsNullOrEmpty(pathOrName)) return false;
            var name = Path.GetFileName(pathOrName);
            return SideloadTargets.Contains(name);
        }

        private async Task<DllUnloadResult> RemediateProcessAndDllsAsync(
            int processId,
            string processName,
            string imagePath,
            List<string> hostileDlls,
            string source)
        {
            var result = new DllUnloadResult
            {
                ProcessId = processId,
                ProcessName = processName
            };

            var actionable = new List<string>();
            foreach (var dll in hostileDlls)
            {
                var key = $"{processId}:{dll.ToLowerInvariant()}";
                if (_remediationHistory.ContainsKey(key)) continue;
                if (!TryConsumeRateLimit()) break;
                _remediationHistory[key] = DateTimeOffset.UtcNow;
                actionable.Add(dll);
            }

            if (actionable.Count == 0) return result;

            // Unload = kill host so Windows unmaps the DLL, then quarantine on disk
            try
            {
                HardeningModule.SafeKillProcessTree(processId);
            }
            catch
            {
                try
                {
                    using var proc = Process.GetProcessById(processId);
                    proc.Kill(entireProcessTree: true);
                }
                catch { /* already dead */ }
            }

            foreach (var dllPath in actionable)
            {
                await RemediateDroppedDll(dllPath, processName, processId);
                result.UnloadedDlls.Add(dllPath);
            }

            result.Success = true;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "DLL Sideloading: Malicious DLL Unloaded (Host Killed + Quarantined)",
                Evidence = $"Process '{processName}' (PID {processId}) image '{imagePath}' co-located with " +
                           $"hostile sideload DLL(s): {string.Join(", ", actionable.Select(Path.GetFileName))}. " +
                           $"Host terminated; DLLs quarantined. Source={source}.",
                Reasoning = "System-named DLLs in the application directory indicate DLL search-order " +
                            "hijacking (T1574.001). The process was killed to unload the mapped modules " +
                            "and the plants were removed from disk.",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = processName,
                ProcessId = processId,
                SignalType = SignalType.ProcessInjection,
                Metadata = new Dictionary<string, string>
                {
                    ["ImagePath"] = imagePath,
                    ["SideloadedDlls"] = string.Join(";", actionable),
                    ["Source"] = source,
                    ["Action"] = "KILL_HOST_AND_QUARANTINE"
                }
            });

            _logger.LogWarning(
                "[DllUnloadEngine] Unloaded sideload host {Name} PID {Pid}: {Dlls}",
                processName, processId, string.Join(", ", actionable.Select(Path.GetFileName)));

            return result;
        }

        private List<string> FindHostileSideloadDlls(string directory)
        {
            var found = new List<string>();
            try
            {
                foreach (var target in SideloadTargets)
                {
                    var path = Path.Combine(directory, target);
                    if (!File.Exists(path)) continue;
                    if (IsHostileSideloadDll(path))
                        found.Add(path);
                }
            }
            catch { /* access denied */ }
            return found;
        }

        /// <summary>
        /// Hostile if: unsigned, or signed by a non-Microsoft publisher, or in Temp/Downloads.
        /// Microsoft-redistributed dbghelp next to crash-reporting apps is allowed.
        /// </summary>
        private bool IsHostileSideloadDll(string dllPath)
        {
            try
            {
                var lower = dllPath.ToLowerInvariant();
                if (lower.Contains(@"\temp\") ||
                    lower.Contains(@"\downloads\") ||
                    lower.Contains(@"\appdata\local\temp\"))
                    return true;

                if (!_signerTrust.IsSignedFile(dllPath))
                    return true;

                var signer = _signerTrust.GetSignerName(dllPath) ?? "";
                // Allow genuine Microsoft redistributables of system DLL names
                if (signer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                    signer.Contains("Windows", StringComparison.OrdinalIgnoreCase))
                    return false;

                // Third-party signature on a system DLL name next to an app = hostile plant
                return true;
            }
            catch
            {
                return true; // fail closed for sideload targets outside System32
            }
        }

        private List<int> KillProcessesFromDirectory(string directory)
        {
            var killed = new List<int>();
            var dirNorm = directory.TrimEnd('\\') + "\\";
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (proc.Id <= 4) continue;
                        var path = SecurityValidation.GetProcessImagePath(proc.Id);
                        if (string.IsNullOrEmpty(path)) continue;
                        if (SecurityValidation.IsGameOrAntiCheatPath(path)) continue;

                        var pDir = Path.GetDirectoryName(path);
                        if (string.IsNullOrEmpty(pDir)) continue;
                        if (!pDir.TrimEnd('\\').Equals(directory.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                            continue;

                        var name = proc.ProcessName;
                        if (ProtectedProcessNames.Contains(name) && IsProtectedPath(path))
                            continue;

                        try { HardeningModule.SafeKillProcessTree(proc.Id); }
                        catch
                        {
                            try { proc.Kill(entireProcessTree: true); } catch { }
                        }
                        killed.Add(proc.Id);
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch { }
            return killed;
        }

        private async Task RemediateDroppedDll(string dllPath, string processName, int processId)
        {
            try
            {
                await Task.Delay(150); // let killed host release handles

                if (File.Exists(dllPath))
                {
                    // force: plants may carry stolen/forged signatures in context of sideload
                    await _quarantineManager.QuarantineFileAtomicAsync(dllPath, forceQuarantineSigned: true);
                }

                // Lock file: zero-byte read-only decoy blocks re-drop
                try
                {
                    if (!File.Exists(dllPath))
                        await File.WriteAllBytesAsync(dllPath, Array.Empty<byte>());
                    File.SetAttributes(dllPath,
                        FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System);
                }
                catch
                {
                    // best-effort
                }

                _logger.LogInformation(
                    "[DllUnloadEngine] Quarantined '{Dll}' (host {Name} PID {Pid}), lock placed",
                    dllPath, processName, processId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[DllUnloadEngine] Failed to quarantine '{Dll}'", dllPath);
            }
        }

        private bool TryConsumeRateLimit()
        {
            lock (_rateLock)
            {
                var now = DateTimeOffset.UtcNow;
                if ((now - _minuteStart).TotalMinutes >= 1)
                {
                    _minuteStart = now;
                    _remediationsThisMinute = 0;
                }
                if (_remediationsThisMinute >= MaxRemediationsPerMinute) return false;
                _remediationsThisMinute++;
                return true;
            }
        }

        public void Dispose()
        {
            // Prune old history entries older than 1 hour
            var cutoff = DateTimeOffset.UtcNow.AddHours(-1);
            foreach (var kv in _remediationHistory)
            {
                if (kv.Value < cutoff)
                    _remediationHistory.TryRemove(kv.Key, out _);
            }
        }

        private static bool IsWindowsSystemDirectory(string directory)
        {
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var lower = directory.ToLowerInvariant();
            return lower.StartsWith((win + @"\system32").ToLowerInvariant()) ||
                   lower.StartsWith((win + @"\syswow64").ToLowerInvariant()) ||
                   lower.StartsWith((win + @"\winsxs").ToLowerInvariant()) ||
                   lower.StartsWith((win + @"\servicing").ToLowerInvariant());
        }

        private static bool IsProtectedPath(string? path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            return path.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase) ||
                   path.StartsWith(@"C:\Program Files", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\AppData\Local\Google\", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\AppData\Local\Microsoft\", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\AppData\Local\BraveSoftware\", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\AppData\Local\Programs\", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\Sentinel", StringComparison.OrdinalIgnoreCase);
        }
    }

    public sealed class DllUnloadResult
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public bool Success { get; set; }
        public List<string> UnloadedDlls { get; set; } = new();
    }
}
