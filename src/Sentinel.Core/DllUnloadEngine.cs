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
    /// DLL identity defense — unload on map, not on count.
    ///
    /// Every mapped module is run through <see cref="ModuleIdentity"/>. Foreign
    /// path / user-writable drop / unsigned sideload plant → FreeLibrary APC now
    /// (constraint: DLL unloaders may remediate without a chain).
    /// Disk-only plants with no loader → Tier2 LogOnly.
    /// Games skipped for handle safety only. Never FreeLibrary lsass/csrss/DISM/NTLite.
    ///
    /// SECURITY NOTE (v2.0.4 MED-3): Remote DLL unloading uses QueueUserAPC with FreeLibrary.
    /// Known risks:
    ///   1. Can crash target processes if the DLL has active threads, hooks, or DllMain callbacks
    ///   2. Uses the same APC injection technique that Sentinel detects in other processes
    ///   3. EDR-aware malware can fingerprint this behavior to identify Sentinel's presence
    /// Mitigation: Unload is only attempted for proven-hostile DLLs after Tier1 chain confirmation.
    /// A graceful unload failure does NOT prevent subsequent quarantine+kill of the host process.
    /// </summary>
    public sealed class DllUnloadEngine : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly QuarantineManager _quarantineManager;
        private readonly SignerTrustService _signerTrust;
        private readonly ILogger<DllUnloadEngine> _logger;
        private readonly ConcurrentDictionary<string, DateTimeOffset> _alertHistory = new();
        private readonly ConcurrentDictionary<string, DateTimeOffset> _remediationHistory = new();
        private int _remediationsThisMinute;
        private DateTimeOffset _minuteStart = DateTimeOffset.UtcNow;
        private readonly object _rateLock = new();

        private const int MaxRemediationsPerMinute = 20;

        /// <summary>
        /// Hosts where FreeLibrary is a boot-loop or self-kill. Identity still
        /// applies to explorer/svchost — those are inject targets.
        /// </summary>
        private static readonly HashSet<string> ProtectedProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "system", "smss", "csrss", "wininit", "services", "lsass",
            "dwm", "winlogon", "MsMpEng", "NisSrv",
            "Sentinel.Service", "Sentinel.Agent",
            // OS servicing / imaging — NEVER FreeLibrary/quarantine (NTLite, DISM, Setup)
            "DismHost", "Dism", "TrustedInstaller", "TiWorker", "NTLite",
            "SetupHost", "WUSA", "msiexec", "Setup", "WindowsPackageManagerServer",
            "MoUsoCoreWorker", "UsoClient", "wuauclt", "MusNotification",
        };

        /// <summary>
        /// Paths used by legitimate offline/online servicing (NTLite scratch, CBS, WinSxS, DISM).
        /// Modules here are not "Temp sideload plants".
        /// </summary>
        private static bool IsOsServicingPath(string? path) => ModuleIdentity.IsOsServicingPath(path);

        private static bool IsOsServicingProcess(string processName, string? imagePath)
        {
            if (!string.IsNullOrEmpty(processName) && ProtectedProcessNames.Contains(processName))
            {
                // Only treat the servicing names as protected when path matches OR name is exclusive
                var n = processName;
                if (n.Equals("DismHost", StringComparison.OrdinalIgnoreCase) ||
                    n.Equals("Dism", StringComparison.OrdinalIgnoreCase) ||
                    n.Equals("TrustedInstaller", StringComparison.OrdinalIgnoreCase) ||
                    n.Equals("TiWorker", StringComparison.OrdinalIgnoreCase) ||
                    n.Equals("NTLite", StringComparison.OrdinalIgnoreCase) ||
                    n.Equals("SetupHost", StringComparison.OrdinalIgnoreCase) ||
                    n.Equals("WUSA", StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return IsOsServicingPath(imagePath);
        }

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
        /// Per-process scan used by timers. Observe-first:
        /// - Disk plant only → emit Tier2 LogOnly (no touch).
        /// - Process has loaded hostile Temp/plant module → proven load behavior → remediate.
        /// </summary>
        public Task<DllUnloadResult> CheckAndUnloadAsync(int processId, string processName)
            => ScanProcessAsync(processId, processName, allowRemediateOnProvenLoad: true);

        /// <summary>
        /// Response path after AdvancedResponseEngine Tier1 (already proven malicious chain).
        /// Always remediates hostile modules/plants for that PID.
        /// </summary>
        public async Task<DllUnloadResult> UnloadInjectedDllAsync(int targetPid)
        {
            string name = "";
            try
            {
                using var proc = Process.GetProcessById(targetPid);
                name = proc.ProcessName;
            }
            catch { /* dead */ }

            return await ScanProcessAsync(targetPid, name, allowRemediateOnProvenLoad: true, forceRemediate: true);
        }

        /// <summary>
        /// File drop of sideload-target name outside System32 — observe unless a process
        /// is already loading it (then remediate that host).
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

                // Is any process running from this directory already? That is load risk.
                var hosts = FindProcessIdsFromDirectory(dir);
                if (hosts.Count > 0)
                {
                    // Behavior: plant present AND host process from same dir → scan/remediate hosts
                    foreach (var pid in hosts)
                    {
                        var r = await ScanProcessAsync(pid, "", allowRemediateOnProvenLoad: true);
                        if (r.Success)
                        {
                            result.Success = true;
                            result.UnloadedDlls.AddRange(r.UnloadedDlls);
                            result.ProcessId = pid;
                        }
                    }
                    return result;
                }

                // Disk plant only — observe, do not touch
                var alertKey = $"plant:{dllPath.ToLowerInvariant()}";
                if (_alertHistory.ContainsKey(alertKey)) return result;
                _alertHistory[alertKey] = DateTimeOffset.UtcNow;

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "DLL Sideloading: System-DLL Plant Observed (Disk)",
                    Evidence = $"Hostile sideload-target '{fileName}' written to '{dllPath}' " +
                               $"(writer='{writerName}' PID {writerPid}). No host process loading it yet — LogOnly.",
                    Reasoning = "Observe-first: a plant on disk is a strong staging signal but not proof of execution. " +
                                "Remediation fires when a process loads the plant or a Tier1 chain implicates the host.",
                    Confidence = 0.72,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = writerName ?? "unknown",
                    ProcessId = writerPid,
                    SignalType = SignalType.ProcessInjection,
                    Metadata = new Dictionary<string, string>
                    {
                        ["DllPath"] = dllPath,
                        ["Directory"] = dir,
                        ["Phase"] = "Observe"
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DllUnloadEngine] OnSideloadDllDropped failed for {Path}", dllPath);
            }

            return result;
        }

        public static bool IsSideloadTargetFileName(string? pathOrName)
        {
            if (string.IsNullOrEmpty(pathOrName)) return false;
            return SideloadTargets.Contains(Path.GetFileName(pathOrName));
        }

        /// <param name="allowRemediateOnProvenLoad">
        /// When true, remediates if process has loaded hostile modules (behavior).
        /// </param>
        /// <param name="forceRemediate">
        /// When true (Tier1 response path), remediate disk plants for this PID even if not yet enumerated as loaded.
        /// </param>
        private async Task<DllUnloadResult> ScanProcessAsync(
            int processId,
            string processName,
            bool allowRemediateOnProvenLoad,
            bool forceRemediate = false)
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
                result.ProcessName = name!;

                // Never touch NTLite / DISM / TrustedInstaller / offline servicing hosts.
                // Treating their Temp-scratch modules as "sideload" breaks feature setup (RPC 1722).
                if (IsOsServicingProcess(name!, imagePath))
                    return result;

                if (ProtectedProcessNames.Contains(name!) && IsProtectedPath(imagePath))
                    return result;

                var procDir = Path.GetDirectoryName(imagePath);
                if (ModuleIdentity.IsOsServicingPath(procDir) || ModuleIdentity.IsOsServicingPath(imagePath))
                    return result;

                var hostileDisk = string.IsNullOrEmpty(procDir)
                    ? new List<string>()
                    : FindHostileSideloadDlls(procDir!);
                var hostileLoaded = new List<(string Path, IntPtr Base)>();

                if (NativeProcessMemory.CanInspect(processId, imagePath))
                {
                    foreach (var mod in NativeProcessMemory.EnumModules(processId))
                    {
                        if (string.IsNullOrEmpty(mod.Path)) continue;
                        if (string.Equals(mod.Path, imagePath, StringComparison.OrdinalIgnoreCase))
                            continue;

                        var verdict = ModuleIdentity.Evaluate(
                            imagePath, mod.Path, IsMicrosoftFamilySigned);
                        if (verdict.Allowed) continue;

                        hostileLoaded.Add((mod.Path, mod.Base));
                    }
                }

                // Proven malicious behavior: process loaded hostile DLL(s)
                bool provenLoad = hostileLoaded.Count > 0;

                // Disk plants with no load → observe only
                if (!provenLoad && hostileDisk.Count > 0 && !forceRemediate)
                {
                    var key = $"disk:{processId}:{string.Join("|", hostileDisk.Select(Path.GetFileName))}";
                    if (!_alertHistory.ContainsKey(key))
                    {
                        _alertHistory[key] = DateTimeOffset.UtcNow;
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "DLL Sideloading: Plant Next to Image (Observe)",
                            Evidence = $"Process '{name}' (PID {processId}) image dir has hostile plant(s): " +
                                       string.Join(", ", hostileDisk.Select(Path.GetFileName)) +
                                       " — not loaded yet; LogOnly.",
                            Reasoning = "Observe-first: co-located system-DLL names are staging. " +
                                        "Remediation waits until the process loads them or a Tier1 chain proves malice.",
                            Confidence = 0.70,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = name!,
                            ProcessId = processId,
                            SignalType = SignalType.ProcessInjection,
                            Metadata = new Dictionary<string, string>
                            {
                                ["ImagePath"] = imagePath!,
                                ["Plants"] = string.Join(";", hostileDisk),
                                ["Phase"] = "Observe"
                            }
                        });
                    }
                    return result;
                }

                if (!provenLoad && !forceRemediate)
                    return result;

                // —— Proven: remediate (FreeLibrary → kill host → quarantine) ——
                if (!allowRemediateOnProvenLoad && !forceRemediate)
                    return result;

                var pathsToQuarantine = hostileLoaded.Select(h => h.Path)
                    .Concat(forceRemediate ? hostileDisk : Array.Empty<string>())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (pathsToQuarantine.Count == 0 && provenLoad)
                    pathsToQuarantine = hostileLoaded.Select(h => h.Path).ToList();

                if (pathsToQuarantine.Count == 0) return result;

                bool allUnloaded = hostileLoaded.Count > 0;
                foreach (var (path, bas) in hostileLoaded)
                {
                    if (bas == IntPtr.Zero) { allUnloaded = false; continue; }
                    if (!NativeProcessMemory.TryQueueFreeLibrary(processId, bas))
                        allUnloaded = false;
                    else
                    {
                        for (int i = 0; i < 20; i++)
                        {
                            Thread.Sleep(10);
                            if (!NativeProcessMemory.EnumModules(processId).Any(m => m.Base == bas))
                                break;
                        }
                        if (NativeProcessMemory.EnumModules(processId).Any(m => m.Base == bas))
                            allUnloaded = false;
                    }
                }

                // Kill the host only for a user-writable drop we could not unmap.
                // Failed FreeLibrary of a misclassified OS DLL must not kill
                // Ceprkac / StartMenu / svchost (2.2.5 did that: CLR 80131506).
                bool dropPlant = hostileLoaded.Any(h => ModuleIdentity.IsUserWritableDrop(h.Path));
                if (dropPlant && !allUnloaded)
                {
                    try { HardeningModule.SafeKillProcessTree(processId); }
                    catch
                    {
                        try
                        {
                            using var p = Process.GetProcessById(processId);
                            p.KillTree();
                        }
                        catch { }
                    }
                }

                foreach (var dllPath in pathsToQuarantine)
                {
                    var rkey = $"{processId}:{dllPath.ToLowerInvariant()}";
                    if (_remediationHistory.ContainsKey(rkey)) continue;
                    if (!TryConsumeRateLimit()) break;
                    _remediationHistory[rkey] = DateTimeOffset.UtcNow;
                    await RemediateDroppedDll(dllPath, name!, processId);
                    result.UnloadedDlls.Add(dllPath);
                }

                foreach (var (path, _) in hostileLoaded)
                {
                    if (!result.UnloadedDlls.Contains(path, StringComparer.OrdinalIgnoreCase))
                        result.UnloadedDlls.Add(path);
                }

                result.Success = result.UnloadedDlls.Count > 0;
                if (result.Success)
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "DLL Injection: Foreign Module Unloaded",
                        Evidence = $"Process '{name}' (PID {processId}) loaded hostile DLL(s): " +
                                   string.Join(", ", result.UnloadedDlls) +
                                   $". FreeLibraryAPC={allUnloaded && hostileLoaded.Count > 0}; hostKilled={dropPlant && !allUnloaded}.",
                        Reasoning = "Proven behavior: a mapped module failed path+signer identity " +
                                    "(foreign folder, user-writable drop, or sideload plant). Unloaded immediately (T1055 / T1574.001).",
                        Confidence = 0.90,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly, // already acted
                        ProcessName = name!,
                        ProcessId = processId,
                        SignalType = SignalType.ProcessInjection,
                        Metadata = new Dictionary<string, string>
                        {
                            ["ImagePath"] = imagePath!,
                            ["SideloadedDlls"] = string.Join(";", result.UnloadedDlls),
                            ["Phase"] = "Remediate"
                        }
                    });
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DllUnloadEngine] ScanProcess failed for PID {Pid}", processId);
                return result;
            }
        }

        private List<string> FindHostileSideloadDlls(string directory)
        {
            var found = new List<string>();
            try
            {
                foreach (var target in SideloadTargets)
                {
                    var path = Path.Combine(directory, target);
                    if (File.Exists(path) && IsHostileSideloadDll(path))
                        found.Add(path);
                }
            }
            catch { }
            return found;
        }

        private bool IsHostileSideloadDll(string dllPath)
        {
            try
            {
                if (ModuleIdentity.IsUserWritableDrop(dllPath))
                    return true;
                return !IsMicrosoftFamilySigned(dllPath);
            }
            catch
            {
                return true;
            }
        }

        private bool IsMicrosoftFamilySigned(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            if (!_signerTrust.IsSignedFile(path)) return false;
            var signer = _signerTrust.GetSignerName(path) ?? "";
            return signer.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0
                   || signer.IndexOf("Windows", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private List<int> FindProcessIdsFromDirectory(string directory)
        {
            var list = new List<int>();
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
                        if (!pDir.TrimEnd('\\').Equals(directory.TrimEnd('\\')))
                            continue;
                        list.Add(proc.Id);
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch { }
            return list;
        }

        private async Task RemediateDroppedDll(string dllPath, string processName, int processId)
        {
            try
            {
                await Task.Delay(150);
                if (File.Exists(dllPath))
                    await _quarantineManager.QuarantineFileAtomicAsync(dllPath, forceQuarantineSigned: true);

                try
                {
                    if (!File.Exists(dllPath))
                        await System.IO.FileNet48.WriteAllBytesAsync(dllPath, Array.Empty<byte>());
                    File.SetAttributes(dllPath,
                        FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System);
                }
                catch { }

                _logger.LogInformation(
                    "[DllUnloadEngine] Quarantined '{Dll}' (host {Name} PID {Pid})",
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
            var cutoff = DateTimeOffset.UtcNow.AddHours(-1);
            foreach (var kv in _alertHistory)
                if (kv.Value < cutoff) _alertHistory.TryRemove(kv.Key, out _);
            foreach (var kv in _remediationHistory)
                if (kv.Value < cutoff) _remediationHistory.TryRemove(kv.Key, out _);
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
            return path!.StartsWith(@"C:\Windows\") ||
                   path.StartsWith(@"C:\Program Files") ||
                   path.Contains(@"\AppData\Local\Google\") ||
                   path.Contains(@"\AppData\Local\Microsoft\") ||
                   path.Contains(@"\AppData\Local\Programs\") ||
                   path.Contains(@"\Sentinel");
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
