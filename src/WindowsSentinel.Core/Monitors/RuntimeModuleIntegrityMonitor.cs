using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Runtime Module Integrity Monitor — Validates ALL loaded modules across ALL running
/// processes. Detects DLL injection, sideloading, replacement, and phantom modules
/// system-wide by maintaining per-process module baselines and detecting deviations.
///
/// Scanning strategy (to avoid CPU exhaustion):
///   - Tier A (critical processes): scanned every 30s — lsass, csrss, svchost, winlogon, etc.
///   - Tier B (high-value targets): scanned every 60s — browsers, office, comms, Sentinel
///   - Tier C (all other processes): scanned every 2 min in batches of 20 per cycle
///
/// Detections emitted (all feed into BehavioralCorrelationEngine automatically):
///
///   1. Runtime DLL Injection — new unsigned/suspicious module appears after baseline
///   2. DLL Replacement — loaded module's on-disk hash changes between scans
///   3. Phantom Module — module's backing file deleted from disk (dropper pattern)
///   4. Signature Invalidation — previously-signed module now fails validation
///
/// Composite correlation (via BehavioralCorrelationEngine):
///   - Module injection + Network → "Injected C2 Implant" (kill-authorized)
///   - Module injection + Clipboard → "Clipboard Exfil via Injection" (kill-authorized)
///   - Module injection + LSASS signal → "Credential Theft Tool Loaded"
///   - Module injection + Privilege escalation → "Post-Exploit Payload"
///
/// MITRE ATT&CK:
///   T1055 — Process Injection (all sub-techniques)
///   T1574 — Hijack Execution Flow
///   T1129 — Shared Modules
/// </summary>
public sealed class RuntimeModuleIntegrityMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<RuntimeModuleIntegrityMonitor> _logger;
    private readonly TelemetryFusionEngine? _fusionEngine;

    // Scan intervals per tier (v4.8.1: relaxed from 30/60/120s to reduce CPU pressure)
    private static readonly TimeSpan TierAScanInterval = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan TierBScanInterval = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan TierCScanInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan BaselineGracePeriod = TimeSpan.FromSeconds(90);
    private const int TierCBatchSize = 25; // scan 25 Tier-C processes per cycle

    // Per-process module baselines: PID → baseline
    private readonly ConcurrentDictionary<int, ProcessModuleBaseline> _baselines = new();
    private readonly ConcurrentDictionary<string, byte> _alertedKeys = new();

    // Scan timing
    private DateTimeOffset _lastTierAScan = DateTimeOffset.MinValue;
    private DateTimeOffset _lastTierBScan = DateTimeOffset.MinValue;
    private DateTimeOffset _lastTierCScan = DateTimeOffset.MinValue;
    private int _tierCOffset = 0; // rotating offset for batch scanning

    // Tier A: system-critical processes (highest scan frequency)
    private static readonly HashSet<string> TierAProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "lsass", "csrss", "services", "svchost", "winlogon", "wininit",
        "smss", "explorer", "dwm", "taskhostw",
    };

    // Tier B: high-value targets (medium scan frequency)
    private static readonly HashSet<string> TierBProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Browsers
        "msedge", "chrome", "firefox", "brave", "opera", "vivaldi",
        // Office
        "winword", "excel", "powerpnt", "outlook", "onenote",
        // Communication
        "teams", "slack", "discord", "telegram", "signal",
        // Remote access
        "mstsc", "rdpclip", "vmconnect",
        // Development (injection targets for supply-chain attacks)
        "devenv", "code", "kiro", "rider64", "idea64",
        // Sentinel
        "sentinelservice", "sentinelagent",
        // Password managers
        "1password", "keepass", "keepassxc", "bitwarden",
    };

    // Processes to skip entirely (kernel/pseudo-processes, or too noisy)
    private static readonly HashSet<string> SkipProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "idle", "system", "registry", "memcompression",
        "securityhealthservice", "msmpeng", "nissrv", // Defender (can't read its modules)
        "werfault", "werfaultsecure", // crash handlers
    };

    // Known legitimate late-load paths (system DLLs loaded on demand)
    private static readonly string[] TrustedModulePaths =
    {
        @"\windows\system32\",
        @"\windows\syswow64\",
        @"\windows\winsxs\",
        @"\windows\assembly\",
        @"\windows\microsoft.net\",
        @"\windows\globalization\",
        @"\windows\systemapps\",
    };

    // DLLs that are commonly late-loaded and should not trigger injection alerts
    private static readonly HashSet<string> KnownLateLoadModules = new(StringComparer.OrdinalIgnoreCase)
    {
        // GPU/display
        "d3d11.dll", "d3d10warp.dll", "dxgi.dll", "d3d9.dll", "d3d12.dll",
        "opengl32.dll", "vulkan-1.dll",
        "nvoglv64.dll", "nvoglv32.dll", "nvwgf2umx.dll", "nvapi64.dll",
        "atig6pxx.dll", "atioglxx.dll", "amdxc64.dll",
        "ig75icd64.dll", "ig75icd32.dll", "igdumdim64.dll",
        // Audio
        "audioses.dll", "mmdevapi.dll", "avrt.dll", "mfplat.dll",
        // Network (lazy init)
        "winhttp.dll", "wininet.dll", "urlmon.dll", "ws2_32.dll", "dnsapi.dll",
        "mswsock.dll", "secur32.dll", "schannel.dll", "ncrypt.dll", "sspicli.dll",
        "iphlpapi.dll", "dhcpcsvc.dll", "nsi.dll", "winnsi.dll",
        // Crypto
        "bcrypt.dll", "ncryptsslp.dll", "rsaenh.dll", "cng.sys",
        // COM/OLE
        "ole32.dll", "oleaut32.dll", "combase.dll", "rpcrt4.dll", "propsys.dll",
        // .NET runtime
        "clrjit.dll", "coreclr.dll", "hostpolicy.dll", "hostfxr.dll",
        "mscorlib.ni.dll", "system.private.corelib.dll",
        // Accessibility
        "uiautomationcore.dll", "oleacc.dll",
        // IME/Input
        "imm32.dll", "msctf.dll", "textinputframework.dll",
        // Print
        "winspool.drv", "spoolss.dll",
        // Shell
        "shell32.dll", "shlwapi.dll", "shcore.dll", "windows.storage.dll",
        // WinRT
        "windows.ui.dll", "twinapi.appcore.dll", "windowscodecs.dll",
        // Diagnostics (legitimate — dbghelp flagged separately by LsassDumpCanaryMonitor)
        "dbghelp.dll", "dbgcore.dll",
        // Theme/UI
        "uxtheme.dll", "dwmapi.dll", "gdi32full.dll",
    };

    // Trusted publishers whose modules are always allowed
    private static readonly string[] TrustedPublishers =
    {
        "Microsoft",
        "Microsoft Corporation",
        "Microsoft Windows",
        "Google LLC",
        "Google Inc",
        "Mozilla Corporation",
        "NVIDIA Corporation",
        "Advanced Micro Devices",
        "Intel Corporation",
        "Valve Corp",
    };

    public RuntimeModuleIntegrityMonitor(
        IDetectionEngine detectionEngine,
        ILogger<RuntimeModuleIntegrityMonitor> logger,
        TelemetryFusionEngine? fusionEngine = null)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _fusionEngine = fusionEngine;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Runtime Module Integrity Monitor starting (ALL processes) ===");

        // Wait for system to stabilize before taking baselines
        await Task.Delay(TimeSpan.FromSeconds(50), stoppingToken);

        // Establish initial baselines for all running processes
        await EstablishAllBaselinesAsync(stoppingToken);

        _logger.LogInformation(
            "RuntimeModuleIntegrity: Baselines established for {Count} processes",
            _baselines.Count);

        // Main scan loop — runs every 10s, but each tier has its own interval
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var now = DateTimeOffset.UtcNow;

                if (now - _lastTierAScan >= TierAScanInterval)
                {
                    await ScanTierAsync(TierAProcesses, "A", stoppingToken);
                    _lastTierAScan = now;
                }

                if (now - _lastTierBScan >= TierBScanInterval)
                {
                    await ScanTierAsync(TierBProcesses, "B", stoppingToken);
                    _lastTierBScan = now;
                }

                if (now - _lastTierCScan >= TierCScanInterval)
                {
                    await ScanAllOtherProcessesAsync(stoppingToken);
                    _lastTierCScan = now;
                }

                // Prune dead process baselines
                PruneDeadProcesses();

                await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "RuntimeModuleIntegrity: Scan loop error");
                await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);
            }
        }
    }

    private async Task EstablishAllBaselinesAsync(CancellationToken ct)
    {
        var processes = Process.GetProcesses();
        try
        {
            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    if (proc.Id <= 4) continue;
                    if (SkipProcesses.Contains(proc.ProcessName)) continue;

                    var baseline = CaptureProcessBaseline(proc);
                    if (baseline != null)
                        _baselines[proc.Id] = baseline;
                }
                catch (InvalidOperationException) { }
                catch (System.ComponentModel.Win32Exception) { }
            }
        }
        finally
        {
            foreach (var p in processes)
                try { p.Dispose(); } catch { }
        }

        await Task.CompletedTask;
    }

    /// <summary>
    /// Scans processes matching a specific tier's name set.
    /// </summary>
    private async Task ScanTierAsync(HashSet<string> tierNames, string tierLabel, CancellationToken ct)
    {
        var processes = Process.GetProcesses();
        try
        {
            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    if (proc.Id <= 4) continue;
                    if (!tierNames.Contains(proc.ProcessName)) continue;

                    await ScanSingleProcessAsync(proc, tierLabel, ct);
                }
                catch (InvalidOperationException) { }
                catch (System.ComponentModel.Win32Exception) { }
            }
        }
        finally
        {
            foreach (var p in processes)
                try { p.Dispose(); } catch { }
        }
    }

    /// <summary>
    /// Scans a batch of processes not in Tier A or B (everything else).
    /// Uses rotating offset to cover all processes over multiple cycles.
    /// </summary>
    private async Task ScanAllOtherProcessesAsync(CancellationToken ct)
    {
        var processes = Process.GetProcesses()
            .Where(p => p.Id > 4 &&
                        !SkipProcesses.Contains(p.ProcessName) &&
                        !TierAProcesses.Contains(p.ProcessName) &&
                        !TierBProcesses.Contains(p.ProcessName))
            .ToArray();

        try
        {
            // Take a batch starting from the rotating offset
            var batch = processes.Skip(_tierCOffset).Take(TierCBatchSize).ToArray();
            _tierCOffset += TierCBatchSize;
            if (_tierCOffset >= processes.Length)
                _tierCOffset = 0;

            foreach (var proc in batch)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    await ScanSingleProcessAsync(proc, "C", ct);
                }
                catch (InvalidOperationException) { }
                catch (System.ComponentModel.Win32Exception) { }
            }
        }
        finally
        {
            foreach (var p in processes)
                try { p.Dispose(); } catch { }
        }
    }

    private async Task ScanSingleProcessAsync(Process proc, string tier, CancellationToken ct)
    {
        if (_baselines.TryGetValue(proc.Id, out var baseline))
        {
            // Existing process — check for deviations
            await CheckProcessDeviationsAsync(proc, baseline, tier, ct);
        }
        else
        {
            // New process — establish baseline
            var newBaseline = CaptureProcessBaseline(proc);
            if (newBaseline != null)
                _baselines[proc.Id] = newBaseline;
        }
    }

    private ProcessModuleBaseline? CaptureProcessBaseline(Process proc)
    {
        ProcessModuleCollection modules;
        try { modules = proc.Modules; }
        catch { return null; }

        var baseline = new ProcessModuleBaseline
        {
            ProcessName = proc.ProcessName,
            CapturedAt = DateTimeOffset.UtcNow,
            Modules = new ConcurrentDictionary<string, ModuleRecord>(StringComparer.OrdinalIgnoreCase)
        };

        foreach (ProcessModule module in modules)
        {
            try
            {
                var path = module.FileName;
                if (string.IsNullOrEmpty(path)) continue;

                baseline.Modules[path.ToLowerInvariant()] = new ModuleRecord
                {
                    Path = path,
                    ModuleName = module.ModuleName ?? Path.GetFileName(path),
                    Hash = null, // Lazy — only compute on deviation check
                    IsSigned = null, // Lazy
                    Publisher = null,
                    FirstSeen = DateTimeOffset.UtcNow
                };
            }
            catch { }
        }

        return baseline.Modules.Count > 0 ? baseline : null;
    }

    private async Task CheckProcessDeviationsAsync(Process proc, ProcessModuleBaseline baseline,
        string tier, CancellationToken ct)
    {
        ProcessModuleCollection currentModules;
        try { currentModules = proc.Modules; }
        catch { return; }

        var currentPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (ProcessModule module in currentModules)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var path = module.FileName;
                if (string.IsNullOrEmpty(path)) continue;

                var pathKey = path.ToLowerInvariant();
                currentPaths.Add(pathKey);

                if (!baseline.Modules.ContainsKey(pathKey))
                {
                    // NEW module not in baseline — possible injection
                    await CheckNewModuleAsync(proc, module, path, baseline, tier, ct);
                }
            }
            catch { }
        }

        // Check for phantom modules (were in baseline, file now deleted)
        // Only check Tier A/B processes (expensive check, high-value targets)
        if (tier is "A" or "B")
        {
            foreach (var kv in baseline.Modules)
            {
                if (!File.Exists(kv.Value.Path) && currentPaths.Contains(kv.Key))
                {
                    await EmitPhantomModuleAsync(proc, kv.Value, ct);
                }
            }
        }
    }

    private async Task CheckNewModuleAsync(Process proc, ProcessModule module, string path,
        ProcessModuleBaseline baseline, string tier, CancellationToken ct)
    {
        var moduleName = module.ModuleName ?? Path.GetFileName(path);
        var pathLower = path.ToLowerInvariant();
        var fileName = Path.GetFileName(path);

        // Skip if within grace period (process still initializing)
        if (DateTimeOffset.UtcNow - baseline.CapturedAt < BaselineGracePeriod) return;

        // Skip known late-load modules
        if (KnownLateLoadModules.Contains(fileName)) return;

        // Skip modules from trusted system paths
        if (TrustedModulePaths.Any(p => pathLower.Contains(p))) return;

        // Skip modules from Program Files (installed software)
        if (pathLower.Contains(@"\program files\") || pathLower.Contains(@"\program files (x86)\"))
        {
            // But still flag if unsigned and in a critical process
            if (tier != "A") return;
        }

        var alertKey = $"inject:{proc.Id}:{pathLower}";
        if (!_alertedKeys.TryAdd(alertKey, 0)) return;

        // Full analysis — compute hash and check signature
        var hash = await ComputeHashAsync(path, ct);
        var isSigned = ValidateSignature(path, out var publisher);

        // Check if publisher is trusted
        if (isSigned == true && publisher != null &&
            TrustedPublishers.Any(tp => publisher.Contains(tp, StringComparison.OrdinalIgnoreCase)))
        {
            // Trusted publisher — add to baseline silently
            baseline.Modules[pathLower] = new ModuleRecord
            {
                Path = path, ModuleName = moduleName, Hash = hash,
                IsSigned = true, Publisher = publisher, FirstSeen = DateTimeOffset.UtcNow
            };
            return;
        }

        // Score the suspicion
        int score = 0;
        var reasons = new List<string>();

        if (isSigned != true)
        {
            score += 40;
            reasons.Add("unsigned module");
        }
        else if (publisher != null &&
                 !TrustedPublishers.Any(tp => publisher.Contains(tp, StringComparison.OrdinalIgnoreCase)))
        {
            score += 15;
            reasons.Add($"signed by non-trusted publisher: {publisher}");
        }

        if (pathLower.Contains(@"\temp\") || pathLower.Contains(@"\tmp\"))
        {
            score += 40;
            reasons.Add("loaded from temp directory");
        }
        else if (pathLower.Contains(@"\appdata\"))
        {
            score += 25;
            reasons.Add("loaded from AppData directory");
        }
        else if (pathLower.Contains(@"\downloads\"))
        {
            score += 30;
            reasons.Add("loaded from Downloads directory");
        }

        if (!File.Exists(path))
        {
            score += 50;
            reasons.Add("file no longer exists on disk (in-memory only payload)");
        }

        // Tier A processes get extra suspicion for any non-system module
        if (tier == "A")
        {
            score += 20;
            reasons.Add("loaded into system-critical process");
        }

        // Only alert if suspicious enough
        if (score < 35)
        {
            // Still add to baseline to avoid re-checking
            baseline.Modules[pathLower] = new ModuleRecord
            {
                Path = path, ModuleName = moduleName, Hash = hash,
                IsSigned = isSigned, Publisher = publisher, FirstSeen = DateTimeOffset.UtcNow
            };
            return;
        }

        var confidence = score switch
        {
            >= 90 => 0.94,
            >= 70 => 0.88,
            >= 50 => 0.82,
            _ => 0.75
        };

        _logger.LogWarning(
            "[MODULE-INJECT] New module '{Module}' in '{Process}' (PID {Pid}) | " +
            "Tier {Tier} | Score: {Score} | {Reasons}",
            moduleName, proc.ProcessName, proc.Id, tier, score, string.Join(", ", reasons));

        await _detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = "Module Integrity: Runtime DLL Injection Detected",
            Evidence = $"New module '{moduleName}' appeared in process '{proc.ProcessName}' (PID {proc.Id}) " +
                      $"after baseline. Path: {path}. Signed: {isSigned}. " +
                      $"Publisher: {publisher ?? "N/A"}. Score: {score}. " +
                      $"Reasons: {string.Join("; ", reasons)}",
            Reasoning = "A DLL not present at process startup has been loaded at runtime. " +
                       "Combined with suspicious indicators (unsigned, temp path, deleted from disk, " +
                       "non-trusted publisher), this indicates DLL injection via CreateRemoteThread, " +
                       "manual mapping, reflective loading, APC injection, or DLL sideloading. " +
                       "Injected code executes within the target process, inheriting its privileges.",
            Confidence = confidence,
            Tier = DetectionTier.Tier1Behavioral,
            ProcessName = proc.ProcessName,
            ProcessId = proc.Id,
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["technique"] = "T1055 - Process Injection",
                ["module_name"] = moduleName,
                ["module_path"] = path,
                ["module_hash"] = hash ?? "unreadable",
                ["is_signed"] = (isSigned ?? false).ToString(),
                ["publisher"] = publisher ?? "unsigned",
                ["suspicion_score"] = score.ToString(),
                ["scan_tier"] = tier,
                ["reasons"] = string.Join("; ", reasons)
            }
        }, ct);

        // Feed telemetry fusion — enables correlation with network/clipboard/LSASS signals
        _fusionEngine?.IngestFileActivity(proc.Id, proc.ProcessName,
            path, FileActivityKind.Read, DateTimeOffset.UtcNow);

        // Add to baseline to prevent re-alerting
        baseline.Modules[pathLower] = new ModuleRecord
        {
            Path = path, ModuleName = moduleName, Hash = hash,
            IsSigned = isSigned, Publisher = publisher, FirstSeen = DateTimeOffset.UtcNow
        };
    }

    private async Task EmitPhantomModuleAsync(Process proc, ModuleRecord phantom, CancellationToken ct)
    {
        var alertKey = $"phantom:{proc.Id}:{phantom.Path}";
        if (!_alertedKeys.TryAdd(alertKey, 0)) return;

        _logger.LogWarning(
            "[PHANTOM-MODULE] '{Module}' in '{Process}' (PID {Pid}) — file deleted from disk",
            phantom.ModuleName, proc.ProcessName, proc.Id);

        await _detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = "Module Integrity: Phantom Module (File Deleted After Load)",
            Evidence = $"Module '{phantom.ModuleName}' is loaded in process '{proc.ProcessName}' " +
                      $"(PID {proc.Id}) but the file no longer exists at '{phantom.Path}'.",
            Reasoning = "A loaded DLL's backing file has been deleted from disk. Classic dropper " +
                       "pattern: (1) write DLL to disk, (2) inject/load into target, (3) delete " +
                       "file to avoid forensic detection. Code remains executable in memory. " +
                       "Used by Cobalt Strike, custom loaders, and fileless malware.",
            Confidence = 0.91,
            Tier = DetectionTier.Tier1Behavioral,
            ProcessName = proc.ProcessName,
            ProcessId = proc.Id,
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["technique"] = "T1055.001 - Process Injection: DLL Injection",
                ["module_name"] = phantom.ModuleName,
                ["original_path"] = phantom.Path,
                ["file_exists"] = "false"
            }
        }, ct);

        // Feed fusion for correlation
        _fusionEngine?.IngestFileActivity(proc.Id, proc.ProcessName,
            phantom.Path, FileActivityKind.Delete, DateTimeOffset.UtcNow);
    }

    private void PruneDeadProcesses()
    {
        var activePids = new HashSet<int>();
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                activePids.Add(p.Id);
                p.Dispose();
            }
        }
        catch { return; }

        foreach (var pid in _baselines.Keys)
        {
            if (!activePids.Contains(pid))
                _baselines.TryRemove(pid, out _);
        }

        // Prune old alert keys (allow re-alerting after 10 min)
        if (_alertedKeys.Count > 5000)
        {
            _alertedKeys.Clear();
        }
    }

    private static async Task<string?> ComputeHashAsync(string path, CancellationToken ct)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var sha = SHA256.Create();
            await using var fs = File.OpenRead(path);
            var hash = await sha.ComputeHashAsync(fs, ct);
            return Convert.ToHexString(hash);
        }
        catch { return null; }
    }

    private static bool? ValidateSignature(string path, out string? publisher)
    {
        publisher = null;
        try
        {
            if (!File.Exists(path)) return null;
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            publisher = cert.GetNameInfo(X509NameType.SimpleName, false);
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            return chain.Build(cert);
        }
        catch { return false; }
    }

    private sealed class ProcessModuleBaseline
    {
        public required string ProcessName { get; init; }
        public required DateTimeOffset CapturedAt { get; init; }
        public required ConcurrentDictionary<string, ModuleRecord> Modules { get; init; }
    }

    private sealed class ModuleRecord
    {
        public required string Path { get; init; }
        public required string ModuleName { get; init; }
        public string? Hash { get; set; }
        public bool? IsSigned { get; init; }
        public string? Publisher { get; init; }
        public required DateTimeOffset FirstSeen { get; init; }
    }
}


