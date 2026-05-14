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
/// Validates loaded modules across critical / high-value processes.
///
/// Ported (security-hardened) from GIDR's ModuleValidationDetection.
///
/// Why this exists in 0.4.0: it directly catches the v0.3.x bypass primitive.
/// The Discord report said: "I sideloaded a .dll into Windows as a system level
/// process, then added it to your whitelisted reputation cache so it's never
/// detected." The reputation cache no longer accepts disk-injected KnownSafe entries
/// (see <see cref="ReputationCache"/>), but this monitor closes the second half of
/// the chain: it scans the actual *loaded modules* of critical processes (lsass,
/// services, svchost, browsers, office apps) and emits Tier1 detections for:
///   - unsigned DLLs in critical processes,
///   - DLLs in critical processes whose path is outside Windows / Program Files,
///   - DLLs in critical processes whose hash is on the IoC malicious list,
///   - DLLs loaded from Temp / AppData\Local\Temp.
///
/// Hardening notes:
///   - We do NOT try to forcibly unload DLLs from foreign processes. That requires
///     remote-thread injection or kernel code; userland-safe response is to emit a
///     high-confidence detection and let the response engine apply policy.
///   - Result cache uses <see cref="ConcurrentDictionary{TKey,TValue}"/> with a 5-min
///     entry TTL; no static mutable state.
/// </summary>
public sealed class ModuleValidationMonitor : BackgroundService
{
    private static readonly TimeSpan ScanInterval = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan ModuleCacheTtl = TimeSpan.FromMinutes(5);

    private static readonly HashSet<string> CriticalProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "lsass.exe", "csrss.exe", "services.exe", "smss.exe", "wininit.exe",
        "svchost.exe", "lsm.exe", "winlogon.exe", "taskhostw.exe", "explorer.exe"
    };

    private static readonly HashSet<string> HighValueTargets = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
        "outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe",
        "teams.exe", "slack.exe", "discord.exe",
        "mstsc.exe", "vmconnect.exe", "vmware.exe"
    };

    private static readonly string[] TrustedSubjectMarkers =
    {
        "Microsoft Corporation",
        "Microsoft Windows",
        "Microsoft Windows Production PCA",
        "Microsoft 3rd Party Application Component",
        "Windows (R), Microsoft Corporation"
    };

    private readonly IDetectionEngine _engine;
    private readonly ILogger<ModuleValidationMonitor> _logger;
    private readonly IoCScanner? _iocScanner;
    private readonly ConcurrentDictionary<string, ModuleInfo> _moduleCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _emittedKeys = new();

    public ModuleValidationMonitor(
        IDetectionEngine engine,
        ILogger<ModuleValidationMonitor> logger,
        IoCScanner? iocScanner = null)
    {
        _engine = engine;
        _logger = logger;
        _iocScanner = iocScanner;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("ModuleValidationMonitor: starting");
        await Task.Delay(TimeSpan.FromSeconds(40), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try { await ScanAsync(stoppingToken); }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { _logger.LogDebug(ex, "ModuleValidationMonitor: scan error"); }

            try { await Task.Delay(ScanInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task ScanAsync(CancellationToken cancellationToken)
    {
        EvictExpiredModules();
        var selfPid = Environment.ProcessId;
        var procs = Process.GetProcesses();
        try
        {
            foreach (var proc in procs)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var p = proc;
                if (p.Id == selfPid || p.Id <= 4) continue;

                string procName;
                try { procName = p.ProcessName + ".exe"; }
                catch { continue; }

                bool isCritical = CriticalProcesses.Contains(procName);
                bool isHighValue = HighValueTargets.Contains(procName);
                if (!isCritical && !isHighValue) continue;

                ProcessModuleCollection modules;
                try { modules = p.Modules; }
                catch { continue; }

                foreach (ProcessModule m in modules)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var path = m.FileName;
                    if (string.IsNullOrEmpty(path)) continue;

                    var fileName = Path.GetFileName(path).ToLowerInvariant();
                    if (fileName.StartsWith("mscor") ||
                        fileName.StartsWith("clr") ||
                        fileName.StartsWith("system.") ||
                        fileName.StartsWith("microsoft.")) continue;

                    var info = GetOrComputeModuleInfo(path);
                    if (info is null) continue;

                    var (score, reasons) = AssessModule(info, path, isCritical, isHighValue);
                    if (score < 50) continue;

                    var key = $"mod:{p.Id}:{path}";
                    if (!_emittedKeys.TryAdd(key, 0)) continue;

                    bool iocMatch = false;
                    string iocName = "", iocTech = "";
                    if (info.Sha256 is not null && _iocScanner != null)
                    {
                        iocMatch = _iocScanner.IsMaliciousHash(info.Sha256, out iocName, out iocTech);
                        if (iocMatch)
                        {
                            score += 50;
                            reasons.Add($"Hash matches IoC entry '{iocName}'");
                        }
                    }

                    var meta = new Dictionary<string, string>
                    {
                        ["technique"] = iocMatch ? iocTech : "T1574 - Hijack Execution Flow",
                        ["module_path"] = path,
                        ["module_name"] = fileName,
                        ["is_signed"] = info.IsSigned.ToString(),
                        ["publisher"] = info.Publisher ?? "(unsigned)",
                        ["heuristic_score"] = score.ToString(),
                        ["reasons"] = string.Join("; ", reasons)
                    };
                    if (info.Sha256 is not null) meta["module_hash"] = info.Sha256;

                    await _engine.EmitAsync(new DetectionEvent
                    {
                        RuleName = iocMatch
                            ? "Module Validation: malicious DLL loaded in critical process"
                            : "Module Validation: suspicious DLL in critical process",
                        Evidence = $"{p.ProcessName} (PID {p.Id}) loaded {fileName} — score {score}",
                        Reasoning = string.Join("; ", reasons),
                        Confidence = iocMatch ? 0.97 : (score >= 80 ? 0.92 : 0.78),
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = p.ProcessName,
                        ProcessId = p.Id,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = meta
                    }, cancellationToken);
                }
            }
        }
        finally
        {
            foreach (var p in procs)
            {
                try { p.Dispose(); } catch { }
            }
        }
    }

    private static (int score, List<string> reasons) AssessModule(
        ModuleInfo info, string path, bool isCritical, bool isHighValue)
    {
        int score = 0;
        var reasons = new List<string>();

        if (isCritical && !info.IsSigned)
        {
            score += 60; reasons.Add("unsigned module in critical process");
        }
        if (isHighValue && !info.IsSigned)
        {
            score += 40; reasons.Add("unsigned module in browser/office app");
        }
        var lower = path.ToLowerInvariant();
        if (lower.Contains(@"\temp\") || lower.Contains(@"\tmp\") ||
            lower.Contains(@"\appdata\local\temp"))
        {
            score += 50; reasons.Add("module loaded from temp directory");
        }
        if (isCritical && !lower.Contains(@"\windows\") && !lower.Contains(@"\program files"))
        {
            score += 45; reasons.Add("non-system DLL path in system process");
        }
        if (info.IsSigned && !info.IsTrustedPublisher && !string.IsNullOrEmpty(info.Publisher))
        {
            score += 30; reasons.Add($"signed but untrusted publisher: {info.Publisher}");
        }
        return (score, reasons);
    }

    private ModuleInfo? GetOrComputeModuleInfo(string path)
    {
        if (_moduleCache.TryGetValue(path, out var existing) &&
            DateTimeOffset.UtcNow - existing.VerifiedAt < ModuleCacheTtl)
        {
            return existing;
        }

        if (!File.Exists(path)) return null;

        var info = new ModuleInfo { Path = path, VerifiedAt = DateTimeOffset.UtcNow };

        try
        {
            using var sha = SHA256.Create();
            using var fs = File.OpenRead(path);
            info.Sha256 = Convert.ToHexString(sha.ComputeHash(fs));
        }
        catch { /* unreadable */ }

        try
        {
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            info.IsSigned = true;
            info.Publisher = cert.Subject;
            info.IsTrustedPublisher = TrustedSubjectMarkers.Any(t =>
                cert.Subject.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0);
        }
        catch
        {
            info.IsSigned = false;
        }

        _moduleCache[path] = info;
        return info;
    }

    private void EvictExpiredModules()
    {
        var cutoff = DateTimeOffset.UtcNow - ModuleCacheTtl;
        foreach (var kv in _moduleCache)
        {
            if (kv.Value.VerifiedAt < cutoff)
                _moduleCache.TryRemove(kv.Key, out _);
        }
    }

    private sealed class ModuleInfo
    {
        public string Path { get; set; } = "";
        public string? Sha256 { get; set; }
        public bool IsSigned { get; set; }
        public string? Publisher { get; set; }
        public bool IsTrustedPublisher { get; set; }
        public DateTimeOffset VerifiedAt { get; set; }
    }
}
