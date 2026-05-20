using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Response;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Browser DLL Monitor (ELF Catcher) — Specifically monitors browser processes for
/// injected/suspicious DLLs that are commonly used by:
///   - Browser extension loaders (ELF = Extension Loading Framework malware)
///   - Credential stealers (form grabbers, cookie thieves)
///   - Ad injection / traffic manipulation DLLs
///   - Banking trojans (Zeus, Emotet browser hooks)
///   - Clipboard hijackers targeting crypto addresses
///
/// Ported from Antivirus.ps1's Invoke-ElfCatcher and Test-SuspiciousDLL.
///
/// Browser-specific heuristics:
///   1. .winmd files outside Windows directory (WinRT abuse)
///   2. Random hex-named DLLs in browser processes
///   3. DLLs from TEMP loaded into browsers (excluding browser cache DLLs)
///   4. DLLs in browser profile folders with non-browser names
///   5. Unsigned DLLs in browser processes (outside system paths)
///   6. Known ELF/malware DLL name patterns (*_elf.dll, *_hook.dll, etc.)
///
/// Response: Can actively unload detected malicious DLLs via DllUnloadEngine.
///
/// Scan frequency: every 45 seconds (browsers are high-value targets).
///
/// MITRE ATT&CK:
///   T1185 — Browser Session Hijacking
///   T1055 — Process Injection
///   T1539 — Steal Web Session Cookie
/// </summary>
public sealed class BrowserDllMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<BrowserDllMonitor> _logger;
    private readonly DllUnloadEngine? _unloadEngine;
    private readonly IoCScanner? _iocScanner;

    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(45);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _processedDlls = new();
    private readonly ConcurrentDictionary<string, byte> _alertedKeys = new();

    // Browser process names to monitor
    private static readonly HashSet<string> BrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "msedge", "firefox", "brave", "opera", "vivaldi",
        "iexplore", "microsoftedge", "waterfox", "palemoon",
        "chromium", "ungoogled-chromium", "thorium", "arc"
    };

    // Known legitimate browser DLL prefixes (don't flag these)
    private static readonly string[] BrowserDllPrefixes =
    {
        "chrome_", "edge_", "moz", "firefox_", "nss", "freebl",
        "softokn", "libssl", "libnspr", "xul", "lgpllibs",
        "mozglue", "mozavutil", "mozavcodec"
    };

    // Known ELF/malware DLL patterns
    private static readonly Regex MalwareDllPattern = new(
        @"_elf\.dll$|_hook\.dll$|_inject\.dll$|_grab\.dll$|_steal\.dll$|_proxy\.dll$|_patch\.dll$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // System DLL whitelist (never flag these)
    private static readonly HashSet<string> SystemDllWhitelist = new(StringComparer.OrdinalIgnoreCase)
    {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
        "gdi32.dll", "gdi32full.dll", "msvcrt.dll", "advapi32.dll",
        "shell32.dll", "ole32.dll", "oleaut32.dll", "combase.dll",
        "rpcrt4.dll", "sechost.dll", "bcrypt.dll", "crypt32.dll",
        "ws2_32.dll", "winhttp.dll", "wininet.dll", "urlmon.dll",
        "mswsock.dll", "dnsapi.dll", "iphlpapi.dll", "nsi.dll",
        "uxtheme.dll", "dwmapi.dll", "d3d11.dll", "dxgi.dll",
        "imm32.dll", "msctf.dll", "clbcatq.dll", "setupapi.dll",
        "cfgmgr32.dll", "devobj.dll", "wintrust.dll", "imagehlp.dll",
        "version.dll", "shlwapi.dll", "shcore.dll", "propsys.dll",
        "profapi.dll", "powrprof.dll", "sspicli.dll", "secur32.dll",
        "ncrypt.dll", "bcryptprimitives.dll", "ucrtbase.dll",
        "msvcp_win.dll", "win32u.dll", "dbghelp.dll", "dbgcore.dll"
    };

    public BrowserDllMonitor(
        IDetectionEngine detectionEngine,
        ILogger<BrowserDllMonitor> logger,
        DllUnloadEngine? unloadEngine = null,
        IoCScanner? iocScanner = null)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _unloadEngine = unloadEngine;
        _iocScanner = iocScanner;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("BrowserDllMonitor (ELF Catcher): Starting");

        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanBrowserProcessesAsync(stoppingToken);
                PruneProcessedDlls();
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "BrowserDllMonitor: Scan error");
            }

            try { await Task.Delay(ScanInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task ScanBrowserProcessesAsync(CancellationToken ct)
    {
        var processes = Process.GetProcesses();

        try
        {
            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    if (!BrowserProcesses.Contains(proc.ProcessName)) continue;
                    if (proc.Id <= 4) continue;

                    ProcessModuleCollection modules;
                    try { modules = proc.Modules; }
                    catch { continue; }

                    foreach (ProcessModule module in modules)
                    {
                        ct.ThrowIfCancellationRequested();

                        try
                        {
                            var dllPath = module.FileName;
                            if (string.IsNullOrEmpty(dllPath)) continue;

                            var dllName = Path.GetFileName(dllPath);
                            var dllNameLower = dllName.ToLowerInvariant();

                            // Skip system DLLs
                            if (SystemDllWhitelist.Contains(dllName)) continue;

                            // Skip already-processed
                            var key = $"{proc.Id}:{dllPath}";
                            if (_processedDlls.ContainsKey(key)) continue;
                            _processedDlls[key] = DateTimeOffset.UtcNow;

                            // Run browser-specific heuristics
                            var result = AnalyzeBrowserDll(dllName, dllPath, proc.ProcessName);
                            if (result == null) continue;

                            var alertKey = $"browser:{proc.Id}:{dllPath}";
                            if (!_alertedKeys.TryAdd(alertKey, 0)) continue;

                            // Check IoC hash
                            string? hash = null;
                            bool iocMatch = false;
                            string iocName = "";
                            if (_iocScanner != null && File.Exists(dllPath))
                            {
                                try
                                {
                                    hash = IoCScanner.ComputeSha256(dllPath);
                                    iocMatch = _iocScanner.IsMaliciousHash(hash, out iocName, out _);
                                }
                                catch { }
                            }

                            double confidence = result.IsElfPattern ? 0.92 : 0.82;
                            if (iocMatch) confidence = 0.97;

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = iocMatch
                                    ? "Browser DLL: Known Malicious Module (IoC Match)"
                                    : result.IsElfPattern
                                        ? "Browser DLL: ELF Malware Pattern Detected"
                                        : "Browser DLL: Suspicious Module in Browser Process",
                                Evidence = $"Browser '{proc.ProcessName}' (PID {proc.Id}) has suspicious " +
                                          $"module '{dllName}' loaded from '{dllPath}'. " +
                                          $"Reasons: {string.Join("; ", result.Reasons)}." +
                                          (iocMatch ? $" IoC match: {iocName}" : ""),
                                Reasoning = "Browser processes are high-value targets for DLL injection. " +
                                           "Injected DLLs in browsers can steal credentials, session cookies, " +
                                           "form data, and cryptocurrency wallet addresses. " +
                                           $"Detection reasons: {string.Join("; ", result.Reasons)}. " +
                                           "This module does not match expected browser or system DLL patterns.",
                                Confidence = confidence,
                                Tier = DetectionTier.Tier1Behavioral,
                                ProcessName = proc.ProcessName,
                                ProcessId = proc.Id,
                                Timestamp = DateTimeOffset.UtcNow,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["technique"] = "T1185 - Browser Session Hijacking",
                                    ["dll_name"] = dllName,
                                    ["dll_path"] = dllPath,
                                    ["browser"] = proc.ProcessName,
                                    ["reasons"] = string.Join("; ", result.Reasons),
                                    ["is_elf_pattern"] = result.IsElfPattern.ToString(),
                                    ["hash"] = hash ?? "unknown",
                                    ["ioc_match"] = iocMatch.ToString()
                                }
                            }, ct);

                            _logger.LogWarning(
                                "BrowserDllMonitor: SUSPICIOUS DLL in {Browser} (PID {Pid}): {Dll} — {Reasons}",
                                proc.ProcessName, proc.Id, dllName, string.Join(", ", result.Reasons));

                            // Active response: unload ELF-pattern DLLs
                            if (result.IsElfPattern && _unloadEngine != null)
                            {
                                var unloadResult = _unloadEngine.UnloadDll(
                                    proc.Id, dllPath,
                                    $"ELF malware pattern: {string.Join(", ", result.Reasons)}");

                                if (unloadResult.Success)
                                {
                                    _logger.LogCritical(
                                        "BrowserDllMonitor: UNLOADED ELF DLL '{Dll}' from {Browser} (PID {Pid})",
                                        dllName, proc.ProcessName, proc.Id);
                                }
                            }
                        }
                        catch { continue; }
                    }
                }
                catch { continue; }
            }
        }
        finally
        {
            foreach (var p in processes)
                try { p.Dispose(); } catch { }
        }
    }

    /// <summary>
    /// Analyzes a DLL loaded in a browser process for suspicious characteristics.
    /// </summary>
    private static BrowserDllAnalysisResult? AnalyzeBrowserDll(string dllName, string dllPath, string browserName)
    {
        var dllNameLower = dllName.ToLowerInvariant();
        var reasons = new List<string>();
        bool isElfPattern = false;

        // Skip known browser DLL prefixes
        if (BrowserDllPrefixes.Any(prefix => dllNameLower.StartsWith(prefix)))
            return null;

        // Skip DLLs from system paths
        var pathLower = dllPath.ToLowerInvariant();
        if (pathLower.Contains(@"\windows\system32\") ||
            pathLower.Contains(@"\windows\syswow64\") ||
            pathLower.Contains(@"\windows\winsxs\"))
            return null;

        // Pattern 1: Known ELF/malware DLL name patterns
        if (MalwareDllPattern.IsMatch(dllNameLower))
        {
            reasons.Add("Known malware DLL naming pattern (ELF/hook/inject/grab)");
            isElfPattern = true;
        }

        // Pattern 2: .winmd files outside Windows directory
        if (dllNameLower.EndsWith(".winmd") && !pathLower.Contains(@"\windows\"))
        {
            reasons.Add("WINMD file outside Windows directory");
        }

        // Pattern 3: Random hex-named DLLs
        if (Regex.IsMatch(dllNameLower, @"^[a-f0-9]{8,}\.(dll|winmd)$"))
        {
            reasons.Add("Random hex-named DLL (common in malware droppers)");
            isElfPattern = true;
        }

        // Pattern 4: DLLs from TEMP directory (excluding browser cache)
        if (pathLower.Contains(@"\appdata\local\temp\") &&
            !BrowserDllPrefixes.Any(prefix => dllNameLower.StartsWith(prefix)))
        {
            reasons.Add("DLL loaded from TEMP directory");
        }

        // Pattern 5: DLLs in browser profile folders with non-browser names
        if (pathLower.Contains(@"\appdata\") &&
            !dllNameLower.Contains("chrome") &&
            !dllNameLower.Contains("edge") &&
            !dllNameLower.Contains("firefox") &&
            !dllNameLower.Contains("mozilla") &&
            !pathLower.Contains(@"\program files"))
        {
            reasons.Add("Non-browser DLL in AppData directory");
        }

        // Pattern 6: Unsigned DLLs in browser processes (check signature)
        if (reasons.Count == 0 && File.Exists(dllPath) &&
            !pathLower.Contains(@"\program files"))
        {
            try
            {
                var cert = X509Certificate.CreateFromSignedFile(dllPath);
                // Signed — probably OK
            }
            catch
            {
                // Unsigned
                if (!pathLower.Contains(@"\windows\"))
                {
                    reasons.Add("Unsigned DLL in browser process (outside system/program paths)");
                }
            }
        }

        // Pattern 7: Very small DLLs in unusual locations (stub loaders)
        if (File.Exists(dllPath))
        {
            try
            {
                var size = new FileInfo(dllPath).Length;
                if (size < 10240 && // < 10KB
                    !pathLower.Contains(@"\windows\") &&
                    !pathLower.Contains(@"\program files"))
                {
                    reasons.Add($"Tiny DLL ({size} bytes) — possible stub loader");
                }
            }
            catch { }
        }

        if (reasons.Count == 0) return null;

        return new BrowserDllAnalysisResult
        {
            Reasons = reasons,
            IsElfPattern = isElfPattern
        };
    }

    private void PruneProcessedDlls()
    {
        var cutoff = DateTimeOffset.UtcNow.AddHours(-1);
        foreach (var key in _processedDlls.Keys)
        {
            if (_processedDlls.TryGetValue(key, out var time) && time < cutoff)
                _processedDlls.TryRemove(key, out _);
        }

        if (_alertedKeys.Count > 5000)
            _alertedKeys.Clear();
    }

    private sealed class BrowserDllAnalysisResult
    {
        public List<string> Reasons { get; init; } = new();
        public bool IsElfPattern { get; init; }
    }
}

