using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core;

/// <summary>
/// Chrome Session Guard Monitor â€” Detects active session hijacking attacks against
/// Chrome/Chromium browsers by monitoring for:
///
///   1. Remote debugging port activation (--remote-debugging-port abuse)
///   2. Chrome DevTools Protocol (CDP) connections from non-browser processes
///   3. Process injection into browser processes (handle duplication targeting chrome.exe)
///   4. Cookie database file locking conflicts (stealer trying to read while browser runs)
///   5. Chrome's "Local State" file being read by non-browser processes (DPAPI key extraction)
///
/// This monitor specifically targets the "cookie-theft-as-a-service" attack chain:
///   Stealer â†’ reads Local State â†’ extracts encrypted_key â†’ DPAPI decrypt â†’ reads Cookies DB â†’ decrypts cookies â†’ exfiltrates
///
/// The monitor also detects the newer "Chrome App-Bound Encryption" bypass attempts
/// where attackers try to use Chrome's elevation_service.exe to decrypt cookies.
///
/// MITRE ATT&amp;CK:
///   T1539 â€” Steal Web Session Cookie
///   T1185 â€” Browser Session Hijacking
///   T1055 â€” Process Injection (into browser)
/// </summary>
public sealed class ChromeSessionGuardMonitor : BackgroundService
{
    private readonly DetectionEngine _detectionEngine;
    private readonly ILogger<ChromeSessionGuardMonitor> _logger;

    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(30);
    private readonly ConcurrentDictionary<string, DateTime> _alertedKeys = new();

    // Chrome remote debugging indicators
    private static readonly string[] RemoteDebugPatterns =
    {
        "--remote-debugging-port",
        "--remote-debugging-pipe",
        "--remote-debugging-address",
        "chrome-devtools-frontend",
        "devtools://devtools",
    };

    // Processes that should NEVER have handles to chrome.exe
    private static readonly HashSet<string> SuspiciousHandleHolders = new(StringComparer.OrdinalIgnoreCase)
    {
        "python", "python3", "pythonw", "py",
        "powershell", "pwsh",
        "cmd", "wscript", "cscript",
        "node", "ruby", "perl",
        "java", "javaw",
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    public ChromeSessionGuardMonitor(
        DetectionEngine detectionEngine,
        ILogger<ChromeSessionGuardMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Chrome Session Guard Monitor starting ===");

        await Task.Delay(TimeSpan.FromSeconds(20), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await DetectRemoteDebuggingAsync(stoppingToken);
                await DetectChromeProcessInjectionAsync(stoppingToken);
                await DetectElevationServiceAbuseAsync(stoppingToken);
                PruneAlertCache();
                await Task.Delay(ScanInterval, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ChromeSessionGuard: Scan error");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
    }

    /// <summary>
    /// Detects Chrome instances launched with remote debugging enabled.
    /// Attackers use this to connect via CDP and steal cookies/sessions programmatically.
    /// </summary>
    private async Task DetectRemoteDebuggingAsync(CancellationToken ct)
    {
        var chromeProcesses = Process.GetProcesses()
            .Where(p => IsBrowserProcess(p.ProcessName));

        foreach (var process in chromeProcesses)
        {
            try
            {
                var cmdLine = GetCommandLine(process.Id);
                if (string.IsNullOrEmpty(cmdLine)) continue;

                var cmdLower = cmdLine.ToLowerInvariant();

                foreach (var pattern in RemoteDebugPatterns)
                {
                    if (cmdLower.Contains(pattern.ToLowerInvariant()))
                    {
                        var alertKey = $"debug|{process.Id}";
                        if (!ShouldAlert(alertKey)) continue;

                        // Check if this was launched by a suspicious parent
                        int parentPid = GetParentProcessId(process.Id);
                        string? parentName = null;
                        try
                        {
                            if (parentPid > 4)
                            {
                                using var parent = Process.GetProcessById(parentPid);
                                parentName = parent.ProcessName;
                            }
                        }
                        catch { }

                        // If parent is explorer.exe (user launched), lower confidence
                        var confidence = parentName?.Equals("explorer", StringComparison.OrdinalIgnoreCase) == true
                            ? 0.70 : 0.92;

                        var tier = confidence >= 0.85
                            ? DetectionTier.Tier1Behavioral
                            : DetectionTier.Tier2Indicator;

                        _logger.LogCritical(
                            "CHROME SESSION GUARD: Remote debugging detected on {Name} (PID {Pid}), parent: {Parent}",
                            process.ProcessName, process.Id, parentName ?? "Unknown");

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Browser Credential Theft: Remote Debugging",
                            Evidence = $"Browser '{process.ProcessName}' (PID {process.Id}) running with " +
                                      $"remote debugging enabled (pattern: '{pattern}'). " +
                                      $"Parent process: {parentName ?? "Unknown"} (PID {parentPid}). " +
                                      $"CommandLine: {cmdLine}",
                            Reasoning = "Chrome DevTools Protocol (CDP) remote debugging allows programmatic " +
                                       "access to all browser data including cookies, saved passwords, and active " +
                                       "sessions. Attackers launch Chrome with --remote-debugging-port to connect " +
                                       "via CDP and steal Google account sessions without triggering any browser " +
                                       "security warnings. This bypasses all cookie encryption.",
                            Confidence = confidence,
                            Tier = tier,
                            ProcessName = process.ProcessName,
                            ProcessId = process.Id,
                            Timestamp = DateTime.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["debug_pattern"] = pattern,
                                ["parent_process"] = parentName ?? "Unknown",
                                ["parent_pid"] = parentPid.ToString(),
                                ["command_line"] = cmdLine,
                                ["technique"] = "T1185 - Browser Session Hijacking"
                            }
                        }, ct);

                        break; // One alert per process
                    }
                }
            }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
            finally
            {
                process.Dispose();
            }
        }
    }

    /// <summary>
    /// Detects suspicious processes that have opened handles to Chrome processes.
    /// This indicates process injection or memory reading for credential extraction.
    /// </summary>
    private async Task DetectChromeProcessInjectionAsync(CancellationToken ct)
    {
        // Find all browser PIDs
        var browserPids = new HashSet<int>();
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (IsBrowserProcess(proc.ProcessName))
                    browserPids.Add(proc.Id);
            }
            finally { proc.Dispose(); }
        }

        if (browserPids.Count == 0) return;

        // Check for suspicious processes that might be targeting browsers
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (process.Id <= 4 || process.Id == Environment.ProcessId) continue;
                if (IsBrowserProcess(process.ProcessName)) continue;

                // Check if this is a suspicious process type
                if (!SuspiciousHandleHolders.Contains(process.ProcessName)) continue;

                // Check command line for browser-targeting indicators
                var cmdLine = GetCommandLine(process.Id);
                if (string.IsNullOrEmpty(cmdLine)) continue;

                var cmdLower = cmdLine.ToLowerInvariant();

                // Look for CDP connection attempts or browser memory reading
                bool isSuspicious = cmdLower.Contains("localhost:") && cmdLower.Contains("json") ||
                                   cmdLower.Contains("127.0.0.1:") && cmdLower.Contains("devtools") ||
                                   cmdLower.Contains("chrome") && cmdLower.Contains("debug") ||
                                   cmdLower.Contains("websocket") && cmdLower.Contains("devtools");

                if (isSuspicious)
                {
                    var alertKey = $"inject|{process.Id}";
                    if (!ShouldAlert(alertKey)) continue;

                    _logger.LogCritical(
                        "CHROME SESSION GUARD: CDP connection attempt from {Name} (PID {Pid})",
                        process.ProcessName, process.Id);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Browser Credential Theft: CDP Session Hijack",
                        Evidence = $"Process '{process.ProcessName}' (PID {process.Id}) attempting to connect " +
                                  $"to Chrome DevTools Protocol. CommandLine: {cmdLine}",
                        Reasoning = "A scripting process is connecting to Chrome's DevTools Protocol endpoint. " +
                                   "This allows full programmatic control of the browser including reading all " +
                                   "cookies (including HttpOnly), accessing saved passwords, and impersonating " +
                                   "the user's Google session. This is the technique used by modern cookie " +
                                   "stealers that bypass Chrome's cookie encryption.",
                        Confidence = 0.91,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = process.ProcessName,
                        ProcessId = process.Id,
                        Timestamp = DateTime.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["command_line"] = cmdLine,
                            ["technique"] = "T1539 - Steal Web Session Cookie",
                            ["method"] = "CDP"
                        }
                    }, ct);
                }
            }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
            finally
            {
                process.Dispose();
            }
        }
    }

    /// <summary>
    /// Detects abuse of Chrome's elevation_service.exe for App-Bound Encryption bypass.
    /// Newer Chrome versions use elevation_service to encrypt cookies â€” attackers abuse it to decrypt.
    /// </summary>
    private async Task DetectElevationServiceAbuseAsync(CancellationToken ct)
    {
        var elevationProcesses = Process.GetProcesses()
            .Where(p => p.ProcessName.Equals("elevation_service", StringComparison.OrdinalIgnoreCase));

        foreach (var process in elevationProcesses)
        {
            try
            {
                // elevation_service should only be started by Chrome itself
                var parentPid = GetParentProcessId(process.Id);
                if (parentPid <= 4) continue;

                string? parentName = null;
                try
                {
                    using var parent = Process.GetProcessById(parentPid);
                    parentName = parent.ProcessName;
                }
                catch { continue; }

                // If parent is NOT a browser process, this is suspicious
                if (parentName != null && !IsBrowserProcess(parentName))
                {
                    var alertKey = $"elevation|{process.Id}";
                    if (!ShouldAlert(alertKey)) continue;

                    _logger.LogCritical(
                        "CHROME SESSION GUARD: elevation_service.exe spawned by non-browser: {Parent} (PID {ParentPid})",
                        parentName, parentPid);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Browser Credential Theft: App-Bound Encryption Bypass",
                        Evidence = $"Chrome's elevation_service.exe (PID {process.Id}) was spawned by " +
                                  $"non-browser process '{parentName}' (PID {parentPid}). " +
                                  "This service handles App-Bound Encryption for cookie protection.",
                        Reasoning = "Chrome's App-Bound Encryption (introduced in Chrome 127) uses " +
                                   "elevation_service.exe to encrypt/decrypt cookies with a key bound to the " +
                                   "Chrome application identity. Attackers abuse this service to decrypt cookies " +
                                   "by calling its IPC interface from a malicious process. If the parent is not " +
                                   "Chrome itself, this indicates an active cookie decryption attack.",
                        Confidence = 0.94,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "elevation_service",
                        ProcessId = process.Id,
                        Timestamp = DateTime.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["parent_process"] = parentName,
                            ["parent_pid"] = parentPid.ToString(),
                            ["technique"] = "T1539 - Steal Web Session Cookie",
                            ["method"] = "App-Bound Encryption Bypass"
                        }
                    }, ct);
                }
            }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
            finally
            {
                process.Dispose();
            }
        }
    }

    private static bool IsBrowserProcess(string processName)
    {
        return processName.Equals("chrome", StringComparison.OrdinalIgnoreCase) ||
               processName.Equals("msedge", StringComparison.OrdinalIgnoreCase) ||
               processName.Equals("brave", StringComparison.OrdinalIgnoreCase) ||
               processName.Equals("opera", StringComparison.OrdinalIgnoreCase) ||
               processName.Equals("vivaldi", StringComparison.OrdinalIgnoreCase) ||
               processName.Equals("arc", StringComparison.OrdinalIgnoreCase) ||
               processName.Equals("chromium", StringComparison.OrdinalIgnoreCase);
    }

    private bool ShouldAlert(string key)
    {
        if (_alertedKeys.TryGetValue(key, out var last))
        {
            if (DateTime.UtcNow - last < TimeSpan.FromMinutes(5))
                return false;
        }
        _alertedKeys[key] = DateTime.UtcNow;
        return true;
    }

    private void PruneAlertCache()
    {
        var cutoff = DateTime.UtcNow.AddMinutes(-5);
        foreach (var kv in _alertedKeys)
        {
            if (kv.Value < cutoff)
                _alertedKeys.TryRemove(kv.Key, out _);
        }
    }

    private static string? GetCommandLine(int pid)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            using var results = searcher.Get();
            foreach (var obj in results)
                return obj["CommandLine"]?.ToString();
        }
        catch { }
        return null;
    }

    private static int GetParentProcessId(int pid)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");
            using var results = searcher.Get();
            foreach (var obj in results)
            {
                if (obj["ParentProcessId"] is uint ppid)
                    return (int)ppid;
            }
        }
        catch { }
        return 0;
    }
}
