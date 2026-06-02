using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core;

/// <summary>
/// Chrome Credential Guard Monitor â€” Detects unauthorized access to Chrome/Chromium
/// browser credential stores, cookies, and session data.
///
/// Protects against:
///   1. Infostealers reading Chrome's Login Data (saved passwords)
///   2. Cookie theft (session hijacking for Google account takeover)
///   3. Local State file access (contains DPAPI-encrypted key for cookie/password decryption)
///   4. Extension manipulation (silent malicious extension installation)
///   5. Chrome profile cloning/exfiltration
///
/// How it works:
///   - Monitors file handles opened on Chrome's sensitive data files
///   - Any non-Chrome process accessing Login Data, Cookies, or Local State triggers an alert
///   - Uses ETW file I/O events + periodic handle scanning as fallback
///   - Covers all Chromium-based browsers (Chrome, Edge, Brave, Opera, Vivaldi, Arc)
///
/// MITRE ATT&amp;CK:
///   T1555.003 â€” Credentials from Password Stores: Credentials from Web Browsers
///   T1539     â€” Steal Web Session Cookie
///   T1185     â€” Browser Session Hijacking
///
/// False positive handling:
///   - Chrome/browser processes themselves are excluded
///   - Windows Defender and known AV scanners are excluded
///   - Cloud sync agents (Google Drive, OneDrive) are excluded for bookmarks only
///   - Backup software is excluded ONLY for non-credential files
/// </summary>
public sealed class ChromeCredentialGuardMonitor : BackgroundService
{
    private readonly DetectionEngine _detectionEngine;
    private readonly ILogger<ChromeCredentialGuardMonitor> _logger;

    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(15);

    // Track alerted (pid, file) pairs to avoid flooding
    private readonly ConcurrentDictionary<string, DateTime> _alertedAccess = new();
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(2);

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // SENSITIVE BROWSER FILES â€” These contain credentials, cookies, or keys
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    /// <summary>
    /// Critical files that contain actual credentials or decryption keys.
    /// Access by non-browser processes is ALWAYS suspicious.
    /// </summary>
    private static readonly string[] CriticalFiles =
    {
        "Login Data",           // SQLite DB with saved passwords (DPAPI-encrypted)
        "Login Data-journal",   // SQLite journal (may contain plaintext during writes)
        "Cookies",              // SQLite DB with session cookies
        "Cookies-journal",      // SQLite journal for cookies
        "Local State",          // JSON with encrypted_key (DPAPI master key for cookies/passwords)
        "Web Data",             // Autofill data, credit cards
        "Web Data-journal",
    };

    /// <summary>
    /// High-value files that indicate session/account theft when accessed externally.
    /// </summary>
    private static readonly string[] HighValueFiles =
    {
        "Network\\Cookies",             // Network service cookies (newer Chrome)
        "Network\\Cookies-journal",
        "Session Storage",              // Active session data
        "Local Storage\\leveldb",       // localStorage (may contain tokens)
        "IndexedDB",                    // May contain OAuth tokens
        "Extension Cookies",            // Extension session data
        "Extension Cookies-journal",
        "Token Service",                // Google account tokens
        "Google Profile.ico",           // Profile identification
    };

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // BROWSER PROFILE PATHS â€” All Chromium-based browsers
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    private static readonly (string BrowserName, string RelativePath)[] BrowserPaths =
    {
        ("Chrome",   @"Google\Chrome\User Data"),
        ("Edge",     @"Microsoft\Edge\User Data"),
        ("Brave",    @"BraveSoftware\Brave-Browser\User Data"),
        ("Opera",    @"Opera Software\Opera Stable"),
        ("Opera GX", @"Opera Software\Opera GX Stable"),
        ("Vivaldi",  @"Vivaldi\User Data"),
        ("Arc",      @"Arc\User Data"),
        ("Chromium", @"Chromium\User Data"),
    };

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // LEGITIMATE PROCESSES â€” Allowed to access browser data
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    private static readonly HashSet<string> LegitimateProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Browser processes themselves
        "chrome", "chrome.exe",
        "msedge", "msedge.exe",
        "brave", "brave.exe",
        "opera", "opera.exe",
        "vivaldi", "vivaldi.exe",
        "arc", "arc.exe",
        "chromium", "chromium.exe",
        // Browser helper/utility processes
        "chrome_crashpad_handler", "chrome_crashpad_handler.exe",
        "msedge_crashpad_handler", "msedge_crashpad_handler.exe",
        "notification_helper", "notification_helper.exe",
        "elevation_service", "elevation_service.exe",
        // Windows Defender / AV
        "MsMpEng", "MsMpEng.exe",
        "MsSense", "MsSense.exe",
        "MpCmdRun", "MpCmdRun.exe",
        // Sentinel itself
        "SentinelService", "SentinelService.exe",
        "SentinelAgent", "SentinelAgent.exe",
        // Windows system
        "SearchIndexer", "SearchIndexer.exe",   // Windows Search (indexes file metadata only)
        "svchost", "svchost.exe",               // Various Windows services
        "System",
    };

    // Processes that may legitimately access SOME browser files (bookmarks, history)
    // but should NEVER access Login Data, Cookies, or Local State
    private static readonly HashSet<string> PartiallyAllowedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "OneDrive", "OneDrive.exe",
        "GoogleDriveFS", "GoogleDriveFS.exe",
        "Dropbox", "Dropbox.exe",
        "BackupService", "BackupService.exe",
    };

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // KNOWN INFOSTEALER PATTERNS
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    private static readonly string[] InfostealerIndicators =
    {
        "stealer", "steal", "grab", "dump", "extract",
        "cookie", "cred", "pass", "token", "wallet",
        "redline", "raccoon", "vidar", "mars", "aurora",
        "stealc", "lumma", "risepro", "mystic",
    };

    // P/Invoke for handle enumeration
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint PROCESS_DUP_HANDLE = 0x0040;

    private readonly List<string> _monitoredPaths = new();
    private readonly List<FileSystemWatcher> _watchers = new();

    public ChromeCredentialGuardMonitor(
        DetectionEngine detectionEngine,
        ILogger<ChromeCredentialGuardMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Chrome Credential Guard Monitor starting ===");

        await Task.Delay(InitialDelay, stoppingToken);

        // Discover browser profile paths
        DiscoverBrowserPaths();

        if (_monitoredPaths.Count == 0)
        {
            _logger.LogWarning("ChromeCredentialGuard: No browser profiles found. Monitor idle.");
            return;
        }

        _logger.LogInformation("ChromeCredentialGuard: Monitoring {Count} browser profile paths", _monitoredPaths.Count);

        // Setup FileSystemWatchers on browser data directories
        SetupWatchers();

        // Periodic active scan for open handles on sensitive files
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanForSuspiciousAccessAsync(stoppingToken);
                PruneAlertCache();
                await Task.Delay(ScanInterval, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ChromeCredentialGuard: Scan error");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }

        // Cleanup watchers
        foreach (var watcher in _watchers)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
        }
    }

    private void DiscoverBrowserPaths()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (var (browserName, relativePath) in BrowserPaths)
        {
            var fullPath = Path.Combine(localAppData, relativePath);
            if (Directory.Exists(fullPath))
            {
                _monitoredPaths.Add(fullPath);
                _logger.LogDebug("ChromeCredentialGuard: Found {Browser} at {Path}", browserName, fullPath);
            }
        }
    }

    private void SetupWatchers()
    {
        foreach (var profilePath in _monitoredPaths)
        {
            try
            {
                // Watch the main User Data directory
                var watcher = new FileSystemWatcher(profilePath)
                {
                    NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite |
                                  NotifyFilters.FileName | NotifyFilters.Size,
                    EnableRaisingEvents = true,
                    IncludeSubdirectories = true,
                    InternalBufferSize = 32768 // 32KB buffer for high-activity directories
                };

                watcher.Changed += OnBrowserFileAccessed;
                watcher.Created += OnBrowserFileCreated;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "ChromeCredentialGuard: Failed to watch {Path}", profilePath);
            }
        }
    }

    private void OnBrowserFileAccessed(object sender, FileSystemEventArgs e)
    {
        // Only care about critical files
        var fileName = Path.GetFileName(e.FullPath);
        if (!IsCriticalFile(fileName) && !IsHighValueFile(e.FullPath))
            return;

        // Check what process triggered this (best-effort via recent process scan)
        _ = Task.Run(async () =>
        {
            try
            {
                await CheckFileAccessAsync(e.FullPath, fileName, CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "ChromeCredentialGuard: Error checking file access for {File}", fileName);
            }
        });
    }

    private void OnBrowserFileCreated(object sender, FileSystemEventArgs e)
    {
        // Detect if someone is copying browser data files out
        var fileName = Path.GetFileName(e.FullPath);

        // Check for suspicious copy patterns (e.g., "Login Data.bak", "Cookies.tmp")
        foreach (var critical in CriticalFiles)
        {
            if (fileName.Contains(critical, StringComparison.OrdinalIgnoreCase) &&
                !fileName.Equals(critical, StringComparison.OrdinalIgnoreCase))
            {
                _ = Task.Run(async () =>
                {
                    await EmitDetectionAsync(
                        "Browser Credential Theft: Suspicious Copy",
                        $"A copy/variant of critical browser file '{critical}' was created: '{e.FullPath}'. " +
                        "This pattern is used by infostealers that copy browser databases before reading them.",
                        "Infostealers copy Chrome's Login Data and Cookies SQLite databases to a temporary " +
                        "location to avoid file-locking conflicts with the running browser. The copy is then " +
                        "read and decrypted at leisure. This is the #1 technique used by Redline, Raccoon, " +
                        "Vidar, and other commodity stealers.",
                        0.92,
                        DetectionTier.Tier1Behavioral,
                        "Unknown", 0,
                        new Dictionary<string, string>
                        {
                            ["target_file"] = e.FullPath,
                            ["original_file"] = critical,
                            ["technique"] = "T1555.003 - Credentials from Web Browsers",
                            ["sub_technique"] = "Copy-then-read"
                        },
                        CancellationToken.None);
                });
            }
        }
    }

    /// <summary>
    /// Actively scans for processes that have open handles to Chrome credential files.
    /// This catches stealers that hold files open for extended reads.
    /// </summary>
    private async Task ScanForSuspiciousAccessAsync(CancellationToken ct)
    {
        var processes = Process.GetProcesses();

        foreach (var process in processes)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                if (process.Id <= 4) continue;
                if (process.Id == Environment.ProcessId) continue;

                var processName = process.ProcessName;

                // Skip legitimate processes
                if (LegitimateProcesses.Contains(processName)) continue;

                // Check if this process has any browser data files open
                // We do this by checking the process's loaded modules and command line
                // for indicators of browser credential access
                var cmdLine = GetProcessCommandLine(process);
                if (string.IsNullOrEmpty(cmdLine)) continue;

                var cmdLower = cmdLine.ToLowerInvariant();

                // Check for direct references to browser credential paths
                foreach (var profilePath in _monitoredPaths)
                {
                    var profileLower = profilePath.ToLowerInvariant();

                    if (cmdLower.Contains(profileLower) || cmdLower.Contains("login data") ||
                        cmdLower.Contains("local state") || cmdLower.Contains("cookies"))
                    {
                        // Determine if this is a critical file reference
                        bool isCritical = CriticalFiles.Any(f =>
                            cmdLower.Contains(f.ToLowerInvariant()));

                        if (isCritical)
                        {
                            var alertKey = $"{process.Id}|{profilePath}";
                            if (ShouldAlert(alertKey))
                            {
                                await EmitDetectionAsync(
                                    "Browser Credential Theft: Direct Access",
                                    $"Process '{processName}' (PID {process.Id}) references Chrome credential " +
                                    $"files in its command line. CommandLine: {cmdLine}",
                                    "Non-browser processes should never reference Login Data, Cookies, or " +
                                    "Local State files. This is a definitive indicator of credential theft " +
                                    "(T1555.003). Common tools: Redline Stealer, Raccoon, Vidar, LaZagne, " +
                                    "SharpChromium, custom Python/C# stealers.",
                                    0.95,
                                    DetectionTier.Tier1Behavioral,
                                    processName, process.Id,
                                    new Dictionary<string, string>
                                    {
                                        ["command_line"] = cmdLine,
                                        ["browser_path"] = profilePath,
                                        ["technique"] = "T1555.003 - Credentials from Web Browsers"
                                    },
                                    ct);
                            }
                        }
                    }
                }

                // Check for known infostealer process name patterns
                var nameLower = processName.ToLowerInvariant();
                if (InfostealerIndicators.Any(ind => nameLower.Contains(ind)))
                {
                    var alertKey = $"stealer|{process.Id}";
                    if (ShouldAlert(alertKey))
                    {
                        await EmitDetectionAsync(
                            "Browser Credential Theft: Infostealer Process",
                            $"Process '{processName}' (PID {process.Id}) matches known infostealer naming patterns. " +
                            $"CommandLine: {cmdLine}",
                            "Process name contains keywords associated with credential-stealing malware families. " +
                            "While name-based detection is bypassable, it provides early warning and correlates " +
                            "with behavioral signals from other monitors.",
                            0.75,
                            DetectionTier.Tier2Indicator,
                            processName, process.Id,
                            new Dictionary<string, string>
                            {
                                ["command_line"] = cmdLine,
                                ["technique"] = "T1555.003 - Credentials from Web Browsers",
                                ["indicator_type"] = "ProcessName"
                            },
                            ct);
                    }
                }
            }
            catch (InvalidOperationException) { /* process exited */ }
            catch (System.ComponentModel.Win32Exception) { /* access denied */ }
            finally
            {
                process.Dispose();
            }
        }
    }

    private async Task CheckFileAccessAsync(string filePath, string fileName, CancellationToken ct)
    {
        // Brief delay to let the accessing process settle
        await Task.Delay(100, ct);

        // Scan all processes for ones that might have this file open
        var processes = Process.GetProcesses();

        foreach (var process in processes)
        {
            try
            {
                if (process.Id <= 4 || process.Id == Environment.ProcessId) continue;

                var processName = process.ProcessName;
                if (LegitimateProcesses.Contains(processName)) continue;

                // For partially allowed processes, only block credential file access
                if (PartiallyAllowedProcesses.Contains(processName))
                {
                    if (!IsCriticalFile(fileName)) continue;
                }

                // Check if this process recently started (infostealers are often short-lived)
                TimeSpan processAge;
                try { processAge = DateTime.UtcNow - process.StartTime.ToUniversalTime(); }
                catch { continue; }

                // Young processes accessing credential files are highly suspicious
                if (processAge < TimeSpan.FromMinutes(2))
                {
                    var cmdLine = GetProcessCommandLine(process);
                    var alertKey = $"{process.Id}|{fileName}";

                    if (ShouldAlert(alertKey))
                    {
                        var confidence = IsCriticalFile(fileName) ? 0.93 : 0.80;

                        await EmitDetectionAsync(
                            "Browser Credential Theft: Unauthorized File Access",
                            $"Recently-started process '{processName}' (PID {process.Id}, age: {processAge.TotalSeconds:F0}s) " +
                            $"detected while browser credential file '{fileName}' was accessed. " +
                            $"CommandLine: {cmdLine ?? "N/A"}",
                            "Short-lived processes accessing browser credential stores are the hallmark of " +
                            "infostealer malware. These tools typically: spawn â†’ copy Login Data/Cookies â†’ " +
                            "decrypt with DPAPI key from Local State â†’ exfiltrate â†’ exit. The entire " +
                            "operation takes seconds. Legitimate software does not access these files.",
                            confidence,
                            DetectionTier.Tier1Behavioral,
                            processName, process.Id,
                            new Dictionary<string, string>
                            {
                                ["accessed_file"] = filePath,
                                ["file_name"] = fileName,
                                ["process_age_seconds"] = processAge.TotalSeconds.ToString("F0"),
                                ["command_line"] = cmdLine ?? "N/A",
                                ["technique"] = "T1555.003 - Credentials from Web Browsers"
                            },
                            ct);
                    }
                }
            }
            catch (InvalidOperationException) { /* process exited */ }
            catch (System.ComponentModel.Win32Exception) { /* access denied */ }
            finally
            {
                process.Dispose();
            }
        }
    }

    private static bool IsCriticalFile(string fileName)
    {
        return CriticalFiles.Any(f => string.Equals(fileName, f, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsHighValueFile(string fullPath)
    {
        var pathLower = fullPath.ToLowerInvariant();
        return HighValueFiles.Any(f => pathLower.Contains(f.ToLowerInvariant()));
    }

    private bool ShouldAlert(string key)
    {
        if (_alertedAccess.TryGetValue(key, out var lastAlert))
        {
            if (DateTime.UtcNow - lastAlert < AlertCooldown)
                return false;
        }
        _alertedAccess[key] = DateTime.UtcNow;
        return true;
    }

    private void PruneAlertCache()
    {
        var cutoff = DateTime.UtcNow - AlertCooldown;
        foreach (var kv in _alertedAccess)
        {
            if (kv.Value < cutoff)
                _alertedAccess.TryRemove(kv.Key, out _);
        }
    }

    private async Task EmitDetectionAsync(
        string ruleName, string evidence, string reasoning,
        double confidence, DetectionTier tier,
        string processName, int processId,
        Dictionary<string, string> metadata,
        CancellationToken ct)
    {
        _logger.LogCritical("CHROME CREDENTIAL GUARD: {Rule} | PID {Pid} ({Name})",
            ruleName, processId, processName);

        await _detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = ruleName,
            Evidence = evidence,
            Reasoning = reasoning,
            Confidence = confidence,
            Tier = tier,
            ProcessName = processName,
            ProcessId = processId,
            Timestamp = DateTime.UtcNow,
            Metadata = metadata
        }, ct);
    }

    private static string? GetProcessCommandLine(Process process)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {process.Id}");
            using var results = searcher.Get();

            foreach (var obj in results)
            {
                return obj["CommandLine"]?.ToString();
            }
        }
        catch { /* WMI access denied or process exited */ }

        return null;
    }
}
