using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core;

/// <summary>
/// Firefox Credential Guard Monitor â€” Detects unauthorized access to Firefox/Gecko
/// browser credential stores, cookies, and session data.
///
/// Firefox uses a fundamentally different credential storage than Chromium:
///   - key4.db: NSS (Network Security Services) database containing the master key
///   - logins.json: Encrypted saved passwords (encrypted with key from key4.db)
///   - cookies.sqlite: Session cookies (unencrypted SQLite â€” high-value target)
///   - cert9.db: Certificate database (client certs for auth)
///   - signons.sqlite: Legacy password storage (older Firefox)
///   - sessionstore.jsonlz4: Active session state (tabs, form data, tokens)
///
/// Attack chain for Firefox credential theft:
///   Stealer â†’ copies key4.db + logins.json â†’ uses NSS library to decrypt â†’ extracts passwords
///   OR: Stealer â†’ copies cookies.sqlite directly â†’ cookies are NOT encrypted (unlike Chrome)
///
/// This is actually EASIER to steal from than Chrome because:
///   - Firefox cookies are stored in plaintext SQLite (no DPAPI encryption)
///   - The NSS key can be extracted without Windows DPAPI
///   - No App-Bound Encryption equivalent exists
///
/// MITRE ATT&amp;CK:
///   T1555.003 â€” Credentials from Password Stores: Credentials from Web Browsers
///   T1539     â€” Steal Web Session Cookie
///
/// Covers: Firefox, Firefox ESR, Waterfox, Pale Moon, Thunderbird (email credentials)
/// </summary>
public sealed class FirefoxCredentialGuardMonitor : BackgroundService
{
    private readonly DetectionEngine _detectionEngine;
    private readonly ILogger<FirefoxCredentialGuardMonitor> _logger;

    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(18);

    private readonly ConcurrentDictionary<string, DateTime> _alertedAccess = new();
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(2);

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // FIREFOX SENSITIVE FILES
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    /// <summary>
    /// Critical files â€” access by non-Firefox processes is ALWAYS suspicious.
    /// </summary>
    private static readonly string[] CriticalFiles =
    {
        "key4.db",              // NSS key database (master decryption key for passwords)
        "key3.db",              // Legacy NSS key database (older Firefox)
        "logins.json",          // Encrypted saved passwords
        "logins-backup.json",   // Backup of saved passwords
        "cookies.sqlite",       // Session cookies (UNENCRYPTED â€” high value)
        "cookies.sqlite-wal",   // Write-ahead log for cookies
        "cookies.sqlite-shm",   // Shared memory for cookies
        "signons.sqlite",       // Legacy password storage
        "cert9.db",             // Client certificates (used for auth)
        "cert8.db",             // Legacy certificate database
    };

    /// <summary>
    /// High-value files that indicate session/account theft.
    /// </summary>
    private static readonly string[] HighValueFiles =
    {
        "sessionstore.jsonlz4",         // Active session (tabs, form data, tokens)
        "sessionstore-backups",         // Session backups
        "webappsstore.sqlite",          // Web app storage (may contain tokens)
        "formhistory.sqlite",           // Form autofill data
        "places.sqlite",               // History + bookmarks (privacy theft)
        "storage.sqlite",              // IndexedDB metadata
        "permissions.sqlite",          // Site permissions
    };

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // FIREFOX PROFILE PATHS
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    private static readonly (string BrowserName, string RelativePath)[] FirefoxPaths =
    {
        ("Firefox",      @"Mozilla\Firefox\Profiles"),
        ("Firefox ESR",  @"Mozilla\Firefox ESR\Profiles"),
        ("Waterfox",     @"Waterfox\Profiles"),
        ("Pale Moon",    @"Moonchild Productions\Pale Moon\Profiles"),
        ("Thunderbird",  @"Thunderbird\Profiles"),  // Email client â€” stores email account credentials
    };

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // LEGITIMATE PROCESSES
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    private static readonly HashSet<string> LegitimateProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Firefox processes
        "firefox", "firefox.exe",
        "waterfox", "waterfox.exe",
        "palemoon", "palemoon.exe",
        "thunderbird", "thunderbird.exe",
        // Firefox helper processes
        "plugin-container", "plugin-container.exe",
        "firefox-crashreporter", "crashreporter", "crashreporter.exe",
        "updater", "updater.exe",
        "maintenanceservice", "maintenanceservice.exe",
        // Windows Defender / AV
        "MsMpEng", "MsMpEng.exe",
        "MsSense", "MsSense.exe",
        "MpCmdRun", "MpCmdRun.exe",
        // Sentinel itself
        "SentinelService", "SentinelService.exe",
        "SentinelAgent", "SentinelAgent.exe",
        // Windows system
        "SearchIndexer", "SearchIndexer.exe",
        "svchost", "svchost.exe",
        "System",
    };

    private readonly List<string> _monitoredPaths = new();
    private readonly List<FileSystemWatcher> _watchers = new();

    public FirefoxCredentialGuardMonitor(
        DetectionEngine detectionEngine,
        ILogger<FirefoxCredentialGuardMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Firefox Credential Guard Monitor starting ===");

        await Task.Delay(InitialDelay, stoppingToken);

        DiscoverFirefoxProfiles();

        if (_monitoredPaths.Count == 0)
        {
            _logger.LogInformation("FirefoxCredentialGuard: No Firefox profiles found. Monitor idle.");
            return;
        }

        _logger.LogInformation("FirefoxCredentialGuard: Monitoring {Count} Firefox profile paths", _monitoredPaths.Count);

        SetupWatchers();

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
                _logger.LogError(ex, "FirefoxCredentialGuard: Scan error");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }

        foreach (var watcher in _watchers)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
        }
    }

    private void DiscoverFirefoxProfiles()
    {
        var appDataRoaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        foreach (var (browserName, relativePath) in FirefoxPaths)
        {
            var profilesDir = Path.Combine(appDataRoaming, relativePath);
            if (!Directory.Exists(profilesDir)) continue;

            // Firefox profiles are named like "xxxxxxxx.default-release"
            foreach (var profileDir in Directory.GetDirectories(profilesDir))
            {
                // Verify it's a real profile (has prefs.js or key4.db)
                if (File.Exists(Path.Combine(profileDir, "prefs.js")) ||
                    File.Exists(Path.Combine(profileDir, "key4.db")))
                {
                    _monitoredPaths.Add(profileDir);
                    _logger.LogDebug("FirefoxCredentialGuard: Found {Browser} profile at {Path}",
                        browserName, profileDir);
                }
            }
        }
    }

    private void SetupWatchers()
    {
        foreach (var profilePath in _monitoredPaths)
        {
            try
            {
                var watcher = new FileSystemWatcher(profilePath)
                {
                    NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite |
                                  NotifyFilters.FileName | NotifyFilters.Size,
                    EnableRaisingEvents = true,
                    IncludeSubdirectories = false,
                    InternalBufferSize = 16384
                };

                watcher.Changed += OnFirefoxFileAccessed;
                watcher.Created += OnFirefoxFileCopied;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "FirefoxCredentialGuard: Failed to watch {Path}", profilePath);
            }
        }
    }

    private void OnFirefoxFileAccessed(object sender, FileSystemEventArgs e)
    {
        var fileName = Path.GetFileName(e.FullPath);
        if (!IsCriticalFile(fileName) && !IsHighValueFile(fileName))
            return;

        _ = Task.Run(async () =>
        {
            try
            {
                await CheckFileAccessAsync(e.FullPath, fileName, CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "FirefoxCredentialGuard: Error checking access for {File}", fileName);
            }
        });
    }

    private void OnFirefoxFileCopied(object sender, FileSystemEventArgs e)
    {
        var fileName = Path.GetFileName(e.FullPath);

        // Detect copies of critical files (e.g., "key4.db.bak", "cookies.sqlite.tmp")
        foreach (var critical in CriticalFiles)
        {
            if (fileName.Contains(critical, StringComparison.OrdinalIgnoreCase) &&
                !fileName.Equals(critical, StringComparison.OrdinalIgnoreCase))
            {
                _ = Task.Run(async () =>
                {
                    await EmitDetectionAsync(
                        "Browser Credential Theft: Firefox Data Copy",
                        $"A copy/variant of Firefox credential file '{critical}' was created: '{e.FullPath}'. " +
                        "Infostealers copy Firefox databases to avoid file-locking conflicts.",
                        "Firefox credential stealers copy key4.db + logins.json (for passwords) or " +
                        "cookies.sqlite (for session cookies) to a temp location. Unlike Chrome, Firefox " +
                        "cookies are stored in PLAINTEXT SQLite â€” no decryption needed. This makes Firefox " +
                        "an even higher-value target for session hijacking.",
                        0.92,
                        DetectionTier.Tier1Behavioral,
                        "Unknown", 0,
                        new Dictionary<string, string>
                        {
                            ["target_file"] = e.FullPath,
                            ["original_file"] = critical,
                            ["browser"] = "Firefox",
                            ["technique"] = "T1555.003 - Credentials from Web Browsers"
                        },
                        CancellationToken.None);
                });
                break;
            }
        }
    }

    private async Task ScanForSuspiciousAccessAsync(CancellationToken ct)
    {
        var processes = Process.GetProcesses();

        foreach (var process in processes)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                if (process.Id <= 4 || process.Id == Environment.ProcessId) continue;
                if (LegitimateProcesses.Contains(process.ProcessName)) continue;

                var cmdLine = GetProcessCommandLine(process);
                if (string.IsNullOrEmpty(cmdLine)) continue;

                var cmdLower = cmdLine.ToLowerInvariant();

                // Check for references to Firefox credential files
                bool targetsFirefox = cmdLower.Contains("key4.db") ||
                                     cmdLower.Contains("key3.db") ||
                                     cmdLower.Contains("logins.json") ||
                                     cmdLower.Contains("cookies.sqlite") ||
                                     cmdLower.Contains("signons.sqlite") ||
                                     cmdLower.Contains("cert9.db") ||
                                     cmdLower.Contains("mozilla\\firefox\\profiles") ||
                                     cmdLower.Contains("thunderbird\\profiles");

                if (targetsFirefox)
                {
                    var alertKey = $"{process.Id}|firefox";
                    if (!ShouldAlert(alertKey)) continue;

                    await EmitDetectionAsync(
                        "Browser Credential Theft: Firefox Data Access",
                        $"Process '{process.ProcessName}' (PID {process.Id}) references Firefox credential " +
                        $"files in its command line. CommandLine: {cmdLine}",
                        "Non-Firefox processes should never reference key4.db, logins.json, or cookies.sqlite. " +
                        "Firefox cookies are stored in PLAINTEXT (no encryption) making them trivial to steal. " +
                        "The key4.db + logins.json combination allows full password decryption via NSS libraries. " +
                        "Tools: LaZagne, Firepwd, firefox_decrypt, custom Python stealers.",
                        0.94,
                        DetectionTier.Tier1Behavioral,
                        process.ProcessName, process.Id,
                        new Dictionary<string, string>
                        {
                            ["command_line"] = cmdLine,
                            ["browser"] = "Firefox",
                            ["technique"] = "T1555.003 - Credentials from Web Browsers"
                        },
                        ct);
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

    private async Task CheckFileAccessAsync(string filePath, string fileName, CancellationToken ct)
    {
        await Task.Delay(100, ct);

        var processes = Process.GetProcesses();

        foreach (var process in processes)
        {
            try
            {
                if (process.Id <= 4 || process.Id == Environment.ProcessId) continue;
                if (LegitimateProcesses.Contains(process.ProcessName)) continue;

                // Check process age â€” young processes accessing Firefox data are suspicious
                TimeSpan processAge;
                try { processAge = DateTime.UtcNow - process.StartTime.ToUniversalTime(); }
                catch { continue; }

                if (processAge < TimeSpan.FromMinutes(2))
                {
                    var alertKey = $"{process.Id}|{fileName}";
                    if (!ShouldAlert(alertKey)) continue;

                    var confidence = IsCriticalFile(fileName) ? 0.93 : 0.78;

                    await EmitDetectionAsync(
                        "Browser Credential Theft: Firefox Unauthorized Access",
                        $"Recently-started process '{process.ProcessName}' (PID {process.Id}, age: {processAge.TotalSeconds:F0}s) " +
                        $"detected while Firefox credential file '{fileName}' was accessed.",
                        "Short-lived processes accessing Firefox credential stores indicate infostealer activity. " +
                        "Firefox's cookies.sqlite requires NO decryption â€” a simple file copy gives the attacker " +
                        "all session cookies including Microsoft account, Google account, and banking sessions.",
                        confidence,
                        DetectionTier.Tier1Behavioral,
                        process.ProcessName, process.Id,
                        new Dictionary<string, string>
                        {
                            ["accessed_file"] = filePath,
                            ["file_name"] = fileName,
                            ["process_age_seconds"] = processAge.TotalSeconds.ToString("F0"),
                            ["browser"] = "Firefox",
                            ["technique"] = "T1555.003 - Credentials from Web Browsers"
                        },
                        ct);
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

    private static bool IsCriticalFile(string fileName)
    {
        return CriticalFiles.Any(f => string.Equals(fileName, f, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsHighValueFile(string fileName)
    {
        return HighValueFiles.Any(f => string.Equals(fileName, f, StringComparison.OrdinalIgnoreCase));
    }

    private bool ShouldAlert(string key)
    {
        if (_alertedAccess.TryGetValue(key, out var last))
        {
            if (DateTime.UtcNow - last < AlertCooldown)
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
        _logger.LogCritical("FIREFOX CREDENTIAL GUARD: {Rule} | PID {Pid} ({Name})",
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
                return obj["CommandLine"]?.ToString();
        }
        catch { }
        return null;
    }
}
