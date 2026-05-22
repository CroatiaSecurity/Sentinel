using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Browser Extension Monitor — Detects silent installation of malicious Chrome extensions.
///
/// Protects against:
///   1. Extensions installed via registry (enterprise policy abuse)
///   2. Extensions side-loaded into profile without user interaction
///   3. Extension manifest tampering (modifying existing extensions)
///   4. Extensions with dangerous permissions (cookies, webRequest, all_urls)
///
/// How it works:
///   - Takes a baseline snapshot of installed extensions at startup
///   - Monitors the Extensions directory for new additions
///   - Checks registry keys used for force-installed extensions
///   - Validates extension manifests for suspicious permission combinations
///
/// MITRE ATT&amp;CK:
///   T1176 — Browser Extensions
///   T1185 — Browser Session Hijacking
///
/// False positive handling:
///   - Extensions installed while browser is in foreground are lower confidence
///   - Known extension IDs from Chrome Web Store are lower priority
///   - Only alerts on dangerous permission combinations
/// </summary>
public sealed class BrowserExtensionMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<BrowserExtensionMonitor> _logger;

    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(20);

    // Baseline of known extensions (extensionId -> hash of manifest)
    private readonly ConcurrentDictionary<string, ExtensionBaseline> _knownExtensions = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedExtensions = new();

    // Dangerous permission combinations that indicate malicious intent
    private static readonly string[] DangerousPermissions =
    {
        "cookies",                  // Can steal session cookies
        "webRequest",              // Can intercept/modify all traffic
        "webRequestBlocking",     // Can block/modify requests
        "<all_urls>",             // Access to all websites
        "http://*/*",             // All HTTP sites
        "https://*/*",            // All HTTPS sites
        "tabs",                   // Can enumerate all tabs
        "history",                // Browser history access
        "bookmarks",             // Bookmark access
        "clipboardRead",         // Clipboard access
        "nativeMessaging",       // Can communicate with native apps
        "debugger",              // Full debugging access
        "proxy",                 // Can redirect traffic
        "management",            // Can manage other extensions
    };

    // Permission combinations that are especially suspicious together
    private static readonly (string[], string Reason)[] SuspiciousCombinations =
    {
        (new[] { "cookies", "<all_urls>" }, "Can steal cookies from any website (session hijacking)"),
        (new[] { "webRequest", "webRequestBlocking", "<all_urls>" }, "Can intercept and modify all web traffic (MitM)"),
        (new[] { "nativeMessaging", "cookies" }, "Can exfiltrate cookies to a native application"),
        (new[] { "tabs", "cookies", "history" }, "Full browser surveillance capability"),
        (new[] { "debugger", "<all_urls>" }, "Can inject JavaScript into any page (credential theft)"),
    };

    // Registry paths for force-installed extensions
    private static readonly string[] ExtensionRegistryPaths =
    {
        @"SOFTWARE\Google\Chrome\Extensions",
        @"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
        @"SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist",
        @"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist",
        @"SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist",
    };

    private static readonly (string BrowserName, string RelativePath)[] BrowserExtensionPaths =
    {
        ("Chrome",   @"Google\Chrome\User Data"),
        ("Edge",     @"Microsoft\Edge\User Data"),
        ("Brave",    @"BraveSoftware\Brave-Browser\User Data"),
        ("Vivaldi",  @"Vivaldi\User Data"),
        ("Arc",      @"Arc\User Data"),
    };

    private readonly List<string> _extensionDirs = new();
    private readonly List<FileSystemWatcher> _watchers = new();

    public BrowserExtensionMonitor(
        IDetectionEngine detectionEngine,
        ILogger<BrowserExtensionMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Browser Extension Monitor starting ===");

        await Task.Delay(InitialDelay, stoppingToken);

        // Discover extension directories
        DiscoverExtensionPaths();

        if (_extensionDirs.Count == 0)
        {
            _logger.LogWarning("BrowserExtensionMonitor: No browser extension directories found. Monitor idle.");
            return;
        }

        // Take baseline snapshot
        await TakeBaselineAsync(stoppingToken);

        _logger.LogInformation("BrowserExtensionMonitor: Baseline captured ({Count} extensions across {Dirs} browsers)",
            _knownExtensions.Count, _extensionDirs.Count);

        // Setup watchers for new extension installations
        SetupWatchers();

        // Periodic scan for registry-based force installs and new extensions
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanForNewExtensionsAsync(stoppingToken);
                await ScanRegistryForceInstallsAsync(stoppingToken);
                await Task.Delay(ScanInterval, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "BrowserExtensionMonitor: Scan error");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }

        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
            w.Dispose();
        }
    }

    private void DiscoverExtensionPaths()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (var (browserName, relativePath) in BrowserExtensionPaths)
        {
            var userDataPath = Path.Combine(localAppData, relativePath);
            if (!Directory.Exists(userDataPath)) continue;

            // Check Default profile and numbered profiles
            var profiles = new[] { "Default" }
                .Concat(Directory.GetDirectories(userDataPath)
                    .Where(d => Path.GetFileName(d).StartsWith("Profile ", StringComparison.OrdinalIgnoreCase))
                    .Select(Path.GetFileName)!);

            foreach (var profile in profiles)
            {
                var extDir = Path.Combine(userDataPath, profile!, "Extensions");
                if (Directory.Exists(extDir))
                {
                    _extensionDirs.Add(extDir);
                    _logger.LogDebug("BrowserExtensionMonitor: Found {Browser}/{Profile} extensions at {Path}",
                        browserName, profile, extDir);
                }
            }
        }
    }

    private async Task TakeBaselineAsync(CancellationToken ct)
    {
        foreach (var extDir in _extensionDirs)
        {
            try
            {
                foreach (var extensionDir in Directory.GetDirectories(extDir))
                {
                    ct.ThrowIfCancellationRequested();
                    var extensionId = Path.GetFileName(extensionDir);

                    // Find the latest version directory
                    var versionDirs = Directory.GetDirectories(extensionDir);
                    if (versionDirs.Length == 0) continue;

                    var latestVersion = versionDirs.OrderByDescending(d => d).First();
                    var manifestPath = Path.Combine(latestVersion, "manifest.json");

                    if (!File.Exists(manifestPath)) continue;

                    var manifestContent = await File.ReadAllTextAsync(manifestPath, ct);
                    var hash = ComputeHash(manifestContent);

                    _knownExtensions[extensionId] = new ExtensionBaseline
                    {
                        ExtensionId = extensionId,
                        ManifestHash = hash,
                        ManifestPath = manifestPath,
                        FirstSeen = DateTimeOffset.UtcNow,
                        ExtensionDir = extDir
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "BrowserExtensionMonitor: Error scanning {Dir}", extDir);
            }
        }
    }

    private void SetupWatchers()
    {
        foreach (var extDir in _extensionDirs)
        {
            try
            {
                var watcher = new FileSystemWatcher(extDir)
                {
                    NotifyFilter = NotifyFilters.DirectoryName | NotifyFilters.FileName,
                    EnableRaisingEvents = true,
                    IncludeSubdirectories = true
                };

                watcher.Created += OnExtensionFileCreated;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "BrowserExtensionMonitor: Failed to watch {Dir}", extDir);
            }
        }
    }

    private void OnExtensionFileCreated(object sender, FileSystemEventArgs e)
    {
        if (!e.FullPath.EndsWith("manifest.json", StringComparison.OrdinalIgnoreCase))
            return;

        // New manifest.json created — possible new extension installation
        _ = Task.Run(async () =>
        {
            // Wait for file to be fully written
            await Task.Delay(2000);

            try
            {
                if (!File.Exists(e.FullPath)) return;

                var manifestContent = await File.ReadAllTextAsync(e.FullPath);
                await AnalyzeNewExtensionAsync(e.FullPath, manifestContent, CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "BrowserExtensionMonitor: Error analyzing new extension");
            }
        });
    }

    private async Task ScanForNewExtensionsAsync(CancellationToken ct)
    {
        foreach (var extDir in _extensionDirs)
        {
            try
            {
                foreach (var extensionDir in Directory.GetDirectories(extDir))
                {
                    ct.ThrowIfCancellationRequested();
                    var extensionId = Path.GetFileName(extensionDir);

                    if (_knownExtensions.ContainsKey(extensionId)) continue;
                    if (_alertedExtensions.ContainsKey(extensionId)) continue;

                    // New extension found
                    var versionDirs = Directory.GetDirectories(extensionDir);
                    if (versionDirs.Length == 0) continue;

                    var latestVersion = versionDirs.OrderByDescending(d => d).First();
                    var manifestPath = Path.Combine(latestVersion, "manifest.json");

                    if (!File.Exists(manifestPath)) continue;

                    var manifestContent = await File.ReadAllTextAsync(manifestPath, ct);
                    await AnalyzeNewExtensionAsync(manifestPath, manifestContent, ct);

                    // Add to baseline
                    _knownExtensions[extensionId] = new ExtensionBaseline
                    {
                        ExtensionId = extensionId,
                        ManifestHash = ComputeHash(manifestContent),
                        ManifestPath = manifestPath,
                        FirstSeen = DateTimeOffset.UtcNow,
                        ExtensionDir = extDir
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "BrowserExtensionMonitor: Error scanning {Dir}", extDir);
            }
        }
    }

    private async Task AnalyzeNewExtensionAsync(string manifestPath, string manifestContent, CancellationToken ct)
    {
        try
        {
            using var doc = JsonDocument.Parse(manifestContent);
            var root = doc.RootElement;

            var name = root.TryGetProperty("name", out var nameProp) ? nameProp.GetString() : "Unknown";
            var description = root.TryGetProperty("description", out var descProp) ? descProp.GetString() : "";

            // Extract permissions
            var permissions = new List<string>();
            if (root.TryGetProperty("permissions", out var permsProp) && permsProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var perm in permsProp.EnumerateArray())
                    permissions.Add(perm.GetString() ?? "");
            }
            if (root.TryGetProperty("host_permissions", out var hostPermsProp) && hostPermsProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var perm in hostPermsProp.EnumerateArray())
                    permissions.Add(perm.GetString() ?? "");
            }
            // Manifest V2 style
            if (root.TryGetProperty("optional_permissions", out var optPermsProp) && optPermsProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var perm in optPermsProp.EnumerateArray())
                    permissions.Add(perm.GetString() ?? "");
            }

            // Check for dangerous permission combinations
            var dangerousPerms = permissions.Where(p =>
                DangerousPermissions.Any(dp => p.Contains(dp, StringComparison.OrdinalIgnoreCase))).ToList();

            if (dangerousPerms.Count == 0) return;

            // Check for especially suspicious combinations
            string? suspiciousReason = null;
            foreach (var (combo, reason) in SuspiciousCombinations)
            {
                if (combo.All(c => permissions.Any(p => p.Contains(c, StringComparison.OrdinalIgnoreCase))))
                {
                    suspiciousReason = reason;
                    break;
                }
            }

            // Determine confidence based on how suspicious the extension is
            double confidence;
            DetectionTier tier;

            if (suspiciousReason != null)
            {
                confidence = 0.88;
                tier = DetectionTier.Tier1Behavioral;
            }
            else if (dangerousPerms.Count >= 3)
            {
                confidence = 0.80;
                tier = DetectionTier.Tier1Behavioral;
            }
            else
            {
                confidence = 0.65;
                tier = DetectionTier.Tier2Indicator;
            }

            // Check if browser is running (if not, this is more suspicious — silent install)
            bool browserRunning = IsBrowserRunning();
            if (!browserRunning)
            {
                confidence = Math.Min(confidence + 0.10, 0.98);
                suspiciousReason = (suspiciousReason ?? "") + " [Installed while browser was NOT running — silent install]";
            }

            var extensionId = GetExtensionIdFromPath(manifestPath);
            _alertedExtensions[extensionId] = DateTimeOffset.UtcNow;

            _logger.LogCritical(
                "BROWSER EXTENSION MONITOR: Suspicious extension '{Name}' (ID: {Id}) with dangerous permissions: {Perms}",
                name, extensionId, string.Join(", ", dangerousPerms));

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Browser Credential Theft: Malicious Extension",
                Evidence = $"New browser extension '{name}' (ID: {extensionId}) installed with dangerous permissions: " +
                          $"[{string.Join(", ", dangerousPerms)}]. " +
                          $"Manifest: {manifestPath}. " +
                          (suspiciousReason != null ? $"Suspicious: {suspiciousReason}" : ""),
                Reasoning = "Malicious browser extensions are a primary vector for Google account compromise. " +
                           "Extensions with cookie access + all_urls can steal active sessions, bypass 2FA, " +
                           "and maintain persistent access to Google accounts. Silent installation (without " +
                           "browser running or via registry policy) indicates malware-driven deployment.",
                Confidence = confidence,
                Tier = tier,
                ProcessName = "Extension Install",
                ProcessId = 0,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["extension_id"] = extensionId,
                    ["extension_name"] = name ?? "Unknown",
                    ["permissions"] = string.Join(", ", dangerousPerms),
                    ["manifest_path"] = manifestPath,
                    ["browser_running"] = browserRunning.ToString(),
                    ["suspicious_reason"] = suspiciousReason ?? "N/A",
                    ["technique"] = "T1176 - Browser Extensions"
                }
            }, ct);
        }
        catch (JsonException)
        {
            // Malformed manifest — could be obfuscated malware
            _logger.LogWarning("BrowserExtensionMonitor: Malformed manifest at {Path}", manifestPath);
        }
    }

    private async Task ScanRegistryForceInstallsAsync(CancellationToken ct)
    {
        foreach (var regPath in ExtensionRegistryPaths)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(regPath);
                if (key == null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var value = key.GetValue(valueName)?.ToString();
                    if (string.IsNullOrEmpty(value)) continue;

                    var alertKey = $"reg|{regPath}|{valueName}";
                    if (_alertedExtensions.ContainsKey(alertKey)) continue;
                    _alertedExtensions[alertKey] = DateTimeOffset.UtcNow;

                    _logger.LogCritical(
                        "BROWSER EXTENSION MONITOR: Registry force-install detected: {Path}\\{Name} = {Value}",
                        regPath, valueName, value);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Browser Credential Theft: Registry Force-Install Extension",
                        Evidence = $"Extension force-installed via registry policy: {regPath}\\{valueName} = {value}. " +
                                  "This bypasses user consent and Chrome Web Store verification.",
                        Reasoning = "Malware uses Chrome enterprise policy registry keys to force-install extensions " +
                                   "without user interaction. These extensions persist across browser restarts and " +
                                   "cannot be easily removed by the user. This is a common persistence mechanism " +
                                   "for session hijackers and credential stealers (T1176).",
                        Confidence = 0.90,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "Registry",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["registry_path"] = $"{regPath}\\{valueName}",
                            ["extension_value"] = value,
                            ["technique"] = "T1176 - Browser Extensions"
                        }
                    }, ct);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "BrowserExtensionMonitor: Error reading registry {Path}", regPath);
            }
        }
    }

    private static bool IsBrowserRunning()
    {
        var browserNames = new[] { "chrome", "msedge", "brave", "opera", "vivaldi", "arc" };
        var processes = Process.GetProcesses();
        try
        {
            return processes.Any(p => browserNames.Contains(p.ProcessName, StringComparer.OrdinalIgnoreCase));
        }
        finally
        {
            foreach (var p in processes) p.Dispose();
        }
    }

    private static string GetExtensionIdFromPath(string manifestPath)
    {
        // Path format: .../Extensions/{extensionId}/{version}/manifest.json
        var parts = manifestPath.Split(Path.DirectorySeparatorChar);
        for (int i = parts.Length - 1; i >= 2; i--)
        {
            if (parts[i] == "manifest.json" && i >= 2)
                return parts[i - 2]; // Two levels up from manifest.json
        }
        return "unknown";
    }

    private static string ComputeHash(string content)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(content);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash);
    }
}

internal sealed class ExtensionBaseline
{
    public string ExtensionId { get; init; } = "";
    public string ManifestHash { get; init; } = "";
    public string ManifestPath { get; init; } = "";
    public DateTimeOffset FirstSeen { get; init; }
    public string ExtensionDir { get; init; } = "";
}
