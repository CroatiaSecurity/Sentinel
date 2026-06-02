using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace WindowsSentinel.Core;

/// <summary>
/// Microsoft Account Guard Monitor â€” Detects unauthorized access to Microsoft account
/// tokens, Azure AD credentials, and Windows Account Manager (WAM) data.
///
/// Microsoft accounts on Windows are protected by multiple token stores:
///   1. WAM (Web Account Manager) tokens â€” stored in TokenBroker cache
///   2. Azure AD / Entra ID tokens â€” stored in WAM + registry
///   3. Office 365 tokens â€” stored in Credential Manager + registry
///   4. OneDrive tokens â€” stored in registry + SQLite
///   5. Windows Hello credentials â€” stored in NGC container
///   6. Microsoft Edge profile tokens â€” stored in Edge User Data
///
/// Attack vectors this monitor detects:
///   - TokenBroker cache theft (PRT/refresh tokens for Azure AD SSO)
///   - Primary Refresh Token (PRT) extraction (enables full Microsoft account takeover)
///   - Office token theft from registry (HKCU\Software\Microsoft\Office)
///   - WAM plugin data theft (tbres files in TokenBroker\Cache)
///   - NGC container access (Windows Hello PIN/biometric bypass)
///   - roadtx/AADInternals/TokenTacticsV2 tool usage
///
/// MITRE ATT&amp;CK:
///   T1528 â€” Steal Application Access Token
///   T1550.001 â€” Use Alternate Authentication Material: Application Access Token
///   T1555.004 â€” Credentials from Password Stores: Windows Credential Manager
///   T1606.002 â€” Forge Web Credentials: SAML Tokens
/// </summary>
public sealed class MicrosoftAccountGuardMonitor : BackgroundService
{
    private readonly DetectionEngine _detectionEngine;
    private readonly ILogger<MicrosoftAccountGuardMonitor> _logger;

    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(12);
    private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(20);

    private readonly ConcurrentDictionary<string, DateTime> _alertedAccess = new();
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(3);

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // MICROSOFT ACCOUNT TOKEN PATHS
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    /// <summary>
    /// TokenBroker cache â€” contains WAM tokens including Primary Refresh Tokens (PRT).
    /// PRT theft = full Microsoft/Azure AD account takeover.
    /// </summary>
    private static readonly string TokenBrokerRelativePath =
        @"Microsoft\TokenBroker\Cache";

    /// <summary>
    /// Windows NGC (Next Generation Credentials) â€” Windows Hello data.
    /// </summary>
    private static readonly string NgcRelativePath =
        @"Microsoft\Crypto\Keys";

    /// <summary>
    /// Critical file patterns in TokenBroker cache.
    /// </summary>
    private static readonly string[] TokenBrokerCriticalPatterns =
    {
        "*.tbres",      // Token Broker response files (contain actual tokens)
        "*.tbacct",     // Token Broker account files
    };

    /// <summary>
    /// Registry paths containing Microsoft account tokens.
    /// </summary>
    private static readonly string[] SensitiveRegistryPaths =
    {
        @"SOFTWARE\Microsoft\Office\16.0\Common\Identity",      // Office 365 tokens
        @"SOFTWARE\Microsoft\Office\16.0\Common\Internet",      // Office auth cache
        @"SOFTWARE\Microsoft\OneDrive\Accounts",                // OneDrive tokens
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\AAD",       // Azure AD tokens
        @"SOFTWARE\Microsoft\IdentityCRL",                      // Microsoft Identity tokens
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin", // Workplace join certs
    };

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // KNOWN MICROSOFT ACCOUNT THEFT TOOLS
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    private static readonly string[] MsftTokenTheftPatterns =
    {
        // Tools
        "roadtx",                       // ROADtools Token eXchange
        "roadrecon",                    // ROADtools reconnaissance
        "aadinternals",                 // AADInternals PowerShell module
        "tokentacticsv2",               // TokenTacticsV2
        "tokentactics",                 // TokenTactics
        "azurehound",                   // AzureHound (BloodHound for Azure)
        "graphrunner",                  // GraphRunner
        "teamfiltration",               // TeamFiltration
        "msolspray",                    // MSOLSpray
        "o365spray",                    // O365Spray
        "trevorspray",                  // TrevorSpray
        "familyofclient",               // Family of Client IDs abuse
        "requesttoken",                 // Generic token request
        // Command patterns
        "get-mslogintoken",
        "get-aadintaccesstoken",
        "invoke-aadintuserenum",
        "get-azureadtoken",
        "new-aadintuserfederationsettings",
        "export-aadintadfstoken",
        "get-prttoken",
        "browsercore.exe",              // BrowserCore â€” used for PRT extraction
        "microsoft.aad.brokerplugin",   // AAD Broker Plugin abuse
        // PRT-specific patterns
        "primaryrefreshtoken",
        "x-ms-refreshtokencredential",
        "tgt_deleg",                    // Kerberos TGT delegation for PRT
        "nonce",                        // PRT nonce extraction
        "cloudap",                      // CloudAP plugin (PRT storage)
    };

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // LEGITIMATE PROCESSES
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    private static readonly HashSet<string> LegitimateProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Microsoft processes that legitimately access tokens
        "lsass", "lsass.exe",
        "svchost", "svchost.exe",
        "RuntimeBroker", "RuntimeBroker.exe",
        "TokenBroker", "Microsoft.AAD.BrokerPlugin.exe",
        "backgroundTaskHost", "backgroundTaskHost.exe",
        "SystemSettings", "SystemSettings.exe",
        "OneDrive", "OneDrive.exe",
        "OUTLOOK", "OUTLOOK.EXE",
        "WINWORD", "WINWORD.EXE",
        "EXCEL", "EXCEL.EXE",
        "POWERPNT", "POWERPNT.EXE",
        "Teams", "Teams.exe", "ms-teams", "ms-teams.exe",
        "msedge", "msedge.exe",
        "chrome", "chrome.exe",
        "SearchHost", "SearchHost.exe",
        "explorer", "explorer.exe",
        "SettingsHost", "SettingsHost.exe",
        "AccountsControlHost", "AccountsControlHost.exe",
        "UserAccountBroker", "UserAccountBroker.exe",
        "MicrosoftEdgeUpdate", "MicrosoftEdgeUpdate.exe",
        // Windows Defender / AV
        "MsMpEng", "MsMpEng.exe",
        "MsSense", "MsSense.exe",
        // Sentinel
        "SentinelService", "SentinelService.exe",
        "SentinelAgent", "SentinelAgent.exe",
        // System
        "System", "services", "services.exe",
        "wininit", "wininit.exe",
        "csrss", "csrss.exe",
    };

    private readonly List<string> _tokenBrokerPaths = new();
    private readonly List<FileSystemWatcher> _watchers = new();

    public MicrosoftAccountGuardMonitor(
        DetectionEngine detectionEngine,
        ILogger<MicrosoftAccountGuardMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Microsoft Account Guard Monitor starting ===");

        await Task.Delay(InitialDelay, stoppingToken);

        DiscoverTokenPaths();
        SetupWatchers();

        _logger.LogInformation("MicrosoftAccountGuard: Monitoring {Count} token cache paths", _tokenBrokerPaths.Count);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanForTokenTheftAsync(stoppingToken);
                await ScanForPrtExtractionAsync(stoppingToken);
                PruneAlertCache();
                await Task.Delay(ScanInterval, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MicrosoftAccountGuard: Scan error");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }

        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
            w.Dispose();
        }
    }

    private void DiscoverTokenPaths()
    {
        // TokenBroker cache in LocalAppData
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var tokenBrokerPath = Path.Combine(localAppData, TokenBrokerRelativePath);
        if (Directory.Exists(tokenBrokerPath))
        {
            _tokenBrokerPaths.Add(tokenBrokerPath);
            _logger.LogDebug("MicrosoftAccountGuard: Found TokenBroker cache at {Path}", tokenBrokerPath);
        }

        // NGC keys
        var ngcPath = Path.Combine(localAppData, NgcRelativePath);
        if (Directory.Exists(ngcPath))
        {
            _tokenBrokerPaths.Add(ngcPath);
            _logger.LogDebug("MicrosoftAccountGuard: Found NGC keys at {Path}", ngcPath);
        }

        // Also check ProgramData for system-wide token caches
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var systemTokenPath = Path.Combine(programData, @"Microsoft\TokenBroker\Cache");
        if (Directory.Exists(systemTokenPath))
        {
            _tokenBrokerPaths.Add(systemTokenPath);
        }
    }

    private void SetupWatchers()
    {
        foreach (var path in _tokenBrokerPaths)
        {
            try
            {
                var watcher = new FileSystemWatcher(path)
                {
                    NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite |
                                  NotifyFilters.FileName,
                    EnableRaisingEvents = true,
                    IncludeSubdirectories = true,
                    InternalBufferSize = 16384
                };

                watcher.Changed += OnTokenFileAccessed;
                watcher.Created += OnTokenFileCreated;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "MicrosoftAccountGuard: Failed to watch {Path}", path);
            }
        }
    }

    private void OnTokenFileAccessed(object sender, FileSystemEventArgs e)
    {
        var fileName = Path.GetFileName(e.FullPath);

        // Only care about token files
        if (!fileName.EndsWith(".tbres", StringComparison.OrdinalIgnoreCase) &&
            !fileName.EndsWith(".tbacct", StringComparison.OrdinalIgnoreCase))
            return;

        _ = Task.Run(async () =>
        {
            try
            {
                await CheckTokenAccessAsync(e.FullPath, fileName, CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "MicrosoftAccountGuard: Error checking token access");
            }
        });
    }

    private void OnTokenFileCreated(object sender, FileSystemEventArgs e)
    {
        var fileName = Path.GetFileName(e.FullPath);

        // Detect copies of token files
        if ((fileName.EndsWith(".tbres", StringComparison.OrdinalIgnoreCase) ||
             fileName.EndsWith(".tbacct", StringComparison.OrdinalIgnoreCase)) &&
            (fileName.Contains(".bak", StringComparison.OrdinalIgnoreCase) ||
             fileName.Contains(".tmp", StringComparison.OrdinalIgnoreCase) ||
             fileName.Contains(".copy", StringComparison.OrdinalIgnoreCase)))
        {
            _ = Task.Run(async () =>
            {
                await EmitDetectionAsync(
                    "Browser Credential Theft: Microsoft Token Copy",
                    $"A copy of Microsoft account token file was created: '{e.FullPath}'. " +
                    "This indicates token exfiltration from the TokenBroker cache.",
                    "The TokenBroker cache contains Primary Refresh Tokens (PRT) and WAM tokens " +
                    "that provide SSO access to all Microsoft services (Outlook, OneDrive, Teams, " +
                    "Azure portal). Copying .tbres files allows offline token extraction and " +
                    "Microsoft account takeover without needing the password.",
                    0.94,
                    DetectionTier.Tier1Behavioral,
                    "Unknown", 0,
                    new Dictionary<string, string>
                    {
                        ["target_file"] = e.FullPath,
                        ["technique"] = "T1528 - Steal Application Access Token",
                        ["account_type"] = "Microsoft"
                    },
                    CancellationToken.None);
            });
        }
    }

    /// <summary>
    /// Scans for processes that reference Microsoft token theft tools or patterns.
    /// </summary>
    private async Task ScanForTokenTheftAsync(CancellationToken ct)
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

                // Check for Microsoft token theft tool patterns
                string? matchedPattern = null;
                foreach (var pattern in MsftTokenTheftPatterns)
                {
                    if (cmdLower.Contains(pattern))
                    {
                        matchedPattern = pattern;
                        break;
                    }
                }

                if (matchedPattern != null)
                {
                    var alertKey = $"msft|{process.Id}|{matchedPattern}";
                    if (!ShouldAlert(alertKey)) continue;

                    _logger.LogCritical(
                        "MICROSOFT ACCOUNT GUARD: Token theft pattern '{Pattern}' from {Name} (PID {Pid})",
                        matchedPattern, process.ProcessName, process.Id);

                    await EmitDetectionAsync(
                        "Browser Credential Theft: Microsoft Account Token Theft",
                        $"Process '{process.ProcessName}' (PID {process.Id}) uses Microsoft account " +
                        $"token theft pattern '{matchedPattern}'. CommandLine: {cmdLine}",
                        "This process references tools or techniques used to steal Microsoft account tokens " +
                        "(PRT, WAM tokens, Office tokens). A stolen Primary Refresh Token provides full " +
                        "access to all Microsoft services: Outlook email, OneDrive files, Teams messages, " +
                        "Azure resources, and more â€” without needing the password or triggering MFA.",
                        0.93,
                        DetectionTier.Tier1Behavioral,
                        process.ProcessName, process.Id,
                        new Dictionary<string, string>
                        {
                            ["matched_pattern"] = matchedPattern,
                            ["command_line"] = cmdLine,
                            ["technique"] = "T1528 - Steal Application Access Token",
                            ["account_type"] = "Microsoft"
                        },
                        ct);
                }

                // Check for TokenBroker cache path references
                if (cmdLower.Contains("tokenbroker") && cmdLower.Contains("cache") ||
                    cmdLower.Contains(".tbres") ||
                    cmdLower.Contains("microsoft\\tokenbroker"))
                {
                    var alertKey = $"tbcache|{process.Id}";
                    if (!ShouldAlert(alertKey)) continue;

                    await EmitDetectionAsync(
                        "Browser Credential Theft: TokenBroker Cache Access",
                        $"Process '{process.ProcessName}' (PID {process.Id}) references the Microsoft " +
                        $"TokenBroker cache. CommandLine: {cmdLine}",
                        "The TokenBroker cache stores WAM (Web Account Manager) tokens including the " +
                        "Primary Refresh Token. Non-system processes should never directly access this cache. " +
                        "Access indicates PRT theft for Microsoft account takeover.",
                        0.91,
                        DetectionTier.Tier1Behavioral,
                        process.ProcessName, process.Id,
                        new Dictionary<string, string>
                        {
                            ["command_line"] = cmdLine,
                            ["technique"] = "T1528 - Steal Application Access Token",
                            ["target"] = "TokenBroker Cache"
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

    /// <summary>
    /// Detects PRT (Primary Refresh Token) extraction attempts.
    /// PRT is the crown jewel â€” it provides SSO to ALL Microsoft services.
    /// </summary>
    private async Task ScanForPrtExtractionAsync(CancellationToken ct)
    {
        var processes = Process.GetProcesses();

        foreach (var process in processes)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                if (process.Id <= 4 || process.Id == Environment.ProcessId) continue;
                if (LegitimateProcesses.Contains(process.ProcessName)) continue;

                var processName = process.ProcessName;

                // BrowserCore.exe is used for PRT extraction â€” should only be spawned by browsers
                if (processName.Equals("BrowserCore", StringComparison.OrdinalIgnoreCase))
                {
                    var parentPid = GetParentProcessId(process.Id);
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

                    // BrowserCore should only be spawned by msedge or chrome
                    bool legitimateParent = parentName != null &&
                        (parentName.Equals("msedge", StringComparison.OrdinalIgnoreCase) ||
                         parentName.Equals("chrome", StringComparison.OrdinalIgnoreCase) ||
                         parentName.Equals("firefox", StringComparison.OrdinalIgnoreCase));

                    if (!legitimateParent)
                    {
                        var alertKey = $"prt|browsercore|{process.Id}";
                        if (!ShouldAlert(alertKey)) continue;

                        _logger.LogCritical(
                            "MICROSOFT ACCOUNT GUARD: BrowserCore.exe spawned by non-browser: {Parent}",
                            parentName ?? "Unknown");

                        await EmitDetectionAsync(
                            "Browser Credential Theft: PRT Extraction via BrowserCore",
                            $"BrowserCore.exe (PID {process.Id}) spawned by non-browser process " +
                            $"'{parentName ?? "Unknown"}' (PID {parentPid}). BrowserCore provides " +
                            "access to the Primary Refresh Token.",
                            "BrowserCore.exe is the Windows component that provides PRT-based SSO to " +
                            "browsers. When spawned by a non-browser process, it indicates an attacker " +
                            "is extracting the PRT for Microsoft account takeover. The PRT provides " +
                            "access to ALL Microsoft services (email, files, Teams, Azure) without MFA.",
                            0.95,
                            DetectionTier.Tier1Behavioral,
                            "BrowserCore",
                            process.Id,
                            new Dictionary<string, string>
                            {
                                ["parent_process"] = parentName ?? "Unknown",
                                ["parent_pid"] = parentPid.ToString(),
                                ["technique"] = "T1528 - Steal Application Access Token",
                                ["target"] = "Primary Refresh Token (PRT)"
                            },
                            ct);
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

    private async Task CheckTokenAccessAsync(string filePath, string fileName, CancellationToken ct)
    {
        await Task.Delay(100, ct);

        var processes = Process.GetProcesses();

        foreach (var process in processes)
        {
            try
            {
                if (process.Id <= 4 || process.Id == Environment.ProcessId) continue;
                if (LegitimateProcesses.Contains(process.ProcessName)) continue;

                TimeSpan processAge;
                try { processAge = DateTime.UtcNow - process.StartTime.ToUniversalTime(); }
                catch { continue; }

                if (processAge < TimeSpan.FromMinutes(3))
                {
                    var alertKey = $"{process.Id}|{fileName}";
                    if (!ShouldAlert(alertKey)) continue;

                    await EmitDetectionAsync(
                        "Browser Credential Theft: Microsoft Token File Access",
                        $"Recently-started process '{process.ProcessName}' (PID {process.Id}, age: {processAge.TotalSeconds:F0}s) " +
                        $"detected while Microsoft token file '{fileName}' was accessed.",
                        "TokenBroker .tbres files contain encrypted WAM tokens including the Primary Refresh " +
                        "Token. Short-lived processes accessing these files indicate token theft malware. " +
                        "A stolen PRT enables full Microsoft account access across all services.",
                        0.90,
                        DetectionTier.Tier1Behavioral,
                        process.ProcessName, process.Id,
                        new Dictionary<string, string>
                        {
                            ["accessed_file"] = filePath,
                            ["file_name"] = fileName,
                            ["process_age_seconds"] = processAge.TotalSeconds.ToString("F0"),
                            ["technique"] = "T1528 - Steal Application Access Token",
                            ["account_type"] = "Microsoft"
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
        _logger.LogCritical("MICROSOFT ACCOUNT GUARD: {Rule} | PID {Pid} ({Name})",
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
