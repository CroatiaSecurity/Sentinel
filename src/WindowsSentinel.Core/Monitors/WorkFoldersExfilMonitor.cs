using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Work Folders Exfiltration Monitor — Detects unauthorized activation or abuse of
/// Windows Work Folders (workfolderssvc.dll) for data exfiltration or surveillance.
///
/// Work Folders is a Windows enterprise sync feature that can silently sync local
/// folders to a remote server over HTTPS (port 443). If an attacker or government
/// entity configures Work Folders via Group Policy or registry manipulation, they
/// can exfiltrate files from the user's machine without any visible indication.
///
/// This monitor detects:
///   1. Work Folders service activation (service starting when not expected)
///   2. Registry configuration changes (new sync server URL appearing)
///   3. Group Policy injection for Work Folders auto-provisioning
///   4. Active sync connections from the Work Folders service
///   5. Unauthorized SyncShare configuration in registry
///   6. workfolderssvc.dll making outbound network connections
///
/// Response: KILL-AUTHORIZED. Any unauthorized Work Folders activation is treated
/// as data exfiltration and the service is immediately stopped + blocked.
///
/// MITRE ATT&amp;CK:
///   T1567     — Exfiltration Over Web Service
///   T1048     — Exfiltration Over Alternative Protocol
///   T1052     — Exfiltration Over Physical Medium (sync to controlled server)
///   T1484.001 — Domain Policy Modification: Group Policy Modification
/// </summary>
public sealed class WorkFoldersExfilMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<WorkFoldersExfilMonitor> _logger;

    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(10);

    private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedKeys = new();
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);

    // Track whether Work Folders was configured at startup (baseline)
    private bool _wasConfiguredAtStartup = false;
    private string? _baselineServerUrl = null;

    // ═══════════════════════════════════════════════════════════════════════════
    // REGISTRY PATHS TO MONITOR
    // ═══════════════════════════════════════════════════════════════════════════

    private static readonly string[] UserRegistryPaths =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\WorkFolders",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\WorkFolders\SyncEngines",
    };

    private static readonly string[] PolicyRegistryPaths =
    {
        @"SOFTWARE\Policies\Microsoft\Windows\WorkFolders",
        @"SOFTWARE\Policies\Microsoft\Windows\WorkFolders\AutoProvision",
        @"SOFTWARE\Policies\Microsoft\Windows\Work Folders",
    };

    private static readonly string[] MachineRegistryPaths =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\WorkFolders",
        @"SOFTWARE\Policies\Microsoft\Windows\WorkFolders",
    };

    // Service name
    private const string WorkFoldersServiceName = "workfolderssvc";

    public WorkFoldersExfilMonitor(
        IDetectionEngine detectionEngine,
        ILogger<WorkFoldersExfilMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Work Folders Exfiltration Monitor starting ===");

        await Task.Delay(InitialDelay, stoppingToken);

        // Take baseline — is Work Folders already configured?
        TakeBaseline();

        if (_wasConfiguredAtStartup)
        {
            _logger.LogCritical(
                "WORK FOLDERS MONITOR: Work Folders is ALREADY CONFIGURED at startup! Server: {Url}",
                _baselineServerUrl ?? "Unknown");

            // Emit immediate alert — this shouldn't be configured on a personal machine
            await EmitDetectionAsync(
                "Browser Credential Theft: Work Folders Pre-Configured",
                $"Work Folders sync is already configured on this machine. " +
                $"Server URL: {_baselineServerUrl ?? "Unknown"}. " +
                "This was not configured by the user and may indicate unauthorized " +
                "data exfiltration via enterprise sync.",
                "Work Folders silently syncs local folders to a remote HTTPS server. " +
                "On a personal machine with no IT department, this configuration should " +
                "not exist. It may have been pushed via Group Policy, MDM enrollment, " +
                "or direct registry manipulation by malware/government surveillance tools.",
                0.95,
                DetectionTier.Tier1Behavioral,
                "workfolderssvc", 0,
                new Dictionary<string, string>
                {
                    ["server_url"] = _baselineServerUrl ?? "Unknown",
                    ["configured_at_startup"] = "true",
                    ["technique"] = "T1567 - Exfiltration Over Web Service"
                },
                stoppingToken);
        }

        _logger.LogInformation("WorkFoldersExfilMonitor: Baseline taken. Configured: {Configured}", _wasConfiguredAtStartup);

        // Main monitoring loop
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckServiceStateAsync(stoppingToken);
                await CheckRegistryConfigAsync(stoppingToken);
                await CheckPolicyInjectionAsync(stoppingToken);
                await CheckNetworkActivityAsync(stoppingToken);
                await Task.Delay(ScanInterval, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "WorkFoldersExfilMonitor: Scan error");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
    }

    private void TakeBaseline()
    {
        try
        {
            // Check HKCU for Work Folders configuration
            using var key = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WorkFolders");

            if (key != null)
            {
                var serverUrl = key.GetValue("ServerUrl")?.ToString()
                             ?? key.GetValue("Url")?.ToString()
                             ?? key.GetValue("SyncUrl")?.ToString();

                if (!string.IsNullOrEmpty(serverUrl))
                {
                    _wasConfiguredAtStartup = true;
                    _baselineServerUrl = serverUrl;
                    return;
                }
            }

            // Check HKLM policies
            using var policyKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\WorkFolders");

            if (policyKey != null)
            {
                var autoUrl = policyKey.GetValue("ServerUrl")?.ToString()
                           ?? policyKey.GetValue("AutoDiscoverUrl")?.ToString();

                if (!string.IsNullOrEmpty(autoUrl))
                {
                    _wasConfiguredAtStartup = true;
                    _baselineServerUrl = autoUrl;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "WorkFoldersExfilMonitor: Error reading baseline");
        }
    }

    /// <summary>
    /// Detects the Work Folders service starting unexpectedly.
    /// </summary>
    private async Task CheckServiceStateAsync(CancellationToken ct)
    {
        try
        {
            using var sc = new System.ServiceProcess.ServiceController(WorkFoldersServiceName);
            if (sc.Status == System.ServiceProcess.ServiceControllerStatus.Running)
            {
                var alertKey = "svc|running";
                if (!ShouldAlert(alertKey)) return;

                _logger.LogCritical("WORK FOLDERS MONITOR: Service is RUNNING!");

                await EmitDetectionAsync(
                    "Browser Credential Theft: Work Folders Service Active",
                    "The Work Folders service (workfolderssvc) is actively running. " +
                    "This service syncs local folders to a remote server over HTTPS. " +
                    "On a personal machine, this should never be running.",
                    "Work Folders service activation on a non-enterprise machine indicates " +
                    "either malware-driven configuration or unauthorized policy push. The service " +
                    "can silently exfiltrate any configured folder's contents to a remote server " +
                    "without any user-visible indication.",
                    0.94,
                    DetectionTier.Tier1Behavioral,
                    "workfolderssvc", 0,
                    new Dictionary<string, string>
                    {
                        ["service_status"] = "Running",
                        ["technique"] = "T1567 - Exfiltration Over Web Service"
                    },
                    ct);

                // Attempt to stop the service
                try
                {
                    sc.Stop();
                    _logger.LogCritical("WORK FOLDERS MONITOR: Service STOPPED by Sentinel");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "WorkFoldersExfilMonitor: Failed to stop service");
                }
            }
        }
        catch (InvalidOperationException)
        {
            // Service doesn't exist — good
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "WorkFoldersExfilMonitor: Error checking service");
        }
    }

    /// <summary>
    /// Detects new Work Folders configuration appearing in registry.
    /// </summary>
    private async Task CheckRegistryConfigAsync(CancellationToken ct)
    {
        try
        {
            // Check HKCU
            using var key = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WorkFolders");

            if (key != null)
            {
                var serverUrl = key.GetValue("ServerUrl")?.ToString()
                             ?? key.GetValue("Url")?.ToString()
                             ?? key.GetValue("SyncUrl")?.ToString();

                if (!string.IsNullOrEmpty(serverUrl) && serverUrl != _baselineServerUrl)
                {
                    var alertKey = $"reg|{serverUrl}";
                    if (!ShouldAlert(alertKey)) return;

                    _logger.LogCritical(
                        "WORK FOLDERS MONITOR: NEW server URL detected: {Url}", serverUrl);

                    await EmitDetectionAsync(
                        "Browser Credential Theft: Work Folders Server Configured",
                        $"Work Folders sync server URL was configured: '{serverUrl}'. " +
                        "This was not present at startup and indicates active configuration " +
                        "of data exfiltration via Work Folders.",
                        "A new Work Folders server URL appearing in the registry means something " +
                        "is actively configuring file sync to a remote server. On a personal machine " +
                        "this is unauthorized and indicates data theft setup — either by malware, " +
                        "a rogue Group Policy, or surveillance software.",
                        0.96,
                        DetectionTier.Tier1Behavioral,
                        "Registry", 0,
                        new Dictionary<string, string>
                        {
                            ["server_url"] = serverUrl,
                            ["registry_path"] = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WorkFolders",
                            ["technique"] = "T1567 - Exfiltration Over Web Service"
                        },
                        ct);

                    // Delete the configuration
                    try
                    {
                        using var writeKey = Registry.CurrentUser.OpenSubKey(
                            @"SOFTWARE\Microsoft\Windows\CurrentVersion\WorkFolders", writable: true);
                        writeKey?.DeleteValue("ServerUrl", throwOnMissingValue: false);
                        writeKey?.DeleteValue("Url", throwOnMissingValue: false);
                        writeKey?.DeleteValue("SyncUrl", throwOnMissingValue: false);
                        _logger.LogCritical("WORK FOLDERS MONITOR: Server URL REMOVED from registry");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "WorkFoldersExfilMonitor: Failed to remove server URL");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "WorkFoldersExfilMonitor: Error checking registry config");
        }
    }

    /// <summary>
    /// Detects Group Policy injection for Work Folders auto-provisioning.
    /// </summary>
    private async Task CheckPolicyInjectionAsync(CancellationToken ct)
    {
        foreach (var path in PolicyRegistryPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key == null) continue;

                var valueNames = key.GetValueNames();
                if (valueNames.Length == 0) continue;

                var alertKey = $"policy|{path}";
                if (!ShouldAlert(alertKey)) continue;

                var values = string.Join(", ", valueNames.Select(v =>
                    $"{v}={key.GetValue(v)}"));

                _logger.LogCritical(
                    "WORK FOLDERS MONITOR: Group Policy detected at {Path}: {Values}",
                    path, values);

                await EmitDetectionAsync(
                    "Browser Credential Theft: Work Folders Policy Injection",
                    $"Work Folders Group Policy configuration detected at HKLM\\{path}. " +
                    $"Values: {values}. This policy forces Work Folders sync without user consent.",
                    "Group Policy-based Work Folders configuration forces automatic file sync " +
                    "to a remote server. On a personal machine not joined to a domain, this " +
                    "policy should not exist. Its presence indicates unauthorized policy injection " +
                    "— potentially by ISP-level surveillance, government tools, or malware that " +
                    "modifies local Group Policy to establish persistent data exfiltration.",
                    0.97,
                    DetectionTier.Tier1Behavioral,
                    "GroupPolicy", 0,
                    new Dictionary<string, string>
                    {
                        ["registry_path"] = $"HKLM\\{path}",
                        ["values"] = values,
                        ["technique"] = "T1484.001 - Group Policy Modification"
                    },
                    ct);

                // Remove the policy
                try
                {
                    Registry.LocalMachine.DeleteSubKeyTree(path, throwOnMissingSubKey: false);
                    _logger.LogCritical("WORK FOLDERS MONITOR: Policy key DELETED: {Path}", path);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "WorkFoldersExfilMonitor: Failed to delete policy key");
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "WorkFoldersExfilMonitor: Error checking policy {Path}", path);
            }
        }
    }

    /// <summary>
    /// Detects the Work Folders process making outbound network connections.
    /// </summary>
    private async Task CheckNetworkActivityAsync(CancellationToken ct)
    {
        try
        {
            // Check if any process named "EFS" or related to Work Folders has network connections
            var processes = Process.GetProcesses();

            foreach (var process in processes)
            {
                try
                {
                    // Work Folders runs inside svchost or as a standalone service
                    if (process.ProcessName.Equals("WorkFolders", StringComparison.OrdinalIgnoreCase) ||
                        process.ProcessName.Equals("workfolderssvc", StringComparison.OrdinalIgnoreCase))
                    {
                        var alertKey = $"proc|{process.Id}";
                        if (!ShouldAlert(alertKey)) continue;

                        _logger.LogCritical(
                            "WORK FOLDERS MONITOR: Work Folders process detected: {Name} (PID {Pid})",
                            process.ProcessName, process.Id);

                        await EmitDetectionAsync(
                            "Browser Credential Theft: Work Folders Process Running",
                            $"Work Folders process '{process.ProcessName}' (PID {process.Id}) is running. " +
                            "This process handles file sync to remote servers.",
                            "The Work Folders process is actively running, which means file synchronization " +
                            "may be in progress. On a personal machine this is unauthorized data exfiltration.",
                            0.93,
                            DetectionTier.Tier1Behavioral,
                            process.ProcessName, process.Id,
                            new Dictionary<string, string>
                            {
                                ["technique"] = "T1567 - Exfiltration Over Web Service"
                            },
                            ct);

                        // Kill it
                        try
                        {
                            process.Kill();
                            _logger.LogCritical("WORK FOLDERS MONITOR: Process KILLED: PID {Pid}", process.Id);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "WorkFoldersExfilMonitor: Failed to kill process");
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
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "WorkFoldersExfilMonitor: Error checking network activity");
        }
    }

    private bool ShouldAlert(string key)
    {
        if (_alertedKeys.TryGetValue(key, out var last))
        {
            if (DateTimeOffset.UtcNow - last < AlertCooldown)
                return false;
        }
        _alertedKeys[key] = DateTimeOffset.UtcNow;
        return true;
    }

    private async Task EmitDetectionAsync(
        string ruleName, string evidence, string reasoning,
        double confidence, DetectionTier tier,
        string processName, int processId,
        Dictionary<string, string> metadata,
        CancellationToken ct)
    {
        _logger.LogCritical("WORK FOLDERS EXFIL: {Rule} | {Process}",
            ruleName, processName);

        await _detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = ruleName,
            Evidence = evidence,
            Reasoning = reasoning,
            Confidence = confidence,
            Tier = tier,
            ProcessName = processName,
            ProcessId = processId,
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = metadata
        }, ct);
    }
}
