using System.Collections.Concurrent;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Windows Update Integrity Monitor (v3.6.0) — Detects update service tampering.
///
/// Malware and APTs commonly disable Windows Update to:
///   - Prevent security patches from closing their exploit vector
///   - Maintain persistence through unpatched vulnerabilities
///   - Avoid detection by Defender definition updates
///
/// Also monitors Windows Defender update state — if definitions are stale,
/// the system is vulnerable to known threats.
///
/// Detection strategy:
///   1. Monitor Windows Update service (wuauserv) state.
///   2. Monitor BITS service state (required for updates).
///   3. Check if automatic updates are disabled via registry/GPO.
///   4. Monitor Defender definition age (stale = vulnerable).
///   5. Detect update-related registry tampering.
/// </summary>
public sealed class WindowsUpdateIntegrityMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<WindowsUpdateIntegrityMonitor> _logger;

    // Baseline
    private bool? _baselineWuRunning;
    private bool? _baselineBitsRunning;
    private bool? _baselineAutoUpdateEnabled;

    // Deduplication
    private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedEvents = new();
    private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromHours(1);
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(2);

    // Defender definitions older than this are considered stale
    private static readonly TimeSpan DefenderStaleThreshold = TimeSpan.FromDays(7);

    public WindowsUpdateIntegrityMonitor(
        IDetectionEngine detectionEngine,
        ILogger<WindowsUpdateIntegrityMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[WindowsUpdateIntegrityMonitor] Starting — update integrity monitoring active");

        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);

        CaptureBaseline();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckUpdateIntegrityAsync(stoppingToken);
                PruneAlertCache();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "[WindowsUpdateIntegrityMonitor] Check error");
            }

            await Task.Delay(PollInterval, stoppingToken);
        }
    }

    private void CaptureBaseline()
    {
        _baselineWuRunning = IsServiceRunning("wuauserv");
        _baselineBitsRunning = IsServiceRunning("BITS");
        _baselineAutoUpdateEnabled = IsAutoUpdateEnabled();

        _logger.LogInformation(
            "[WindowsUpdateIntegrityMonitor] Baseline: WU={Wu}, BITS={Bits}, AutoUpdate={Auto}",
            _baselineWuRunning, _baselineBitsRunning, _baselineAutoUpdateEnabled);
    }

    private async Task CheckUpdateIntegrityAsync(CancellationToken ct)
    {
        // ═══════════════════════════════════════════════════════════════════
        // CHECK 1: Windows Update service stopped
        // ═══════════════════════════════════════════════════════════════════
        var wuRunning = IsServiceRunning("wuauserv");
        if (_baselineWuRunning == true && wuRunning == false)
        {
            var dedupeKey = "wu_stopped";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Update Integrity: Windows Update Service Stopped",
                    Evidence = "Windows Update service (wuauserv) was STOPPED (was previously running). " +
                               "Security patches and Defender updates cannot be delivered.",
                    Reasoning = "Malware stops the Windows Update service to prevent security patches " +
                                "from closing the vulnerability it exploits. APTs maintain access by " +
                                "ensuring the system remains unpatched. If the user didn't stop it, " +
                                "this is active defense evasion.",
                    Confidence = 0.78,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "WindowsUpdate",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["service"] = "wuauserv",
                        ["state"] = "stopped",
                        ["technique"] = "T1562.001 - Impair Defenses: Disable or Modify Tools",
                        ["attack_type"] = "wu_service_stopped"
                    }
                }, ct);
            }
        }
        _baselineWuRunning = wuRunning;

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 2: BITS service stopped (required for update delivery)
        // ═══════════════════════════════════════════════════════════════════
        var bitsRunning = IsServiceRunning("BITS");
        if (_baselineBitsRunning == true && bitsRunning == false)
        {
            var dedupeKey = "bits_stopped";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Update Integrity: BITS Service Stopped",
                    Evidence = "Background Intelligent Transfer Service (BITS) was STOPPED. " +
                               "Windows Update cannot download patches without BITS.",
                    Reasoning = "BITS is required for Windows Update to download patches. Stopping it " +
                                "silently prevents updates without showing obvious errors to the user. " +
                                "This is a subtler approach than disabling Windows Update directly.",
                    Confidence = 0.65,
                    Tier = DetectionTier.Tier2Indicator,
                    ProcessName = "WindowsUpdate",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["service"] = "BITS",
                        ["state"] = "stopped",
                        ["technique"] = "T1562.001 - Impair Defenses: Disable or Modify Tools",
                        ["attack_type"] = "bits_stopped"
                    }
                }, ct);
            }
        }
        _baselineBitsRunning = bitsRunning;

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 3: Automatic updates disabled via registry
        // ═══════════════════════════════════════════════════════════════════
        var autoUpdateEnabled = IsAutoUpdateEnabled();
        if (_baselineAutoUpdateEnabled == true && autoUpdateEnabled == false)
        {
            var dedupeKey = "autoupdate_disabled";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Update Integrity: Automatic Updates Disabled",
                    Evidence = "Windows automatic updates were DISABLED via registry/GPO " +
                               "(was previously enabled). The system will not receive security patches.",
                    Reasoning = "Disabling automatic updates via registry is a common malware technique " +
                                "to prevent the system from patching vulnerabilities. Unlike stopping the " +
                                "service (which may auto-restart), registry changes persist across reboots.",
                    Confidence = 0.80,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "WindowsUpdate",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["auto_update"] = "disabled",
                        ["technique"] = "T1562.001 - Impair Defenses: Disable or Modify Tools",
                        ["attack_type"] = "autoupdate_disabled"
                    }
                }, ct);
            }
        }
        _baselineAutoUpdateEnabled = autoUpdateEnabled;

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 4: Defender definitions stale
        // ═══════════════════════════════════════════════════════════════════
        var defenderAge = GetDefenderDefinitionAge();
        if (defenderAge != null && defenderAge > DefenderStaleThreshold)
        {
            var dedupeKey = "defender_stale";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Update Integrity: Defender Definitions Stale",
                    Evidence = $"Windows Defender virus definitions are {defenderAge.Value.TotalDays:F0} days old " +
                               $"(threshold: {DefenderStaleThreshold.TotalDays} days). " +
                               "The system is vulnerable to recently discovered threats.",
                    Reasoning = "Stale Defender definitions mean the system cannot detect recently discovered " +
                                "malware. This can be caused by: (1) malware blocking Defender updates, " +
                                "(2) Windows Update being disabled, (3) network isolation preventing downloads. " +
                                "Combined with other tampering indicators, this confirms active defense evasion.",
                    Confidence = 0.70,
                    Tier = DetectionTier.Tier2Indicator,
                    ProcessName = "WindowsDefender",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["definition_age_days"] = defenderAge.Value.TotalDays.ToString("F0"),
                        ["threshold_days"] = DefenderStaleThreshold.TotalDays.ToString(),
                        ["technique"] = "T1562.001 - Impair Defenses: Disable or Modify Tools",
                        ["attack_type"] = "defender_stale"
                    }
                }, ct);
            }
        }
    }

    private static bool IsServiceRunning(string serviceName)
    {
        try
        {
            using var sc = new System.ServiceProcess.ServiceController(serviceName);
            return sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
        }
        catch { return false; }
    }

    private static bool IsAutoUpdateEnabled()
    {
        try
        {
            // Check GPO setting
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU");
            if (key != null)
            {
                var noAutoUpdate = key.GetValue("NoAutoUpdate") as int?;
                if (noAutoUpdate == 1) return false;
            }

            // Check standard setting
            using var key2 = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update");
            if (key2 != null)
            {
                var auOptions = key2.GetValue("AUOptions") as int?;
                if (auOptions == 1) return false; // 1 = disabled
            }

            return true; // Default: enabled
        }
        catch { return true; }
    }

    private static TimeSpan? GetDefenderDefinitionAge()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Signature Updates");
            if (key == null) return null;

            var lastUpdate = key.GetValue("SignaturesLastUpdated") as byte[];
            if (lastUpdate == null || lastUpdate.Length < 8) return null;

            var fileTime = BitConverter.ToInt64(lastUpdate, 0);
            var lastUpdateTime = DateTime.FromFileTimeUtc(fileTime);
            return DateTime.UtcNow - lastUpdateTime;
        }
        catch { return null; }
    }

    private void PruneAlertCache()
    {
        var cutoff = DateTimeOffset.UtcNow - AlertDedupeWindow;
        foreach (var kvp in _alertedEvents)
        {
            if (kvp.Value < cutoff)
                _alertedEvents.TryRemove(kvp.Key, out _);
        }
    }
}
