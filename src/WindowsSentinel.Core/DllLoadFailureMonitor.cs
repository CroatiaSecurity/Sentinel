using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core;

/// <summary>
/// DLL Load Failure Monitor â€” Monitors Windows Event Log for DLL load failures
/// (Event ID 7 in System log) which can indicate:
///   - DLL hijacking attempts (attacker planted DLL was blocked/failed)
///   - Missing dependencies from malware that was partially cleaned
///   - Side-loading attempts that failed due to architecture mismatch
///   - Phantom DLL references from persistence mechanisms
///
/// Ported from Antivirus.ps1's Event Log DLL load failure monitoring.
///
/// Also monitors:
///   - Event ID 11 (SideBySide) â€” manifest/activation context errors
///   - Event ID 59 (Application Error) â€” DLL initialization failures
///
/// MITRE ATT&CK:
///   T1574 â€” Hijack Execution Flow
///   T1055 â€” Process Injection (failed attempts)
/// </summary>
public sealed class DllLoadFailureMonitor : BackgroundService
{
    private readonly DetectionEngine _detectionEngine;
    private readonly ILogger<DllLoadFailureMonitor> _logger;

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);
    private readonly ConcurrentDictionary<string, byte> _alertedEvents = new();
    private DateTime _lastPollTime = DateTime.UtcNow.AddMinutes(-5);

    // Known benign DLL load failures (Windows generates these normally)
    private static readonly HashSet<string> BenignFailurePatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        "ieshims.dll", "api-ms-win", "ext-ms-win", "wer.dll",
        "uxtheme.dll", "propsys.dll", "edputil.dll"
    };

    public DllLoadFailureMonitor(
        DetectionEngine detectionEngine,
        ILogger<DllLoadFailureMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("DllLoadFailureMonitor: Starting (polling System log every 30s)");

        await Task.Delay(TimeSpan.FromSeconds(45), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PollEventLogAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "DllLoadFailureMonitor: Poll error");
            }

            try { await Task.Delay(PollInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task PollEventLogAsync(CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var queryTime = _lastPollTime.ToUniversalTime();
        _lastPollTime = now;

        // Query System log for Event ID 7 (Service Control Manager â€” DLL load failures)
        await QuerySystemLogAsync(queryTime, ct);

        // Query Application log for SideBySide errors (manifest/activation context)
        await QuerySideBySideErrorsAsync(queryTime, ct);
    }

    /// <summary>
    /// Queries System event log for Event ID 7 (DLL load failures from SCM).
    /// </summary>
    private async Task QuerySystemLogAsync(DateTime since, CancellationToken ct)
    {
        try
        {
            var sinceStr = since.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            var query = new EventLogQuery("System", PathType.LogName,
                $"*[System[(EventID=7) and TimeCreated[@SystemTime >= '{sinceStr}']]]");

            using var reader = new EventLogReader(query);

            EventRecord? record;
            while ((record = reader.ReadEvent()) != null)
            {
                ct.ThrowIfCancellationRequested();

                using (record)
                {
                    var message = record.FormatDescription() ?? "";
                    var timeCreated = record.TimeCreated ?? DateTime.UtcNow;

                    // Check if this is a DLL-related failure
                    if (!message.Contains("dll", StringComparison.OrdinalIgnoreCase) &&
                        !message.Contains("DLL", StringComparison.Ordinal) &&
                        !message.Contains("module", StringComparison.OrdinalIgnoreCase) &&
                        !message.Contains("load", StringComparison.OrdinalIgnoreCase))
                        continue;

                    // Skip known benign patterns
                    if (BenignFailurePatterns.Any(p => message.Contains(p, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    var alertKey = $"evt7:{timeCreated:yyyyMMddHHmmss}:{message.GetHashCode()}";
                    if (!_alertedEvents.TryAdd(alertKey, 0)) continue;

                    // Extract DLL name from message if possible
                    var dllName = ExtractDllName(message);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "DLL Load Failure: Potential Hijacking Indicator",
                        Evidence = $"System Event ID 7 at {timeCreated:u}: {TruncateMessage(message, 300)}",
                        Reasoning = "A DLL load failure in the System event log can indicate: " +
                                   "(1) A DLL hijacking attempt where the planted DLL failed to load " +
                                   "(wrong architecture, missing exports, or access denied). " +
                                   "(2) A partially-cleaned malware infection where persistence mechanisms " +
                                   "still reference deleted payloads. " +
                                   "(3) A side-loading attempt that failed. " +
                                   "Investigate the referenced DLL path and the process that attempted the load.",
                        Confidence = 0.65,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = "EventLog",
                        ProcessId = 0,
                        Timestamp = timeCreated.ToUniversalTime(),
                        Metadata = new Dictionary<string, string>
                        {
                            ["technique"] = "T1574 - Hijack Execution Flow",
                            ["event_id"] = "7",
                            ["event_log"] = "System",
                            ["dll_name"] = dllName ?? "unknown",
                            ["message"] = TruncateMessage(message, 500)
                        }
                    }, ct);
                }
            }
        }
        catch (EventLogNotFoundException)
        {
            _logger.LogDebug("DllLoadFailureMonitor: System event log not accessible");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "DllLoadFailureMonitor: Error querying System log");
        }
    }

    /// <summary>
    /// Queries Application log for SideBySide errors (Event ID 33, 59, 80)
    /// which indicate manifest/activation context failures â€” often caused by
    /// DLL hijacking attempts that fail due to manifest validation.
    /// </summary>
    private async Task QuerySideBySideErrorsAsync(DateTime since, CancellationToken ct)
    {
        try
        {
            var sinceStr = since.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            var query = new EventLogQuery("Application", PathType.LogName,
                $"*[System[Provider[@Name='SideBySide'] and TimeCreated[@SystemTime >= '{sinceStr}']]]");

            using var reader = new EventLogReader(query);

            EventRecord? record;
            int count = 0;
            while ((record = reader.ReadEvent()) != null && count < 20) // Cap at 20 per poll
            {
                ct.ThrowIfCancellationRequested();
                count++;

                using (record)
                {
                    var message = record.FormatDescription() ?? "";
                    var timeCreated = record.TimeCreated ?? DateTime.UtcNow;

                    // Only interested in DLL-related SideBySide errors
                    if (!message.Contains(".dll", StringComparison.OrdinalIgnoreCase)) continue;

                    // Skip common benign SideBySide noise
                    if (message.Contains("Microsoft.Windows.Common-Controls", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var alertKey = $"sxs:{timeCreated:yyyyMMddHHmmss}:{message.GetHashCode()}";
                    if (!_alertedEvents.TryAdd(alertKey, 0)) continue;

                    var dllName = ExtractDllName(message);

                    // Only emit if the DLL path looks suspicious
                    if (dllName != null && IsSuspiciousDllPath(message))
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "DLL Load Failure: SideBySide Manifest Error",
                            Evidence = $"SideBySide error at {timeCreated:u}: {TruncateMessage(message, 300)}",
                            Reasoning = "A SideBySide (activation context) error involving a DLL can indicate " +
                                       "a failed DLL hijacking attempt. The Windows loader rejected the DLL " +
                                       "because it didn't match the expected manifest. This is a defensive " +
                                       "success but indicates an attacker attempted to plant a malicious DLL.",
                            Confidence = 0.60,
                            Tier = DetectionTier.Tier2Indicator,
                            ProcessName = "EventLog",
                            ProcessId = 0,
                            Timestamp = timeCreated.ToUniversalTime(),
                            Metadata = new Dictionary<string, string>
                            {
                                ["technique"] = "T1574 - Hijack Execution Flow",
                                ["event_source"] = "SideBySide",
                                ["dll_name"] = dllName ?? "unknown",
                                ["message"] = TruncateMessage(message, 500)
                            }
                        }, ct);
                    }
                }
            }
        }
        catch (EventLogNotFoundException)
        {
            _logger.LogDebug("DllLoadFailureMonitor: Application event log not accessible");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "DllLoadFailureMonitor: Error querying Application log");
        }
    }

    private static string? ExtractDllName(string message)
    {
        // Try to extract DLL filename from the message
        var match = System.Text.RegularExpressions.Regex.Match(
            message, @"[\w\-\.]+\.dll", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        return match.Success ? match.Value : null;
    }

    private static bool IsSuspiciousDllPath(string message)
    {
        var lower = message.ToLowerInvariant();
        return lower.Contains(@"\temp\") ||
               lower.Contains(@"\tmp\") ||
               lower.Contains(@"\appdata\") ||
               lower.Contains(@"\downloads\") ||
               lower.Contains(@"\desktop\") ||
               lower.Contains(@"\users\");
    }

    private static string TruncateMessage(string message, int maxLength)
    {
        return message.Length <= maxLength ? message : message[..maxLength] + "...";
    }
}


