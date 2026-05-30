using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Scheduled Task Persistence Monitor (v3.6.0) — Detects malicious task creation.
///
/// Scheduled Tasks are one of the most common persistence mechanisms (T1053.005).
/// Malware creates tasks to:
///   - Survive reboots (persistence)
///   - Execute payloads at specific times (delayed execution)
///   - Run with SYSTEM privileges (privilege escalation)
///   - Execute on user logon (credential harvesting)
///
/// Detection strategy:
///   1. Snapshot all scheduled tasks at startup.
///   2. Every 30 seconds, diff against baseline.
///   3. Alert on new tasks with suspicious properties:
///      - Running from temp/user-writable paths
///      - Running encoded PowerShell
///      - Running as SYSTEM from non-system paths
///      - Hidden tasks (no description, random names)
///      - Tasks executing scripts (.bat, .ps1, .vbs, .js)
///
/// Complements WmiPersistenceMonitor (WMI event subscriptions) and the
/// existing PersistenceRule (registry run keys, services).
/// </summary>
public sealed class ScheduledTaskMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<ScheduledTaskMonitor> _logger;

    // Baseline: task names known at startup
    private readonly HashSet<string> _baselineTasks = new(StringComparer.OrdinalIgnoreCase);
    private bool _baselineCaptured;

    // Deduplication
    private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedEvents = new();
    private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(60);

    // Suspicious path fragments in task actions
    private static readonly string[] SuspiciousPathFragments =
    {
        @"\Temp\", @"\tmp\", @"\AppData\Local\Temp\",
        @"\Downloads\", @"\Desktop\",
        @"\ProgramData\", // Not always suspicious but worth noting
        @"\Users\Public\",
        @"C:\Windows\Temp\",
    };

    // Suspicious command patterns
    private static readonly string[] SuspiciousCommandPatterns =
    {
        "-encodedcommand", "-enc ", "-e ", // Encoded PowerShell
        "powershell -w hidden", "powershell.exe -w h",
        "cmd /c", "cmd.exe /c",
        "mshta ", "wscript ", "cscript ",
        "regsvr32 ", "rundll32 ",
        "certutil ", "bitsadmin ",
        "iex(", "invoke-expression",
        "downloadstring", "downloadfile",
        "net user ", "net localgroup ",
    };

    public ScheduledTaskMonitor(
        IDetectionEngine detectionEngine,
        ILogger<ScheduledTaskMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[ScheduledTaskMonitor] Starting — scheduled task persistence monitoring active");

        await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);

        CaptureBaseline();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanTasksAsync(stoppingToken);
                PruneAlertCache();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "[ScheduledTaskMonitor] Scan error");
            }

            await Task.Delay(PollInterval, stoppingToken);
        }
    }

    private void CaptureBaseline()
    {
        var tasks = GetScheduledTaskNames();
        foreach (var task in tasks)
            _baselineTasks.Add(task);

        _baselineCaptured = true;
        _logger.LogInformation("[ScheduledTaskMonitor] Baseline: {Count} scheduled tasks", _baselineTasks.Count);
    }

    private async Task ScanTasksAsync(CancellationToken ct)
    {
        if (!_baselineCaptured) return;

        var currentTasks = GetScheduledTaskNames();
        var newTasks = currentTasks.Where(t => !_baselineTasks.Contains(t)).ToList();

        foreach (var taskName in newTasks)
        {
            _baselineTasks.Add(taskName);

            var dedupeKey = $"new_task:{taskName}";
            if (_alertedEvents.ContainsKey(dedupeKey)) continue;
            _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

            // Get task details for analysis
            var details = GetTaskDetails(taskName);
            var isSuspicious = AnalyzeTask(taskName, details);

            if (isSuspicious.IsSuspicious)
            {
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Persistence: Suspicious Scheduled Task Created",
                    Evidence = $"New scheduled task created: '{taskName}'. " +
                               $"Action: {details?.Action ?? "unknown"}. " +
                               $"Run As: {details?.RunAs ?? "unknown"}. " +
                               $"Triggers: {details?.Trigger ?? "unknown"}. " +
                               $"Suspicious indicators: {string.Join(", ", isSuspicious.Reasons)}.",
                    Reasoning = "A new scheduled task was created with suspicious properties. " +
                                "Scheduled tasks are the most common persistence mechanism for malware " +
                                "(MITRE T1053.005). Indicators include: execution from temp directories, " +
                                "encoded PowerShell commands, SYSTEM-level execution from user paths, " +
                                "and use of known LOLBins (mshta, wscript, certutil).",
                    Confidence = Math.Min(0.60 + (isSuspicious.Reasons.Count * 0.10), 0.92),
                    Tier = isSuspicious.Reasons.Count >= 2 ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                    ProcessName = "TaskScheduler",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["task_name"] = taskName,
                        ["action"] = details?.Action ?? "unknown",
                        ["run_as"] = details?.RunAs ?? "unknown",
                        ["trigger"] = details?.Trigger ?? "unknown",
                        ["suspicious_indicators"] = string.Join(";", isSuspicious.Reasons),
                        ["technique"] = "T1053.005 - Scheduled Task",
                        ["attack_type"] = "scheduled_task_persistence"
                    }
                }, ct);
            }
            else
            {
                // Log non-suspicious new tasks as Tier2 for awareness
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Persistence: New Scheduled Task Created",
                    Evidence = $"New scheduled task: '{taskName}'. Action: {details?.Action ?? "unknown"}.",
                    Reasoning = "A new scheduled task was created. While likely legitimate (software " +
                                "installation, updates), all new persistence mechanisms are logged for " +
                                "audit purposes.",
                    Confidence = 0.35,
                    Tier = DetectionTier.Tier2Indicator,
                    ProcessName = "TaskScheduler",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["task_name"] = taskName,
                        ["action"] = details?.Action ?? "unknown",
                        ["technique"] = "T1053.005 - Scheduled Task",
                        ["attack_type"] = "scheduled_task_new"
                    }
                }, ct);
            }
        }
    }

    private static (bool IsSuspicious, List<string> Reasons) AnalyzeTask(string taskName, TaskDetails? details)
    {
        var reasons = new List<string>();

        if (details == null)
        {
            reasons.Add("Could not retrieve task details (hidden/protected)");
            return (true, reasons);
        }

        var action = details.Action?.ToLowerInvariant() ?? "";

        // Check for suspicious paths
        foreach (var fragment in SuspiciousPathFragments)
        {
            if (action.Contains(fragment, StringComparison.OrdinalIgnoreCase))
            {
                reasons.Add($"Executes from suspicious path ({fragment.Trim('\\')})");
                break;
            }
        }

        // Check for suspicious commands
        foreach (var pattern in SuspiciousCommandPatterns)
        {
            if (action.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                reasons.Add($"Suspicious command pattern: {pattern.Trim()}");
                break;
            }
        }

        // SYSTEM execution from non-system path
        if (details.RunAs?.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase) == true &&
            !action.Contains(@"c:\windows\", StringComparison.OrdinalIgnoreCase) &&
            !action.Contains(@"c:\program files", StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add("Runs as SYSTEM from non-system path");
        }

        // Script execution
        var scriptExtensions = new[] { ".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".hta" };
        if (scriptExtensions.Any(ext => action.Contains(ext, StringComparison.OrdinalIgnoreCase)))
        {
            reasons.Add("Executes a script file");
        }

        // Random-looking task name (no spaces, high entropy)
        if (!taskName.Contains(' ') && !taskName.Contains('\\') && taskName.Length > 15)
        {
            var hasDigits = taskName.Any(char.IsDigit);
            var hasMixed = taskName.Any(char.IsUpper) && taskName.Any(char.IsLower);
            if (hasDigits && hasMixed)
                reasons.Add("Random-looking task name");
        }

        return (reasons.Count > 0, reasons);
    }

    private static List<string> GetScheduledTaskNames()
    {
        var tasks = new List<string>();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks",
                Arguments = "/query /fo csv /nh",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc == null) return tasks;

            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10000);

            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = line.Trim().Trim('"');
                if (string.IsNullOrEmpty(trimmed)) continue;

                // CSV format: "TaskName","Next Run Time","Status"
                var parts = trimmed.Split("\",\"");
                if (parts.Length > 0)
                {
                    var name = parts[0].Trim('"');
                    if (!string.IsNullOrEmpty(name))
                        tasks.Add(name);
                }
            }
        }
        catch { }
        return tasks;
    }

    private static TaskDetails? GetTaskDetails(string taskName)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks",
                Arguments = $"/query /tn \"{taskName}\" /v /fo list",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc == null) return null;

            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            return new TaskDetails
            {
                Action = ExtractField(output, "Task To Run:"),
                RunAs = ExtractField(output, "Run As User:"),
                Trigger = ExtractField(output, "Schedule Type:"),
            };
        }
        catch { return null; }
    }

    private static string? ExtractField(string output, string fieldName)
    {
        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith(fieldName, StringComparison.OrdinalIgnoreCase))
            {
                return trimmed[fieldName.Length..].Trim();
            }
        }
        return null;
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

    private sealed class TaskDetails
    {
        public string? Action { get; init; }
        public string? RunAs { get; init; }
        public string? Trigger { get; init; }
    }
}
