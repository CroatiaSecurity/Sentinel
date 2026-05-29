using System.Diagnostics;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Agent;

/// <summary>
/// Lightweight response engine for the Agent. Handles detections from user-session
/// monitors. For Tier1 detections matching kill criteria, terminates the process
/// directly (Agent runs in user session so it can kill user processes).
/// For Tier2, logs only.
///
/// This is intentionally simpler than the service's AdvancedResponseEngine — no
/// chain tracer, no deception engine, no scoring. The Agent's job is:
///   1. Detect (via monitors)
///   2. Kill if high-confidence Tier1
///   3. Log everything to shared events.jsonl
/// </summary>
internal sealed class AgentResponseEngine : IResponseEngine
{
    private readonly IEventLogger _eventLogger;
    private readonly ILogger<AgentResponseEngine> _logger;
    private readonly TrayIconService? _trayIcon;

    // President's Law fragments that authorize a kill from the Agent
    private static readonly string[] KillFragments =
    {
        // User-session spyware / surveillance
        "audio injection",
        "audio hijack",
        "audio routed to microphone",
        "screen exfiltration",
        "overlay attack",
        "clipboard hijack",
        "credential phishing",
        "surveillance suite",
        "camera/mic exfiltration",
        "browser credential theft",
        // RAT / APT campaign (v3.3.0)
        "campaign:",
        "rat activity",
        "remote access trojan",
        "confirmed rat",
        // v3.5.0 — Behavioral RAT composites (novel RAT detection)
        "covert rat:",
        "covert c2:",
        "confirmed c2 beacon:",
        // v3.5.0 — Existing composites now kill-authorized
        "injected c2 beacon",
        "dga + c2 beaconing",
        "spoofed process phoning home",
        "dropped payload phoning home",
        // Keylogging / input capture (v3.3.0)
        "keylogger",
        "keystroke capture",
        "input capture",
        // Reverse shell (v3.3.0)
        "reverse shell",
        "interactive shell: outbound",
        // Credential theft (v3.3.0)
        "confirmed lsass dump",
        "lsass dump",
        "credential dump",
        // Data exfiltration (v3.3.0)
        "data exfiltration",
        "exfiltration: credential theft + network",
    };

    private const double KillConfidenceThreshold = 0.85;

    public AgentResponseEngine(IEventLogger eventLogger, ILogger<AgentResponseEngine> logger, TrayIconService? trayIcon = null)
    {
        _eventLogger = eventLogger;
        _logger = logger;
        _trayIcon = trayIcon;
    }

    public async Task HandleAsync(DetectionEvent detection, CancellationToken cancellationToken)
    {
        // Log all detections
        await _eventLogger.LogDetectionAsync(detection, cancellationToken);

        // Tier2 = always log only
        if (detection.Tier == DetectionTier.Tier2Indicator)
        {
            _logger.LogWarning("[AGENT-T2] {Rule} | PID {Pid} | {Process}",
                detection.RuleName, detection.ProcessId, detection.ProcessName);

            await _eventLogger.LogResponseAsync(new ResponseAction
            {
                Kind = ResponseActionKind.LogOnly,
                TriggerEvent = detection,
                Timestamp = DateTimeOffset.UtcNow,
                Notes = $"Agent Tier2: logged only (Score: N/A)"
            }, cancellationToken);
            return;
        }

        // Tier1 — check if it matches kill criteria
        if (detection.Confidence >= KillConfidenceThreshold && ShouldKill(detection))
        {
            _logger.LogCritical("[AGENT-KILL] {Rule} | Conf {Conf:P0} | PID {Pid} ({Name})",
                detection.RuleName, detection.Confidence, detection.ProcessId, detection.ProcessName);

            _trayIcon?.ShowBalloon(
                "\U0001f6e1 Threat Killed",
                $"{detection.ProcessName} (PID {detection.ProcessId})\n{detection.RuleName}",
                System.Windows.Forms.ToolTipIcon.Error);

            await KillProcessAsync(detection, cancellationToken);
            return;
        }

        // Tier1 but below kill threshold — log only
        _logger.LogWarning("[AGENT-T1] {Rule} | Conf {Conf:P0} | PID {Pid} | {Process} — log only",
            detection.RuleName, detection.Confidence, detection.ProcessId, detection.ProcessName);

        _trayIcon?.ShowBalloon(
            "\u26a0 Threat Detected",
            $"{detection.ProcessName} (PID {detection.ProcessId})\n{detection.RuleName} [{detection.Confidence:P0}]",
            System.Windows.Forms.ToolTipIcon.Warning);

        await _eventLogger.LogResponseAsync(new ResponseAction
        {
            Kind = ResponseActionKind.LogOnly,
            TriggerEvent = detection,
            Timestamp = DateTimeOffset.UtcNow,
            Notes = $"Agent Tier1: below kill threshold or no matching fragment (Conf: {detection.Confidence:P0})"
        }, cancellationToken);
    }

    private bool ShouldKill(DetectionEvent detection)
    {
        var rule = detection.RuleName.ToLowerInvariant();
        foreach (var frag in KillFragments)
        {
            if (rule.Contains(frag)) return true;
        }
        return false;
    }

    private async Task KillProcessAsync(DetectionEvent detection, CancellationToken cancellationToken)
    {
        if (detection.ProcessId <= 4)
        {
            _logger.LogError("[AGENT] Refusing to kill system process PID {Pid}", detection.ProcessId);
            return;
        }

        // Don't kill ourselves
        if (detection.ProcessId == Environment.ProcessId)
        {
            _logger.LogCritical("[AGENT] BLOCKED SELF-KILL attempt");
            return;
        }

        try
        {
            using var process = Process.GetProcessById(detection.ProcessId);

            // Verify PID still matches expected process name
            if (!string.Equals(process.ProcessName, detection.ProcessName, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("[AGENT] PID {Pid} name mismatch: expected {Expected}, found {Actual}. Skipping.",
                    detection.ProcessId, detection.ProcessName, process.ProcessName);
                return;
            }

            _logger.LogCritical("[AGENT] Killing {Name} (PID {Pid})", process.ProcessName, detection.ProcessId);
            process.Kill(entireProcessTree: true);

            await _eventLogger.LogResponseAsync(new ResponseAction
            {
                Kind = ResponseActionKind.KillProcess,
                TriggerEvent = detection,
                Timestamp = DateTimeOffset.UtcNow,
                Notes = $"Agent killed process {detection.ProcessName} (PID {detection.ProcessId})"
            }, cancellationToken);
        }
        catch (ArgumentException)
        {
            _logger.LogWarning("[AGENT] Process {Pid} already exited", detection.ProcessId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[AGENT] Failed to kill PID {Pid}", detection.ProcessId);
        }
    }
}


