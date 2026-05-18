using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Deception;
using WindowsSentinel.Core.Health;
using WindowsSentinel.Core.IncidentResponse;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Notifications;
using WindowsSentinel.Core.Quarantine;
using WindowsSentinel.Core.Response;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Advanced Response Engine - Enhanced response with Chain Tracer, Scoring, Incident Response,
/// and full Antivirus project integration (Akinator, Contextual Analysis, FP Tracking, etc.)
/// </summary>
public sealed class AdvancedResponseEngine : IResponseEngine
{
    private readonly IEventLogger _eventLogger;
    private readonly ILogger<AdvancedResponseEngine> _logger;
    private readonly ScoringEngine _scoringEngine;
    private readonly ChainTracer? _chainTracer;
    private readonly IncidentResponseService? _incidentResponse;
    private readonly HeartbeatService? _heartbeat;
    private readonly QuarantineManager? _quarantine;
    private readonly AkinatorEngine? _akinator;
    private readonly ContextualAnalysisEngine? _contextualAnalysis;
    private readonly FalsePositiveTracker? _fpTracker;
    private readonly BehavioralBaselineService? _baselineService;
    private readonly ReputationCache? _reputationCache;
    private readonly ToastNotificationService? _toastService;
    private readonly IDeceptionEngine? _deceptionEngine;
    private readonly ThreatIntelReporter? _threatReporter;
    private readonly bool _activeResponseEnabled;

    public AdvancedResponseEngine(
        IEventLogger eventLogger,
        ILogger<AdvancedResponseEngine> logger,
        ScoringEngine scoringEngine,
        ChainTracer? chainTracer = null,
        IncidentResponseService? incidentResponse = null,
        HeartbeatService? heartbeat = null,
        QuarantineManager? quarantine = null,
        AkinatorEngine? akinator = null,
        ContextualAnalysisEngine? contextualAnalysis = null,
        FalsePositiveTracker? fpTracker = null,
        BehavioralBaselineService? baselineService = null,
        ReputationCache? reputationCache = null,
        ToastNotificationService? toastService = null,
        IDeceptionEngine? deceptionEngine = null,
        ThreatIntelReporter? threatReporter = null,
        bool activeResponseEnabled = false)
    {
        _eventLogger = eventLogger;
        _logger = logger;
        _scoringEngine = scoringEngine;
        _chainTracer = chainTracer;
        _incidentResponse = incidentResponse;
        _heartbeat = heartbeat;
        _quarantine = quarantine;
        _akinator = akinator;
        _contextualAnalysis = contextualAnalysis;
        _fpTracker = fpTracker;
        _baselineService = baselineService;
        _reputationCache = reputationCache;
        _toastService = toastService;
        _deceptionEngine = deceptionEngine;
        _threatReporter = threatReporter;
        _activeResponseEnabled = activeResponseEnabled;
    }

    public async Task HandleAsync(DetectionEvent detection, CancellationToken cancellationToken)
    {
        // Record detection in heartbeat
        _heartbeat?.RecordDetection();

        // Check reputation cache first
        if (CheckReputationCache(detection))
        {
            // Known safe file - reduce priority
            _logger.LogDebug("[REPUTATION] {Rule} detected but file has good reputation - reducing priority", 
                detection.RuleName);
        }

        // Tier2 is ALWAYS log-only — no exceptions
        if (detection.Tier == DetectionTier.Tier2Indicator)
        {
            await HandleTier2Async(detection, cancellationToken);
            return;
        }

        // Tier1 behavioral — calculate score and determine response
        await HandleTier1Async(detection, cancellationToken);
    }

    private bool CheckReputationCache(DetectionEvent detection)
    {
        if (_reputationCache == null) return false;
        
        if (detection.Metadata.TryGetValue("file_hash", out var hash))
        {
            return _reputationCache.IsKnownSafe(hash);
        }
        
        return false;
    }

    private async Task HandleTier2Async(DetectionEvent detection, CancellationToken cancellationToken)
    {
        // Calculate score for Tier2 (informational purposes only)
        var score = _scoringEngine.CalculateScore(
            detection,
            MapToDetectionSource(detection),
            isSigned: detection.Metadata.TryGetValue("is_signed", out var signed) && bool.Parse(signed),
            isSystemProcess: IsSystemProcess(detection),
            corroboratingSources: _scoringEngine.GetCorroboratingSourceCount(detection.ProcessId, MapToDetectionSource(detection)));

        _logger.LogWarning(
            "[TIER2] {Rule} | Score: {Score} ({Verdict}) | PID: {Pid} | {Reason}",
            detection.RuleName, score.Score, score.Verdict, detection.ProcessId, score.Category);

        // Always log-only for Tier2
        var action = new ResponseAction
        {
            Kind = ResponseActionKind.LogOnly,
            TriggerEvent = detection,
            Timestamp = DateTimeOffset.UtcNow,
            Notes = $"Tier2 indicator logged (Score: {score.Score}, Verdict: {score.Verdict}). No action taken by policy."
        };

        await _eventLogger.LogDetectionAsync(detection, cancellationToken);
        await _eventLogger.LogResponseAsync(action, cancellationToken);
    }

    // ════════════════════════════════════════════════════════════════════════
    // PRESIDENT'S LAW — CLOSED KILL LIST (per architecture-council.md E2.1)
    // Philosophy (per GIDR v6.3): act only on what a process DOES at runtime —
    // never on what a file LOOKS like. IOC/hash/campaign-name matches, YARA
    // hits, PE entropy, unsigned binaries, suspicious imports → log only.
    //
    // These are the ONLY rule-name fragments that authorize a kill. Everything
    // else — including ReverseShell, Beaconing, AttackTools, HollowProcess,
    // CampaignIoc, ProcessInjection, ThreatIntelInjection, Persistence,
    // PrivilegeEscalation, all consultant signals — is LogOnly.
    //
    // ADDING TO THIS LIST REQUIRES EXPLICIT USER SIGN-OFF AND A DOC UPDATE.
    // ════════════════════════════════════════════════════════════════════════
    private static readonly string[] PresidentsLawFragments = new[]
    {
        // Credential theft
        "lsass credential",
        "credential dump",
        // Telemetry tampering (EDR blinding)
        "amsi tampering",
        "etw tampering",
        "etw-amsi",
        "amsi patching",
        "etw unhooking",
        // Ransomware
        "ransomware: mass write",
        "ransomware activity",
        "shadow copy deletion",
        // Fileless / in-memory execution
        "reflective dll",
        "memory execution: reflective",
        "memory execution: process has no executable path",
        // Audio hijack / screen capture / overlay (attack on user)
        "audiohijack",
        "audio hijack",
        "audio routed to microphone",
        "audio injection",
        // Screen capture / overlay (spyware / phishing)
        "overlay attack",
        "screen exfiltration",
        "surveillance suite",
        "credential phishing: overlay",
        // Webcam/mic exfiltration (spyware / RAT)
        "camera/mic exfiltration",
        "total av surveillance",
        // Data exfiltration composites (v1.8.0) — only composites kill, never single signals
        "data exfiltration",
        "data staging",
        "exfiltration: upload service + network",
        "exfiltration: credential theft + network",
        "exfiltration: usb media + network",
        "exfiltration: staging + upload service",
        // Honeypot trip
        "honeypot: decoy",
        // NeuroBehavior anomaly
        "neurobehavior",
        // Sentinel self-protection
        "self-protection: amsi patching",
        "self-protection: etw unhooking",
        "self-protection: dll hijacking",
        "self-protection: executable tampering",
        "critical: service binary path tampered",
        "critical: service registry key deleted",
        "critical: service removed from scm",
        // ADS verdict-gated
        "verdict-gated"
    };

    private const double MustKillConfidenceThreshold = 0.85;

    // ═══════════════════════════════════════════════════════════════════════════
    // PRE-KILL VALIDATION GATE
    //
    // Purpose: Prevent killing user-interactive processes whose normal behavior
    // mimics threat patterns (games, media players, creative tools).
    //
    // Philosophy: Real malware HIDES. If a process is the foreground app, owns
    // visible windows, and has been running stably for minutes — it's not covert.
    // This gate does NOT whitelist anything by path or name. It checks behavioral
    // properties that are inherently incompatible with being a hidden threat.
    //
    // Returns null if kill should proceed, or a reason string if downgraded.
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Performs final sanity checks before a President's Law kill is executed.
    /// Returns null if the kill should proceed, or a descriptive reason if the
    /// kill should be downgraded to log-only.
    /// </summary>
    private string? EvaluatePreKillValidation(DetectionEvent detection)
    {
        if (detection.ProcessId <= 0) return null; // Can't validate, let kill proceed

        try
        {
            using var process = Process.GetProcessById(detection.ProcessId);

            // ── CHECK 1: Does the process own a visible window? ──────────────
            // Real spyware/RATs doing screen exfiltration, credential phishing,
            // or data theft operate WITHOUT visible windows. A process with a
            // visible, non-trivial window is something the user is aware of.
            bool ownsVisibleWindow = ProcessOwnsVisibleWindow(process.Id);

            // ── CHECK 2: Is it the foreground application? ───────────────────
            // The foreground app is what the user is actively interacting with.
            // Malware does not operate as the foreground window — that would
            // immediately alert the user to its presence.
            bool isForeground = IsProcessForeground(process.Id);

            // ── CHECK 3: Process age — has it been running stably? ───────────
            // Implants/RATs typically beacon within seconds of injection or launch.
            // A process that has been running for 5+ minutes without escalation
            // and is only NOW triggering a composite is more likely a false positive
            // from accumulated benign signals.
            TimeSpan processAge = TimeSpan.Zero;
            try { processAge = DateTimeOffset.UtcNow - process.StartTime.ToUniversalTime(); }
            catch { /* Access denied — can't determine age, don't use this check */ }

            bool isLongRunning = processAge > TimeSpan.FromMinutes(5);

            // ── DECISION LOGIC ───────────────────────────────────────────────
            // We require BOTH visibility AND longevity to downgrade.
            // A hidden process that's been running a long time? Still kill it.
            // A visible process that just spawned? Still kill it (could be a
            // just-launched attack tool with a decoy window).
            //
            // Only downgrade when the process is clearly user-interactive AND
            // has been stable — this combination is incompatible with being
            // a covert threat.

            if ((ownsVisibleWindow || isForeground) && isLongRunning)
            {
                var reasons = new List<string>();
                if (isForeground) reasons.Add("foreground app");
                else if (ownsVisibleWindow) reasons.Add("has visible window");
                reasons.Add($"running for {processAge.TotalMinutes:F0} min");

                return $"Process is user-interactive ({string.Join(", ", reasons)}). " +
                       $"Covert malware does not operate as a visible foreground application for extended periods.";
            }

            return null; // Kill proceeds
        }
        catch (ArgumentException)
        {
            // Process already exited — no need to kill
            return "Process no longer exists";
        }
        catch (Exception ex)
        {
            // If we can't validate, err on the side of caution — let the kill proceed.
            // We don't want validation failures to become a bypass vector.
            _logger.LogDebug(ex, "[PRE-KILL GATE] Validation failed for PID {Pid}, allowing kill to proceed",
                detection.ProcessId);
            return null;
        }
    }

    // ── P/Invoke for pre-kill validation ─────────────────────────────────────

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern int GetWindowLongW(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll")]
    private static extern int GetWindowThreadProcessId(IntPtr hWnd, out int processId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    private const int GWL_EXSTYLE_GATE = -20;
    private const int WS_EX_TOOLWINDOW_GATE = 0x00000080;

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left, Top, Right, Bottom;
        public int Width => Right - Left;
        public int Height => Bottom - Top;
        public int Area => Width * Height;
    }

    /// <summary>
    /// Returns true if the process owns at least one visible, non-trivial top-level window.
    /// </summary>
    private static bool ProcessOwnsVisibleWindow(int pid)
    {
        bool found = false;

        EnumWindows((hWnd, _) =>
        {
            if (!IsWindowVisible(hWnd)) return true;

            GetWindowThreadProcessId(hWnd, out int windowPid);
            if (windowPid != pid) return true;

            // Ignore tiny windows (tray icons, hidden helpers)
            if (!GetWindowRect(hWnd, out RECT rect)) return true;
            if (rect.Area < 50000) return true; // ~224x224 minimum

            // Skip tool windows (tooltips, floating toolbars)
            var exStyle = GetWindowLongW(hWnd, GWL_EXSTYLE_GATE);
            if ((exStyle & WS_EX_TOOLWINDOW_GATE) != 0) return true;

            found = true;
            return false; // Stop enumerating
        }, IntPtr.Zero);

        return found;
    }

    /// <summary>
    /// Returns true if the process owns the current foreground window.
    /// </summary>
    private static bool IsProcessForeground(int pid)
    {
        var fgHwnd = GetForegroundWindow();
        if (fgHwnd == IntPtr.Zero) return false;

        GetWindowThreadProcessId(fgHwnd, out int fgPid);
        return fgPid == pid;
    }

    private bool EvaluateMustKill(DetectionEvent detection)
    {
        if (detection.Confidence < MustKillConfidenceThreshold) return false;
        var rule = detection.RuleName.ToLowerInvariant();
        foreach (var frag in PresidentsLawFragments)
        {
            if (rule.Contains(frag)) return true;
        }
        return false;
    }

    private async Task HandleTier1Async(DetectionEvent detection, CancellationToken cancellationToken)
    {
        // PRESIDENT'S LAW — only the closed kill list authorizes immediate chain-nuke.
        if (_activeResponseEnabled && EvaluateMustKill(detection))
        {
            // ═══════════════════════════════════════════════════════════════════
            // PRE-KILL VALIDATION GATE — sanity check before lethal action.
            //
            // The composite/rule fired legitimately, but before killing we verify
            // the process isn't a user-interactive application whose normal behavior
            // mimics the threat pattern (e.g., games: DXGI + network + dbghelp).
            //
            // This does NOT weaken detection — real threats hide from the user.
            // A process the user is actively interacting with is not covert malware.
            // ═══════════════════════════════════════════════════════════════════
            var downgradeReason = EvaluatePreKillValidation(detection);
            if (downgradeReason != null)
            {
                _logger.LogWarning(
                    "[PRE-KILL GATE] Kill DOWNGRADED to log-only for {Rule} | PID {Pid} ({Name}) — Reason: {Reason}",
                    detection.RuleName, detection.ProcessId, detection.ProcessName, downgradeReason);

                var downgradedScore = new ThreatScore
                {
                    Score = 150,
                    Verdict = Verdict.Critical,
                    Category = "downgraded_by_validation_gate",
                    Source = MapToDetectionSource(detection),
                    OriginalConfidence = detection.Confidence,
                    CorroboratingSources = 0
                };

                await _eventLogger.LogDetectionAsync(detection, cancellationToken);

                _toastService?.ShowThreatDetected(
                    detection.RuleName,
                    detection.ProcessName,
                    detection.ProcessId,
                    "Critical (Downgraded)",
                    $"Kill blocked: {downgradeReason}");

                await LogOnlyAsync(detection, downgradedScore,
                    $"President's Law matched but pre-kill validation gate blocked execution: {downgradeReason}. " +
                    $"Process appears to be user-interactive. Review manually.",
                    cancellationToken);
                return;
            }

            _logger.LogCritical(
                "[CHAIN-NUKE] {Rule} | Conf {Conf:P0} | {Process} (PID {Pid}) — President's Law kill",
                detection.RuleName, detection.Confidence, detection.ProcessName,
                detection.ProcessId);

            var mustKillScore = new ThreatScore
            {
                Score = 200,
                Verdict = Verdict.Critical,
                Category = "presidents_law",
                Source = MapToDetectionSource(detection),
                OriginalConfidence = detection.Confidence,
                CorroboratingSources = 0
            };

            await _eventLogger.LogDetectionAsync(detection, cancellationToken);
            await TakeAggressiveActionAsync(detection, mustKillScore, cancellationToken);
            return;
        }

        // Gather additional context
        var context = _contextualAnalysis?.AnalyzeContext(
            detection.ProcessName,
            detection.Metadata.TryGetValue("parent_process", out var parent) ? parent : null,
            detection.Metadata.TryGetValue("command_line", out var cmdLine) ? cmdLine : null) ?? ContextFlags.None;

        // Calculate Akinator score (contextual heuristic)
        AkinatorScore? akinatorScore = null;
        if (_akinator != null)
        {
            akinatorScore = _akinator.CalculateScore(
                detection,
                detection.Metadata.TryGetValue("file_path", out var filePath) ? filePath : null,
                detection.Metadata.TryGetValue("command_line", out var cmd) ? cmd : null,
                detection.Metadata.TryGetValue("parent_process", out var pp) ? pp : null,
                isSigned: detection.Metadata.TryGetValue("is_signed", out var signed) && bool.Parse(signed),
                isMicrosoftSigned: detection.Metadata.TryGetValue("is_microsoft_signed", out var ms) && bool.Parse(ms),
                signerName: detection.Metadata.TryGetValue("signer_name", out var signer) ? signer : null);
        }

        // Check behavioral baseline
        var baselineTrust = _baselineService?.GetProcessTrustScore(detection.ProcessName) ?? 50;
        
        // Check false positive history
        var fpReduction = _fpTracker?.GetSuspicionReduction(
            detection.Metadata.TryGetValue("file_hash", out var hash) ? hash : null,
            detection.ProcessName,
            detection.Metadata.TryGetValue("signer_name", out var sn) ? sn : null,
            detection.Metadata.TryGetValue("file_path", out var fp) ? fp : null) ?? 0;

        // Calculate weighted score with all factors
        var score = _scoringEngine.CalculateScore(
            detection,
            MapToDetectionSource(detection),
            isSigned: detection.Metadata.TryGetValue("is_signed", out var s) && bool.Parse(s),
            isSystemProcess: IsSystemProcess(detection),
            corroboratingSources: _scoringEngine.GetCorroboratingSourceCount(detection.ProcessId, MapToDetectionSource(detection)));

        // Apply contextual adjustments
        var contextModifier = _contextualAnalysis?.GetContextModifier(context) ?? 0;
        score.Score = Math.Max(0, Math.Min(200, score.Score + contextModifier + fpReduction));
        
        // Re-evaluate verdict after adjustments — thresholds match ScoringEngine
        score.Verdict = score.Score switch
        {
            >= 120 => Verdict.Critical,
            >= 80  => Verdict.Malicious,
            >= 50  => Verdict.Suspicious,
            >= 25  => Verdict.Low,
            _      => Verdict.Clean
        };

        _logger.LogCritical(
            "[TIER1] {Rule} | Score: {Score} ({Verdict}) | Confidence: {Confidence:P0} | PID: {Pid} | Context: {Context} | Akinator: {Akinator}",
            detection.RuleName, score.Score, score.Verdict, detection.Confidence, detection.ProcessId,
            context, akinatorScore?.Score ?? 0);

        // Log detection with score information
        var scoredDetection = new DetectionEvent
        {
            RuleName = detection.RuleName,
            Evidence = detection.Evidence,
            Reasoning = $"{detection.Reasoning} [Score: {score.Score}, Verdict: {score.Verdict}, Category: {score.Category}]",
            Confidence = detection.Confidence,
            Tier = detection.Tier,
            ProcessName = detection.ProcessName,
            ProcessId = detection.ProcessId,
            Timestamp = detection.Timestamp,
            Metadata = new Dictionary<string, string>(detection.Metadata)
            {
                ["calculated_score"] = score.Score.ToString(),
                ["verdict"] = score.Verdict.ToString(),
                ["category"] = score.Category,
                ["corroborating_sources"] = score.CorroboratingSources.ToString()
            }
        };

        await _eventLogger.LogDetectionAsync(scoredDetection, cancellationToken);

        // Show toast notification for high-severity detections
        if (score.Verdict == Verdict.Critical || score.Verdict == Verdict.Malicious)
        {
            _toastService?.ShowThreatDetected(
                detection.RuleName,
                detection.ProcessName,
                detection.ProcessId,
                score.Verdict.ToString(),
                _activeResponseEnabled ? "Active response engaged" : "Log-only mode");
        }

        // PRESIDENT'S LAW ENFORCEMENT — non-President's-Law Tier1 rules are ALWAYS log-only.
        // The scoring path provides context and toast notifications but NEVER kills.
        // Only the closed President's Law fragment list above may authorize a kill.
        // This is what prevents games, browsers, and legit apps from being killed by
        // Beaconing, AttackTools, ReverseShell, FileEntropy, ModuleValidation, etc.
        await LogOnlyAsync(scoredDetection, score,
            $"Tier1 non-President's-Law: scored {score.Verdict} ({score.Score}) — log only by policy. " +
            $"Kill requires President's Law rule match at conf ≥{MustKillConfidenceThreshold:P0}.",
            cancellationToken);
    }

    private async Task LogOnlyAsync(DetectionEvent detection, ThreatScore score, string reason, CancellationToken cancellationToken)
    {
        _logger.LogWarning(
            "[RESPONSE] {Rule} | {Reason}",
            detection.RuleName, reason);

        var action = new ResponseAction
        {
            Kind = ResponseActionKind.LogOnly,
            TriggerEvent = detection,
            Timestamp = DateTimeOffset.UtcNow,
            Notes = $"{reason} (Score: {score.Score}, Verdict: {score.Verdict})"
        };

        await _eventLogger.LogResponseAsync(action, cancellationToken);
    }

    private async Task TakeAggressiveActionAsync(DetectionEvent detection, ThreatScore score, CancellationToken cancellationToken)
    {
        // SECURITY: Never kill our own process — prevents injected code from weaponizing
        // Sentinel's kill authority against itself.
        var selfPid = Environment.ProcessId;
        if (detection.ProcessId == selfPid)
        {
            _logger.LogCritical(
                "[RESPONSE] BLOCKED SELF-KILL: Injected code attempted to use Sentinel's kill authority " +
                "against itself (PID {Pid}). Rule={Rule}. This is a confirmed compromise indicator.",
                detection.ProcessId, detection.RuleName);
            return;
        }

        // SAFETY CHECK: Validate PID is reasonable before taking action
        if (detection.ProcessId <= 0 || detection.ProcessId > 999999)
        {
            _logger.LogError("[RESPONSE] Invalid PID {Pid} - refusing to take aggressive action", detection.ProcessId);
            return;
        }

        // SAFETY CHECK: Validate process name isn't empty
        if (string.IsNullOrWhiteSpace(detection.ProcessName))
        {
            _logger.LogError("[RESPONSE] Empty process name for PID {Pid} - refusing to take action", detection.ProcessId);
            return;
        }

        _logger.LogCritical(
            "[RESPONSE] Initiating chain trace for {Rule} (PID {Pid})",
            detection.RuleName, detection.ProcessId);

        // ── v1.7.0: Pre-kill deception — poison, destabilize, and flood BEFORE killing ──
        if (_deceptionEngine != null)
        {
            try
            {
                var deceptionContext = BuildDeceptionContext(detection);
                var deceptionResult = await _deceptionEngine.ExecutePreKillDeceptionAsync(
                    detection, deceptionContext, cancellationToken);

                if (deceptionResult.Executed)
                {
                    _logger.LogWarning(
                        "[DECEPTION] Pre-kill deception complete: {Tactics} tactics in {Duration}ms",
                        deceptionResult.Tactics.Count(t => t.Success), deceptionResult.Duration.TotalMilliseconds);
                }
            }
            catch (Exception ex)
            {
                // Deception failure NEVER prevents the kill
                _logger.LogDebug(ex, "[DECEPTION] Pre-kill deception failed (non-fatal, proceeding to kill)");
            }
        }

        ChainTraceResult? chainResult = null;

        // Use Chain Tracer if available
        if (_chainTracer != null && detection.ProcessId > 0)
        {
            try
            {
                chainResult = await _chainTracer.TraceAndEliminateAsync(detection, score, cancellationToken);

                if (chainResult.Success)
                {
                    _logger.LogCritical(
                        "[RESPONSE] Chain trace complete. Killed {Killed} processes, quarantined {Quarantined} files, removed {Persistence} persistence items",
                        chainResult.KilledProcesses.Count,
                        chainResult.QuarantinedFiles.Count,
                        chainResult.PersistenceRemoved.Count);

                    _heartbeat?.RecordResponse();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[RESPONSE] Chain trace failed, falling back to simple kill");
            }
        }

        // Fallback to simple kill if chain trace unavailable or failed
        if (chainResult == null || !chainResult.Success)
        {
            await SimpleKillAsync(detection, cancellationToken);
        }

        // Collect incident evidence
        if (_incidentResponse != null)
        {
            try
            {
                var evidence = await _incidentResponse.CollectEvidenceAsync(
                    detection,
                    chainResult,
                    collectMemoryDump: score.Verdict == Verdict.Critical,
                    cancellationToken);

                if (evidence.Success)
                {
                    _logger.LogCritical(
                        "[RESPONSE] Evidence collected in case folder: {CaseId}",
                        evidence.CaseId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[RESPONSE] Failed to collect evidence");
            }
        }

        // Log response action
        var responseAction = new ResponseAction
        {
            Kind = chainResult?.Success == true ? ResponseActionKind.KillProcess : ResponseActionKind.LogOnly,
            TriggerEvent = detection,
            Timestamp = DateTimeOffset.UtcNow,
            Notes = chainResult?.Success == true
                ? $"Chain trace executed: {chainResult.KilledProcesses.Count} processes killed, {chainResult.QuarantinedFiles.Count} files quarantined"
                : "Process termination attempted"
        };

        await _eventLogger.LogResponseAsync(responseAction, cancellationToken);

        // Show notification for action taken
        if (chainResult?.Success == true)
        {
            _toastService?.ShowProcessTerminated(
                detection.ProcessName,
                detection.ProcessId,
                $"Chain trace: {chainResult.KilledProcesses.Count} processes killed");

            // v2.1.0: Report confirmed threat to community threat intelligence platforms
            if (_threatReporter != null)
            {
                string? remoteAddr = null;
                int? remotePort = null;
                string? fileHash = null;

                detection.Metadata.TryGetValue("remote_address", out remoteAddr);
                if (remoteAddr == null) detection.Metadata.TryGetValue("RemoteAddress", out remoteAddr);

                if (detection.Metadata.TryGetValue("remote_port", out var portStr) && int.TryParse(portStr, out var port))
                    remotePort = port;

                detection.Metadata.TryGetValue("file_hash", out fileHash);
                if (fileHash == null) detection.Metadata.TryGetValue("module_hash", out fileHash);

                detection.Metadata.TryGetValue("technique", out var technique);

                _threatReporter.QueueReport(detection, remoteAddr, remotePort, fileHash, technique);
            }
        }
    }

    private Task SimpleKillAsync(DetectionEvent detection, CancellationToken cancellationToken)
    {
        // SAFETY CHECK: Validate PID before attempting kill
        if (detection.ProcessId <= 0 || detection.ProcessId > 999999)
        {
            _logger.LogError("[RESPONSE] Invalid PID {Pid} - refusing to kill", detection.ProcessId);
            return Task.CompletedTask;
        }

        // SAFETY CHECK: Double-check this isn't a critical system process by name
        if (IsCriticalSystemProcessByName(detection.ProcessName))
        {
            _logger.LogError(
                "[RESPONSE] SAFETY BLOCK: Attempted to kill critical system process {Name} (PID {Pid}) - REFUSING",
                detection.ProcessName, detection.ProcessId);
            return Task.CompletedTask;
        }

        try
        {
            using var process = Process.GetProcessById(detection.ProcessId);
            
            // SAFETY CHECK: Verify process name matches what we expect (prevent PID reuse attacks)
            if (!string.Equals(process.ProcessName, detection.ProcessName, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning(
                    "[RESPONSE] PID {Pid} name mismatch: expected {Expected}, found {Actual}. Possible PID reuse. Skipping.",
                    detection.ProcessId, detection.ProcessName, process.ProcessName);
                return Task.CompletedTask;
            }
            
            // Check if it's a protected process
            if (IsProtectedProcess(process.ProcessName))
            {
                _logger.LogWarning(
                    "[RESPONSE] Cannot kill protected process: {Name} (PID {Pid})",
                    process.ProcessName, detection.ProcessId);
                return Task.CompletedTask;
            }

            _logger.LogCritical(
                "[RESPONSE] Terminating process {Name} (PID {Pid}) and its children",
                process.ProcessName, detection.ProcessId);

            process.Kill(entireProcessTree: true);

            _logger.LogCritical(
                "[RESPONSE] Process {Pid} ({Name}) terminated",
                detection.ProcessId, process.ProcessName);

            _heartbeat?.RecordResponse();
        }
        catch (ArgumentException)
        {
            _logger.LogWarning(
                "[RESPONSE] Process {Pid} no longer exists",
                detection.ProcessId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "[RESPONSE] Failed to kill process {Pid}",
                detection.ProcessId);
        }

        return Task.CompletedTask;
    }

    private DetectionSource MapToDetectionSource(DetectionEvent detection)
    {
        var ruleName = detection.RuleName.ToLowerInvariant();

        if (ruleName.Contains("memory")) return DetectionSource.MemoryScanner;
        if (ruleName.Contains("chain")) return DetectionSource.ProcessChain;
        if (ruleName.Contains("yara")) return DetectionSource.YaraRules;
        if (ruleName.Contains("network") || ruleName.Contains("beacon")) return DetectionSource.Network;
        if (ruleName.Contains("static")) return DetectionSource.StaticAnalysis;
        if (ruleName.Contains("hash")) return DetectionSource.HashReputation;
        if (ruleName.Contains("mitre")) return DetectionSource.MitreMapping;

        return DetectionSource.BehaviorEngine;
    }

    private bool IsSystemProcess(DetectionEvent detection)
    {
        var systemPaths = new[]
        {
            @"C:\Windows\System32",
            @"C:\Windows\SysWOW64"
        };

        if (detection.Metadata.TryGetValue("image_path", out var path))
        {
            return systemPaths.Any(sp => path.StartsWith(sp, StringComparison.OrdinalIgnoreCase));
        }

        // Common system processes
        var systemProcesses = new[] { "svchost", "lsass", "csrss", "services", "smss", "wininit", "winlogon", "dwm" };
        return systemProcesses.Contains(detection.ProcessName.ToLowerInvariant());
    }

    private bool IsProtectedProcess(string processName)
    {
        var protectedProcesses = new[]
        {
            "system", "registry", "smss", "csrss", "wininit", "services",
            "lsass", "svchost", "dwm", "winlogon"
        };

        return protectedProcesses.Contains(processName.ToLowerInvariant());
    }

    /// <summary>
    /// Additional safety check for critical system processes that should NEVER be killed.
    /// This is a separate check from IsProtectedProcess for defense-in-depth.
    /// </summary>
    private bool IsCriticalSystemProcessByName(string processName)
    {
        var criticalProcesses = new[]
        {
            "system", "registry", "smss", "csrss", "wininit", "services",
            "lsass", "svchost", "dwm", "winlogon", "crss", "sessionmanager",
            "kernel", "system idle process", "interrupts", "memory compression"
        };

        return criticalProcesses.Contains(processName.ToLowerInvariant().Trim());
    }

    /// <summary>
    /// Builds a DeceptionContext from the detection event metadata.
    /// Maps rule names and metadata to attack categories for tactic selection.
    /// </summary>
    private static DeceptionContext BuildDeceptionContext(DetectionEvent detection)
    {
        var category = AttackCategory.None;
        var ruleLower = detection.RuleName.ToLowerInvariant();

        if (ruleLower.Contains("exfil") || ruleLower.Contains("staging") || ruleLower.Contains("screen"))
            category |= AttackCategory.Exfiltration;
        if (ruleLower.Contains("beacon") || ruleLower.Contains("c2") || ruleLower.Contains("reverse shell"))
            category |= AttackCategory.C2Beaconing;
        if (ruleLower.Contains("credential") || ruleLower.Contains("lsass") || ruleLower.Contains("dump"))
            category |= AttackCategory.CredentialTheft;
        if (ruleLower.Contains("ransomware"))
            category |= AttackCategory.Ransomware;
        if (ruleLower.Contains("injection") || ruleLower.Contains("hollow") || ruleLower.Contains("implant"))
            category |= AttackCategory.ProcessInjection;
        if (ruleLower.Contains("recon"))
            category |= AttackCategory.Reconnaissance;
        if (ruleLower.Contains("clipboard"))
            category |= AttackCategory.ClipboardTheft;
        if (ruleLower.Contains("dns") || ruleLower.Contains("tunnel"))
            category |= AttackCategory.DnsTunneling;

        // If no specific category matched, default to general exfiltration + C2
        if (category == AttackCategory.None)
            category = AttackCategory.Exfiltration | AttackCategory.C2Beaconing;

        detection.Metadata.TryGetValue("remote_address", out var remoteAddr);
        detection.Metadata.TryGetValue("remote_port", out var remotePortStr);
        detection.Metadata.TryGetValue("c2_framework", out var c2Framework);
        detection.Metadata.TryGetValue("image_path", out var imagePath);
        detection.Metadata.TryGetValue("file_path", out var filePath);

        int? remotePort = int.TryParse(remotePortStr, out var rp) ? rp : null;

        var stagedFiles = new List<string>();
        if (!string.IsNullOrEmpty(filePath)) stagedFiles.Add(filePath);
        if (detection.Metadata.TryGetValue("staged_files", out var staged))
            stagedFiles.AddRange(staged.Split(';', StringSplitOptions.RemoveEmptyEntries));

        return new DeceptionContext
        {
            ProcessId = detection.ProcessId,
            ProcessName = detection.ProcessName,
            Category = category,
            RemoteAddress = remoteAddr,
            RemotePort = remotePort,
            C2Framework = c2Framework,
            ImagePath = imagePath,
            StagedFiles = stagedFiles
        };
    }
}
