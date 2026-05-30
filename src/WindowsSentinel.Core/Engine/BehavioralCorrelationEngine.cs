using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Multi-signal behavioral correlation engine.
///
/// Commercial EDRs at scale can't do this well — a false positive on 50,000
/// endpoints means 50,000 support tickets. At single-user scale, aggressive
/// correlation is a feature, not a liability.
///
/// How it works:
///   1. Every DetectionEvent is fed into a time-windowed signal buffer
///      keyed by ProcessId (or host-level for file/network events).
///   2. Correlation rules evaluate the buffer and fire composite detections
///      when combinations of weak signals exceed a threshold.
///   3. Composite detections are injected back into the DetectionEngine
///      as new Tier1 events with high confidence.
///
/// v4.6.0: Unified C2 detection — all "suspicious process + network" composites
/// consolidated into a single scored EvaluateC2Communication() method.
/// Credential theft composites unified into EvaluateCredentialTheft().
/// Removed 15 redundant methods, reducing composite count from ~40 to ~25.
/// </summary>
public sealed class BehavioralCorrelationEngine : IAsyncDisposable
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<BehavioralCorrelationEngine> _logger;

    // Signal buffer: key = ProcessId (0 = host-level), value = list of recent signals
    private readonly ConcurrentDictionary<int, SignalBuffer> _buffers = new();

    // Correlation window — signals older than this are ignored (tightened for RAM)
    private static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(60);

    // v3.3.0: Electron/JIT apps that legitimately have RWX memory + network connections.
    // These are excluded from composite correlation to prevent false "In-Memory Implant" alerts.
    private static readonly HashSet<string> ElectronAndJitApps = new(StringComparer.OrdinalIgnoreCase)
    {
        // Electron apps (Chromium V8 JIT + constant network)
        "Kiro", "code", "Code",
        "discord", "Discord",
        "slack", "Slack",
        "teams", "Teams", "ms-teams",
        "signal", "Signal",
        "notion", "Notion",
        "obsidian", "Obsidian",
        "figma", "Figma",
        "postman", "Postman",
        "bitwarden", "Bitwarden",
        "1password", "1Password",
        "spotify", "Spotify",
        "whatsapp", "WhatsApp",
        "telegram", "Telegram",
        "gitkraken", "GitKraken",
        "insomnia", "Insomnia",
        "loom", "Loom",
        "linear", "Linear",
        "todoist", "Todoist",
        "clickup", "ClickUp",
        // Steam (CEF embedded browser)
        "steam", "steamwebhelper",
        // Browsers (V8/SpiderMonkey JIT + network is their entire purpose)
        "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "arc",
        // IDEs with JIT
        "devenv", "rider64", "idea64", "pycharm64", "webstorm64", "goland64",
        // Windows system processes with legitimate unbacked executable memory
        "dwm", "TextInputHost", "SearchHost", "ShellExperienceHost",
        "StartMenuExperienceHost", "RuntimeBroker",
        // Windows services that legitimately have no resolvable image path or RWX memory
        "sppsvc", "sppsvc.exe",
        "WmiPrvSE", "wmiprvse",
        "MpDefenderCoreService", "MsMpEng", "NisSrv",
        "SgrmBroker", "SecurityHealthService",
        "OneDrive.Sync.Service",
        "MicrosoftStartFeedProvider",
        "backgroundTaskHost", "BackgroundTransferHost",
        "widgets", "WidgetService",
        "PhoneExperienceHost", "YourPhone",
        "GameBarPresenceWriter",
        "sihost", "taskhostw",
    };

    // Pruning interval
    private Task? _pruneTask;

    public BehavioralCorrelationEngine(
        IDetectionEngine detectionEngine,
        ILogger<BehavioralCorrelationEngine> logger)
    {
        _detectionEngine = detectionEngine;
        _logger          = logger;
    }

    public void Start(CancellationToken cancellationToken)
    {
        _pruneTask = PruneLoopAsync(cancellationToken);
    }

    /// <summary>
    /// Called by SentinelService after each detection event is processed.
    /// Adds the signal to the buffer and evaluates correlation rules.
    /// </summary>
    public async Task OnDetectionAsync(DetectionEvent detection, CancellationToken cancellationToken)
    {
        // v3.3.0: Skip correlation for known Electron/JIT apps whose normal behavior
        // (RWX memory + sustained network) triggers false composite detections.
        if (IsElectronOrJitApp(detection.ProcessName))
        {
            // Still log the individual signal but don't feed it into composite correlation
            return;
        }

        var signal = new Signal(
            detection.RuleName,
            detection.ProcessId,
            detection.Tier,
            detection.Confidence,
            detection.Timestamp,
            detection.Metadata);

        // Add to per-process buffer
        var buffer = _buffers.GetOrAdd(detection.ProcessId, _ => new SignalBuffer());
        buffer.Add(signal);

        // Also add to host-level buffer (pid=0) for cross-process correlations
        if (detection.ProcessId != 0)
        {
            var hostBuffer = _buffers.GetOrAdd(0, _ => new SignalBuffer());
            hostBuffer.Add(signal);
        }

        // Evaluate all correlation rules
        await EvaluateCorrelationsAsync(detection.ProcessId, cancellationToken);
        if (detection.ProcessId != 0)
            await EvaluateCorrelationsAsync(0, cancellationToken);
    }

    private async Task EvaluateCorrelationsAsync(int scopePid, CancellationToken ct)
    {
        if (!_buffers.TryGetValue(scopePid, out var buffer)) return;

        var recent = buffer.GetRecent(CorrelationWindow);
        if (recent.Count < 2) return;

        // Run each correlation rule
        var composite = EvaluateRansomwareChain(recent, scopePid)
                     ?? EvaluateFilelessAttackChain(recent, scopePid)
                     ?? EvaluatePostExploitRecon(recent, scopePid)
                     ?? EvaluateC2Communication(recent, scopePid)
                     ?? EvaluateCredentialTheft(recent, scopePid)
                     ?? EvaluateFullAttackChain(recent, scopePid)
                     ?? EvaluateTokenEscalationWithPersistence(recent, scopePid)
                     ?? EvaluateBulkFileWriteWithDns(recent, scopePid)
                     ?? EvaluateInjectionApiWithFileWrite(recent, scopePid)
                     ?? EvaluateDgaWithAnyFileAccess(recent, scopePid)
                     // v1.4.0 — clipboard exfiltration composite
                     ?? EvaluateClipboardWithNetwork(recent, scopePid)
                     // v1.4.0 — module injection composites
                     ?? EvaluateModuleInjectionWithClipboard(recent, scopePid)
                     // v1.5.0 — screen capture & overlay composites
                     ?? EvaluateScreenCaptureWithNetwork(recent, scopePid)
                     ?? EvaluateScreenCaptureWithClipboard(recent, scopePid)
                     ?? EvaluateOverlayWithInjection(recent, scopePid)
                     ?? EvaluateFullSurveillanceSuite(recent, scopePid)
                     // v1.6.0 — webcam/mic exfiltration composites
                     ?? EvaluateWebcamMicWithNetwork(recent, scopePid)
                     ?? EvaluateWebcamMicWithScreenCapture(recent, scopePid)
                     // v1.8.0 — data exfiltration composites
                     ?? EvaluateExfilDnsWithNetwork(recent, scopePid)
                     ?? EvaluateSensitiveFileWithNetwork(recent, scopePid)
                     ?? EvaluateRemovableMediaWithNetwork(recent, scopePid)
                     ?? EvaluateExfilDnsWithSensitiveFile(recent, scopePid)
                     // v2.5.0 — NeuroBehavior visual manipulation composites
                     ?? EvaluateNeuroWithMicSession(recent, scopePid)
                     ?? EvaluateNeuroWithAudioHijack(recent, scopePid)
                     ?? EvaluateNeuroWithInjection(recent, scopePid)
                     ?? EvaluateMultipleNeuroSignals(recent, scopePid);

        if (composite is null) return;

        // Prevent re-firing the same composite within the window
        var dedupeKey = $"COMPOSITE:{composite.RuleName}:{scopePid}";
        if (buffer.HasFiredComposite(dedupeKey, CorrelationWindow)) return;
        buffer.MarkCompositeFired(dedupeKey);

        _logger.LogCritical(
            "[CORRELATION] Composite detection: {Rule} (confidence {Confidence:P0})",
            composite.RuleName, composite.Confidence);

        await _detectionEngine.EmitAsync(composite, ct);
    }

    // ── Correlation Rules ─────────────────────────────────────────────────────

    /// <summary>
    /// Shadow copy deletion + bulk file rename = active ransomware.
    /// Confidence: 0.99 — this combination has essentially no legitimate explanation.
    /// </summary>
    private static DetectionEvent? EvaluateRansomwareChain(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasShadowDelete = signals.Any(s =>
            s.RuleName.Contains("Ransomware") &&
            s.Metadata.GetValueOrDefault("MatchedPattern", "").Contains("shadow"));

        bool hasBulkRename = signals.Any(s =>
            s.RuleName.Contains("Ransomware") &&
            s.Metadata.ContainsKey("RenameCount"));

        bool hasShadowOrRename = signals.Any(s => s.RuleName.Contains("Ransomware"));

        // Need at least two distinct ransomware signals
        var ransomwareSignals = signals.Where(s => s.RuleName.Contains("Ransomware")).ToList();
        if (ransomwareSignals.Count < 2) return null;

        // Check they're distinct sub-types
        bool hasProcessSignal = ransomwareSignals.Any(s => s.Metadata.ContainsKey("MatchedPattern"));
        bool hasFileSignal    = ransomwareSignals.Any(s => s.Metadata.ContainsKey("RenameCount") ||
                                                           s.Metadata.ContainsKey("NewPath"));

        if (!hasProcessSignal && !hasFileSignal) return null;

        return MakeComposite(
            "Active Ransomware Chain [COMPOSITE]",
            "Shadow copy destruction combined with file rename activity detected within the correlation window. " +
            $"Signals: {string.Join(", ", ransomwareSignals.Select(s => s.RuleName).Distinct())}",
            "This combination — backup destruction followed by file encryption/renaming — is the " +
            "definitive behavioral signature of ransomware execution. Virtually no legitimate software " +
            "performs both operations. Families: LockBit, BlackCat, Conti, REvil, Ryuk, WannaCry.",
            0.99,
            scopePid,
            ransomwareSignals.Last().Timestamp);
    }

    /// <summary>
    /// AMSI bypass + encoded PowerShell + network connection = fileless attack chain.
    /// </summary>
    private static DetectionEvent? EvaluateFilelessAttackChain(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasAmsiBypass = signals.Any(s =>
            s.RuleName.Contains("Evasion") || s.RuleName.Contains("ETW") || s.RuleName.Contains("AMSI"));

        bool hasEncodedPs = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") &&
            s.Metadata.GetValueOrDefault("MatchedPattern", "").Contains("Encoded"));

        bool hasNetwork = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") &&
            s.Metadata.ContainsKey("RemotePort"));

        if (!hasAmsiBypass || (!hasEncodedPs && !hasNetwork)) return null;

        return MakeComposite(
            "Fileless Attack Chain [COMPOSITE]",
            "AMSI/ETW bypass followed by encoded PowerShell or C2 network activity detected. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "The classic fileless attack sequence: disable script scanning (AMSI bypass), " +
            "execute encoded payload (evade logging), establish C2 channel. " +
            "Used by Empire, Covenant, PowerShell Empire, and most modern APT toolkits.",
            0.95,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// v4.6.0 — Unified C2 Communication Detection.
    /// Consolidates 10+ overlapping composites into a single scored evaluation.
    /// 
    /// Detects: any suspicious process characteristic + network activity = C2.
    /// Scores based on how many indicators are present:
    ///   - Kernel injection (ThreatIntel ETW)     → +0.30 (highest-confidence anchor)
    ///   - PPID spoofing                          → +0.25
    ///   - Module/DLL injection                   → +0.25
    ///   - Memory anomaly (RWX/shellcode)         → +0.20
    ///   - Unsigned binary from staging path      → +0.15
    ///   - High entropy binary                    → +0.10
    ///   - DGA DNS resolution                     → +0.15
    ///   - Statistical beaconing pattern          → +0.20
    ///   - Sustained connection (60s+)            → +0.10
    ///   - Non-standard port                      → +0.10
    ///   - C2 port (4444, 50050, etc.)            → +0.15
    ///
    /// Fires when: suspicion score ≥ 0.35 AND network activity is present.
    /// Confidence = min(0.98, 0.70 + suspicion_score).
    /// </summary>
    private static DetectionEvent? EvaluateC2Communication(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        // Only per-process — host-level combines unrelated signals
        if (scopePid == 0) return null;

        // ── Suspicion indicators (process characteristics) ──
        bool hasKernelInjection = signals.Any(s =>
            s.RuleName.Contains("ThreatIntel") || s.RuleName.Contains("Kernel-Observed"));
        bool hasPpidSpoof = signals.Any(s => s.RuleName.Contains("Parent PID Spoofing"));
        bool hasModuleInjection = signals.Any(s =>
            s.RuleName.Contains("Module Integrity") ||
            s.RuleName.Contains("DLL Injection") ||
            s.RuleName.Contains("Phantom Module") ||
            (s.Metadata.ContainsKey("technique") && s.Metadata["technique"].Contains("T1055")));
        bool hasMemoryAnomaly = signals.Any(s =>
            s.RuleName.Contains("Memory Behavior") ||
            s.RuleName.Contains("Memory Execution") ||
            s.Metadata.ContainsKey("memory_kind") ||
            s.Metadata.ContainsKey("rwx_regions"));
        bool hasUnsignedStaged = signals.Any(s =>
            s.RuleName.Contains("Unsigned") &&
            (s.Metadata.GetValueOrDefault("InStagingPath", "False") == "True" ||
             s.Metadata.GetValueOrDefault("ImagePath", "").Contains("Temp", StringComparison.OrdinalIgnoreCase) ||
             s.Metadata.GetValueOrDefault("ImagePath", "").Contains("AppData", StringComparison.OrdinalIgnoreCase)));
        bool hasHighEntropy = signals.Any(s => s.RuleName.Contains("Entropy"));
        bool hasDga = signals.Any(s => s.RuleName.Contains("DGA"));

        // ── Network indicators ──
        bool hasBeaconing = signals.Any(s =>
            s.RuleName.Contains("Beacon") || s.RuleName.Contains("Beaconing"));
        bool hasSustainedConnection = signals.Any(s =>
            s.RuleName.Contains("Sustained Outbound") ||
            (s.Metadata.TryGetValue("duration_seconds", out var dur) &&
             int.TryParse(dur, out var secs) && secs >= 60));
        bool hasC2Port = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") && s.Metadata.ContainsKey("RemotePort"));
        bool hasNonStandardPort = signals.Any(s =>
        {
            if (!s.Metadata.TryGetValue("RemotePort", out var portStr) &&
                !s.Metadata.TryGetValue("remote_port", out portStr)) return false;
            if (!int.TryParse(portStr, out var port)) return false;
            return port != 80 && port != 443 && port != 8080 && port != 8443 && port != 53;
        });
        bool hasAnyNetwork = hasBeaconing || hasSustainedConnection || hasC2Port || hasNonStandardPort ||
            signals.Any(s =>
                s.RuleName.Contains("Network") ||
                s.Metadata.ContainsKey("RemotePort") ||
                s.Metadata.ContainsKey("remote_port"));

        // Must have at least one network indicator
        if (!hasAnyNetwork) return null;

        // ── Score calculation ──
        double suspicionScore = 0;
        var indicators = new List<string>();

        if (hasKernelInjection)  { suspicionScore += 0.30; indicators.Add("kernel injection"); }
        if (hasPpidSpoof)        { suspicionScore += 0.25; indicators.Add("PPID spoofing"); }
        if (hasModuleInjection)  { suspicionScore += 0.25; indicators.Add("module injection"); }
        if (hasMemoryAnomaly)    { suspicionScore += 0.20; indicators.Add("memory anomaly"); }
        if (hasUnsignedStaged)   { suspicionScore += 0.15; indicators.Add("unsigned from staging path"); }
        if (hasHighEntropy)      { suspicionScore += 0.10; indicators.Add("high entropy binary"); }
        if (hasDga)              { suspicionScore += 0.15; indicators.Add("DGA DNS"); }
        if (hasBeaconing)        { suspicionScore += 0.20; indicators.Add("statistical beaconing"); }
        if (hasSustainedConnection) { suspicionScore += 0.10; indicators.Add("sustained connection"); }
        if (hasNonStandardPort)  { suspicionScore += 0.10; indicators.Add("non-standard port"); }
        if (hasC2Port)           { suspicionScore += 0.15; indicators.Add("known C2 port"); }

        // Minimum threshold: need meaningful suspicion beyond just "has network"
        if (suspicionScore < 0.35) return null;

        var confidence = Math.Min(0.98, 0.70 + suspicionScore);

        return MakeComposite(
            "C2 Communication Detected [COMPOSITE]",
            $"Process exhibits C2 indicators ({string.Join(" + ", indicators)}) with active network. " +
            $"Score: {suspicionScore:F2}. Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "Multiple behavioral indicators confirm command-and-control communication. " +
            "The process shows characteristics incompatible with legitimate software " +
            "(injection, spoofing, unsigned staging, memory anomalies, DGA) combined with " +
            "active outbound network activity (beaconing, sustained connections, C2 ports). " +
            "Covers: Cobalt Strike, Metasploit, Sliver, Brute Ratel, custom RATs, and novel implants.",
            confidence,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// v4.6.0 — Unified Credential Theft Detection.
    /// Consolidates LSASS + network, dbghelp + LSASS, dbghelp + network, credential canary + network.
    /// </summary>
    private static DetectionEvent? EvaluateCredentialTheft(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasLsass = signals.Any(s => s.RuleName.Contains("LSASS"));
        bool hasDbghelp = signals.Any(s => s.RuleName.Contains("dbghelp"));
        bool hasCanary = signals.Any(s => s.RuleName.Contains("Credential Canary"));
        bool hasNetwork = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") ||
            s.RuleName.Contains("Beacon") ||
            s.RuleName.Contains("Network") ||
            s.Metadata.ContainsKey("RemotePort") ||
            s.Metadata.ContainsKey("remote_port"));

        // Pattern 1: dbghelp + LSASS = confirmed dump (no network needed)
        if (hasDbghelp && hasLsass)
        {
            return MakeComposite(
                "Credential Dump Confirmed [COMPOSITE]",
                "Process loaded dbghelp.dll AND targets LSASS. " +
                $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
                "dbghelp.dll (MiniDumpWriteDump) combined with LSASS-targeting confirms " +
                "an active credential dump regardless of tool name or technique.",
                0.97,
                scopePid,
                signals.Last().Timestamp);
        }

        // Pattern 2: Any credential indicator + network = exfiltration
        bool hasCredentialSignal = hasLsass || hasDbghelp || hasCanary;
        if (hasCredentialSignal && hasNetwork)
        {
            var credType = hasLsass ? "LSASS dump" : hasCanary ? "credential canary" : "dump tool";
            return MakeComposite(
                "Credential Theft + Exfiltration [COMPOSITE]",
                $"Credential access ({credType}) combined with network activity. " +
                $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
                "Credential harvesting combined with active network connections indicates " +
                "stolen credentials are being exfiltrated to an attacker-controlled server.",
                0.96,
                scopePid,
                signals.Last().Timestamp);
        }

        return null;
    }

    /// <summary>
    /// 3+ distinct recon commands within the window = post-exploitation discovery phase.
    /// </summary>
    private static DetectionEvent? EvaluatePostExploitRecon(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        var reconSignals = signals
            .Where(s => s.RuleName.Contains("Suspicious API") &&
                        s.Metadata.ContainsKey("ReconType"))
            .ToList();

        // Need at least 3 distinct recon types
        var distinctReconTypes = reconSignals
            .Select(s => s.Metadata.GetValueOrDefault("ReconType", ""))
            .Distinct()
            .ToList();

        if (distinctReconTypes.Count < 3) return null;

        return MakeComposite(
            "Post-Exploitation Recon Sequence [COMPOSITE]",
            $"{distinctReconTypes.Count} distinct reconnaissance commands within {CorrelationWindow.TotalSeconds}s: " +
            string.Join(", ", distinctReconTypes),
            "Multiple reconnaissance commands in rapid succession is the hallmark of post-exploitation " +
            "discovery (MITRE ATT&CK TA0007). Attackers run whoami, net user, ipconfig, nltest, etc. " +
            "immediately after gaining a foothold to understand the environment. " +
            "Individual commands are low-confidence; this sequence is high-confidence.",
            0.88,
            scopePid,
            reconSignals.Last().Timestamp);
    }

    /// <summary>
    /// Token integrity escalation + persistence installation = post-exploitation privilege persistence.
    /// Attacker escalated privileges AND is making them survive reboot.
    /// </summary>
    private static DetectionEvent? EvaluateTokenEscalationWithPersistence(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasEscalation = signals.Any(s =>
            s.RuleName.Contains("Token Integrity") || s.RuleName.Contains("Privilege Escalation"));
        bool hasPersistence = signals.Any(s => s.RuleName.Contains("Persistence"));

        if (!hasEscalation || !hasPersistence) return null;

        return MakeComposite(
            "Privilege Escalation + Persistence [COMPOSITE]",
            "Process escalated token integrity AND installed persistence mechanism. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "An attacker who escalates privileges and immediately installs persistence is " +
            "securing their foothold. This combination — UAC bypass or token manipulation " +
            "followed by Run key, scheduled task, or service creation — is the standard " +
            "post-exploitation sequence for maintaining access across reboots.",
            0.94,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// Triple signal: PPID spoof + token escalation + injection API = full attack chain.
    /// This is the complete Cobalt Strike / advanced implant lifecycle in one correlation.
    /// </summary>
    private static DetectionEvent? EvaluateFullAttackChain(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasPpidSpoof = signals.Any(s => s.RuleName.Contains("Parent PID Spoofing"));
        bool hasEscalation = signals.Any(s =>
            s.RuleName.Contains("Token Integrity") || s.RuleName.Contains("Privilege"));
        bool hasInjection = signals.Any(s =>
            s.RuleName.Contains("Injection") || s.RuleName.Contains("ThreatIntel"));

        // Need at least 2 of 3 for this composite
        int matchCount = (hasPpidSpoof ? 1 : 0) + (hasEscalation ? 1 : 0) + (hasInjection ? 1 : 0);
        if (matchCount < 2) return null;

        return MakeComposite(
            "Advanced Attack Chain (multi-technique) [COMPOSITE]",
            $"Multiple advanced techniques detected on same PID: " +
            $"PPID spoof={hasPpidSpoof}, Token escalation={hasEscalation}, Injection={hasInjection}. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "Multiple advanced attack techniques correlating on the same process within the " +
            "correlation window indicates a sophisticated implant lifecycle: spawn with fake parent, " +
            "escalate privileges, inject into target. This is the behavioral signature of " +
            "Cobalt Strike, Brute Ratel, Sliver, and custom APT tooling.",
            0.98,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// Bulk file writes (50+) + DNS resolution to non-cached domain = kill.
    /// Rationale: ransomware encrypts files then phones home to report success.
    /// Also catches infostealers collecting then exfiltrating.
    /// </summary>
    private static DetectionEvent? EvaluateBulkFileWriteWithDns(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasBulkFiles = signals.Any(s =>
            s.RuleName.Contains("Ransomware") ||
            (s.Metadata.TryGetValue("FilesModified", out var count) && int.TryParse(count, out var n) && n >= 50) ||
            (s.Metadata.TryGetValue("RenameCount", out var rc) && int.TryParse(rc, out var rn) && rn >= 20));

        bool hasDns = signals.Any(s =>
            s.RuleName.Contains("DNS") || s.RuleName.Contains("DGA"));

        if (!hasBulkFiles || !hasDns) return null;

        return MakeComposite(
            "Mass File Operation + DNS Resolution [COMPOSITE]",
            "Process performed bulk file operations AND resolved DNS. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process that modified/renamed many files is also resolving domain names. " +
            "This is the ransomware completion pattern (encrypt → phone home) or an " +
            "infostealer pattern (collect files → resolve C2 → exfiltrate).",
            0.93,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// Injection API in cmdline + file write activity = kill.
    /// Rationale: if you're explicitly using injection APIs AND writing files,
    /// you're a dropper/loader staging payloads.
    /// </summary>
    private static DetectionEvent? EvaluateInjectionApiWithFileWrite(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasInjectionApi = signals.Any(s =>
            s.RuleName.Contains("Injection") && s.Metadata.ContainsKey("MatchedApi"));
        bool hasFileWrite = signals.Any(s =>
            s.RuleName.Contains("Ransomware") ||
            s.RuleName.Contains("File") ||
            s.Metadata.ContainsKey("NewPath") ||
            s.Metadata.ContainsKey("file_path"));

        if (!hasInjectionApi || !hasFileWrite) return null;

        return MakeComposite(
            "Injection Tool + File Staging [COMPOSITE]",
            "Process using injection APIs AND performing file write operations. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process with injection API names in its command line is also writing files. " +
            "This is a loader/dropper that injects into other processes while staging " +
            "additional payloads on disk. Legitimate software never exposes injection APIs.",
            0.91,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// DGA DNS + ANY file access = kill.
    /// Rationale: if you're resolving algorithmically-generated domains AND touching
    /// files, you're malware doing C2 + data collection/encryption.
    /// </summary>
    private static DetectionEvent? EvaluateDgaWithAnyFileAccess(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasDga = signals.Any(s => s.RuleName.Contains("DGA"));
        bool hasFileAccess = signals.Any(s =>
            s.RuleName.Contains("Ransomware") ||
            s.RuleName.Contains("File") ||
            s.Metadata.ContainsKey("NewPath") ||
            s.Metadata.ContainsKey("file_path") ||
            s.Metadata.ContainsKey("FilesModified"));

        if (!hasDga || !hasFileAccess) return null;

        return MakeComposite(
            "DGA Resolution + File Operations [COMPOSITE]",
            "Process resolving DGA domains AND performing file operations. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process resolving high-entropy (algorithmically generated) domain names is also " +
            "accessing files. DGA + file operations = malware doing C2 communication while " +
            "collecting, encrypting, or exfiltrating data. No legitimate software uses DGA.",
            0.94,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// v1.4.0 — Clipboard access + network activity = clipboard exfiltration.
    /// Catches malware that reads clipboard content (passwords, crypto addresses, sensitive data)
    /// and sends it to an attacker-controlled server. Also catches scenarios where a legitimate
    /// process is hijacked (DLL injection, browser extension) to exfiltrate clipboard data.
    /// </summary>
    private static DetectionEvent? EvaluateClipboardWithNetwork(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasClipboard = signals.Any(s =>
            s.RuleName.Contains("Clipboard") ||
            s.Metadata.ContainsKey("technique") &&
            s.Metadata["technique"].Contains("T1115"));
        bool hasNetwork = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") ||
            s.RuleName.Contains("Beacon") ||
            s.RuleName.Contains("Network") ||
            s.Metadata.ContainsKey("RemotePort") ||
            s.Metadata.ContainsKey("remote_port"));

        if (!hasClipboard || !hasNetwork) return null;

        return MakeComposite(
            "Clipboard Exfiltration: Clipboard Access + Network [COMPOSITE]",
            "Process with clipboard access/hijacking AND outbound network activity. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process that is accessing/modifying the clipboard is also making network " +
            "connections. This is the definitive clipboard exfiltration pattern: malware " +
            "harvests clipboard content (passwords, crypto wallet addresses, sensitive text) " +
            "and transmits it to a C2 server. This catches both direct clipboard stealers " +
            "and scenarios where a legitimate process is hijacked via DLL injection or " +
            "browser extension to silently exfiltrate clipboard data.",
            0.93,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// v1.4.0 — Module injection + clipboard access = clipboard exfil via injected DLL.
    /// An injected DLL that accesses the clipboard is stealing data through a trusted process.
    /// </summary>
    private static DetectionEvent? EvaluateModuleInjectionWithClipboard(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasModuleInjection = signals.Any(s =>
            s.RuleName.Contains("Module Integrity") ||
            s.RuleName.Contains("DLL Injection") ||
            s.RuleName.Contains("Phantom Module") ||
            (s.Metadata.ContainsKey("technique") &&
             s.Metadata["technique"].Contains("T1055")));
        bool hasClipboard = signals.Any(s =>
            s.RuleName.Contains("Clipboard") ||
            (s.Metadata.ContainsKey("technique") &&
             s.Metadata["technique"].Contains("T1115")));

        if (!hasModuleInjection || !hasClipboard) return null;

        return MakeComposite(
            "Clipboard Theft via Injected Module [COMPOSITE]",
            "Process received DLL injection AND is accessing/modifying clipboard. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process that had a suspicious module injected is now accessing the clipboard. " +
            "This is the definitive 'clipboard theft via injection' pattern: attacker injects " +
            "a DLL into a trusted process (browser, explorer, etc.) and uses it to silently " +
            "harvest clipboard content (passwords, crypto addresses, sensitive data) while " +
            "hiding behind the trusted process name to evade detection.",
            0.94,
            scopePid,
            signals.Last().Timestamp);
    }

    // ── v1.5.0 Screen Capture & Overlay Composites ──────────────────────────

    /// <summary>
    /// v1.5.0 — Screen capture + network activity = screen exfiltration (spyware).
    /// A process capturing the screen AND sending data over the network is streaming
    /// or uploading screenshots to an attacker. Classic RAT/spyware behavior.
    /// </summary>
    private static DetectionEvent? EvaluateScreenCaptureWithNetwork(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasScreenCapture = signals.Any(s =>
            s.RuleName.Contains("Screen Capture") ||
            (s.Metadata.ContainsKey("technique") &&
             s.Metadata["technique"].Contains("T1113")));
        bool hasNetwork = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") ||
            s.RuleName.Contains("Beacon") ||
            s.RuleName.Contains("Network") ||
            s.Metadata.ContainsKey("RemotePort") ||
            s.Metadata.ContainsKey("remote_port"));

        if (!hasScreenCapture || !hasNetwork) return null;

        return MakeComposite(
            "Screen Exfiltration: Capture + Network [COMPOSITE]",
            "Process with screen capture capability AND outbound network activity. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process performing screen capture (DXGI duplication, GDI BitBlt, or overlay " +
            "rendering) is also communicating over the network. This is the definitive " +
            "screen-exfiltration pattern: spyware captures screenshots or streams the desktop " +
            "to an attacker-controlled server. RATs (Remote Access Trojans), stalkerware, and " +
            "corporate espionage tools all exhibit this exact behavior. Legitimate screen " +
            "sharing tools (Teams, Zoom) are allowlisted and won't trigger this.",
            0.93,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// v1.5.0 — Screen capture + clipboard access = data harvesting (infostealer).
    /// A process that captures both screen content AND clipboard data is performing
    /// comprehensive data harvesting — the hallmark of infostealers.
    /// </summary>
    private static DetectionEvent? EvaluateScreenCaptureWithClipboard(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasScreenCapture = signals.Any(s =>
            s.RuleName.Contains("Screen Capture") ||
            s.RuleName.Contains("Overlay") ||
            (s.Metadata.ContainsKey("technique") &&
             s.Metadata["technique"].Contains("T1113")));
        bool hasClipboard = signals.Any(s =>
            s.RuleName.Contains("Clipboard") ||
            (s.Metadata.ContainsKey("technique") &&
             s.Metadata["technique"].Contains("T1115")));

        if (!hasScreenCapture || !hasClipboard) return null;

        return MakeComposite(
            "Data Harvesting: Screen + Clipboard Capture [COMPOSITE]",
            "Process performing BOTH screen capture AND clipboard access/hijacking. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A single process (or correlated processes on the same PID) capturing both " +
            "screen content and clipboard data is performing comprehensive data harvesting. " +
            "This is the behavioral signature of infostealers (RedLine, Raccoon, Vidar, " +
            "Mars Stealer) that collect screenshots + clipboard content (passwords, crypto " +
            "addresses, sensitive text) before exfiltrating everything to C2. The combination " +
            "of both capture vectors on one process is extremely unlikely to be legitimate.",
            0.92,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// v1.5.0 — Overlay window + process injection = credential phishing via overlay.
    /// An injected process creating overlay windows is a banking trojan drawing fake
    /// login prompts over legitimate applications.
    /// </summary>
    private static DetectionEvent? EvaluateOverlayWithInjection(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasOverlay = signals.Any(s =>
            s.RuleName.Contains("Overlay") ||
            (s.Metadata.ContainsKey("technique") &&
             s.Metadata["technique"].Contains("T1056.004")));
        bool hasInjection = signals.Any(s =>
            s.RuleName.Contains("Injection") ||
            s.RuleName.Contains("ThreatIntel") ||
            s.RuleName.Contains("Module Integrity") ||
            s.RuleName.Contains("Phantom Module") ||
            (s.Metadata.ContainsKey("technique") &&
             s.Metadata["technique"].Contains("T1055")));

        if (!hasOverlay || !hasInjection) return null;

        return MakeComposite(
            "Credential Phishing: Overlay + Injection [COMPOSITE]",
            "Process with suspicious overlay window AND injection indicators. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process that was injected (or is performing injection) AND has created a " +
            "transparent overlay window is almost certainly a banking trojan or credential " +
            "phishing attack. The attacker injects into a trusted process, then draws a " +
            "fake login overlay on top of the real application (browser, banking app) to " +
            "capture credentials. Families: Zeus, TrickBot, Dridex, Emotet (banking module), " +
            "QakBot. This combination has essentially no legitimate explanation.",
            0.96,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// v1.5.0 — Multi-vector surveillance: Screen + Clipboard/Keylogger + Audio-to-Mic + Webcam/Mic = full spyware suite.
    /// A process (or correlated processes) performing screen capture, input capture, AND/OR
    /// audio hijacking (output routed to mic), AND/OR webcam/mic recording is a comprehensive surveillance implant.
    /// Updated in v1.6.0 to include webcam/mic as a fourth vector.
    /// </summary>
    private static DetectionEvent? EvaluateFullSurveillanceSuite(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasScreen = signals.Any(s =>
            s.RuleName.Contains("Screen Capture") ||
            s.RuleName.Contains("Overlay") ||
            (s.Metadata.ContainsKey("technique") && s.Metadata["technique"].Contains("T1113")));
        bool hasInputCapture = signals.Any(s =>
            s.RuleName.Contains("Clipboard") ||
            s.RuleName.Contains("Keylogger") ||
            (s.Metadata.ContainsKey("technique") && s.Metadata["technique"].Contains("T1056")) ||
            (s.Metadata.ContainsKey("technique") && s.Metadata["technique"].Contains("T1115")));
        bool hasAudioHijack = signals.Any(s =>
            s.RuleName.Contains("AudioHijack") ||
            s.RuleName.Contains("Audio Hijack") ||
            s.RuleName.Contains("Audio routed to microphone"));
        bool hasWebcamMic = signals.Any(s =>
            s.RuleName.Contains("Webcam/Mic") ||
            (s.Metadata.ContainsKey("device_type"))); // Only WebcamMicMonitor sets device_type

        // Need at least 2 of 4 surveillance vectors
        int matchCount = (hasScreen ? 1 : 0) + (hasInputCapture ? 1 : 0) +
                         (hasAudioHijack ? 1 : 0) + (hasWebcamMic ? 1 : 0);
        if (matchCount < 2) return null;

        // Higher confidence with more vectors
        double confidence = matchCount >= 4 ? 0.99 : matchCount >= 3 ? 0.98 : 0.94;

        return MakeComposite(
            "Full Surveillance Suite Detected [COMPOSITE]",
            $"Multiple surveillance vectors active: Screen={hasScreen}, " +
            $"Input/Clipboard={hasInputCapture}, Audio-to-Mic={hasAudioHijack}, " +
            $"Webcam/Mic={hasWebcamMic} ({matchCount}/4 vectors). " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "Multiple surveillance capabilities are active on the same process or within the " +
            "correlation window: screen capture/overlay, input monitoring (keylogging/clipboard), " +
            "audio hijacking (routing output to microphone for voice impersonation), and/or " +
            "webcam/microphone recording. This is the behavioral signature of a comprehensive " +
            "surveillance implant. No legitimate single application performs all of these " +
            "simultaneously from the background. The more vectors active, the higher the certainty.",
            confidence,
            scopePid,
            signals.Last().Timestamp);
    }

    // ── v1.6.0 Webcam/Mic Exfiltration Composites ────────────────────────────

    /// <summary>
    /// v1.6.0 — Webcam/Mic background access + network activity = camera/mic exfiltration.
    /// A background process accessing the camera or microphone AND communicating over the
    /// network is streaming audio/video to an attacker. Classic RAT/stalkerware behavior.
    /// </summary>
    private static DetectionEvent? EvaluateWebcamMicWithNetwork(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasWebcamMic = signals.Any(s =>
            s.RuleName.Contains("Webcam/Mic") ||
            s.Metadata.ContainsKey("device_type")); // Only WebcamMicMonitor sets device_type
        bool hasNetwork = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") ||
            s.RuleName.Contains("Beacon") ||
            s.RuleName.Contains("Network") ||
            s.Metadata.ContainsKey("RemotePort") ||
            s.Metadata.ContainsKey("remote_port"));

        if (!hasWebcamMic || !hasNetwork) return null;

        return MakeComposite(
            "Camera/Mic Exfiltration: Capture + Network [COMPOSITE]",
            "Background process with webcam/microphone access AND outbound network activity. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A background process (no visible window) accessing the camera or microphone is " +
            "also communicating over the network. This is the definitive webcam/mic exfiltration " +
            "pattern: spyware or a RAT secretly records the user via camera/mic and streams or " +
            "uploads the footage to an attacker-controlled server. Legitimate conferencing and " +
            "streaming apps are allowlisted and have visible windows. Background-only capture " +
            "combined with network activity has no legitimate explanation.",
            0.94,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// v1.6.0 — Webcam/Mic + Screen Capture = comprehensive AV surveillance.
    /// A process capturing both camera/mic AND screen content is performing total
    /// surveillance — recording everything the user sees and does.
    /// </summary>
    private static DetectionEvent? EvaluateWebcamMicWithScreenCapture(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasWebcamMic = signals.Any(s =>
            s.RuleName.Contains("Webcam/Mic") ||
            s.Metadata.ContainsKey("device_type")); // Only WebcamMicMonitor sets device_type
        bool hasScreenCapture = signals.Any(s =>
            s.RuleName.Contains("Screen Capture") ||
            (s.Metadata.ContainsKey("technique") &&
             s.Metadata["technique"].Contains("T1113")));

        if (!hasWebcamMic || !hasScreenCapture) return null;

        return MakeComposite(
            "Total AV Surveillance: Camera + Screen Capture [COMPOSITE]",
            "Process performing BOTH webcam/mic capture AND screen capture from background. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A single process (or correlated processes) capturing both the user's camera/mic " +
            "feed AND their screen content is performing total audio-visual surveillance. " +
            "This captures everything: what the user looks like, what they say, and what's on " +
            "their screen. This is the behavioral signature of advanced stalkerware and " +
            "nation-state surveillance implants (FinFisher, Pegasus-like, DarkComet). " +
            "No legitimate application performs both from the background simultaneously.",
            0.95,
            scopePid,
            signals.Last().Timestamp);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // v1.8.0 — DATA EXFILTRATION COMPOSITES
    // These fire when exfil indicators correlate with network activity.
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Process resolved a known exfil service domain (Mega, pastebin, transfer.sh, Telegram API)
    /// AND has an active network connection = confirmed data exfiltration in progress.
    /// </summary>
    private static DetectionEvent? EvaluateExfilDnsWithNetwork(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasExfilDns = signals.Any(s =>
            s.RuleName.Contains("Exfiltration: Upload Service DNS") ||
            s.RuleName.Contains("exfiltration") && s.Metadata.ContainsKey("domain"));
        bool hasNetwork = signals.Any(s =>
            s.RuleName.Contains("Network") ||
            s.Metadata.ContainsKey("remote_address") ||
            s.Metadata.ContainsKey("remote_port"));

        if (!hasExfilDns || !hasNetwork) return null;

        var domain = signals.FirstOrDefault(s => s.Metadata.ContainsKey("domain"))?.Metadata["domain"] ?? "unknown";

        return MakeComposite(
            "Data Exfiltration: Upload Service + Network [COMPOSITE]",
            $"Process resolved exfil domain '{domain}' AND has active network connection. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A non-browser process resolved a known file-sharing/paste/upload service domain " +
            "and has an active outbound network connection. This is confirmed data exfiltration — " +
            "the process is actively uploading stolen data to an external service.",
            0.96,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// Process accessed sensitive files (SSH keys, cloud creds, browser passwords)
    /// AND has network activity = credential theft + exfiltration.
    /// </summary>
    private static DetectionEvent? EvaluateSensitiveFileWithNetwork(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasSensitiveAccess = signals.Any(s =>
            s.RuleName.Contains("Sensitive File Access") ||
            s.RuleName.Contains("Credential") ||
            (s.Metadata.ContainsKey("category") && (
                s.Metadata["category"] == "ssh_keys" ||
                s.Metadata["category"] == "cloud_credentials" ||
                s.Metadata["category"] == "browser_credentials" ||
                s.Metadata["category"] == "cryptocurrency")));
        bool hasNetwork = signals.Any(s =>
            s.RuleName.Contains("Network") ||
            s.Metadata.ContainsKey("remote_address"));

        if (!hasSensitiveAccess || !hasNetwork) return null;

        return MakeComposite(
            "Data Exfiltration: Credential Theft + Network [COMPOSITE]",
            $"Process accessed sensitive credential files AND has network activity. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process accessed SSH keys, cloud credentials, browser password databases, or " +
            "cryptocurrency wallets and then initiated a network connection. This is the classic " +
            "infostealer pattern: harvest credentials locally, then exfiltrate to C2/upload service.",
            0.95,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// Process read files from removable media (USB) AND has network activity = USB-to-network exfil.
    /// This is exactly the attack vector that was missed.
    /// </summary>
    private static DetectionEvent? EvaluateRemovableMediaWithNetwork(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasRemovableRead = signals.Any(s =>
            s.RuleName.Contains("Removable Media") ||
            (s.Metadata.ContainsKey("drive_path") && s.Metadata.ContainsKey("file_path")));
        bool hasNetwork = signals.Any(s =>
            s.RuleName.Contains("Network") ||
            s.Metadata.ContainsKey("remote_address"));

        if (!hasRemovableRead || !hasNetwork) return null;

        var filePath = signals.FirstOrDefault(s => s.Metadata.ContainsKey("file_path"))?.Metadata["file_path"] ?? "unknown";

        return MakeComposite(
            "Data Exfiltration: USB Media + Network Upload [COMPOSITE]",
            $"Process read from removable media ('{filePath}') AND has outbound network connection. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process read files from a USB/removable drive and then initiated a network connection. " +
            "This is USB-to-network data exfiltration — the attacker is stealing data from removable " +
            "media and uploading it to their infrastructure.",
            0.96,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// Process resolved exfil domain AND accessed sensitive files = pre-exfil staging confirmed.
    /// Kill before the upload even starts.
    /// </summary>
    private static DetectionEvent? EvaluateExfilDnsWithSensitiveFile(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasExfilDns = signals.Any(s =>
            s.RuleName.Contains("Exfiltration: Upload Service DNS"));
        bool hasSensitiveAccess = signals.Any(s =>
            s.RuleName.Contains("Sensitive File Access") ||
            s.RuleName.Contains("Removable Media"));

        if (!hasExfilDns || !hasSensitiveAccess) return null;

        return MakeComposite(
            "Data Exfiltration: Staging + Upload Service [COMPOSITE]",
            $"Process resolved exfil service domain AND accessed sensitive/removable files. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process accessed sensitive files or removable media AND resolved a known upload " +
            "service domain. This is pre-exfiltration staging — the process is preparing to upload " +
            "stolen data. Kill immediately before the transfer begins.",
            0.94,
            scopePid,
            signals.Last().Timestamp);
    }

    // ── v2.5.0 NeuroBehavior Visual Manipulation Composites ──────────────────
    // Philosophy: visual manipulation signals (flash, color, focus, cursor) are
    // individually low-confidence (games/video cause them). But combined with
    // audio injection, mic sessions, or process injection, they indicate a
    // coordinated attack on the user's senses.

    /// <summary>
    /// NeuroBehavior signal + unauthorized mic session = sensory manipulation attack.
    /// A process is manipulating the screen AND injecting audio into the mic.
    /// This is the "hypno command" scenario: visual distraction + audio injection.
    /// </summary>
    private static DetectionEvent? EvaluateNeuroWithMicSession(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasNeuro = signals.Any(s =>
            s.RuleName.Contains("NeuroBehavior") &&
            s.Metadata.ContainsKey("neuro_signal"));

        bool hasMicSession = signals.Any(s =>
            s.RuleName.Contains("Mic Session") ||
            s.RuleName.Contains("Audio Injection"));

        if (!hasNeuro || !hasMicSession) return null;

        var neuroSignals = signals.Where(s => s.RuleName.Contains("NeuroBehavior")).ToList();
        var neuroTypes = neuroSignals
            .Select(s => s.Metadata.GetValueOrDefault("neuro_signal", "unknown"))
            .Distinct().ToList();

        return MakeComposite(
            "Sensory Manipulation: Visual + Audio Injection [COMPOSITE]",
            $"NeuroBehavior visual manipulation ({string.Join(", ", neuroTypes)}) detected " +
            $"alongside unauthorized microphone session. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process is simultaneously manipulating the user's visual environment (screen " +
            "flashing, color distortion, focus stealing, or cursor manipulation) AND holding " +
            "an unauthorized audio session on the microphone. This combination indicates a " +
            "coordinated sensory manipulation attack — visual distraction paired with audio " +
            "injection (deepfake voice, subliminal audio, or command injection via mic feed). " +
            "No legitimate application performs both operations simultaneously.",
            0.93,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// NeuroBehavior signal + audio-to-mic routing = output-to-mic manipulation.
    /// Visual manipulation combined with audio routing into the mic device.
    /// </summary>
    private static DetectionEvent? EvaluateNeuroWithAudioHijack(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasNeuro = signals.Any(s =>
            s.RuleName.Contains("NeuroBehavior") &&
            s.Metadata.ContainsKey("neuro_signal"));

        bool hasAudioHijack = signals.Any(s =>
            s.RuleName.Contains("AudioHijack") ||
            s.RuleName.Contains("Audio routed to microphone"));

        if (!hasNeuro || !hasAudioHijack) return null;

        var neuroSignals = signals.Where(s => s.RuleName.Contains("NeuroBehavior")).ToList();
        var neuroTypes = neuroSignals
            .Select(s => s.Metadata.GetValueOrDefault("neuro_signal", "unknown"))
            .Distinct().ToList();

        return MakeComposite(
            "Sensory Manipulation: Visual + Audio Hijack [COMPOSITE]",
            $"NeuroBehavior visual manipulation ({string.Join(", ", neuroTypes)}) detected " +
            $"alongside audio output-to-microphone routing. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process is manipulating the user's visual environment AND routing audio output " +
            "into the microphone device. This is a coordinated attack: visual manipulation " +
            "(flashing, color shifts) combined with audio injection into voice chat. The attacker " +
            "is using both visual and auditory channels to influence or impersonate.",
            0.94,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// NeuroBehavior signal + process injection = injected visual manipulator.
    /// A process was injected into AND is now manipulating the screen.
    /// </summary>
    private static DetectionEvent? EvaluateNeuroWithInjection(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasNeuro = signals.Any(s =>
            s.RuleName.Contains("NeuroBehavior") &&
            s.Metadata.ContainsKey("neuro_signal"));

        bool hasInjection = signals.Any(s =>
            s.RuleName.Contains("Injection") ||
            s.RuleName.Contains("ThreatIntel") ||
            s.RuleName.Contains("Module Injection"));

        if (!hasNeuro || !hasInjection) return null;

        return MakeComposite(
            "Injected Visual Manipulator [COMPOSITE]",
            $"Process injection detected alongside NeuroBehavior visual manipulation. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process that received injected code is now manipulating the user's visual " +
            "environment. This indicates malicious code was injected into a legitimate process " +
            "and is using it to perform visual manipulation (flashing, color distortion, " +
            "focus stealing). The injection provides stealth; the visual manipulation is the payload.",
            0.92,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// Multiple distinct NeuroBehavior signals from same process = coordinated visual attack.
    /// If a single process triggers 3+ different neuro detections, it's not accidental.
    /// </summary>
    private static DetectionEvent? EvaluateMultipleNeuroSignals(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        var neuroSignals = signals
            .Where(s => s.RuleName.Contains("NeuroBehavior") && s.Metadata.ContainsKey("neuro_signal"))
            .ToList();

        var distinctTypes = neuroSignals
            .Select(s => s.Metadata.GetValueOrDefault("neuro_signal", ""))
            .Where(s => !string.IsNullOrEmpty(s))
            .Distinct()
            .ToList();

        // Need 3+ distinct neuro signal types from same scope
        if (distinctTypes.Count < 3) return null;

        return MakeComposite(
            "Coordinated Visual Manipulation Attack [COMPOSITE]",
            $"Multiple distinct NeuroBehavior signals detected: {string.Join(", ", distinctTypes)}. " +
            $"Total neuro signals: {neuroSignals.Count} across {distinctTypes.Count} categories.",
            "A single process or scope triggered 3+ distinct visual manipulation techniques " +
            "(e.g., flashing + color distortion + focus stealing + cursor jitter). Individual " +
            "signals are low-confidence, but 3+ distinct techniques from the same source is " +
            "not accidental — it indicates a coordinated visual manipulation attack designed " +
            "to disorient, influence, or incapacitate the user.",
            0.90,
            scopePid,
            signals.Last().Timestamp);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// v3.3.0: Returns true if the process is a known Electron/JIT app that should be
    /// excluded from composite correlation (RWX + network is their normal behavior).
    /// </summary>
    private static bool IsElectronOrJitApp(string processName)
    {
        if (string.IsNullOrEmpty(processName)) return false;
        // Match with or without .exe suffix
        var name = processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? processName[..^4]
            : processName;
        return ElectronAndJitApps.Contains(name) || ElectronAndJitApps.Contains(processName);
    }

    private static DetectionEvent MakeComposite(
        string ruleName, string evidence, string reasoning,
        double confidence, int pid, DateTimeOffset timestamp)
    {
        return new DetectionEvent
        {
            RuleName    = ruleName,
            Evidence    = evidence,
            Reasoning   = reasoning,
            Confidence  = confidence,
            Tier        = DetectionTier.Tier1Behavioral,
            ProcessName = pid == 0 ? "Host-Level" : pid.ToString(),
            ProcessId   = pid,
            Timestamp   = timestamp,
            Metadata    = new() { ["DetectionType"] = "Composite", ["CorrelationWindowSec"] = CorrelationWindow.TotalSeconds.ToString() }
        };
    }

    private async Task PruneLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(15), cancellationToken);
                foreach (var buffer in _buffers.Values)
                    buffer.Prune(CorrelationWindow);

                // Remove empty buffers for dead processes
                foreach (var key in _buffers.Keys.ToList())
                {
                    if (_buffers.TryGetValue(key, out var b) && b.IsEmpty)
                        _buffers.TryRemove(key, out _);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[CorrelationEngine] Prune error.");
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_pruneTask is not null)
        {
            try { await _pruneTask.WaitAsync(TimeSpan.FromSeconds(3)); }
            catch { /* best-effort */ }
        }
    }
}

// ── Signal and buffer types ───────────────────────────────────────────────────

public sealed record Signal(
    string RuleName,
    int ProcessId,
    DetectionTier Tier,
    double Confidence,
    DateTimeOffset Timestamp,
    IReadOnlyDictionary<string, string> Metadata);

public sealed class SignalBuffer
{
    private readonly List<Signal> _signals = new();
    private readonly Dictionary<string, DateTimeOffset> _firedComposites = new();
    private readonly object _lock = new();

    public void Add(Signal signal)
    {
        lock (_lock)
        {
            _signals.Add(signal);
            // Hard cap: keep only the most recent 50 signals to bound RAM
            if (_signals.Count > 50)
                _signals.RemoveRange(0, _signals.Count - 50);
        }
    }

    public IReadOnlyList<Signal> GetRecent(TimeSpan window)
    {
        var cutoff = DateTimeOffset.UtcNow - window;
        lock (_lock)
        {
            return _signals.Where(s => s.Timestamp >= cutoff).ToList();
        }
    }

    public bool HasFiredComposite(string key, TimeSpan window)
    {
        lock (_lock)
        {
            return _firedComposites.TryGetValue(key, out var t) &&
                   DateTimeOffset.UtcNow - t < window;
        }
    }

    public void MarkCompositeFired(string key)
    {
        lock (_lock) { _firedComposites[key] = DateTimeOffset.UtcNow; }
    }

    public void Prune(TimeSpan window)
    {
        var cutoff = DateTimeOffset.UtcNow - window;
        lock (_lock)
        {
            _signals.RemoveAll(s => s.Timestamp < cutoff);
            foreach (var key in _firedComposites.Keys
                .Where(k => _firedComposites[k] < cutoff).ToList())
                _firedComposites.Remove(key);
        }
    }

    public bool IsEmpty
    {
        get { lock (_lock) { return _signals.Count == 0; } }
    }
}


