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
/// Example correlations:
///   - Unsigned binary + outbound C2 port within 60s → "Staged payload phoning home"
///   - AMSI bypass + encoded PowerShell + network connection → "Fileless attack chain"
///   - Recon commands (whoami, net user, ipconfig) × 3 within 120s → "Post-exploitation recon"
///   - Shadow copy delete + bulk file rename → "Active ransomware" (near-certain)
///   - ThreatIntel injection + C2 port → "Injected C2 beacon"
///   - High entropy binary + unsigned + staging path + network → "Dropped payload executing"
/// </summary>
public sealed class BehavioralCorrelationEngine : IAsyncDisposable
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<BehavioralCorrelationEngine> _logger;

    // Signal buffer: key = ProcessId (0 = host-level), value = list of recent signals
    private readonly ConcurrentDictionary<int, SignalBuffer> _buffers = new();

    // Correlation window — signals older than this are ignored
    private static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(120);

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
                     ?? EvaluateDroppedPayloadPhoneHome(recent, scopePid)
                     ?? EvaluatePostExploitRecon(recent, scopePid)
                     ?? EvaluateInjectedC2Beacon(recent, scopePid)
                     ?? EvaluateLsassWithNetwork(recent, scopePid)
                     // v1.1.0 — composites using new anti-APT monitors
                     ?? EvaluatePpidSpoofWithC2(recent, scopePid)
                     ?? EvaluateDbghelpWithLsass(recent, scopePid)
                     ?? EvaluateTokenEscalationWithPersistence(recent, scopePid)
                     ?? EvaluateDgaWithBeaconing(recent, scopePid)
                     ?? EvaluateCredentialCanaryWithNetwork(recent, scopePid)
                     ?? EvaluateFullAttackChain(recent, scopePid)
                     // v1.3.0 — aggressive anchor-based composites
                     ?? EvaluatePpidSpoofWithAnyNetwork(recent, scopePid)
                     ?? EvaluateDbghelpWithAnyNetwork(recent, scopePid)
                     ?? EvaluateTempBinaryWithNonStandardPort(recent, scopePid)
                     ?? EvaluateBulkFileWriteWithDns(recent, scopePid)
                     ?? EvaluateTokenEscalationWithAnyNetwork(recent, scopePid)
                     ?? EvaluateInjectionApiWithFileWrite(recent, scopePid)
                     ?? EvaluateDgaWithAnyFileAccess(recent, scopePid)
                     ?? EvaluateMemoryAnomalyWithNetwork(recent, scopePid)
                     // v1.4.0 — clipboard exfiltration composite
                     ?? EvaluateClipboardWithNetwork(recent, scopePid)
                     // v1.4.0 — module injection composites
                     ?? EvaluateModuleInjectionWithNetwork(recent, scopePid)
                     ?? EvaluateModuleInjectionWithClipboard(recent, scopePid)
                     // v1.5.0 — screen capture & overlay composites
                     ?? EvaluateScreenCaptureWithNetwork(recent, scopePid)
                     ?? EvaluateScreenCaptureWithClipboard(recent, scopePid)
                     ?? EvaluateOverlayWithInjection(recent, scopePid)
                     ?? EvaluateFullSurveillanceSuite(recent, scopePid)
                     // v1.6.0 — webcam/mic exfiltration composites
                     ?? EvaluateWebcamMicWithNetwork(recent, scopePid)
                     ?? EvaluateWebcamMicWithScreenCapture(recent, scopePid);

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
    /// Unsigned binary in staging path + outbound C2 port = dropped payload phoning home.
    /// </summary>
    private static DetectionEvent? EvaluateDroppedPayloadPhoneHome(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasUnsignedStaged = signals.Any(s =>
            s.RuleName.Contains("Unsigned") &&
            s.Metadata.GetValueOrDefault("InStagingPath", "False") == "True");

        bool hasHighEntropy = signals.Any(s => s.RuleName.Contains("Entropy"));

        bool hasC2Network = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") &&
            s.Metadata.ContainsKey("RemotePort"));

        if ((!hasUnsignedStaged && !hasHighEntropy) || !hasC2Network) return null;

        return MakeComposite(
            "Dropped Payload Phoning Home [COMPOSITE]",
            "Unsigned/high-entropy binary from staging path followed by C2 network connection. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A binary was dropped to a staging path (Temp/AppData), executed, and immediately " +
            "established a connection to a known C2 port. This is the standard dropper→beacon " +
            "sequence used by commodity malware and APT initial access tooling.",
            0.93,
            scopePid,
            signals.Last().Timestamp);
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
    /// Kernel-observed injection (ThreatIntel ETW) + C2 network port = injected C2 beacon.
    /// This is the highest-confidence composite — kernel evidence + network evidence.
    /// </summary>
    private static DetectionEvent? EvaluateInjectedC2Beacon(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasKernelInjection = signals.Any(s =>
            s.RuleName.Contains("ThreatIntel") || s.RuleName.Contains("Kernel-Observed"));

        bool hasC2Network = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") &&
            s.Metadata.ContainsKey("RemotePort"));

        if (!hasKernelInjection || !hasC2Network) return null;

        return MakeComposite(
            "Injected C2 Beacon [COMPOSITE]",
            "Kernel-observed process injection followed by C2 network activity. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "The kernel observed injection APIs (VirtualAllocEx/MapViewOfSection/APC) AND " +
            "a C2 network connection was established. This is the Cobalt Strike / Metasploit " +
            "meterpreter / Sliver beacon pattern: inject shellcode into a legitimate process, " +
            "then beacon out. Near-certain compromise.",
            0.98,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// LSASS credential dump attempt + outbound network = credentials being exfiltrated.
    /// </summary>
    private static DetectionEvent? EvaluateLsassWithNetwork(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasLsass = signals.Any(s => s.RuleName.Contains("LSASS"));
        bool hasNetwork = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") &&
            s.Metadata.ContainsKey("RemotePort"));

        if (!hasLsass || !hasNetwork) return null;

        return MakeComposite(
            "Credential Dump + Exfiltration [COMPOSITE]",
            "LSASS credential dump attempt followed by outbound network connection. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "Credential dumping (Mimikatz/procdump) combined with an active C2 channel " +
            "indicates credentials are being harvested and exfiltrated. " +
            "This is the standard lateral movement preparation sequence.",
            0.96,
            scopePid,
            signals.Last().Timestamp);
    }

    // ── v1.1.0 Correlation Rules (using new anti-APT monitors) ────────────────

    /// <summary>
    /// Parent PID spoofing + C2 network connection = Cobalt Strike / advanced C2 beacon.
    /// PPID spoofing is the default behavior of Cobalt Strike's spawn command.
    /// </summary>
    private static DetectionEvent? EvaluatePpidSpoofWithC2(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasPpidSpoof = signals.Any(s => s.RuleName.Contains("Parent PID Spoofing"));
        bool hasC2 = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") ||
            s.RuleName.Contains("Beacon") ||
            (s.Metadata.ContainsKey("RemotePort") && s.RuleName.Contains("Network")));

        if (!hasPpidSpoof || !hasC2) return null;

        return MakeComposite(
            "PPID Spoof + C2 Channel [COMPOSITE]",
            "Process spoofed its parent PID AND established a C2 network connection. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "Parent PID spoofing combined with C2 network activity is the signature behavior " +
            "of Cobalt Strike, Sliver, and Brute Ratel. The attacker spawned a beacon process " +
            "with a fake parent (typically explorer.exe or svchost.exe) to blend in, then " +
            "established a command-and-control channel.",
            0.96,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// dbghelp.dll loaded + LSASS-targeting signal = confirmed credential dump in progress.
    /// dbghelp is the prerequisite for MiniDumpWriteDump; combined with LSASS targeting = certain.
    /// </summary>
    private static DetectionEvent? EvaluateDbghelpWithLsass(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasDbghelp = signals.Any(s => s.RuleName.Contains("dbghelp"));
        bool hasLsass = signals.Any(s => s.RuleName.Contains("LSASS") || s.RuleName.Contains("Credential"));

        if (!hasDbghelp || !hasLsass) return null;

        return MakeComposite(
            "Confirmed LSASS Dump (dbghelp + targeting) [COMPOSITE]",
            "Process loaded dbghelp.dll AND shows LSASS-targeting behavior. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "dbghelp.dll contains MiniDumpWriteDump — the function used by all credential " +
            "dumping tools. Combined with LSASS-targeting command-line patterns, this confirms " +
            "an active credential dump regardless of what the tool is named or how it was built.",
            0.97,
            scopePid,
            signals.Last().Timestamp);
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
    /// DGA DNS resolution + statistical beaconing = confirmed C2 over generated domains.
    /// High-entropy domains + periodic connections = DGA-based malware phoning home.
    /// </summary>
    private static DetectionEvent? EvaluateDgaWithBeaconing(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasDga = signals.Any(s => s.RuleName.Contains("DGA") || s.RuleName.Contains("DNS"));
        bool hasBeaconing = signals.Any(s => s.RuleName.Contains("Beacon"));

        if (!hasDga || !hasBeaconing) return null;

        return MakeComposite(
            "DGA + C2 Beaconing [COMPOSITE]",
            "Process resolving high-entropy (DGA) domains AND showing periodic beacon pattern. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "Domain Generation Algorithms combined with statistical beaconing confirms an active " +
            "C2 channel using generated domains. The malware is cycling through algorithmically " +
            "generated domain names and successfully establishing periodic callbacks. " +
            "Families: Conficker, Necurs, Emotet, TrickBot, and custom APT implants.",
            0.95,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// Credential canary tripped + outbound network = credentials being exfiltrated.
    /// Someone harvested credentials AND data is leaving the machine.
    /// </summary>
    private static DetectionEvent? EvaluateCredentialCanaryWithNetwork(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasCanary = signals.Any(s => s.RuleName.Contains("Credential Canary"));
        bool hasNetwork = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") ||
            s.RuleName.Contains("Beacon") ||
            s.Metadata.ContainsKey("RemotePort"));

        if (!hasCanary || !hasNetwork) return null;

        return MakeComposite(
            "Credential Theft + Exfiltration [COMPOSITE]",
            "Credential canary was tripped AND outbound network activity detected. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "The honeypot credential was accessed (indicating active credential harvesting) " +
            "and network connections are active on the same timeline. Stolen credentials are " +
            "likely being exfiltrated to an attacker-controlled server.",
            0.97,
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

    // ── v1.3.0 Aggressive Anchor-Based Composites ─────────────────────────────
    // Philosophy: if a process is ALREADY suspicious (spoofed parent, loaded dump
    // tools, came from temp, has DGA DNS, has memory anomalies), then ANY additional
    // activity becomes the kill trigger. The anchor signal establishes suspicion;
    // the second signal confirms hostile intent.

    /// <summary>
    /// PPID-spoofed process + ANY network activity = kill.
    /// Rationale: legitimate processes never spoof their parent. If it's also talking
    /// to the network, it's a C2 beacon regardless of what port it uses.
    /// </summary>
    private static DetectionEvent? EvaluatePpidSpoofWithAnyNetwork(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasPpidSpoof = signals.Any(s => s.RuleName.Contains("Parent PID Spoofing"));
        bool hasAnyNetwork = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") ||
            s.RuleName.Contains("Beacon") ||
            s.RuleName.Contains("Network") ||
            s.Metadata.ContainsKey("RemotePort") ||
            s.Metadata.ContainsKey("remote_port"));

        if (!hasPpidSpoof || !hasAnyNetwork) return null;

        return MakeComposite(
            "Spoofed Process Phoning Home [COMPOSITE]",
            "PPID-spoofed process established network connection. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process with a spoofed parent PID is communicating over the network. " +
            "Legitimate Windows processes never disagree on parent PID. Any network activity " +
            "from a spoofed process confirms it is a C2 implant regardless of destination port.",
            0.95,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// Process that loaded dbghelp.dll + ANY outbound connection = kill.
    /// Rationale: if you loaded the dump library and you're talking to the network,
    /// you're exfiltrating credentials. No legitimate app does both.
    /// </summary>
    private static DetectionEvent? EvaluateDbghelpWithAnyNetwork(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasDbghelp = signals.Any(s => s.RuleName.Contains("dbghelp"));
        bool hasAnyNetwork = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") ||
            s.RuleName.Contains("Beacon") ||
            s.RuleName.Contains("Network") ||
            s.Metadata.ContainsKey("RemotePort") ||
            s.Metadata.ContainsKey("remote_port"));

        if (!hasDbghelp || !hasAnyNetwork) return null;

        return MakeComposite(
            "Dump Tool + Network Exfil [COMPOSITE]",
            "Process loaded dbghelp.dll AND has outbound network activity. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A non-debugger process loaded dbghelp.dll (required for MiniDumpWriteDump) and is " +
            "communicating over the network. This is the credential dump + exfiltration pattern " +
            "regardless of what port or protocol is used.",
            0.94,
            scopePid,
            signals.Last().Timestamp);
    }

    /// <summary>
    /// Unsigned binary from temp/staging path + connection to non-standard port = kill.
    /// Rationale: legitimate software doesn't run from Temp and connect to weird ports.
    /// </summary>
    private static DetectionEvent? EvaluateTempBinaryWithNonStandardPort(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasUnsignedStaged = signals.Any(s =>
            (s.RuleName.Contains("Unsigned") || s.RuleName.Contains("Entropy")) &&
            (s.Metadata.GetValueOrDefault("InStagingPath", "False") == "True" ||
             s.Metadata.GetValueOrDefault("image_path", "").Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
             s.Metadata.GetValueOrDefault("image_path", "").Contains("\\AppData\\", StringComparison.OrdinalIgnoreCase)));

        bool hasNonStandardNetwork = signals.Any(s =>
        {
            if (!s.Metadata.TryGetValue("RemotePort", out var portStr)) return false;
            if (!int.TryParse(portStr, out var port)) return false;
            // Standard ports that legitimate software uses
            return port != 80 && port != 443 && port != 8080 && port != 8443 && port != 53;
        });

        if (!hasUnsignedStaged || !hasNonStandardNetwork) return null;

        return MakeComposite(
            "Staged Payload + Non-Standard Port [COMPOSITE]",
            "Unsigned binary from staging path connected to non-standard port. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "An unsigned or high-entropy binary running from a temporary/staging location " +
            "(Temp, AppData) established a connection to a non-standard port. Legitimate " +
            "software uses standard ports (80/443). This is the classic dropper→beacon pattern.",
            0.92,
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
    /// Token escalation + ANY network activity = kill.
    /// Rationale: if you just escalated privileges and immediately hit the network,
    /// you're an attacker establishing a privileged C2 channel.
    /// </summary>
    private static DetectionEvent? EvaluateTokenEscalationWithAnyNetwork(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasEscalation = signals.Any(s =>
            s.RuleName.Contains("Token Integrity") || s.RuleName.Contains("Privilege Escalation"));
        bool hasAnyNetwork = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") ||
            s.RuleName.Contains("Beacon") ||
            s.RuleName.Contains("Network") ||
            s.Metadata.ContainsKey("RemotePort") ||
            s.Metadata.ContainsKey("remote_port"));

        if (!hasEscalation || !hasAnyNetwork) return null;

        return MakeComposite(
            "Privilege Escalation + Network Activity [COMPOSITE]",
            "Process escalated privileges AND established network connection. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process that escalated its token integrity (bypassed UAC or manipulated tokens) " +
            "is now communicating over the network. Legitimate elevation doesn't immediately " +
            "phone home. This is an attacker establishing a privileged reverse shell.",
            0.94,
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
    /// Memory anomaly (RWX/shellcode/unbacked) + ANY network = kill.
    /// Rationale: if your memory looks like shellcode and you're talking to the network,
    /// you're an in-memory implant beaconing out.
    /// </summary>
    private static DetectionEvent? EvaluateMemoryAnomalyWithNetwork(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasMemoryAnomaly = signals.Any(s =>
            s.RuleName.Contains("Memory Behavior") ||
            s.RuleName.Contains("Memory Execution") ||
            s.Metadata.ContainsKey("memory_kind") ||
            s.Metadata.ContainsKey("rwx_regions"));
        bool hasAnyNetwork = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") ||
            s.RuleName.Contains("Beacon") ||
            s.RuleName.Contains("Network") ||
            s.Metadata.ContainsKey("RemotePort") ||
            s.Metadata.ContainsKey("remote_port"));

        if (!hasMemoryAnomaly || !hasAnyNetwork) return null;

        return MakeComposite(
            "In-Memory Implant + Network Beacon [COMPOSITE]",
            "Process with suspicious memory (RWX/shellcode/unbacked) AND network activity. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process with shellcode-like memory patterns (RWX regions, unbacked executable " +
            "memory, shellcode prologues) is communicating over the network. This is the " +
            "definitive in-memory implant pattern: injected shellcode beaconing to C2. " +
            "Cobalt Strike, Metasploit meterpreter, Sliver, and custom implants all exhibit this.",
            0.96,
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
    /// v1.4.0 — Module injection + network = injected C2 implant.
    /// A process that received a suspicious DLL injection AND is making network connections
    /// is almost certainly running an injected C2 beacon (Cobalt Strike, Sliver, etc.).
    /// </summary>
    private static DetectionEvent? EvaluateModuleInjectionWithNetwork(
        IReadOnlyList<Signal> signals, int scopePid)
    {
        bool hasModuleInjection = signals.Any(s =>
            s.RuleName.Contains("Module Integrity") ||
            s.RuleName.Contains("DLL Injection") ||
            s.RuleName.Contains("Phantom Module") ||
            (s.Metadata.ContainsKey("technique") &&
             s.Metadata["technique"].Contains("T1055")));
        bool hasNetwork = signals.Any(s =>
            s.RuleName.Contains("Reverse Shell") ||
            s.RuleName.Contains("Beacon") ||
            s.RuleName.Contains("Network") ||
            s.Metadata.ContainsKey("RemotePort") ||
            s.Metadata.ContainsKey("remote_port"));

        if (!hasModuleInjection || !hasNetwork) return null;

        return MakeComposite(
            "Injected Implant + Network C2 [COMPOSITE]",
            "Process received suspicious DLL injection AND has outbound network activity. " +
            $"Signals: {string.Join(", ", signals.Select(s => s.RuleName).Distinct())}",
            "A process that had a suspicious module injected at runtime is now communicating " +
            "over the network. This is the canonical injected-implant pattern: attacker injects " +
            "a DLL (via CreateRemoteThread, manual mapping, reflective loading) and the injected " +
            "code establishes a C2 channel. Cobalt Strike, Sliver, Brute Ratel, and custom " +
            "implants all follow this exact sequence.",
            0.95,
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

    // ── Helpers ───────────────────────────────────────────────────────────────

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
                await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
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
        lock (_lock) { _signals.Add(signal); }
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
