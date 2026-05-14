using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Deception;
using WindowsSentinel.Core.Detection.Rules;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Hardening;
using WindowsSentinel.Core.Health;
using WindowsSentinel.Core.Hid;
using WindowsSentinel.Core.Honeypot;
using WindowsSentinel.Core.IncidentResponse;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Jobs;
using WindowsSentinel.Core.Logging;
using WindowsSentinel.Core.Monitors;
using WindowsSentinel.Core.Notifications;
using WindowsSentinel.Core.Quarantine;
using WindowsSentinel.Core.Response;
using WindowsSentinel.Core.SelfProtection;
using WindowsSentinel.Core.Session;

namespace WindowsSentinel.Core;

/// <summary>
/// Sentinel version information
/// </summary>
public static class SentinelVersion
{
    /// <summary>
    /// Current version - 1.7.0 Aggressive Deception Engine
    /// </summary>
    public const string Version = "1.7.0";

    /// <summary>
    /// Release date
    /// </summary>
    public static readonly DateTime ReleaseDate = new(2026, 5, 14);

    /// <summary>
    /// Version description
    /// </summary>
    public const string Description =
        "1.7.0 — Aggressive Deception Engine. " +
        "New DeceptionEngine executes attacker-hostile tactics BEFORE process kill: " +
        "memory flooding (pollute crash dumps), DLL stomping (crash on restart), " +
        "beacon flooding (pollute C2 console), clipboard poisoning (fake credentials), " +
        "sparse file bombs (exhaust exfil bandwidth), symlink loops (crash recursive tools), " +
        "environment poisoning (break reconnection), honeypot weaponization (expose attacker infra). " +
        "All tactics operate on own system against confirmed intruders. " +
        "2-second time budget ensures kill is never delayed. " +
        "Total composites: 30.";
}

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers all Windows Sentinel services with the DI container.
    /// </summary>
    public static IServiceCollection AddWindowsSentinel(
        this IServiceCollection services,
        string? logPath = null,
        bool activeResponseEnabled = true,   // Default ON — Sentinel ships in killing mode
        string? watchPath = null)
    {
        logPath = string.IsNullOrWhiteSpace(logPath) ? null : logPath;

        logPath ??= Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WindowsSentinel", "events.jsonl");

        // ── Detection rules — Tier1 ──────────────────────────────────────────
        services.AddSingleton<IDetectionRule, LsassAccessRule>();
        services.AddSingleton<IDetectionRule, ReverseShellRule>();
        services.AddSingleton<IDetectionRule, ProcessInjectionRule>();
        services.AddSingleton<IDetectionRule, RansomwareDetectionRule>(); // Unified (merged RansomwareActivity + RansomwareBehavior)
        services.AddSingleton<IDetectionRule, EtwTamperingRule>();
        services.AddSingleton<IDetectionRule, ThreatIntelInjectionRule>(); // kernel-observed injection
        services.AddSingleton<IDetectionRule, BeaconingRule>();            // statistical C2 beaconing
        services.AddSingleton<IDetectionRule, HollowProcessRule>();        // process hollowing
        services.AddSingleton<IDetectionRule, PersistenceRule>();        // persistence mechanisms
        services.AddSingleton<IDetectionRule, PrivilegeEscalationRule>(); // privilege escalation
        services.AddSingleton<IDetectionRule, AttackToolsRule>();        // known attack tools
        services.AddSingleton<IDetectionRule, CampaignIocRule>();        // campaign IOCs
        services.AddSingleton<IDetectionRule, CampaignDetectionRule>();    // DragonBreathHunter - APT campaigns

        // ── Detection rules — Tier2 (log only) ──────────────────────────────
        services.AddSingleton<IDetectionRule, UnsignedBinaryRule>();
        services.AddSingleton<IDetectionRule, HighEntropyRule>();
        services.AddSingleton<IDetectionRule, SuspiciousImportsRule>();

        // ── 0.4.0 — IoC scanner rule (process-start hash matching) ──────────
        services.AddSingleton<IoCScanner>();
        services.AddSingleton<IDetectionRule, IoCScannerRule>();

        // ── 0.4.0 — GIDR-ported detection rules (hardened) ───────────────────
        services.AddSingleton<IDetectionRule, AudioHijackRule>();           // Audio output to mic detection
        services.AddSingleton<IDetectionRule, MemoryExecutionRule>();       // Fileless malware detection
        services.AddSingleton<IDetectionRule, ModuleValidationRule>();      // DLL hijacking/sideloading detection
        services.AddSingleton<UserProtectionRule>();
        services.AddSingleton<IDetectionRule>(sp => sp.GetRequiredService<UserProtectionRule>());
        // NOTE: RansomwareBehaviorRule merged into RansomwareDetectionRule

        // ── 0.4.0 — Free API-based hash reputation service ────────────────────
        services.AddSingleton<HashReputationService>();                      // CIRCL, Cymru, MalwareBazaar APIs
        services.AddSingleton<IDetectionRule, HashReputationRule>();       // Hash reputation checking
        services.AddSingleton<IDetectionRule, FileEntropyRule>();          // Packed/encrypted file detection
        services.AddSingleton<IDetectionRule, CertificateTamperingRule>(); // Certificate store tampering detection

        // ── Detection engine ─────────────────────────────────────────────────
        services.AddSingleton<IDetectionEngine, DetectionEngine>();

        // ── Process ancestry cache (shared by monitors and rules) ────────────
        services.AddSingleton<ProcessAncestryCache>();

        // ── Behavioral correlation engine ────────────────────────────────────
        services.AddSingleton<BehavioralCorrelationEngine>();

        // ═══════════════════════════════════════════════════════════════════════
        // 1.0.0 — TELEMETRY FUSION & EVENT GRAPHING
        // ═══════════════════════════════════════════════════════════════════════

        // ── Event Graph (in-memory process/file/network graph) ────────────────
        services.AddSingleton<EventGraph>();

        // ── Telemetry Fusion Engine (unified event chains) ────────────────────
        services.AddSingleton<TelemetryFusionEngine>();
        services.AddHostedService(sp => sp.GetRequiredService<TelemetryFusionEngine>());

        // ── Memory Behavior Analyzer (RWX scanning, shellcode detection) ──────
        services.AddHostedService<MemoryBehaviorAnalyzer>();

        // ═══════════════════════════════════════════════════════════════════════

        // ── Beaconing detector ───────────────────────────────────────────────
        services.AddSingleton<BeaconingDetector>();

        // ── Scoring Engine ───────────────────────────────────────────────────
        services.AddSingleton<ScoringEngine>();

        // ── YARA Engine ────────────────────────────────────────────────────────
        services.AddSingleton<YaraEngine>();

        // ═══════════════════════════════════════════════════════════════════════
        // PORTED FROM HYDRADRAGONANTIVIRUS - SECURITY ANALYSIS ENGINES
        // ═══════════════════════════════════════════════════════════════════════

        // ── PE Analyzer ────────────────────────────────────────────────────────
        // Ported from Hydra's pe_feature_extractor.py
        // Performs static PE analysis: entropy calculation, import/export analysis,
        // section analysis, and suspicious indicator detection
        services.AddSingleton<PEAnalyzer>();

        // ── Process Validator ───────────────────────────────────────────────────
        // SECURITY FIX: Validates process names to prevent Unicode spoofing,
        // homoglyph attacks, and path traversal in process identifiers
        services.AddSingleton<ProcessValidator>();

        // ── ClamAV Engine ───────────────────────────────────────────────────────
        // Ported from Hydra's antivirus integration
        // CLI-based virus scanning using ClamAV signatures
        services.AddSingleton<ClamAVEngine>();

        // ── YARA-X Engine ────────────────────────────────────────────────────────
        // Modern YARA (Rust rewrite) with better performance
        // Ported from Hydra's YARA-X integration pattern
        services.AddSingleton<YaraXEngine>();

        // ═══════════════════════════════════════════════════════════════════════

        // ── Chain Tracer ───────────────────────────────────────────────────────
        services.AddSingleton<ChainTracer>();

        // ── PseudoSandbox ─────────────────────────────────────────────────────
        services.AddSingleton<PseudoSandbox>();

        // ── MITRE Mapper ───────────────────────────────────────────────────────
        services.AddSingleton<MitreMapper>();

        // ── Quarantine Manager ────────────────────────────────────────────────
        services.AddSingleton<QuarantineManager>();

        // ── Incident Response ──────────────────────────────────────────────────
        services.AddSingleton<IncidentResponseService>();

        // ── Detection Job Scheduler ────────────────────────────────────────────
        services.AddHostedService<DetectionJobScheduler>();

        // ── Self-Protection Service ────────────────────────────────────────────
        services.AddHostedService<SelfProtectionService>();
        services.AddHostedService<ServiceProtectionMonitor>(); // CRITICAL: Service/registry tamper protection

        // ── Hardening Module ───────────────────────────────────────────────────
        services.AddHostedService<HardeningModule>();

        // ── Health Check Service ──────────────────────────────────────────────
        services.AddHostedService<HealthCheckService>();

        // ── Heartbeat Service ───────────────────────────────────────────────────
        services.AddSingleton<HeartbeatService>();
        services.AddHostedService(sp => sp.GetRequiredService<HeartbeatService>());

        // ═══════════════════════════════════════════════════════════════════════
        // ANTIVIRUS PROJECT INTEGRATION
        // ═══════════════════════════════════════════════════════════════════════

        // ── Smart Scoring & Analysis ────────────────────────────────────────────
        services.AddSingleton<AkinatorEngine>();           // Contextual heuristic scoring
        services.AddSingleton<BehavioralBaselineService>(); // Learn normal behavior
        services.AddSingleton<FalsePositiveTracker>();      // Self-improving FP reduction
        services.AddSingleton<AllowlistService>();           // Proactive allowlist (vendor trust + dev tools + user)
        services.AddSingleton<ContextualAnalysisEngine>();  // Installer/update context detection
        services.AddSingleton<ReputationCache>();          // 5-tier reputation system
        services.AddSingleton<NeuroBehaviorMonitor>();      // Advanced behavioral analysis

        // ── Resilience ──────────────────────────────────────────────────────────
        services.AddSingleton<CircuitBreaker>();           // API failure handling

        // ── Notifications ────────────────────────────────────────────────────────
        services.AddSingleton<ToastNotificationService>(); // Windows toast notifications

        // ── Advanced Detection ───────────────────────────────────────────────────
        services.AddSingleton<HeadersCheckEngine>();         // File header analysis
        services.AddSingleton<CrudePayloadGuard>();        // Simple payload detection
        services.AddSingleton<ElfCatcher>();                 // ELF/WSL abuse detection
        services.AddSingleton<ShadowProxyDetector>();      // Proxy manipulation detection
        services.AddHostedService<ShadowProxyDetector>();   // Run as background service

        // ── Council of Elders — Consultant Signal Ingestor ───────────────────
        services.AddHostedService<ConsultantSignalIngestor>(); // Tails PS consultant JSONL drops

        // ── Honeypot & HID ─────────────────────────────────────────────────────
        services.AddSingleton<HoneypotMonitor>();            // Decoy file monitoring
        services.AddHostedService<HoneypotMonitor>();         // Run as background service
        services.AddSingleton<HIDMacroGuard>();              // USB injection detection
        services.AddHostedService<HIDMacroGuard>();          // Run as background service

        // ═══════════════════════════════════════════════════════════════════════
        // 1.7.0 — AGGRESSIVE DECEPTION ENGINE
        // ═══════════════════════════════════════════════════════════════════════
        services.AddSingleton<MemoryFloodingTactic>();
        services.AddSingleton<FileTrapTactic>();
        services.AddSingleton<ClipboardPoisonTactic>();
        services.AddSingleton<ImplantDestabilizer>();
        services.AddSingleton<BeaconFlooder>();
        services.AddSingleton<EnvironmentPoisoner>();
        services.AddSingleton<HoneypotWeaponizer>();
        services.AddSingleton<NetworkHoneypotDeployer>();
        services.AddSingleton<IDeceptionEngine, DeceptionEngine>();

        // ═══════════════════════════════════════════════════════════════════════

        // ── Graceful Shutdown ──────────────────────────────────────────────────
        services.AddHostedService<SentinelGracefulShutdown>();

        // ── Event logger ─────────────────────────────────────────────────────
        services.AddSingleton<IEventLogger>(sp =>
            new JsonlEventLogger(logPath, sp.GetRequiredService<ILogger<JsonlEventLogger>>()));

        // ── Response engine (with full Antivirus integration) ────────────────
        services.AddSingleton<IResponseEngine>(sp =>
            new AdvancedResponseEngine(
                sp.GetRequiredService<IEventLogger>(),
                sp.GetRequiredService<ILogger<AdvancedResponseEngine>>(),
                sp.GetRequiredService<ScoringEngine>(),
                sp.GetRequiredService<ChainTracer>(),
                sp.GetRequiredService<IncidentResponseService>(),
                sp.GetRequiredService<HeartbeatService>(),
                sp.GetRequiredService<QuarantineManager>(),
                sp.GetRequiredService<AkinatorEngine>(),           // Smart scoring
                sp.GetRequiredService<ContextualAnalysisEngine>(),  // Context awareness
                sp.GetRequiredService<FalsePositiveTracker>(),      // FP reduction
                sp.GetRequiredService<BehavioralBaselineService>(), // Baseline learning
                sp.GetRequiredService<ReputationCache>(),          // File reputation
                sp.GetRequiredService<ToastNotificationService>(), // Notifications
                sp.GetRequiredService<IDeceptionEngine>(),        // Pre-kill deception (v1.7.0)
                activeResponseEnabled));

        // ── Monitors ─────────────────────────────────────────────────────────
        services.AddSingleton<IMonitor>(sp => new EtwProcessMonitor(
            sp.GetRequiredService<IDetectionEngine>(),
            sp.GetRequiredService<ILogger<EtwProcessMonitor>>(),
            sp.GetRequiredService<ProcessAncestryCache>(),
            sp.GetRequiredService<TelemetryFusionEngine>(),
            sp.GetRequiredService<ParentPidSpoofDetector>()));
        services.AddSingleton<IMonitor, EtwThreatIntelMonitor>();   // kernel injection visibility
        services.AddSingleton<IMonitor, HollowProcessMonitor>();    // hollow process detection
        services.AddSingleton<IMonitor>(sp => new FileActivityMonitor(
            sp.GetRequiredService<IDetectionEngine>(),
            sp.GetRequiredService<ILogger<FileActivityMonitor>>(),
            watchPath,
            sp.GetRequiredService<TelemetryFusionEngine>()));
        services.AddSingleton<INetworkMonitor>(sp => new NetworkMonitor(
            sp.GetRequiredService<IDetectionEngine>(),
            sp.GetRequiredService<ILogger<NetworkMonitor>>(),
            sp.GetRequiredService<BeaconingDetector>(),
            sp.GetRequiredService<TelemetryFusionEngine>()));
        services.AddSingleton<IMonitor>(sp => sp.GetRequiredService<INetworkMonitor>());

        // ── 0.4.0 — Ports from GIDR (security-hardened) ──────────────────────
        services.AddHostedService<AudioHijackMonitor>();
        services.AddHostedService<RansomwareIoMonitor>();
        services.AddHostedService<MemoryExecutionMonitor>();
        services.AddHostedService<ModuleValidationMonitor>();

        // ═══════════════════════════════════════════════════════════════════════
        // 1.1.0 — ADVANCED ANTI-APT MONITORS
        // ═══════════════════════════════════════════════════════════════════════

        // ── DNS Query Monitor (DGA detection, DNS tunneling) ──────────────────
        services.AddSingleton<IMonitor, DnsQueryMonitor>();

        // ── Parent PID Spoof Detector ─────────────────────────────────────────
        services.AddSingleton<ParentPidSpoofDetector>();

        // ── Syscall Stub Integrity Monitor (ntdll unhooking detection) ─────────
        services.AddHostedService<SyscallStubMonitor>();

        // ── Credential Canary (honeypot credential in Credential Manager) ─────
        services.AddHostedService<CredentialCanaryMonitor>();

        // ── Token Integrity Monitor (privilege escalation detection) ───────────
        services.AddHostedService<TokenIntegrityMonitor>();

        // ── LSASS Dump Canary (dbghelp.dll load detection) ────────────────────
        services.AddHostedService<LsassDumpCanaryMonitor>();

        // ═══════════════════════════════════════════════════════════════════════
        // 1.4.0 — CLIPBOARD SECURITY MONITOR
        // ═══════════════════════════════════════════════════════════════════════

        // ── Clipboard Monitor (clipboard hijacking, scraping, exfiltration) ───
        services.AddHostedService<ClipboardMonitor>();

        // ── Runtime Module Integrity Monitor (injection, replacement, phantoms) ─
        services.AddHostedService<RuntimeModuleIntegrityMonitor>();

        // ═══════════════════════════════════════════════════════════════════════
        // 1.5.0 — SCREEN CAPTURE & OVERLAY MONITOR
        // ═══════════════════════════════════════════════════════════════════════

        // ── Screen Capture Monitor (DXGI capture, overlay phishing, background grabbers) ─
        services.AddHostedService<ScreenCaptureMonitor>();

        // ── Local Server Monitor (localhost listeners, mounted ISO/VHD attacks) ─
        services.AddHostedService<LocalServerMonitor>();

        // ═══════════════════════════════════════════════════════════════════════
        // 1.6.0 — WEBCAM & MICROPHONE EXFILTRATION MONITOR
        // ═══════════════════════════════════════════════════════════════════════

        // ── Webcam/Mic Monitor (background camera/mic access, exfiltration composites) ─
        services.AddHostedService<WebcamMicMonitor>();

        // ═══════════════════════════════════════════════════════════════════════

        // ── Main hosted service ──────────────────────────────────────────────
        services.AddHostedService<SentinelService>();

        // ── User Session Launcher (launches Agent into user session) ──────────
        services.AddHostedService<UserSessionLauncher>();

        return services;
    }
}
