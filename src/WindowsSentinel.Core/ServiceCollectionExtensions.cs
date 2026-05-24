using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.IO;
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
using WindowsSentinel.Core.Configuration;
using WindowsSentinel.Core.Security;
using WindowsSentinel.Core.Utilities;
using ThreatReportingConfig = WindowsSentinel.Core.Response.ThreatReportingConfig;

// 2.0.0 — Hardened & Portable (DLL Analysis, Active Response, Barebone Windows fallbacks)
// 2.1.0 — Community Threat Intelligence Reporting (AbuseIPDB, URLhaus, MalwareBazaar)
// 2.2.0 — Pre-Kill Validation Gate (prevents killing user-interactive processes)
// 2.3.0 — Mic Session Injection Detection (WASAPI capture session enumeration)
// 2.4.0 — ADS Staging Detection + Agent Architecture (user-session monitors moved to Agent)
// 2.5.0 — NeuroBehavior Visual Monitor + AudioHijack module-based detection
// 2.8.0 — Deception Refinements, Ransomware Fast-Path, Asynchronous Off-host Deception
// 2.8.1 — Architecture Hardening & Bug Fixes (version.txt managed)
// 3.0.0 — Security Hardening, Observability & Resilience
// 3.2.0 — Browser Credential Protection (Chrome/Google account theft prevention)
// 3.3.0 — Electron Allowlist & Work Folders Protection
// 3.4.0 — Active Response Expansion (RAT/Campaign kill, LSASS dump kill, host-level composite resolution)
// 3.5.0 — Behavioral RAT Kill (novel RAT composites, beaconing kill-authorized)

namespace WindowsSentinel.Core;

/// <summary>
/// Sentinel version information
/// </summary>
public static class SentinelVersion
{
    /// <summary>
    /// Current version - 3.6.0 Network Hijack Protection
    /// Version is managed in version.txt for consistency across build scripts
    /// </summary>
    public const string Version = "3.6.0";

    /// <summary>
    /// Release date
    /// </summary>
    public static readonly DateTime ReleaseDate = new(2026, 5, 24);

    /// <summary>
    /// Version description
    /// </summary>
    public const string Description =
        "3.6.0 — Full-Spectrum Protection. " +
        "Sentinel expands beyond IDS/EDR into comprehensive system protection. " +
        "Network Hijack Protection: ARP Spoof Monitor, Gateway Fingerprint Monitor, " +
        "Public IP Monitor (geo/ASN shift), Route Table Monitor, DNS Response Validation, " +
        "TLS Certificate Monitor (MITM detection). " +
        "Wireless Security: Wi-Fi Security Monitor (deauth flood, evil twin, encryption downgrade), " +
        "Bluetooth Monitor (BadBT HID injection, unauthorized pairing). " +
        "System Integrity: Secure Boot & Boot Integrity (firmware tampering, test signing, kernel debug), " +
        "Firewall Integrity Monitor (profile disabled, bulk rules, service stopped), " +
        "Scheduled Task Persistence Monitor (malicious task creation), " +
        "Windows Update Integrity (WU/BITS tampering, Defender definition staleness).";
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

        // ── Configuration Validation ───────────────────────────────────────────
        services.AddSingleton<IValidateOptions<ThreatReportingConfig>, ThreatReportingConfigValidator>();
        services.AddSingleton<ConfigurationValidationService>();
        services.AddSingleton<SentinelConfigurationValidator>();

        // ── Security & Utilities ───────────────────────────────────────────────
        // NOTE: SecurityValidation is a static utility class — no DI registration needed
        services.AddSingleton<RateLimiter>(sp => new RateLimiter(100, TimeSpan.FromSeconds(1))); // Global rate limiter
        services.AddSingleton<BurstRateLimiter>(sp => new BurstRateLimiter(
            sustainedRate: 10, 
            sustainedWindow: TimeSpan.FromSeconds(1),
            burstCapacity: 50,
            burstRechargeTime: TimeSpan.FromMinutes(1)));

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

        // ── Health Check Options ─────────────────────────────────────────────
        // NOTE: HealthCheckOptions configured via appsettings.json binding in Service host
        services.AddOptions<HealthCheckOptions>()
            .Validate(data =>
            {
                if (data.Port < 1 || data.Port > 65535)
                    throw new InvalidOperationException($"Health check port must be between 1 and 65535. Current value: {data.Port}");
                return true;
            }, "Invalid health check port configuration");

        // ── Log Rotation Options ─────────────────────────────────────────────
        // NOTE: LogRotationOptions configured via appsettings.json binding in Service host

        // ── 2.8.0 — Quick Wins (Anti-Evasion & Lateral Movement) ─────────────
        services.AddSingleton<IDetectionRule, FirewallTamperingRule>();
        services.AddSingleton<IDetectionRule, AccountManipulationRule>();
        services.AddSingleton<IDetectionRule, DataExfiltrationRule>();

        // ── 3.2.0 — Browser Credential Protection ───────────────────────────
        services.AddSingleton<IDetectionRule, BrowserCredentialTheftRule>();

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
        services.AddHostedService<ConfigIntegrityMonitor>();   // Configuration tampering detection

        // ── Hardening Module ───────────────────────────────────────────────────
        services.AddHostedService<HardeningModule>();

        // ── Health Check Service ──────────────────────────────────────────────
        services.AddHostedService<HealthCheckService>();
        services.AddSingleton<SentinelHealthCheck>();
        services.AddHostedService(sp => sp.GetRequiredService<SentinelHealthCheck>());

        // ── Startup Self-Test ──────────────────────────────────────────────────
        services.AddSingleton(sp => new StartupSelfTest(
            sp.GetRequiredService<ILogger<StartupSelfTest>>(),
            sp.GetRequiredService<IEnumerable<IDetectionRule>>(),
            logPath!));

        // ── Metrics ────────────────────────────────────────────────────────────
        services.AddSingleton<SentinelMetrics>();

        // ── Secure HTTP Client ─────────────────────────────────────────────────
        services.AddSingleton<SecureHttpClientFactory>();

        // ── Heartbeat Service ───────────────────────────────────────────────────
        services.AddSingleton<HeartbeatService>();
        services.AddHostedService(sp => sp.GetRequiredService<HeartbeatService>());

        // ═══════════════════════════════════════════════════════════════════════
        // ANTIVIRUS PROJECT INTEGRATION
        // ═══════════════════════════════════════════════════════════════════════

        // ── Smart Scoring & Analysis ────────────────────────────────────────────
        services.AddSingleton<AkinatorEngine>();           // Contextual heuristic scoring
        services.AddSingleton<BehavioralBaselineService>(); // Learn normal behavior
        services.AddHostedService(sp => sp.GetRequiredService<BehavioralBaselineService>()); // Run background learning loop
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
        services.AddHostedService(sp => sp.GetRequiredService<ShadowProxyDetector>());   // Run as background service

        // ── Threat Intelligence Reporter (v2.1.0) ──────────────────────────────
        services.AddSingleton<ThreatReportingConfig>();
        services.AddSingleton<ThreatIntelReporter>();
        services.AddHostedService(sp => sp.GetRequiredService<ThreatIntelReporter>());

        // ── Council of Elders — Consultant Signal Ingestor ───────────────────
        services.AddHostedService<ConsultantSignalIngestor>(); // Tails PS consultant JSONL drops

        // ── Honeypot & HID ─────────────────────────────────────────────────────
        services.AddSingleton<HoneypotMonitor>();            // Decoy file monitoring
        services.AddHostedService(sp => sp.GetRequiredService<HoneypotMonitor>());  // Run as background service
        services.AddSingleton<HIDMacroGuard>();              // USB injection detection
        services.AddHostedService(sp => sp.GetRequiredService<HIDMacroGuard>());    // Run as background service

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
                sp.GetRequiredService<SentinelMetrics>(),          // Observability metrics (v3.0.0)
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
                sp.GetRequiredService<ThreatIntelReporter>(),     // Community reporting (v2.1.0)
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
            sp.GetRequiredService<TelemetryFusionEngine>(),
            sp.GetRequiredService<ProcessAncestryCache>()));
        services.AddSingleton<IMonitor>(sp => sp.GetRequiredService<INetworkMonitor>());

        // ── Named Pipe Monitor (C2/lateral movement detection) ────────────────
        services.AddSingleton<IMonitor>(sp => new NamedPipeMonitor(
            sp.GetRequiredService<IDetectionEngine>(),
            sp.GetRequiredService<ILogger<NamedPipeMonitor>>(),
            sp.GetRequiredService<ProcessAncestryCache>()));

        // ── 0.4.0 — Ports from GIDR (security-hardened) ──────────────────────
        // NOTE: AudioHijackMonitor moved to Agent (v2.3.0 — requires user session)
        services.AddHostedService<RansomwareIoMonitor>();
        services.AddHostedService<MemoryExecutionMonitor>();
        services.AddHostedService<ModuleValidationMonitor>();

        // ── 2.8.0 — Canary File Monitor (Ransomware) ──────────────────────────
        services.AddHostedService<CanaryFileMonitor>();

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

        // ── WMI Event Subscription Persistence Monitor (T1546.003) ────────────
        services.AddHostedService<WmiPersistenceMonitor>();

        // ═══════════════════════════════════════════════════════════════════════
        // 1.4.0 — CLIPBOARD SECURITY MONITOR
        // ═══════════════════════════════════════════════════════════════════════

        // ── Clipboard Monitor — MOVED TO AGENT (v2.3.0 — requires user session for clipboard ownership) ─
        // services.AddHostedService<ClipboardMonitor>();

        // ── Runtime Module Integrity Monitor (injection, replacement, phantoms) ─
        services.AddHostedService<RuntimeModuleIntegrityMonitor>();

        // ═══════════════════════════════════════════════════════════════════════
        // 1.5.0 — SCREEN CAPTURE & OVERLAY MONITOR
        // ═══════════════════════════════════════════════════════════════════════

        // ── Screen Capture Monitor — MOVED TO AGENT (v2.3.0 — requires user session for window enumeration) ─
        // services.AddHostedService<ScreenCaptureMonitor>();

        // ── Local Server Monitor (localhost listeners, mounted ISO/VHD attacks) ─
        services.AddHostedService<LocalServerMonitor>();

        // ═══════════════════════════════════════════════════════════════════════
        // 1.6.0 — WEBCAM & MICROPHONE EXFILTRATION MONITOR
        // ═══════════════════════════════════════════════════════════════════════

        // ── Webcam/Mic Monitor — MOVED TO AGENT (v2.3.0 — requires user session) ─
        // services.AddHostedService<WebcamMicMonitor>();

        // ── Mic Session Monitor — MOVED TO AGENT (v2.3.0 — WASAPI requires user session) ─
        // services.AddHostedService<MicSessionMonitor>();

        // ── ADS Data Staging Monitor (v2.3.0 — detects large NTFS alternate data streams) ─
        services.AddHostedService<AdsDataStagingMonitor>();

        // ═══════════════════════════════════════════════════════════════════════
        // 1.8.0 — DATA EXFILTRATION PREVENTION
        // ═══════════════════════════════════════════════════════════════════════

        // ── Data Exfiltration Monitor (outbound volume, sensitive file access, USB reads) ─
        services.AddHostedService<DataExfiltrationMonitor>();

        // ═══════════════════════════════════════════════════════════════════════
        // 2.0.0 — DLL ANALYSIS & ACTIVE RESPONSE (ported from Antivirus.ps1)
        // ═══════════════════════════════════════════════════════════════════════

        // ── DLL Unload Engine (active response: FreeLibrary via CreateRemoteThread) ─
        services.AddSingleton<DllUnloadEngine>();

        // NOTE: ThreatIntelReporter already registered above (v2.1.0 section)

        // ── UAC Bypass Surface Monitor (COM AutoElevation, manifest autoElevate, copy-drop) ─
        services.AddHostedService<UacBypassSurfaceMonitor>();

        // ── DLL Entropy Analyzer (Shannon entropy, hex-named DLL detection, packed/encrypted) ─
        services.AddHostedService<DllEntropyAnalyzer>();

        // ── DLL Load Failure Monitor (Event Log ID 7, SideBySide errors) ─
        services.AddHostedService<DllLoadFailureMonitor>();

        // ── Browser DLL Monitor / ELF Catcher (browser-specific injection detection + unload) ─
        services.AddHostedService<BrowserDllMonitor>();

        // ═══════════════════════════════════════════════════════════════════════
        // 3.2.0 — BROWSER & ACCOUNT CREDENTIAL PROTECTION
        // ═══════════════════════════════════════════════════════════════════════

        // ── Chrome/Chromium Credential Guard (Login Data, Cookies, Local State file access monitoring) ─
        services.AddHostedService<ChromeCredentialGuardMonitor>();

        // ── Firefox/Gecko Credential Guard (key4.db, logins.json, cookies.sqlite monitoring) ─
        services.AddHostedService<FirefoxCredentialGuardMonitor>();

        // ── Microsoft Account Guard (WAM tokens, PRT, TokenBroker cache, Azure AD) ─
        services.AddHostedService<MicrosoftAccountGuardMonitor>();

        // ── Browser Extension Monitor (malicious extension installation detection) ─
        services.AddHostedService<BrowserExtensionMonitor>();

        // ── Chrome Session Guard (remote debugging, CDP hijack, App-Bound Encryption bypass) ─
        services.AddHostedService<ChromeSessionGuardMonitor>();

        // ── PowerShell Threat Monitor (script-block logging, encoded commands, AMSI bypass) ─
        services.AddHostedService<PowerShellThreatMonitor>();

        // ── Work Folders Exfiltration Monitor (unauthorized sync/exfil detection + kill) ─
        services.AddHostedService<WorkFoldersExfilMonitor>();

        // ── Disk-Wide DLL Scanner (all drives, unsigned DLL detection, IoC matching + unload) ─
        services.AddHostedService<DiskWideDllScanner>();

        // ═══════════════════════════════════════════════════════════════════════
        // 3.6.0 — NETWORK HIJACK PROTECTION
        // ═══════════════════════════════════════════════════════════════════════

        // ── ARP Spoof Monitor (gateway MAC change, ARP table poisoning) ──────
        services.AddHostedService<ArpSpoofMonitor>();

        // ── Gateway Fingerprint Monitor (evil twin, rogue DHCP, DNS hijack) ──
        services.AddHostedService<GatewayFingerprintMonitor>();

        // ── Public IP Monitor (VPN hijack, BGP manipulation, geo shift) ──────
        services.AddHostedService<PublicIpMonitor>();

        // ── Route Table Monitor (static route injection, selective redirect) ──
        services.AddHostedService<RouteTableMonitor>();

        // ── DNS Response Validation (DNS poisoning, captive portal detection) ─
        services.AddHostedService<DnsResponseValidationMonitor>();

        // ── TLS Certificate Monitor (MITM proxy, self-signed certs, CA change) ─
        services.AddHostedService<TlsCertificateMonitor>();

        // ── Bluetooth Attack Surface Monitor (BadBT, unauthorized pairing) ───
        services.AddHostedService<BluetoothMonitor>();

        // ── Wi-Fi Security Monitor (deauth, evil twin, open network, downgrade) ─
        services.AddHostedService<WifiSecurityMonitor>();

        // ── Secure Boot & Boot Integrity (firmware tampering, test signing) ───
        services.AddHostedService<SecureBootIntegrityMonitor>();

        // ── Windows Firewall Integrity (profile disabled, bulk rules, service) ─
        services.AddHostedService<FirewallIntegrityMonitor>();

        // ── Scheduled Task Persistence (malicious task creation detection) ────
        services.AddHostedService<ScheduledTaskMonitor>();

        // ── Windows Update Integrity (WU/BITS stopped, Defender stale) ────────
        services.AddHostedService<WindowsUpdateIntegrityMonitor>();

        // ═══════════════════════════════════════════════════════════════════════

        // ── Main hosted service ──────────────────────────────────────────────
        services.AddHostedService<SentinelService>();

        // ── User Session Launcher (launches Agent into user session) ──────────
        services.AddHostedService<UserSessionLauncher>();

        // ── Log Rotation Service ─────────────────────────────────────────────
        services.AddHostedService<LogRotationService>();

        return services;
    }
}

/// <summary>
/// Validates health check configuration options
/// </summary>
public class HealthCheckOptionsValidator : IValidateOptions<HealthCheckOptions>
{
    public ValidateOptionsResult Validate(string? name, HealthCheckOptions options)
    {
        var errors = new List<string>();

        if (options.Port < 1 || options.Port > 65535)
        {
            errors.Add($"Health check port must be between 1 and 65535. Current value: {options.Port}");
        }

        if (errors.Count > 0)
        {
            return ValidateOptionsResult.Fail(string.Join("; ", errors));
        }

        return ValidateOptionsResult.Success;
    }
}

/// <summary>
/// Log rotation service - rotates events.jsonl when it exceeds size threshold
/// </summary>
public class LogRotationService : BackgroundService
{
    private readonly ILogger<LogRotationService> _logger;
    private readonly string _logPath;
    private readonly long _maxFileSize;
    private readonly int _maxRetainedFiles;

    public LogRotationService(
        ILogger<LogRotationService> logger,
        IOptionsMonitor<LogRotationOptions> options)
    {
        _logger = logger;
        var opts = options.CurrentValue;
        _logPath = opts.LogPath;
        _maxFileSize = opts.MaxFileSize;
        _maxRetainedFiles = opts.MaxRetainedFiles;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Log rotation service started - checking every 60 seconds");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(60), stoppingToken);
                RotateLogs();
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Log rotation error");
            }
        }
    }

    private void RotateLogs()
    {
        try
        {
            if (!File.Exists(_logPath)) return;

            var fileInfo = new FileInfo(_logPath);
            if (fileInfo.Length < _maxFileSize) return;

            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var rotatedPath = $"{_logPath}.{timestamp}";

            File.Move(_logPath, rotatedPath);
            File.Create(_logPath).Close();

            _logger.LogInformation("Log rotated: {OldPath} -> {NewPath}", rotatedPath, _logPath);

            // Clean up old rotated logs
            CleanupOldLogs();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to rotate log file");
        }
    }

    private void CleanupOldLogs()
    {
        try
        {
            var directory = Path.GetDirectoryName(_logPath);
            if (string.IsNullOrEmpty(directory)) return;

            var pattern = Path.GetFileName(_logPath) + ".*";
            var files = Directory.GetFiles(directory, pattern)
                .OrderByDescending(f => new FileInfo(f).LastWriteTime)
                .Skip(_maxRetainedFiles);

            foreach (var file in files)
            {
                try
                {
                    File.Delete(file);
                    _logger.LogDebug("Deleted old log: {Path}", file);
                }
                catch { /* Ignore deletion errors */ }
            }
        }
        catch { /* Ignore cleanup errors */ }
    }
}

/// <summary>
/// Log rotation configuration options
/// </summary>
public class LogRotationOptions
{
    /// <summary>
    /// Path to the log file (default: events.jsonl in LocalApplicationData)
    /// </summary>
    public string LogPath { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WindowsSentinel", "events.jsonl");

    /// <summary>
    /// Maximum file size before rotation (default: 100MB)
    /// </summary>
    public long MaxFileSize { get; set; } = 100L * 1024 * 1024; // 100MB

    /// <summary>
    /// Number of rotated files to retain (default: 5)
    /// </summary>
    public int MaxRetainedFiles { get; set; } = 5;
}


