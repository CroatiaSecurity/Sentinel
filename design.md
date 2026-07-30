# Sentinel — Design Document

**Version: 1.8.0**

---

## Platform

- .NET 10, Windows only (`net10.0-windows`)
- Self-contained single-file publish for distribution
- Targets win-x64 self-contained single-file (installer ships x64)

---

## Architecture Overview

Sentinel follows a clean pipeline architecture with strict separation of concerns:

```
Monitors → TelemetryFusionEngine → DetectionEngine → AdvancedResponseEngine → JsonlEventLogger
                    ↓                      ↑               ↓
               EventGraph          BehavioralCorrelationEngine
           (queryable graph)              ↑               ↓
                                   (composite detections via EmitAsync)
                                                     ChainTracer (kill + quarantine)
```

All components are wired via Microsoft.Extensions.DependencyInjection. No static mutable state anywhere.

### Telemetry Fusion Layer

Every monitor feeds raw telemetry through the `TelemetryFusionEngine` before the `DetectionEngine`. The fusion layer:
1. Enriches events with cross-source context
2. Builds temporal event chains per-process
3. Maintains the `EventGraph` for causal/temporal queries
4. Produces `FusedTelemetryContext` with behavioral velocity, diversity, and multi-vector flags

The fusion layer is PASSIVE — it never blocks, kills, or modifies telemetry.

---

## Two-Process Architecture

| Process | Session | Runs As | Purpose |
|---------|---------|---------|---------|
| `Sentinel.Service.exe` | Session 0 | SYSTEM | Core detection, response, ETW, network, file, registry monitoring |
| `Sentinel.Agent.exe` | User session | Logged-in user | Tray icon, clipboard, keyboard hooks, screen/webcam, UI attack detection |

The Service is the authority. The Agent provides user-session visibility and UI.
`AgentWatchdog` (Service-side) monitors Agent liveness and relaunches it if killed.

---

## Component Inventory

### Service-Side Monitors (SYSTEM session)

Organized by MonitorGroup. Each group has staggered startup, independent failure restart, and priority-based resource allocation.

#### Group 1: Critical (starts immediately, restarts indefinitely)

| Component | Mechanism | Interval |
|-----------|-----------|----------|
| `AntiTamperGuard` | Service self-reinstall, anti-suspend timing, binary integrity, FIPS enforcement | 2s timing / 10s integrity |
| `IPSecIntegrityGuard` | Verifies GSecurity IPSec policy is active; re-applies if deleted | 30s |
| `AsrPolicyGuard` | Verifies Defender ASR Block rules (Policy hive); re-applies on drift/tamper | 60s |
| `AgentWatchdog` | Polls for Agent process; relaunches via CreateProcessAsUser if absent | 10s |
| `SyscallStubMonitor` | Compares ntdll/amsi function prologues against startup baseline; indirect syscall pattern detection | 30s |
| `ConnectivityCanaryMonitor` | Verifies Sentinel can reach threat intel endpoints; detects EDRSilencer | 45s |
| `EtwSessionGuard` | Checks UnifiedEtwSession IsActive + events/sec floor; auto-recreates | 3s |
| `EtwProviderTamperMonitor` | Checks EtwEventWrite patches in critical processes; detects logman/wevtutil manipulation | 30s |

#### Group 2: CoreDetection (2s start delay, max 5 restarts)

| Component | Mechanism | Interval |
|-----------|-----------|----------|
| `RansomwareIoMonitor` | High-frequency I/O rate monitoring for bulk rename/encrypt patterns | continuous |
| `BeaconingDetector` | Statistical CV analysis of connection intervals per (PID, Remote, Port) | 30s |
| `BehavioralBaselineService` | Learns normal processes, paths, parent-child, network destinations | continuous |
| `FileVerdictScanner` | Lazy background hash reputation scanning + ADS tagging (CIRCL/MalwareBazaar/VT) | background walk |
| `ConsultantSignalIngestor` | Tails external consultant signal JSONL files | continuous |
| `GhostProcessMonitor` | Detects PIDs with network connections but empty/unresolvable process names | 15s |
| `EphemeralProcessMonitor` | Catches short-lived processes via Prefetch + Event 4688 polling | 5s |
| `ModuleValidationMonitor` | Scans critical process modules for unsigned/tampered DLLs (baseline + detect) | 30s |
| `RuntimeModuleIntegrityMonitor` | Per-process module baseline; detects new suspicious DLLs appearing post-baseline | 60s |
| `DllEntropyAnalyzer` | Shannon entropy analysis on loaded DLLs; flags packed/encrypted (≥7.2) | periodic |
| `DllLoadFailureMonitor` | Event Log ID 7 + SideBySide errors for failed DLL hijack attempts | periodic |
| `DiskWideDllScanner` | Scans all drives for unsigned/suspicious DLLs at relaxed intervals | periodic |
| `PersistentConnectionMonitor` | Detects long-lived connections (webhooks, C2 pairing) and failover on drop | 10s |
| `DataExfiltrationMonitor` | Monitors outbound network volume, sensitive file access, USB writes | 15s |
| `AdsDataStagingMonitor` | Detects non-standard NTFS Alternate Data Streams (>1KB) in Temp/Downloads | periodic |
| `ScriptExecutionMonitor` | PowerShell Event 4104, parent-child anomalies, AMSI bypass, SAM extraction, script drops | 10s |
| `ScriptHardeningMonitor` | PS history integrity, SBL enforcement, downgrade, obfuscation scoring, profile persistence | 8s |
| `NamedPipeMonitor` | Polls `\\.\pipe\` for C2/lateral movement patterns; GetNamedPipeServerProcessId attribution | 15s |
| `RpcLateralMonitor` | Detects outbound lateral movement via RPC/DCOM/WMI/WinRM (ports 135/445/5985/5986) | 10s |
| `TokenTheftMonitor` | Detects non-service SYSTEM tokens and SeImpersonatePrivilege from user-writable paths | 20s |
| `CloudSyncExfilMonitor` | Monitors cloud sync directories for burst file staging; detects rclone/megasync | 15s |
| `LnkShortcutMonitor` | Real-time FileSystemWatcher on Desktop/Start Menu/Taskbar/Startup (all profiles); UNC/protocol/LOLBin remote launch | FSW + startup scan |

#### Group 3: CredentialProtection (4s start delay, max 3 restarts)

| Component | Mechanism | Interval |
|-----------|-----------|----------|
| `CanaryFileMonitor` | Deploys decoy files in ransomware-target directories; any access triggers alert | 10s |
| `BrowserCredentialGuard` | Monitors Chromium + Firefox credential files (Login Data, Cookies, key4.db, logins.json) | 30s |
| `BrowserC2Guard` | Headless chrome-as-proxy detection, CDP session hijacking, extension manifest integrity scanning | 30s |
| `MicrosoftAccountGuardMonitor` | TokenBroker cache, PRT extraction, Azure AD token theft tool detection | 30s |
| `NullSessionGuard` | Enforces LimitBlankPasswordUse, RestrictAnonymous, EveryoneIncludesAnonymous | 60s |
| `BuiltinAdminGuard` | Monitors built-in Administrator account (RID 500); disables if found active | 15s |
| `PasswordRotationGuard` | Rotates local account passwords every 10 min; UAC=5; auto-logon via LSA secret | 10 min |
| `RemoteSessionGuard` | WTSEnumerateSessions; force-logoff non-console remote sessions (RDP etc.); never session 0 / console | 5s |

#### Group 4: NetworkIntegrity (6s start delay, max 3 restarts)

| Component | Mechanism | Interval |
|-----------|-----------|----------|
| `ArpSpoofMonitor` | GetIpNetTable P/Invoke; detects gateway MAC change, ARP poisoning, virtual OUI | 15s |
| `DnsResponseValidationMonitor` | Resolves canary domains; validates against expected CIDR ranges | 1min |
| `PublicIpMonitor` | Checks public IP via Cloudflare/ipify/icanhazip; detects geo/ASN shift | 5min |
| `WifiSecurityMonitor` | Polls Wi-Fi state via netsh; detects deauth flood, open network, encryption downgrade | 15s |
| `NetworkInterfaceGuard` | Removes bridges via SetupAPI, restores disabled adapters, locks DNS | 15s |
| `AppDnsExfilMonitor` | Detects non-browser processes connecting to known DoH resolvers on port 443 | 500ms |
| `NetworkShareMonitor` | Monitors SMB shares, admin share access (C$/ADMIN$/IPC$), inbound sessions | 15s |
| `NetworkReinfectionDetector` | Monitors NIC state changes; flags new suspicious processes after network reconnection | on NIC event |
| `ReinfectionCorrelator` | Tracks killed/quarantined hashes across reboots; scans for reappearance | 60s |
| `DnsCrossValidator` | Resolves test domain via system + direct Cloudflare; detects router DNS poisoning | periodic |
| `TrafficVolumeBaseline` | Monitors raw NetworkInterface BytesSent; alerts on 3x baseline upload volume | 30s |
| `OutboundConnectionWhitelist` | Monitors/enforces outbound connections against allowed IP subnets | periodic |
| `RemoteAccessMonitor` | Scans for 35+ remote access tools; Tier2 presence / Tier1 tunnels from staging paths | 60s |
| `ThreatIntelFeedBlocker` | Spamhaus DROP + Feodo + EmergingThreats IP blocklists → firewall rules; active-conn check | 4h refresh / 30s conn |
| `ForumHrWatchMonitor` | Dedicated forum.hr watch (site not blocked): non-browser DNS/TCP + persistent sessions → kill; browsers allowed | 10s / 15m DNS refresh |

#### Group 5: SystemIntegrity (10s start delay, max 3 restarts)

| Component | Mechanism | Interval |
|-----------|-----------|----------|
| `FirewallIntegrityMonitor` | Polls firewall profiles via netsh advfirewall; detects disable/bulk rules | 60s |
| `SecureBootIntegrityMonitor` | Checks Secure Boot, test signing, kernel debug via registry+bcdedit | 5min |
| `WindowsUpdateIntegrityMonitor` | Monitors WU/BITS services and auto-update registry | 2min |
| `ScheduledTaskMonitor` | Polls scheduled tasks via schtasks; multi-indicator suspicious task analysis | 60s |
| `CriticalServiceGuard` | Monitors 15 critical services for crash storms via SCM events (7034/7031) | 10s |
| `RegistryMonitor` | WMI-based monitoring of Run keys, Services, CLSID COM hijacking | continuous |
| `WmiPersistenceMonitor` | Periodic scan for __EventFilter/__EventConsumer persistence (T1546.003) | 5min |
| `WmiProviderIntegrityMonitor` | Enumerates __Win32Provider objects; validates Authenticode on provider DLLs | 5min |
| `WorkFoldersExfilMonitor` | Detects unauthorized Work Folders activation; active response: kills service | 15s |
| `TlsCertificateMonitor` | Monitors LocalMachine\Root certificate store; baselines at startup | 60s |
| `UacBypassSurfaceMonitor` | Detects COM AutoElevation vectors and manifest autoElevate + copy-drop | periodic |
| `HostsFileGuard` | Enforces embedded hosts file content (SHA-256 verified); deletes other files in drivers\etc | FSW + 30s |
| `BrowserDnsPolicyGuard` | Disables DoH system-wide across all browsers; 15s self-healing | 15s |
| `BootIntegrityGuard` | Monitors BCD, boot drivers, EFI partition for bootkit indicators | 60s |
| `CveShieldHardener` | Fetches CISA KEV feed; maps against local assets; generates block rules | 4h |
| `ApplicationIntegrityMonitor` | Cuckoo Egg Detection — baselines protected apps (SHA-256 + Authenticode) | FSW + 30s |
| `PseudoSandbox` | Lightweight behavioral sandbox via restricted Job Objects | on-demand |
| `AcousticThreatMonitor` | Detects harmful audio frequencies via WASAPI loopback + Goertzel algorithm | continuous |
| `WfpIntegrityMonitor` | Scans WFP filters for BLOCK rules targeting Sentinel/EDR processes | 30s |
| `DriverLoadMonitor` | Monitors for BYOVD attacks via Event 7045, registry, .sys file creation; cert-tracing revokes planted signing certs | 15s |

#### Group 6: Peripheral (30s start delay, max 2 restarts)

| Component | Mechanism | Interval |
|-----------|-----------|----------|
| `BluetoothMonitor` | Monitors BT device registry and service state; detects BadBT HID pairing | 15s |
| `PhantomDeviceMonitor` | ARP table scanning for new LAN devices; probes suspicious ports; firewall blocks | 45s |
| `DeviceInstallMonitor` | Baselines PnP devices/drivers; detects new device installs and BYOVD | 15s + WMI event |
| `MtpTransferGuard` | Blocks non-media file transfers to/from MTP devices (phones/tablets) | 5s |
| `VolumeMountMonitor` | Detects RAM disks, PMEM, VeraCrypt, VHD; extends FileActivityMonitor dynamically | 5s |
| `CastDeviceGuard` | Kills Cast port connections to non-allowlisted IPs; self-healing firewall rules | 5s |
| `WslMonitor` | Monitors WSL process spawns, suspicious commands, new distro installs | 10s |
| `RawDiskAccessMonitor` | Detects processes opening raw disk device paths via NtQuerySystemInformation handles | 20s |
| `PrintSpoolerMonitor` | Monitors print spooler for bulk spool file creation and XPS exfiltration | 15s |
| `SandboxEscapeMonitor` | Monitors Windows Sandbox, Docker, Hyper-V for escape indicators | 15s |
| `HardwareSecurityGuard` | Checks IOMMU/VT-d, Secure Boot, BitLocker encryption status | 60s |
| `UsbHidWhitelist` | Baselines connected HID devices; disables unknown HID keyboards (BadUSB) | 15s |
| `PhysicalAccessMonitor` | Correlates idle periods with hardware changes on user return | on idle return |

### Service-Side Standalone Monitors (not in a MonitorGroup)

| Component | Mechanism | Notes |
|-----------|-----------|-------|
| `EtwProcessMonitor` | ETW kernel provider (Kernel-Process); IMonitor interface | Falls back to WMI |
| `EtwThreatIntelMonitor` | Microsoft-Windows-Threat-Intelligence ETW provider; VirtualQueryEx-based unbacked RWX detection every 3rd cycle | Requires elevation |
| `DnsQueryMonitor` | Microsoft-Windows-DNS-Client ETW provider; IMonitor | Requires elevation |
| `WmiProcessMonitor` | Win32_ProcessStartTrace WMI event subscription | Disabled when ETW active |
| `FileActivityMonitor` | FileSystemWatcher on user profile + dynamic paths | Singleton |
| `NetworkMonitor` | GetExtendedTcpTable/UdpTable P/Invoke, IPv4+IPv6 | Singleton |
| `LsassDumpCanaryMonitor` | Scans system-wide process handles for unauthorized lsass.exe read access | 30s |
| `RouteTableMonitor` | GetIpForwardTable P/Invoke; detects route injection, default route hijack | 15s |
| `MemoryBehaviorAnalyzer` | Process.Modules enumeration + module count tracking; process hollowing and DLL sideloading detection | 90s |
| `TokenIntegrityMonitor` | GetTokenInformation(TokenIntegrityLevel); detects Medium→High without UAC | 45s |
| `CredentialCanaryMonitor` | Plants/monitors honeypot credentials in Windows Credential Manager | periodic |
| `LocalServerMonitor` | Detects suspicious processes listening on localhost (mounted ISO/VHD origins) | 20s |
| `AppNetworkPolicyMonitor` | Per-app network destination learning and enforcement (30-min learning phase) | 15s |
| `UsbDeviceFingerprinter` | USB device baseline via VID:PID:Serial; BadUSB detection; failed-enum disable + verified PnP removal (pnputil fallback, periodic zombie re-sweep) | 30s |

### Agent-Side Monitors (user session)

| Component | Mechanism | Notes |
|-----------|-----------|-------|
| `TrayIconService` | System tray NotifyIcon; context menu **Settings** opens Agent settings UI (Overview / Events / Report to Police / Quarantine). **No** `ShowBalloonTip` (WpnService removed by hardening deadlocks STA) | WinForms STA |
| `AgentDashboardForm` | TrimKit-style dark sidebar Settings UI; affidavit editor + national portal open for evidence packs | WinForms STA |
| `ClipboardSanitizer` | Strips zero-width chars, RTL overrides, Cyrillic homoglyphs, Unicode tags; ClickFix paste-run clear | 10s poll |
| `ScreenCaptureMonitor` | Detects DXGI desktop duplication + transparent overlay phishing windows | 15–25s |
| `WebcamMicMonitor` | Detects background camera/mic access via DLL analysis (Media Foundation, WASAPI) | 20s |
| `AudioHijackMonitor` | Module-based detection of output-to-mic redirection (virtual audio cables) | periodic |
| `MicSessionMonitor` | Standalone microphone session monitoring (defense-in-depth with WebcamMicMonitor) | periodic |
| `NeuroBehaviorVisualMonitor` | Focus steals, cursor jumps, brightness oscillations, large transparent topmost overlays | 1s sample |
| `BrowserExtensionMonitor` | Baselines extensions; detects new extensions with dangerous permissions | 30s |
| `PhantomKeystrokeGuard` | WH_KEYBOARD_LL hook; blocks software-injected keystrokes | continuous |
| `ClickjackingGuard` | Mouse hook; detects injected clicks, cursor teleport, fake UAC/credential prompts, clipboard crypto swap | continuous |
| `WebcamHijackMonitor` | Monitors ConsentStore for webcam/microphone access by new apps | periodic |
| `ShellWatchdog` | Monitors explorer.exe responsiveness via SendMessageTimeout; auto-restarts shell | 5s |
| `ScarewareWindowMonitor` | Window-title scareware / fake UAC / fake Defender dialogs (≥2 keywords) | 10s |
| `CursorTakeoverMonitor` | Low velocity-variance continuous cursor motion (bot/RDP-takeover style) | 3s sample |
| `CookieIntegrityMonitor` | SHA-256 integrity on Chrome/Edge/Brave cookie DBs (alert-only; no force-restore) | 5 min |

### Engines

| Component | Role |
|-----------|------|
| `DetectionEngine` | Runs all `IDetectionRule` instances against incoming telemetry. Channel-based async stream. Tiered deduplication (10s Tier1, 30s Tier2). Records metrics via `SentinelMetrics`. |
| `AdvancedResponseEngine` | Single point of action enforcement. Tier2 is always log-only. Tier1 may kill process when `--active-response` is set. President's Law closed kill list. |
| `TelemetryFusionEngine` | Correlates raw telemetry across all sources into per-process event chains. Produces `FusedTelemetryContext` with behavioral metrics. |
| `EventGraph` | In-memory graph of processes, files, and network endpoints with temporal/causal edges. Supports incident timeline queries. |
| `MemoryBehaviorAnalyzer` | Scans process modules every 90s via .NET Process.Modules. Detects process hollowing (missing MainModule), DLL injection (module count growth ≥3), and DLL sideloading via DllUnloadEngine. |
| `ProcessAncestryCache` | `CreateToolhelp32Snapshot` refreshed every 5s (WMI fallback for Server Core/IoT). Provides parent name resolution. |
| `BehavioralCorrelationEngine` | Time-windowed (60s) multi-signal correlator. Fires composite `DetectionEvent`s via `IDetectionEngine.EmitAsync`. |
| `BeaconingDetector` | Statistical C2 beacon detection. Tracks inter-connection intervals. Fires when CV < 0.40 with 5+ observations. Multi-factor Authenticode trust verification. |
| `ScoringEngine` | Weighted multi-factor threat scoring with source weights, category base scores, corroboration bonuses. |
| `FileReputationEngine` | Composite file trust scoring (0-100) aggregating CIRCL, MalwareBazaar, VirusTotal (via proxy), static PE analysis, signer trust. |
| `DllUnloadEngine` | Detects DLL sideloading; unloads malicious DLLs via QueueUserAPC+FreeLibrary or kills host process. |
| `ChainTracer` | Attack chain walker: kills non-critical processes in chain, quarantines binaries, removes persistence. |
| `IncidentResponseService` | Automated incident resolution: persistence removal, quarantine orchestration. Integrates with ChainTracer. |
| `IsolationResponseEngine` | Handles threats from isolated environments: ISO dismount, Docker stop+rm+rmi, Hyper-V/VM stop. |
| `DynamicRulesEvaluator` | Loads HMAC-signed JSON rule files from `/rules` directory at runtime. |
| `ResponseCoordinator` | Per-PID semaphore-based response serialization. Prevents duplicate kills, supports escalation. |
| `ReinfectionCorrelator` | Tracks killed/quarantined hashes across reboots. Scans for reappearance of known-bad. |

### Orchestration Layer

| Component | Role |
|-----------|------|
| `SentinelOrchestrator` | Central coordination: routes detections through incident grouping before response. Per-PID response locks. |
| `IncidentManager` | Groups detections into unified incidents by PID/parent/hash. Lifecycle: Open → Active → Responded → Closed. |
| `MonitorRegistry` | Supervises all monitors with heartbeat tracking. Auto-restarts crashed monitors. Death fires anti-tamper. |
| `StartupSequencer` | Phased dependency-ordered boot: Infrastructure → Engines → Monitors → Validators. |
| `ContextBus` | Thread-safe pub/sub for cross-monitor enrichment signals. Bounded channels, TTL-based expiry. |
| `MonitorGroup` | Infrastructure class grouping monitors with staggered startup, restart policies, health checks. |

### Infrastructure & Utilities

| Component | Role |
|-----------|------|
| `JsonlEventLogger` | JSONL output to events.jsonl. Thread-safe, rate-limited, size-rotated, self-healing. |
| `SecureCacheStore` | DPAPI machine-scope encryption + HMAC integrity for persisted cache files. |
| `HashReputationService` | Two-tier caching (memory + DPAPI disk). 3-API lookup: CIRCL, MalwareBazaar, VT proxy. |
| `QuarantineManager` | DPAPI-encrypted quarantine with SYSTEM+Admins-only ACL. Atomic encrypt→move→delete. |
| `SignerTrustService` | Centralized Authenticode verification (WinVerifyTrust + catalog fallback). Trusted publisher cache. |
| `AllowlistService` | User/dev/gaming/publisher allowlists. President's Law rules never suppressed. |
| `SecurityValidation` | Input validation, Authenticode verification (embedded + catalog), process image path resolution. |
| `SentinelMetrics` | Performance counters with histograms (P50/P90/P95/P99) for detection and response. |
| `SentinelHealthCheck` | Structured health checks: process, memory, handles, log file, quarantine, thread pool. |
| `StartupSelfTest` | Verifies ETW, DPAPI, quarantine, log file, and rule loading before activating monitors. |
| `ThreatReportService` | Reports threats to MalwareBazaar/URLhaus/AbuseIPDB via Cloudflare Worker proxy. |
| `AutoIncidentReporter` | v1.7.7/1.7.8: Reportable-grade evidence packs, integrity seal (SHA-256+HMAC), victim affidavit, zip export, TI share, national portals. Does not file police reports. |
| `LawEnforcementPortals` | Country → cybercrime portal directory (IC3, Action Fraud, MUP, …); INTERPOL info-only. |
| `IoCScanner` | Loads threat intel indicators from DPAPI-encrypted external cache. |
| `InstallerHeuristics` | Shared utility for installer name/Inno extractor/benign prefetch pattern recognition. |
| `HardeningModule` | Native C# hardening: service disabling, registry security settings, LGPO policy, ACL enforcement. |
| `UnifiedEtwSession` | Single real-time ETW session subscribing to 9 kernel/system providers via raw P/Invoke. |
| `EtwEventDispatcher` | Routes raw ETW events by provider GUID to typed telemetry objects. |
| `ConfigIntegrityMonitor` | Runtime detection of config/executable tampering (SHA-256 baseline, 5-min checks). Integrated into `AntiTamperGuard`. |
| `ProxyAuthHelper` | HMAC-SHA256 signing for all proxy requests using installation entropy key. |
| `ParentPidSpoofDetector` | Detects PPID spoofing via CreateToolhelp32Snapshot parent-child validation. |
| `SafeProcessExemptionRegistry` | Tracks processes confirmed safe by VerdictGateRule to prevent redundant scanning. |
| `FileVerdictAds` | Reads/writes ADS-based verdict tags on scanned files to avoid re-scanning. |
| `ToastService` | System toast notification delivery for user-visible alerts (Agent-side). |

---

## Detection Rules

### Tier 1 — Behavioral (active response allowed via President's Law)

| Rule | Category | Key Signals | Confidence Range |
|------|----------|-------------|-----------------|
| `LsassAccessRule` | CredentialDump | LSASS-targeting cmdline tokens, dump file names | 0.85–0.92 |
| `RansomwareDetectionRule` | Ransomware | Shadow copy deletion, bulk renames, I/O rate, 100+ extensions | 0.68–0.99 |
| `ReverseShellRule` | ReverseShell | Encoded PowerShell, LOLBins, C2 ports, C2 framework strings | 0.80–0.93 |
| `ThreatIntelInjectionRule` | ProcessInjection | Kernel-observed VirtualAllocEx, VirtualProtect RWX, APC, SetThreadContext | 0.72–0.93 |
| `PrivilegeEscalationRule` | PrivilegeEscalation | UAC bypass, token manipulation, named pipe impersonation, DLL hijacking | 0.80–0.95 |
| `AttackToolsRule` | SecurityEvasion | C2 frameworks, credential tools, AD tools, LOLBin abuse (60+ patterns) | 0.75–0.97 |
| `CampaignIocRule` | CampaignIoC | Known malicious hashes, domains, IPs, campaign patterns | 0.78–0.92 |
| `CampaignDetectionRule` | CampaignIoC | Multi-indicator campaign matching (CobaltStrike, QBot, Emotet, TrickBot) | 0.70–0.90 |
| `ClickFixDetectionRule` | ReverseShell | Paste-and-run / FakeCAPTCHA exploits from explorer/browser | 0.78–0.92 |
| `NpmSupplyChainRule` | SecurityEvasion | node/npm/yarn/pnpm spawning shell with download/encode patterns | 0.75–0.90 |
| `ChromeRemoteDebuggingRule` | CredentialDump | Browser launched with --remote-debugging-port by non-browser parent | 0.85 |
| `DllSideloadingDetectionRule` | ProcessInjection | Signed Microsoft utilities executing from user-writable paths | 0.80–0.90 |
| `VerdictGateRule` | AntiTamper | On-execute reputation check; blocks Malicious/HighRisk binaries | 0.80–0.95 |

### Tier 2 — Corroborating Signals (log only, feeds correlation engine)

| Rule | Key Signals | Confidence Range |
|------|-------------|-----------------|
| `UnsignedBinaryRule` | Unsigned binary outside system paths, staging path boost | 0.50–0.68 |
| `DynamicRulesEvaluator` | HMAC-signed JSON rules loaded from `/rules` directory | varies |

### Composite Detections (BehavioralCorrelationEngine)

Emitted as Tier1 `DetectionEvent`s directly via `EmitAsync`. Requires signals from different sources within a 60s window on the same PID.

| Composite | Confidence | Trigger Combination |
|-----------|-----------|---------------------|
| Active Ransomware Chain | 0.99 | 2+ distinct ransomware signals from different rules |
| Injected C2 Beacon | 0.98 | Kernel-observed injection + C2 network |
| Credential Dump + Exfiltration | 0.96 | LSASS/credential access + outbound network |
| In-Memory Implant Active | 0.96 | Memory anomaly (injection/RWX) + network callback |
| Named Pipe C2 + Network Beaconing | 0.95 | Suspicious named pipe + C2 network beaconing on same PID |
| Fileless Attack Chain | 0.95 | AMSI/ETW/security evasion + shell or C2 |
| DGA + C2 Beaconing | 0.94 | High-entropy/rapid DNS + periodic beacon |
| Token Theft + Lateral Movement | 0.93 | Token manipulation + RPC/SMB/pipe lateral movement on same PID |
| Dropped Payload Active | 0.93 | Unsigned/staged binary + C2 communication (catch-all) |
| Confirmed C2 Beacon: Unsigned Process | 0.88–0.93 | Unsigned binary + periodic beaconing pattern (staging path boost) |
| Spoofed Process Phoning Home | 0.92 | PPID spoofing + network communication |
| Evasion + Persistence Install | 0.91 | Security evasion + persistence mechanism |
| Covert C2: Unsigned + Sustained Connection | 0.90 | Unsigned binary maintaining 60s+ outbound connection |
| Escalation + C2 Channel | 0.90 | Privilege escalation + outbound C2 |
| Covert RAT: Unsigned + Hidden + Network | 0.88–0.92 | Unsigned from staging path + C2 network (recon activity boost) |

---

## Telemetry Types

| Type | Source | Consumed by |
|------|--------|-------------|
| `ProcessTelemetry` | `EtwProcessMonitor`, `WmiProcessMonitor` | All Tier1 rules, `TelemetryFusionEngine` |
| `NetworkTelemetry` | `NetworkMonitor`, `UnifiedEtwSession` (Kernel-Network) | `ReverseShellRule`, `BeaconingDetector` |
| `FileActivityTelemetry` | `FileActivityMonitor`, `UnifiedEtwSession` (Kernel-File) | `RansomwareDetectionRule` |
| `ThreatIntelTelemetry` | `EtwThreatIntelMonitor` | `ThreatIntelInjectionRule` |
| `RegistryTelemetry` | `UnifiedEtwSession` (Kernel-Registry) | `RegistryMonitor` |
| `DnsTelemetry` | `UnifiedEtwSession` (DNS-Client) | `DnsQueryMonitor` |
| `FirewallTelemetry` | `UnifiedEtwSession` (Firewall) | `FirewallIntegrityMonitor` |
| `TaskSchedulerTelemetry` | `UnifiedEtwSession` (TaskScheduler) | `ScheduledTaskMonitor` |
| `DetectionEvent` (direct) | `NamedPipeMonitor`, `WmiPersistenceMonitor`, other monitors | Direct emission to `DetectionEngine.EmitAsync` |

---

## Response Actions

| Kind | When |
|------|------|
| `LogOnly` | Always for Tier2; Tier1 when `--active-response` is not set; non-President's-Law rules |
| `NetworkIsolate` | Firewall block of C2 IP; DNS flush; ARP cache flush |
| `KillProcess` | Tier1 President's Law rules, confidence ≥ 0.85, via ChainTracer |
| `KillProcessTree` | Same as above but walks and kills entire process tree |
| `Quarantine` | DPAPI-encrypted file quarantine to `%ProgramData%\Sentinel\Quarantine` |
| `QuarantineAndKill` | Kill process + quarantine binary + place lock file |
| `RemoveRegistryEntry` | Removes malicious autorun/service/COM entries |
| `DismountVolume` | Dismounts ISO/VHD/SUBST drives hosting threats |
| `RemoveCert` | Removes suspicious root certificates from store |
| `RemoveCertAndKillAdder` | Removes planted certificate + kills the process that installed it (BYOVD cert-trace) |

---

## Key Design Rules

- **Dependency Injection** — all components receive dependencies via constructor injection
- **No static mutable state** — `ConcurrentDictionary`, `Channel<T>`, `SemaphoreSlim` for shared state
- **CancellationToken everywhere** — no `Thread.Sleep`, no blocking waits without cancellation
- **No silent failures** — all exceptions caught and logged; monitors fail independently
- **Graceful degradation** — ETW → WMI fallback; ThreatIntel ETW unavailable → continue without
- **Startup self-test** — Verifies ETW, DPAPI, quarantine, log file, and rule loading before activating monitors
- **Tier2 enforcement** — `AdvancedResponseEngine` hard-codes `LogOnly` for all `Tier2Indicator` events regardless of configuration
- **Deduplication** — `DetectionEngine` suppresses identical `(RuleName, ProcessId)` pairs within 10s (Tier1) / 30s (Tier2)
- **All file reads use `FileShare.ReadWrite | FileShare.Delete`** — Sentinel observes, never obstructs
- **Monitors are grouped by function and priority** — critical self-protection first, peripheral last
- **No LOLBin dependencies** — all response actions use native C# APIs / P/Invoke (no sc.exe, cmd.exe, powershell.exe)
- **No offensive deception tactics** — removed to avoid AV heuristic false positives on the Sentinel binary

---

## Logging

`JsonlEventLogger` writes newline-delimited JSON to `%ProgramData%\Sentinel\events.jsonl`.

- Thread-safe via `SemaphoreSlim`
- `System.Text.Json` only — no string-built JSON
- Size-based rotation at 50 MB, up to 5 rotated files
- Rate-limited: max 1000 entries/second, burst of 5000
- `FileShare.ReadWrite` — concurrent readers never blocked
- Self-healing: retries on write failure; renames stale locked files

---

## Unified ETW Session Architecture

Single real-time ETW trace session replacing per-monitor polling:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    UnifiedEtwSession                                  │
│   Single real-time trace session (SentinelUnifiedTrace)              │
│   64 buffers x 256KB, QPC timestamps, AboveNormal priority          │
│                                                                      │
│   PROVIDERS:                                                         │
│   1. Microsoft-Windows-Kernel-Process     -> ProcessTelemetry        │
│   2. Microsoft-Windows-Kernel-File        -> FileActivityTelemetry   │
│   3. Microsoft-Windows-Kernel-Registry    -> RegistryTelemetry       │
│   4. Microsoft-Windows-DNS-Client         -> DnsTelemetry            │
│   5. Microsoft-Windows-Threat-Intelligence-> ThreatIntelTelemetry    │
│   6. Microsoft-Windows-PowerShell         -> ProcessTelemetry (4104) │
│   7. Microsoft-Windows-Firewall           -> FirewallTelemetry       │
│   8. Microsoft-Windows-TaskScheduler      -> TaskSchedulerTelemetry  │
│   9. Microsoft-Windows-Kernel-Network     -> NetworkTelemetry        │
└─────────────────────────────────────────────────────────────────────┘
```

- **P/Invoke only**: Raw Win32 ETW APIs. No TraceEvent NuGet (embeds AV-triggering strings).
- **Single thread**: ProcessTrace blocks on a dedicated background thread.
- **Graceful degradation**: If ETW session fails, all monitors continue with poll-based implementations.
- **WMI deduplication**: When ETW is active, `WmiProcessMonitor.Disable()` prevents duplicate events.

---

## v1.6.8 Additions

### New Monitor: BrowserC2Guard (Group 3: CredentialProtection)

Full browser-based C2 detection expanding `ChromeRemoteDebuggingRule`:

| Detection Mode | Confidence | Response |
|----------------|-----------|----------|
| Headless Chrome-as-proxy (debug port + non-browser parent) | 0.78–0.90 | KillProcessTree |
| CDP session hijacking (non-browser WebSocket to debug port) | 0.88 | NetworkIsolate |
| Extension manifest: dangerous permissions (debugger, nativeMessaging, proxy) | 0.55–0.78 | LogOnly |

### Expanded Monitors

| Monitor | What was added |
|---------|----------------|
| `EtwThreatIntelMonitor` | VirtualQueryEx-based detection of unbacked RWX regions in high-value targets (ALLOCVM_REMOTE + PROTECTVM_REMOTE effects). Runs every 3rd cycle. Provider GUID `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`. |
| `SyscallStubMonitor` | Indirect syscall / Hell's Gate pattern detection via ReadProcessMemory. Scans non-image executable memory for `mov r10,rcx; mov eax,SSN; syscall` (4C 8B D1 B8 xx xx 00 00 ... 0F 05). Fires at 3+ stubs (0.92 confidence). |
| `PrintSpoolerMonitor` | PrintNightmare-class exploitation: baselines printer driver DLLs, detects new unsigned DLLs in spool\drivers, catches spoolsv.exe spawning unexpected child processes. |
| `WslMonitor` | Container-to-host lateral movement: (1) WSL writing to sensitive host paths via /mnt/c/, (2) WSL interop spawning security-sensitive Windows .exe, (3) Docker overlay filesystem processes accessing host resources. |

### New Composite Detections (BehavioralCorrelationEngine)

| Composite | Confidence | Trigger Combination |
|-----------|-----------|---------------------|
| Named Pipe C2 + Network Beaconing | 0.95 | Suspicious named pipe + C2 network beaconing on same PID |
| Token Theft + Lateral Movement | 0.93 | Token manipulation + RPC/SMB/pipe lateral movement on same PID |

### ContextBus Integration (v1.6.8)

| Monitor | Signal Published | Consumed By |
|---------|-----------------|-------------|
| `NamedPipeMonitor` | `NamedPipeSignal` | BehavioralCorrelationEngine, ChainTracer |
| `TokenTheftMonitor` | `TokenTheftSignal` | BehavioralCorrelationEngine, ChainTracer |

---

## v1.7.0 Additions

### Enhanced Monitor: DriverLoadMonitor — BYOVD Certificate Tracing

Full cert-revocation chain for BYOVD attacks. When a vulnerable/suspicious driver is detected, Sentinel now traces back to the signing certificate and revokes it if planted.

| Capability | Description | Confidence | Response |
|------------|-------------|-----------|----------|
| Cert extraction | Authenticode cert extracted from detected .sys binary | — | — |
| TrustedPublisher plant detection | Checks if signing cert is in TrustedPublisher store (not a known public CA) | 0.95 | RemoveCertAndKillAdder |
| Root CA plant detection | Checks if cert issuer is a planted Root CA (fake Chromecast/IoT CA pattern) | 0.95 | RemoveCertAndKillAdder |
| Cross-driver scan | After cert revocation, scans System32\drivers for other .sys files signed by same cert | 0.93 | Disable+Delete service |
| CurrentUser store coverage | Also checks CurrentUser\TrustedPublisher and CurrentUser\Root | 0.95 | RemoveCertAndKillAdder |

**Attack chain closed:**
```
1. Attacker plants fake cert in TrustedPublisher
2. Attacker signs driver with that cert → Windows DSE validates
3. Sentinel DriverLoadMonitor detects new kernel driver (Event 7045 / registry / .sys drop)
4. Cert-trace: extracts Authenticode cert → finds it in TrustedPublisher → NOT a public CA
5. Fires RemoveCertAndKillAdder → cert removed from store
6. Scans System32\drivers → disables all services using that cert
7. Driver cannot be reloaded (DSE will now reject it)
```

**Public CA protection:** Well-known vendor and CA certs (DigiCert, Microsoft, NVIDIA, Intel, Realtek, etc.) are never revoked — only non-public planted certs trigger revocation.

---

## v1.7.4 Additions

### ThreatIntelFeedBlocker (Service · NetworkIntegrity)

| Item | Value |
|------|--------|
| Feeds | Spamhaus DROP, Feodo Tracker recommended, EmergingThreats block list |
| Refresh | Startup (+45s delay) then every 4h |
| Firewall | COM `HNetCfg.FwPolicy2` batch rules (100 IPs/rule, IN+OUT), max 5000 rules / 2000 IPs per feed |
| Connection check | Every 30s against active established TCP remotes; Tier1 + `NetworkIsolate` on hit |
| CIDR policy | Prefix /8–/32 only (rejects /0–/7) |

### LnkShortcutMonitor (Service · CoreDetection)

| Item | Value |
|------|--------|
| Mechanism | FileSystemWatcher `*.lnk` + full initial scan |
| Paths | All `C:\Users\*\Desktop|Start Menu|Taskbar|Startup` + Common Desktop/Programs/Startup |
| Resolution | COM `IShellLink` + binary UNC fallback |
| Detections | UNC target, `search-ms:`/`ms-msdt:`/`http(s):`, LOLBin+remote args |
| Response | Tier1 + Quarantine (delete fallback) |
| Note | Sole LNK guard — poll-based `LnkUncGuard` heuristics folded in; not dual-registered |

### Agent user-session ports (from PowerShell Detection/)

| Monitor | Interval | Response |
|---------|----------|----------|
| `ScarewareWindowMonitor` | 10s | Tier1 + KillProcessTree (scareware ≥2 keywords / fake system title) |
| `CursorTakeoverMonitor` | 3s sample | Tier2 LogOnly (low velocity variance + motion) |
| `CookieIntegrityMonitor` | 5 min | Tier2 LogOnly (Chrome/Edge/Brave cookie DB hash change) |

---

## v1.8.0 Additions

### TokenTheft false-positive hardening

| Item | Value |
|------|--------|
| Problem | Built-in `Memory Compression` / `Registry` (SYSTEM token, empty image path) treated as potato/token theft → kill-grade + police packs every cooldown |
| Fix | Expanded OS allowlists; empty path not suspicious; empty path + OS name skipped; unknown empty path LogOnly 0.55 only |
| Cooldown | Per-PID/rule alert cache 60 minutes (was 5) |
| Packs | `AutoIncidentReporter.IsTokenTheftOsFalsePositive` blocks LE packs for those FPs; Token Theft pack cooldown ≥ 1 hour |
| Tests | `V180FeatureTests` |

## v1.7.9 Additions

### Agent Settings UI

| Item | Value |
|------|--------|
| Entry | Tray **Settings** (bold) / double-click; optional **Report to Police…** shortcut |
| Form | `AgentDashboardForm` — dark sidebar (TrimKit-style), STA-safe sync I/O only |
| Pages | Overview · Events · Report to Police · Quarantine · About |
| Filing | Edit affidavit → save `victim_affidavit.txt` → Send Report opens national portal + pack folder; rebuilds ZIP |
| Prefs | `%LocalAppData%\Sentinel\user_report_prefs.json` |
| Not exposed | ActiveResponse toggle (service-only); balloon tips |

## v1.7.8 Additions

### Reportable-grade evidence quality

| Item | Value |
|------|--------|
| Policy | `ReportableGradeOnly` (default true); MinConfidence 0.85; kill floor 0.80 |
| Seal | `MANIFEST.sha256` + machine-bound `MANIFEST.hmac` + `evidence_manifest.json` |
| Affidavit | `victim_affidavit.txt` (post-seal fill; excluded from hash list) |
| Custody | `chain_of_custody.txt` (timeline + handoff table; excluded from hash list) |
| Export | `.zip` + `.zip.sha256` |
| Verify | `AutoIncidentReporter.VerifyPackIntegrity` |

## v1.7.7 Additions

### Automatic attack incident reporting

| Item | Value |
|------|--------|
| Hook | `SentinelOrchestrator.ProcessDetectionAsync` after response (async, non-blocking) |
| Pack root | `%ProgramData%\Sentinel\IncidentReports\AUTO_*` |
| TI share | Existing `ThreatReportService` / Worker (hash, URL, IP) when secret configured |
| LE filing | Human: national portal URL embedded in pack + toast |
| Not supported | Direct INTERPOL / police API auto-file (does not exist for consumers) |

Config section: `AutoIncidentReporting` (see CHANGELOG 1.7.7 / 1.7.8).

## v1.7.6 Additions

### Forum.hr policy: watch, don't block

| Item | Value |
|------|--------|
| Hosts block | **Removed** from `HostsFileGuard` trusted content (was opinionated) |
| Monitor | `ForumHrWatchMonitor` (NetworkIntegrity) |
| Allowed | Browser processes browsing forum.hr |
| Enforced | Non-browser DNS/TCP to forum.hr IPs; persistent non-browser sessions ≥5 min |
| Response | Unsigned → Tier1 KillProcessTree; signed → Tier2 LogOnly |
| DNS feed | `DnsQueryMonitor` → `RecordDnsQuery` |

## v1.7.5 Additions

AV-safe PowerShell residual ports. **Not** included (high AV heuristic risk): KeyScrambler keyboard injection, FocusLock network lockdown, Preferences JSON mutation, mass browser kills.

### HardeningModule (install / ApplyOrFail)

| Capability | Source | Mechanism |
|------------|--------|-----------|
| Defender ASR Block rules (14 GUIDs) | `GEDR_ASR_Rules.ps1` + expanded set | Policy hive `...\ASR\Rules` value `"1"`; excludes prevalence-based unknown-exe rule (installer FP) |
| Credential residual | `Creds.ps1` | `RunAsPPL=1`, `DisableDomainCreds=1`, `CachedLogonsCount=2`, WDigest off |
| Browser residual | `Browsers.ps1` | WebRTC localhost IP handling policy (Chrome/Edge/Brave); CRD remote-access host policies off; disable `chrome-remote-desktop-host` / `chromoting` |

### AsrPolicyGuard (Service · Critical)

| Item | Value |
|------|--------|
| Interval | 60s (20s initial delay) |
| Check | `HardeningModule.IsAsrPolicyIntact()` — every required GUID present and Block |
| Response | Re-apply + Tier1 LogOnly Anti-Tamper detection on drift |

### RemoteSessionGuard (Service · CredentialProtection)

| Item | Value |
|------|--------|
| Source | `Credentials/ES.ps1` |
| Mechanism | `WTSEnumerateSessions` + `WTSLogoffSession` (no qwinsta/rwinsta shell) |
| Interval | 5s |
| Terminate | Non-console Active/Connected/Disconnected remote sessions |
| Never | Session 0, active console session id, WTSListen/Init/Down/Reset stubs |
| Response | Force logoff + Tier1 LogOnly (0.92) |

---

## Hardening at install (HardeningModule.ApplyOrFail)

Applied once at service start (best-effort, non-fatal failures):

1. DLL search path restriction (`SetDllDirectory` / `SetDefaultDllDirectories`)
2. IPSec GSecurity policy (50+ dangerous ports) + Safe Mode registration + RPC ephemeral block
3. Remote access service disablement (TermService, WinRM, RemoteRegistry, sshd, discovery, third-party RATs)
4. Registry security (LSA, TLS 1.3, SEHOP, Spectre/Meltdown, AlwaysInstallElevated, firewall profiles, QUIC off)
5. DEP AlwaysOn (`bcdedit /set nx AlwaysOn`)
6. LGPO import of embedded `GSecurity.inf` (only remaining intentional shell-out for policy template)
7. **v1.7.5:** ASR Block rules, credential hardening residual, browser/CRD policy hardening

Self-heal loops: `IPSecIntegrityGuard` (30s), `AsrPolicyGuard` (60s), plus various integrity monitors.

---

## Remaining Backlog

- [x] **Agent-side monitor documentation** — Inventory complete as of 1.7.5 (includes 1.7.4 PS ports).
- [ ] **BrowserCredentialTheftRule** — Detection rule designed but never implemented as a standalone rule class (detection covered by BrowserCredentialGuard monitor).
- [ ] **Test coverage for v1.6.7+ monitors** — NamedPipeMonitor, RpcLateralMonitor, TokenTheftMonitor, CloudSyncExfilMonitor, EtwProviderTamperMonitor, BrowserC2Guard need more unit tests.
- [ ] **ThreatIntelFeedBlocker PID attribution** — `IPGlobalProperties` lacks PID; connection hits currently alert without owning process kill.
- [ ] **KeyScrambler / FocusLock** — Intentionally not ported (AV heuristics / high operational cost).
