# Windows Sentinel — Design Document

**Version: 3.3.0**

---

## Platform

- .NET 8, Windows only (`net8.0-windows`)
- Self-contained single-file publish for distribution
- Targets x64 and arm64

---

## Architecture Overview

Windows Sentinel follows a clean pipeline architecture with strict separation of concerns:

```
Monitors → TelemetryFusionEngine → DetectionEngine → ResponseEngine → JsonlEventLogger
                    ↓                      ↑               ↓
               EventGraph          BehavioralCorrelationEngine
           (queryable graph)              ↑               ↓
                                   (composite detections via EmitAsync)
                                                     DeceptionEngine (pre-kill)
                                                          ↓
                                                     ChainTracer (kill + quarantine)
```

All components are wired via Microsoft.Extensions.DependencyInjection. No static mutable state anywhere.

### 1.0.0 Addition: Telemetry Fusion Layer

Every monitor feeds raw telemetry through the `TelemetryFusionEngine` before the `DetectionEngine`. The fusion layer:
1. Enriches events with cross-source context
2. Builds temporal event chains per-process
3. Maintains the `EventGraph` for causal/temporal queries
4. Produces `FusedTelemetryContext` with behavioral velocity, diversity, and multi-vector flags

The fusion layer is PASSIVE — it never blocks, kills, or modifies telemetry.

---

## Component Inventory

### Monitors

| Component | Mechanism | Elevation Required |
|-----------|-----------|-------------------|
| `EtwProcessMonitor` | ETW kernel provider (`KernelTraceEventParser.Keywords.Process`) | Yes (falls back to WMI) |
| `WmiProcessMonitor` | `Win32_ProcessStartTrace` WMI event | No |
| `EtwThreatIntelMonitor` | `Microsoft-Windows-Threat-Intelligence` ETW provider | Yes (degrades gracefully) |
| `DnsQueryMonitor` | `Microsoft-Windows-DNS-Client` ETW provider | Yes (degrades gracefully) |
| `NetworkMonitor` | `GetExtendedTcpTable` / `GetExtendedUdpTable` P/Invoke, IPv4+IPv6 TCP+UDP | No |
| `FileActivityMonitor` | `FileSystemWatcher` on user profile (or configured path) | No |
| `HollowProcessMonitor` | `GetMappedFileName` + `EnumProcessModules` P/Invoke, scans every 30s | No (own integrity level) |
| `MemoryBehaviorAnalyzer` | `VirtualQueryEx` + `ReadProcessMemory`, scans every 45s | No (own integrity level) |
| `SyscallStubMonitor` | Compares ntdll/amsi function prologues against startup baseline every 10s | No (own process only) |
| `TokenIntegrityMonitor` | `GetTokenInformation(TokenIntegrityLevel)` scans every 20s | No (PROCESS_QUERY_LIMITED_INFORMATION) |
| `LsassDumpCanaryMonitor` | `EnumProcessModulesEx` checking for dbghelp.dll every 15s | No (PROCESS_QUERY_INFORMATION) |
| `CredentialCanaryMonitor` | Windows Credential Manager canary via `CredWrite`/`CredRead` | No |
| `ParentPidSpoofDetector` | Compares ETW-reported parent PID vs snapshot-reported parent | Yes (requires ETW) |
| `FileActivityMonitor` | `FileSystemWatcher` on user profile (or configured path) | No |
| `HollowProcessMonitor` | `GetMappedFileName` + `EnumProcessModules` P/Invoke, scans every 30s | No (own integrity level) |
| `ScreenCaptureMonitor` | **1.5.0** Detects background DXGI screen capture + transparent overlay phishing windows via `EnumWindows` + `GetWindowLong`, scans every 15–25s | No |
| `LocalServerMonitor` | **1.5.0** Detects suspicious processes listening on localhost via `GetExtendedTcpTable` (LISTEN state), flags mounted ISO/VHD/removable origins, scans every 30s | No |
| `WebcamMicMonitor` | **1.6.0** Detects background processes accessing camera/microphone via DLL analysis (Media Foundation, DirectShow, WASAPI). Allowlists browsers, conferencing, streaming apps. Confirmation threshold prevents transient FPs. Scans every 20s | No |
| `NamedPipeMonitor` | **3.1.0** Polls `\\.\pipe\` for C2/lateral movement pipe patterns (Cobalt Strike, PsExec, Impacket, Metasploit). Uses `GetNamedPipeServerProcessId` for owner attribution. Scans every 15s | No |
| `WmiPersistenceMonitor` | **3.1.0** Periodic WMI namespace scan for `__EventFilter`/`__EventConsumer`/`__FilterToConsumerBinding` persistence (T1546.003). Scans every 5min | No |
| `ChromeCredentialGuardMonitor` | **3.2.0** Monitors Chromium browser credential files (Login Data, Cookies, Local State, Web Data) via FileSystemWatcher + process scanning. Detects copy-then-read patterns. Covers Chrome, Edge, Brave, Opera, Vivaldi, Arc. Scans every 10s | No |
| `FirefoxCredentialGuardMonitor` | **3.2.0** Monitors Firefox/Gecko credential files (key4.db, logins.json, cookies.sqlite, cert9.db) via FileSystemWatcher. Covers Firefox, Waterfox, Pale Moon, Thunderbird. Scans every 10s | No |
| `MicrosoftAccountGuardMonitor` | **3.2.0** Monitors TokenBroker cache (.tbres), detects PRT extraction (BrowserCore abuse), Azure AD token theft tools (ROADtools, AADInternals). Scans every 12s | No |
| `BrowserExtensionMonitor` | **3.2.0** Baselines installed extensions, detects new extensions with dangerous permissions, registry force-install. Scans every 30s | No |
| `ChromeSessionGuardMonitor` | **3.2.0** Detects remote debugging port abuse, CDP connections from scripting processes, App-Bound Encryption bypass (elevation_service.exe). Scans every 15s | No |
| `PowerShellThreatMonitor` | **3.2.0** ETW script-block logging (Event ID 4104). Detects AMSI/ETW bypass, download cradles, reflective loading, offensive frameworks, credential theft commands. Falls back to cmdline scanning. | Yes (ETW preferred) |
| `WorkFoldersExfilMonitor` | **3.3.0** Detects unauthorized Work Folders activation (service running, registry config, Group Policy injection). Active response: kills service, removes config, deletes policy keys. Kill-authorized. Scans every 15s | No |

### Engine

| Component | Role |
|-----------|------|
| `DetectionEngine` | Runs all `IDetectionRule` instances against incoming telemetry. Channel-based async stream. 60s deduplication window. Records metrics via `SentinelMetrics`. |
| `AdvancedResponseEngine` | Single point of action enforcement. Tier2 is always log-only. Tier1 may kill process when `--active-response` is set. President's Law closed kill list. Records response latency and success/failure via `SentinelMetrics`. |
| `TelemetryFusionEngine` | **1.0.0** Correlates raw telemetry across all sources into per-process event chains. Produces `FusedTelemetryContext` with behavioral metrics. |
| `EventGraph` | **1.0.0** In-memory graph of processes, files, and network endpoints with temporal/causal edges. Supports incident timeline queries. |
| `MemoryBehaviorAnalyzer` | **1.0.0** Scans process memory regions every 45s for RWX, unbacked executables, and shellcode prologues. |
| `ProcessAncestryCache` | `CreateToolhelp32Snapshot` refreshed every 2s (WMI/CIM fallback for Server Core/IoT). Provides parent name resolution for all monitors and rules. |
| `BehavioralCorrelationEngine` | Time-windowed (120s) multi-signal correlator. Fires composite `DetectionEvent`s via `IDetectionEngine.EmitAsync`. |
| `BeaconingDetector` | Statistical C2 beacon detection. Tracks inter-connection intervals per `(ProcessId, RemoteAddress, Port)`. Fires when CV < 0.40 with 5+ observations. |
| `ScoringEngine` | Weighted multi-factor threat scoring with source weights, category base scores, corroboration bonuses. |
| `DeceptionEngine` | **1.7.0** Pre-kill attacker punishment. Executes hostile tactics (memory flooding, DLL stomping, stack corruption, handle pollution, beacon flooding, protocol confusion, clipboard poisoning, sparse file bombs, symlink loops, polyglot files, corrupted archives, file locking, environment poisoning, honeypot deployment, network honeypot listeners) within 2s budget before ChainTracer kills. |

### Detection Rules

#### Tier 1 — Behavioral (active response allowed via President's Law)

Only rules whose name matches a President's Law fragment can trigger kills. All others are log-only regardless of tier.

| Rule | Key Signals | Confidence Range | Notes (v1.1.0) |
|------|-------------|-----------------|----------------|
| `LsassAccessRule` | LSASS-targeting cmdline tokens, dump file names | 0.85–0.92 | Behavioral only. Placeholder hashes removed. |
| `ReverseShellRule` | Encoded PowerShell, LOLBins, C2 ports, C2 framework strings | 0.80–0.93 | |
| `ProcessInjectionRule` | Injection API names in cmdline | 0.78–0.92 | Tool-name matching demoted to metadata. Parent-child is Tier2. |
| `RansomwareDetectionRule` | Shadow copy deletion, bulk renames, I/O rate, 100+ extensions | 0.68–0.99 | Multi-signal weighted scoring. |
| `EtwTamperingRule` | AMSI bypass, ETW patching, event log clearing, AV/EDR termination | 0.85–0.95 | |
| `ThreatIntelInjectionRule` | Kernel-observed VirtualAllocEx, VirtualProtect RWX, MapViewOfSection, APC, SetThreadContext | 0.72–0.93 | Strongest injection signal (kernel-level). |
| `SyscallStubMonitor` | ntdll/amsi function prologue modification in own process | 0.97 | Self-protection — President's Law. |
| `BeaconingRule` | Statistical CV analysis of connection intervals | 0.70–0.95 | |
| `HollowProcessRule` | Image path vs mapped file mismatch | 0.75–0.92 | |
| `PersistenceRule` | Registry Run keys, scheduled tasks, WMI subscriptions, service creation | 0.80–0.92 | |
| `PrivilegeEscalationRule` | UAC bypass, token manipulation, named pipe impersonation | 0.80–0.95 | |
| `AttackToolsRule` | Known C2 frameworks, credential tools, AD tools, LOLBin abuse | 0.75–0.97 | |
| `CampaignIocRule` | Known malicious hashes, domains, IPs, campaign patterns | 0.78–0.92 | |

#### Tier 2 — Corroborating Signals (log only, feeds correlation engine)

These never kill independently. Multiple Tier2 signals on the same PID within 120s can produce a composite kill.

| Rule | Key Signals | Confidence Range | Notes (v1.1.0) |
|------|-------------|-----------------|----------------|
| `DnsQueryMonitor` | DGA domains (entropy > 3.8), DNS tunneling (>30 qpm) | 0.60–0.90 | NEW. |
| `ParentPidSpoofDetector` | ETW parent ≠ snapshot parent | 0.95 | NEW. Near-zero FP. |
| `TokenIntegrityMonitor` | Medium→High integrity without consent.exe | 0.93 | NEW. |
| `LsassDumpCanaryMonitor` | dbghelp.dll in non-debugger process | 0.85 | NEW. |
| `CredentialCanaryMonitor` | Honeypot credential accessed/deleted | 0.98–0.99 | NEW. Zero-FP, no PID. |
| `UnsignedBinaryRule` | Unsigned binary outside system paths, staging path boost | 0.50–0.68 | |
| `HighEntropyRule` | Shannon entropy > 4.2 on process name stem, GUID exclusion | 0.30–0.85 | |
| `SuspiciousImportsRule` | Injection APIs in command line, recon commands, persistence patterns | 0.30–0.65 | |

#### Composite Detections (BehavioralCorrelationEngine)

Composite detections are emitted as Tier1 `DetectionEvent`s directly into the detection stream via `EmitAsync`, bypassing the rule pipeline.

| Composite | Confidence | Trigger Combination |
|-----------|-----------|---------------------|
| Active Ransomware Chain | 0.99 | 2+ distinct ransomware signals (process + file) |
| Fileless Attack Chain | 0.95 | AMSI/ETW evasion + encoded PS or C2 network |
| Dropped Payload Phoning Home | 0.93 | Unsigned staged binary + C2 port |
| Post-Exploitation Recon Sequence | 0.88 | 3+ distinct recon command types |
| Injected C2 Beacon | 0.98 | Kernel injection (ThreatIntel) + C2 network |
| Credential Dump + Exfiltration | 0.96 | LSASS dump + outbound C2 connection |
| PPID Spoof + C2 Channel | 0.96 | Parent PID spoofing + C2 network (v1.2.0) |
| Confirmed LSASS Dump | 0.97 | dbghelp.dll loaded + LSASS-targeting (v1.2.0) |
| Privilege Escalation + Persistence | 0.94 | Token integrity change + persistence (v1.2.0) |
| DGA + C2 Beaconing | 0.95 | High-entropy DNS + periodic beacon (v1.2.0) |
| Credential Theft + Exfiltration | 0.97 | Credential canary tripped + network (v1.2.0) |
| Advanced Attack Chain | 0.98 | 2 of 3: PPID spoof + escalation + injection (v1.2.0) |
| Spoofed Process Phoning Home | 0.95 | PPID spoof + ANY network (v1.3.0) |
| Dump Tool + Network Exfil | 0.94 | dbghelp.dll + ANY outbound (v1.3.0) |
| Staged Payload + Non-Standard Port | 0.92 | Unsigned from temp + non-80/443 port (v1.3.0) |
| Mass File Operation + DNS | 0.93 | 50+ file writes + DNS resolution (v1.3.0) |
| Privilege Escalation + Network | 0.94 | Token escalation + ANY network (v1.3.0) |
| Injection Tool + File Staging | 0.91 | Injection API cmdline + file writes (v1.3.0) |
| DGA + File Operations | 0.94 | DGA DNS + ANY file access (v1.3.0) |
| In-Memory Implant + Network | 0.96 | Memory anomaly + ANY network (v1.3.0) |
| Camera/Mic Exfiltration: Capture + Network | 0.94 | Background webcam/mic access + ANY network (v1.6.0) |
| Total AV Surveillance: Camera + Screen Capture | 0.95 | Webcam/mic capture + screen capture (v1.6.0) |

### Logging

`JsonlEventLogger` writes newline-delimited JSON to `%ProgramData%\WindowsSentinel\events.jsonl`.

- Thread-safe via `SemaphoreSlim`
- No string-built JSON — `System.Text.Json` only
- Size-based rotation at 50 MB, up to 5 rotated files (`events.jsonl.1` … `.5`)
- Each line: `{"type":"detection"|"response","timestamp":"...","data":{...}}`
- Rate-limited: max 100 entries/second, burst of 200 — prevents log flooding attacks
- `FileShare.ReadWrite` — concurrent readers (SIEMs, forensic tools) never blocked
- **Graceful degradation:** If the log file cannot be opened at startup, the service starts in degraded mode (detections processed but not persisted) and logs a warning
- **Self-healing:** On each write, if the writer is null, it retries opening the file — auto-recovers when the file becomes accessible
- **Stale file handling:** If the file is locked or inaccessible, renames it to `.stale.<timestamp>` and creates fresh

---

## Key Design Rules

- **Dependency Injection** — all components receive dependencies via constructor injection
- **No static mutable state** — `ConcurrentDictionary`, `Channel<T>`, `SemaphoreSlim` for shared state
- **CancellationToken everywhere** — no `Thread.Sleep`, no blocking waits without cancellation
- **No silent failures** — all exceptions caught and logged; monitors fail independently
- **Graceful degradation** — ETW → WMI fallback; ThreatIntel ETW unavailable → log warning and continue; ProcessAncestryCache Toolhelp32 → WMI fallback on Server Core
- **Startup self-test** — Verifies ETW, DPAPI, quarantine, log file, and rule loading before activating monitors
- **Tier2 enforcement** — `ResponseEngine` hard-codes `LogOnly` for all `Tier2Indicator` events regardless of configuration
- **Deduplication** — `DetectionEngine` suppresses identical `(RuleName, ProcessId)` pairs within 60s; `NetworkMonitor` suppresses identical `(pid, remote, port)` alerts within 5 minutes
- **Atomic snapshot** — `ProcessAncestryCache` uses `volatile IReadOnlyDictionary` swap; readers never block
- **All disposable objects disposed** — `IAsyncDisposable` throughout; `SentinelService.StopAsync` disposes all components in order

---

## Telemetry Types

| Type | Source | Consumed by |
|------|--------|-------------|
| `ProcessTelemetry` | `EtwProcessMonitor`, `WmiProcessMonitor` | `LsassAccessRule`, `ReverseShellRule`, `ProcessInjectionRule`, `RansomwareDetectionRule`, `EtwTamperingRule`, `UnsignedBinaryRule`, `HighEntropyRule`, `SuspiciousImportsRule`, `PersistenceRule` |
| `NetworkTelemetry` | `NetworkMonitor` | `ReverseShellRule` |
| `FileActivityTelemetry` | `FileActivityMonitor` | `RansomwareDetectionRule` |
| `ThreatIntelTelemetry` | `EtwThreatIntelMonitor` | `ThreatIntelInjectionRule` |
| `BeaconingTelemetry` | `BeaconingDetector` | `BeaconingRule` |
| `HollowProcessTelemetry` | `HollowProcessMonitor` | `HollowProcessRule` |
| `DetectionEvent` (pipe) | `NamedPipeMonitor` | Direct emission to `DetectionEngine.ProcessAsync` |
| `DetectionEvent` (WMI) | `WmiPersistenceMonitor` | Direct emission to `DetectionEngine.ProcessAsync` |

---

## Response Actions

| Kind | When |
|------|------|
| `DeceptionPhase` | **1.7.0** Always before kill. 2s budget. Memory flooding, DLL stomping, beacon flooding, clipboard poisoning, file traps, environment poisoning, honeypot deployment. |
| `LogOnly` | Always for Tier2; Tier1 when `--active-response` is not set; Tier1 non-President's-Law rules |
| `KillProcess` | Tier1 President's Law rules only, with `--active-response`, confidence ≥ 0.85, via ChainTracer |
| `SuspendProcess` | Reserved for future use |
| `AlertUser` | Reserved for future use |

---

## Removed in 1.0.0

| Component | Reason |
|-----------|--------|
| `ResponseEngine` | Superseded by `AdvancedResponseEngine` |
| `LearningModeService` | Protection is active by default; dead code |
| Key Scrambler (agent) | Security theater — fake keystroke injection ineffective against real keyloggers |
| Password Rotator | Disabled stub that did nothing |

## Changed in 1.1.0

| Component | Change | Reason |
|-----------|--------|--------|
| `LsassAccessRule` | Removed `KnownDumperHashes` (placeholder values) and `CheckHashMatch()` | Fake hashes gave false confidence. Hash reputation handled by live API. |
| `ProcessInjectionRule` | Tool-name matching no longer triggers detection | Trivially bypassed by renaming. Demoted to metadata enrichment. |
| `SecureCacheStore` | Format v2: boot-nonce-bound HMAC key | Defeats SYSTEM-context replay from previous boot sessions. |
| `DumperNames` list | Retained for threat intel correlation only | Not used for detection decisions — clearly documented. |

## Added in 1.5.0

| Component | Purpose |
|-----------|---------|
| `ScreenCaptureMonitor` | Detects background DXGI screen capture + transparent overlay phishing windows |
| `LocalServerMonitor` | Detects suspicious processes listening on localhost (mounted ISO/VHD/removable origins) |
| Volume Dismount (ChainTracer) | Dismounts read-only media when File.Delete fails on ISO/CD-ROM/VHD |
| 5 new composite rules | Screen+Network, Screen+Clipboard, Overlay+Injection, Full Surveillance Suite |

## Added in 1.6.0

| Component | Purpose |
|-----------|---------|
| `WebcamMicMonitor` | Detects background processes accessing camera/microphone via DLL analysis |
| 2 new composite rules | Camera/Mic+Network (exfiltration), Camera+ScreenCapture (total surveillance) |
| Full Surveillance Suite update | Now 4 vectors (screen+clipboard+audio+webcam), max confidence 0.99 |

## Added in 1.7.0

| Component | Purpose |
|-----------|---------|
| `DeceptionEngine` | Orchestrates pre-kill attacker-hostile tactics within 2s time budget |
| `MemoryFloodingTactic` | Injects 256MB random garbage via VirtualAllocEx into target process |
| `ImplantDestabilizer` | DLL stomping (INT3 overwrite) + stack corruption + handle table pollution with decoy objects |
| `BeaconFlooder` | Floods identified C2 server with 50+ fake beacon check-ins + 20 protocol confusion payloads |
| `ClipboardPoisonTactic` | Replaces clipboard with fake AWS keys, SSH keys, crypto addresses |
| `FileTrapTactic` | Deploys sparse file bombs (500GB), symlink loops, polyglot files (PDF/XLSX/DOCX), corrupted archives (tar.gz/7z), and file locks |
| `EnvironmentPoisoner` | Corrupts proxy, TLS, and persistence registry settings (HKCU only) |
| `HoneypotWeaponizer` | Deploys weaponized fake credentials, zip bombs, wallet seeds, VPN configs |
| `NetworkHoneypotDeployer` | Spins up fake SMB/RDP/HTTP/SSH listeners as lateral movement traps (30min lifetime) |

## Added in 2.8.0

| Component | Purpose |
|-----------|---------|
| `Ransomware Fast-Path` | Instantly bypasses the deception engine execution window if "ransomware" is detected in rule or reasoning, terminating processes immediately to minimize encryption speed damage. |
| `x64 Context Aligned Stack Corruption` | Suspends thread and queries thread context using a native 16-byte packed CONTEXT struct, safely targeting stack pointer (Rsp) on x64 processes. |
| `Asynchronous Deception` | Refactors execution of off-host/network deception tactics (BeaconFlooder, NetworkHoneypotDeployer) into fire-and-forget background tasks. |

## Added in 2.8.1

| Component | Purpose |
|-----------|---------|
| `Architecture Hardening & Bug Fixes` | Fixes filename parsing metadata collision in `QuarantineManager`, process handle leaks in `HardeningModule`, named kernel object premature GC in `ImplantDestabilizer`, sync-over-async blocking, process name resolution in network telemetry, honeypot lifetime truncation, and NTP-resistant boot-bound nonce generation. |

## Added in 3.0.0

| Component | Purpose |
|-----------|---------|
| `SecurityValidation` | Centralized input validation utility — filenames, paths, IPs, PIDs, ports, timestamps, secure comparison. |
| `RateLimiter` / `BurstRateLimiter` | Thread-safe rate limiting with burst capability for response actions. |
| `SafeExecution` | Retry, timeout, circuit breaker, and performance measurement patterns. |
| `ConfigurationValidation` | Startup validation framework for all configuration sections. |
| `ConfigIntegrityMonitor` | Runtime detection of config/executable tampering (SHA-256 baseline, 5-min checks). |
| `SentinelHealthCheck` | Structured health checks: process, memory, handles, log file, quarantine, thread pool. |
| `SentinelMetrics` | Performance counters with histograms (P50/P90/P95/P99) for detection, response, deception. |
| `SecureHttpClientFactory` | TLS 1.2+ enforcement, domain allowlisting, certificate validation for threat intel APIs. |
| `StructuredLoggingExtensions` | BeginScope helpers for consistent operation context in all log entries. |
| `QuarantineFileAtomicAsync` | Atomic quarantine: encrypt→move→delete prevents race conditions. |
| `DllUnloadEngine` improvements | IDisposable, burst rate limiter, async API, validation, safe unload. |

## Added in 3.1.0

| Component | Purpose |
|-----------|---------|
| `SentinelMetrics` wiring | DetectionEngine and AdvancedResponseEngine now record metrics (detection rate, response latency, FP tracking). |
| `HashReputationService` cache | Two-tier caching (in-memory + DPAPI-encrypted disk) cuts API calls by 90%+. |
| `NamedPipeMonitor` | Detects C2/lateral movement via named pipe pattern matching (Cobalt Strike, PsExec, Impacket, Metasploit). |
| `WmiPersistenceMonitor` | Periodic WMI namespace scan for planted event subscription persistence (T1546.003). |
| `StartupSelfTest` | Verifies ETW, DPAPI, quarantine, log file, and rule loading on service start. |
| Watchdog HMAC signing | Heartbeat file HMAC-signed with DPAPI-derived key — unforgeable without SYSTEM access. |
| `ProcessAncestryCache` WMI fallback | Falls back to `Win32_Process` WMI query when Toolhelp32 fails (Server Core/IoT). |

## Added in 3.2.0

| Component | Purpose |
|-----------|---------|
| `ChromeCredentialGuardMonitor` | Monitors Chromium browser credential files (Login Data, Cookies, Local State) for unauthorized access. Detects copy-then-read infostealer patterns. Covers Chrome, Edge, Brave, Opera, Vivaldi, Arc. |
| `FirefoxCredentialGuardMonitor` | Monitors Firefox/Gecko credential files (key4.db, logins.json, cookies.sqlite). Firefox cookies are UNENCRYPTED — trivial to steal. Covers Firefox, Waterfox, Pale Moon, Thunderbird. |
| `MicrosoftAccountGuardMonitor` | Protects Microsoft account tokens: TokenBroker cache (.tbres), PRT extraction via BrowserCore, Azure AD token theft tools (ROADtools, AADInternals, TokenTacticsV2). |
| `BrowserExtensionMonitor` | Baselines installed extensions, detects new extensions with dangerous permission combinations, registry-based force-install (enterprise policy abuse). |
| `ChromeSessionGuardMonitor` | Detects Chrome remote debugging abuse, CDP connections from scripting processes, App-Bound Encryption bypass (elevation_service.exe spawned by non-browser). |
| `PowerShellThreatMonitor` | ETW script-block logging (Event ID 4104). Detects AMSI/ETW bypass, download cradles, reflective loading, offensive frameworks (Mimikatz, BloodHound, PowerSploit), credential theft commands, encoded commands. Falls back to cmdline scanning when ETW unavailable. |
| `BrowserCredentialTheftRule` | Process-start detection rule for browser credential theft tools. Covers Chromium paths, Firefox paths, Microsoft token paths, DPAPI patterns, known stealer tools. |
| President's Law update | `"browser credential theft"` fragment added to kill list in both AdvancedResponseEngine and AgentResponseEngine. |

## Added in 3.3.0

| Component | Purpose |
|-----------|---------|
| Electron/JIT allowlist (BehavioralCorrelationEngine) | 40+ Electron apps excluded from composite correlation. Eliminates false "In-Memory Implant + Network Beacon" and "DGA + C2 Beaconing" composites for Kiro, VS Code, Discord, Slack, Steam, etc. |
| Electron/JIT allowlist (MemoryBehaviorAnalyzer) | Expanded JIT process exclusion list with all common Electron apps. Prevents false RWX memory alerts. |
| `WorkFoldersExfilMonitor` | Detects unauthorized Work Folders activation: service state monitoring, registry config detection, Group Policy injection detection. Active response: kills service, removes config, deletes injected policies. Kill-authorized. |

---

## Monitoring Coverage by Elevation Level

| Capability | Standard User | Elevated (Admin) |
|-----------|--------------|-----------------|
| Process start events | WMI fallback | ETW kernel provider |
| Injection API calls | ❌ | ETW Threat Intelligence provider |
| DNS query monitoring | ❌ | ETW DNS-Client provider |
| Parent PID spoof detection | ❌ | ETW + snapshot comparison |
| Network connections (IPv4+IPv6 TCP/UDP) | ✅ | ✅ |
| File rename/write activity | ✅ | ✅ |
| Hollow process detection | ✅ (same integrity) | ✅ (all processes) |
| Memory behavior analysis | ✅ (same integrity) | ✅ (all processes) |
| Syscall stub integrity | ✅ (own process) | ✅ (own process) |
| Token integrity monitoring | ✅ (limited) | ✅ (all processes) |
| LSASS dump canary (dbghelp) | ✅ (same integrity) | ✅ (all processes) |
| Credential canary | ✅ | ✅ |
| Process ancestry resolution | ✅ | ✅ |
| Named pipe C2 detection | ✅ | ✅ |
| WMI persistence scanning | ✅ | ✅ |
| Behavioral correlation | ✅ | ✅ |
| Statistical beaconing detection | ✅ | ✅ |


