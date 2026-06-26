# Windows Sentinel — Design Document

**Version: 1.0.2**

---

## Platform

- .NET 10, Windows only (`net10.0-windows`)
- Self-contained single-file publish for distribution
- Targets x64 and arm64

---

## Architecture Overview

Windows Sentinel follows a clean pipeline architecture with strict separation of concerns:

```
Monitors â†’ TelemetryFusionEngine â†’ DetectionEngine â†’ ResponseEngine â†’ JsonlEventLogger
                    â†“                      â†‘               â†“
               EventGraph          BehavioralCorrelationEngine
           (queryable graph)              â†‘               â†“
                                   (composite detections via EmitAsync)
                                                     ChainTracer (kill + quarantine)
```

All components are wired via Microsoft.Extensions.DependencyInjection. No static mutable state anywhere.

### 1.0.0 Addition: Telemetry Fusion Layer

Every monitor feeds raw telemetry through the `TelemetryFusionEngine` before the `DetectionEngine`. The fusion layer:
1. Enriches events with cross-source context
2. Builds temporal event chains per-process
3. Maintains the `EventGraph` for causal/temporal queries
4. Produces `FusedTelemetryContext` with behavioral velocity, diversity, and multi-vector flags

The fusion layer is PASSIVE â€” it never blocks, kills, or modifies telemetry.

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
| `LsassDumpCanaryMonitor` | Scans system-wide process handles for unauthorized lsass.exe read access every 45s | Yes (PROCESS_DUP_HANDLE) |
| `CredentialCanaryMonitor` | Windows Credential Manager canary via `CredWrite`/`CredRead` | No |
| `ParentPidSpoofDetector` | Compares ETW-reported parent PID vs snapshot-reported parent | Yes (requires ETW) |
| `FileActivityMonitor` | `FileSystemWatcher` on user profile (or configured path) | No |
| `HollowProcessMonitor` | `GetMappedFileName` + `EnumProcessModules` P/Invoke, scans every 30s | No (own integrity level) |
| `PhantomKeystrokeGuard` | **0.8.3** Intercepts and actively blocks software-injected keystrokes (e.g., via `SendInput`) to prevent automated typing via global `WH_KEYBOARD_LL` hook. | No |
| `ScreenCaptureMonitor` | **1.5.0** Detects background DXGI screen capture + transparent overlay phishing windows via `EnumWindows` + `GetWindowLong`, scans every 15â€“25s | No |
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
| `ArpSpoofMonitor` | **3.6.0** Polls ARP table via GetIpNetTable. Detects gateway MAC change, ARP table poisoning, virtual OUI on gateway. Scans every 5s | No |
| `GatewayFingerprintMonitor` | **3.6.0** Monitors gateway IP, DNS servers, DHCP server, subnet mask. Detects evil twin, rogue DHCP, DNS hijack. Scans every 15s | No |
| `PublicIpMonitor` | **3.6.0** Checks public IP via Cloudflare/ipify/icanhazip. Detects geo/ASN shift, VPN hijack, network isolation. Checks every 2min | No |
| `RouteTableMonitor` | **3.6.0** Polls routing table via GetIpForwardTable. Detects route injection, default route hijack, next-hop modification. Scans every 10s | No |
| `DnsResponseValidationMonitor` | **3.6.0** Resolves canary domains and validates against expected CIDR ranges. Detects DNS poisoning, captive portal. Checks every 1min | No |
| `TlsCertificateMonitor` | **6.3.0** Monitors the Windows `LocalMachine\Root` certificate store. Baselines existing certs silently at startup; alerts on new root CAs added after baseline. Never auto-removes. Polls every 60s | No |
| `WifiSecurityMonitor` | **3.6.0** Polls Wi-Fi state via netsh. Detects deauth flood, open network, encryption downgrade, BSSID change. Scans every 10s | No |
| `NetworkInterfaceGuard` | **0.8.4** Periodically (every 15s) scans adapters, removes bridges via SetupAPI, restores disabled physical adapters via WMI, locks NameServer settings, and enforces DoH. | No |
| `BluetoothMonitor` | **3.6.0** Monitors BT device registry and service state. Detects BadBT HID pairing, unauthorized devices, BT activation. Scans every 15s | No |
| `SecureBootIntegrityMonitor` | **3.6.0** Checks Secure Boot, test signing, kernel debug via registry+bcdedit. Scans every 5min | Yes (bcdedit) |
| `FirewallIntegrityMonitor` | **3.6.0** Polls firewall profiles via netsh advfirewall. Detects profile disabled, bulk rules, service stopped. Scans every 30s | No |
| `ScheduledTaskMonitor` | **3.6.0** Polls scheduled tasks via schtasks. Detects malicious task creation with suspicious command/path analysis. Scans every 30s | No |
| `WindowsUpdateIntegrityMonitor` | **3.6.0** Monitors WU/BITS services and auto-update registry. Detects update suppression, Defender staleness. Checks every 2min | No |
| `GhostProcessMonitor` | **0.7.1** Detects PIDs with active outbound TCP connections whose process name is empty or unresolvable. Catches PlugX/ShadowPad DLL sideloading blind spot where RAT connections persist under hollowed PIDs. Network-isolates on masquerade ports (5228, 8009, 4443). Scans every 15s | No |
| `ShellWatchdog` | **0.7.1** Monitors explorer.exe responsiveness via `SendMessageTimeout`. Auto-restarts shell on death. Detects cross-process hangs (AppHangXProcB1) and repeated crashes indicating active shell attack. Scans every 5s | No |
| `CriticalServiceGuard` | **0.7.1** Monitors 15 critical Windows services for repeated crash patterns via SCM event log polling (Event 7034/7031). Detects exploitation indicators (STATUS_STACK_BUFFER_OVERRUN). Monitors BSOD-critical processes for debugger kill switches. Scans every 10s | No |
| `HostsFileGuard` | **0.8.7** Monitors `drivers\etc` directory. Enforces embedded hosts file content (SHA-256 verified). Deletes all other files (hosts.ics, lmhosts.sam, etc.) as bypass vectors. FileSystemWatcher + 30s periodic check. KillProcessTree on modifier. | Yes (SYSTEM write to System32) |
| `BrowserDnsPolicyGuard` | **0.8.7** Disables DNS-over-HTTPS system-wide: Windows OS (EnableAutoDoh=0), Chrome, Edge, Brave, Vivaldi, Opera, Chromium (BuiltInDnsClientEnabled=0, DnsOverHttpsMode=off), Firefox (DNSOverHTTPS.Enabled=0, Locked=1). 15s self-healing. Ensures hosts file is authoritative. | Yes (registry write) |
| `MtpTransferGuard` | **0.8.8** Blocks non-media file transfers to MTP devices (phones/tablets). Allows only images, video, audio, and mobile app packages (APK/IPA). Kills transferring process on violation. Detects WPD API usage via loaded module scanning + WPDNSE staging directory monitoring. 5s scan interval. | No |
| `VolumeMountMonitor` | **1.0.1** Detects new volume mounts at runtime: RAM disks (ImDisk, OSFMount, SoftPerfect, Arsenal), PMEM/DAX, VeraCrypt/encrypted containers, VHD/VHDX. Classifies volume type and dynamically extends FileActivityMonitor to cover new drives. WMI Win32_Volume polling every 5s. | No |
| `WslMonitor` | **1.0.1** Monitors WSL process spawns, suspicious command execution inside WSL, new distro installs, and processes running from \\wsl$ filesystem. Tracks wsl.exe/wslhost.exe/bash.exe activity. Scans every 10s. | No |
| `RawDiskAccessMonitor` | **1.0.1** Detects processes opening raw disk device paths (\\.\PhysicalDrive, \Device\Harddisk) via NtQuerySystemInformation handle enumeration. Bypasses filesystem-level monitoring. Allows known disk management/backup tools. Scans every 20s. | Yes (PROCESS_DUP_HANDLE) |
| `NetworkShareMonitor` | **1.0.1** Monitors SMB/network share activity: new drive mappings, admin share access (C$, ADMIN$, IPC$), inbound SMB sessions. Uses NetFileEnum/NetSessionEnum. Detects lateral movement patterns. Scans every 15s. | No |
| `EphemeralProcessMonitor` | **1.0.1** Catches short-lived processes that exit before WMI reports them via Prefetch file monitoring (FileSystemWatcher + periodic scan) and Security Event ID 4688 polling. Detects self-deleting droppers. Scans every 5s. | Yes (Prefetch access) |
| `PrintSpoolerMonitor` | **1.0.1** Monitors print spooler for data exfiltration: bulk spool file creation, suspicious files in spool directory, XPS output creation. FileSystemWatcher on spool\PRINTERS + periodic scan every 15s. | No |
| `SandboxEscapeMonitor` | **1.0.1** Monitors Windows Sandbox, Docker containers, and Hyper-V for escape indicators: privileged containers, host namespace access, sensitive path mappings in .wsb files, processes spawned by container runtime from host paths. Scans every 15s. | No |
| `AppDnsExfilMonitor` | **1.0.1** Detects application-level DNS-over-HTTPS bypass where non-browser processes communicate directly with known DoH resolvers (Cloudflare, Google, Quad9, etc.) on port 443, evading Windows DNS Client event log and hosts file. Scans every 10s. | No |
| `CastDeviceGuard` | **1.0.2** Baselines Cast protocol devices (port 8008/8009) on LAN at startup. Detects Chrome/browser connections to non-baselined Cast devices. Validates Google OUI MAC prefix to distinguish real Chromecasts from rogue relay devices. Kills connections to non-Google-OUI post-boot devices. Correlates with PhantomDeviceMonitor. Scans every 10s. | No |

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
| `BeaconingDetector` | Statistical C2 beacon detection. Tracks inter-connection intervals per `(ProcessId, RemoteAddress, Port)`. Fires when CV < 0.40 with 5+ observations. **v0.8.2:** Multi-factor Authenticode trust verification (WinVerifyTrust + path + diversity + baseline) demotes response for verified-legitimate software. Detection always fires and logs. |
| `ScoringEngine` | Weighted multi-factor threat scoring with source weights, category base scores, corroboration bonuses. |

### Detection Rules

#### Tier 1 â€” Behavioral (active response allowed via President's Law)

Only rules whose name matches a President's Law fragment can trigger kills. All others are log-only regardless of tier.

| Rule | Key Signals | Confidence Range | Notes (v1.1.0) |
|------|-------------|-----------------|----------------|
| `LsassAccessRule` | LSASS-targeting cmdline tokens, dump file names | 0.85â€“0.92 | Behavioral only. Placeholder hashes removed. |
| `LsassDumpCanaryMonitor` | Active process handles holding read rights to lsass.exe | 0.90 | NEW. Tier1 Behavioral, kill-authorized. |
| `ReverseShellRule` | Encoded PowerShell, LOLBins, C2 ports, C2 framework strings | 0.80â€“0.93 | |
| `ProcessInjectionRule` | Injection API names in cmdline | 0.78â€“0.92 | Tool-name matching demoted to metadata. Parent-child is Tier2. |
| `RansomwareDetectionRule` | Shadow copy deletion, bulk renames, I/O rate, 100+ extensions | 0.68â€“0.99 | Multi-signal weighted scoring. |
| `EtwTamperingRule` | AMSI bypass, ETW patching, event log clearing, AV/EDR termination | 0.85â€“0.95 | |
| `ThreatIntelInjectionRule` | Kernel-observed VirtualAllocEx, VirtualProtect RWX, MapViewOfSection, APC, SetThreadContext | 0.72â€“0.93 | Strongest injection signal (kernel-level). |
| `SyscallStubMonitor` | ntdll/amsi function prologue modification in own process | 0.97 | Self-protection â€” President's Law. |
| `BeaconingRule` | Statistical CV analysis of connection intervals | 0.70â€“0.95 | |
| `HollowProcessRule` | Image path vs mapped file mismatch | 0.75â€“0.92 | |
| `PersistenceRule` | Registry Run keys, scheduled tasks, WMI subscriptions, service creation | 0.80â€“0.92 | |
| `PrivilegeEscalationRule` | UAC bypass, token manipulation, named pipe impersonation | 0.80â€“0.95 | |
| `AttackToolsRule` | Known C2 frameworks, credential tools, AD tools, LOLBin abuse | 0.75â€“0.97 | |
| `CampaignIocRule` | Known malicious hashes, domains, IPs, campaign patterns | 0.78â€“0.92 | |

#### Tier 2 â€” Corroborating Signals (log only, feeds correlation engine)

These never kill independently. Multiple Tier2 signals on the same PID within 120s can produce a composite kill.

| Rule | Key Signals | Confidence Range | Notes (v1.1.0) |
|------|-------------|-----------------|----------------|
| `DnsQueryMonitor` | DGA domains (entropy > 3.8), DNS tunneling (>30 qpm) | 0.60â€“0.90 | NEW. |
| `ParentPidSpoofDetector` | ETW parent â‰  snapshot parent | 0.95 | NEW. Near-zero FP. |
| `TokenIntegrityMonitor` | Mediumâ†’High integrity without consent.exe | 0.93 | NEW. |
| `CredentialCanaryMonitor` | Honeypot credential accessed/deleted | 0.98â€“0.99 | NEW. Zero-FP, no PID. |
| `UnsignedBinaryRule` | Unsigned binary outside system paths, staging path boost | 0.50â€“0.68 | |
| `HighEntropyRule` | Shannon entropy > 4.2 on process name stem, GUID exclusion | 0.30â€“0.85 | |
| `SuspiciousImportsRule` | Injection APIs in command line, recon commands, persistence patterns | 0.30â€“0.65 | |

#### Composite Detections (BehavioralCorrelationEngine)

Composite detections are emitted as Tier1 `DetectionEvent`s directly into the detection stream via `EmitAsync`, bypassing the rule pipeline. Requires signals from different sources (distinct SignalTypes) within a 60-second window on the same PID.

| Composite | Confidence | Trigger Combination |
|-----------|-----------|---------------------|
| Active Ransomware Chain | 0.99 | 2+ distinct ransomware signals from different rules |
| Injected C2 Beacon | 0.98 | Kernel-observed injection (ThreatIntel ETW) + C2 network |
| Credential Dump + Exfiltration | 0.96 | LSASS/credential access + outbound network |
| In-Memory Implant Active | 0.96 | Memory anomaly (injection/RWX) + network callback |
| Fileless Attack Chain | 0.95 | AMSI/ETW/security evasion + shell or C2 |
| DGA + C2 Beaconing | 0.94 | High-entropy/rapid DNS + periodic beacon |
| Dropped Payload Active | 0.93 | Unsigned/staged binary + C2 communication |
| Spoofed Process Phoning Home | 0.92 | PPID spoofing + network communication |
| Evasion + Persistence Install | 0.91 | Security evasion + persistence mechanism |
| Escalation + C2 Channel | 0.90 | Privilege escalation + outbound C2 |

**Design:** Evaluated in confidence order (highest first). First match wins. All produce KillProcessTree. Redundant variants (e.g., "Staged Payload + Non-Standard Port", "Covert RAT", "Unsigned with Sustained C2") were consolidated into "Dropped Payload Active" since they fire on the same signal combination. Surveillance composites (Camera/Mic + Network) removed because underlying signal sources are shallow (registry polling only, no actual DXGI/Media Foundation detection).

### Logging

`JsonlEventLogger` writes newline-delimited JSON to `%ProgramData%\WindowsSentinel\events.jsonl`.

- Thread-safe via `SemaphoreSlim`
- No string-built JSON â€” `System.Text.Json` only
- Size-based rotation at 50 MB, up to 5 rotated files (`events.jsonl.1` â€¦ `.5`)
- Each line: `{"type":"detection"|"response","timestamp":"...","data":{...}}`
- Rate-limited: max 100 entries/second, burst of 200 â€” prevents log flooding attacks
- `FileShare.ReadWrite` â€” concurrent readers (SIEMs, forensic tools) never blocked
- **Graceful degradation:** If the log file cannot be opened at startup, the service starts in degraded mode (detections processed but not persisted) and logs a warning
- **Self-healing:** On each write, if the writer is null, it retries opening the file â€” auto-recovers when the file becomes accessible
- **Stale file handling:** If the file is locked or inaccessible, renames it to `.stale.<timestamp>` and creates fresh

---

## Key Design Rules

- **Dependency Injection** â€” all components receive dependencies via constructor injection
- **No static mutable state** â€” `ConcurrentDictionary`, `Channel<T>`, `SemaphoreSlim` for shared state
- **CancellationToken everywhere** â€” no `Thread.Sleep`, no blocking waits without cancellation
- **No silent failures** â€” all exceptions caught and logged; monitors fail independently
- **Graceful degradation** â€” ETW â†’ WMI fallback; ThreatIntel ETW unavailable â†’ log warning and continue; ProcessAncestryCache Toolhelp32 â†’ WMI fallback on Server Core
- **Startup self-test** â€” Verifies ETW, DPAPI, quarantine, log file, and rule loading before activating monitors
- **Tier2 enforcement** â€” `ResponseEngine` hard-codes `LogOnly` for all `Tier2Indicator` events regardless of configuration
- **Deduplication** â€” `DetectionEngine` suppresses identical `(RuleName, ProcessId)` pairs within 60s; `NetworkMonitor` suppresses identical `(pid, remote, port)` alerts within 5 minutes
- **Atomic snapshot** â€” `ProcessAncestryCache` uses `volatile IReadOnlyDictionary` swap; readers never block
- **All disposable objects disposed** â€” `IAsyncDisposable` throughout; `SentinelService.StopAsync` disposes all components in order

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
| `LogOnly` | Always for Tier2; Tier1 when `--active-response` is not set; Tier1 non-President's-Law rules |
| `KillProcess` | Tier1 President's Law rules only, with `--active-response`, confidence â‰¥ 0.85, via ChainTracer |
| `SuspendProcess` | Reserved for future use |
| `AlertUser` | Reserved for future use |

---

## Removed in 1.0.0

| Component | Reason |
|-----------|--------|
| `ResponseEngine` | Superseded by `AdvancedResponseEngine` |
| `LearningModeService` | Protection is active by default; dead code |
| Key Scrambler (agent) | Security theater â€” fake keystroke injection ineffective against real keyloggers |
| Password Rotator | Disabled stub that did nothing |

## Changed in 1.1.0

| Component | Change | Reason |
|-----------|--------|--------|
| `LsassAccessRule` | Removed `KnownDumperHashes` (placeholder values) and `CheckHashMatch()` | Fake hashes gave false confidence. Hash reputation handled by live API. |
| `ProcessInjectionRule` | Tool-name matching no longer triggers detection | Trivially bypassed by renaming. Demoted to metadata enrichment. |
| `SecureCacheStore` | Format v2: boot-nonce-bound HMAC key | Defeats SYSTEM-context replay from previous boot sessions. |
| `DumperNames` list | Retained for threat intel correlation only | Not used for detection decisions â€” clearly documented. |

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
| `BeaconFlooder` | Floods identified C2 server with 50+ fake beacon check-ins + 20 protocol confusion payloads |
| `ClipboardPoisonTactic` | Replaces clipboard with fake AWS keys, SSH keys, crypto addresses |
| `FileTrapTactic` | Deploys sparse file bombs (500GB), symlink loops, polyglot files (PDF/XLSX/DOCX), corrupted archives (tar.gz/7z), and file locks |
| `EnvironmentPoisoner` | Corrupts proxy, TLS, and persistence registry settings (HKCU only) |
| `HoneypotWeaponizer` | Deploys weaponized fake credentials, zip bombs, wallet seeds, VPN configs |
| `NetworkHoneypotDeployer` | Spins up fake SMB/RDP/HTTP/SSH listeners as lateral movement traps (30min lifetime) |

## Added in 2.8.0

| Component | Purpose |
|-----------|---------|

## Added in 2.8.1

| Component | Purpose |
|-----------|---------|
| `Architecture Hardening & Bug Fixes` | Fixes filename parsing metadata collision in `QuarantineManager`, process handle leaks in `HardeningModule`, named kernel object premature GC in `ImplantDestabilizer`, sync-over-async blocking, process name resolution in network telemetry, honeypot lifetime truncation, and NTP-resistant boot-bound nonce generation. |

## Added in 3.0.0

| Component | Purpose |
|-----------|---------|
| `SecurityValidation` | Centralized input validation utility â€” filenames, paths, IPs, PIDs, ports, timestamps, secure comparison. |
| `RateLimiter` / `BurstRateLimiter` | Thread-safe rate limiting with burst capability for response actions. |
| `SafeExecution` | Retry, timeout, circuit breaker, and performance measurement patterns. |
| `ConfigurationValidation` | Startup validation framework for all configuration sections. |
| `ConfigIntegrityMonitor` | Runtime detection of config/executable tampering (SHA-256 baseline, 5-min checks). |
| `SentinelHealthCheck` | Structured health checks: process, memory, handles, log file, quarantine, thread pool. |
| `SentinelMetrics` | Performance counters with histograms (P50/P90/P95/P99) for detection, response. |
| `SecureHttpClientFactory` | TLS 1.2+ enforcement, domain allowlisting, certificate validation for threat intel APIs. |
| `StructuredLoggingExtensions` | BeginScope helpers for consistent operation context in all log entries. |
| `QuarantineFileAtomicAsync` | Atomic quarantine: encryptâ†’moveâ†’delete prevents race conditions. |
| `DllUnloadEngine` improvements | IDisposable, burst rate limiter, async API, validation, safe unload. |

## Added in 3.1.0

| Component | Purpose |
|-----------|---------|
| `SentinelMetrics` wiring | DetectionEngine and AdvancedResponseEngine now record metrics (detection rate, response latency, FP tracking). |
| `HashReputationService` cache | Two-tier caching (in-memory + DPAPI-encrypted disk) cuts API calls by 90%+. |
| `NamedPipeMonitor` | Detects C2/lateral movement via named pipe pattern matching (Cobalt Strike, PsExec, Impacket, Metasploit). |
| `WmiPersistenceMonitor` | Periodic WMI namespace scan for planted event subscription persistence (T1546.003). |
| `StartupSelfTest` | Verifies ETW, DPAPI, quarantine, log file, and rule loading on service start. |
| Watchdog HMAC signing | Heartbeat file HMAC-signed with DPAPI-derived key â€” unforgeable without SYSTEM access. |
| `ProcessAncestryCache` WMI fallback | Falls back to `Win32_Process` WMI query when Toolhelp32 fails (Server Core/IoT). |

## Added in 3.2.0

| Component | Purpose |
|-----------|---------|
| `ChromeCredentialGuardMonitor` | Monitors Chromium browser credential files (Login Data, Cookies, Local State) for unauthorized access. Detects copy-then-read infostealer patterns. Covers Chrome, Edge, Brave, Opera, Vivaldi, Arc. |
| `FirefoxCredentialGuardMonitor` | Monitors Firefox/Gecko credential files (key4.db, logins.json, cookies.sqlite). Firefox cookies are UNENCRYPTED â€” trivial to steal. Covers Firefox, Waterfox, Pale Moon, Thunderbird. |
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

## Added in 3.4.0

| Component | Purpose |
|-----------|---------|
| President's Law expansion (AdvancedResponseEngine) | Kill list expanded with: `confirmed lsass dump`, `lsass dump`, `campaign:`, `rat activity`, `remote access trojan`, `confirmed rat`, `apt:`, `uac bypass: exploited`, `uac bypass: active exploitation`, `process hollowing`, `process injection: confirmed`, `hollow process`, `keylogger`, `keystroke capture`, `input capture`, `reverse shell`, `interactive shell: outbound`. |
| Campaign confidence threshold | New `CampaignCorroboratedThreshold = 0.75` for campaign IOCs (vs 0.85 default). Campaign rules already correlate multiple signals internally. |
| Host-level composite resolution | `HandleHostLevelCompositeAsync` resolves PID 0 composites by extracting offending PIDs from evidence text, then dispatches kill actions against resolved processes. |
| `ExtractPidsFromEvidence` | Regex-based PID extraction from composite evidence strings (matches "PID XXXX" patterns). |
| Agent kill list sync | `AgentResponseEngine.KillFragments` expanded to include RAT campaigns, keyloggers, reverse shells, credential dumps, data exfiltration. |

## Added in 3.5.0

| Component | Purpose |
|-----------|---------|
| `EvaluateCovertRatBehavioral` (BehavioralCorrelationEngine) | Novel RAT composite: unsigned binary from staging path + sustained network/beaconing. Kills RATs without campaign IOCs. Confidence 0.88-0.92. |
| `EvaluateConfirmedBeaconingFromUnsigned` (BehavioralCorrelationEngine) | Unsigned binary + periodic beaconing pattern = confirmed C2. Confidence 0.88-0.93. |
| `EvaluateUnsignedWithSustainedC2` (BehavioralCorrelationEngine) | Unsigned binary + 60s+ sustained outbound connection. Catches PlugX-style persistent HTTPS C2. Confidence 0.90. |
| C2 composite kill promotion | Existing composites promoted to kill-authorized: Injected C2 Beacon (0.98), DGA + C2 Beaconing (0.94), Spoofed Process Phoning Home (0.92), Dropped Payload Phoning Home (0.93), Staged Payload + Non-Standard Port (0.92). |
| Kill fragments (service + agent) | Added: `covert rat:`, `covert c2:`, `confirmed c2 beacon:`, `injected c2 beacon`, `dga + c2 beaconing`, `spoofed process phoning home`, `dropped payload phoning home`, `staged payload + non-standard port`. |

## Added in 3.6.0

| Component | Purpose |
|-----------|---------|
| `ArpSpoofMonitor` | ARP table integrity monitoring via GetIpNetTable P/Invoke. Detects gateway MAC change (ARP spoof), MAC duplication (ARP poisoning), virtual OUI on gateway (VM-based MITM). |
| `GatewayFingerprintMonitor` | Comprehensive network fingerprint baseline (gateway, DNS, DHCP, subnet). Detects evil twin AP, rogue DHCP, DNS server hijack, subnet change. |
| `PublicIpMonitor` | Public IP baseline via Cloudflare/ipify/icanhazip. Detects VPN hijack, BGP manipulation, geo/ASN shift, network isolation. |
| `RouteTableMonitor` | Routing table integrity via GetIpForwardTable P/Invoke. Detects static route injection, selective traffic redirection, default route hijack. Filters VPN/Docker/Hyper-V routes. |
| `DnsResponseValidationMonitor` | DNS response validation against hardcoded CIDR ranges for canary domains. Detects DNS poisoning, captive portal (all domains â†’ same IP). |
| `TlsCertificateMonitor` | Monitors the Windows Root certificate store (`LocalMachine\Root`). Baselines all existing certs silently at startup; detects newly added root CAs at runtime. Scores by validity, revocation info, subject patterns, and expiration. Alerts only — never auto-removes certificates. |
| `WifiSecurityMonitor` | Wi-Fi state monitoring via netsh. Detects deauthentication flood (rapid disconnect pattern), open network connection, encryption downgrade (evil twin), BSSID change. |
| `BluetoothMonitor` | Bluetooth attack surface monitoring via registry + service state. Detects BadBT HID device pairing, unauthorized device pairing, unexpected BT activation. |
| `SecureBootIntegrityMonitor` | Boot integrity via registry + bcdedit. Detects Secure Boot disabled, test signing mode (rootkit vector), kernel debugging enabled. |
| `FirewallIntegrityMonitor` | Windows Firewall integrity via netsh advfirewall. Detects profile disabled, bulk inbound rule additions, firewall service stopped. |
| `ScheduledTaskMonitor` | Scheduled task persistence detection via schtasks. Detects malicious task creation with multi-indicator analysis (suspicious paths, encoded commands, SYSTEM from user paths, script execution). |
| `WindowsUpdateIntegrityMonitor` | Update service integrity monitoring. Detects WU/BITS service stopped, automatic updates disabled via registry/GPO, Defender definitions stale (>7 days). |
| `GhostProcessMonitor` | **0.7.1** Detects PIDs with active outbound TCP but empty/unresolvable process names. Covers PlugX/ShadowPad DLL sideloading blind spot. Network-isolates connections to masquerade ports (5228, 8009). Requires 2+ sightings to avoid startup races. |
| `ShellWatchdog` | **0.7.1** Explorer.exe health monitor. SendMessageTimeout responsiveness check every 5s. Auto-restarts dead shell. Detects AppHangXProcB1 cross-process hangs and repeated crash patterns (active shell attack). |
| `CriticalServiceGuard` | **0.7.1** Monitors critical Windows services (TokenBroker, Defender, Firewall, EventLog, etc.) for crash storms via SCM events. Detects exploitation patterns (0xC0000409 stack buffer overrun). Monitors BSOD-critical processes for debugger kill switches. |

## Added in 0.8.8

| Component | Purpose |
|-----------|---------|
| `MtpTransferGuard` | Bidirectional MTP firewall. Outbound (PC→Phone): blocks non-media/app file transfers by killing WPD processes transferring dangerous content. Inbound (Phone→PC): deletes executables, scripts, archives, macros arriving from MTP devices via WPDNSE staging + drop target monitoring. 5s scan interval. |

## Added in 0.8.7

| Component | Purpose |
|-----------|---------|
| `HostsFileGuard` | Self-healing monitor for `drivers\etc`. Enforces embedded trusted hosts content (ad/tracker blocklist + FCM push block hardcoded in binary). Deletes ALL other files in the directory (hosts.ics, lmhosts.sam, networks, protocol, services) — they serve as bypass vectors. FileSystemWatcher + 30s periodic SHA-256 integrity check. KillProcessTree on identified modifier. |
| `BrowserDnsPolicyGuard` | System-wide DoH kill. Disables DNS-over-HTTPS at Windows OS level (EnableAutoDoh=0), all Chromium browsers (Chrome, Edge, Brave, Vivaldi, Opera, Chromium via BuiltInDnsClientEnabled=0 + DnsOverHttpsMode=off), and Firefox (DNSOverHTTPS.Enabled=0, Locked=1). 15s self-healing interval. Ensures the hosts file is authoritative for all DNS resolution. |

## Added in 0.8.4

| Component | Purpose |
|-----------|---------|
| `NetworkInterfaceGuard` | Monitors and protects network adapters: uninstalls bridges via SetupAPI, re-enables disabled primary physical adapters via WMI, and locks DNS registry NameServer settings. |
| `ArpSpoofMonitor` lock | Dynamic static gateway ARP cache lock via `CreateIpNetEntry` to prevent ARP redirection/spoofing attacks. |
| `WifiSecurityMonitor` toggle | Wi-Fi adapter toggling via WMI to recover from deauthentication floods. |

## Added in 5.5.0

| Component | Purpose |
|-----------|---------|
| `FileActivityMonitor` fix | Excluded common game directories, launchers, and publisher folders (Steam, Epic, My Games, Sports Interactive, etc.) from Restart Manager handle queries to generally prevent file lock contention and sharing violations for all games. |
| `RansomwareIoMonitor` whitelist | Added `fm` and `fm.exe` to the process whitelist to prevent false behavioral ransomware alerts during high match simulation and save activity. |
| `AntiTamperGuard` | **New background watchdog service.** Prevents EDR process termination (denies `PROCESS_TERMINATE` to non-SYSTEM handles), detects process suspension gaps (NtSuspendProcess), auto-heals SCM registry service entries/paths, and enforces agent login Run key persistence. |
| `FileActivityMonitor` DLL block | **Global DLL Sideloading Block.** Intercepts writes of `dbghelp.dll`/`dbgcore.dll` in non-system paths by untrusted processes, deleting the file and killing the writer immediately to prevent successful sideload execution without causing target application crashes. |
| Native ACL folder lockdown | Enforces NTFS folder permissions on `C:\Program Files\WindowsSentinel` natively using DirectorySecurity to allow only SYSTEM/Administrators modification access and Users read/execute access, blocking icacls LOLBin command executions. |
| Sentinel Folder Watch | Recursively monitors Sentinel's own directory. Any unauthorized creation or modification of files is immediately blocked, the file deleted, and the responsible process terminated. |
| `TrayIconService` alerts | Tails `events.jsonl` in the user session to display balloon tips for detections with integrated `RateLimiter` protection (max 3 alerts per 5s) to prevent notification flooding/spam. |

## Added in 4.5.0

| Component | Purpose |
|-----------|---------|
| `ClipboardSanitizer` | Active clipboard sanitization every 2s on STA thread. Strips zero-width chars (U+200B/C/D, FEFF, 2060), RTL overrides (U+202A-E), Cyrillic homoglyphs (a/e/o/p/c), invisible Unicode tags (U+E0001-E007F). Emits Tier2 detection on sanitization. Prevents chat injection, filename spoofing, phishing URL obfuscation. |
| `AppNetworkPolicyMonitor` | Per-app network destination learning and enforcement. 30-min learning phase records /24 subnets per process. After learning, alerts on new destinations (Tier2, 0.55). Uses GetExtendedTcpTable. Caps: 1K subnets/process, 5K total. Hourly prune. |
| `UsbDeviceFingerprinter` | USB device baseline via WMI (Win32_PnPEntity). Fingerprints by VID:PID:Serial. Detects: BadUSB unknown HID (Tier1/0.80), composite devices (Tier1/0.75), new mass storage (Tier2/0.50), other new devices (Tier2/0.40). Known-good VID allowlist for 9 major peripheral manufacturers. |
| Test suite expansion | 27 new tests covering ClipboardSanitizer, AppNetworkPolicy, UsbFingerprinter, EventGraph memory caps, AudioHijack module hints, RouteTable exclusions. Total: 367 tests. |

## Added in 4.4.0

| Component | Purpose |
|-----------|---------|
| `RouteTableMonitor` fix | Excluded multicast (224.0.0.0/4) and broadcast (255.255.255.255) from next-hop change detection. Eliminates 104 false alerts per session from normal DHCP renewal behavior. |
| `MemoryExecutionRule` fix | Added svchost.exe exclusion to fileless execution detection. svchost instances launched by SCM may not have resolvable image paths. |
| `DataExfiltrationMonitor` fix | Added fallback trust for sandboxed Microsoft processes (msedgewebview2, SearchHost, widgets, backgroundTaskHost) when path verification fails due to access restrictions. |
| `DnsQueryMonitor` fix | Added dotnet/nuget to DNS tunneling allowlist. Package restore and build operations legitimately burst DNS queries. |
| `AudioHijackMonitor` fix | Replaced generic multimedia DLLs (winmm.dll, mf.dll) with actual virtual audio cable indicators (vbcable, voicemeeter, wasapiloopback). |
| `EventGraph` memory fix | AddEdge() caps at 300 edges/process (trims to 150). Prune() hard caps halved. |
| `BehavioralBaselineService` memory fix | Hard caps: 5K network destinations, 3K paths, 3K parent-child. Evicts by lowest usage. |
| `HealthCheckService` GC | Non-blocking Gen2 GC.Collect every 5 minutes forces runtime to return pages to OS. |
| Console view separation | Console now launches as separate cmd.exe process. Closing it no longer kills the Agent. |
| Hidden form fix | Opacity=0 + off-screen positioning prevents the marshalling form from being visible. |
| `UserSessionLauncher` path fix | Uses Environment.ProcessPath for single-file exe compatibility. |

## Added in 4.3.0

| Component | Purpose |
|-----------|---------|
| `TrayIconService` | System tray NotifyIcon in the Agent process. Context menu: Open Console (live-tails events.jsonl with color-coded output, 1s poll), Open Quarantine Folder (Explorer), Open Event Log (Notepad), Start/Stop Protection (dynamic toggle with balloon confirmation). Balloon tip notifications for Tier1 detections/kills. Runs on dedicated STA thread with WinForms ApplicationContext message pump. FreeConsole on startup to detach from CreateProcessAsUser console. |
| `AudioHijackMonitor` fix | Removed false-positive-prone generic DLLs (winmm.dll, mf.dll, mfreadwrite.dll, directsound) from MicInputModuleHints. Replaced with actual output-to-mic routing indicators (virtual cable drivers, loopback capture DLLs). |
| `EventGraph` memory fix | AddEdge() now caps at 300 edges per process (trims to 150 when hit). Prune() thresholds halved. Prevents 3GB+ memory growth on busy systems. |
| `ToastNotificationService` | Removed WTSSendMessage modal popups from SYSTEM service. User notifications delegated to Agent tray icon balloons. |
| `UserSessionLauncher` path fix | Uses Environment.ProcessPath instead of AppContext.BaseDirectory for single-file exe compatibility. |
| Registry Run key | HKLM Run entry for Agent auto-start on login (installer). Primary launch mechanism replacing unreliable CreateProcessAsUser. |

---

## Monitoring Coverage by Elevation Level

| Capability | Standard User | Elevated (Admin) |
|-----------|--------------|-----------------|
| Process start events | WMI fallback | ETW kernel provider |
| Injection API calls | âŒ | ETW Threat Intelligence provider |
| DNS query monitoring | âŒ | ETW DNS-Client provider |
| Parent PID spoof detection | âŒ | ETW + snapshot comparison |
| Network connections (IPv4+IPv6 TCP/UDP) | âœ… | âœ… |
| File rename/write activity | âœ… | âœ… |
| Hollow process detection | âœ… (same integrity) | âœ… (all processes) |
| Memory behavior analysis | âœ… (same integrity) | âœ… (all processes) |
| Syscall stub integrity | âœ… (own process) | âœ… (own process) |
| Token integrity monitoring | âœ… (limited) | âœ… (all processes) |
| LSASS dump canary (dbghelp) | âœ… (same integrity) | âœ… (all processes) |
| Credential canary | âœ… | âœ… |
| Process ancestry resolution | âœ… | âœ… |
| Named pipe C2 detection | âœ… | âœ… |
| WMI persistence scanning | âœ… | âœ… |
| Behavioral correlation | âœ… | âœ… |
| Statistical beaconing detection | âœ… | âœ… |


