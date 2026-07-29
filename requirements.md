# Sentinel — Requirements

**Version: 1.7.8**

---

## Project Overview

Userland-only defensive IDS/EDR for monitoring Windows systems.  
Focus: transparency, safety, real-world threat detection, and blue-team education.

---

## Intended Use & Scope

**Designed for:**
- Personal system visibility and monitoring
- Blue-team education and security research
- Real-world detection of malware, ransomware, C2 beacons, and post-exploitation activity

**Not designed for:**
- Offensive security or red-team tooling
- Evasion or stealth monitoring
- Deployment as a managed enterprise agent

---

## Functional Requirements

### FR-1: Detection Tiers

The system must implement two detection tiers with strictly enforced response contracts:

- **Tier 1 (Behavioral):** Active response allowed when explicitly enabled
- **Tier 2 (Indicator):** Log only â€” response action is **never** permitted regardless of configuration

### FR-2: Tier 1 Detection Rules

The system must detect the following behavioral threats:

| ID | Threat | Key Technique |
|----|--------|--------------|
| T1-01 | LSASS credential dumping | Known dumper names, LSASS-targeting command patterns, dump file names |
| T1-02 | Reverse shell / C2 callback | Encoded PowerShell, LOLBin abuse, C2 framework indicators, suspicious ports |
| T1-03 | Process injection / hollowing | Known injection tools, hollowing APIs, suspicious parent-child process relationships |
| T1-04 | Ransomware activity | Shadow copy deletion, backup destruction, bulk file renames, 60+ ransomware extensions |
| T1-05 | Security tool evasion | AMSI bypass, ETW patching, event log clearing, AV/EDR process termination |
| T1-06 | Kernel-observed injection | VirtualAllocEx, VirtualProtect RWX, NtMapViewOfSection, APC injection, SetThreadContext (ETW Threat Intelligence provider) |
| T1-07 | C2 beaconing | Statistical detection via coefficient of variation on connection intervals |
| T1-08 | Process hollowing | Memory vs disk image path mismatch via GetMappedFileName |
| T1-09 | Persistence mechanisms | Registry Run/RunOnce keys, scheduled tasks, WMI event subscriptions, service creation |
| T1-10 | Privilege escalation | UAC bypass (COM, manifests), token manipulation, named pipe impersonation, DLL hijacking |
| T1-11 | Known attack tools | C2 frameworks, credential tools, network attack tools, AD attack tools, LOLBin abuse |
| T1-12 | Campaign IOCs | Known malicious hashes, domains, IPs, file names, threat campaign patterns |
| T1-13 | Phantom keystrokes | Injected keystrokes detected via `LLKHF_INJECTED` flag and blocked via `WH_KEYBOARD_LL` |
| T1-14 | Network: Unauthorized Network Bridge Detected | Virtual bridge detection and active SetupAPI uninstallation |
| T1-15 | Network: Primary Adapter Disabled | Baselined physical adapter disabled state detection and active WMI restoration |
| T1-16 | Network: Unauthorized DNS Change | NameServer configuration registry lock and global DoH enforcement |

### FR-3: Tier 2 Detection Rules

The system must detect the following indicators (log only):

| ID | Indicator |
|----|-----------|
| T2-01 | Unsigned binary execution outside trusted system paths |
| T2-02 | High-entropy process names (Shannon entropy > 4.2) |
| T2-03 | Suspicious Win32 API names in command line, post-exploitation recon commands, persistence mechanism patterns |

### FR-4: Composite Detections

The system must implement a behavioral correlation engine that fires composite detections when multiple signals combine within a 60-second window:

| ID | Composite | Min Confidence |
|----|-----------|---------------|
| C-01 | Active Ransomware Chain | 0.99 |
| C-02 | Injected C2 Beacon | 0.98 |
| C-03 | Credential Dump + Exfiltration | 0.96 |
| C-04 | In-Memory Implant Active | 0.96 |
| C-05 | Fileless Attack Chain | 0.95 |
| C-06 | DGA + C2 Beaconing | 0.94 |
| C-07 | Dropped Payload Active | 0.93 |
| C-08 | Spoofed Process Phoning Home | 0.92 |
| C-09 | Evasion + Persistence Install | 0.91 |
| C-10 | Escalation + C2 Channel | 0.90 |
| C-06 | Credential Dump + Exfiltration | 0.96 |

### FR-5: Monitoring Sources

| Source | Mechanism | Fallback |
|--------|-----------|---------|
| Process events | ETW kernel provider | WMI Win32_ProcessStartTrace |
| Injection API calls | ETW Threat Intelligence provider | None (log warning, continue) |
| Network connections | GetExtendedTcpTable / GetExtendedUdpTable (IPv4+IPv6 TCP+UDP) | None |
| File activity | FileSystemWatcher | None |
| Process memory | GetMappedFileName + EnumProcessModules | None |
| Process ancestry | CreateToolhelp32Snapshot (2s refresh) | None |
| Webcam/Mic access | Process module enumeration (camera/mic DLL detection) | None |

### FR-6: Response Actions

| Action | Condition |
|--------|-----------|
| Pre-kill deception (DeceptionEngine) | Always before kill when active response is enabled. 2s time budget. |
| Log detection + log response (LogOnly) | Always for Tier2; Tier1 when active response is disabled |
| Kill process (`Process.Kill`) | Tier1 only, when `--active-response` is explicitly set |

### FR-6a: Deception Tactics (v1.7.0)

The system must execute attacker-hostile tactics before process termination:

| ID | Tactic | Mechanism | Time Budget |
|----|--------|-----------|-------------|
| D-01 | Memory Flooding | VirtualAllocEx + WriteProcessMemory (256MB random garbage) | 500ms |
| D-02 | DLL Stomping | Overwrite non-system module .text with INT3 (0xCC) | 200ms |
| D-03 | Stack Corruption | Inject garbage into thread stack regions via WriteProcessMemory | 200ms |
| D-04 | Handle Pollution | Create 60+ decoy named objects (fake debugger/EDR/C2 names) | 100ms |
| D-05 | Beacon Flooding | Send 50+ fake beacon check-ins to identified C2 server | 800ms |
| D-06 | Protocol Confusion | Send 20+ malformed payloads exploiting C2 parser bugs | included in D-05 |
| D-07 | Clipboard Poisoning | Replace clipboard with fake AWS keys, SSH keys, crypto addresses | 100ms |
| D-08 | Sparse File Bombs | Create 500GB sparse files in exfil-target directories | 200ms |
| D-09 | Symlink Loops | Create 50-level recursive directory symlinks | 200ms |
| D-10 | Polyglot Files | Deploy PDF/XLSX/DOCX with canary callbacks + parser crash payloads | 200ms |
| D-11 | Corrupted Archives | Deploy tar.gz/gz/7z with valid headers but corrupted data | 200ms |
| D-12 | File Locking | Exclusively lock files attacker is reading | 100ms |
| D-13 | Environment Poisoning | Corrupt proxy, TLS, persistence registry (HKCU only) | 100ms |
| D-14 | Honeypot Weaponization | Deploy fake SSH keys, cloud creds, wallet seeds, zip bombs | 500ms |
| D-15 | Network Honeypots | Spin up fake SMB/RDP/HTTP/SSH listeners (30min lifetime) | 200ms |

Constraints:
- Total deception time must not exceed 2 seconds
- Deception failure must never prevent kill
- Never target own PID or system-critical processes
- Beacon flooding only targets public IP addresses
- All actions must be logged before execution
- Ransomware Fast-Path: If 'ransomware' is detected in rule or reasoning, the pre-kill deception phase is bypassed entirely to prioritize immediate termination.
- Thread context queries: Context retrieval must suspend target threads on x64 and map to a 16-byte packed native struct to avoid access violations or stack corruption.
- Async background deception: Off-host and network-based deception tactics (BeaconFlooder, NetworkHoneypotDeployer) run asynchronously in the background, without blocking process termination or consuming the pre-kill budget.

### FR-7: Logging

- Output format: JSONL (newline-delimited JSON), `System.Text.Json` only
- Default path: `%ProgramData%\Sentinel\events.jsonl`
- Size-based rotation: 50 MB per file, up to 5 rotated files
- Each entry must include: `type`, `timestamp`, `data` (with `ruleName`, `evidence`, `reasoning`, `confidence`, `tier`, `processName`, `processId`, `metadata`)
- Rate limiting: max 100 entries/second, burst of 200 (prevents log flooding attacks)
- File sharing: `FileShare.ReadWrite` â€” concurrent readers must not be blocked
- Graceful degradation: log file access failure must NOT crash the service; fall back to degraded mode
- Self-healing: writer must retry opening the file on each write if the initial open failed
- Stale file handling: locked/inaccessible files renamed to `.stale.<timestamp>` and fresh file created

### FR-8: Explainability

Every `DetectionEvent` must include:
- `RuleName` â€” which rule fired
- `Evidence` â€” what was specifically observed
- `Reasoning` â€” why it is suspicious (human-readable)
- `Confidence` â€” 0.0â€“1.0 score calibrated per rule
- `Metadata` â€” key-value pairs with raw observable data

### FR-9: CLI Interface

The CLI must support:
- `--active-response` â€” enable Tier1 process termination
- `--log <path>` â€” override log file path
- `--verbose` â€” enable debug logging
- Configuration via `appsettings.json` (CLI flags override config)

### FR-10: Deduplication

- `DetectionEngine` must suppress identical `(RuleName, ProcessId)` detections within a 60-second window
- `NetworkMonitor` must suppress identical `(ProcessId, RemoteAddress, RemotePort)` alerts within a 5-minute window

---

## Non-Functional Requirements

### NFR-1: Safety
- Active response is enabled by default (President's Law rules fire immediately)
- The tool must not persist, self-replicate, or hide itself
- No kernel drivers, no direct syscalls

### NFR-2: Reliability
- Monitors must fail independently â€” one monitor failure must not crash the service
- All exceptions must be caught and logged; no silent failures
- All `IDisposable` / `IAsyncDisposable` objects must be properly disposed

### NFR-3: Performance
- Must not materially impact system performance during normal operation
- Detection deduplication must prevent log flooding
- Process ancestry snapshot must use atomic swap (no reader blocking)

### NFR-4: Portability of Privilege
- Must run as a standard user with reduced capability
- Must run as an elevated user with full capability
- Degradation must be logged clearly

### NFR-5: Testability
- All detection rules must be unit-testable without system access
- Tier2 response contract must be verified by automated test
- Composite detection logic must be testable with mock detection engine

### NFR-6: Deception Safety (v1.7.0)
- Deception must never delay kill beyond 2 seconds
- Deception failure must be non-fatal (kill always proceeds)
- Deception must never target own process or system-critical processes (PID â‰¤ 4)
- Environment poisoning must be HKCU-scoped only (never HKLM)
- Beacon flooding must only target public IP addresses (never private/loopback)
- All deception actions must be logged with full detail for forensic review and reversal
- Honeypot files must use non-standard names to avoid confusion with real credentials


