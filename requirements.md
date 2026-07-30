# Sentinel — Requirements

**Version: 1.8.1**

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
- Deployment as a managed enterprise agent (no managed fleet / PPL kernel component)

---

## Functional Requirements

### FR-1: Detection Tiers

The system must implement two detection tiers with strictly enforced response contracts:

- **Tier 1 (Behavioral):** Active response allowed when `Sentinel:ActiveResponse` is true (default **true**). `EnforceActiveResponse` (default **true**) treats disabling ActiveResponse as tampering and force-re-enables it.
- **Tier 2 (Indicator):** Log only — response action is **never** permitted regardless of configuration.

### FR-2: Tier 1 Detection Rules

The system must detect the following behavioral threats:

| ID | Threat | Key Technique |
|----|--------|--------------|
| T1-01 | LSASS credential dumping | Known dumper names, LSASS-targeting command patterns, dump file names |
| T1-02 | Reverse shell / C2 callback | Encoded PowerShell, LOLBin abuse, C2 framework indicators, suspicious ports |
| T1-03 | Process injection / hollowing | Known injection tools, hollowing APIs, suspicious parent-child process relationships |
| T1-04 | Ransomware activity | Shadow copy deletion, backup destruction, bulk file renames, ransomware extensions |
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
| T1-15 | Network: Primary Adapter Disabled | Baselined physical adapter disabled state detection and active restoration |
| T1-16 | Network: Unauthorized DNS Change | NameServer configuration registry lock and browser DoH policy enforcement |
| T1-17 | BYOVD / planted driver certs | Driver load + cert-trace; neutralize via service stop/SCM key remove (no System32 driver mass-delete) |
| T1-18 | Token theft / potato-class impersonation | Non-service SYSTEM tokens from user-writable paths (OS false positives suppressed) |

### FR-3: Tier 2 Detection Rules

The system must detect the following indicators (log only):

| ID | Indicator |
|----|-----------|
| T2-01 | Unsigned binary execution outside trusted system paths |
| T2-02 | High-entropy process names (Shannon entropy > 4.2) |
| T2-03 | Suspicious Win32 API names in command line, post-exploitation recon commands, persistence mechanism patterns |
| T2-04 | Dynamic rules (`DynamicRulesEvaluator`) and consultant JSONL signals (sticky LogOnly; never kill) |

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
| C-11 | Named Pipe C2 + Network Beaconing | 0.95 |
| C-12 | Token Theft + Named Pipe / Lateral | 0.94 |

### FR-5: Monitoring Sources

| Source | Mechanism | Fallback |
|--------|-----------|---------|
| Process events | ETW kernel provider | WMI Win32_ProcessStartTrace |
| Injection API calls | ETW Threat Intelligence provider | None (log warning, continue) |
| Network connections | GetExtendedTcpTable / GetExtendedUdpTable (IPv4+IPv6 TCP+UDP) | None |
| File activity | FileSystemWatcher | None |
| Process memory | GetMappedFileName + EnumProcessModules | None |
| Process ancestry | CreateToolhelp32Snapshot (~5s refresh) | WMI on constrained SKUs |
| Webcam/Mic access | Process module enumeration (camera/mic DLL detection) | None |
| Hash reputation | CIRCL + MalwareBazaar + optional VT proxy | Unknown (fail closed for Safe) |

### FR-6: Response Actions

| Action | Condition |
|--------|-----------|
| Log detection + log response (`LogOnly`) | Always for Tier2; consultant signals; ActiveResponse disabled (lab); allowlist demotion; IDE host protection |
| Kill process / process tree | Tier1 with kill authority when `ActiveResponse=true`; rate-limited (`MaxKillsPerMinute`, default 15) |
| Quarantine / QuarantineAndKill | DPAPI machine-scope under `%ProgramData%\Sentinel\Quarantine`; refuse OS-critical paths; max 128 MB; production ACL SYSTEM+Admins |
| NetworkIsolate | Public C2 IP only: firewall block (COM), DNS flush, ARP entry purge (native). Skip private/LAN/link-local/multicast/CDN resolvers. Rate-limited (`MaxNetworkIsolatesPerMinute`, default 10) |
| RemoveCert / RemoveCertAndKillAdder | Planted / high-confidence rogue certificates |
| RemoveRegistryEntry | Malicious autorun / service / COM persistence |
| DismountVolume | ISO/VHD/SUBST hosts for threats |

**ActiveResponse model:**

| Source | Behavior |
|--------|----------|
| `Sentinel:ActiveResponse` | Default **true** in config and install |
| `Sentinel:EnforceActiveResponse` | Default **true** — AntiTamper force-re-enables if flipped off |
| CLI `--active-response` | Optional force-enable at service start (legacy / override; not required for normal install) |

**Removed (not required):** pre-kill **DeceptionEngine** / attacker-hostile deception tactics. Removed for Defender / AV compatibility; design rule is “no offensive deception tactics.”

### FR-7: Logging

- Output format: JSONL (newline-delimited JSON), `System.Text.Json` only
- Default path: `%ProgramData%\Sentinel\events.jsonl`
- Size-based rotation: 50 MB per file, up to 5 rotated files
- Each entry must include: `type`, `timestamp`, `data` (with `ruleName`, `evidence`, `reasoning`, `confidence`, `tier`, `processName`, `processId`, `metadata`)
- Rate limiting: max **1000** entries/second, burst of **5000**
- File sharing: `FileShare.ReadWrite` — concurrent readers must not be blocked
- Graceful degradation: log file access failure must NOT crash the service
- Self-healing: writer must retry opening the file on each write if the initial open failed
- Stale file handling: locked/inaccessible files renamed to `.stale.<timestamp>` and fresh file created

### FR-8: Explainability

Every `DetectionEvent` must include:
- `RuleName` — which rule fired
- `Evidence` — what was specifically observed
- `Reasoning` — why it is suspicious (human-readable)
- `Confidence` — 0.0–1.0 score calibrated per rule
- `Metadata` — key-value pairs with raw observable data

### FR-9: Configuration & CLI

- Primary configuration: `appsettings.json` (`Sentinel` + `ThreatReporting` + `AutoIncidentReporting` sections)
- CLI may support:
  - `--active-response` — force-enable Tier1 destructive actions (does not replace default-true config)
  - `--log <path>` — override log file path
  - `--verbose` — enable debug logging
- CLI flags override config when present

### FR-9a: Agent Settings UI (v1.7.9+)

The user-session Agent must provide a Settings window (tray menu + double-click):
- Overview of protection / service status and recent detections
- Event log viewer (from `events.jsonl`)
- Report-to-police helper: load evidence packs, edit affidavit fields, open national portal, attach ZIP workflow
- Quarantine listing / open folder (**must not** create the quarantine directory as the interactive user)
- Must **not** expose any user-level ActiveResponse disable control
- Must not use balloon tips / Win32 notification APIs that deadlock under hardened WpnService removal

### FR-10: Deduplication

- `DetectionEngine` must suppress identical `(RuleName, ProcessId)` detections within **10s (Tier1)** / **30s (Tier2)**
- Network / monitor-level secondary cooldowns may apply per monitor

### FR-11: Threat proxy authentication (v1.6.0 / v1.8.1)

- Outbound threat report / VT proxy calls must HMAC-sign `{timestamp}.{path}.{body}` with `ThreatReporting:ProxySharedSecret`
- Headers: `X-Sentinel-Timestamp`, `X-Sentinel-Signature` only
- Must **not** transmit the shared secret in any header
- Fail closed (skip reporting) if secret missing or shorter than 16 characters

### FR-12: Evidence packs (v1.7.7–1.7.8)

- Optional automatic local evidence packs under `%ProgramData%\Sentinel\IncidentReports`
- Reportable-grade defaults: integrity seal (SHA-256 + machine HMAC), victim affidavit, national portal helper
- Does **not** auto-file with law enforcement

### FR-13: Self-protection

- Service runs as SYSTEM; Agent is user-session UI/hooks only
- Binary / config integrity and ActiveResponse enforcement via `AntiTamperGuard`
- Safe Mode service registration
- Kill and isolate budgets with Tier1 budget-exhaustion visibility

---

## Non-Functional Requirements

### NFR-1: Safety
- Active response is enabled by default; President's Law categories cannot be allowlist-suppressed into silent kill bypass
- The tool must not self-replicate or hide itself as malware would
- No kernel drivers required for core detection (userland EDR)
- Never quarantine OS-critical / WRP paths
- Never NetworkIsolate private/LAN addresses

### NFR-2: Reliability
- Monitors must fail independently — one monitor failure must not crash the service
- All exceptions must be caught and logged; no silent failures
- All `IDisposable` / `IAsyncDisposable` objects must be properly disposed
- Telemetry queue must be **bounded** (DropOldest under flood) to prevent OOM

### NFR-3: Performance
- Must not materially impact system performance during normal operation
- Detection deduplication must prevent log flooding
- Process ancestry snapshot must use atomic swap (no reader blocking)

### NFR-4: Portability of Privilege
- Service requires SYSTEM for full detection/response
- Agent runs as logged-in user with reduced capability (UI / session hooks only)
- Degradation / missing elevation must be logged clearly

### NFR-5: Testability
- Detection rules and response contracts must be unit-testable without live malware
- Tier2 response contract must be verified by automated test
- Composite detection logic must be testable with mock detection engine
- Security remediations covered by versioned suites (e.g. `V181SecurityHardeningTests`)

### NFR-6: Response-path hygiene
- Prefer native APIs / P/Invoke / COM for kill, firewall, DNS, ARP
- Installer and some integrity helpers may still shell `sc`/`icacls`/`netsh`/`secedit`/`LGPO` (documented exceptions)
- Prefer cancellable async delays; short `Thread.Sleep` allowed only for documented settle/STA cases

### NFR-7: Intentionally out of scope
- Pre-kill offensive deception (removed for AV compatibility)
- Kernel PPL / ELAM driver
- Authenticated Service↔Agent IPC (tracked backlog)
- Full threat-intel certificate pinning (partial: Worker HMAC path preferred)

---

## Document history (parity)

| Version | Notes |
|---------|--------|
| 1.7.9 | Agent Settings UI requirements added |
| 1.8.1 | ActiveResponse defaults, response matrix, proxy auth, quarantine ACL, no DeceptionEngine, dedup windows, isolate private-IP deny |
