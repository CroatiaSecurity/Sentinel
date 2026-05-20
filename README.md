# Windows Sentinel

**Userland EDR for Windows — Behavioral Detection, Automated Response & Aggressive Deception**

> Version: 2.7.0 (Deception Refinements & Ransomware Fast-Path)  
> Author: [Gorstak](https://github.com/tandrlemandrle/Sentinel)  
> License: MIT

---

## What it is

Windows Sentinel is a userland endpoint detection and response (EDR) tool for Windows. It detects malicious behavior at runtime and responds by killing threat chains, quarantining binaries, removing persistence, and — as of v1.7.0 — actively punishing the attacker before the kill. Designed for:

- Personal endpoint protection (layered defense alongside Defender)
- Blue-team education and security research
- Behavioral analysis and threat hunting
- Learning how EDR internals work

It is **not** a replacement for commercial EDR. It has no kernel driver, which means a sufficiently privileged attacker (admin + BYOVD) can bypass it. It's a userland defense layer. See [THREAT_MODEL.md](THREAT_MODEL.md) for honest bypass analysis.

---

## Architecture

```
Monitors → TelemetryFusionEngine → DetectionEngine → ResponseEngine → JsonlEventLogger
                    ↓                      ↑               ↓
               EventGraph          BehavioralCorrelation   DeceptionEngine (pre-kill)
           (queryable graph)              ↑                    ↓
                                   (composite detections)  Kill / Quarantine / Block
```

### President & Council of Elders

**President (Core)** — Behavioral detection rules with kill authority. Only the President can terminate processes. Kill decisions are gated by the closed "President's Law" fragment list — a hardcoded set of rule-name patterns that authorize lethal response at confidence ≥ 0.85.

**Council of Elders (Advisory)** — Additional detection modules that emit Tier2 signals. They observe and report but never kill independently. Multiple corroborating council signals can produce a composite kill via the Behavioral Correlation Engine.

### Telemetry Fusion (v1.0.0+)

All monitors feed raw telemetry through the `TelemetryFusionEngine` before the detection engine. The fusion layer:
- Builds per-process event chains (ordered sequence of all actions)
- Maintains the `EventGraph` (process/file/network relationships with temporal edges)
- Produces `FusedTelemetryContext` with behavioral velocity, event diversity, and multi-vector flags
- Enables cross-source correlation that no single rule can achieve alone

### Aggressive Deception Engine (v1.7.0)

When a kill is authorized, the `DeceptionEngine` executes attacker-hostile tactics BEFORE process termination:
- Poisons exfiltrated data with trackable fakes
- Floods attacker memory dumps with garbage
- Destabilizes implant code for crash-on-restart
- Floods C2 servers with fake beacon sessions
- Deploys filesystem traps that exhaust exfil tools
- Corrupts environment to break reconnection

All deception operates within a strict 2-second time budget. Kill always proceeds regardless of deception success.

---

## Detection Philosophy (v1.1.0)

1. **Behavioral over static** — Detect what processes DO, not what they ARE
2. **No security theater** — If a feature doesn't work against a competent attacker, it's removed
3. **Fewer solid detections > many fragile ones** — Each rule must justify its existence
4. **Assume the attacker reads the code** — No security-by-obscurity
5. **Honest documentation** — State what works and what doesn't

### What was removed and why

| Removed | Reason |
|---------|--------|
| Key Scrambler (fake keystroke injection) | Security theater — ineffective against anything beyond primitive loggers |
| Placeholder hash lists (LsassAccessRule) | Fake SHA256 values gave false confidence. Hash reputation handled by live API lookup |
| Tool-name-based detection triggers | Trivially bypassed by renaming. Demoted to metadata-only |
| Learning Mode | Dead code — protection is active by default |
| Password Rotator | Stub that did nothing |

---

## Detection

### Tier 1 — Kill Authority (President's Law)

These rules can trigger immediate process termination + quarantine:

| Rule | Detects | Signal Type |
|------|---------|-------------|
| LSASS Credential Dump | comsvcs MiniDump, sekurlsa, procdump -ma lsass, dump file patterns | Behavioral (cmdline tokens) |
| ETW/AMSI Tampering | AmsiScanBuffer patch, EtwEventWrite patch, NtTraceEvent patch | Behavioral (memory integrity) |
| Syscall Stub Integrity | ntdll function prologue modification in Sentinel process | Behavioral (self-protection) |
| Ransomware (Unified) | Shadow copy deletion + bulk renames + I/O rate + 100+ extensions | Behavioral (multi-signal scoring) |
| Process Injection (Kernel) | VirtualAllocEx, VirtualProtect RWX, MapViewOfSection, QueueUserAPC, SetThreadContext | Kernel ETW (API observation) |
| Memory Behavior | RWX regions, unbacked executables, shellcode prologues | Behavioral (memory scanning) |
| Audio/Webcam Hijack | Output-to-mic redirection, virtual audio cable abuse | Behavioral (device state + module analysis) |
| Self-Protection | AMSI repair, ETW repair, DLL hijacking, config tampering, service tampering | Behavioral (integrity monitoring) |
| NeuroBehavior Anomaly | Process behavior entropy, multi-vector activity scoring | Behavioral (statistical) |
| NeuroBehavior Visual | Focus abuse, flash stimulus, topmost abuse, cursor jitter, color distortion | Behavioral (screen/input analysis) |
| Honeypot Trip | Decoy file access detection | Behavioral (canary) |
| Transparent Overlay Phishing | WS_EX_LAYERED + WS_EX_TRANSPARENT + WS_EX_TOPMOST from non-allowlisted processes | Behavioral (window enumeration) |
| Browser DLL Injection (ELF) | ELF-pattern DLLs in browser processes → active unload | Behavioral (module analysis + response) |
| Malicious DLL on Disk (IoC) | Disk-scanned DLL matches threat intel hash → active unload from all processes | Behavioral (hash reputation + response) |

### Tier 2 — Advisory / Corroborating (Log Only, Feeds Correlation)

These never kill independently. Multiple Tier2 signals on the same PID within 120s can produce a composite kill via the BehavioralCorrelationEngine:

| Rule | Detects |
|------|---------|
| LSASS Dump Canary | dbghelp.dll loaded in non-debugger process |
| Parent PID Spoofing | ETW-reported parent ≠ snapshot-reported parent |
| Token Integrity Escalation | Medium → High integrity without UAC consent |
| Credential Canary | Honeypot credential accessed/deleted |
| DNS: DGA Domains | High-entropy domain names (3+ hits from same process) |
| DNS: Tunneling | Sustained >30 queries/min from single process |
| Process Injection (cmdline) | Injection API names in command-line arguments |
| Suspicious Parent-Child | Office/browser spawning cmd/powershell |
| Hash Reputation | Multi-source API lookup (CIRCL, Cymru, MalwareBazaar) |
| Campaign IOCs | Known malicious hashes, IPs, domains, APT patterns |
| File Entropy | Packed/encrypted files |
| Clipboard Scraping | Rapid automated clipboard changes (crypto swappers, stealers) |
| Clipboard Hijack | Background process taking clipboard ownership silently |
| Clipboard Lock | Process holding clipboard locked, blocking copy/paste |
| Module Injection (Runtime) | New suspicious DLL appears in any process after baseline |
| Phantom Module | Loaded DLL's file deleted from disk (dropper pattern) |
| Module Validation | DLL hijacking, sideloading |
| UAC Bypass Surface | COM AutoElevation vectors, manifest autoElevate + copy-drop vulnerable binaries |
| DLL Entropy | Packed/encrypted DLLs (Shannon entropy ≥ 7.2), random hex-named DLLs |
| DLL Load Failure | Event Log ID 7 failures, SideBySide manifest errors (failed hijacking indicators) |
| Browser DLL (ELF Catcher) | Suspicious DLLs in browser processes (ELF patterns, unsigned, temp-loaded) |
| Disk-Wide DLL Scan | Unsigned/suspicious DLLs on disk in user-writable locations |
| Unsigned Binary | Unsigned executables in staging paths |
| Beaconing (Statistical) | Coefficient of variation analysis for C2 patterns |
| Keylogger Detection | Suspicious keyboard hook DLLs (service-only) |
| Background Screen Capture | DXGI/D3D11 + image encoding DLLs with no visible window |
| Local Server (Mounted Media) | Processes from ISO/VHD/removable media binding listening sockets |
| Local Server (Staging Path) | Processes from Temp/AppData/Downloads binding ports |
| Background Webcam/Mic | Camera/microphone DLLs loaded by background processes |
| NeuroBehavior: Focus Abuse | Process stealing focus >8 times in 10 seconds |
| NeuroBehavior: Flash Stimulus | Rapid screen brightness oscillation (strobing) |
| NeuroBehavior: Topmost Abuse | Non-allowlisted process forcing WS_EX_TOPMOST |
| NeuroBehavior: Cursor Jitter | Rapid programmatic cursor movement (>6 jumps in 10s) |
| NeuroBehavior: Color Inversion | Screen colors inverted (current ≈ inverse of previous frame) |
| NeuroBehavior: Screen Distortion | Rapid color channel shifts without inversion |

### Composite Detections (Behavioral Correlation Engine)

Multiple weak signals within a 120-second window produce high-confidence composite kills:

| Composite | Confidence | Trigger |
|-----------|-----------|---------|
| Active Ransomware Chain | 0.99 | Shadow copy deletion + file renames |
| Fileless Attack Chain | 0.95 | AMSI bypass + encoded PS + C2 network |
| Injected C2 Beacon | 0.98 | Kernel-observed injection + C2 network |
| Credential Dump + Exfiltration | 0.96 | LSASS dump + outbound C2 |
| Dropped Payload Phoning Home | 0.93 | Unsigned staged binary + C2 port |
| Post-Exploitation Recon | 0.88 | 3+ distinct recon commands in 120s |
| PPID Spoof + C2 Channel | 0.96 | Parent PID spoofing + C2 network |
| Confirmed LSASS Dump | 0.97 | dbghelp.dll loaded + LSASS-targeting pattern |
| Privilege Escalation + Persistence | 0.94 | Token integrity change + persistence installation |
| DGA + C2 Beaconing | 0.95 | High-entropy DNS + periodic beacon pattern |
| Credential Theft + Exfiltration | 0.97 | Credential canary tripped + outbound network |
| Advanced Attack Chain | 0.98 | 2 of 3: PPID spoof + token escalation + injection |
| Spoofed Process Phoning Home | 0.95 | PPID spoof + ANY network activity |
| Dump Tool + Network Exfil | 0.94 | dbghelp.dll + ANY outbound connection |
| Staged Payload + Non-Standard Port | 0.92 | Unsigned binary from temp + non-80/443 port |
| Mass File Operation + DNS | 0.93 | 50+ file writes + DNS resolution |
| Privilege Escalation + Network | 0.94 | Token escalation + ANY network activity |
| Injection Tool + File Staging | 0.91 | Injection API in cmdline + file writes |
| DGA + File Operations | 0.94 | DGA DNS resolution + ANY file access |
| In-Memory Implant + Network | 0.96 | Memory anomaly (RWX/shellcode) + ANY network |
| Clipboard Access + Network | 0.93 | Clipboard scraping/hijacking + outbound network |
| Injected Implant + Network C2 | 0.95 | DLL injection + network activity |
| Clipboard Theft via Injected Module | 0.94 | DLL injection + clipboard access |
| Screen Exfiltration: Capture + Network | 0.93 | Screen capture + outbound network |
| Data Harvesting: Screen + Clipboard | 0.92 | Screen capture + clipboard access |
| Credential Phishing: Overlay + Injection | 0.96 | Transparent overlay + DLL injection |
| Full Surveillance Suite | 0.94–0.99 | 2+ of (screen, clipboard, audio, webcam) |
| Camera/Mic Exfiltration: Capture + Network | 0.94 | Background webcam/mic + outbound network |
| Total AV Surveillance: Camera + Screen | 0.95 | Webcam/mic + screen capture |
| Sensory Manipulation: Visual + Mic Session | 0.93 | NeuroBehavior visual signal + unauthorized mic session |
| Sensory Manipulation: Visual + Audio Hijack | 0.94 | NeuroBehavior visual signal + audio output-to-mic routing |
| Injected Visual Manipulator | 0.92 | Process injection + NeuroBehavior visual manipulation |
| Coordinated Visual Manipulation Attack | 0.90 | 3+ distinct NeuroBehavior signal types from same process |

Total: 34 composite rules.

---

## Response

When a President's Law detection fires above confidence 0.85:

1. **Deception Phase** (v1.7.0) — Execute attacker-hostile tactics (2s max):
   - Memory flooding (pollute crash dumps with 256MB garbage)
   - DLL stomping (INT3 overwrite for crash-on-restart)
   - Stack corruption (garbage in thread stacks → corrupted C2 crash reports)
   - Handle pollution (60+ decoy named objects confuse forensics)
   - Beacon flooding (50+ fake Cobalt Strike/Sliver sessions to C2)
   - Protocol confusion (malformed payloads crash C2 team servers)
   - Clipboard poisoning (replace with trackable fake credentials)
   - File traps (sparse bombs, symlink loops, polyglot files, corrupted archives)
   - Environment poisoning (break proxy/TLS/persistence registry)
   - Honeypot weaponization (fake SSH keys, cloud creds, wallet seeds, zip bombs)
   - Network honeypots (fake SMB/RDP/HTTP/SSH listeners for lateral movement traps)
2. **Active DLL Unloading** (v1.9.0) — Forcefully unload injected/malicious DLLs:
   - CreateRemoteThread + FreeLibrary to eject DLLs from live processes
   - Rate-limited (10 unloads/minute), never touches system-critical processes
   - Used by BrowserDllMonitor (ELF patterns) and DiskWideDllScanner (IoC matches)
3. **Chain Trace** — Walk parent chain (forensic), collect descendants
3. **Kill process tree** — Leaves first, root last
4. **Quarantine binaries** — DPAPI-encrypted, ACL-hardened (SYSTEM + Admins only)
5. **Remove persistence** — Registry Run keys, startup folder, scheduled tasks, services
6. **Block attacker IPs** — Windows Firewall COM API → registry fallback
7. **Collect forensic evidence** — Memory dump, module inventory, network snapshot

**Zero LOLBin dependencies.** All response actions use native C# APIs. No `sc.exe`, `schtasks.exe`, `netsh.exe`, `powershell.exe`, or `reg.exe` in the response path.

---

## Deception Engine (v1.7.0)

The Deception Engine makes every kill hurt the attacker. Instead of just stopping the threat, it actively wastes attacker time, pollutes their data, and exposes their infrastructure.

| Tactic | What It Does | Impact on Attacker |
|--------|-------------|-------------------|
| Memory Flooding | Injects 256MB of random garbage into target process | Crash dumps are gigabytes of noise; C2 crash reports polluted |
| DLL Stomping | Overwrites malicious module .text with INT3 breakpoints | Implant crashes immediately on restart; hard to debug remotely |
| Stack Corruption | Injects garbage into thread stacks before termination | C2 crash-reporting sends corrupted telemetry; pollutes operator logs |
| Handle Pollution | Creates 60+ decoy named objects (fake debugger/EDR/C2 names) | Forensic handle enumeration full of misleading noise |
| Beacon Flooding | Sends 50+ fake beacon check-ins to identified C2 server | Operator console flooded with ghost sessions |
| Protocol Confusion | Sends malformed payloads exploiting C2 parser bugs | Integer overflows, null-byte injection, chunked encoding corruption crash team servers |
| Clipboard Poisoning | Replaces clipboard with fake AWS keys, SSH keys, crypto wallets | Stolen data is useless; canary tokens expose attacker when used |
| Sparse File Bombs | Creates 500GB sparse files in exfil-target directories | Automated exfil tools try to read 500GB of zeros |
| Symlink Loops | Creates 50-level recursive directory symlinks in staging paths | Recursive file collection infinite-loops, crashes implant |
| Polyglot Files | Deploys PDF/XLSX/DOCX with canary callbacks + malformed internals | Crashes attacker's automated parsers; XXE/entity expansion attacks on their tools |
| Corrupted Archives | Deploys tar.gz/gz/7z with valid headers but corrupted data streams | Passes initial validation but fails during extraction, wasting hours |
| File Locking | Exclusively locks files attacker is trying to read | Forces retry loops, wastes time, generates detectable I/O |
| Environment Poisoning | Corrupts proxy, TLS, and persistence registry settings (HKCU) | C2 reconnection fails; implant restart executes harmless cmd |
| Honeypot Weaponization | Deploys fake SSH keys, cloud creds, wallet seeds, VPN configs, zip bombs | Attacker uses fake creds → exposes their infrastructure to us |
| Network Honeypots | Spins up fake SMB/RDP/HTTP/SSH listeners on local ports (30min lifetime) | Attacker's lateral movement finds fake DCs, vCenter, Exchange — wastes days |

All tactics:
- Execute within a strict 2-second time budget (network honeypots persist 30min post-kill)
- Never prevent the kill from proceeding (failure is non-fatal)
- Never target own PID or system-critical processes
- Are logged for forensic review
- Operate entirely on our own system (legally defensive)

---

## False Positive Reduction

| System | How It Reduces FPs |
|--------|-------------------|
| AllowlistService | 3-tier trust: signed vendor, dev tools, user allowlist. President's Law NEVER suppressed. |
| ContextualAnalysisEngine | Installer/update/boot/dev/gaming context modifiers |
| BehavioralBaselineService | Learns normal processes over time. Established processes get trust boost |
| FalsePositiveTracker | Records user-restored files. Auto-reduces future scoring after repeated FPs |
| ReputationCache | 5-tier hash reputation with boot-nonce-bound DPAPI persistence |
| CPU Throttling | Job scheduler backs off under pressure. Never degrades user experience |

---

## Self-Protection

| Protection | Method |
|-----------|--------|
| DLL sideload prevention | CIG, SetDefaultDllDirectories, install-dir ACL |
| Syscall stub integrity | Monitors ntdll/amsi function prologues every 10s against baseline |
| AMSI/ETW integrity | Monitors syscall stubs, auto-repair |
| Self-kill prevention | All kill paths refuse to target own PID |
| Config tampering | Hash-based integrity, allowlist freeze on modification |
| Cross-process watchdog | Service heartbeat → Agent restart on stale |
| Quarantine security | DPAPI encryption + restrictive ACL |
| Cache integrity | Boot-nonce-bound HMAC (v1.1.0) — previous-session caches rejected |
| Credential canary | Honeypot credential detects credential harvesting |

---

## Monitoring Coverage

### Monitors by Category

| Category | Monitor | Mechanism | Added |
|----------|---------|-----------|-------|
| Process | EtwProcessMonitor | ETW kernel provider (fallback: WMI) | 0.1.0 |
| Process | HollowProcessMonitor | GetMappedFileName + EnumProcessModules | 0.1.0 |
| Process | ParentPidSpoofDetector | ETW parent vs snapshot comparison | 1.1.0 |
| Memory | MemoryBehaviorAnalyzer | VirtualQueryEx + ReadProcessMemory | 1.0.0 |
| Memory | SyscallStubMonitor | ntdll/amsi prologue baseline comparison | 1.1.0 |
| Memory | RuntimeModuleIntegrityMonitor | Per-process module baseline tracking | 1.4.0 |
| Network | NetworkMonitor | GetExtendedTcpTable/UdpTable (IPv4+IPv6) | 0.1.0 |
| Network | BeaconingDetector | Statistical CV analysis | 0.1.0 |
| Network | DnsQueryMonitor | ETW DNS-Client provider | 1.1.0 |
| Network | LocalServerMonitor | GetExtendedTcpTable LISTEN state | 1.5.0 |
| File | FileActivityMonitor | FileSystemWatcher | 0.1.0 |
| File | HoneypotMonitor | Decoy file access detection | 0.9.0 |
| Credential | CredentialCanaryMonitor | Windows Credential Manager canary | 1.1.0 |
| Credential | TokenIntegrityMonitor | GetTokenInformation scans | 1.1.0 |
| Credential | LsassDumpCanaryMonitor | dbghelp.dll detection | 1.1.0 |
| AV/Spyware | ScreenCaptureMonitor | DXGI/D3D11 + overlay detection | 1.5.0 |
| AV/Spyware | WebcamMicMonitor | Camera/mic DLL analysis | 1.6.0 |
| AV/Spyware | AudioHijackMonitor | Audio-to-mic redirection | 0.4.0 |
| AV/Spyware | ClipboardMonitor | Win32 clipboard API polling | 1.4.0 |
| Injection | EtwThreatIntelMonitor | Microsoft-Windows-Threat-Intelligence | 0.1.0 |
| DLL Analysis | DllEntropyAnalyzer | Shannon entropy + hex-name detection | 1.9.0 |
| DLL Analysis | BrowserDllMonitor (ELF Catcher) | Browser-specific DLL injection detection | 1.9.0 |
| DLL Analysis | DiskWideDllScanner | Disk-wide unsigned DLL scanning (all drives) | 1.9.0 |
| DLL Analysis | DllLoadFailureMonitor | Event Log ID 7 + SideBySide errors | 1.9.0 |
| DLL Analysis | UacBypassSurfaceMonitor | COM AutoElevation + manifest autoElevate | 1.9.0 |
| NeuroBehavior | NeuroBehaviorVisualMonitor | Screen capture + foreground window + cursor analysis | 2.5.0 |

---

## Installation

```powershell
# Run installer as Administrator
.\WindowsSentinelSetup-2.7.0.exe
```

The installer:
1. Installs to `%ProgramFiles%\WindowsSentinel` (ACL-hardened)
2. Adds Defender exclusion for install directory only
3. Creates Windows Service (runs as SYSTEM, full telemetry)
4. Launches Agent into user session (watchdog-only)

---

## Configuration

`appsettings.json` in install directory:

```json
{
  "Sentinel": {
    "ActiveResponse": true,
    "LogPath": null,
    "WatchPath": null
  },
  "ThreatReporting": {
    "Enabled": false,
    "AbuseIpDbApiKey": null,
    "UrlhausAuthToken": null,
    "ReportToMalwareBazaar": true,
    "ReportToUrlhaus": true
  }
}
```

- `ActiveResponse: true` (default) — Kills on President's Law detections (with pre-kill deception)
- `ActiveResponse: false` — Monitor-only, all detections logged
- `ThreatReporting.Enabled: true` — Reports confirmed C2 IPs/hashes to community platforms after kills
- `AbuseIpDbApiKey` — Free API key from https://www.abuseipdb.com/account/api
- `UrlhausAuthToken` — Free token from https://urlhaus.abuse.ch/api/#account

---

## Threat Intelligence Reporting (v2.1.0)

After a confirmed kill (President's Law, confidence ≥ 0.85), Sentinel can report the attacker's infrastructure to community threat intelligence platforms:

| Platform | What's Reported | Effect |
|----------|----------------|--------|
| AbuseIPDB | C2 IP address + attack category + evidence summary | IP gets flagged in global abuse database; ISPs/hosting providers receive abuse reports |
| URLhaus (abuse.ch) | C2 URL/IP:port | URL added to community blocklist used by firewalls, DNS filters, and other EDRs worldwide |
| MalwareBazaar (abuse.ch) | Malicious file SHA-256 hash + tags | Hash added to community malware database for signature generation |

**Safety guarantees:**
- All reporting is **opt-in** (disabled by default)
- Only reports **confirmed threats** (post-kill, confidence ≥ 0.85)
- **Never reports private/internal IPs** (RFC1918, link-local, loopback)
- **Never uploads file contents** — only hashes and metadata
- **Rate-limited**: max 10 reports per hour
- **Deduplication**: same IP/hash never reported twice
- Reports are queued and sent asynchronously (never blocks kill response)

---

## Building

Requires .NET 8 SDK on Windows.

```bash
dotnet build WindowsSentinel.sln
dotnet test WindowsSentinel.sln
```

### Publishing installer

```powershell
cd installer
.\build.ps1
```

Output: `installer\output\WindowsSentinelSetup-2.7.0.exe`

---

## Limitations (Honest)

- **No kernel driver** — Cannot prevent BYOVD, direct syscalls, or kernel callbacks. Detects but cannot block.
- **Local admin wins** — An attacker with admin can kill the service. Watchdog adds seconds of delay, not real protection.
- **Command-line detection has limits** — Sophisticated tooling avoids cmdline exposure entirely. ETW ThreatIntel and MemoryBehaviorAnalyzer cover this gap.
- **Not a replacement for commercial EDR** — Use alongside Windows Defender, not instead of it.
- **Single-machine scope** — No central management, no fleet telemetry, no cloud reputation.
- **Statistical detections need tuning** — Beaconing, NeuroBehavior, and entropy rules may need per-environment adjustment.
- **Deception is best-effort** — Tactics may fail if process is already dying or access is denied. Kill always proceeds.

See [THREAT_MODEL.md](THREAT_MODEL.md) for detailed bypass analysis.

---

## Barebone Windows Compatibility (v2.0.0)

Sentinel runs on minimal Windows installations with graceful degradation:

| Feature | Full Desktop | Server Core / IoT | Stripped/Debloated |
|---------|-------------|-------------------|-------------------|
| ETW Process Monitoring | ✅ Full | ✅ Full | ✅ Full |
| ETW Threat Intelligence | ✅ Full | ✅ Full (if elevated) | ⚠️ Falls back to WMI |
| Toast Notifications | ✅ Full | ❌ Disabled (no shell) | ❌ Disabled |
| User Session Agent Launch | ✅ Full | ⚠️ Disabled if no WTS | ⚠️ Disabled |
| DLL Search Hardening | ✅ Full | ✅ Full | ⚠️ Skipped on pre-Win8 |
| CIG (Code Integrity Guard) | ✅ Audit mode | ✅ Audit mode | ⚠️ Skipped if unsupported |
| Event Log Monitoring | ✅ Full | ✅ Full | ⚠️ Skipped if logs unavailable |
| Registry Scanning (UAC) | ✅ Full | ✅ Full | ⚠️ Per-key fallback |
| File/Network/Memory Monitors | ✅ Full | ✅ Full | ✅ Full |
| Active DLL Unloading | ✅ Full | ✅ Full | ✅ Full |
| Detection + Kill Response | ✅ Full | ✅ Full | ✅ Full |

**Design principle:** Detection and response ALWAYS work. UI features (toasts, agent session) degrade gracefully. No crash loops, no error spam — just a single informational log at startup explaining what's unavailable.

---

## Project Structure

```
src/
  WindowsSentinel.Core/       — Detection engine, rules, monitors, response, deception, hardening
  WindowsSentinel.Service/    — Windows service host (runs as SYSTEM)
  WindowsSentinel.Agent/      — User-session watchdog (heartbeat monitor)
tests/
  WindowsSentinel.Tests/      — Unit tests
installer/
  build.ps1                   — Build + publish + compile installer
  setup.iss                   — Inno Setup script
```

---

## Version History

| Version | Codename | Key Changes |
|---------|----------|-------------|
| 0.9.0 | False Positive Reduction | AllowlistService, CPU throttling, context awareness, President's Law |
| 1.0.0 | Telemetry Fusion | TelemetryFusionEngine, EventGraph, MemoryBehaviorAnalyzer, Key Scrambler removed |
| 1.1.0 | Hardened Foundations | Anti-APT monitors (DNS, PPID spoof, syscall integrity, credential canary, token integrity, LSASS dump canary), placeholder hashes removed, threat model |
| 1.2.0 | Correlated Kill | 6 new composite correlation rules wiring anti-APT monitors into kill-authorized composites. Total: 12 composites. |
| 1.3.0 | Aggressive Correlation | 8 new anchor-based composites: suspicious process + ANY second signal = kill. Total: 20 composites. |
| 1.4.0 | Clipboard Guardian | ClipboardMonitor, RuntimeModuleIntegrityMonitor, 3 new composites (clipboard+network, injection+network, injection+clipboard). Total: 23. |
| 1.5.0 | Anti-Spyware Suite | ScreenCaptureMonitor, LocalServerMonitor, overlay phishing detection, volume dismount on read-only media, 5 new composites. Total: 28. |
| 1.6.0 | Webcam/Mic Exfiltration Guard | WebcamMicMonitor, background camera/mic detection, 2 new composites (camera+network, camera+screen). Total: 30. |
| 1.7.0 | Aggressive Deception | DeceptionEngine with 8 pre-kill tactic classes: memory flooding, implant destabilization (DLL stomping + stack corruption + handle pollution), beacon flooding + protocol confusion, clipboard poisoning, file traps (sparse bombs + symlink loops + polyglot files + corrupted archives + file locking), environment poisoning, honeypot weaponization, network honeypot deployment (fake SMB/RDP/HTTP/SSH). |
| 1.8.0 | Data Exfiltration Prevention | DataExfiltrationMonitor (outbound volume, sensitive file access, USB reads, path-verified allowlists). DnsQueryMonitor enhanced with 40+ exfil domain detection. 4 new composites (ExfilDNS+Network, SensitiveFile+Network, USB+Network, ExfilDNS+SensitiveFile). Zero false positives via correlation-only kills. Total: 34. |
| 1.9.0 | DLL Analysis & Active Response | DllUnloadEngine (active DLL unloading via CreateRemoteThread+FreeLibrary). UacBypassSurfaceMonitor (COM AutoElevation, manifest autoElevate, copy-drop vulnerability scanning). DllEntropyAnalyzer (Shannon entropy, hex-named DLL detection). DllLoadFailureMonitor (Event Log ID 7, SideBySide errors). BrowserDllMonitor/ELF Catcher (browser-specific injection detection + active unload). DiskWideDllScanner (disk-wide unsigned DLL scanning with HashReputationService integration + active unload on IoC match). 6 new monitors, 1 new response engine. |
| 2.0.0 | Hardened & Portable | Graceful fallbacks for barebone/minimal Windows (Server Core, IoT, stripped builds). UserSessionLauncher no longer crash-loops on missing WTS APIs. Toast notifications bounds-safe. LsassDumpCanary allowlist expanded (Electron, browsers, crash handlers). All P/Invoke wrapped with EntryPointNotFoundException guards. Event Log/Registry monitors degrade gracefully. |
| 2.1.0 | Community Threat Intel Reporting | ThreatIntelReporter: after confirmed kills, reports attacker C2 IPs to AbuseIPDB, malicious URLs to URLhaus (abuse.ch), hashes to MalwareBazaar. All reporting opt-in, rate-limited (10/hour), never reports private IPs. Exposes attacker infrastructure to authorities and security community. |
| 2.2.0 | Pre-Kill Validation Gate | AdvancedResponseEngine pre-kill sanity check: before executing a President's Law kill, validates the target is not a user-interactive foreground app running stably for 5+ minutes. Prevents false-positive kills on games (DXGI + network + dbghelp mimics spyware pattern). ScreenCaptureMonitor fix: enumerates all top-level windows via EnumWindows instead of relying on Process.MainWindowHandle (unreliable for fullscreen/multi-window apps). No allowlists added — detection logic improved to distinguish covert threats from visible user applications. |
| 2.3.0 | Mic Session Injection Detection | MicSessionMonitor: WASAPI capture session enumeration detects unauthorized mic access (deepfake audio injection). Added "audio injection" to President's Law kill list. Tier1Behavioral at 0.85 confidence for new participants. |
| 2.4.0 | ADS Staging + Agent Architecture | AdsDataStagingMonitor: detects large NTFS Alternate Data Streams used to hide exfiltration staging data (invisible disk fill). User-session monitors (clipboard, screen capture, webcam/mic, audio hijack, mic sessions) moved from SYSTEM service to Agent for correct user-context access. MemoryBehaviorAnalyzer fix: capped VirtualQueryEx scan at user-mode limit (fixes 2.3TB virtual memory). Added "data staging" to President's Law kill list. Agent now has own detection pipeline with kill authority. |
| 2.5.0 | NeuroBehavior Visual + AudioHijack Enhancement | NeuroBehaviorVisualMonitor: ported from Antivirus.ps1, detects focus abuse (>8 focus steals in 10s), flash stimulus (rapid brightness oscillation), topmost abuse (non-allowlisted WS_EX_TOPMOST), cursor jitter (>6 large jumps in 10s), color distortion/inversion. All signals emit as Tier2 advisory — never kill independently, safe for games/browsers. 4 new composite rules: Neuro+MicSession (0.93), Neuro+AudioHijack (0.94), Neuro+Injection (0.92), MultipleNeuroSignals (0.90). AudioHijackMonitor enhanced: no longer requires command-line tokens — detects output-to-mic routing by module analysis alone (background process with audio-out + mic-in modules and no visible window). Total composites: 34. |
| 2.7.0 | Deception Refinements & Ransomware Fast-Path | Ransomware Response Fast-Path: immediately kills process chains without running deception. x64 stack corruption fix: corrected context layout for thread stacks with thread suspension. Asynchronous deception: runs off-host and network-based deception (BeaconFlooder, NetworkHoneypotDeployer) asynchronously in the background. |

---

## License

MIT — see [LICENSE](LICENSE)

