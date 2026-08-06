# Sentinel

Real-time endpoint detection and response for Windows. Runs as a background service, monitors system behavior, and kills threats automatically when multiple signals correlate.

**Current version: 2.0.1**

### Product posture (v2.0 — observe-only until malice + dual audit trail + explainable correlation)

**Full sensors. Do not block your work. Silent until a real attack chain. Then nuke — and seal an evidence pack.**

- **Observe by default** (`ObserveUntilChain: true`): every monitor logs to `events.jsonl`; **no kill / quarantine / isolate / host rewrite / toast / evidence pack** on single-signal noise.
- **Work-first host surface (v1.9.7):** default does **not** apply IPSec lockdown, RPC firewall blocks, ASR Block re-arm, RemoteRegistry disable, RDP force-logoff, or USB auto-disable. Older lockdown leftovers are **removed** on upgrade. Kiosk/lockdown only if you set `RestrictivePortHardening: true`.
- **Post-incident MitM suite (v2.0.1):** set `Sentinel:MitmDefense:Enabled` after a confirmed MitM / fake-Chromecast incident. Restores: planted-root cert removal, FCM “Send Tab to Self” block, invisible-process→Cast kill, rogue Cast (e.g. `B0-B3-69` / known IPs) firewall — without full kiosk lockdown. Default **off** on clean installs.
- **Nuke only** when multi-signal / composite chain points at: **C2 beaconing**, **exfil**, **token theft**, **reverse shell**, **credential dump**, **BYOVD**, or **coercion toolkit composites** (covert surveillance + remote channel, remote-control abuse toolkit, session theft + abuse channel, stalkerware persistence) → quarantine + kill + isolate + chain tracer.
- **Digital coercion / surveillance toolkit (v1.9.4):** platform-agnostic host defense against tools used in online harassment, sexual coercion, stalkerware, account takeover, and remote blackmail. **Does not** moderate chat or identify offenders by social profile. Settings → **Safety**.
- **Evidence packs on every chain-confirmed nuke** (`AutoIncidentReporter`): integrity-sealed pack under `%ProgramData%\Sentinel\IncidentReports` + critical toast; coercion-tagged packs include LE-oriented harm checkboxes (you complete them).
- **Windows Event Log trail (v1.9.5):** critical events also written to Application / source `Sentinel` (IDs 1000–1500) when Event Log exists. **Self-disables** on barebone/custom Windows where Event Log is stripped — JSONL remains primary. Config: `Sentinel:WindowsEventLog`.
- **Graceful degradation:** missing ETW → WMI/poll; missing Event Log → JSONL only; monitor start failures isolated; never crash the host for optional telemetry.
- **Weak observe seeds never chain-nuke alone:** LAN Cast observe, module-count growth, UX heuristics, outbound-whitelist noise, etc. Surveillance legs can still **feed composites**.
- **DLL unloaders stay armed** (`DllUnloadEngine`): FreeLibrary / quarantine on **proven** hostile Temp/plant module loads only.
- **Not an attack:** Steam DirectX, Vulkan/CUDA, GPU driver redistributables writing System32/SysWOW64 (and PID‑0 writer races) → LogOnly, never a kill seed.
- **Silent observe** (`SilentObserve: true`): no peeps until chain-confirmed.
- **Games / Denuvo:** skip process-memory handles only (`CanInspect` fail-closed when path unresolved) — not a global disable.
- **Default IPSec** blocks only attack/legacy ports. SSH/RDP/SMB/SOCKS/Docker stay open.
- **`RestrictivePortHardening: true`** for kiosk / locked-down hosts.
- **AV / VirusTotal:** see [docs/VIRUSTOTAL.md](docs/VIRUSTOTAL.md).

---

## What does it protect against?

Sentinel is effective against:

- **Script kiddies and commodity malware** — Ransomware, infostealers, RATs, cryptominers. Behavioral detection means it doesn't matter what the malware is named or where it came from. If it deletes shadow copies, encrypts files in bulk, dumps credentials, or injects into processes — it dies.

- **Living-off-the-land attacks (LOLBins)** — PowerShell abuse, WMI lateral movement, MSHTA/rundll32 proxy execution, scheduled task persistence, UAC bypasses. Sentinel watches what trusted binaries *do*, not just that they exist.

- **Credential theft** — LSASS dumps (dbghelp.dll sideloading, direct syscall variants), browser credential store access (Chrome/Edge/Firefox), honeypot credential tripwires, Credential Guard disablement monitoring, token theft / impersonation (SYSTEM token from user process; SeImpersonate alone is LogOnly — kill on confirmed SYSTEM-token / composite). Install-time LSASS PPL (`RunAsPPL`) + password rotation + UAC credential-only elevation.

- **Browser-based C2** — Headless Chrome used as a proxy, Chrome DevTools Protocol session hijacking, malicious extensions with debugger/nativeMessaging/proxy permissions. Correlates with beaconing for high-confidence composite kills.

- **Physical access attacks** — BadUSB/Rubber Ducky devices (HID whitelist), post-idle hardware change detection, new Bluetooth devices, rogue USB drives.

- **Network attacks** — ARP spoofing, DNS poisoning, rogue Wi-Fi, unauthorized Cast/screen-share devices, C2 beaconing (statistical), DNS tunneling/exfiltration, phantom network devices. Threat-intel feeds are **observe + reactive isolate** by default (`ThreatIntelProactiveFirewall: false`); optional proactive FW block. Unauthorized RDP/remote sessions can be force-logged-off (`RemoteSessionGuard`).

- **Malicious shortcuts** — Real-time `.lnk` monitoring on Desktop/Start Menu/Taskbar/Startup (all user profiles). Quarantines UNC targets, `search-ms:`/`ms-msdt:` protocol abuse, and LOLBin+remote URL/UNC argument patterns (CVE-2024-21412 / T1566.002).

- **AI agent / MCP abuse (v1.8.2)** — Coding agents (Claude, Cursor, Codex, …) treated as high-privilege automation: high-risk child processes, burst spawn (recon), credential-path tool spawn.

- **Package supply-chain runtime (v1.8.2)** — Package managers spawning LOLBins, binaries under `node_modules`/site-packages, and AI instruction-file poison (`CLAUDE.md`, Cursor/MCP configs).

- **Persistence mechanisms** — Scheduled tasks, WMI subscriptions, registry run keys, DLL sideloading, boot config tampering, PrintNightmare-class spooler exploitation (driver DLL planting + child process detection).

- **Container/WSL escape** — Detects lateral movement FROM WSL/Docker INTO the Windows host: filesystem writes to sensitive paths via /mnt/c/, WSL interop spawning security-sensitive Windows binaries, Docker container processes accessing host resources.

- **BYOVD (driver-based EDR killers)** — Detects vulnerable driver staging (.sys drops in temp/user paths), service installation (Event 7045), and planted code-signing certificates. Automatically revokes non-public certs from TrustedPublisher/Root stores, kills the installer chain, and disables all driver services signed by the revoked cert. Covers 35+ known vulnerable drivers from the Microsoft WDBL and LOLDrivers project.

- **Advanced evasion** — Indirect syscalls / Hell's Gate pattern detection (scans process memory for syscall stubs in non-image regions), process injection via unbacked RWX memory detection, named pipe C2 enumeration with known-bad pattern matching.

- **Hardware security downgrade** — Detects if someone disables TPM, Secure Boot, BitLocker, or Credential Guard.

- **Attack surface reduction** — Self-healing Defender ASR Block rules; DEP/SEHOP/Spectre mitigations; AlwaysInstallElevated stripped; attack-only IPSec + Telnet/Remote Registry disable by default. Optional full port/service lockdown via `RestrictivePortHardening`.

## What it does NOT protect against

Sentinel is honest about its limits:

- **Kernel implants already loaded and active** — Sentinel runs in userland. A kernel driver that is already executing can suppress any user-mode process. However, Sentinel detects the *entire attack chain leading up to driver load* (privilege escalation, driver file drop, service creation, cert planting) and can neutralize attacks before they reach kernel. See "BYOVD Defense" below.
- **Nation-state zero-days with novel kernel implants** — Custom kernel exploits targeting unknown vulnerabilities are difficult for any behavioral tool to catch at the moment of exploitation. Sentinel still shrinks classic lateral-movement surface (attack-only IPSec, ASR, service/registry hardening, reactive threat-intel isolate) without pre-breaking SSH/RDP for normal users. For kiosk-style lockdown, set `RestrictivePortHardening: true`.
- **Pre-boot attacks** — Sentinel starts after Windows. It detects boot config changes (BCD, EFI, boot drivers) after the fact via `BootIntegrityGuard`.
- **Weak / non-terminal signals alone** — Shell using SSH, Downloads network, SeImpersonate alone, LAN Cast observe, module-count growth, System32 redistributable writes (DirectX/GPU), netsh noise: **logged**, not killed. Destructive response requires a multi-signal chain to C2/exfil/token/shell/cred-dump/BYOVD (`ObserveUntilChain`, v1.9.3).

---

## BYOVD Defense (Bring Your Own Vulnerable Driver)

BYOVD is the #1 technique used by ransomware groups to disable endpoint security. Sentinel has a multi-layer defense:

1. **Pre-load detection** — `DriverLoadMonitor` watches Event 7045 (service install), registry service creation, and .sys file drops in user-writable paths. Known vulnerable drivers (hash + filename blocklist from Microsoft WDBL + LOLDrivers) trigger immediate `KillProcessTree` + service disable.

2. **Certificate tracing (v1.7.0)** — When a suspicious driver is detected, Sentinel extracts its Authenticode signing cert and checks whether it was planted in `TrustedPublisher` or `Root` stores. If the cert is NOT a well-known public CA, Sentinel fires `RemoveCertAndKillAdder` — revoking the planted cert, killing the installer chain, and scanning System32\drivers for other drivers signed by the same cert.

3. **Cross-driver quarantine** — After cert revocation, any other .sys files signed by the same identity are found and their services disabled. The attacker cannot reload without repeating the entire cert-planting chain.

4. **Prerequisite monitoring** — Loading a kernel driver requires admin. Sentinel monitors the full privilege escalation surface (UAC bypass, token manipulation, credential dump) and can terminate attack chains before they reach the point of driver installation.

The result: an attacker needs to escalate privileges, plant a certificate, drop a driver, and register a service — and Sentinel monitors each of those steps independently. Even if one detection layer is bypassed, the others catch it.

Full transparency in [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Is this for you?

**Yes, if:**
- You want a second layer alongside Windows Defender (Sentinel doesn't replace it)
- You run Windows 10/11 and want behavioral detection that works even against unknown threats
- You're a power user, developer, or small team that wants endpoint visibility without paying for enterprise EDR
- You want open-source security you can audit yourself

**Probably not, if:**
- You need enterprise-grade management console, centralized reporting, or fleet deployment
- You expect kernel-level protection (that requires signed drivers and Microsoft certification)
- You want set-and-forget antivirus that never needs a glance at the Events log

**v1.8.3 note:** Sentinel is still opinionated about *attacks*, but default mode no longer kills processes solely for looking like “network from Downloads” or using SSH/torrents/portable tools.

---

## How it works

1. **Unified ETW Session** — A single real-time kernel trace session subscribes to 9 Windows providers (Kernel-Process, Kernel-File, Kernel-Registry, DNS-Client, Threat-Intelligence, PowerShell, Firewall, TaskScheduler, Kernel-Network). Detection latency is ~50ms — fast enough to catch droppers that execute and exit in under a second.

2. **Monitors** — 80+ background monitors consume ETW telemetry and perform additional analysis (behavioral baselines, statistical beaconing detection, memory scanning, hardware state checks, certificate integrity). Monitors that previously polled every 5-30 seconds now react instantly via ETW events.

3. **Detection engine** — Events are scored by the multi-factor ScoringEngine and classified into tiers. Tier 1 (behavioral) signals are high-confidence. Tier 2 (indicator) signals are corroborating evidence. Rules declare their detection category at compile time via attributes. **v2.0:** detections are tagged with MITRE ATT&CK technique IDs when mappable.

4. **Correlation** — Two engines run in parallel:
   - **BehavioralCorrelationEngine** — hand-authored multi-signal composites (ransomware chain, injected C2, token theft + lateral, coercion toolkit, …) at 0.90–0.99 confidence.
   - **WeightedCorrelationEngine (v2.0)** — explainable score cards (`Credential=50 + C2=42 + … ≥ 100`) that emit `Weighted Correlation: Multi-Signal Threat` when threshold + terminal contribution are met. Score-card fields are always written to detection metadata.

5. **Response** — Authorized responses range from log-only to process termination, quarantine, network isolation, certificate removal, and persistence cleanup. The ChainTracer walks the parent process tree, quarantines attack-root binaries, and removes persistence (Run keys, scheduled tasks). Only corroborated threats get killed.

6. **Reputation** — The FileReputationEngine queries 3 sources (CIRCL, MalwareBazaar, VirusTotal via Cloudflare Worker proxy) and combines hash reputation with static PE analysis, signer trust, and contextual risk into a composite 0-100 score.

7. **Reportable-grade evidence (v1.7.7/1.7.8)** — High-confidence attacks produce integrity-sealed packs under `%ProgramData%\Sentinel\IncidentReports\` (SHA-256 manifest + machine-bound HMAC, victim affidavit template, chain of custody, national cybercrime portal links, optional TI share). Sentinel prepares evidence for **you** to file; it does not auto-submit to police or INTERPOL.

8. **Settings UI** — Tray **Settings** (double-click): Overview, Events, **Report to Police**, Quarantine, Safety, **Ops (v2.0 metrics)**, Tools, About. No ActiveResponse toggle in the agent (service-only).

9. **Plugins + rule packs (v2.0)** — `IDetector` / `ICorrelationRule` / `ITelemetryProvider` / `IResponsePlugin` via `PluginRegistry`. Signed disk packs under `%ProgramData%\Sentinel\rules\packs\` (see [docs/RULE_PACKS.md](docs/RULE_PACKS.md)).

10. **Service↔Agent IPC (v2.0)** — Authenticated named pipe (`SentinelIpc-v2`) for live Ops/health. HMAC token under ProgramData; read-only commands only.

---

## Test Suite

**600+** automated tests (xUnit) on net48:
- End-to-end integration tests (full pipeline: telemetry → detection → scoring → correlation → response)
- Unit tests for all critical engines (Response, Correlation, ChainTracer, FileReputation, AntiTamper, Detection)
- Monitor unit tests including LNK classification, threat-intel feed parsing, USB failed-enumeration, PS-ported guards, v1.7.5–1.7.6 features, auto incident evidence packs (v1.7.7/1.7.8)
- Run with `dotnet test`

---

## Installation

Download **`SentinelSetup-2.0.0.exe`** from [GitHub Releases](https://github.com/CroatiaSecurity/Sentinel/releases) (or `releases/2.0.0/` after a local build) and run it as Administrator.

If Setup fails with **Error 5 / temporary directory** while an older Sentinel is installed, that was ASR rule `c1db55ab` (fixed in 1.9.6+). Use elevated `installer\install-no-inno.ps1` or `fix-asr-for-setup.ps1`, then upgrade.

**Minimum installer** — framework-dependent `net48-windows` (no bundled runtime). Small setup package.

Requirements:
- Windows 10 or 11 (x64)
- **.NET Framework 4.8** (already on most machines; Setup offers the Microsoft download page if missing)
- Administrator privileges for installation
- Service runs as SYSTEM; tray Agent runs in the user session (starts immediately after install)

Build the installer locally:
```powershell
cd installer
.\build.ps1
# → installer\SentinelSetup-<version>.exe
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [CHANGELOG.md](CHANGELOG.md) | Full version history and security fixes |
| [THREAT_MODEL.md](THREAT_MODEL.md) | What Sentinel can and cannot detect, bypass scenarios, confidence levels |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting and responsible disclosure |
| [design.md](design.md) | Architecture and technical design |
| [architecture-council.md](architecture-council.md) | Detailed architecture specification |
| [constraints.md](constraints.md) | Hard rules and design constraints |
| [requirements.md](requirements.md) | Functional requirements |
| [docs/RULE_PACKS.md](docs/RULE_PACKS.md) | v2.0 signed correlation rule packs |

---

## Legal Disclaimer

**Sentinel is provided "as is", without warranty of any kind.** See [LICENSE](LICENSE) for the full MIT license.

- Sentinel may terminate processes it identifies as threats. This includes false positives. The authors are not responsible for data loss, service interruption, or any damages resulting from automated response actions.
- Sentinel is a supplementary security tool. It does not replace antivirus software, firewalls, or proper security practices.
- You are responsible for configuring allowlists and reviewing detection logs in your environment.
- Sentinel modifies system state (firewall rules, registry values, device configurations) as part of its response actions. Understand what it does before deploying in production.
- This software is not certified by Microsoft or any security authority. It does not use kernel drivers and has no special OS-level protections.

**Use at your own risk. Test in a non-production environment first.**

---

## License

MIT License. See [LICENSE](LICENSE).

Copyright (c) 2026 Gorstak
