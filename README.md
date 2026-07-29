# Sentinel

Real-time endpoint detection and response for Windows. Runs as a background service, monitors system behavior, and kills threats automatically when multiple signals correlate.

**Current version: 1.7.2**

---

## What does it protect against?

Sentinel is effective against:

- **Script kiddies and commodity malware** — Ransomware, infostealers, RATs, cryptominers. Behavioral detection means it doesn't matter what the malware is named or where it came from. If it deletes shadow copies, encrypts files in bulk, dumps credentials, or injects into processes — it dies.

- **Living-off-the-land attacks (LOLBins)** — PowerShell abuse, WMI lateral movement, MSHTA/rundll32 proxy execution, scheduled task persistence, UAC bypasses. Sentinel watches what trusted binaries *do*, not just that they exist.

- **Credential theft** — LSASS dumps (dbghelp.dll sideloading, direct syscall variants), browser credential store access (Chrome/Edge/Firefox), honeypot credential tripwires, Credential Guard disablement monitoring, token theft / impersonation (SYSTEM token from user process, SeImpersonatePrivilege abuse).

- **Browser-based C2** — Headless Chrome used as a proxy, Chrome DevTools Protocol session hijacking, malicious extensions with debugger/nativeMessaging/proxy permissions. Correlates with beaconing for high-confidence composite kills.

- **Physical access attacks** — BadUSB/Rubber Ducky devices (HID whitelist), post-idle hardware change detection, new Bluetooth devices, rogue USB drives.

- **Network attacks** — ARP spoofing, DNS poisoning, rogue Wi-Fi, unauthorized Cast/screen-share devices, C2 beaconing (statistical), DNS tunneling/exfiltration, phantom network devices.

- **Persistence mechanisms** — Scheduled tasks, WMI subscriptions, registry run keys, DLL sideloading, boot config tampering, PrintNightmare-class spooler exploitation (driver DLL planting + child process detection).

- **Container/WSL escape** — Detects lateral movement FROM WSL/Docker INTO the Windows host: filesystem writes to sensitive paths via /mnt/c/, WSL interop spawning security-sensitive Windows binaries, Docker container processes accessing host resources.

- **BYOVD (driver-based EDR killers)** — Detects vulnerable driver staging (.sys drops in temp/user paths), service installation (Event 7045), and planted code-signing certificates. Automatically revokes non-public certs from TrustedPublisher/Root stores, kills the installer chain, and disables all driver services signed by the revoked cert. Covers 35+ known vulnerable drivers from the Microsoft WDBL and LOLDrivers project.

- **Advanced evasion** — Indirect syscalls / Hell's Gate pattern detection (scans process memory for syscall stubs in non-image regions), process injection via unbacked RWX memory detection, named pipe C2 enumeration with known-bad pattern matching.

- **Hardware security downgrade** — Detects if someone disables TPM, Secure Boot, BitLocker, or Credential Guard.

## What it does NOT protect against

Sentinel is honest about its limits:

- **Kernel implants already loaded and active** — Sentinel runs in userland. A kernel driver that is already executing can suppress any user-mode process. However, Sentinel detects the *entire attack chain leading up to driver load* (privilege escalation, driver file drop, service creation, cert planting) and can neutralize attacks before they reach kernel. See "BYOVD Defense" below.
- **Nation-state zero-days with novel kernel implants** — Custom kernel exploits targeting unknown vulnerabilities are difficult for any behavioral tool to catch at the moment of exploitation. However, Sentinel significantly reduces the attack surface that nation-state tools depend on: it disables WinRM, RDP, SMB, remote WMI, Remote Registry, SSH, and 50+ inbound ports via self-healing IPSec policy; disables discovery protocols (SSDP, UPnP, LLMNR, mDNS); enforces DEP AlwaysOn, SEHOP, and Spectre/Meltdown mitigations; strips AlwaysInstallElevated; and kills lateral movement services at the kernel level. Even APT tooling that relies on WMI lateral movement, WinRM, or SMB will find those services disabled and re-disabled every 30 seconds if re-enabled. Cozy Bear (APT29) relies on WinRM and WMI for lateral movement — both are dead on a Sentinel-hardened machine.
- **Pre-boot attacks** — Sentinel starts after Windows. It detects boot config changes (BCD, EFI, boot drivers) after the fact via `BootIntegrityGuard`.

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
- You want set-and-forget antivirus — Sentinel is opinionated and may kill processes aggressively

---

## How it works

1. **Unified ETW Session** — A single real-time kernel trace session subscribes to 9 Windows providers (Kernel-Process, Kernel-File, Kernel-Registry, DNS-Client, Threat-Intelligence, PowerShell, Firewall, TaskScheduler, Kernel-Network). Detection latency is ~50ms — fast enough to catch droppers that execute and exit in under a second.

2. **Monitors** — 80+ background monitors consume ETW telemetry and perform additional analysis (behavioral baselines, statistical beaconing detection, memory scanning, hardware state checks, certificate integrity). Monitors that previously polled every 5-30 seconds now react instantly via ETW events.

3. **Detection engine** — Events are scored by the multi-factor ScoringEngine and classified into tiers. Tier 1 (behavioral) signals are high-confidence. Tier 2 (indicator) signals are corroborating evidence. Rules declare their detection category at compile time via attributes.

4. **Correlation** — The BehavioralCorrelationEngine evaluates multi-signal composites on the same process within 60 seconds. 12 composite patterns (Injected C2 Beacon, Active Ransomware Chain, Credential Dump + Exfiltration, Named Pipe C2 + Beaconing, Token Theft + Lateral Movement, etc.) produce kill-authorized detections with 0.90-0.99 confidence.

5. **Response** — Authorized responses range from log-only to process termination, quarantine, network isolation, certificate removal, and persistence cleanup. The ChainTracer walks the parent process tree, quarantines attack-root binaries, and removes persistence (Run keys, scheduled tasks). Only corroborated threats get killed.

6. **Reputation** — The FileReputationEngine queries 3 sources (CIRCL, MalwareBazaar, VirusTotal via Cloudflare Worker proxy) and combines hash reputation with static PE analysis, signer trust, and contextual risk into a composite 0-100 score.

---

## Test Suite

689 automated tests (xUnit), all passing in < 5 seconds:
- End-to-end integration tests (full pipeline: telemetry → detection → scoring → correlation → response)
- Unit tests for all critical engines (Response, Correlation, ChainTracer, FileReputation, AntiTamper, Detection)
- Run with `dotnet test`

---

## Installation

Download the latest installer from [releases/](releases/) and run it. Sentinel installs as a Windows Service and starts automatically.

Requirements:
- Windows 10 or 11 (x64)
- .NET 10 Runtime
- Administrator privileges for installation
- Runs as SYSTEM after install

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
