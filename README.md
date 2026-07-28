# Sentinel

Real-time endpoint detection and response for Windows. Runs as a background service, monitors system behavior, and kills threats automatically when multiple signals correlate.

**Current version: 1.6.8**

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

- **Advanced evasion** — Indirect syscalls / Hell's Gate pattern detection (scans process memory for syscall stubs in non-image regions), process injection via unbacked RWX memory detection, named pipe C2 enumeration with known-bad pattern matching.

- **Hardware security downgrade** — Detects if someone disables TPM, Secure Boot, BitLocker, or Credential Guard.

## What it does NOT protect against

Sentinel is honest about its limits:

- **Kernel-level attacks** — If the attacker loads a driver, it's game over. Sentinel runs in userland.
- **Nation-state tooling** — Custom kernel implants, zero-days, hardware backdoors are out of scope.
- **Attacker already running as SYSTEM** — They can kill the service. A watchdog adds seconds of delay, not real protection.
- **Pre-boot attacks** — Sentinel starts after Windows. It detects boot config changes after the fact.

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

2. **Monitors** — 55+ background monitors consume ETW telemetry and perform additional analysis (behavioral baselines, statistical beaconing detection, memory scanning, hardware state checks). Monitors that previously polled every 5-30 seconds now react instantly via ETW events.

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
