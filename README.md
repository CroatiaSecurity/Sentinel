# Windows Sentinel

Real-time endpoint detection and response for Windows. Runs as a background service, monitors system behavior, and kills threats automatically when multiple signals correlate.

**Current version: 1.4.5**

---

## What does it protect against?

Sentinel is effective against:

- **Script kiddies and commodity malware** — Ransomware, infostealers, RATs, cryptominers. Behavioral detection means it doesn't matter what the malware is named or where it came from. If it deletes shadow copies, encrypts files in bulk, dumps credentials, or injects into processes — it dies.

- **Living-off-the-land attacks (LOLBins)** — PowerShell abuse, WMI lateral movement, MSHTA/rundll32 proxy execution, scheduled task persistence, UAC bypasses. Sentinel watches what trusted binaries *do*, not just that they exist.

- **Credential theft** — LSASS dumps (dbghelp.dll sideloading, direct syscall variants), browser credential store access (Chrome/Edge/Firefox), honeypot credential tripwires, Credential Guard disablement monitoring.

- **Physical access attacks** — BadUSB/Rubber Ducky devices (HID whitelist), post-idle hardware change detection, new Bluetooth devices, rogue USB drives.

- **Network attacks** — ARP spoofing, DNS poisoning, rogue Wi-Fi, unauthorized Cast/screen-share devices, C2 beaconing (statistical), DNS tunneling/exfiltration, phantom network devices.

- **Persistence mechanisms** — Scheduled tasks, WMI subscriptions, registry run keys, DLL sideloading, boot config tampering.

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

1. **Monitors** — 50+ background monitors observe process creation, network connections, file changes, registry modifications, hardware state, and credentials via ETW, WMI, and native APIs.

2. **Detection engine** — Events are scored and classified into tiers. Tier 1 (behavioral) signals are high-confidence. Tier 2 (indicator) signals are corroborating evidence.

3. **Correlation** — Multiple signals on the same process within 120 seconds produce a composite detection. Single signals rarely kill on their own.

4. **Response** — Authorized responses range from log-only to process termination, quarantine, and network isolation. Only corroborated threats get killed.

---

## Installation

Download the latest installer from [releases/](releases/) and run it. Sentinel installs as a Windows Service and starts automatically.

Requirements:
- Windows 10 or 11 (x64)
- .NET 8 Runtime
- Administrator privileges for installation
- Runs as SYSTEM after install

---

## Documentation

| Document | Description |
|----------|-------------|
| [CHANGELOG.md](CHANGELOG.md) | Full version history and security fixes |
| [THREAT_MODEL.md](THREAT_MODEL.md) | What Sentinel can and cannot detect, bypass scenarios, confidence levels |
| [design.md](design.md) | Architecture and technical design |
| [architecture-council.md](architecture-council.md) | Detailed architecture specification |
| [constraints.md](constraints.md) | Hard rules and design constraints |
| [requirements.md](requirements.md) | Functional requirements |

---

## Legal Disclaimer

**Windows Sentinel is provided "as is", without warranty of any kind.** See [LICENSE](LICENSE) for the full MIT license.

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
