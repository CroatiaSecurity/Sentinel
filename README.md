# 🛡️ Windows Sentinel

**Userland IDS/EDR for Windows — Behavioral Threat Detection & Automated Response**

> Version: 0.7.9 | Author: [Gorstak](https://gorstak.eu) | License: MIT

[![Release](https://img.shields.io/github/v/release/CroatiaSecurity/Sentinel?style=flat-square)](https://github.com/CroatiaSecurity/Sentinel/releases/latest)
[![License](https://img.shields.io/github/license/CroatiaSecurity/Sentinel?style=flat-square)](LICENSE)

---

## 📖 What Is This

Windows Sentinel is a runtime behavioral EDR that monitors what processes **do** — not what they are. It detects malicious behavior at runtime and responds by killing threat chains, quarantining binaries, removing persistence, and blocking attacker infrastructure.

No signatures. No blocklists. No name-based detection. Pure behavioral analysis.

**Philosophy:** Allow anything to run until it proves itself malicious. Then kill it, quarantine it, trace its installer, and remove every trace of persistence.

---

## ⚡ Quick Start

```powershell
# Run as Administrator
.\WindowsSentinelSetup-0.7.9.exe
```

Installs a Windows Service (SYSTEM) + user Agent (tray icon). Active response is enabled by default.

---

## 🔍 How Detection Works

```
Telemetry → Fusion → Rules → Scoring → Response → Chain Trace
```

1. **Telemetry** — ETW kernel events, network connections (GetExtendedTcpTable), file system watchers, ARP table polling, DNS queries, registry changes
2. **Fusion** — Events are grouped per-process with behavioral flags (has network? wrote to temp? called injection APIs?)
3. **Rules** — 10+ detection rules evaluate fused context: LSASS access, ransomware patterns, reverse shells, LOLBin abuse, DLL sideloading, privilege escalation, attack tools
4. **Scoring** — Multi-signal scoring with corroboration boosts. Only fires when confidence crosses threshold
5. **Response** — Tier1 (proven malicious) → kill + quarantine. Tier2 (suspicious) → log only, feed correlation engine
6. **Chain Trace** — Walk parent process tree, find the dropper, quarantine it, remove Run keys / scheduled tasks / services

---

## 🎯 What It Detects

| Category | Technique | Detection Method |
|----------|-----------|-----------------|
| 💀 **Credential Theft** | LSASS dump, token theft | Sysmon/Security event log monitoring |
| 🔐 **Ransomware** | Shadow copy deletion, mass rename | VSS event + FileActivityMonitor rename counter |
| 🌐 **C2 Beaconing** | Regular interval callbacks | Statistical coefficient of variation (CV < 0.40) |
| 💉 **Process Injection** | Hollowing, reflective DLL, thread injection | VirtualQueryEx memory layout + ETW ThreatIntel |
| 🔑 **Privilege Escalation** | UAC bypass, token manipulation | Command-line pattern matching (fodhelper, sdclt, etc.) |
| 🛠️ **LOLBin Abuse** | certutil, mshta, regsvr32, rundll32, etc. | 60+ behavioral patterns (binary + suspicious arguments) |
| 📡 **Network Attacks** | ARP spoofing, phantom devices, route injection | GetIpNetTable, GetIpForwardTable, ARP polling |
| 📜 **Persistence** | Run keys, services, scheduled tasks, COM hijack | Registry polling + WMI watchers |
| 🔒 **Certificate Attacks** | MitM root CA, BYOVD driver signing | Root + TrustedPublisher store monitoring |
| 🖥️ **DLL Sideloading** | System DLL in app directory | Module enumeration + quarantine + lock file |
| 🛑 **Anti-Tamper** | Process suspend, binary deletion, service removal | 2s timing tick, binary integrity, SCM monitoring |

---

## 🛡️ Response Actions

| Response | What It Does |
|----------|-------------|
| **KillProcessTree** | Terminate entire process tree + quarantine binary + remove persistence |
| **NetworkIsolate** | Block IP via Windows Firewall COM API + flush DNS |
| **RemoveCert** | Remove malicious certificate from Root/TrustedPublisher store |
| **QuarantineAndKill** | Quarantine injected DLLs + kill host process + lock file path |
| **RemoveRegistryEntry** | Delete malicious Run key / service / CLSID |
| **BYOVD Chain** | Remove cert + stop driver service + delete registry + quarantine .sys |

---

## 🏗️ Architecture

**Service (SYSTEM session):** ETW monitors, network scanning, registry monitoring, beaconing detection, route table protection, certificate monitoring, file activity, 50+ background monitors.

**Agent (user session):** Tray icon, clipboard sanitizer, screen capture detection, overlay phishing detection, shell watchdog, browser extension monitor.

Both communicate through shared detection/response pipeline via the `DetectionEngine` → `AdvancedResponseEngine` → `ChainTracer` chain.

---

## 🔒 Security Design

- **No name-based trust** — process names are trivially spoofed. All exemptions require verified install paths
- **No built-in allowlists** — only user-managed allowlist can suppress (and never for President's Law rules)
- **President's Law** — LSASS, ransomware, injection, credential theft ALWAYS fire regardless of any allowlist
- **AV-clean** — no CreateRemoteThread, no ReadProcessMemory, no netsh shell-outs. Uses COM APIs and event logs
- **Graceful degradation** — works on custom/debloated Windows without WMI (falls back to registry polling)
- **Open source** — attackers can read the code, but behavioral detection can't be bypassed by renaming

---

## 📋 Documentation

| Document | Description |
|----------|-------------|
| [CHANGELOG.md](CHANGELOG.md) | Full version history with every fix and feature |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Threat model and detection confidence scores |
| [design.md](design.md) | Architecture, component inventory, data flow |
| [requirements.md](requirements.md) | Functional and non-functional requirements |
| [constraints.md](constraints.md) | Hard rules that are never violated |

---

## ⚙️ Configuration

`appsettings.json` in the install directory:

```json
{
  "Sentinel": {
    "ActiveResponse": true,
    "LogPath": null,
    "WatchPath": null
  },
  "ThreatReporting": {
    "Enabled": true,
    "AbuseIPDbApiKey": "",
    "MalwareBazaarApiKey": ""
  }
}
```

- `ActiveResponse: true` — kill/quarantine/block enabled (default)
- `ActiveResponse: false` — log-only mode, no active response
- `LogPath` — custom path for events.jsonl (default: `%ProgramData%\WindowsSentinel\`)
- `WatchPath` — custom directory for FileActivityMonitor (default: all user profiles)

---

## 📊 Logs

All events logged to `%ProgramData%\WindowsSentinel\events.jsonl` in structured JSONL format:

```json
{"type":"detection","timestamp":"...","data":{"RuleName":"...","Evidence":"...","Confidence":0.95,...}}
{"type":"response","timestamp":"...","data":{"ActionTaken":"KILL","Reason":"...",...}}
{"type":"health","timestamp":"...","data":{"WorkingSetMB":128,"DetectionsTotal":12345,...}}
```

---

## ⚠️ Limitations

- Userland only — no kernel driver, can't prevent kernel-level attacks
- Windows only — no cross-platform support
- Single-machine scope — no central management or fleet telemetry
- Not a replacement for commercial EDR — designed for personal use, education, and research

---

## 📜 License & Disclaimer

MIT License — see [LICENSE](LICENSE).

**This software kills processes, quarantines files, modifies firewall rules, and removes certificates automatically.** You are responsible for understanding what it does before deploying it. The author accepts no liability for false positives, data loss, or system instability. Use only on systems you own or have explicit authorization to protect.
