# Windows Sentinel

**Userland EDR for Windows — Behavioral Detection & Automated Response**

> Version: 5.7.0 | Author: [Gorstak](https://gorstak.eu) | [GitHub](https://github.com/CroatiaSecurity/Sentinel) | License: MIT

---

## What it is

Windows Sentinel is a userland endpoint detection and response (EDR) tool for Windows. It monitors process behavior at runtime and responds by killing threat chains, quarantining binaries, removing persistence, and blocking attacker infrastructure.

Designed for personal endpoint protection, blue-team education, behavioral analysis, and learning how EDR internals work. It is **not** a replacement for commercial EDR.

---

## What it does

- **Detects** malicious behavior across 50+ monitors: process injection, credential dumping, ransomware, C2 beaconing, overlay phishing, lateral movement, phantom keystrokes, and more
- **Responds** by killing the process tree, quarantining binaries, removing persistence, and blocking attacker IPs
- **Reports** confirmed threat hashes and IPs to community threat intel platforms (MalwareBazaar, AbuseIPDB, URLhaus)

---

## Installation

Run the installer as Administrator:

```powershell
.\WindowsSentinelSetup-5.7.0.exe
```

Installs to `%ProgramFiles%\WindowsSentinel`, creates a Windows Service (SYSTEM), and launches the Agent into the user session with a system tray icon.

---

## Configuration

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
    "AbuseIPDB_ApiKey": "",
    "MalwareBazaar_ApiKey": ""
  }
}
```

---

## Version History

| Version | Date | Summary |
|---------|------|---------|
| 5.7.0 | 2026-06-03 | Restored BeaconingDetector, AllowlistService, ScoringEngine, BehavioralBaselineService, CampaignDetectionRule, ChainTracer, DllUnloadEngine (unload-only fix); installer upgrade/uninstall hardening; 196 tests |
| 5.6.0 | 2026-06-03 | .NET 10 upgrade, YARA/static-analysis removal, restored DllUnload/ModuleValidation/ChainTracer/BeaconingDetector/26 rules with dbghelp.dll fix |
| 5.5.0 | 2026-06-03 | AntiTamperGuard, RansomwareIo whitelist hardening, game path exclusions |
| 5.4.0 | 2026-06-03 | HollowProcessMonitor game false positive fix |
| 5.3.0 | 2026-06-02 | Import 42+ monitors from SentinelOld, remove DeceptionEngine/BrowserDllMonitor |
| 5.2.0 | 2026-06-02 | Complete codebase rebuild from design specs, flat namespace, modern DI |
| 5.1.0 | 2026-06-02 | Active response hardening, expanded kill-authorization fragments |
| 5.0.0 | 2026-06-01 | PhantomKeystrokeGuard, SecureCacheStore salt fix, DeceptionEngine hang fix |
| 4.8.1 | 2026-05-30 | Performance optimization: 25% CPU -> 3-5%, 3GB -> 200-400MB RAM |
| 4.8.0 | 2026-05-30 | Overlay detection game false positive fix (path+signature validation) |
| 4.7.0 | 2026-05-30 | Aggressive RAM optimization: all retention windows tightened |
| 4.6.0 | 2026-05-30 | BrowserDllMonitor removed, unified C2 detection, false positive reduction III |
| 4.5.0 | 2026-05-30 | ClipboardSanitizer, AppNetworkPolicyMonitor, UsbDeviceFingerprinter |
| 4.4.0 | 2026-05-29 | False positive reduction II (games, system services, hardware utilities) |
| 4.3.0 | 2026-05-29 | System tray icon, toast/balloon notifications, real-time UI |
| 4.2.0 | 2026-05-28 | Device installation security, Bluetooth/WiFi/TLS monitors |
| 4.1.0 | 2026-05-27 | Critical false positive fixes (browsers, system services, Defender) |
| 4.0.0 | 2026-05-26 | Anti-tamper, route remediation, secure boot integrity |
| 3.9.0 | 2026-05-25 | Deception cleanup, auto-reporting to threat intel platforms |
| 3.8.0 | 2026-05-25 | Campaign detection false positive fix (exact filename matching) |
| 3.7.0 | 2026-05-24 | Hardening & testing (367 tests), DLL entropy analyzer |
| 3.6.0 | 2026-05-24 | Ransomware I/O monitor, data exfiltration monitor, screen capture monitor |
| 3.5.0 | 2026-05-23 | Chrome credential/session guards, browser extension monitor |
| 3.4.0 | 2026-05-23 | ADS data staging, work folders exfil, named pipe monitor |
| 3.3.0 | 2026-05-23 | Token integrity, syscall stub, parent PID spoof detection |
| 3.2.0 | 2026-05-22 | Memory behavior analyzer, LSASS dump canary, credential canary |
| 3.1.0 | 2026-05-21 | Detection rules framework (26 rules), tiered response system |
| 3.0.0 | 2026-05-20 | Chain tracer, scoring engine, behavioral baseline service |
| 2.8.1 | 2026-05-15 | Fix HealthCheckService blocking GC, EventGraph memory fix |
| 2.8.0 | 2026-05-10 | Module validation, DLL unload engine, process validator |
| 2.5.0 | 2026-04-28 | Beaconing detector, campaign IoC/detection rules |
| 2.3.0 | 2026-04-20 | Allowlist service, false positive tracker, reputation cache |
| 2.1.0 | 2026-04-10 | ETW Threat Intelligence provider integration |
| 2.0.0 | 2026-04-01 | DLL analysis & active response (DLL unload, entropy analyzer) |
| 1.9.0 | 2026-02-20 | WMI persistence monitor, scheduled task monitor |
| 1.8.0 | 2026-03-15 | Remote access monitor, public IP monitor |
| 1.7.0 | 2026-03-01 | Deception engine (pre-kill attacker disruption) |
| 1.6.0 | 2026-02-25 | Webcam/mic monitor, audio hijack detection |
| 1.5.0 | 2026-02-22 | PowerShell threat monitor, ETW tampering detection |
| 1.4.0 | 2026-02-18 | Network monitor, DNS blocklist engine |
| 1.3.0 | 2026-02-12 | File activity monitor, quarantine manager |
| 1.2.0 | 2026-02-08 | Event graph, telemetry fusion engine |
| 1.1.0 | 2026-02-01 | Hollow process detection, process injection rule |
| 1.0.0 | 2026-01-20 | Persistence rule, privilege escalation detection |
| 0.9.0 | 2026-01-15 | Behavioral correlation engine, composite rules |
| 0.7.0 | 2026-01-13 | Scoring engine, IoC scanner, hash reputation |
| 0.6.0 | 2026-01-12 | WMI process monitor, process ancestry cache, circuit breaker |
| 0.5.0 | 2026-01-11 | Ransomware behavior rule, account manipulation detection |
| 0.4.0 | 2026-01-10 | Module validation, DLL sideloading detection |
| 0.3.0 | 2026-01-08 | ETW process monitor, firewall integrity monitor |
| 0.2.0 | 2026-01-07 | Detection engine, JSONL event logger, secure cache store |
| 0.1.0 | 2026-01-05 | Initial release: core architecture, service host, basic detection |

See [CHANGELOG.md](CHANGELOG.md) for full details.

---

## Architecture

- **Runtime** — .NET 10, Windows Service (SYSTEM) + User Agent (tray icon)
- **Detection** — 50+ BackgroundService monitors, ETW kernel/ThreatIntel providers, WMI fallback, campaign IOC detection, beaconing analysis, behavioral baseline profiling
- **Response** — Tiered via structured verdicts: Tier1 (kill-authorized), Tier2 (advisory/log-only), chain tracing with quarantine and persistence removal
- **Logging** — JSONL structured event log, Windows Event Log
- **Security** — DPAPI-encrypted cache, Authenticode-validated quarantine, anti-tamper

---

## Limitations

- Userland only — no kernel driver, limited by standard user/admin access
- Windows only — no cross-platform support
- Single-machine scope — no central management or fleet telemetry

---

## Legal Disclaimer

**Windows Sentinel is provided "as is", without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.**

The author(s) accept no liability for any damage, data loss, system instability, false positives, or unintended consequences arising from the use or misuse of this software. This includes but is not limited to:

- Termination of legitimate processes incorrectly identified as threats
- Quarantine or deletion of files
- Network blocks applied to legitimate hosts
- Conflicts with antivirus, EDR, or other security software

**The aggressive response features (process termination, DLL unloading, firewall rules, file operations) are powerful and operate automatically. You are responsible for understanding what this software does before deploying it.**

This software is intended for use on systems you own or have explicit written authorization to monitor and protect. Use on systems without authorization may violate computer fraud and abuse laws in your jurisdiction.

By using this software, you agree that the author(s) bear no responsibility for any outcome.

---

MIT License — see [LICENSE](LICENSE) for full terms.
