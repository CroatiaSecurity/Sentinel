# Windows Sentinel

**Userland EDR for Windows � Behavioral Detection & Automated Response**

> Version: 5.9.2 | Author: [Gorstak](https://gorstak.eu) | [GitHub](https://github.com/CroatiaSecurity/Sentinel) | License: MIT

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
.\WindowsSentinelSetup-5.9.2.exe
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

## How it Works

### Architecture

```
+--------------------------------------------------------------+
�  Windows Service (SYSTEM session)                            �
�  +----------------+  +------------------+  +--------------+ �
�  � ETW Monitors   �  � WMI Process      �  � File Activity � �
�  � (Process,      �  � Monitor          �  � Monitor      � �
�  �  ThreatIntel)  �  � (fallback)       �  � (FSWatcher)  � �
�  +----------------+  +------------------+  +--------------+ �
�          +-----------------------------------------+         �
�              +------?----------+                             �
�              � Telemetry Fusion�                             �
�              � Engine          �                             �
�              +-----------------+                             �
�              +------?----------+   +-----------------------+ �
�              � Detection Engine�--?� Rules (5+):           � �
�              � (dedup, emit)   �   � LsassAccess, Ransom,  � �
�              +-----------------+   � ReverseShell, Campaign� �
�                     �              � UnsignedBinary         � �
�              +------?----------+   +-----------------------+ �
�              � Response Engine �                             �
�              � (structured     �   +-----------------------+ �
�              �  verdicts)      �--?� ChainTracer           � �
�              +-----------------+   � (kill, quarantine,    � �
�                     �              �  remove persistence)  � �
�              +------?----------+   +-----------------------+ �
�              � JSONL Logger    �                             �
�              +-----------------+                             �
�                                                              �
�  + 50 BackgroundService monitors running in parallel         �
�  + ScoringEngine, AllowlistService, BehavioralBaseline       �
�  + BeaconingDetector, DllUnloadEngine, AntiTamperGuard       �
+--------------------------------------------------------------+

+--------------------------------------------------------------+
�  User Agent (user session)                                   �
�  +--------------+  +--------------+  +--------------------+ �
�  � Tray Icon    �  � Clipboard    �  � Phantom Keystroke  � �
�  � + Balloon    �  � Sanitizer    �  � Guard (LLKH)       � �
�  �   Alerts     �  � (STA thread) �  �                    � �
�  +--------------+  +--------------+  +--------------------+ �
+--------------------------------------------------------------+
```

### Detection Pipeline

1. **Telemetry collection** � ETW kernel events, WMI process creation, FileSystemWatcher, network connections
2. **Fusion** � `TelemetryFusionEngine` aggregates events per-process into `FusedTelemetryContext` with flags (network activity, file writes, suspicious APIs)
3. **Rule evaluation** � `DetectionEngine` runs all `IDetectionRule` implementations against fused context
4. **Scoring** � `ScoringEngine` aggregates multiple detections per-process, applies corroboration boosts and allowlist reductions, produces a `Verdict` (Clean/Suspicious/Malicious/Critical)
5. **Response** � `AdvancedResponseEngine` acts on structured verdicts (`ResponseAction` enum). Only Tier1 detections with `KillAuthorized=true` trigger active response
6. **Chain tracing** � `ChainTracer` walks the process ancestry, kills malicious processes, quarantines binaries, removes Run/RunOnce persistence

### Response Tiers

| Tier | Confidence | Action | Example |
|------|-----------|--------|---------|
| **Tier1Behavioral** | = 0.80 | Kill process tree, quarantine, remove persistence | LSASS dump, ransomware shadow copy deletion, encoded PowerShell |
| **Tier2Indicator** | 0.40�0.79 | Log only, feed correlation engine | Binary from Temp dir, unusual network destination |


### Active Response Matrix

| Detection | Response | Details |
|---|---|---|
| LSASS dump, ransomware, encoded PowerShell, campaign malware | KillProcessTree | Kill + quarantine binary + remove persistence |
| Process hollowing, shellcode injection | KillProcessTree | Kill injected process tree |
| PPID spoofing (T1134.004) | KillProcess | Kill the spoofed process |
| Privilege escalation (elevated from user-writable dir) | KillProcess | Kill |
| DNS poisoning (critical domain IP swap) | NetworkIsolate | Block IP + flush ARP + flush DNS |
| ARP spoof (gateway MAC change) | NetworkIsolate | Block spoofed gateway |
| Default gateway hijack | NetworkIsolate | Block rogue gateway IP |
| C2 beaconing (statistical CV analysis) | NetworkIsolate | Block C2 server IP |
| Data exfiltration spike | NetworkIsolate | Block outbound destination |
| Canary file deleted | KillProcessTree | Ransomware response |
| Credential canary deleted | KillProcessTree | Credential harvester response |
| Phantom rogue network device | Full isolation | Firewall + ARP flush + conn kill + mDNS/SSDP block |
| DLL sideloading | Unload DLL only | FreeLibrary via remote thread (no kill) |
### Key Subsystems

- **AllowlistService** � Suppresses false positives for dev tools, games, trusted publishers. Never suppresses "President's Law" rules (LSASS access, ransomware, credential theft)
- **BeaconingDetector** � Statistical C2 detection via coefficient of variation of inter-connection intervals
- **BehavioralBaselineService** � Learns normal process/path/network patterns, persisted across restarts
- **DllUnloadEngine** � Detects DLL sideloading (system DLL loaded from app directory); unloads the DLL instead of killing the host process
- **CampaignDetectionRule** � Matches known campaign indicators (CobaltStrike, QBot, Emotet, TrickBot) using exact filename matching to avoid false positives
- **PhantomDeviceMonitor** � Scans ARP table for unauthorized network devices, probes suspicious ports (Cast/ADB/DevTools), identifies manufacturer via OUI lookup, blocks rogue devices via firewall + ARP flush + connection kill + mDNS/SSDP discovery block
- **AntiTamperGuard** � Protects Sentinel's own binaries and hardens installation directory ACLs

### Security

- **DPAPI-encrypted cache** � AllowlistService, BehavioralBaseline, and IoC data encrypted at rest via `SecureCacheStore`
- **Authenticode validation** � Quarantine and trusted path checks use code signing verification
- **Anti-tamper** � Installation directory locked with restrictive ACLs; self-monitoring for binary integrity
- **Input validation** � `SecurityValidation` class provides path traversal prevention, filename safety, IP classification

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for full version history.

---

## Limitations

- Userland only � no kernel driver, limited by standard user/admin access
- Windows only � no cross-platform support
- Single-machine scope � no central management or fleet telemetry

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

MIT License � see [LICENSE](LICENSE) for full terms.


