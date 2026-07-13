# Windows Sentinel

**Userland EDR for Windows — Behavioral Threat Detection & Automated Response**

> Version: 1.4.4 | Author: [Gorstak](https://gorstak.eu) | License: MIT

---

## Read This Before Installing

Sentinel is not a passive antivirus. It actively modifies your system to harden it against attack. You need to understand what it does before you install it.

### What Sentinel changes on your machine

| Action | What it does | Why |
|--------|-------------|-----|
| **Password rotation** | Rotates all local account passwords to random 32-character strings every 10 minutes. Configures Windows auto-logon so boot/restart is seamless. | Prevents null-session and blank-password network attacks. You won't type this password — Windows Hello PIN or auto-logon handles authentication. |
| **IPSec port blocking** | Creates a Windows IPSec policy ("GSecurity") that blocks 60+ inbound/outbound ports including SSH (22), RDP (3389), SMB (445), Telnet (23), VNC (5900), WinRM (5985/5986), and common RAT ports. | Eliminates network attack surface. If you need any of these ports, you must remove the IPSec rules manually. |
| **Built-in Administrator disabled** | Disables the built-in Administrator account (RID 500) every 15 seconds if it gets re-enabled. | Attackers enable this account for persistence. If you use it, stop — create a named admin account instead. |
| **UAC enforced to maximum** | Sets UAC `ConsentPromptBehaviorAdmin` to 5 (prompt for credentials on secure desktop). | Prevents silent elevation. You'll be prompted for credentials on UAC dialogs, not just "Yes/No". |
| **Firewall rules added** | Blocks inbound RPC ephemeral ports (49664-49675) from LAN, blocks Cast device ports, blocks all outbound to listed dangerous ports. | Prevents lateral movement via DCOM/WMI/Task Scheduler RPC, rogue Cast device relay attacks. |
| **Safe Mode registration** | Registers the service to run in Safe Mode (both Minimal and Networking). | Prevents attackers from rebooting into Safe Mode to operate without Sentinel. |
| **Screen lock timeout disabled** | If Windows Hello PIN is not configured, disables screen lock timeout. | Prevents lockout since you can't type the rotated random password. **Set up a Windows Hello PIN to restore lock screen.** |
| **Process killing** | Kills processes and entire process trees that exhibit malicious behavior. | This is the core function. Active response is enabled by default. |
| **File quarantine** | Moves malicious binaries to a DPAPI-encrypted vault and deletes originals. | Removes threats from disk. Quarantined files are in `%ProgramData%\WindowsSentinel\Quarantine\`. |
| **Certificate removal** | Removes unauthorized root/trusted publisher certificates from the certificate store. | Prevents MitM attacks via rogue CAs. |
| **DNS cache flush** | Flushes DNS resolver cache when network threats are detected. | Clears potentially poisoned DNS entries. |
| **Registry modifications** | Removes malicious Run keys, services, scheduled tasks, COM objects, and QoS throttling policies targeting Sentinel. | Removes attacker persistence and anti-EDR throttling. |

### Who this is for

- Security researchers and enthusiasts who want aggressive endpoint protection on personal machines
- Users who have experienced active intrusion and want to harden their system
- People willing to trade convenience for security

### Who this is NOT for

- Shared workstations or enterprise environments (no central management)
- Users who rely on RDP, SSH, SMB file sharing, or remote PowerShell to their machine
- Systems running services that need the blocked ports (databases, Docker, game servers)
- Users who don't understand what the above table means

### Before you install

1. **Set up a Windows Hello PIN** — Sentinel rotates your account password. If you don't have a PIN, you'll need auto-logon to get in (which Sentinel configures), but you won't have a lock screen
2. **Document any ports you need open** — The IPSec policy blocks RDP, SSH, SMB, and many others. You'll need to manually remove rules via `netsh ipsec static delete rule` if you need them
3. **Don't use the built-in Administrator account** — It will be disabled. Use a named account in the Administrators group instead
4. **Understand that Sentinel kills things** — Active response is on by default. If you run penetration testing tools, they will be terminated. Use `appsettings.json` → `ActiveResponse: false` for log-only mode

---

## Quick Start

```powershell
# Run as Administrator
.\WindowsSentinelSetup-1.4.4.exe
```

Installs a Windows Service (SYSTEM) + user-session Agent (tray icon). Protection begins immediately.

To disable active response without uninstalling:
```powershell
# Edit the config (requires admin)
notepad "C:\Program Files\WindowsSentinel\appsettings.json"
# Set "ActiveResponse": false, then restart the service
sc stop "Windows Sentinel" & sc start "Windows Sentinel"
```

---

## How Detection Works

```
Monitors → Telemetry Fusion → Detection Rules → Scoring Engine → Response → Chain Trace
```

1. **Monitors** (60+ BackgroundServices) — ETW kernel events, network connections, file system watchers, ARP table, DNS queries, registry, USB devices, Bluetooth, certificates, process memory
2. **Fusion** — Events grouped per-process with behavioral context (network? temp writes? injection APIs?)
3. **Rules** — Behavioral detection: LSASS access, ransomware patterns, C2 beaconing, DLL sideloading, privilege escalation, reverse shells, credential theft
4. **Scoring** — Multi-signal scoring with corroboration. Multiple weak signals on the same PID = composite kill
5. **Response** — Tier1 (proven malicious) → kill + quarantine. Tier2 (suspicious) → log, feed correlation
6. **Chain Trace** — Walk parent tree, find the dropper, quarantine it, remove Run keys / services / tasks

### President's Law — Always kills, no exceptions

These behaviors ALWAYS trigger kill response regardless of allowlists, trust scores, or signed binaries:
- LSASS credential access
- Ransomware (shadow copy deletion + bulk encryption)
- Process injection (hollowing, reflective DLL, thread injection)
- Reverse shells
- AMSI/ETW tampering
- Privilege escalation
- Self-protection tampering (anti-Sentinel behavior)

---

## What It Detects

| Category | Detection Method |
|----------|-----------------|
| Credential theft | LSASS dump monitoring, credential canary tripwires, browser credential guard |
| Ransomware | Shadow copy events + FileActivityMonitor bulk rename/encrypt counter |
| C2 beaconing | Statistical coefficient of variation on connection intervals (CV < 0.40) |
| Process injection | ETW ThreatIntel kernel-level API observation + memory layout analysis |
| DLL sideloading | Module enumeration + in-memory FreeLibrary unload + quarantine + lock file |
| Network attacks | ARP spoofing, DNS poisoning, route injection, phantom devices, rogue adapters |
| Persistence | Registry Run keys, services, WMI subscriptions, scheduled tasks, COM hijack |
| Certificate attacks | Root CA injection, BYOVD driver signing, TLS interception |
| Anti-tamper evasion | Process suspend detection (QPC), binary deletion, service deregistration |
| Data exfiltration | Upload volume baseline + outbound connection whitelist + MTP transfer guard |
| Boot attacks | BCD monitoring, EFI partition scan, Secure Boot state, boot driver baseline |
| USB attacks | HID device whitelist, BadUSB/Rubber Ducky detection, device disable |

---

## Architecture

**Service (SYSTEM):** 60+ background monitors in 6 priority groups, ETW sessions, detection engine, response engine, chain tracer, quarantine manager, IPSec enforcement, password rotation, port blocking.

**Agent (user session):** Tray icon notifications, clipboard sanitizer, screen capture detection, webcam/mic monitoring, phantom keystroke guard, browser extension monitor. Supervised by the Service-side `AgentWatchdog`.

Monitor groups start in priority order with staggered timing:
1. **Critical** (0s) — AntiTamper, IPSec, AgentWatchdog, SyscallStub — restarts indefinitely
2. **Core Detection** (2s) — Ransomware, Beaconing, FileVerdict, GhostProcess — 5 restart attempts
3. **Credential Protection** (4s) — BrowserCredentialGuard, CanaryFile, NullSession — 3 attempts
4. **Network Integrity** (6s) — ARP, DNS validation, PublicIP, WiFi, NetworkShare — 3 attempts
5. **System Integrity** (10s) — Firewall, SecureBoot, Registry, WMI persistence — 3 attempts
6. **Peripheral** (30s) — Bluetooth, USB, MTP, Volume, Cast, WSL — 2 attempts

Source layout (each group has a matching source file):
```
src/WindowsSentinel.Core/
├── MonitorGroup.cs                          — Group infrastructure
├── Monitors/
│   ├── CriticalMonitors.cs                  — SyscallStubMonitor, IPSecIntegrityGuard
│   ├── CoreDetectionMonitors.cs             — DLL scanning, entropy, module integrity
│   ├── CredentialProtectionMonitors.cs      — Canary files, browser creds, password rotation
│   ├── NetworkIntegrityMonitors.cs          — ARP, DNS, WiFi, phantom devices
│   ├── SystemIntegrityMonitors.cs           — Firewall, boot, TLS, registry, persistence
│   └── PeripheralMonitors.cs               — Bluetooth, USB, MTP transfer
```

---

## Configuration

`appsettings.json` in the install directory (`C:\Program Files\WindowsSentinel\`):

```json
{
  "Sentinel": {
    "ActiveResponse": true,
    "LogPath": null,
    "TrustedCastDevices": [],
    "DnsPollIntervalSeconds": 15,
    "RouteTableScanIntervalSeconds": 15,
    "CveShield": {
      "Enabled": true,
      "PollIntervalHours": 4
    }
  },
  "ThreatReporting": {
    "Enabled": true,
    "ProxyEndpoint": "https://sentinel-threat-proxy.znastidobrostoje-6ee.workers.dev"
  },
  "ApplicationIntegrity": {
    "Enabled": true,
    "ScanIntervalSeconds": 30,
    "ProtectedApps": []
  }
}
```

Key settings:
- `ActiveResponse: false` — disables all kill/quarantine/block actions (log-only mode)
- `TrustedCastDevices: ["192.168.1.50"]` — IPs of your Chromecast/Nest devices (not killed)
- `ApplicationIntegrity.ProtectedApps` — executables to protect from unauthorized replacement
- Config is preserved across upgrades (never overwritten)

---

## Logs & Forensics

- **Event log:** `%ProgramData%\WindowsSentinel\events.jsonl` (structured JSONL, 50MB rotation)
- **Quarantine:** `%ProgramData%\WindowsSentinel\Quarantine\` (DPAPI-encrypted)
- **Incident reports:** `%ProgramData%\WindowsSentinel\IncidentReports\` (forensic evidence)
- **Crash logs:** `%ProgramData%\WindowsSentinel\agent_crash.log`

---

## Threat Reporting

When Sentinel detects confirmed malicious files/IPs/URLs, it reports them to community threat intelligence platforms (MalwareBazaar, URLhaus, AbuseIPDB) via a Cloudflare Worker proxy. This helps the security community.

- Reports are HMAC-signed (cannot be spoofed or replayed)
- No personal data is sent — only file hashes, malicious IPs, and malicious URLs
- Disable with `"ThreatReporting": { "Enabled": false }` in appsettings.json

---

## Uninstalling

```powershell
# Run the uninstaller from Add/Remove Programs, or:
"C:\Program Files\WindowsSentinel\unins000.exe"
```

The uninstaller:
- Stops and deletes the Windows Sentinel service
- Removes the Agent auto-start registry key
- Deletes the program files
- **Preserves** `%ProgramData%\WindowsSentinel\` (your logs and quarantine vault)
- **Does NOT remove** the IPSec policy — run `netsh ipsec static delete policy name=GSecurity` manually
- **Does NOT restore** your original password — set a new one via `net user <username> <newpassword>`

---

## Limitations

- **Userland only** — no kernel driver, cannot prevent kernel-level attacks
- **Windows only** — .NET 10, x64
- **Single-machine** — no central management, no fleet telemetry
- **Not a replacement for commercial EDR** — designed for personal use, research, and education
- **False positives possible** — pentesting tools, custom development builds, and some gaming anti-cheat systems may trigger detections

---

## Security Design

- **Behavioral, not signature-based** — detects what processes DO, not what they ARE
- **President's Law** — critical threats always killed regardless of allowlists or trust
- **No name-based trust** — process names are trivially spoofed; all exemptions require path + signature verification
- **Open source** — assume the attacker reads this code; behavioral detection still works
- **Absence ≠ safety** — unknown files get Unknown verdict, not Safe. Only positive reputation confirms trust
- **No user-level response control** — only SYSTEM can toggle protection
- **HMAC-signed telemetry** — threat reports cryptographically signed, unforgeable
- **Minimum-privilege handles** — no overprivileged process access rights
- **No shell interpolation** — all external commands use safe parameter passing

---

## Documentation

| Document | Description |
|----------|-------------|
| [CHANGELOG.md](CHANGELOG.md) | Full version history |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Threat model, bypass scenarios, confidence assessment |
| [design.md](design.md) | Architecture, component inventory, data flow |
| [constraints.md](constraints.md) | Hard rules that are never violated |

---

## License & Disclaimer

MIT License — see [LICENSE](LICENSE).

**This software actively modifies your system.** It rotates passwords, blocks ports, kills processes, quarantines files, modifies firewall rules, disables accounts, removes certificates, and deletes registry entries — all automatically. You are responsible for understanding what it does before deploying it. The author accepts no liability for lockouts, data loss, broken network services, or system instability.

**Test in a VM first.**
