# Windows Sentinel

**Userland EDR for Windows — Behavioral Detection, Automated Response & Aggressive Deception**

> Version: 5.0.0 | Author: [Gorstak](https://gorstak.eu) | [GitHub](https://github.com/CroatiaSecurity/Sentinel) | License: MIT

---

## What it is

Windows Sentinel is a userland endpoint detection and response (EDR) tool for Windows. It monitors process behavior at runtime and responds by killing threat chains, quarantining binaries, removing persistence, and actively disrupting attacker infrastructure before the kill.

Designed for personal endpoint protection, blue-team education, behavioral analysis, and learning how EDR internals work. It is **not** a replacement for commercial EDR.

---

## What it does

- **Detects** malicious behavior across 50+ monitors: process injection, credential dumping, ransomware, C2 beaconing, overlay phishing, lateral movement, phantom keystrokes, and more
- **Responds** by killing the process tree, quarantining binaries, removing persistence, and blocking attacker IPs
- **Deceives** attackers before the kill: poisons exfiltrated data, floods C2 servers with fake sessions, deploys filesystem traps, and corrupts implant memory
- **Reports** confirmed threat hashes and IPs to community threat intel platforms (MalwareBazaar, AbuseIPDB, URLhaus)

---

## Installation

Run the installer as Administrator:

```powershell
.\WindowsSentinelSetup-5.0.0.exe
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
    "AbuseIpDbApiKey": null,
    "UrlhausAuthToken": null,
    "ReportToMalwareBazaar": true,
    "ReportToUrlhaus": true
  }
}
```

- `ActiveResponse: false` — switches to monitor-only mode (no kills)
- AbuseIPDB/URLhaus reporting requires free API keys from their respective sites

---

## Building

Requires .NET 8 SDK on Windows.

```bash
dotnet build WindowsSentinel.sln
```

```powershell
cd installer
.\build.ps1
```

---

## Limitations

- No kernel driver — cannot prevent BYOVD, direct syscalls, or kernel-level attacks
- Local admin wins — an attacker with admin rights can kill the service
- Not a replacement for Windows Defender or commercial EDR — run alongside them
- Single-machine scope — no central management or fleet telemetry

---

## Legal Disclaimer

**Windows Sentinel is provided "as is", without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.**

The author(s) accept no liability for any damage, data loss, system instability, false positives, or unintended consequences arising from the use or misuse of this software. This includes but is not limited to:

- Termination of legitimate processes incorrectly identified as threats
- Quarantine or deletion of files
- Network blocks applied to legitimate hosts
- Deception tactics affecting system state
- Conflicts with antivirus, EDR, or other security software

**The aggressive response and deception features (process termination, DLL unloading, firewall rules, memory manipulation, file operations) are powerful and operate automatically. You are responsible for understanding what this software does before deploying it.**

This software is intended for use on systems you own or have explicit written authorization to monitor and protect. Use on systems without authorization may violate computer fraud and abuse laws in your jurisdiction.

By using this software, you agree that the author(s) bear no responsibility for any outcome.

---

MIT License — see [LICENSE](LICENSE) for full terms.
