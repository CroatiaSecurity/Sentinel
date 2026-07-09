## What's New in v1.2.9

### Security Hardening: 12 Patches from Red-Team Audit

Comprehensive defensive hardening based on adversarial analysis of all detection monitors. Closes timing windows, prevents trust gaming, and eliminates blanket exclusions that attackers could exploit.

#### P0 — Critical Blind Spots Closed

- **WMI Process Gap Coverage** — 250ms fast-poll catches sub-second payloads that executed between WMI's 1-2s event delivery
- **AppData Monitoring Restored** — Temp, Roaming\Microsoft, and program directories under AppData are no longer excluded from file monitoring
- **Learning Phase Hardened** — Unsigned binaries from staging paths can no longer poison the network baseline during the 30-minute learning window

#### P1 — Detection Evasion Prevented

- **Kill Protection Path-Verified** — Malware naming itself `csrss.exe` or `explorer.exe` outside System32 will be killed
- **Composite Correlation for Signed Apps** — Supply-chain compromises of Electron apps no longer evade multi-signal detection
- **Beaconing Trust Demotion Hardened** — DLL sideloading into signed apps + decoy connections no longer demotes response to LogOnly
- **Ghost Process Immediate Alert** — First-scan detection for connections to known C2/reverse-shell ports

#### P2 — Tamper Resistance & Deception

- **Anti-Suspend Threshold Halved** — 4s detection (was 10s) with hardware-monotonic QPC time source
- **Cache HMAC Non-Deterministic** — Key now includes install-specific entropy, not just boot time
- **Credential Canaries Randomized** — 3-5 decoys per boot with unique names from 8 enterprise service templates
- **DNS Event Gap Closed** — No more 30s time filter dropping events between polls

#### P3 — Forensic Chain Integrity

- **Dead PID Retention** — Killed processes remain in ancestry cache for 60s, enabling complete chain tracing

**Full Changelog**: https://github.com/CroatiaSecurity/Sentinel/compare/v1.2.8...v1.2.9
