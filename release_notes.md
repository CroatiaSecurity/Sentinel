# v1.3.5 — EDR Stability, Hardening, and Self-Contained IPSec Policy

This release resolves critical EDR false positives, stabilizes system-level process terminations (preventing unexpected reboots and BSODs), addresses download file locking contentions, hardens directory path checks, and packages the legacy IPSec policy builder as a fully self-contained C# feature.

## What's New

### EDR Stability & BSOD Prevention
- **Process Ancestry Lookup Fix**: Corrected a bug in parent name resolution cache walk that returned shifted child process names. Legitimate system processes like `services.exe` are now correctly identified and protected from tree-kills.
- **Robust Image Path Querying**: Replaced buggy `MainModule.FileName` queries in `RawDiskAccessMonitor` and `NetworkReinfectionDetector` (which throw "Access Denied" for elevated system binaries, leading to untrusted process classification) with robust low-privilege `GetProcessImagePath` API calls.
- **Disk Access Allowlist**: Added `services.exe`, `svchost.exe`, `taskhostw.exe`, and `System` to the raw disk access allowlist, preventing unintended Service Control Manager terminations that triggered Windows reboots and BSODs.

### File Contention & Download Fixes
- **UUP Dump Offline Downloads**: Added directory exclusion checks for `\uups\` and `uup` folders to bypass Restart Manager handle locks and reputation checks. This resolves "file in use by another process" sharing violations in `aria2c` downloader scripts.

### False Positive Mitigation
- **Signed Updaters Protection**: `NetworkReinfectionDetector` now integrates `SignerTrustService` to check Authenticode signatures, skipping immediate alerts/kills on signed browser updaters (GoogleUpdate, BraveUpdate) launching right after network-up events.
- **Cast Device Guard Relaxation**: Changed the default action of unauthorized local Cast connections from `KillProcessTree` to `LogOnly`. Because connections are already blocked via the Windows Firewall, this keeps browsers (Chrome/Brave) alive while maintaining security.

### Security Hardening
- **Directory Path Hijack Prevention**: Hardened all Windows directory validation checks (`.StartsWith(winDir)`) to enforce a trailing backslash (`\`) suffix. This blocks path-traversal / namespace spoofing bypasses where malware runs from folders like `C:\WindowsTemp\`.
- **Self-Contained IPSec Policy**: Ported the entire `IPSecPolicy.ps1` script (port tables, rules, filters) directly into native C# within the `HardeningModule`. The policy is applied dynamically on the first boot (creating a `.ipsec_applied` common flag to skip on subsequent boots), eliminating any external script or registry dependencies.
