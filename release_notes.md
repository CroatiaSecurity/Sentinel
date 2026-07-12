# v1.3.6 — Proactive CVE Shield & Security Blind Spot Remediation

This release introduces the **Proactive CVE Shield** (anti-PoC engine), which matches local system assets with active vulnerability feeds to deploy defense rules and IoC hashes. It also closes three critical security blind spots: User-Store CA hijacking, browser extension force-installation, and registry-based proxy server redirects.

## What's New

### 🛡️ Proactive CVE Shield (Anti-PoC Engine)
- **Asset Matcher & Hardening**: Periodically crawls active vulnerability catalogs (e.g., CISA KEV), maps them against local registry uninstalls, active TCP/UDP ports, and running process names, and generates dynamic JSON block rules or blocklists known PoC file hashes with `IoCScanner`.
- **Background Worker**: Integrated as a native Windows service background worker (`CveShieldHardener`) managed via the Orchestrator.

### 🔒 Security Blind Spot Remediation
- **User-Store Certificate Monitoring**: Expanded `TlsCertificateMonitor` to audit and monitor both `StoreLocation.LocalMachine` and `StoreLocation.CurrentUser` root trust stores. This stops non-elevated user-space malware from planting a rogue root CA without UAC alerts.
- **Generic Certificate Removal**: Updated `AdvancedResponseEngine` active response to support removing rogue certificates from all current user and local machine stores.
- **Browser Extension Policy Protection**: Added registry monitoring and active response (automatic deletion) for Chrome/Edge force-installed extension policies under `ExtensionInstallForcelist`.
- **Proxy Hijack Protection**: Added registry monitoring and automatic restoration of internet settings proxy keys (`ProxyEnable`, `ProxyServer`, `AutoConfigURL`) back to safe baselines.
