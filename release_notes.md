# v1.3.7 — Proactive DLL Sideloading Remediation & Memory Unloading

This release activates proactive system-wide DLL sideloading validation and memory unloading, ensuring that rogue modules are terminated and quarantined in real time. It builds upon the version 1.3.6 protections (CVE Shield, User-Store CAs, browser extensions, and proxies).

## What's New

### 🛡️ Proactive DLL Sideload Scanning & Memory Unloading
- **Proactive Module Validation**: Integrated the `DllUnloadEngine` into the periodic background scan loop in `MemoryBehaviorAnalyzer`. All running processes' loaded modules are now audited system-wide every 90 seconds.
- **Active Memory Remediation**: Sideloaded DLLs detected during periodic scans are immediately unloaded in memory (via `QueueUserAPC` + `FreeLibrary`), with the host process terminated, the DLL quarantined, and read-only lock files placed to prevent re-exploitation.

### 🔒 Security & Blind Spot Remediation (v1.3.6)
- **Proactive CVE Shield**: Fetches CVE catalogs and maps against local assets to drop hardening rules.
- **User-Store Certificate Monitoring**: Audits and monitors both `StoreLocation.LocalMachine` and `StoreLocation.CurrentUser` root trust stores.
- **Browser Extension Policy Protection**: Automated deletion of unauthorized Chrome/Edge force-installed extension policies.
- **Proxy Hijack Protection**: Automatic restoration of proxy settings back to safe baselines.
