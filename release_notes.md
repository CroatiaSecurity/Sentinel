# v1.3.8 — Missing Core Rules and Monitors Activation

This release integrates and activates several critical rules and background monitors that were previously implemented but remained unregistered in the dependency injection container.

## What's New

### 🛡️ Browser Session Protection (CDP Debug Port Block)
- **ChromeRemoteDebuggingRule**: Registered system-wide (service + agent) to immediately detect and block browser instances (Chrome, Edge, Brave, etc.) spawned with the `--remote-debugging-port` parameter by non-browser parent processes. This closes the gap where attackers steal active session cookies and credentials via the Chrome DevTools Protocol.

### 🔌 Missing Background Monitors Registered
- **DeviceInstallMonitor**: Actively monitors the installation of new drivers and system devices to identify and block Bring Your Own Vulnerable Driver (BYOVD) attack patterns.
- **GatewayFingerprintMonitor**: Actively tracks default gateway addresses to detect and trigger responses on rogue network changes and routing redirects.

### 🔒 Proactive Memory Unloading (v1.3.7)
- System-wide periodic auditing of loaded DLLs and active memory unloads of sideloaded system modules.
