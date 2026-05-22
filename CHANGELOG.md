# Changelog

All notable changes to Windows Sentinel are documented in this file.

## [3.2.0] - 2026-05-22

### Added — Browser & Account Credential Protection + PowerShell Threat Monitoring

This release closes the browser credential theft gap across ALL browsers and adds Microsoft account protection. Sentinel now actively detects and kills processes attempting to steal saved passwords, cookies, session tokens, or Microsoft account PRT tokens. Also adds PowerShell script-block threat monitoring to detect living-off-the-land attacks.

#### New Monitors

- **ChromeCredentialGuardMonitor** — Monitors file-level access to Chromium browser credential stores:
  - `Login Data` (saved passwords, DPAPI-encrypted)
  - `Cookies` / `Network\Cookies` (session cookies for Google account hijacking)
  - `Local State` (contains the encrypted DPAPI key for decryption)
  - `Web Data` (autofill, credit cards)
  - Detects copy-then-read patterns used by infostealers (Redline, Raccoon, Vidar)
  - Covers all Chromium browsers: Chrome, Edge, Brave, Opera, Vivaldi, Arc

- **FirefoxCredentialGuardMonitor** — Monitors Firefox/Gecko credential stores:
  - `key4.db` (NSS master key database — decrypts all passwords)
  - `logins.json` (encrypted saved passwords)
  - `cookies.sqlite` (session cookies — UNENCRYPTED in Firefox, high-value target)
  - `cert9.db` (client certificates for authentication)
  - Covers: Firefox, Firefox ESR, Waterfox, Pale Moon, Thunderbird
  - Note: Firefox cookies are stored in PLAINTEXT SQLite — no decryption needed by attackers

- **MicrosoftAccountGuardMonitor** — Protects Microsoft/Azure AD account tokens:
  - TokenBroker cache monitoring (`.tbres` files containing WAM tokens)
  - Primary Refresh Token (PRT) extraction detection
  - BrowserCore.exe abuse detection (PRT access from non-browser processes)
  - Azure AD token theft tool detection (ROADtools, AADInternals, TokenTacticsV2)
  - Office 365 token protection (registry-based token stores)
  - MITRE T1528 — Steal Application Access Token

- **BrowserExtensionMonitor** — Detects malicious extension installation:
  - Baselines installed extensions at startup
  - Alerts on new extensions with dangerous permission combinations
  - Detects registry-based force-install (enterprise policy abuse)
  - Higher confidence when extensions are installed while browser is NOT running
  - MITRE T1176 — Browser Extensions

- **ChromeSessionGuardMonitor** — Detects active session hijacking:
  - Chrome remote debugging port abuse (`--remote-debugging-port`)
  - Chrome DevTools Protocol (CDP) connections from scripting processes
  - App-Bound Encryption bypass (elevation_service.exe spawned by non-browser)
  - MITRE T1539 — Steal Web Session Cookie, T1185 — Browser Session Hijacking

- **PowerShellThreatMonitor** — Detects malicious PowerShell usage:
  - ETW script-block logging (Microsoft-Windows-PowerShell provider, Event ID 4104)
  - AMSI bypass detection (AmsiScanBuffer patching, AmsiUtils reflection)
  - ETW bypass detection (NtTraceEvent/EtwEventWrite patching)
  - Download cradle detection (IEX+IWR, WebClient.DownloadString, BITS)
  - Reflective loading (Assembly.Load, Invoke-ReflectivePEInjection)
  - Offensive framework detection (Mimikatz, BloodHound, PowerSploit, Empire)
  - Credential theft commands (Invoke-Kerberoast, DCSync, etc.)
  - Encoded command detection (-EncodedCommand obfuscation)
  - Execution policy bypass detection
  - Falls back to command-line scanning when ETW is unavailable
  - MITRE T1059.001, T1562.001, T1027, T1105

#### New Detection Rule

- **BrowserCredentialTheftRule** — Process-start detection for browser credential theft:
  - Known stealer tools: SharpChromium, HackBrowserData, LaZagne, ChromePass, Firepwd, etc.
  - Chromium path patterns (Login Data, Local State, Cookies)
  - Firefox path patterns (key4.db, logins.json, cookies.sqlite)
  - Microsoft account patterns (TokenBroker, PRT, AADInternals, ROADtools)
  - DPAPI decryption indicators (CryptUnprotectData, sekurlsa::dpapi)
  - Python/PowerShell stealer library imports
  - MITRE T1555.003, T1539, T1528

#### Response Policy Update

- **President's Law** kill list updated: `"browser credential theft"` fragment added
- Both Service (AdvancedResponseEngine) and Agent (AgentResponseEngine) will now terminate processes that trigger browser credential theft detections with confidence ≥ 0.85
- PowerShell critical threats (AMSI bypass, credential theft) are kill-authorized via existing ETW tampering and credential dump fragments
- Pre-kill validation gate still applies (won't kill user-interactive foreground apps)

### Changed

- Version bumped to 3.2.0 across all projects (Core, Service, Agent, Installer)

---

## [3.1.0] - 2026-05-21

### Added — Observability, Blind Spots & Resilience

- Centralized security validation (`SecurityValidation` utility)
- Rate limiting with burst capability (`BurstRateLimiter`)
- Configuration integrity monitoring (`ConfigIntegrityMonitor`)
- Structured health checks (`SentinelHealthCheck`)
- Performance metrics (`SentinelMetrics`)
- Secure HTTP client factory (`SecureHttpClientFactory`)
- Atomic quarantine operations
- Comprehensive test coverage

---

## [3.0.0] - 2026-05-20

### Added — Security Hardening, Observability & Resilience

- DLL-search-order hardening (`ProcessHardening`)
- Strict install directory validation (opt-in via `SENTINEL_STRICT_INSTALL_DIR=1`)
- Service binary tamper protection (`ServiceProtectionMonitor`)
- Event Log flooding reduction (Warning+ only to Event Viewer)
- Log rotation service with configurable size/retention
- Graceful shutdown service

---

## [2.8.1] - 2026-05-15

### Fixed — Architecture Hardening & Bug Fixes

- Version management via version.txt
- Build script improvements

---

## [2.8.0] - 2026-05-10

### Added — Deception Refinements & Ransomware Fast-Path

- Aggressive Deception Engine (memory flooding, file traps, clipboard poison, beacon flooding)
- Canary File Monitor (ransomware fast-path detection)
- Firewall Tampering Rule
- Account Manipulation Rule
- Data Exfiltration Rule
- Asynchronous off-host deception

---

## [2.5.0] - 2026-04-28

### Added — NeuroBehavior & AudioHijack

- NeuroBehavior Visual Monitor
- AudioHijack module-based detection

---

## [2.3.0] - 2026-04-20

### Changed — Agent Architecture

- Moved user-session monitors to Agent (Clipboard, ScreenCapture, WebcamMic, AudioHijack, MicSession)
- ADS Data Staging Monitor

---

## [2.1.0] - 2026-04-10

### Added — Community Threat Intelligence

- ThreatIntelReporter (AbuseIPDB, URLhaus, MalwareBazaar)

---

## [2.0.0] - 2026-04-01

### Added — DLL Analysis & Active Response

- DLL Unload Engine (active response via FreeLibrary)
- Browser DLL Monitor / ELF Catcher
- Disk-Wide DLL Scanner
- DLL Entropy Analyzer
- UAC Bypass Surface Monitor
- PE Analyzer, ClamAV Engine, YARA-X Engine

---

## [1.8.0] - 2026-03-15

### Added — Data Exfiltration Prevention

- Data Exfiltration Monitor (outbound volume, sensitive file access, USB)

---

## [1.7.0] - 2026-03-01

### Added — Aggressive Deception Engine

- Pre-kill deception tactics (memory flooding, implant destabilizer, beacon flooder)

---

## [1.1.0] - 2026-02-01

### Added — Advanced Anti-APT Monitors

- DNS Query Monitor (DGA, tunneling)
- Parent PID Spoof Detector
- Syscall Stub Integrity Monitor
- Credential Canary Monitor
- Token Integrity Monitor
- LSASS Dump Canary Monitor
- WMI Persistence Monitor
