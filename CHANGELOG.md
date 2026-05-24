# Changelog

All notable changes to Windows Sentinel are documented in this file.

## [3.6.0] - 2026-05-24

### Added — Full-Spectrum Protection (Beyond IDS/EDR)

Sentinel expands from a pure IDS/EDR into comprehensive system protection. 13 new monitors cover network integrity, wireless security, and system hardening — attack surfaces that were previously outside Sentinel's scope.

#### Network Hijack Protection (6 monitors)

- **ArpSpoofMonitor** — Polls ARP table via `GetIpNetTable` P/Invoke every 5s. Captures gateway IP→MAC baseline at startup. Detects: gateway MAC change (classic ARP spoof, confidence 0.92), multiple IPs sharing gateway MAC (ARP poisoning, 0.88), virtual OUI on gateway (VM-based MITM, Tier2 0.55). MITRE T1557.002.

- **GatewayFingerprintMonitor** — Captures comprehensive network fingerprint (gateway IP, DNS servers, DHCP server, subnet mask) at startup. Detects: gateway IP change (evil twin/rogue DHCP, 0.80), DNS server change (DNS hijack, 0.82), DHCP server change (rogue DHCP, 0.78), subnet change (network swap, Tier2 0.70). MITRE T1557, T1584.002.

- **PublicIpMonitor** — Checks public IP every 2 minutes via Cloudflare trace + ipify + icanhazip (HTTPS only, no system data sent). Detects: country change (VPN hijack/BGP manipulation, 0.90), ASN change (traffic rerouted through different provider, 0.82), IP change within same ASN (Tier2 0.70), sustained inability to reach check services (network isolation, Tier2 0.50). MITRE T1090.

- **RouteTableMonitor** — Polls routing table via `GetIpForwardTable` P/Invoke every 10s. Captures baseline at startup. Detects: new host routes /32 (selective traffic redirection, 0.85), default route changed (all traffic hijacked, 0.90), route next-hop modified (targeted interception, 0.85), new subnet routes (Tier2 0.72). Filters VPN/Docker/Hyper-V virtual adapter routes. MITRE T1565.002.

- **DnsResponseValidationMonitor** — Periodically resolves canary domains (Google, Microsoft, Cloudflare, GitHub) and validates responses against hardcoded CIDR ranges. Detects: resolution to unexpected IP range (DNS poisoning, 0.88), all domains resolving to same IP (captive portal, Tier2 0.75). Cross-validates via trusted DNS. MITRE T1584.002.

- **TlsCertificateMonitor** — Connects to well-known HTTPS endpoints every 3 minutes and inspects TLS certificates. Detects: self-signed certificate on major domain (0.95), unexpected CA/issuer (MITM proxy, 0.90), known enterprise TLS inspection CA (Tier2 0.65), certificate issuer change from baseline (Tier2 0.60), suspicious validity period (Tier2 0.55). Distinguishes enterprise proxies (Zscaler, BlueCoat) from attacker MITM. MITRE T1557.

#### Wireless Security (2 monitors)

- **WifiSecurityMonitor** — Polls Wi-Fi state via `netsh wlan show interfaces` every 10s. Detects: deauthentication flood (4+ disconnects in 2 minutes, 0.85), connection to open/unencrypted network (0.75), encryption downgrade WPA2→WEP/Open on same SSID (evil twin, 0.88), BSSID change on same SSID (Tier2 0.55). MITRE T1557, T1040.

- **BluetoothMonitor** — Monitors Bluetooth device registry and service state every 15s. Detects: new HID device pairing (BadBT keyboard injection, 0.80), new non-HID device pairing (Tier2 0.55), Bluetooth service activated when previously stopped (Tier2 0.50). MITRE T1200, T1011.

#### System Integrity (5 monitors)

- **SecureBootIntegrityMonitor** — Checks boot configuration every 5 minutes via registry + bcdedit. Detects: Secure Boot disabled (bootkit vector, 0.70-0.92 depending on baseline), test signing mode enabled (rootkit vector, 0.90 if changed from disabled), kernel debugging enabled (kernel manipulation, 0.60-0.90). MITRE T1542, T1014.

- **FirewallIntegrityMonitor** — Polls firewall state via `netsh advfirewall` every 30s. Detects: firewall profile disabled (0.88), bulk inbound allow rules added (5+ rules, 0.82), Windows Firewall service stopped (0.90). MITRE T1562.004.

- **ScheduledTaskMonitor** — Polls scheduled tasks via `schtasks` every 30s. Captures baseline at startup. Detects: new tasks with suspicious properties (temp paths, encoded PowerShell, SYSTEM from user paths, script execution, random names). Multi-indicator scoring: 1 indicator = Tier2, 2+ = Tier1 (0.60-0.92). MITRE T1053.005.

- **WindowsUpdateIntegrityMonitor** — Monitors update services every 2 minutes. Detects: Windows Update service stopped (0.78), BITS service stopped (Tier2 0.65), automatic updates disabled via registry/GPO (0.80), Defender definitions stale >7 days (Tier2 0.70). MITRE T1562.001.

### Changed

- Version bumped to 3.6.0 across all projects (Core, Service, Agent, Installer, version.txt)
- `ServiceCollectionExtensions.cs` updated with new monitor registrations
- All documentation updated (README, CHANGELOG, THREAT_MODEL, design, requirements, constraints, architecture-council)

### Security Impact

Sentinel now detects attacks that were previously completely invisible:
- **ARP spoofing** on local network (coffee shop, hotel, office)
- **Evil twin** Wi-Fi access points
- **DNS poisoning** (rogue DHCP pushing attacker DNS)
- **TLS MITM** (mitmproxy, Burp Suite, rogue proxy)
- **Route injection** (selective traffic redirection)
- **VPN hijacking** (traffic silently rerouted)
- **Deauth attacks** (forcing reconnection to rogue AP)
- **BadBT** (Bluetooth keyboard injection)
- **Bootkit preparation** (Secure Boot/test signing tampering)
- **Firewall disabling** (opening the system for C2/lateral movement)
- **Scheduled task persistence** (most common malware persistence mechanism)
- **Update suppression** (preventing security patches)

---

## [3.5.0] - 2026-05-23

### Added — Behavioral RAT Kill (Novel RAT Detection Without IOCs)

#### New Composite Correlation Rules (BehavioralCorrelationEngine)

- **Covert RAT: Unsigned + Hidden + Network [COMPOSITE]** — Detects novel RATs by behavioral pattern alone: unsigned binary from staging path (Temp/AppData) + sustained outbound network connection or beaconing. Confidence 0.88 (0.92 with recon activity). No campaign IOC required.
- **Confirmed C2 Beacon: Unsigned Process [COMPOSITE]** — Unsigned binary exhibiting periodic beaconing pattern (regular intervals with jitter). Confidence 0.88 (0.93 from staging path). Catches any C2 beacon regardless of framework.
- **Covert C2: Unsigned Binary + Sustained Connection [COMPOSITE]** — Unsigned binary maintaining a 60s+ outbound connection. Confidence 0.90. Catches the exact PlugX/RAT pattern: fake updater from temp path holding persistent HTTPS to C2.

#### President's Law Kill List — Existing Composites Promoted

The following composites were previously log-only despite high confidence. They are now kill-authorized:

| Composite | Confidence | Previous | New |
|-----------|-----------|----------|-----|
| Injected C2 Beacon | 0.98 | LogOnly | **Kill** |
| DGA + C2 Beaconing | 0.94 | LogOnly | **Kill** |
| Spoofed Process Phoning Home | 0.92 | LogOnly | **Kill** |
| Dropped Payload Phoning Home | 0.93 | LogOnly | **Kill** |
| Staged Payload + Non-Standard Port | 0.92 | LogOnly | **Kill** |

#### Kill Fragments Added

Service (`AdvancedResponseEngine`):
- `"covert rat:"`, `"covert c2:"`, `"confirmed c2 beacon:"`
- `"injected c2 beacon"`, `"dga + c2 beaconing"`, `"spoofed process phoning home"`, `"dropped payload phoning home"`, `"staged payload + non-standard port"`

Agent (`AgentResponseEngine`):
- `"covert rat:"`, `"covert c2:"`, `"confirmed c2 beacon:"`
- `"injected c2 beacon"`, `"dga + c2 beaconing"`, `"spoofed process phoning home"`, `"dropped payload phoning home"`

### Changed

- Version bumped to 3.5.0 across all projects (Core, Service, Agent, Installer)

### Security Impact

With these composites, a novel RAT (no known campaign IOC) will now be killed if it exhibits ANY of:
- Unsigned binary from temp/AppData + sustained network connection (60s+)
- Unsigned binary + periodic beaconing pattern
- Unsigned binary from staging path + any network + no visible window

This closes the gap where PlugX survived because its confidence (0.78) was below the campaign threshold. The new behavioral composites don't need campaign recognition — the behavior alone is sufficient.

---

## [3.4.0] - 2026-05-23

### Added — Active Response Expansion (President's Law Kill List)

#### President's Law Kill List Expansion

The response engine now actively kills processes for threat categories that were previously log-only:

- **RAT / APT Campaign Composites**: `"campaign:"`, `"rat activity"`, `"remote access trojan"`, `"confirmed rat"`, `"apt:"` — confirmed campaign IOC matches (PlugX, Cobalt Strike, etc.) are now kill-authorized with a lowered confidence threshold of 0.75 (campaign rules already correlate multiple signals internally).
- **Confirmed LSASS Dumps**: `"confirmed lsass dump"`, `"lsass dump"` — composite detections confirming credential dumping via dbghelp.dll + LSASS targeting are now killed immediately.
- **Reverse Shells**: `"reverse shell"`, `"interactive shell: outbound"` — confirmed interactive outbound shells are kill-authorized.
- **Process Injection / Hollowing**: `"process hollowing"`, `"process injection: confirmed"`, `"hollow process"` — runtime-confirmed injection is kill-authorized.
- **Keylogging / Input Capture**: `"keylogger"`, `"keystroke capture"`, `"input capture"` — spyware behavior is kill-authorized.
- **UAC Bypass Exploitation**: `"uac bypass: exploited"`, `"uac bypass: active exploitation"` — active exploitation of elevation vectors is kill-authorized.

#### Host-Level Composite Resolution

- **HandleHostLevelCompositeAsync**: Composite detections that fire with PID 0 / "Host-Level" (e.g., "Data Exfiltration: Credential Theft + Network") now extract actual offending PIDs from the evidence text using regex PID extraction, then re-dispatch kill actions against those specific processes.
- **ExtractPidsFromEvidence**: New utility method that parses "PID XXXX" patterns from composite evidence strings.

#### Agent Kill List Synchronization

- **AgentResponseEngine**: Kill fragments expanded to match the service engine — now includes RAT campaigns, keyloggers, reverse shells, credential dumps, and data exfiltration composites.

### Changed

- **EvaluateMustKill**: Now uses per-fragment confidence thresholds. Campaign IOCs use 0.75 (vs 0.85 default) because campaign rules already perform multi-signal correlation internally.
- **CampaignCorroboratedThreshold**: New constant (0.75) for campaign IOC confidence gating.
- Version bumped to 3.4.0 across all projects (Core, Service, Agent, Installer)

### Security Impact

With these changes, the following threats from the events.jsonl would now be actively killed:

| Threat | Rule | PID | Previous Response | New Response |
|--------|------|-----|-------------------|--------------|
| PlugX RAT | Campaign: PlugX | 7264, 7644 | LogOnly | **Kill** (conf 0.78 ≥ 0.75 campaign threshold) |
| LSASS Dump | Confirmed LSASS Dump [COMPOSITE] | 7120 | LogOnly | **Kill** (conf 0.97 ≥ 0.85) |
| Data Exfiltration | Data Exfiltration: Credential Theft + Network | Host-Level→resolved PIDs | LogOnly | **Kill** (PID resolution from evidence) |

---

## [3.3.0] - 2026-05-23

### Added — Electron Allowlist & Work Folders Protection

#### Electron/JIT App Allowlist (False Positive Elimination)

- **BehavioralCorrelationEngine**: Added comprehensive allowlist of 40+ Electron/JIT apps that are now excluded from composite correlation. Eliminates false "In-Memory Implant + Network Beacon" and "DGA + C2 Beaconing" composites for:
  - IDEs: Kiro, VS Code, Rider, IntelliJ, PyCharm, WebStorm, GoLand
  - Communication: Discord, Slack, Teams, Signal, WhatsApp, Telegram
  - Productivity: Notion, Obsidian, Figma, Postman, Todoist, ClickUp, Linear
  - Security: Bitwarden, 1Password
  - Media: Spotify, Loom
  - Gaming: Steam, steamwebhelper
  - Dev tools: GitKraken, Insomnia
  - Windows system: dwm, TextInputHost, SearchHost, ShellExperienceHost
  
- **MemoryBehaviorAnalyzer**: Expanded JIT process exclusion list with all the above Electron apps. These processes legitimately use RWX memory for V8/SpiderMonkey JIT compilation.

#### Work Folders Exfiltration Monitor (Kill-Authorized)

- **WorkFoldersExfilMonitor** — Detects and blocks unauthorized Work Folders activation:
  - Monitors Work Folders service state (kills if running on personal machine)
  - Detects new sync server URLs appearing in registry (removes them)
  - Detects Group Policy injection for auto-provisioning (deletes policy keys)
  - Detects Work Folders process execution (kills immediately)
  - Takes baseline at startup — alerts if already configured
  - Active response: stops service, kills process, removes registry config
  - MITRE T1567, T1048, T1484.001

### Changed

- Version bumped to 3.3.0 across all projects

---

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
