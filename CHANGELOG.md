# Changelog

## 2.8.1 — Architecture Hardening & Bug Fixes (May 2026)

### Fixes: Installer Upgrade Race Condition
- **File-lock race (DeleteFile code 5):** The previous teardown issued `taskkill /f` and waited a fixed 3 seconds, which was insufficient when the OS deferred handle closure. A new `WaitForFileLockRelease` helper now actively probes `SentinelService.exe` with a rename-probe loop (up to 30 s), ensuring Inno Setup never attempts to overwrite a still-locked binary. Fixes *"An error occurred while trying to replace the existing file: DeleteFile failed; code 5. Access is denied."* on upgrades.
- **Double taskkill pass:** Added a second `taskkill /f /im SentinelService.exe` after a 1 s sleep to catch deferred process exits before the file-lock poll begins.

### Fixes: Concurrency & Resource Leak Hardening
- **Process Handle Leaks:** Fixed a process handle leak in `HardeningModule.cs` where process querying handles were not closed/disposed, causing system handle exhaustion over time.
- **Implant Destabilizer GC Lifetimes:** Moving EventWaitHandle and TcpListener instances to long-lived `IDisposable` container classes to prevent premature Garbage Collection during asynchronous execution.
- **Sync-over-Async Mitigation:** Converted several thread-blocking calls in `ClamAVEngine.cs` and `HardeningModule.cs` to use proper asynchronous await patterns, preventing thread pool starvation under high load.
- **Telemetry Process Name Resolution:** Modified `NetworkMonitor.cs` to inject `ProcessAncestryCache` directly, providing accurate process names in outbound telemetry reports instead of raw PIDs.
- **Honeypot Listener Lifetimes:** Modified `DeceptionEngine.cs` to ensure background tactical listeners (BeaconFlooder, NetworkHoneypotDeployer) run as long-lived tasks bound to the application lifetime, rather than being cancelled early by tactical tokens.

### Fixes: Storage & Cryptography
- **NTP-Resistant Boot-Bound Nonce:** Updated `SecureCacheStore.cs` to extract boot session timestamps directly from the System process (PID 4) start time via `Process.GetProcessById(4).StartTime`, eliminating NTP time-drift validation issues.
- **Robust Quarantine Metadata Parsing:** Upgraded `QuarantineManager.cs` to use split boundary guards, preventing parsing crashes on complex path strings or metadata delimiters.

### Infrastructure
- All version references bumped to 2.8.1.
- Released May 21, 2026.

---

## 2.8.0 — Quick Wins: Anti-Evasion & Zero-Latency Ransomware Defense (May 2026)

### New: Ransomware Canary Monitor
- Introduced `CanaryFileMonitor`, which deploys hidden `.docx` and `.xlsx` canary files to the user's `Documents` and `Desktop`.
- Instantly triggers a Tier 1 high-confidence kill if any process tampers with these files, providing a zero-latency defense before mass I/O ransomware rules even trigger.

### New: Network & Account Tampering Detection
- Added `FirewallTamperingRule` to detect `netsh` and PowerShell commands that disable firewalls or alter routing, utilizing highly specific argument combinations to defeat executable renaming.
- Added `AccountManipulationRule` to detect lateral movement attempts via `net user /add` or `New-LocalUser`.

### New: Data Exfiltration Detection
- Added `DataExfiltrationRule` to detect known data-hoarding tools like `rclone` and `azcopy` configured for bulk transfer, relying on unique parameter combinations to catch renamed binaries.

### Enhancements: Execution & Response
- **Suspicious Parent-Child Process Trees:** `MemoryExecutionRule` now instantly flags any shell spawned by an Office application (`winword.exe`, `excel.exe`, etc.), even if the command is not obfuscated.
- **Forensic Process Suspension:** `AdvancedResponseEngine` now uses `NtSuspendProcess` to freeze malicious processes in memory *before* calling `Process.Kill()`. This neutralizes threats instantly while preserving memory state for forensic analysis.

### Fix: Event Logger Resilience
- `JsonlEventLogger` constructor no longer crashes the entire service if the log file cannot be opened at startup. Falls back to degraded mode (detections still processed, just not persisted to disk) and logs a warning.
- `OpenWriter()` now uses explicit `FileStream` with `FileShare.ReadWrite`, allowing concurrent log readers (SIEMs, forensic tools) without sharing violations.
- **Self-healing writer:** If the log file was inaccessible at startup, subsequent write attempts automatically retry opening it. The service recovers as soon as the file becomes accessible.
- **Stale file handling:** If the log file is locked or has hostile ACLs, `OpenWriter()` renames it to `.stale.<timestamp>` and creates a fresh log file, preventing permanent startup failures.
- Log rotation catch block now safely wraps the fallback `OpenWriter()` call to prevent cascading failures.

### Fix: Installer Upgrade Hardening
- Service teardown now runs in `[Code] CurStepChanged(ssInstall)` — **before** file extraction — so the service binary is not locked during overwrite.
- `TearDownExistingService` resets tamper-protection ACLs, kills processes, stops and deletes the service, then polls SCM for up to 15 seconds until the entry is fully purged.
- Added `events.jsonl` cleanup: during upgrade, the installer renames the old log file to `.upgrade-backup` to prevent `UnauthorizedAccessException` crashes from stale file locks or inherited ACLs.

### Infrastructure
- All version references bumped to 2.8.0.
- Released May 20, 2026.

---

## 2.7.0 — Tamper Protection & Pipeline Resilience (May 2026)

### Security: Service ACL Tamper Protection
- Introduced strict Security Descriptors (SDDL) in `setup.iss` to protect the Sentinel Service from being stopped or modified by standard local administrators.
- The service can now only be stopped by `SYSTEM`, mitigating `net stop` and `taskkill` evasion attempts by attackers who have bypassed UAC but lack SYSTEM privileges.

### Reliability: Pipeline & Deception Timeouts
- **Global Pipeline Timeout:** Added a strict 2000ms `CancellationToken` wrapper in `AdvancedResponseEngine.cs` to prevent the agent from hanging due to ReDoS or locked files during the evaluation and response phase.
- **Background Deception Timeout:** Added a 10-second `CancellationToken` to asynchronous network deception tasks (`BeaconFlooder`, `NetworkHoneypotDeployer`) in `DeceptionEngine.cs` to prevent thread pool exhaustion from hanging sockets.

### Detection Rule Enhancements
- **MemoryExecutionRule:** Added coverage for `pwsh.exe` (PowerShell Core). Replaced naive empty-path checks with a native `QueryFullProcessImageName` fallback in `ProcessValidator` to prevent false positives from ETW delays.
- **EtwTamperingRule:** Added missing EDR tools (`MsSense.exe`, `senseir.exe`, `sysmon.exe`, Splunk). Fixed registry pattern to catch PSDrive variations (`HKLM:\SYSTEM\...`). Added evasion patterns `phollow`, `unhook`, and `amsi.fail`.

### Infrastructure
- All version references bumped to 2.7.0.
- Released May 20, 2026.

---

## 2.6.0 — Deception Refinements & Ransomware Fast-Path (May 2026)

### New: Ransomware Response Fast-Path
Ransomware attacks require immediate containment. In `AdvancedResponseEngine.cs`, we introduced a high-priority bypass for ransomware detections.
- Checks if the rule name or reasoning contains `"ransomware"`.
- If matched, the engine completely bypasses the 2-second `DeceptionEngine` window.
- The process kill proceeds immediately, prioritizing zero-latency termination to protect files on disk.

### Fix: x64 Thread Stack Corruption Bug
The `ImplantDestabilizer` previously queried thread contexts using a simplified byte-array representation of the `CONTEXT` structure, which suffered from layout misalignment on x64, leading to random access violations and stack corruption.
- Replaced the byte-array with a fully aligned, 16-byte packed native `CONTEXT` struct.
- Added `SuspendThread` and `ResumeThread` P/Invokes to safely pause target threads before querying context.
- Extracted the stack pointer (`Rsp`) directly on x64 processes, enabling precise target writing for stack corruption without causing process instability.

### New: Asynchronous / Background Deception Tactics
Off-host and network-based deception tactics can take considerable time. Awaiting them sequentially within the 2-second pre-kill budget can delay process termination.
- Network-based tactics (`BeaconFlooder`, `NetworkHoneypotDeployer`) are now executed asynchronously in the background.
- They run as fire-and-forget tasks, letting the EDR proceed immediately to the process kill step.
- Only local-process deception (memory flooding, DLL/module stomping, clipboard/file traps) blocks the kill within the pre-kill window.

### Infrastructure
- All version references bumped to 2.6.0 across source files, project files, and installers.
- Released May 20, 2026.

---

## 2.5.0 — NeuroBehavior Visual Monitor + AudioHijack Enhancement (May 2026)

### New: NeuroBehaviorVisualMonitor (ported from Antivirus.ps1)
Detects visual/input manipulation attacks by monitoring the user's screen and input devices. Ported from the original `Invoke-NeuroBehaviorMonitor` in Antivirus.ps1 which was previously lost during the C# port.

**Detections (all Tier2 advisory — never kill independently):**
- **Focus Abuse** — Process stealing focus >8 times in 10 seconds
- **Flash Stimulus** — Rapid brightness oscillation (6+ large brightness changes)
- **Topmost Abuse** — Non-allowlisted process forcing WS_EX_TOPMOST
- **Cursor Jitter** — Rapid programmatic cursor movement (>6 large jumps in 10s)
- **Color Inversion** — Screen colors inverted (current ≈ inverse of previous frame)
- **Screen Distortion** — Rapid color channel shifts without inversion

**Why Tier2:** Games, video players, and browsers legitimately cause rapid brightness changes, topmost windows, and cursor movement. Killing on these alone would destroy the user experience. But combined with other signals (mic session, audio hijack, injection), they produce composite kills.

**Safe for games/browsers:** The Pre-Kill Validation Gate (v2.2.0) provides additional safety — even if a composite fires, user-interactive foreground apps running stably for 5+ minutes are never killed.

### New: 4 Composite Correlation Rules
| Composite | Confidence | Trigger |
|-----------|-----------|---------|
| Sensory Manipulation: Visual + Mic Session | 0.93 | NeuroBehavior signal + unauthorized mic session |
| Sensory Manipulation: Visual + Audio Hijack | 0.94 | NeuroBehavior signal + audio output-to-mic routing |
| Injected Visual Manipulator | 0.92 | Process injection + NeuroBehavior visual manipulation |
| Coordinated Visual Manipulation Attack | 0.90 | 3+ distinct NeuroBehavior signal types from same process |

Total composites: 34.

### Enhanced: AudioHijackMonitor (no longer command-line dependent)
Previously, the AudioHijackMonitor only fired if it found specific command-line tokens like `-output=mic` or `virtualmic`. This was trivially bypassed by any tool that doesn't advertise its intent in the command line.

**New detection path (module-based):**
- If a background process (no visible window) loads BOTH audio-output modules AND mic-input modules, AND is not in the allowlist of legitimate audio apps → fires at 0.75 confidence
- Command-line token detection still works (fires at 0.85 confidence when found)
- Allowlist covers: Discord, Teams, Zoom, browsers, OBS, Audacity, Spotify, etc.

### Infrastructure
- All version references bumped to 2.5.0
- NeuroBehaviorVisualMonitor registered in Agent (requires user session for screen capture, cursor, foreground window)
- Feeds TelemetryFusionEngine for cross-monitor composite correlation

---

## 2.4.0 — ADS Staging Detection + Agent Architecture (May 2026)

### New: AdsDataStagingMonitor
Detects large NTFS Alternate Data Streams used to hide exfiltration staging data. ADS are invisible to Explorer, `dir`, and standard file listings — attackers use them to stage hundreds of GBs of stolen data that causes "invisible" disk usage.

**How it works:**
- Scans high-value directories (Temp, AppData, ProgramData, Public) every 2 minutes
- Uses `FindFirstStreamW`/`FindNextStreamW` to enumerate ADS on files
- Flags any non-standard ADS larger than 10 MB (legitimate ADS are always <1 KB)
- Fires as Tier1Behavioral at 0.80-0.90 confidence
- Added `"data staging"` to President's Law kill list

### Architecture: User-Session Monitors Moved to Agent
Monitors that require user-session context have been moved from the SYSTEM service to the Agent process:

**Moved to Agent:**
- `ClipboardMonitor` — clipboard ownership is per-session
- `ScreenCaptureMonitor` — window visibility/foreground detection requires user desktop
- `WebcamMicMonitor` — camera/mic DLL scanning in user processes
- `AudioHijackMonitor` — audio routing detection
- `MicSessionMonitor` — WASAPI session enumeration is per-user-session

**Agent now has its own detection pipeline:**
- `AgentDetectionPipeline` — reads DetectionEngine channel, routes to response engine
- `AgentResponseEngine` — lightweight response engine with President's Law kill authority
- `AgentEventLogger` — writes to shared `events.jsonl`

### Fix: MemoryBehaviorAnalyzer virtual memory explosion
- Added user-mode address space cap (`0x7FFFFFFEFFFF`) to the `VirtualQueryEx` scan loop
- Fixes the 2.3 TB virtual memory allocation on SentinelService

### Infrastructure
- All version references bumped to 2.4.0.
- President's Law fragment list extended with `"data staging"`.

---

## 2.3.0 — Mic Session Injection Detection (May 2026)

### New: MicSessionMonitor
Detects unauthorized processes holding active audio sessions on microphone capture endpoints — the attack vector where an attacker injects a DLL (or runs a hidden tool) that feeds fake audio directly into the mic capture buffer without any command-line flags or virtual cable software.

**How it works:**
- Enumerates active WASAPI audio sessions on all capture (microphone) devices via COM: `IMMDeviceEnumerator` → `IMMDevice::Activate(IAudioSessionManager2)` → `IAudioSessionEnumerator` → `IAudioSessionControl2::GetProcessId`
- For each PID holding a mic session, checks:
  - Is it allowlisted? (conferencing, browsers, recording apps, system audio)
  - Does it own a visible window? (user is aware of it)
  - Is it the foreground app?
- Flags background processes with no visible window that hold mic sessions
- Tracks session participants over time — a NEW participant appearing on a previously-stable mic endpoint gets higher confidence (0.85)
- Confirmation threshold: must persist across 2 scan cycles (avoids transient opens)

**What it catches:**
- DLL injection into any process that then opens a mic session to feed audio
- Standalone hidden tools writing to mic capture buffer
- Virtual audio driver abuse from background processes
- Any unauthorized process with an active mic session

**President's Law:** Added `"audio injection"` to the kill list — this rule can trigger a kill at ≥85% confidence.

### Infrastructure
- All version references bumped to 2.3.0.
- President's Law fragment list extended with `"audio injection"`.

---

## 2.2.0 — Pre-Kill Validation Gate (May 2026)

### New: Pre-Kill Validation Gate in AdvancedResponseEngine
Before executing a President's Law kill, the response engine now performs a final sanity check to verify the target process is not a user-interactive application whose normal behavior mimics threat patterns.

**Validation checks:**
- **Visible window ownership**: Enumerates all top-level windows (via `EnumWindows`) to determine if the process has a visible, non-trivial window. Real spyware hides — it does not render UI the user interacts with.
- **Foreground status**: Checks if the process owns the current foreground window. Malware does not operate as the active foreground application.
- **Process age**: Verifies the process has been running stably for 5+ minutes. Implants beacon immediately; a long-running interactive app is not a covert threat.

**Decision logic**: Kill is downgraded to log-only ONLY when the process is both user-interactive (visible window OR foreground) AND long-running (5+ min). This combination is incompatible with covert malware. A hidden process running for hours still gets killed. A visible process that just spawned still gets killed.

**No allowlists**: This fix does not whitelist any paths, publishers, or process names. It validates behavioral properties inherently incompatible with being a hidden threat.

### Fix: ScreenCaptureMonitor visible-window detection
- `Process.MainWindowHandle` is unreliable for games and multi-window applications (returns `IntPtr.Zero` for fullscreen exclusive, borderless fullscreen, and engines with separate render windows).
- Added `ProcessOwnsVisibleWindow()`: enumerates all top-level windows via `EnumWindows` and checks if any visible, non-tool window ≥224×224px belongs to the process.
- Added `IsProcessForegroundFullscreen()`: checks if the process owns the foreground window and that window covers the entire monitor.
- These checks run before classifying a process as "background" — prevents games from triggering the "Background Process with Capture DLLs" rule.

### Bug fixed
- Star Trek Online (GameClient.exe) killed mid-gameplay: game's normal behavior (DXGI rendering + 5s server keepalive + dbghelp for crash reporting + MainWindowHandle not recognized) triggered composite "Screen Exfiltration: Capture + Network" at 93% confidence.

### Infrastructure
- All version references bumped to 2.2.0.

---

## 2.1.0 — Community Threat Intelligence Reporting (May 2026)

### New: ThreatIntelReporter
After a confirmed kill (President's Law, confidence ≥ 0.85), Sentinel now reports attacker infrastructure to community threat intelligence platforms, exposing their network to authorities and the security community.

**Reporting targets:**
- **AbuseIPDB**: Reports C2 IP addresses with attack category (Hacking, Exploited Host, etc.) and evidence summary. ISPs and hosting providers receive automated abuse notifications.
- **URLhaus (abuse.ch)**: Reports C2 URLs/IP:port combinations. Added to community blocklists used by firewalls, DNS filters, and EDRs worldwide.
- **MalwareBazaar (abuse.ch)**: Logs malicious file hashes with tags for community signature generation.

**Safety guarantees:**
- All reporting is opt-in (`ThreatReporting.Enabled=true` in appsettings.json)
- Only reports CONFIRMED threats (post-kill, confidence ≥ 0.85)
- Never reports private/internal IPs (RFC1918, link-local, loopback)
- Never uploads file contents — only hashes and metadata
- Rate-limited: max 10 reports per hour
- Deduplication: same IP/hash never reported twice
- Reports queued and sent asynchronously (never blocks kill response)

**Configuration:**
```json
{
  "ThreatReporting": {
    "Enabled": true,
    "AbuseIpDbApiKey": "your-free-api-key",
    "UrlhausAuthToken": "your-free-token",
    "ReportToMalwareBazaar": true,
    "ReportToUrlhaus": true
  }
}
```

**Integration point:** Wired into `AdvancedResponseEngine` — called automatically after every successful chain trace kill. Extracts C2 address, port, and file hash from detection metadata.

### Infrastructure
- All version references bumped to 2.1.0.
- DI registration: ThreatReportingConfig (singleton), ThreatIntelReporter (singleton + hosted service).
- AdvancedResponseEngine constructor extended with ThreatIntelReporter parameter.
- MITRE D3FEND coverage: D3-TIRA (Threat Intelligence Reporting).

---

## 1.9.0 / 2.0.0 — DLL Analysis & Active Response + Hardened & Portable (May 2026)

### New: DllUnloadEngine (Active DLL Response)
Active response capability that forcefully unloads malicious/suspicious DLLs from running processes using CreateRemoteThread + FreeLibrary. Ported from Antivirus.ps1's `Invoke-ElfDLLUnloader` and `Invoke-UnsignedDLLRemover`.

**Safety constraints:**
- Rate-limited: max 10 unloads per minute
- Never touches system-critical processes (lsass, csrss, smss, services, etc.)
- Never unloads system DLLs (ntdll, kernel32, kernelbase, etc.)
- Never targets Sentinel's own processes
- All unloads logged with full forensic context

### New: UacBypassSurfaceMonitor
Proactive scanning for DLL hijacking vectors that could be exploited for privilege escalation via UAC bypass. Scan interval: 15 minutes.

**Detection vectors:**
- **COM AutoElevation**: Scans HKLM\SOFTWARE\Classes\CLSID for COM objects with Elevation\Enabled=1 whose InprocServer32/LocalServer32 targets are writable or missing.
- **Manifest AutoElevate**: Scans System32/SysWOW64 for binaries with `<autoElevate>true</autoElevate>` manifest.
- **Copy-Drop Vulnerability**: Checks autoElevate binaries for missing SetDllDirectory/SetDefaultDllDirectories hardening (vulnerable to copy-to-temp sideload).
- **PATH Directory DLLs**: Detects recently-created DLLs in user-writable PATH directories.

### New: DllEntropyAnalyzer
Shannon entropy analysis for detecting packed, encrypted, or obfuscated DLLs. Ported from Antivirus.ps1's `Measure-FileEntropy` + `Invoke-FileEntropyDetection`.

**Capabilities:**
- Shannon entropy calculation (8KB sample, threshold: 7.2 normal, 7.6 critical)
- Random hex-named DLL detection (`^[a-f0-9]{8,}\.dll$`)
- Scans high-risk directories (AppData, Temp, Downloads) every 3 minutes
- Scans loaded modules in running processes every 5 minutes
- IoC hash matching for detected high-entropy files

### New: DllLoadFailureMonitor
Monitors Windows Event Log for DLL load failures that indicate hijacking attempts. Ported from Antivirus.ps1's Event Log monitoring.

**Monitored events:**
- System Event ID 7 (Service Control Manager DLL load failures)
- Application SideBySide errors (manifest/activation context failures)
- Polls every 30 seconds

### New: BrowserDllMonitor (ELF Catcher)
Browser-specific DLL injection detection with active unload response. Ported from Antivirus.ps1's `Invoke-ElfCatcher` and `Test-SuspiciousDLL`.

**Browser-specific heuristics:**
- Known ELF/malware DLL name patterns (*_elf.dll, *_hook.dll, *_inject.dll, etc.)
- .winmd files outside Windows directory (WinRT abuse)
- Random hex-named DLLs in browser processes
- DLLs from TEMP loaded into browsers (excluding browser cache)
- DLLs in browser profile folders with non-browser names
- Unsigned DLLs in browser processes (outside system paths)
- Active unload via DllUnloadEngine for confirmed ELF-pattern DLLs

**Monitored browsers:** Chrome, Edge, Firefox, Brave, Opera, Vivaldi, Waterfox, Palemoon, Chromium, Arc. Scan interval: 45 seconds.

### New: DiskWideDllScanner
Disk-wide scanning for unsigned/suspicious DLLs across all drives. Ported from Antivirus.ps1's `Invoke-UnsignedDLLRemover`.

**Scanning strategy:**
- High-risk paths (AppData, Temp, Downloads, Desktop, ProgramData): every 5 minutes
- Drive roots (fixed, removable, network — depth 2): every 15 minutes
- Max 500 files per scan cycle
- Results cached by SHA-256 hash

**Analysis pipeline:**
- Signature validation (Authenticode)
- IoC hash matching (local IoCScanner)
- External hash reputation (HashReputationService: Cymru, MalwareBazaar, CIRCL)
- Entropy analysis (via DllEntropyAnalyzer)
- Hex-name pattern detection
- Active unload via DllUnloadEngine on IoC match

### Enhanced: HashReputationService Integration
The existing HashReputationService (Cymru, MalwareBazaar, CIRCL APIs) now feeds the DiskWideDllScanner for live threat intelligence enrichment of disk-scanned DLLs. Previously only triggered on process-start events.

### Infrastructure
- All version references bumped to 2.0.0 (Core, Service, Agent, installer, build script).
- DI registration: DllUnloadEngine (singleton), 5 new hosted services.
- architecture-council.md updated with v2.0.0 component roster.
- MITRE ATT&CK coverage: T1548.002, T1574, T1574.001, T1055, T1027, T1027.002, T1185, T1036, T1539.

### Hardened & Portable (v2.0.0 — Barebone Windows Compatibility)

**Problem:** Sentinel crashed or spammed errors on minimal Windows installations (Server Core, IoT Enterprise, stripped/debloated builds) where certain APIs or services are unavailable.

**Fixes:**
- **UserSessionLauncher**: `WTSGetActiveConsoleSessionId` P/Invoke moved from `wtsapi32.dll` to `kernel32.dll` (correct location). Added startup probe — if the API throws `EntryPointNotFoundException` or `DllNotFoundException`, the launcher exits gracefully instead of crash-looping every 30 seconds.
- **ToastNotificationService**: Changed from `ToastImageAndText04` (requires image asset) to `ToastText04` (text-only). Added bounds checking on `XmlNodeList` access — no more `ArgumentOutOfRangeException`. All toast failures downgraded from `LogError` to `LogDebug` (non-critical).
- **LsassDumpCanaryMonitor**: Expanded allowlist with 30+ legitimate dbghelp.dll users: all Chromium browsers, Electron apps (Kiro, VS Code, Cursor, Discord, Slack, Teams), Steam, Google crash handlers, JetBrains IDEs, svchost.exe (WER). Eliminates false positive composites.
- **DllLoadFailureMonitor**: Catches `EventLogNotFoundException` when System/Application logs are inaccessible (Server Core without Event Log service).
- **UacBypassSurfaceMonitor**: Registry scanning wrapped in try-catch per key — missing hives don't crash the scan.
- **ProcessHardening**: `SetProcessMitigationPolicy` failures logged at Debug level (expected on older Windows builds that don't support CIG/ImageLoad policies).
- **EtwProcessMonitor/EtwThreatIntelMonitor**: Already had WMI fallback — no changes needed, but documented as a design pattern for barebone compatibility.

---

## 1.8.0 — Data Exfiltration Prevention (May 2026)

### New: DataExfiltrationMonitor
Correlation-based DLP that stops data theft without false positives. Every detection requires 2+ independent signals correlating on the same process within 120 seconds — single signals are ALWAYS Tier2 (log only).

**Monitoring layers:**
- **Outbound connection tracking**: Detects non-allowlisted processes maintaining sustained (60s+) connections to external IPs. Tier2 signal — feeds correlation engine.
- **Sensitive directory monitoring**: Watches SSH keys, cloud credentials, browser password databases, Windows credential stores, crypto wallets. Tier2 signal on access.
- **Removable media monitoring**: Watches all USB/removable drives for file activity. Disk image access (.iso, .vhd, .img) gets higher confidence. Tier2 signal.

**Why zero false positives:**
- Chrome visiting mega.nz → No alert (browser allowlisted in DNS check)
- Git reading ~/.ssh/id_rsa → No alert (git in credential allowlist)
- Unknown process resolves pastebin.com → Tier2 log only (no kill)
- Unknown process resolves pastebin.com AND has outbound connection → **KILL + deception**

### Enhanced: DnsQueryMonitor (Exfil Domain Detection)
Added detection of 40+ known exfiltration service domains: file-sharing (Mega, transfer.sh, gofile.io), paste services (pastebin, paste.ee), messaging APIs (Telegram bot API, Discord webhooks), tunneling services (ngrok, Cloudflare tunnels). Non-browser processes resolving these emit Tier2 signals that feed the correlation engine.

### New Composite Correlation Rules (4 new, total: 34)
- **Data Exfiltration: Upload Service + Network [COMPOSITE]** (0.96): Exfil DNS resolution + outbound connection on same PID = confirmed upload in progress.
- **Data Exfiltration: Credential Theft + Network [COMPOSITE]** (0.95): Sensitive file access + outbound connection = infostealer exfiltrating credentials.
- **Data Exfiltration: USB Media + Network Upload [COMPOSITE]** (0.96): Removable media read + outbound connection = USB-to-network data theft.
- **Data Exfiltration: Staging + Upload Service [COMPOSITE]** (0.94): Exfil DNS + sensitive/removable file access = pre-exfil staging (kill before upload starts).

### President's Law Kill List Additions
- `"data exfiltration"` — all exfil composite rules
- `"exfiltration: upload service + network"` — DNS + network composite
- `"exfiltration: credential theft + network"` — cred access + network composite
- `"exfiltration: usb media + network"` — USB + network composite
- `"exfiltration: staging + upload service"` — pre-staging composite

### Allowlist Architecture
Three separate allowlists prevent false positives on legitimate software:
- **CredentialAccessAllowlist**: Processes that legitimately read SSH keys, cloud creds (git, ssh, kubectl, password managers, IDEs)
- **NetworkAllowlist**: Processes that legitimately make sustained outbound connections (browsers, cloud sync, dev tools, games)
- **RemovableMediaAllowlist**: Processes that legitimately read from USB (explorer, file managers, backup tools)

### Infrastructure
- All version references bumped to 1.8.0.
- DI registration: `DataExfiltrationMonitor` as hosted service.
- MITRE ATT&CK coverage: T1041, T1052, T1552, T1567.

---

## 1.7.0 — Aggressive Deception Engine (May 2026)

### New: Deception Engine (Pre-Kill Attacker Punishment)
When a President's Law kill is authorized, the new `DeceptionEngine` executes attacker-hostile tactics BEFORE process termination. Every kill now costs the attacker time, pollutes their data, and potentially exposes their infrastructure.

**Philosophy:** Don't just stop the attacker — make them pay. All tactics operate on our own system against a confirmed intruder. Legally defensive (same principle as dye packs in bank robbery).

### Deception Tactics

**Memory Flooding** — Injects up to 256MB of random garbage into the target process's address space via `VirtualAllocEx` + `WriteProcessMemory`. If the attacker has memory dump capabilities or C2 crash-reporting, their data is now gigabytes of noise. Random data (not zeros) ensures it doesn't compress well.

**Implant Destabilizer (DLL Stomping)** — Overwrites the `.text` section of non-system modules with INT3 (0xCC) breakpoint instructions. If the implant has persistence and restarts after kill, it immediately crashes on first instruction fetch — extremely hard to debug remotely. Also corrupts thread stacks (garbage injection into stack regions so C2 crash-reporting sends corrupted telemetry to the operator). Creates 60+ decoy named objects (fake debugger/EDR/C2 mutex names) to pollute handle table forensics.

**Beacon Flooder** — When C2 address and port are identified, sends 50+ fake beacon check-ins mimicking known C2 framework protocols (Cobalt Strike HTTP beacons, Sliver mTLS sessions, generic HTTP C2). Additionally sends 20+ protocol confusion payloads — malformed HTTP with integer overflows in Content-Length, null bytes in headers, impossible chunked encoding, and oversized URIs designed to trigger parsing bugs and crash the C2 team server. The operator's console fills with ghost sessions they must manually triage.

**Clipboard Poisoner** — When clipboard theft is detected, replaces clipboard contents with convincing-looking but fake/trackable data: fake AWS keys, SSH private keys, cryptocurrency addresses, GitHub tokens, Slack tokens, database connection strings. Attacker's stolen clipboard is now useless AND trackable (canary tokens alert when used).

**File Trap Deployer** — Deploys filesystem-based traps in common exfil-target directories:
- **Sparse file bombs**: Files that report as 500GB via metadata but consume 0 bytes on disk. Automated exfil tools try to read 500GB of zeros, saturating C2 bandwidth for hours.
- **Symlink loops**: Deeply nested directories (50 levels) with symlinks back to root. Recursive file collection tools infinite-loop and crash.
- **Polyglot files**: PDF/XLSX/DOCX with valid headers but malformed internals — canary JavaScript callbacks in PDFs, XML entity expansion bombs (billion laughs) in XLSX, XXE payloads in DOCX. Crashes automated parsers (pdftotext, PyPDF2, openpyxl) and phones home when opened.
- **Corrupted archives**: tar.gz, gz, and 7z files with valid magic bytes/headers that pass initial "is this a real archive?" checks but corrupt during extraction. Attacker wastes hours trying to recover "stolen" data.
- **File locking**: Exclusively locks files the attacker is trying to read, forcing retry loops.

**Environment Poisoner** — Corrupts registry settings that C2 frameworks depend on:
- WinINet proxy → 127.0.0.1:1 (HTTP C2 reconnection fails)
- WinHTTP connection settings → corrupted blob (WinHTTP channels fail)
- TLS settings → SSL2-only (encrypted C2 handshake fails)
- Persistence Run keys → replaced with harmless `cmd /c exit`

**Honeypot Weaponizer** — Deploys weaponized fake files that actively harm the attacker when used:
- Fake SSH keys + config pointing to honeypot servers (captures attacker sessions)
- Fake AWS/Azure credentials (triggers CloudTrail alerts, exposes attacker IP)
- Fake `.env.production` with database URLs, Stripe keys, JWT secrets
- Fake browser password export CSV on Desktop (high-value infostealer target)
- Zip bombs disguised as `financial_records_2024.zip` (crashes extraction tools)
- Fake VPN configs routing through logging proxy
- Fake crypto wallet seed phrases (attacker wastes time on empty wallets)

**Network Honeypot Deployer (Nuclear Option)** — Automatically spins up fake lateral movement targets on the local machine the moment a kill is confirmed:
- **Fake SMB shares** (3 listeners): Respond to SMB2 negotiation, log attacker's share enumeration attempts
- **Fake RDP endpoints** (2 listeners): Accept RDP negotiation, log credential attempts
- **Fake HTTP admin panels** (3 listeners): Serve convincing login pages for "VMware vCenter", "Exchange Admin Center", "Domain Controller Management" — log submitted credentials
- **Fake SSH servers** (2 listeners): Send OpenSSH banner, log client key exchange and auth attempts
- All listeners auto-terminate after 30 minutes. Attacker wastes time exploring fake infrastructure while the real system is already clean.

### Safety Guarantees
- **2-second time budget**: All deception must complete within 2 seconds. Kill always proceeds on timeout.
- **Non-fatal failures**: Deception failure never prevents the kill from executing.
- **Self-protection**: Never targets own PID or system-critical processes (PID ≤ 4).
- **Full logging**: Every tactic execution is logged before and after for forensic review.
- **No network attacks on private IPs**: Beacon flooding only targets public C2 addresses.

### Architecture
```
DetectionEngine → AdvancedResponseEngine
                       ↓
                  DeceptionEngine.ExecutePreKillDeceptionAsync()
                       ↓ (2s max)
                  ChainTracer.TraceAndEliminateAsync()
                       ↓
                  Kill → Quarantine → Persistence Removal → IP Block
```

### New Files
- `Deception/IDeceptionEngine.cs` — Interface
- `Deception/IDeceptionTactic.cs` — Tactic interface
- `Deception/DeceptionModels.cs` — Context, result, and category models
- `Deception/DeceptionEngine.cs` — Orchestrator (tactic selection + time budget)
- `Deception/MemoryFloodingTactic.cs` — Memory pollution via VirtualAllocEx
- `Deception/ImplantDestabilizer.cs` — DLL stomping + stack corruption + handle pollution
- `Deception/BeaconFlooder.cs` — C2 server flooding + protocol confusion
- `Deception/ClipboardPoisonTactic.cs` — Clipboard replacement with fakes
- `Deception/FileTrapTactic.cs` — Sparse bombs + symlink loops + polyglot files + corrupted archives + file locking
- `Deception/EnvironmentPoisoner.cs` — Registry/proxy/TLS corruption
- `Deception/HoneypotWeaponizer.cs` — Weaponized fake credential deployment
- `Deception/NetworkHoneypotDeployer.cs` — Fake SMB/RDP/HTTP/SSH lateral movement traps

### Infrastructure
- All version references bumped to 1.7.0 (Core, Service, Agent, Installer).
- `AdvancedResponseEngine` now accepts `IDeceptionEngine` dependency.
- DI container registers all 7 tactics + engine.
- MITRE ATT&CK coverage: T1565 (Data Manipulation), T1036 (Masquerading — decoy objects).

---

## 1.6.0 — Webcam/Mic Exfiltration Guard (May 2026)

### New: Webcam & Microphone Monitor
Detects unauthorized background access to camera and microphone devices — catches spyware, RATs, and stalkerware secretly recording the user:

- **Background Camera/Mic Capture Detection** (Tier2, 0.70–0.82): Flags processes loading camera/microphone capture DLLs (Media Foundation, DirectShow, WASAPI) with no visible window. Requires confirmation across 2+ scan cycles to avoid transient false positives during app startup.
- **Strong Camera Indicators**: Processes loading camera-specific DLLs (`mfsensorgroup.dll`, `frameserver.dll`, `avicap32.dll`, `qcap.dll`, `ksproxy.ax`) get higher confidence — these are only loaded for actual camera access, not general media playback.

**How it avoids false positives on legitimate use:**
- Comprehensive allowlist: Teams, Zoom, Discord, Slack, OBS, Chrome, Firefox, Edge, Brave, Opera, Vivaldi, Windows Camera, Steam, and 40+ other legitimate apps
- Browsers are fully allowlisted — users on Google Meet, streaming sites, or any web-based video call are never interrupted
- Only background processes (no visible window) trigger detection — if the user can see the app, it's allowed
- Standalone detection is Tier2 (log only) — only composites with network activity authorize kills
- Confirmation threshold prevents alerts from transient DLL loads during app startup

### New Composite Correlation Rules (2 new, total: 30)
- **Camera/Mic Exfiltration: Capture + Network [COMPOSITE]** (0.94): Background webcam/mic access + outbound network activity = spyware streaming to C2. This is the kill trigger — standalone camera access is log-only, but camera + network = exfiltration.
- **Total AV Surveillance: Camera + Screen Capture [COMPOSITE]** (0.95): Webcam/mic capture + screen capture from background = total audio-visual surveillance (FinFisher, Pegasus-like, DarkComet pattern).

### Updated: Full Surveillance Suite Composite
- Now includes webcam/mic as a 4th surveillance vector (was 3: screen + clipboard + audio-to-mic)
- 4/4 vectors active → confidence 0.99 (was max 0.98 with 3/3)
- 3/4 vectors → 0.98, 2/4 vectors → 0.94

### President's Law Kill List Additions
- `"camera/mic exfiltration"` — webcam/mic + network composite
- `"total av surveillance"` — camera + screen capture composite

### Infrastructure
- All version references bumped to 1.6.0 (Core, Service, Agent, Installer).
- MITRE ATT&CK coverage added: T1125 (Video Capture), T1123 (Audio Capture) for webcam/mic detection.

---

## 1.5.0 — Anti-Spyware Suite (May 2026)

### New: Screen Capture & Overlay Monitor
Detects unauthorized screen capture and credential phishing overlays:

- **Background Screen Capture Detection** (Tier2, 0.75): Flags processes loading DXGI/D3D11 + image encoding DLLs with no visible window — catches silent screenshot malware invisible to the user.
- **Transparent Overlay Phishing Detection** (Tier1, 0.70–0.88): Enumerates all top-level windows for the `WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST` combination from non-allowlisted processes. Requires persistence across 3 scan cycles (45s) to avoid tooltip false positives. Catches banking trojan overlays and credential phishing attacks that can also cause screen glitches.

Comprehensive allowlists for browsers, games, GPU tools, IDEs, streaming software, and system UI prevent false positives.

### New: Local Server Monitor
Detects suspicious processes listening on localhost — closes the gap where attackers serve exploits via local web servers invisible to outbound network monitoring:

- **Mounted ISO/VHD Origin Detection** (Tier1, 0.85): Processes running from mounted ISO, VHD, CD-ROM, or removable media that bind listening sockets are flagged with high confidence.
- **Staging Path Listeners** (Tier1, 0.78): Processes from Temp/AppData/Downloads binding ports.
- **Unknown Path Listeners** (Tier2, 0.75): Processes whose path cannot be determined (possible WPD or hidden volume origin).
- **Unknown Listeners on Non-Dev Ports** (Tier2, 0.60): Catch-all for unrecognized processes on non-standard ports.

Developer-friendly: node, python, dotnet, java, IDEs, Docker, and common dev ports (3000, 5173, 8080, etc.) are all allowlisted.

### New: Volume Dismount on Read-Only Media
The `ChainTracer` response engine now handles read-only media (mounted ISO, CD-ROM, write-protected VHD):

- When `File.Delete` fails due to read-only filesystem, Sentinel attempts to **dismount the volume** using `FSCTL_DISMOUNT_VOLUME` + `IOCTL_STORAGE_EJECT_MEDIA`.
- For VHDs, attempts WMI `Dismount` method first, then falls back to FSCTL.
- Safety: never dismounts C: or fixed system drives.
- Effect: process is killed AND the volume is ejected, preventing re-execution from read-only media.

### Updated: AudioHijackMonitor
- Now feeds into `TelemetryFusionEngine` for composite correlation with screen capture and clipboard signals.
- Audio-to-mic routing remains a standalone Tier1 kill (no network correlation required) — the attack is local by nature.

### New Composite Correlation Rules (5 new, total: 28)
- **Screen Exfiltration: Capture + Network [COMPOSITE]** (0.93): Screen capture + outbound network = spyware streaming screenshots to C2.
- **Data Harvesting: Screen + Clipboard [COMPOSITE]** (0.92): Screen capture + clipboard access = comprehensive infostealer (RedLine, Raccoon, Vidar pattern).
- **Credential Phishing: Overlay + Injection [COMPOSITE]** (0.96): Transparent overlay + DLL injection = banking trojan drawing fake login UI (Zeus, TrickBot, Dridex).
- **Full Surveillance Suite [COMPOSITE]** (0.94–0.98): 2+ of (screen capture, clipboard/keylogger, audio-to-mic hijack) = comprehensive surveillance implant.

### President's Law Kill List Additions
- `"overlay attack"` — transparent overlay phishing windows
- `"screen exfiltration"` — screen capture + network composite
- `"surveillance suite"` — multi-vector surveillance composite
- `"credential phishing: overlay"` — overlay + injection composite

### Infrastructure
- All version references bumped to 1.5.0 (Core, Service, Agent, Installer).
- MITRE ATT&CK coverage: T1113 (Screen Capture), T1056.004 (Credential API Hooking), T1571 (Non-Standard Port), T1090 (Proxy).

---

## 1.4.0 — Clipboard Guardian (May 2026)

### New: Clipboard Security Monitor
Detects unauthorized clipboard access, hijacking, and exfiltration via Win32 API polling:

- **Clipboard Scraping Detection**: Alerts when a process causes 5+ clipboard changes within 10 seconds — catches crypto address swappers and automated clipboard stealers.
- **Background Clipboard Hijack**: Detects background processes (no visible window) repeatedly taking clipboard ownership without user interaction — the signature pattern of clipboard-stealing malware.
- **Extended Clipboard Lock**: Identifies processes holding the clipboard locked for extended periods, blocking copy/paste for all other applications.
- **Trusted Process Hijack Detection**: Even allowlisted processes (browsers, explorer) are flagged if they exhibit abnormal clipboard rates from the background — catches DLL injection using trusted processes as proxies.

Comprehensive allowlists for browsers, editors, IDEs, password managers, and legitimate clipboard tools prevent false positives.

### New: Runtime Module Integrity Monitor (System-Wide)
Validates ALL loaded modules across ALL running processes. Maintains per-process module baselines and detects deviations at runtime:

- **Runtime DLL Injection**: Detects new unsigned/suspicious modules appearing in any process after baseline — catches CreateRemoteThread, manual mapping, reflective loading, APC injection.
- **Phantom Module Detection**: Flags modules whose backing file has been deleted from disk (classic dropper pattern: load → delete → execute in memory).
- **Tiered Scanning**: System-critical processes (lsass, svchost, etc.) scanned every 30s; browsers/office every 60s; all other processes in rotating batches every 2 min.
- **Smart Filtering**: Trusted publishers (Microsoft, Google, NVIDIA, etc.), known late-load system DLLs, and Program Files paths are auto-allowed to minimize noise.

MITRE ATT&CK: T1055 (Process Injection), T1574 (Hijack Execution Flow), T1129 (Shared Modules).

### New: Clipboard Exfiltration Composite Rule
- **Clipboard Access + Network [COMPOSITE]** (0.93): Clipboard scraping/hijacking signal + ANY outbound network activity on the same PID within 120s = kill-authorized composite.

### New: Module Injection Composite Rules
- **Injected Implant + Network C2 [COMPOSITE]** (0.95): DLL injection signal + network activity = injected C2 beacon (Cobalt Strike, Sliver, etc.).
- **Clipboard Theft via Injected Module [COMPOSITE]** (0.94): DLL injection + clipboard access = clipboard exfiltration through injected DLL in trusted process.

Total composites: 23 (20 from v1.3.0 + 3 new).

MITRE ATT&CK: T1115 — Clipboard Data.

### Fixed: Event Viewer Flooding
- EventLog provider now filtered to `Warning` level and above only.
- Information-level telemetry (Tier2 detections, monitor status, etc.) still logged to the JSONL event file but no longer floods Windows Event Viewer with hundreds of entries per minute.
- Dramatically reduces Event Viewer noise while preserving full forensic detail in the JSONL log.

### Infrastructure
- All version references bumped to 1.4.0 (Core, Service, Agent, Installer).

---

## 1.3.0 — Aggressive Correlation (May 2026)

### New Anchor-Based Composite Rules
8 new composites that use a "suspicion anchor + second signal = kill" philosophy. If a process is ALREADY suspicious, then ANY additional activity becomes the kill trigger:

- **Spoofed Process Phoning Home** (0.95): PPID spoof + ANY network activity. Legitimate processes never spoof parents.
- **Dump Tool + Network Exfil** (0.94): dbghelp.dll loaded + ANY outbound connection. If you loaded the dump library and you're talking to the network, you're exfiltrating.
- **Staged Payload + Non-Standard Port** (0.92): Unsigned binary from Temp/AppData + connection to non-80/443 port. Classic dropper→beacon.
- **Mass File Operation + DNS** (0.93): 50+ file writes/renames + DNS resolution. Ransomware completion or infostealer exfil pattern.
- **Privilege Escalation + Network** (0.94): Token escalation + ANY network. Attacker establishing privileged reverse shell.
- **Injection Tool + File Staging** (0.91): Injection API in cmdline + file writes. Loader/dropper staging payloads.
- **DGA + File Operations** (0.94): DGA DNS + ANY file access. Malware doing C2 while collecting/encrypting data.
- **In-Memory Implant + Network** (0.96): Memory anomaly (RWX/shellcode/unbacked) + ANY network. Definitive in-memory beacon pattern.

Total composite rules: 20 (6 original + 6 v1.2.0 + 8 v1.3.0).

### Philosophy
The anchor-based approach means: a single suspicious signal alone doesn't kill (it's Tier2). But once a process has an anchor signal establishing it as suspicious, the bar for the second signal drops dramatically — ANY network activity, ANY file access, ANY DNS resolution becomes sufficient for a composite kill. This catches sophisticated attackers who avoid known-bad ports/domains but can't avoid making network connections entirely.

---

## 1.2.0 — Correlated Kill (May 2026)

### New Composite Correlation Rules
6 new composites wiring the anti-APT monitors into kill-authorized detections via the BehavioralCorrelationEngine. No single monitor kills alone — all require multiple independent signals correlating on the same PID within 120 seconds:

- **PPID Spoof + C2 Channel** (0.96): Parent PID spoofing + C2 network connection. Catches Cobalt Strike, Sliver, Brute Ratel default spawn behavior.
- **Confirmed LSASS Dump** (0.97): dbghelp.dll loaded in non-debugger + LSASS-targeting cmdline pattern. Catches custom dumpers regardless of tool name.
- **Privilege Escalation + Persistence** (0.94): Token integrity escalation + persistence mechanism installation. Catches post-exploitation foothold securing.
- **DGA + C2 Beaconing** (0.95): High-entropy DNS resolution + statistical beacon pattern. Catches DGA-based malware (Emotet, TrickBot, Conficker).
- **Credential Theft + Exfiltration** (0.97): Credential canary tripped + outbound network activity. Catches active credential harvesting + exfil.
- **Advanced Attack Chain** (0.98): 2 of 3: PPID spoof + token escalation + injection. Catches full implant lifecycle (Cobalt Strike, APT tooling).

Total composite rules: 12 (6 original + 6 new).

### Architecture Note
All new anti-APT monitors (DNS, PPID spoof, token integrity, credential canary, dbghelp) emit **Tier2 corroborating signals**. They never kill independently. The correlation engine combines them with other signals to produce high-confidence composite kills. This preserves the "kill only on advanced corroboration" philosophy.

---

## 1.1.0 — Hardened Foundations (May 2026)

### Anti-APT Monitors (NEW)
- **DnsQueryMonitor**: ETW DNS-Client provider. Detects DGA domains (Shannon entropy > 3.8, 3+ hits), DNS tunneling (>30 queries/min sustained). Catches iodine, dnscat2, dns2tcp, DGA-based C2. **Tier2 — corroborating signal, feeds correlation engine.**
- **ParentPidSpoofDetector**: Compares ETW-reported parent PID (kernel truth) against CreateToolhelp32Snapshot (declared parent). Detects Cobalt Strike PPID spoofing, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS abuse. Near-zero false positives. **Tier2 — corroborating signal, feeds correlation engine.**
- **SyscallStubMonitor**: Baselines first 16 bytes of critical ntdll/amsi exports at startup, checks every 10s. Detects ntdll unhooking (fresh ntdll remapping), ETW blinding, AMSI patching in Sentinel's own process. **Tier1 — self-protection (President's Law: "self-protection:" fragment match).**
- **CredentialCanaryMonitor**: Plants a honeypot credential in Windows Credential Manager. If accessed, modified, or deleted — zero-FP indicator of credential harvesting (Mimikatz vault, LaZagne, infostealers). **Tier2 — no PID to kill, feeds correlation engine.**
- **TokenIntegrityMonitor**: Scans process tokens every 20s. Detects medium→high integrity transitions that bypass UAC consent. Catches UAC bypass exploits, token manipulation, named pipe impersonation. **Tier2 — corroborating signal, feeds correlation engine.**
- **LsassDumpCanaryMonitor**: Scans for dbghelp.dll loaded in non-debugger processes every 15s. This DLL is a prerequisite for MiniDumpWriteDump — catches custom LSASS dumpers regardless of tool name. **Tier2 — dbghelp alone doesn't prove malice, feeds correlation engine.**

### Security Hardening
- **SecureCacheStore v2**: HMAC key now incorporates system boot-time nonce. Caches from previous boot sessions are automatically rejected. Narrows the window for SYSTEM-context replay attacks.
- **Removed placeholder hashes** from LsassAccessRule. The `KnownDumperHashes` set contained fake SHA256 values that gave false confidence. Hash-based detection is now exclusively handled by `HashReputationService` (live 3-API lookup).
- **ProcessInjectionRule tightened**: Tool-name matching (`KnownInjectionTools`) no longer triggers detection — trivially bypassed by renaming. Retained as metadata enrichment only. Detection fires on injection API patterns in command line + suspicious parent-child context.

### Documentation
- Added `THREAT_MODEL.md` — 8 specific bypass scenarios with honest residual risk ratings, detection confidence table, and "what Sentinel cannot protect against" section.
- Updated all documentation to reflect behavioral-only detection philosophy.
- Added Detection Integrity Constraints to `constraints.md`.

### Philosophy
- "Fewer rock-solid detections > many fragile ones"
- "Assume the attacker reads the code"
- "No security theater"

---

## 1.0.0 — Telemetry Fusion (May 2026)

### New Features
- **TelemetryFusionEngine**: Unified event chain store correlating raw telemetry across all sources (ETW process, file I/O, network, ThreatIntel injection, memory behavior) into per-process event chains.
- **EventGraph**: In-memory graph maintaining temporal and causal relationships between processes, files, and network endpoints. Supports incident timeline queries, process tree traversal, file accessor lookup.
- **MemoryBehaviorAnalyzer**: Active memory scanning every 45s. Detects RWX regions, unbacked executables, shellcode prologues (Metasploit/Cobalt Strike patterns), NOP sleds.
- All monitors wired to feed TelemetryFusionEngine before DetectionEngine.

### Removed
- **Key Scrambler** (agent + service): Fake keystroke injection was security theater. Replaced with keylogger hook detection (service-only, detection-only).
- **LearningModeService**: Dead code — protection is active by default.
- **Password Rotator**: Disabled stub that did nothing.
- **Old ResponseEngine**: Superseded by AdvancedResponseEngine since 0.7.0.

### Agent
- Simplified to watchdog-only (service heartbeat monitor + restart). No keyboard hooks, no P/Invoke, no user32.dll dependency.

---

## 0.9.0 — False Positive Reduction (May 2026)

### New Features
- **AllowlistService**: 3-tier trust (signed vendor, dev tools, user allowlist). President's Law rules NEVER respect allowlists.
- **CPU Throttling**: Job scheduler backs off under memory/thread pressure.
- **Context Awareness**: Development (-25) and gaming (-30) suspicion reduction.
- **Security Hardening**: DPAPI quarantine encryption, CIG audit, self-kill guards, watchdog, NtTraceEvent/CLR.DLL monitoring, expanded BYOVD detection.
- Zero LOLBin dependencies in response path.

### Architecture
- All detection and hardening logic built into C# binary (no external PowerShell scripts required).
- ConsultantSignalIngestor retained for optional external integration.


