# Sentinel — Threat Model

**Version: 1.9.7**

This document assumes the attacker has read the source code.

---

## Digital coercion / surveillance toolkit (v1.9.4)

**Mission:** Protect users from **endpoint tools** commonly used to control, watch, or take over a PC in online harassment, sexual coercion, stalkerware, account takeover, and remote blackmail.

**In scope (host behaviour):**

| Toolkit | Examples of signals | Composite / response |
|---------|---------------------|----------------------|
| Covert surveillance | Screen capture, webcam, keystroke-class monitors | + remote/C2 → `Covert Surveillance + Remote Channel` |
| Remote control | Reverse shell, RDP abuse, AnyDesk/TeamViewer-class from staging | + network → `Remote Control Abuse Toolkit` |
| Session / account theft | Browser/OS credential stores, token theft, CDP/extension abuse | + network/exfil → `Session Theft + Abuse Channel` |
| Stalkerware | Surveillance + autorun/persistence | `Stalkerware Persistence Chain` |
| Classic malware | C2, ransomware, BYOVD, injection | Existing composites (unchanged) |

**Out of scope (explicit):**

- Reading Discord / social / email message content  
- Identifying a person as a “rapist” or sexual offender  
- Moderating speech or ban-list scraping  
- Proving offline sexual assault  
- Stopping abuse that never touches the victim’s Windows host  

**Platforms:** Platform-agnostic. Messaging, social, email, browsers, games, voice/video, remote-support — anything that leaves process, file, registry, or network traces on Windows.

**Evidence:** Coercion-tagged packs include a technical section stating what Sentinel asserts vs does not assert, plus optional affidavit checkboxes the **victim** completes (remote control, recording, session theft, threats/coercion). Sentinel never auto-files with police.

**Honesty for users:** Settings → **Safety** page. Product language must not overclaim.

---

## Windows Event Log + barebone Windows (v1.9.5)

| Capability | Full Windows | Stripped / custom image |
|------------|--------------|-------------------------|
| JSONL `events.jsonl` | Primary trail | Primary trail (required) |
| Windows Event Log Application/Sentinel | Secondary trail (critical IDs) | **Auto-disabled** if create/write fails |
| Unified ETW | ~50 ms sensors | Falls back to WMI/poll |
| Toasts | Best effort | Skip if no session / AppId |
| TI proxy / feeds | Optional | Fail closed without secret |

Attacker wiping only Event Log does not erase JSONL packs. Attacker wiping JSONL may still leave Event Log IDs 1100/1200 if the service was up. Neither is a substitute for offline backups of packs.

---

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│ KERNEL (ring 0)                                         │
│   - Sentinel has NO kernel component                    │
│   - Active driver can suppress userland (but Sentinel   │
│     detects the ENTIRE chain leading to driver load:    │
│     priv esc → cert plant → .sys drop → service create) │
│   - v1.7.0: Planted signing certs are auto-revoked     │
└─────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────────────────────────────────────┐
│ SYSTEM (ring 3, highest userland privilege)              │
│   - Sentinel service runs here                          │
│   - ETW providers, full process access                  │
│   - SecureCacheStore, quarantine, firewall rules        │
└─────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────────────────────────────────────┐
│ ADMINISTRATOR (ring 3, elevated)                        │
│   - Can stop/delete services via SCM                    │
│   - Can take ownership of SYSTEM files                  │
│   - Can load drivers (BYOVD)                            │
└─────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────────────────────────────────────┐
│ STANDARD USER (ring 3)                                  │
│   - Cannot touch Sentinel service or files              │
│   - Sentinel agent (watchdog) runs here                 │
│   - Limited telemetry (WMI fallback, no ThreatIntel)    │
└─────────────────────────────────────────────────────────┘
```

---

## Monitor Coverage Summary (v1.7.6)

See [design.md](design.md) for the full component inventory (all MonitorGroups + Agent). Key additions since v1.4.5:

- **DriverLoadMonitor** (v1.5.0) — BYOVD detection + cert-tracing (v1.7.0)
- **BrowserC2Guard** (v1.6.8) — Headless Chrome proxy, CDP hijacking, extension integrity
- **EtwThreatIntelMonitor expanded** (v1.6.8) — Unbacked RWX region detection
- **SyscallStubMonitor expanded** (v1.6.8) — Hell's Gate / indirect syscall detection
- **PrintSpoolerMonitor expanded** (v1.6.8) — PrintNightmare-class exploitation
- **WslMonitor expanded** (v1.6.8) — Container-to-host lateral movement
- **WfpIntegrityMonitor** (v1.6.8) — WFP filter tamper detection
- **WmiProviderIntegrityMonitor** (v1.6.6) — Malicious WMI provider DLLs
- **ConnectivityCanaryMonitor** — EDRSilencer detection
- **EtwSessionGuard** (v1.6.1) — Self-healing ETW session
- **EtwProviderTamperMonitor** — EtwEventWrite patch detection
- **ThreatIntelFeedBlocker** (v1.7.4) — Spamhaus/Feodo/ET IP blocklists
- **LnkShortcutMonitor** (v1.7.4) — Real-time malicious shortcut guard
- **AgenticProcessMonitor** (v1.8.2) — AI coding agent / MCP toolchain abuse
- **PackageRuntimeMonitor** (v1.8.2) — Package-manager runtime + AI config poison
- **AsrPolicyGuard** (v1.7.5) — Self-healing Defender ASR Block rules
- **RemoteSessionGuard** (v1.7.5) — Force-logoff unauthorized RDP/remote sessions
- **ForumHrWatchMonitor** (v1.7.6) — Dedicated forum.hr abuse watch (site no longer hosts-blocked)
- **Observe-first posture (v1.8.3)** — Weak path/port/shell heuristics LogOnly; IPSec attack-only by default; `RestrictivePortHardening` for full lockdown

### Group 1: Critical (Self-Protection)
| Monitor | Purpose |
|---------|---------|
| SyscallStubMonitor | Detects ntdll unhooking/tampering |
| IPSecIntegrityGuard | Detects IPSec policy tampering |
| AsrPolicyGuard | Detects/re-applies demoted ASR Block rules |

### Group 2: Core Detection
| Monitor | Purpose |
|---------|---------|
| DiskWideDllScanner | Finds DLLs planted outside trusted directories |
| DllEntropyAnalyzer | Detects packed/encrypted DLLs |
| DllLoadFailureMonitor | Watches event log for suspicious load failures |
| ModuleValidationMonitor | Checks loaded DLL integrity via hash |
| RuntimeModuleIntegrityMonitor | Verifies loaded module paths |
| ScriptExecutionMonitor | PowerShell/WMI/AMSI bypass/SAM extraction/script drops |

### Group 3: Network Integrity
| Monitor | Purpose |
|---------|---------|
| ArpSpoofMonitor | Detects ARP cache poisoning |
| DnsResponseValidationMonitor | Detects DNS poisoning via TTL anomalies |
| PublicIpMonitor | Detects VPN/proxy changes |
| WifiSecurityMonitor | Detects open/WEP networks |
| RemoteAccessMonitor | Detects RAT indicators (RDP, VNC, etc.) |
| PhantomDeviceMonitor | Detects unauthorized network devices |

### Group 4: System Integrity
| Monitor | Purpose |
|---------|---------|
| FirewallIntegrityMonitor | Detects firewall rule tampering |
| SecureBootIntegrityMonitor | Checks Secure Boot state |
| ScheduledTaskMonitor | Detects new/modified scheduled tasks |
| TlsCertificateMonitor | Detects unauthorized root CA installations |
| UacBypassSurfaceMonitor | Detects autoelevate binary abuse |

### Group 5: Credential Protection
| Monitor | Purpose |
|---------|---------|
| CanaryFileMonitor | Honeypot files in sensitive directories |
| BrowserCredentialGuard | Chrome/Edge/Firefox credential theft detection |
| MicrosoftAccountGuardMonitor | Watches for MS account token access |
| NullSessionGuard | Detects null session enumeration |
| BuiltinAdminGuard | Detects enabled/exploited built-in Administrator |
| PasswordRotationGuard | Monitors password age and blank passwords |

### Group 6: Peripheral & Environmental
| Monitor | Purpose |
|---------|---------|
| BluetoothMonitor | Detects new unknown Bluetooth devices |
| PhantomDeviceMonitor | Detects unauthorized network peripherals |
| DeviceInstallMonitor | New device driver installations |
| MtpTransferGuard | Blocks non-media writes to portable devices |
| VolumeMountMonitor | RAM disks, SUBST, VHD, VeraCrypt mounts |
| CastDeviceGuard | Blocks unauthorized Cast/screen-share devices |
| WslMonitor | WSL execution evasion detection |
| RawDiskAccessMonitor | Direct disk I/O bypass detection |
| PrintSpoolerMonitor | Print spooler exfiltration detection |
| SandboxEscapeMonitor | Container/sandbox escape detection |
| HardwareSecurityGuard | TPM, Secure Boot, BitLocker, Credential Guard |
| UsbHidWhitelist | BadUSB/Rubber Ducky defense |
| PhysicalAccessMonitor | Post-idle hardware change correlation |

### Standalone Monitors (not grouped)
| Monitor | Purpose |
|---------|---------|
| FileActivityMonitor | Real-time file system change tracking |
| EtwProcessMonitor | Process creation/termination via ETW |
| EtwThreatIntelMonitor | Kernel-level API observation |
| GhostProcessMonitor | Detects orphan/invisible processes |
| NetworkMonitor | TCP connection tracking and C2 detection |
| RegistryMonitor | Registry change monitoring |
| BeaconingDetector | Statistical C2 beacon detection |
| RansomwareIoMonitor | Shadow copy + bulk encryption detection |
| TokenIntegrityMonitor | Privilege escalation detection |
| MemoryBehaviorAnalyzer | RWX/shellcode pattern detection |
| DataExfiltrationMonitor | Large outbound data transfer detection |
| NetworkInterfaceGuard | Bridge/adapter tampering detection |
| AcousticThreatMonitor | Microphone access monitoring |
| WebcamHijackMonitor | Camera access monitoring |

---

## Bypass Scenarios (Known)

### B1: Attacker has local admin

**Attack:** `sc stop "Sentinel"` or `taskkill /f /im SentinelService.exe`

**Mitigation:**
- Agent watchdog detects stale heartbeat and attempts restart
- Service registry key ACL'd to deny Administrators delete (partial)
- ServiceProtectionMonitor detects SCM tampering

**Residual risk:** HIGH. Local admin can always win against userland. This is a fundamental Windows limitation without PPL or kernel driver.

**Honest assessment:** If the attacker has admin and knows Sentinel is running, they can kill it. The watchdog adds seconds of delay, not real protection.

---

### B2: BYOVD (Bring Your Own Vulnerable Driver)

**Attack:** Load a signed vulnerable driver, use it to kill Sentinel from kernel.

**Mitigation:**
- `DriverLoadMonitor` detects Event 7045 (service install), registry service creation, and .sys drops in user-writable paths every 15s
- Embedded blocklist of 35+ known vulnerable driver hashes (Microsoft WDBL + LOLDrivers)
- Known vulnerable driver filenames flagged even without hash match
- High-confidence matches (hash or name+non-standard-path) → `KillProcessTree` + service disable/delete via native SCM
- **v1.7.0 cert-tracing:** Extracts Authenticode cert from detected driver → checks if cert was planted in TrustedPublisher/Root stores → if NOT a public CA, fires `RemoveCertAndKillAdder` (revokes cert, kills installer chain, scans for other drivers signed by same cert)
- Prerequisite monitoring: privilege escalation, UAC bypass, token manipulation all detected before attacker reaches the point of driver installation
- `SecureBootIntegrityMonitor` detects test signing mode / kernel debug enabled
- `WfpIntegrityMonitor` detects WFP filters blocking Sentinel/EDR processes
- Memory Integrity (HVCI) monitoring — alerts if disabled

**Residual risk:** MEDIUM. Sentinel wins the race in most scenarios because it monitors the prerequisites (priv esc, file drop, service creation, cert planting). If an attacker has admin, bypasses all prerequisite detections silently, uses an unknown driver not on the blocklist signed by a legitimate public CA (not a planted cert), AND loads it faster than the 15s poll — then the driver can suppress Sentinel. Remote alerting fires before suppression in most cases.

---

### B3: ETW blinding

**Attack:** Patch `ntdll!EtwEventWrite` or `ntdll!NtTraceEvent` in Sentinel's process to suppress telemetry.

**Mitigation:**
- EtwTamperingRule detects known patching patterns
- Self-protection monitors for DLL injection into own process
- CIG (Code Integrity Guard) audit prevents unsigned DLL load

**Residual risk:** MEDIUM. Direct syscall patching bypasses userland hooks. Sentinel detects the ATTEMPT but cannot prevent it if attacker is already in-process.

---

### B4: Reputation cache poisoning (FIXED in v1.1.0)

**Attack (pre-1.1.0):** Attacker running as SYSTEM writes a "safe" verdict for their payload into the SecureCacheStore.

**Mitigation (v1.1.0+):**
- HMAC key incorporates installation entropy — requires SYSTEM access to forge
- DPAPI machine-scope encryption — file is unreadable on another machine
- ACL restricts to SYSTEM + Administrators only
- Unknown verdicts are not cached (re-checked next scan cycle)

**Residual risk:** LOW. An attacker with SYSTEM access can do far more damage than forging cache entries.

---

### B5: Process name/path spoofing

**Attack:** Rename malware to match allowlisted process names.

**Mitigation:**
- Detection rules use behavioral signals, not process names
- Allowlist uses full path verification (binary must reside under legitimate directory)
- Self-exclusion checks normalize paths with `Path.GetFullPath()`

**Residual risk:** LOW. Path-based verification prevents simple rename attacks.

---

### B6: Command-line obfuscation

**Attack:** Encode/obfuscate command-line arguments to bypass token matching.

**Mitigation:**
- Encoded PowerShell detection (base64 patterns)
- Multi-signal correlation (cmdline + network + memory = composite)
- ETW ThreatIntel provides kernel-level API observation regardless of cmdline

**Residual risk:** MEDIUM. Sophisticated tooling can avoid command-line exposure entirely. MemoryBehaviorAnalyzer and ETW ThreatIntel cover this gap.

---

### B7: DLL sideloading into Sentinel process

**Attack:** Place a malicious DLL in Sentinel's search path.

**Mitigation:**
- ProcessHardening.ApplyOrFail() at startup: restricts DLL search to System32 only
- NTFS ACL lockdown on installation directory
- Directory watcher deletes unauthorized files and kills writing processes
- CIG audit mode prevents unsigned DLL loads

**Residual risk:** LOW if CIG is enforced. MEDIUM if CIG is audit-only.

---

### B8: Time-of-check-to-time-of-use (TOCTOU) on file hashes

**Attack:** Swap a file between when Sentinel hashes it and when it executes.

**Mitigation:**
- Hash checks happen at process-start time (ETW event)
- File is already mapped into memory by the time we hash it
- Quarantine reads, encrypts, then deletes atomically

**Residual risk:** LOW. Race window is milliseconds.

---

### B8b: Installer / shell false kills (FIXED in v1.6.2)

**Attack surface (pre-1.6.2, operator self-DoS):** Legitimate software installs and Windows shell behavior were classified as high-severity threats and chain-quarantined:

1. **PPID spoof on Inno Setup** — Git for Windows / Chrome extractors (`innosetup-*.tmp`) race ETW vs kernel parent PID → Kill + ChainTracer quarantine of the signed installer.
2. **Raw disk on explorer / taskhostw** — Shell holds `\Device\HarddiskVolume*` / disk handles; catalog-sign verify could fail → KillProcessTree on system binaries.
3. **ChainTracer empty path** — Critical process names with unresolved image path were treated as non-system → kill/quarantine.
4. **Signed quarantine** — Any chain path could wipe Authenticode-valid installers (Git, ChromeSetup, even SentinelSetup).

**Mitigation (v1.6.2+):**
- `InstallerHeuristics` + PPID skip for Inno/NSIS extractors and signed installer parents
- `RawDiskAccessMonitor` never kills critical hosts under `%SystemRoot%`; volume-root LogOnly; PhysicalDrive kill only for unsigned non-Windows paths
- `ChainTracer` preserves critical names when path empty; preserves signed installer ancestors
- `QuarantineManager` refuses signed files unless force (cuckoo/sideload)
- Ephemeral prefetch noise suppressed for GIT/INNOSETUP/DOTNET/setup patterns

**Residual risk:** LOW for official signed installers. Unsigned portable tools in Temp may still draw LogOnly or, if also holding PhysicalDrive, kill. True PPID spoof malware that is unsigned remains kill-authorized.

---

### B8c: Parallel quarantine path / OS binary wipe (FIXED in v1.6.3)

**Attack surface (pre-1.6.3, operator self-DoS):** ChainTracer skipped System32/SysWOW64 quarantine, but `AdvancedResponseEngine` always called `IncidentResponseService.CollectEvidenceAsync` *before* ChainTracer. That path quarantined `MainModule` with no OS-path gate. Combined with AMSI “no amsi.dll” → KillProcessTree on stock PowerShell (catalog-signed verify fail-open), production deleted `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`.

**Mitigation (v1.6.3+):**
- `QuarantineManager` hard-refuses OS-critical paths (`IsOsCriticalPath`); force flag cannot override
- Signature-check exceptions fail closed under Windows / Program Files
- `IncidentResponseService` skips OS-critical paths before quarantine
- System PowerShell hosts missing amsi.dll → LogOnly only (not kill)
- USB failed-enumeration Tier1 + auto-disable; trusted VID:PID allowlist

**Residual risk:** LOW for System32 hosts. Impostor `powershell.exe` outside system paths can still be killed. Catalog verify failures on non-Windows paths may still quarantine unsigned drops (intended).

---

### B9: Behavioral baseline poisoning (FIXED in v1.5.9)

**Attack:** Malware achieves persistence (e.g., scheduled task) and runs 10+ times over days to earn "established" status in `BehavioralBaselineService`. Once established, all future detections receive a −10 to −20 score reduction, potentially dropping below the kill threshold.

**Mitigation (v1.5.9+):**
- `IsEstablishedProcess()` requires ZERO detection events for the process name within a 7-day window
- `ScoringEngine.Score()` records every detection via `RecordDetectionForProcess()`, permanently revoking established status
- Detection records age out after 7 days with no new detections (allows recovery from one-time false positives)
- Total baseline/trust reduction is capped at −20 regardless (v1.3.0)

**Residual risk:** LOW. A process that has EVER fired a detection cannot earn baseline trust.

---

### B10: ActiveResponse config tampering (FIXED in v1.5.9 / v1.6.0)

**Attack:** Attacker modifies `appsettings.json` or injects config to set `ActiveResponse=false`, neutering all kill/quarantine/isolate responses while Sentinel continues running (appearing functional but inert). Includes reboot with `ActiveResponse=false` already set.

**Mitigation (v1.5.9+ / v1.6.0):**
- `AntiTamperGuard` monitors `ActiveResponse` flag every ~10s
- Transition from true→false fires Tier1 anti-tamper detection (confidence 0.99)
- **v1.6.0:** Boot-time `ActiveResponse=false` is force-enabled in `StartAsync` and alerted on first integrity tick
- **v1.6.0:** `appsettings.json` content hash monitored; modifications emit anti-tamper detection
- **v1.6.0:** `EnforceActiveResponse` (default true) policy; set false only for intentional observation mode
- ActiveResponse is forcibly re-enabled immediately upon detection
- The alert is immune to the ActiveResponse flag (uses LogOnly response type)

**Residual risk:** LOW. Requires `EnforceActiveResponse=false` (operator choice) or kernel/SYSTEM ability to patch the process image.

---

### B11: Supply-chain C2 via signed binary (FIXED in v1.5.9)

**Attack:** Compromise a legitimate software update (SolarWinds-style). The signed binary is installed in Program Files, passes all trust checks (Authenticode + protected path + baseline + diversity). Its C2 beaconing gets demoted to LogOnly, maintaining an unblocked communication channel.

**Mitigation (v1.5.9+):**
- `BeaconingDetector` never demotes confirmed statistical beaconing below `NetworkIsolate`
- Even maximum trust score (signed + protected path + diversity + baseline) only achieves `NetworkIsolate` — C2 IP is always firewall-blocked
- C2Beaconing added to President's Law — cannot be suppressed by user allowlisting
- DLL sideloading check invalidates Authenticode trust for compromised processes

**Residual risk:** MEDIUM. The C2 channel is blocked, but if the attacker uses a legitimate CDN/cloud endpoint as C2 (domain fronting), the NetworkIsolate may block legitimate traffic to that IP too. The detection still fires and is logged regardless.

---

### B12: Dynamic rule injection (FIXED in v1.5.9 / v1.6.0)

**Attack:** Attacker deletes the `.install_entropy` file (used for HMAC key derivation), then drops a malicious JSON rule file into the `rules/` directory. Previously, missing entropy caused HMAC verification to be skipped (fail-open), allowing arbitrary unsigned rules to load. Local admins could also read entropy and forge valid HMACs.

**Mitigation (v1.5.9+ / v1.6.0):**
- `DynamicRulesEvaluator` now fails CLOSED — missing HMAC key rejects all rules
- **v1.6.0:** `.install_entropy` ACL is SYSTEM-only (Administrators cannot read signing material)
- **v1.6.0:** Rules directory write is SYSTEM-only; Admins/Users are read-only
- Entropy file deletion itself would require SYSTEM access

**Residual risk:** LOW. Requires SYSTEM (or taking ownership of the entropy file) to forge signed rules.

---

### B13: Threat proxy forgery (FIXED in v1.6.0)

**Attack:** Unauthenticated or client-key HMAC on the Cloudflare Worker allowed anyone to forge threat reports / burn VT quota.

**Mitigation (v1.6.0+):**
- Worker requires `SENTINEL_SHARED_SECRET` (fail closed with 503 if missing)
- HMAC uses server-side secret only — `X-Sentinel-Key` removed
- Agent signs with `ThreatReporting:ProxySharedSecret`; reporting skipped if secret unset
- Per-IP rate limit (60/min) on the Worker

**Residual risk:** LOW if secret is strong and not committed. Shared secret in open-source configs must be set per-deployment.

---

### B14: Kill-storm / response weaponization (FIXED in v1.6.0)

**Attack:** Induce many false positives to make Sentinel kill large numbers of processes.

**Mitigation (v1.6.0+):**
- `MaxKillsPerMinute` (default 15) rate-limits kill and quarantine-kill actions
- Expanded protected process list (Defender / Sense / smartscreen) with path verification
- Excess kills demoted to LogOnly with a rate-limit response event

**Residual risk:** MEDIUM. NetworkIsolate is not rate-limited; determined attackers can still cause noise.

---

## What Sentinel CANNOT Protect Against

Fundamental limitations, not bugs:

1. **Kernel-level attacks with novel implants** — No visibility below ring 3. Default (v1.8.3) IPSec is **attack-only** (Telnet/rsh/classic RAT ports; Remote Registry/Telnet services off) so users keep SSH/RDP/SMB. Full port/service lockdown is opt-in (`RestrictivePortHardening: true`). DEP/SEHOP/Spectre mitigations and ASR still apply.
2. **Hardware implants** — No firmware/UEFI visibility (but detects Secure Boot disabled)
3. **Pre-boot attacks** — Sentinel starts after Windows boots (detects boot config tampering)
4. **Attacker with physical access + offline disk** — Can boot from USB, modify disk (but detects post-idle hardware changes)
5. **Attacker already running as SYSTEM** — Can kill Sentinel (watchdog adds delay only)
6. **Encrypted C2 over legitimate ports** — Looks like normal HTTPS (but TLS cert monitor detects rogue CA installations; beaconing detector catches statistical patterns)
7. **Direct syscalls from custom code** — Bypasses ntdll hooks (SyscallStubMonitor detects unhooking attempts; v1.6.8 Hell's Gate in-memory pattern detection scans for syscall stubs in non-image regions)
8. **GPU memory-resident malware** — Code in GPU VRAM/compute shaders has no CPU-side memory to scan
9. **Physical-layer Wi-Fi attacks** — Cannot see deauth frames directly (detects rapid disconnects)

---

## What Sentinel CAN Detect Even Against Skilled Attackers

Hard-to-bypass detections (require kernel access to evade):

1. **Parent PID spoofing** — ETW reports kernel truth; can't be faked from userland
2. **Credential harvesting** — Canary credential is a zero-FP tripwire
3. **Ransomware** — Shadow copy deletion + bulk encryption is behaviorally unavoidable
4. **ntdll unhooking** — Stub integrity check detects the modification itself
5. **Privilege escalation** — Token integrity transitions are observable regardless of method
6. **Process injection (kernel ETW)** — API calls observed at kernel level
7. **Phantom keystrokes (SendInput)** — Blocked globally via WH_KEYBOARD_LL
8. **Credential Guard disablement** — LsaIso.exe absence + registry state change
9. **Hardware security downgrade** — TPM/SecureBoot/BitLocker state monitored every 5 minutes

---

## Detection Confidence Levels

| Detection | vs Commodity Malware | vs Targeted Attacker |
|-----------|---------------------|---------------------|
| Ransomware (shadow copy + bulk rename) | HIGH | HIGH |
| Credential canary (honeypot) | HIGH | HIGH |
| Parent PID spoofing | HIGH | HIGH |
| Phantom keystrokes (SendInput) | HIGH | HIGH |
| Parent-child anomaly (Office→shell) | HIGH | HIGH |
| SAM hive extraction (reg save) | HIGH | HIGH |
| LSASS dump (dbghelp.dll load) | HIGH | MEDIUM |
| Syscall stub integrity | HIGH | MEDIUM |
| Token integrity escalation | HIGH | MEDIUM |
| Process injection (ETW ThreatIntel) | HIGH | MEDIUM |
| Credential Guard disablement | HIGH | MEDIUM |
| Hardware security downgrade | HIGH | MEDIUM |
| AMSI bypass (amsi.dll unloaded) | HIGH | MEDIUM |
| PowerShell Script Block patterns | HIGH | MEDIUM |
| Memory behavior (RWX/shellcode) | MEDIUM | MEDIUM |
| DNS DGA detection | MEDIUM | MEDIUM |
| BadUSB/unauthorized HID | HIGH | MEDIUM |
| Suspicious script file drops | MEDIUM | LOW |
| C2 beaconing (statistical) | HIGH | MEDIUM |
| DNS tunneling | MEDIUM | LOW |
| File entropy | LOW | LOW |
| Campaign IOCs | MEDIUM | LOW |

---

## Design Principles

1. **Behavioral over static** — Detect what processes DO, not what they ARE
2. **No security theater** — If it doesn't work against a competent attacker, document limitations
3. **Assume the attacker reads the code** — No security-by-obscurity
4. **Layered defense** — Sentinel is ONE layer alongside Defender, not a replacement
5. **Kill only on corroboration** — Multiple Tier2 signals correlating produce composite kills. Single signals never kill independently (except self-protection)
6. **Honest documentation** — State what works and what doesn't

---

## Closed Vulnerabilities

See CHANGELOG.md for full history. Key fixes:

- **v1.7.6:** Removed opinionated forum.hr hosts block; added `ForumHrWatchMonitor` for non-browser C2/relay abuse of that site alone.
- **v1.7.5:** ASR Block self-heal (`AsrPolicyGuard`), remote session force-logoff (`RemoteSessionGuard`), install-time credential/browser residual hardening. Documentation inventory parity with runtime registration.
- **v1.7.4:** ThreatIntelFeedBlocker (Spamhaus/Feodo/ET), real-time `LnkShortcutMonitor`, Agent scareware/cursor/cookie ports.
- **v1.7.0:** BYOVD cert-tracing: `DriverLoadMonitor` now extracts Authenticode cert from detected drivers, checks TrustedPublisher/Root stores, revokes planted non-public certs via `RemoveCertAndKillAdder`, scans System32\drivers for other drivers signed by same identity. Closes the fake-Chromecast-CA / planted-cert BYOVD attack chain.
- **v1.6.9:** IDE false-positive kill prevention: V8 JIT code matching syscall-stub patterns no longer kills Electron IDEs; ChainTracer preserves IDE host ancestors; AdvancedResponseEngine IDE host protection demotes to LogOnly for non-President's-Law rules.
- **v1.6.8:** BrowserC2Guard (headless Chrome proxy + CDP hijack + extension integrity), EtwThreatIntelMonitor RWX detection, SyscallStubMonitor Hell's Gate patterns, PrintSpoolerMonitor PrintNightmare exploitation, WslMonitor container-to-host lateral movement, Named Pipe + Beaconing and Token + Lateral composite detections.
- **v1.6.3:** OS self-DoS closed: `QuarantineManager` + `IncidentResponseService` hard-refuse OS-critical paths (production FP deleted System32 `powershell.exe` after AMSI false positive). System PowerShell AMSI demotion to LogOnly. Failed USB enumeration Tier1 + auto-disable; `TrustedUsbDevices` allowlist.
- **v1.6.2:** Installer/shell false-positive remediation (ProgramData evidence): PPID spoof no longer kills Inno Setup extractors; Raw Disk Access never kills explorer/taskhostw under Windows; ChainTracer preserves critical hosts with empty path and signed installer ancestors; QuarantineManager refuses Authenticode-signed files by default; EphemeralProcessMonitor ignores installer prefetch noise; shared InstallerHeuristics
- **v1.6.1:** EtwSessionGuard (heal stopped ETW session), NetworkIsolate rate limit + budget Tier1 alerts, ClickFix/FakeCAPTCHA rule expansion, NpmSupplyChainRule
- **v1.6.0:** Audit remediation: threat-proxy server-side HMAC (no client key), ActiveResponse boot-time force + appsettings integrity, SYSTEM-only entropy, rules dir write SYSTEM-only, kill rate limit, protected AV processes, native SCM driver disable, Cast IP validation, tray LOLBin removal
- **v1.5.9:** 7 false-positive/false-negative fixes: supply-chain beaconing gap (C2 never LogOnly), signed injector quarantine prevention, C2 back in President's Law, ActiveResponse tamper detection, baseline poisoning prevention, dynamic rules fail-closed, svchost correlation bypass
- **v1.4.5:** LSA secret storage for auto-logon, Credential Guard monitoring, ScriptExecutionMonitor (PowerShell/AMSI/SAM/script drops), Tier1+Tier2 correlation fix, Agent code placement cleanup
- **v1.4.4:** 15 red-team findings fixed (command injection, handle leaks, HMAC weakness, socket exhaustion, installer race conditions)
- **v1.1.0:** Cache poisoning, process name spoofing, self-exclusion bypass
- **v1.0.1:** RAM disk staging, WSL evasion, raw disk bypass, print spooler exfil, sandbox escape
