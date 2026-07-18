# Behavedr — Threat Model

**Version: 1.4.9**

This document assumes the attacker has read the source code.

---

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│ KERNEL (ring 0)                                         │
│   - Behavedr has NO visibility here                     │
│   - Attacker with driver = game over                    │
└─────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────────────────────────────────────┐
│ SYSTEM (ring 3, highest userland privilege)              │
│   - Behavedr service runs here                          │
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
│   - Cannot touch Behavedr service or files              │
│   - Behavedr agent (watchdog) runs here                 │
│   - Limited telemetry (WMI fallback, no ThreatIntel)    │
└─────────────────────────────────────────────────────────┘
```

---

## Monitor Coverage Summary (v1.4.5)

### Group 1: Critical (Self-Protection)
| Monitor | Purpose |
|---------|---------|
| SyscallStubMonitor | Detects ntdll unhooking/tampering |
| IPSecIntegrityGuard | Detects IPSec policy tampering |

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

**Attack:** `sc stop "Behavedr"` or `taskkill /f /im BehavedrService.exe`

**Mitigation:**
- Agent watchdog detects stale heartbeat and attempts restart
- Service registry key ACL'd to deny Administrators delete (partial)
- ServiceProtectionMonitor detects SCM tampering

**Residual risk:** HIGH. Local admin can always win against userland. This is a fundamental Windows limitation without PPL or kernel driver.

**Honest assessment:** If the attacker has admin and knows Behavedr is running, they can kill it. The watchdog adds seconds of delay, not real protection.

---

### B2: BYOVD (Bring Your Own Vulnerable Driver)

**Attack:** Load a signed vulnerable driver, use it to kill Behavedr from kernel.

**Mitigation:**
- BYOVD detection rule (known vulnerable driver hashes)
- Memory Integrity (HVCI) monitoring — alerts if disabled

**Residual risk:** HIGH. If HVCI is off and attacker has admin, they can load any signed driver. Behavedr cannot prevent kernel-level attacks.

---

### B3: ETW blinding

**Attack:** Patch `ntdll!EtwEventWrite` or `ntdll!NtTraceEvent` in Behavedr's process to suppress telemetry.

**Mitigation:**
- EtwTamperingRule detects known patching patterns
- Self-protection monitors for DLL injection into own process
- CIG (Code Integrity Guard) audit prevents unsigned DLL load

**Residual risk:** MEDIUM. Direct syscall patching bypasses userland hooks. Behavedr detects the ATTEMPT but cannot prevent it if attacker is already in-process.

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

### B7: DLL sideloading into Behavedr process

**Attack:** Place a malicious DLL in Behavedr's search path.

**Mitigation:**
- ProcessHardening.ApplyOrFail() at startup: restricts DLL search to System32 only
- NTFS ACL lockdown on installation directory
- Directory watcher deletes unauthorized files and kills writing processes
- CIG audit mode prevents unsigned DLL loads

**Residual risk:** LOW if CIG is enforced. MEDIUM if CIG is audit-only.

---

### B8: Time-of-check-to-time-of-use (TOCTOU) on file hashes

**Attack:** Swap a file between when Behavedr hashes it and when it executes.

**Mitigation:**
- Hash checks happen at process-start time (ETW event)
- File is already mapped into memory by the time we hash it
- Quarantine reads, encrypts, then deletes atomically

**Residual risk:** LOW. Race window is milliseconds.

---

## What Behavedr CANNOT Protect Against

Fundamental limitations, not bugs:

1. **Kernel-level attacks** — No visibility below ring 3
2. **Hardware implants** — No firmware/UEFI visibility (but detects Secure Boot disabled)
3. **Pre-boot attacks** — Behavedr starts after Windows boots (detects boot config tampering)
4. **Attacker with physical access + offline disk** — Can boot from USB, modify disk (but detects post-idle hardware changes)
5. **Attacker already running as SYSTEM** — Can kill Behavedr (watchdog adds delay only)
6. **Nation-state tooling** — Custom kernel implants, 0-days, hardware backdoors
7. **Encrypted C2 over legitimate ports** — Looks like normal HTTPS (but TLS cert monitor detects rogue CA installations)
8. **Direct syscalls from custom code** — Bypasses ntdll hooks (SyscallStubMonitor detects unhooking attempts)
9. **GPU memory-resident malware** — Code in GPU VRAM/compute shaders has no CPU-side memory to scan
10. **Physical-layer Wi-Fi attacks** — Cannot see deauth frames directly (detects rapid disconnects)

---

## What Behavedr CAN Detect Even Against Skilled Attackers

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
| C2 beaconing (statistical) | MEDIUM | LOW |
| DNS tunneling | MEDIUM | LOW |
| File entropy | LOW | LOW |
| Campaign IOCs | MEDIUM | LOW |

---

## Design Principles

1. **Behavioral over static** — Detect what processes DO, not what they ARE
2. **No security theater** — If it doesn't work against a competent attacker, document limitations
3. **Assume the attacker reads the code** — No security-by-obscurity
4. **Layered defense** — Behavedr is ONE layer alongside Defender, not a replacement
5. **Kill only on corroboration** — Multiple Tier2 signals correlating produce composite kills. Single signals never kill independently (except self-protection)
6. **Honest documentation** — State what works and what doesn't

---

## Closed Vulnerabilities

See CHANGELOG.md for full history. Key fixes:

- **v1.4.5:** LSA secret storage for auto-logon, Credential Guard monitoring, ScriptExecutionMonitor (PowerShell/AMSI/SAM/script drops), Tier1+Tier2 correlation fix, Agent code placement cleanup
- **v1.4.4:** 15 red-team findings fixed (command injection, handle leaks, HMAC weakness, socket exhaustion, installer race conditions)
- **v1.1.0:** Cache poisoning, process name spoofing, self-exclusion bypass
- **v1.0.1:** RAM disk staging, WSL evasion, raw disk bypass, print spooler exfil, sandbox escape
