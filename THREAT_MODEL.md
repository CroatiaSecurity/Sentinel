# Windows Sentinel — Threat Model

**Version: 0.8.3**

This document assumes the attacker has read the source code.

---

## Trust Boundaries

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ KERNEL (ring 0)                                         â”‚
â”‚   - Sentinel has NO visibility here                     â”‚
â”‚   - Attacker with driver = game over                    â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                          â”‚
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ SYSTEM (ring 3, highest userland privilege)              â”‚
â”‚   - Sentinel service runs here                          â”‚
â”‚   - ETW providers, full process access                  â”‚
â”‚   - SecureCacheStore, quarantine, firewall rules        â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                          â”‚
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ ADMINISTRATOR (ring 3, elevated)                        â”‚
â”‚   - Can stop/delete services via SCM                    â”‚
â”‚   - Can take ownership of SYSTEM files                  â”‚
â”‚   - Can load drivers (BYOVD)                            â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                          â”‚
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ STANDARD USER (ring 3)                                  â”‚
â”‚   - Cannot touch Sentinel service or files              â”‚
â”‚   - Sentinel agent (watchdog) runs here                 â”‚
â”‚   - Limited telemetry (WMI fallback, no ThreatIntel)    â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

---

## Bypass Scenarios (Known)

### B1: Attacker has local admin

**Attack:** `sc stop "Windows Sentinel"` or `taskkill /f /im SentinelService.exe`

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
- BYOVD detection rule (known vulnerable driver hashes)
- Memory Integrity (HVCI) monitoring â€” alerts if disabled

**Residual risk:** HIGH. If HVCI is off and attacker has admin, they can load any signed driver. Sentinel cannot prevent kernel-level attacks.

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

**Mitigation (v1.1.0):**
- HMAC key now incorporates boot-time nonce â€” caches from previous boots are rejected
- DPAPI machine-scope encryption â€” file is unreadable on another machine
- ACL restricts to SYSTEM + Administrators only
- Boot-nonce means attacker must poison DURING current session (narrower window)

**Residual risk:** MEDIUM. An attacker already running as SYSTEM in the current boot session CAN still write to the cache. The mitigation narrows the window but doesn't eliminate it. True elimination requires an out-of-band trust anchor (TPM, remote attestation, or kernel-protected memory).

---

### B5: Process name/path spoofing

**Attack:** Rename malware to match allowlisted process names.

**Mitigation (v1.1.0):**
- Detection rules no longer use process names as primary signals
- LsassAccessRule: behavioral-only (command-line patterns)
- ProcessInjectionRule: behavioral-only (API patterns in cmdline)
- Tool-name lists retained only for metadata enrichment, not detection decisions

**Residual risk:** LOW for detection rules. The allowlist service still uses process paths for FP reduction, but President's Law kills NEVER respect allowlists.

---

### B6: Command-line obfuscation

**Attack:** Encode/obfuscate command-line arguments to bypass token matching.

**Mitigation:**
- Encoded PowerShell detection (base64 patterns)
- Multi-signal correlation (cmdline + network + memory = composite)
- ETW ThreatIntel provides kernel-level API observation regardless of cmdline

**Residual risk:** MEDIUM. Sophisticated tooling (Cobalt Strike, custom loaders) can avoid command-line exposure entirely. The MemoryBehaviorAnalyzer and ETW ThreatIntel monitor cover this gap for in-memory attacks.

---

### B7: DLL sideloading into Sentinel process

**Attack:** Place a malicious DLL in Sentinel's search path to get loaded into the service.

**Mitigation:**
- ProcessHardening.ApplyOrFail() at startup: sets DLL search order, removes CWD
- CIG audit mode prevents unsigned DLL loads
- Self-integrity hash check detects binary modification

**Residual risk:** LOW if CIG is enforced. MEDIUM if CIG is audit-only (current default).

---

### B8: Time-of-check-to-time-of-use (TOCTOU) on file hashes

**Attack:** Swap a file between when Sentinel hashes it and when it executes.

**Mitigation:**
- Hash checks happen at process-start time (ETW event)
- File is already loaded into memory by the time we hash it
- For quarantine: file is read, encrypted, then original deleted atomically

**Residual risk:** LOW for process-start detection. The race window is milliseconds.

---

## What Sentinel CANNOT Protect Against

These are fundamental limitations, not bugs:

1. **Kernel-level attacks** â€” No visibility below ring 3
2. **Hardware implants** â€” No visibility into firmware/UEFI (but detects Secure Boot disabled)
3. **Pre-boot attacks** â€” Sentinel starts after Windows boots (but detects boot config tampering)
4. **Attacker with physical access** â€” Can boot from USB, modify disk offline
5. **Attacker who already has SYSTEM** â€” Can kill Sentinel (watchdog adds delay only)
6. **Nation-state tooling** â€” Custom kernel implants, 0-days, hardware backdoors
7. **Encrypted C2 over legitimate ports** â€” Looks like normal HTTPS traffic (but TLS cert monitor detects unauthorized root CA installations that could enable MITM)
8. **Direct syscalls from custom code** â€” Bypasses ntdll hooks (but SyscallStubMonitor detects unhooking attempts)
9. **Upstream BGP hijacking** â€” Detectable via public IP shift but not preventable
10. **Physical-layer Wi-Fi attacks** â€” Cannot see deauth frames directly (detects the symptom: rapid disconnects)

## What Sentinel CAN Detect Even Against Skilled Attackers

These detections are hard to bypass without kernel access. All are **Tier2 corroborating signals** (except SyscallStubMonitor which is self-protection). They feed the correlation engine â€” multiple signals on the same PID within 120s produce a composite kill:

1. **Parent PID spoofing** (Tier2) â€” ETW reports kernel truth; can't be faked from userland
2. **Credential harvesting** (Tier2) â€” Canary credential is a zero-FP tripwire
3. **Ransomware** (Tier1) â€” Shadow copy deletion + bulk encryption is behaviorally unavoidable
4. **ntdll unhooking** (Tier1 self-protection) â€” Stub integrity check detects the modification itself
5. **Privilege escalation** (Tier2) â€” Token integrity transitions are observable regardless of method
6. **dbghelp.dll abuse** (Tier2) â€” Module load is visible even if the tool is custom-built
7. **DNS-based C2** (Tier2) â€” ETW DNS-Client fires on all resolutions regardless of method
8. **Process injection (kernel ETW)** (Tier1) â€” API calls observed at kernel level

---

## Detection Confidence Levels (Honest Assessment)

| Detection | Confidence Against Commodity Malware | Confidence Against Targeted Attacker |
|-----------|--------------------------------------|--------------------------------------|
| Ransomware (shadow copy + bulk rename) | HIGH | HIGH (behavioral, hard to avoid) |
| Credential canary (honeypot credential) | HIGH | HIGH (zero-FP tripwire, can't avoid without knowing it exists) |
| LSASS dump (dbghelp.dll load) | HIGH | MEDIUM (attacker can bring own dbghelp or use direct syscalls) |
| LSASS dump (cmdline patterns) | HIGH | LOW (attacker uses direct syscalls) |
| Parent PID spoofing detection | HIGH | HIGH (kernel truth vs userland â€” can't fake ETW) |
| Syscall stub integrity | HIGH | MEDIUM (attacker must patch before Sentinel starts, or use kernel) |
| Token integrity escalation | HIGH | MEDIUM (detects the result, not the method) |
| Process injection (ETW ThreatIntel) | HIGH | MEDIUM (kernel-level, but can be blinded with driver) |
| Process injection (cmdline API names) | MEDIUM | LOW (attacker won't put API names in cmdline) |
| DNS DGA detection | MEDIUM | MEDIUM (attacker can use low-entropy domains or legitimate DNS) |
| DNS tunneling | MEDIUM | LOW (attacker can stay under 30 queries/min threshold) |
| C2 beaconing (statistical) | MEDIUM | LOW (attacker uses jitter/legitimate ports) |
| Memory behavior (RWX/shellcode) | MEDIUM | MEDIUM (hard to avoid RWX entirely) |
| Phantom keystrokes (SendInput) | HIGH | HIGH (blocked globally at ring 3 via WH_KEYBOARD_LL) |
| File entropy | LOW | LOW (trivially bypassed with padding) |
| Campaign IOCs | MEDIUM | LOW (attacker uses fresh infrastructure) |
| Campaign IOCs | MEDIUM | LOW (attacker uses fresh infrastructure) |

---

## Design Principles (v1.7.0)

1. **Behavioral over static** â€” Detect what processes DO, not what they ARE
2. **No security theater** â€” If a feature doesn't work against a competent attacker, remove it or honestly document its limitations
3. **Fewer solid detections > many fragile ones** â€” Each rule must justify its existence
4. **Assume the attacker reads the code** â€” No security-by-obscurity
5. **Layered defense** â€” Sentinel is ONE layer alongside Defender, not a replacement
6. **Honest documentation** â€” State what works and what doesn't
7. **Kill only on corroboration** â€” New monitors are Tier2 (corroborating signals). Only the President's Law closed list authorizes kills. Multiple Tier2 signals correlating on the same PID produce composite kills via the BehavioralCorrelationEngine. Single signals never kill independently (except self-protection).
8. **Make kills hurt** (v1.7.0) â€” Every authorized kill should cost the attacker time, data integrity, and operational security. Deception tactics execute pre-kill to maximize damage to attacker operations.

---

## Deception Threat Analysis (v1.7.0)

### What deception CAN achieve against skilled attackers

| Tactic | Effectiveness vs Commodity | Effectiveness vs Targeted | Notes |
|--------|---------------------------|--------------------------|-------|
| Memory Flooding | HIGH | MEDIUM | Commodity tools rarely handle polluted dumps; targeted attackers may detect allocation patterns |
| DLL Stomping | HIGH | MEDIUM | Persistence-based implants will crash; targeted attackers may verify integrity before restart |
| Stack Corruption | HIGH | MEDIUM | C2 crash reports polluted; targeted attackers may not rely on crash telemetry |
| Beacon Flooding | MEDIUM | LOW | Floods create noise but sophisticated C2 frameworks may fingerprint legitimate vs fake beacons |
| Protocol Confusion | MEDIUM | LOW | Triggers parser bugs in many frameworks; hardened C2 servers may handle gracefully |
| Clipboard Poisoning | HIGH | MEDIUM | Infostealers blindly exfil; targeted attackers may validate stolen data before use |
| Sparse File Bombs | HIGH | LOW | Automated tools choke; targeted attackers check file sizes vs disk usage |
| Symlink Loops | HIGH | LOW | Recursive tools crash; targeted attackers limit recursion depth |
| Polyglot Files | HIGH | MEDIUM | Automated parsers crash on entity expansion/XXE; targeted attackers may sandbox analysis |
| Corrupted Archives | HIGH | LOW | Passes initial checks but fails extraction; targeted attackers verify checksums |
| Environment Poisoning | MEDIUM | MEDIUM | Breaks reconnection for most frameworks; targeted attackers may restore from backup config |
| Honeypot Weaponization | HIGH | MEDIUM | Infostealers exfil everything; targeted attackers may recognize honeypot patterns |
| Network Honeypots | HIGH | MEDIUM | Lateral movement tools find fake services; targeted attackers may fingerprint honeypot responses |

### Deception bypass scenarios

**B9: Attacker detects deception and adapts**

The attacker reads this source code and knows deception tactics will execute pre-kill. They may:
- Implement anti-deception checks (detect VirtualAllocEx from Sentinel's PID)
- Use direct syscalls to avoid memory flooding detection
- Validate exfiltrated data before sending to C2

**Residual risk:** LOW. By the time deception executes, the kill is already authorized. Even if the attacker detects deception, they have <2 seconds before termination. The deception is a bonus, not a dependency.

**B10: Attacker uses deception artifacts against the user**

The attacker could theoretically:
- Use the poisoned proxy settings to deny the user internet access
- Use the fake credentials to frame the user

**Mitigation:** All deception actions are logged with full detail. Proxy/TLS poisoning is HKCU-scoped and easily reversed. Fake credential files are clearly named (.bak, backup) and placed in non-standard locations.

**Residual risk:** LOW. The user's legitimate applications are unaffected (they don't read .bak files or backup SSH keys). Proxy poisoning may briefly affect the user's browser until reverted â€” acceptable tradeoff for breaking C2 reconnection.

---

## Deception Threat Analysis (v2.8.0 Updates)

### B11: Deception time budget delays critical ransomware containment
**Attack:** Ransomware encrypts files at a high rate. If the EDR delays termination by executing a 2-second pre-kill deception window, more files will be encrypted.
**Mitigation:** The EDR implements a Ransomware Response Fast-Path. Detections matching "ransomware" in their rule name or reasoning bypass the `DeceptionEngine` completely and proceed immediately to process termination, achieving near-zero latency.
**Residual risk:** LOW. Bypassing deception is the safest approach for high-speed destructive threats like ransomware.

### B12: Querying thread context causes target process crash or EDR instability
**Attack:** If thread contexts are queried on x64 without proper structure alignment and thread suspension, it triggers native access violations or stack corruption, potentially causing the EDR process or target system components to crash.
**Mitigation:** Replaced the unaligned byte-array CONTEXT layout with a fully aligned, 16-byte packed native struct representation of x64 CONTEXT. Target threads are explicitly suspended via `SuspendThread` before context retrieval and resumed via `ResumeThread` immediately after, ensuring safe, stable stack corruption.
**Residual risk:** LOW. Safe thread state manipulation prevents process corruption.

### B13: Off-host or network deception delays process termination
**Attack:** Network-based deception tactics (e.g., BeaconFlooder, NetworkHoneypotDeployer) wait on sockets or remote connections, which easily exhausts the 2-second pre-kill budget and delays target process termination.
**Mitigation:** All network-based and lateral movement deception tactics are executed asynchronously in the background. They run as fire-and-forget background tasks (`Task.Run`), allowing the pre-kill pipeline to immediately proceed with process termination without blocking.
**Residual risk:** LOW. Network latency cannot affect containment times.

## Threat Analysis Updates (v2.8.1 Hardening & Bug Fixes)

### B14: Quarantine filename parsing vulnerability
**Attack:** An attacker could craft a file path containing multiple dashes or special characters, causing the four-part split parsing schema in `QuarantineManager` to crash or map metadata incorrectly, potentially leading to directory traversal or signature bypasses.
**Mitigation:** Refactored the parsing routine in `QuarantineManager.cs` to leverage regex-like split boundaries, verifying array length matches expectations, and falling back gracefully without throwing exceptions.
**Residual risk:** LOW. Files are safely encrypted prior to parsing.

### B15: File handle leak in process and hook monitoring
**Attack:** Querying active processes inside a high-frequency polling loop can exhaust system handle limits if process handles are not closed, resulting in service denial of service or instability.
**Mitigation:** Wrapped process queries in `using` statements, and ensured that all obtained native process handles are closed/disposed properly in `HardeningModule.cs`.
**Residual risk:** LOW. Memory and handle usage remain flat.

### B16: NTP time-drift or clock manipulation bypasses cache validity
**Attack:** An attacker who poisons the reputation cache might trigger NTP synchronization or local clock manipulation to trick `SecureCacheStore` into accepting older caches or validating compromised reputation lists.
**Mitigation:** Replaced the subtractive boot time extraction (using TickCount64) with direct querying of the System process (PID 4) start time via `Process.GetProcessById(4).StartTime`, establishing a tamper-resistant boot session anchor.
**Residual risk:** LOW. Safe fallback to local clock remains in place.

---

### B17: DLL sideloading/hijacking of Sentinel itself
**Attack:** Attacker drops a malicious DLL into Sentinel's installation directory to hijack the Service or Agent when launched.
**Mitigation (v5.5.0):**
- **DLL Search Hardening:** Call `HardeningModule.ApplyOrFail()` at the absolute start of both the Service and Agent processes to restrict dynamic DLL loading solely to `%SystemRoot%\System32`.
- **NTFS ACL Lockdown:** Enforces strict NTFS permissions on Sentinel's installation folder to deny modify access to standard users and restrict write access to `SYSTEM` and `Administrators`.
- **Sentinel Directory Watcher:** Recurse-watches the Sentinel folder. If any unauthorized process attempts to write or drop files, Sentinel immediately deletes the file, flags a Tier 1 event, and terminates the writer.
**Residual risk:** LOW. Standard users cannot write to the folder, and any attempt by other processes to tamper with it is immediately contained.

---

### B18: Evading EDR via dbghelp.dll sideloading / crashing target application
**Attack:** Attacker drops a malicious `dbghelp.dll` in the target application's directory to hijack execution or dump LSASS memory, causing target application crashes when the EDR terminates it.
**Mitigation (v5.5.0):**
- **Pre-emptive DLL Deletion:** Intercepts writes of critical system DLLs (`dbghelp.dll`/`dbgcore.dll`) in non-system paths.
- **Trusted Writer Verification:** If the writing process is untrusted, Sentinel immediately deletes the file and terminates the writer process.
- **Containment without Crashing:** Since the malicious DLL is deleted before the target application is executed, the target application runs cleanly by falling back to the system's DLL in `System32` (no crash or hijack).
**Residual risk:** LOW. Untrusted droppers are blocked, and target applications remain uncompromised and operational.


