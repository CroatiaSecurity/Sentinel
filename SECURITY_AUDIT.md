# Sentinel v1.8.0 — Red Team / Blue Team Security Audit

**Date:** 2026-07-30  
**Scope:** Full source code review of Sentinel.Core, Sentinel.Service, Sentinel.Agent, installer, build pipeline, and configuration.  
**Methodology:** Manual code audit with adversarial (red team) and defensive (blue team) perspective.

### Remediation status (v1.8.1 — 2026-07-30)

Independent red-team re-audit added RT-NEW-* findings (see CHANGELOG). Status:

| Finding | Status |
|---------|--------|
| RT-CRIT-1 Cleartext `X-Sentinel-Auth` | **Fixed** |
| RT-CRIT-2 Reflection without allowlist | **Fixed** |
| RT-CRIT-3 MachineGuid + entropy key KD | **Mitigated (v2.0)** — DPAPI LocalMachine `.machine_secret.dpapi` + hmac-v3 |
| RT-HIGH-1 Rules reload TOCTOU sleep | **Mitigated** |
| RT-HIGH-2 Hardlink self-exclusion | **Mitigated (v2.0)** — `SelfPathGuard` final-path + known binary names |
| RT-HIGH-3 Installer ACL reset window | Open |
| RT-HIGH-4 No Service↔Agent IPC auth | **Mitigated (v2.0)** — HMAC named pipe `SentinelIpc-v2` + `.ipc_token` |
| RT-MED-1 Unbounded telemetry channel | **Fixed** |
| RT-MED-2 Thread.Sleep in rules watcher | **Fixed** |
| RT-MED-3 Diagnostic writes before ACL | **Fixed** |
| RT-MED-4 Signer pin on allowlist | Open |
| RT-MED-5 secedit shell-out | Open (intentional) |
| RT-MED-6 No cert pinning on TI APIs | Open |
| RT-LOW-1 Unbounded kill budget queues | **Fixed** |
| RT-LOW-2 Installer-name demotion evasion | **Fixed** |
| RT-LOW-3 Quarantine restore auth | Accepted + harden restore path |
| **RT-NEW-1** BYOVD empty-CN mass driver wipe | **Fixed** — thumbprint-only, no System32 delete |
| **RT-NEW-2** Consultant→Critical kill re-escalation | **Fixed** — sticky LogOnly |
| **RT-NEW-3** NetworkIsolate private IPs | **Fixed** |
| **RT-NEW-4** Quarantine world-readable ACL | **Fixed** |
| **RT-NEW-5** Unbounded quarantine file size | **Fixed** — 128 MB cap |
| **RT-NEW-7** Rule HMAC non-constant-time | **Fixed** |
| **RT-NEW-8** RestoreAsync path writes | **Fixed** (guards) |

---

## Executive Summary

Sentinel is a well-hardened userland EDR with defense-in-depth at multiple layers. The codebase shows evidence of iterative security improvements (v1.1.0 through v1.8.0) addressing real red-team findings. The architecture is sound: SYSTEM-session service for privileged detection, user-session agent for UI-layer monitoring, DPAPI-encrypted storage, HMAC-signed dynamic rules, and behavioral detection with strict tier enforcement.

**Overall Posture: Strong** — with specific areas for improvement documented below.

---

## RED TEAM FINDINGS

### CRITICAL (Exploitable with standard user or admin access)

#### RT-CRIT-1: ProxySharedSecret Transmitted in Cleartext Header

**File:** `ProxyAuthHelper.cs` line 44  
**Issue:** The `X-Sentinel-Auth` header sends `config.ProxySharedSecret` as a raw plaintext value alongside the HMAC signature. This is redundant (the HMAC already authenticates the request) and exposes the shared secret to any network observer, proxy, or CDN log between Sentinel and the Cloudflare Worker.

**Impact:** An attacker with network visibility (corporate proxy, ISP, Cloudflare dashboard access) can extract the shared secret and forge threat intelligence reports, potentially poisoning community threat databases or causing denial-of-service against the reporting proxy.

**Recommendation:** Remove the `X-Sentinel-Auth` header entirely. The HMAC signature + timestamp is sufficient authentication. If the Worker needs a dual check, use a derived token (HMAC of the secret) rather than the raw secret.

---

#### RT-CRIT-2: DynamicRulesEvaluator Uses Reflection for Condition Evaluation

**File:** `DynamicRulesEvaluator.cs`, `DynamicCondition.Evaluate()`  
**Issue:** The `Evaluate()` method uses `GetProperty()` with `BindingFlags.IgnoreCase` to resolve arbitrary field names from JSON rule files against telemetry objects. While rules require HMAC signatures, if an attacker achieves SYSTEM access (needed to sign rules), they could craft rules that inspect internal .NET properties for information disclosure, or exploit complex property getters with side effects.

**Impact:** Medium — requires SYSTEM access to sign a rule, at which point the attacker already has full control. However, the reflection path has no property name allowlist, meaning it could theoretically access properties not intended for rule evaluation.

**Recommendation:** Add a whitelist of allowed property names per telemetry type. Restrict reflection to only the documented telemetry model properties.

---

#### RT-CRIT-3: HMAC Key Derivation Weakness — MachineGuid is Standard-User Readable

**File:** `SecureCacheStore.cs`, `GenerateBootBoundKey()`  
**Issue:** The HMAC key is derived from `SHA256(MachineGuid + InstallEntropy + label)`. While the install entropy file is ACL-locked to SYSTEM, `MachineGuid` is readable by all users at `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`. If the entropy file ACL is ever weakened (e.g., by a backup tool, takeown during troubleshooting, or installer ACL reset), the full key becomes reconstructible.

**Impact:** If an attacker obtains the entropy file content (requires SYSTEM or ACL misconfiguration), they can forge cache entries, allowlist entries, and reputation verdicts.

**Recommendation:** Consider adding a third derivation component that is SYSTEM-only (e.g., LSA secret, or a value stored in the SYSTEM registry hive under a key only accessible to SYSTEM). This provides defense-in-depth if the entropy file ACL is weakened.

---

### HIGH (Exploitable with elevated admin access)

#### RT-HIGH-1: Race Condition in DynamicRulesEvaluator File Loading

**File:** `DynamicRulesEvaluator.cs`, `OnRulesChanged()`  
**Issue:** The `OnRulesChanged` handler sleeps 100ms then calls `LoadRules()`. An attacker with write access to the rules directory could:
1. Drop a legitimate signed rule file (triggers watcher)
2. During the 100ms sleep, replace it with a modified version

The HMAC check mitigates this significantly (attacker needs SYSTEM to sign), but the TOCTOU window exists between the FileSystemWatcher event and the actual file read.

**Impact:** Low-medium — attacker needs SYSTEM access to forge signatures anyway. The race condition is a theoretical concern.

**Recommendation:** Read the file content atomically (single read), compute HMAC on the bytes read, and only parse JSON from those same bytes. Currently this is effectively what happens, but the debounce sleep introduces unnecessary window.

---

#### RT-HIGH-2: Self-Exclusion Path Bypass via Hardlinks/Junctions

**File:** `AdvancedResponseEngine.cs`, self-exclusion check  
**Issue:** The self-exclusion check uses `Path.GetFullPath()` to normalize and compares against `AppContext.BaseDirectory`. While this handles symlinks and `../` segments, Windows hardlinks (`mklink /H`) create a second name for the same file that resolves to a different path via `GetFullPath()`. An attacker could:
1. Create a hardlink to a malicious binary in Sentinel's install directory
2. The malicious binary (now appearing to be "in" the install dir) would be self-excluded from response

**Mitigation:** Requires admin/SYSTEM access to create hardlinks in Program Files (which is ACL-locked by `HardeningModule.SecureInstallationDirectory()`), significantly reducing exploitability.

**Recommendation:** Additionally verify that the file's volume serial + file index matches known Sentinel binaries (a compile-time embedded hash, or a baseline established at install time).

---

#### RT-HIGH-3: Installer ACL Reset Window During Upgrade

**File:** `setup.iss`, `ResetInstallDirAcls()`  
**Issue:** During upgrade, the installer resets ACLs on the install directory (`takeown /A`, then `icacls /grant Administrators:F`), briefly granting Administrators full control before the new binary is deployed. If an attacker with admin access (but not SYSTEM) times a file drop during this window, they could replace the Service binary with a trojanized version before it's launched.

**Impact:** Medium — requires admin access and precise timing during upgrade. The HardeningModule will re-lock ACLs on next service start.

**Recommendation:** Minimize the ACL reset window by performing the ACL unlock only on specific files being replaced (not the entire directory tree). Consider using atomic file replacement (rename to .bak → deploy new → lock) rather than broad ACL manipulation.

---

#### RT-HIGH-4: No IPC Authentication Between Service and Agent

**Issue:** The design document mentions a two-process architecture (Service as SYSTEM, Agent as user-session) with `AgentWatchdog` monitoring agent liveness. However, there is no visible authenticated IPC channel between the two processes. The Agent runs its own detection engine independently with its own rules.

**Impact:** A rogue process could impersonate the Agent (if the watchdog can be evaded) or inject false telemetry. Since the Agent doesn't send commands to the Service (only observes), this is limited to user-session attacks.

**Recommendation:** Consider implementing a named pipe with SYSTEM-only server-side ACL for Service→Agent communication, authenticated with the installation entropy. This would allow the Service to push verified detections to the Agent UI and verify the Agent's identity.

---

### MEDIUM

#### RT-MED-1: Unbounded Channel in DetectionEngine

**File:** `DetectionEngine.cs`  
**Issue:** `Channel.CreateUnbounded<FusedTelemetryContext>()` is used for the telemetry queue. Under sustained attack (thousands of process starts per second), this could lead to memory exhaustion.

**Recommendation:** Use `Channel.CreateBounded<>` with a capacity limit and `BoundedChannelFullMode.DropOldest` to prevent OOM.

---

#### RT-MED-2: Thread.Sleep in DynamicRulesEvaluator (Constraint Violation)

**File:** `DynamicRulesEvaluator.cs` line in `OnRulesChanged`  
**Issue:** `System.Threading.Thread.Sleep(100)` is used without cancellation token, violating the project's own constraint ("No Thread.Sleep without cancellation"). This blocks a thread pool thread.

**Recommendation:** Replace with `await Task.Delay(100, cancellationToken)` and make the handler async-aware.

---

#### RT-MED-3: Startup Diagnostic Trace Writes to World-Readable Location

**File:** `Sentinel.Service/Program.cs`  
**Issue:** The service writes `startup_trace.log` and `fatal_crash.log` to `%ProgramData%\Sentinel\` at process start, before the logger's ACLs are applied. If the directory doesn't exist yet, it may be created with inherited default ACLs, making these diagnostic files readable (potentially writable) by standard users.

**Impact:** Information disclosure of service startup state, version, and error messages to unprivileged users.

**Recommendation:** Either write diagnostics to the Windows Event Log (which respects ACLs), or ensure the directory is created with restricted ACLs before any writes.

---

#### RT-MED-4: AllowlistService Requires Signature for Suppression — Good but Bypassable via SignerTrust

**File:** `AllowlistService.cs`  
**Issue:** The `IsUserAllowlisted()` method requires both a path match AND a valid Authenticode signature. However, if an attacker can sign their malware with a valid code-signing certificate (purchased, stolen, or from a compromised CA), the binary would pass the signature check and be suppressible via allowlist manipulation.

**Mitigation:** The allowlist itself is stored in `SecureCacheStore` (DPAPI-encrypted), making manipulation difficult.

**Recommendation:** Consider pinning allowed signers (not just "any valid signature") in the allowlist entries.

---

#### RT-MED-5: AntiTamperGuard secedit Shell-Out

**File:** `AntiTamperGuard.cs`, `ApplyFipsSecurityDatabaseOverride()`  
**Issue:** This method uses `Process.Start("secedit.exe", ...)`. While the arguments are hardcoded (not user-controllable), this creates a `secedit.exe` child process that could be observed by attackers for timing, and the temp file (`fips_off.inf`) exists briefly on disk.

**Recommendation:** Document this as an intentional exception to the "no shelling out" constraint (it's noted in `design.md` as "only remaining intentional shell-out"). Consider writing directly to the security database via API if possible.

---

#### RT-MED-6: No Certificate Pinning on Threat Intel API Endpoints

**File:** `HashReputationService.cs`  
**Issue:** HTTPS connections to `hashlookup.circl.lu` and `mb-api.abuse.ch` use default TLS validation. A sophisticated attacker with a position to MITM (compromised root CA in the machine store, or corporate proxy) could intercept and forge responses, marking malware as "safe" via CIRCL trust scores.

**Recommendation:** Consider certificate pinning for critical threat intel endpoints, or use the proxy endpoint exclusively (which you control) with the HMAC authentication.

---

### LOW

#### RT-LOW-1: Rate Limiter Uses ConcurrentQueue Without Bounded Size

**File:** `AdvancedResponseEngine.cs`, kill/isolate budget tracking  
**Issue:** `ConcurrentQueue<long>` for timestamps grows unbounded within the 60s window. Under pathological conditions (millions of kills attempted per second — unlikely but possible in a DoS), this could consume memory.

**Recommendation:** Cap queue size at `MaxKillsPerMinute * 2` with overflow eviction.

---

#### RT-LOW-2: InstallerHeuristics Path in Detection Demotion

**File:** `DetectionEngine.cs`  
**Issue:** `InstallerHeuristics.LooksLikeInstallerName()` is used to demote HighRisk verdicts to Tier2/LogOnly. An attacker who names their binary to match installer patterns (e.g., `ChromeSetup_v123.exe`) in a user-writable path could exploit this for evasion.

**Mitigation:** The demotion only fires when there's no positive malicious confirmation from APIs. If MalwareBazaar or VirusTotal flag it, it stays Tier1.

**Recommendation:** Consider adding path constraints (only demote if in a known download/installer path, not in AppData\Roaming or Temp).

---

#### RT-LOW-3: Quarantine Restore Has No Authentication

**File:** `QuarantineManager.cs`, `RestoreAsync()`  
**Issue:** The `RestoreAsync` method decrypts and writes a quarantined file to the destination path. While the quarantine directory is ACL-locked to SYSTEM, if an attacker gains SYSTEM access, they could restore malware from quarantine.

**Mitigation:** Attacker with SYSTEM access already has full control — this is a non-issue in practice.

---

---

## BLUE TEAM ASSESSMENT (Defensive Strengths)

### BT-STRONG-1: Tiered Detection Architecture (Excellent)

The strict Tier1/Tier2 separation with hardcoded tier enforcement in `AdvancedResponseEngine` is a textbook-correct design. Tier2 can **never** trigger action regardless of configuration. This prevents escalation of noisy indicators into destructive responses.

---

### BT-STRONG-2: DPAPI + HMAC Layered Cache Security (Excellent)

The `SecureCacheStore` uses machine-scope DPAPI (binds ciphertext to the host) with an HMAC integrity layer derived from installation-specific entropy. This is significantly stronger than most EDR cache implementations. The fail-closed behavior (HMAC mismatch → delete cache file) prevents tampering-for-effect.

---

### BT-STRONG-3: Constant-Time HMAC Comparison (Correct)

`SecurityValidation.SecureCompare()` uses `[MethodImpl(NoOptimization | NoInlining)]` with XOR accumulation — correct implementation preventing timing side-channels on signature verification.

---

### BT-STRONG-4: Dynamic Rules Require SYSTEM-Signed HMAC (Excellent)

The `DynamicRulesEvaluator` requires rules to be HMAC-signed with the installation entropy (SYSTEM-only readable). This means even a local administrator cannot inject malicious detection rules without first escalating to SYSTEM. The fail-closed behavior (v1.5.9: rules rejected if entropy is missing) prevents entropy-deletion attacks.

---

### BT-STRONG-5: Self-Exclusion is Path-Verified, Not Name-Based (Good)

The response engine's self-exclusion resolves the actual process image path via `QueryFullProcessImageName` (minimum-privilege handle) and compares against the normalized install directory with trailing separator. This prevents name-based spoofing attacks documented in v1.1.0.

---

### BT-STRONG-6: Kill Rate Limiting (Defense-in-Depth)

The `MaxKillsPerMinute` (15) and `MaxNetworkIsolatesPerMinute` (10) budgets prevent an attacker from weaponizing false positives to DoS the user's system. Budget exhaustion generates its own Tier1 alert, creating visibility into the attack.

---

### BT-STRONG-7: Anti-Suspend Detection via QPC (Hardware-Monotonic)

The `AntiTamperGuard` uses both `DateTimeOffset` and `QueryPerformanceCounter` (hardware-driven, immune to `SetSystemTime` manipulation) to detect NtSuspendProcess attacks. Takes the larger of both values, preventing clock manipulation evasion.

---

### BT-STRONG-8: Authenticode Verification with Catalog Fallback (Comprehensive)

`SecurityValidation.VerifyAuthenticodeSignature()` handles both embedded Authenticode and Windows Catalog Store signatures via native P/Invoke (no PowerShell dependency). The WinVerifyTrust state is properly closed to prevent memory leaks. This correctly identifies catalog-signed system binaries (explorer.exe, powershell.exe) that lack embedded signatures.

---

### BT-STRONG-9: No LOLBin Dependencies in Response Actions (Excellent)

Response actions use native APIs: SCM P/Invoke for service management, COM `HNetCfg.FwPolicy2` for firewall rules, `DnsFlushResolverCache` for DNS flush. No `cmd.exe`, `powershell.exe`, or `netsh.exe` in the hot path. This eliminates LOLBin detection by other security tools and prevents PATH poisoning attacks.

---

### BT-STRONG-10: OS-Critical Path Protection (Correct)

`SecurityValidation.IsOsCriticalPath()` prevents quarantining of WRP-protected files (System32, Windows directory minus Temp). The v1.6.3 fix documents a real incident where powershell.exe was quarantined. `QuarantineManager` enforces this unconditionally, even with `forceQuarantineSigned`.

---

### BT-STRONG-11: Behavioral-Only Kill Authority (Sound Philosophy)

The "President's Law" closed list ensures only confirmed behavioral detections (what a process DOES, not what it IS) can trigger process termination. This is documented, version-controlled, and requires explicit sign-off to modify. Prevents static-signal kill escalation.

---

### BT-STRONG-12: Installer Preserves User Configuration

`appsettings.json` uses `Flags: onlyifdoesntexist` in the Inno Setup script, preventing upgrades from overwriting user customizations. This is both a usability and security feature (prevents config regression to less-secure defaults).

---

### BT-STRONG-13: ActiveResponse Enforcement at Boot (Anti-Downgrade)

`AntiTamperGuard.EnforceActiveResponseAtStartup()` detects and force-re-enables ActiveResponse if it was disabled via config file editing between reboots. The runtime monitoring also catches live transitions from true→false. This closes the "edit config → reboot → operate while Sentinel is neutered" attack path.

---

### BT-STRONG-14: Safe Mode Service Registration

The installer registers Sentinel in both `SafeBoot\Minimal` and `SafeBoot\Network` registry keys, ensuring the service runs even in Safe Mode — closing the "boot to Safe Mode to evade EDR" attack vector.

---

### BT-STRONG-15: IDE/Development Tool Protection (False-Positive Mitigation)

`ChainTracer.IsLegitimateIdeHost()` prevents killing IDE processes (VS Code, Rider, Visual Studio) for non-President's-Law detections. This requires both name match AND legitimate install path verification, preventing abuse via renamed binaries in user-writable paths.

---

---

## RECOMMENDATIONS SUMMARY

| Priority | Finding | Action |
|----------|---------|--------|
| Critical | RT-CRIT-1: Shared secret in cleartext header | Remove `X-Sentinel-Auth` header |
| High | RT-HIGH-4: No IPC auth between Service/Agent | Implement authenticated named pipe |
| High | RT-HIGH-3: Installer ACL reset window | Minimize to per-file, atomic replacement |
| Medium | RT-MED-1: Unbounded telemetry channel | Switch to bounded channel |
| Medium | RT-MED-2: Thread.Sleep constraint violation | Replace with cancellable delay |
| Medium | RT-MED-3: Diagnostic writes before ACL | Use Event Log or pre-create secured dir |
| Medium | RT-MED-6: No cert pinning on threat intel | Pin critical endpoints or use proxy only |
| Low | RT-CRIT-2: Reflection without property allowlist | Add property name whitelist |
| Low | RT-LOW-2: Installer name demotion evasion | Add path constraints to heuristic |

---

## ATTACK SCENARIOS (Red Team Playbook)

### Scenario 1: Disable-and-Operate (Standard User)

1. **Goal:** Operate malware while Sentinel is running
2. **Approach:** Sentinel runs as SYSTEM — standard user cannot kill it
3. **Evasion options:**
   - Name binary to match installer heuristics → demoted to Tier2 (log only) IF no positive malicious signal from APIs
   - Use unsigned binary from a non-staging path with no API hits → Suspicious (Tier2, LogOnly)
   - Avoid behavioral triggers (no LSASS access, no shadow copy deletion, no encoded PowerShell)
4. **Detection gaps:** A novel, behavior-conservative implant that only does DNS-based C2 at intervals above the beaconing CV threshold (>0.40) could evade statistical detection
5. **Mitigation:** The BehavioralCorrelationEngine's composite detections catch multi-signal combinations. The BeaconingDetector's 0.40 CV threshold is documented — an attacker reading source could tune beacon jitter to evade.

### Scenario 2: Tamper-and-Disable (Admin Access)

1. **Goal:** Disable Sentinel's response capabilities
2. **Approach:**
   - Edit `appsettings.json` to set `ActiveResponse: false` → **Detected + force-re-enabled** by AntiTamperGuard
   - Delete `.install_entropy` → Dynamic rules fail-closed (rejected), cache HMAC fails → caches purged. But core detection is unaffected
   - Modify `Sentinel.Service.exe` on disk → Detected by binary integrity check (file deleted alert). But attacker can't replace while running (locked).
   - Set service StartType to Disabled → **Detected + force-reverted** by AntiTamperGuard
   - `NtSuspendProcess` on Sentinel → **Detected in <4s** via QPC timing
3. **Remaining option:** Kill via Task Manager (admin can terminate) → Service restart failure actions (1s/5s/30s) and AgentWatchdog (10s) will relaunch
4. **Nuclear option:** Boot to Safe Mode → Mitigated by Safe Mode registration

### Scenario 3: Supply Chain (Compromise Build Machine)

1. **Goal:** Inject malicious code into published binaries
2. **Risk factors:**
   - Build script (`build.ps1`) does not verify dotnet SDK integrity
   - No binary signing (installer and executables are unsigned)
   - No reproducible builds mechanism
   - No SBOM or dependency pinning beyond NuGet lock files
3. **Mitigation:** Single-developer project, local build only. Risk is proportional to the threat model (personal use, not enterprise deployment).

---

## ARCHITECTURAL OBSERVATIONS

### What's Done Right

1. **Separation of privilege** — SYSTEM service for detection, user-session for UI
2. **Defense-in-depth** — Multiple independent monitors, any one can fail without affecting others
3. **Fail-closed everywhere** — API failures → Unknown (never Safe), missing entropy → rules rejected, HMAC mismatch → cache deleted
4. **No security through obscurity** — Design docs state "assumes attacker has read the source code"
5. **Rate limiting on destructive actions** — Prevents weaponization of false positives
6. **Comprehensive self-protection** — Binary integrity, service registration, timing, config monitoring, QoS throttling detection, WFP filter detection, ETW session monitoring

### Areas for Future Hardening

1. **Code signing** — Both the installer and binaries are unsigned. Authenticode signing would prevent binary replacement attacks and improve trust signals for AV compatibility.
2. **Secure boot of trust chain** — The entropy file is the root of trust. Consider sealing it with TPM (if available) for hardware-bound key derivation.
3. **Authenticated IPC** — The Service and Agent operate independently. A cryptographically authenticated channel would prevent agent impersonation.
4. **Telemetry channel bounds** — Replace unbounded channels with bounded alternatives to prevent memory exhaustion under adversarial load.
5. **Build pipeline security** — Add binary signing, dependency hash verification, and reproducible build documentation.

---

## CONCLUSION

Sentinel demonstrates a mature security architecture with iterative hardening across 18+ versions. The code shows awareness of common EDR evasion techniques (PPID spoofing, ETW patching, AMSI bypass, process hollowing, LSASS dumping) and implements countermeasures for each.

The most impactful finding is RT-CRIT-1 (shared secret in cleartext header), which is a straightforward fix. The remaining findings are either defense-in-depth improvements or require elevated access that largely moots the attack (if you have SYSTEM, you already won).

The defensive posture (Blue Team assessment) is strong across 15 documented areas, with particularly notable implementations in cache security, behavioral-only kill authority, anti-suspend detection, and LOLBin-free response actions.

**Risk Rating:** Low residual risk for the documented threat model (personal system defense against remote attackers without kernel access).
