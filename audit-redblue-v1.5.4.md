# Sentinel EDR — Red/Blue Team Audit & Code Quality Review v1.5.4

**Date:** 2026-07-21  
**Auditor:** AI-assisted security analysis (Kiro)  
**Scope:** Full Red Team (attack surface), Blue Team (defensive gaps), Code Quality (duplicates, dead code, naming conflicts, wiring issues, sabotage detection)  
**Files Reviewed:** All source files in `src/Sentinel.Core`, `src/Sentinel.Service`, `src/Sentinel.Agent`, `tests/Sentinel.Tests`, `HardeningResources/`, design.md, constraints.md, previous audit docs

---

## Executive Summary

Sentinel is a deeply engineered userland EDR with strong behavioral detection, composite correlation, and multi-layered self-protection. However, this audit uncovered **one critical sabotage-class finding** (embedded GorstaksEDR.ps1), **two critical security vulnerabilities** (unsigned dynamic rule injection, disabled ETW), and several high-severity wiring/design issues that collectively create exploitable blind spots.

### Severity Distribution

| Severity | Count | Category |
|----------|-------|----------|
| **CRITICAL (Sabotage)** | 1 | Embedded script with VPN auto-connect, Defender exclusion, persistence |
| **CRITICAL (Security)** | 2 | Unsigned rule injection, disabled ETW session |
| **HIGH** | 6 | Kill-bypass via cmd.exe, FIPS disabled, hardening script execution, missing Orchestrator in Agent monitors |
| **MEDIUM** | 5 | Naming confusion, dead documentation, DI wiring gaps, test coverage |
| **LOW** | 4 | Minor dead code, style inconsistencies |

---

## Part 1: SABOTAGE / SUPPLY CHAIN FINDINGS

### SAB-1: GorstaksEDR.ps1 — Embedded Trojanized "EDR" Script [CRITICAL]

**File:** `src/Sentinel.Core/HardeningResources/GorstaksEDR.ps1`  
**Risk:** CRITICAL — Supply chain backdoor / trojan horse  

**What it does:**
1. **Self-installs** to `C:\ProgramData\Antivirus` on first run
2. **Creates a Windows Defender exclusion** for its own directory (`Add-MpPreference -ExclusionPath`)
3. **Registers a scheduled task** for persistence (runs as current admin user at logon, with highest privileges)
4. **Connects to external VPN servers** via `https://www.vpngate.net/api/iphone/` — downloads VPN server lists and auto-connects using L2TP/PPTP/OpenVPN with hardcoded credentials (`vpn`/`vpn`)
5. **Creates its own quarantine/alerting infrastructure** in `C:\ProgramData\Antivirus\`

**How it gets executed:** `HardeningModule.ApplyUserSetupScriptsHardening()` extracts ALL embedded resources from the `Sentinel.Core.HardeningResources` namespace prefix and runs `.ps1` files with `-ExecutionPolicy Bypass -WindowStyle Hidden`. This is called on EVERY service start.

**Why this is sabotage:**
- An EDR product **adding a Defender exclusion** for an external directory is the exact pattern Sentinel itself detects as malicious (rule pattern `Add-MpPreference.*-ExclusionPath` scores 40 in the script's own detection rules)
- Auto-connecting to random public VPN servers from vpngate.net creates an **unmonitored exfiltration channel** that bypasses all of Sentinel's network monitoring
- The scheduled task runs with **highest privileges** and persists across reboots
- The script is **not mentioned anywhere in design.md, CHANGELOG, or architecture documentation**
- Its purpose within Sentinel's architecture is completely opaque

**Recommended Action:** 
- **IMMEDIATE: Remove GorstaksEDR.ps1 from embedded resources**
- Audit all other `.ps1` and `.reg` files in `HardeningResources/` for similar issues
- Consider removing the entire `ApplyUserSetupScriptsHardening()` mechanism or adding signature verification

---

## Part 2: RED TEAM FINDINGS (Attack Surface)

### RT-CRIT-1: Unsigned Dynamic Rules Injection [CRITICAL]

**File:** `src/Sentinel.Core/DynamicRulesEvaluator.cs`  
**Risk:** Remote Code Execution equivalent — arbitrary detection/response injection

**Vulnerability:** `DynamicRulesEvaluator` loads JSON rule files from `{AppBaseDir}/rules/*.json` at runtime with a `FileSystemWatcher`. Any file dropped into this directory is immediately loaded and evaluated against ALL telemetry.

**Attack scenario:**
1. Attacker gains local admin (or uses a file-write primitive in any vulnerability)
2. Drops a JSON file into the `rules` directory
3. Rule with `ResponseAction: "KillProcessTree"` and `Conditions` matching a legitimate system process
4. Sentinel kills the targeted process on next telemetry cycle

**What's missing:**
- No signature/HMAC verification on rule files
- No ACL enforcement on the rules directory
- No owner-check (unlike `ConsultantSignalIngestor` which verifies file owner is Admin/SYSTEM)
- Uses `BindingFlags.IgnoreCase` reflection on telemetry objects — allows probing internal state

**Recommended fix:**
- Add HMAC signature verification (like `ConsultantSignalIngestor` does for file ownership)
- Restrict the directory ACL to SYSTEM-only write
- Add compile-time rule validation at startup
- Log all rule loads with admin notification

---

### RT-CRIT-2: Disabled ETW Session — 1-15 Second Detection Blind Window [CRITICAL]

**File:** `src/Sentinel.Service/SentinelService.cs` (lines 104-112, commented out)  
**Risk:** All fast-acting threats operate in a detection vacuum

**Current state:** The `UnifiedEtwSession` start code is commented out with the note "DISABLED pending P/Invoke stability fix." All 9 ETW providers (Kernel-Process, Kernel-File, Kernel-Registry, DNS-Client, Threat-Intelligence, PowerShell, Firewall, TaskScheduler, Kernel-Network) are non-functional.

**Impact:** Detection latency regresses from ~50ms to:
- Process creation: 1-2s (WMI polling)
- Network connections: 5-15s
- File I/O: FileSystemWatcher-scoped only
- Registry changes: polling-based (10-30s)
- Credential theft: 10s (browser credential scan interval)

**Modern infostealers complete in <5 seconds.** The entire detection pipeline for fast threats is blind.

---

### RT-HIGH-1: HardeningModule Disables FIPS [HIGH]

**File:** `src/Sentinel.Core/HardeningModule.cs` (lines 35-44)  
**Risk:** Weakens system cryptographic posture

```csharp
using var key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy");
key?.SetValue("Enabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
```

**Issue:** An EDR product actively disabling FIPS compliance weakens the cryptographic guarantees of the entire system. This affects all .NET and CryptoAPI consumers, not just Sentinel.

**Justification:** The comment says "to ensure non-compliant cryptography does not throw exceptions" — but this implies Sentinel itself uses non-FIPS algorithms internally, which should be fixed at the source.

---

### RT-HIGH-2: `cmd.exe` in Critical Process Kill Protection List [HIGH]

**File:** `src/Sentinel.Core/HardeningModule.cs`, `IsCriticalProcessName()`

```csharp
string.Equals(name, "cmd", StringComparison.OrdinalIgnoreCase)
```

**Issue:** `cmd.exe` is listed as a critical process that `SafeKillProcessTree` refuses to terminate (if the binary resides in a system directory). This means ANY malware launched via `cmd.exe` from System32 — which is extremely common in attack chains (LOLBin abuse, reverse shells, credential dumping) — **cannot be killed by Sentinel's response engine**.

**Attack:** `cmd.exe /c powershell -enc [malicious_payload]` — the parent cmd.exe process is protected from kill. While the PowerShell child might be killed, the cmd.exe that spawned it persists and can re-launch.

**Recommended fix:** Remove `cmd` from `IsCriticalProcessName`. It is NOT a BSOD-critical process. Killing a cmd.exe window does not destabilize Windows.

---

### RT-HIGH-3: HardeningModule Runs Embedded Scripts Without Integrity Validation [HIGH]

**File:** `src/Sentinel.Core/HardeningModule.cs`, `ApplyUserSetupScriptsHardening()`

**Issue:** The method:
1. Extracts embedded resources to `%ProgramData%\Sentinel\HardeningTemp\`
2. Runs ALL `.reg` files via `reg.exe import`
3. Runs ALL `.ps1` files via `powershell.exe -ExecutionPolicy Bypass`
4. Runs `LGPO.exe` (embedded third-party binary)
5. Runs `takeown.exe` and `icacls.exe` on system files

**Problems:**
- No hash verification of extracted files before execution
- The extraction directory (`%ProgramData%\Sentinel\HardeningTemp\`) permissions are not locked down before extraction
- Race condition: between directory creation and file extraction, an attacker could plant files
- `LGPO.exe` is an embedded unsigned binary that gets extracted and executed

---

### RT-HIGH-4: Agent-Side Monitors Bypass Orchestrator on Direct EmitAsync [HIGH]

**File:** `src/Sentinel.Agent/Program.cs` and various user-session monitors

**Issue:** While `detectionEngine.SetOrchestrator(orchestrator)` is called in the Agent's `Program.cs`, some monitors (like `ShellWatchdog`, `ClipboardSanitizer`) use `_detectionEngine.EmitAsync()` which routes through `HandleDetectionEventAsync` → Orchestrator. However, any monitor that calls `ProcessDetectionAsync` directly on a `DetectionEvent` would bypass scoring entirely if the Orchestrator isn't wired.

The design relies on late-binding (`SetOrchestrator`) which has no compile-time guarantee of being called.

---

### RT-HIGH-5: `powershell.exe` and `pwsh.exe` Protected from Kill [HIGH]

**File:** `src/Sentinel.Core/HardeningModule.cs`, `IsCriticalProcessName()`

**Issue:** Same problem as cmd.exe. PowerShell processes from System32 are protected from kill. This is directly contradicted by Sentinel's own detection rules — `ReverseShellRule` and `AttackToolsRule` can authorize `KillProcessTree` against PowerShell processes, but `SafeKillProcessTree` will refuse to execute the kill if the process is running from `C:\Windows\System32\`.

**This creates a critical logic gap:** Detection fires → Response authorizes kill → Kill is refused by the kill-safety guard → Attacker PowerShell session continues uninterrupted.

---

## Part 3: BLUE TEAM FINDINGS (Defensive Gaps)

### BT-HIGH-1: No Telemetry Source Feeding Detection Rules in Normal Operation

**Issue:** With ETW disabled, the only sources calling `SubmitTelemetry()` on the `DetectionEngine` are:
1. `WmiProcessMonitor` — process starts only
2. `FileActivityMonitor` — file operations in user profile
3. `NetworkMonitor` — active connections
4. `EtwEventDispatcher` — **disabled** (ETW session not started)

This means the `ThreatIntelInjectionRule` (which requires `ThreatIntelTelemetry`) **NEVER fires** in the current deployed state. The highest-fidelity injection detection rule is dead code.

---

### BT-MEDIUM-1: CredentialCanaryMonitor Registered in DI But Not in Any MonitorGroup

**File:** `src/Sentinel.Service/Program.cs`

`CredentialCanaryMonitor` is registered as a DI singleton and injected into `SentinelService` constructor, but it does NOT appear in any of the 6 `MonitorGroup` lists. It depends on `SentinelService.ExecuteAsync()` starting it via `_monitors` (the `IEnumerable<IMonitor>` collection). But `CredentialCanaryMonitor` is registered as `services.AddSingleton<CredentialCanaryMonitor>()`, NOT as `services.AddSingleton<IMonitor, CredentialCanaryMonitor>()`.

**Impact:** CredentialCanaryMonitor may be constructed but never started, depending on whether it self-starts during construction.

---

### BT-MEDIUM-2: ConnectivityCanaryMonitor in Critical Group AND SystemIntegrity Group

**File:** `src/Sentinel.Service/Program.cs`

`ConnectivityCanaryMonitor` is registered as a singleton AND added to both:
- Critical group (line ~group 1)
- It's NOT in SystemIntegrity group

But `WfpIntegrityMonitor` and `DriverLoadMonitor` ARE in SystemIntegrity group (with 10s start delay) while also registered in the Critical group area. This dual-registration could cause the monitor to receive `StartAsync` twice or have lifecycle confusion.

---

## Part 4: CODE QUALITY FINDINGS

### CQ-1: Naming Confusion — Multiple "Credential Guard" Monitors [MEDIUM]

| Class Name | Location | Purpose |
|-----------|----------|---------|
| `CredentialCanaryMonitor` | Sentinel.Core root | Windows Credential Manager honeypot |
| `CanaryFileMonitor` | CredentialProtectionMonitors.cs | Honeypot files in sensitive directories |
| `BrowserCredentialGuard` | CredentialProtectionMonitors.cs | Unified Chrome/Firefox/Edge credential file monitoring |
| `ChromeCredentialGuardMonitor` | **Referenced in design.md but doesn't exist** | Was consolidated into BrowserCredentialGuard |
| `FirefoxCredentialGuardMonitor` | **Referenced in design.md but doesn't exist** | Was consolidated into BrowserCredentialGuard |
| `MicrosoftAccountGuardMonitor` | CredentialProtectionMonitors.cs | TokenBroker/PRT protection |

**Issue:** Design.md still documents `ChromeCredentialGuardMonitor` and `FirefoxCredentialGuardMonitor` as separate classes. These were consolidated into `BrowserCredentialGuard` but documentation wasn't updated. This creates confusion about what's actually running.

---

### CQ-2: Dead Documentation vs Live Code Divergence [MEDIUM]

**design.md** documents monitors that no longer exist as separate classes:
- `ChromeCredentialGuardMonitor` → consolidated into `BrowserCredentialGuard`
- `FirefoxCredentialGuardMonitor` → consolidated into `BrowserCredentialGuard`
- `ChromeSessionGuardMonitor` → not found as a standalone class
- `PowerShellThreatMonitor` → not found as a standalone class (functionality in `ScriptHardeningMonitor`)

The design doc's "Component Inventory" table lists these as separate monitors with specific scan intervals, but they're actually consolidated classes.

---

### CQ-3: DI Wiring — Monitors Registered Twice [MEDIUM]

**File:** `src/Sentinel.Service/Program.cs`

Multiple monitors are registered both as standalone singletons AND inside `MonitorGroup` lists:
```csharp
services.AddSingleton<WfpIntegrityMonitor>();    // standalone registration
services.AddSingleton<DriverLoadMonitor>();       // standalone registration
// ... then later both are sp.GetRequiredService<>() inside SystemIntegrity group
```

This is correct (singleton guarantees one instance), but the `MonitorGroup` calls `StartAsync`/`StopAsync` on the instance, while `SentinelService.ExecuteAsync()` ALSO iterates `IEnumerable<IMonitor>` and starts those. If a monitor implements both `IHostedService` (via BackgroundService) AND `IMonitor`, it could be started twice.

---

### CQ-4: Duplicate Functionality — `BeaconingDetector` vs `AppNetworkPolicyMonitor` [LOW]

Both monitors watch outbound network connections for anomalies:
- `BeaconingDetector` — statistical CV analysis of connection intervals
- `AppNetworkPolicyMonitor` — per-app network destination learning/enforcement

These have significant overlap in network connection enumeration (both call `GetExtendedTcpTable`). While their detection logic differs, the enumeration cost is doubled.

---

### CQ-5: Unused `using System.Linq;` in AdvancedResponseEngine [LOW]

**File:** `src/Sentinel.Core/AdvancedResponseEngine.cs`

The file uses `.Select()` on one line but has no `using System.Linq;` at the top — this compiles because it's in a `.Select()` call on `traceResult.QuarantinedFiles` which resolves via extension methods likely imported elsewhere. Minor inconsistency.

---

### CQ-6: `ResponseEngine` (old) Referenced in design.md Changelog [LOW]

Design.md notes "Removed in 1.0.0: ResponseEngine — Superseded by AdvancedResponseEngine" but no class named `ResponseEngine` exists in the codebase. Clean removal, just dead documentation.

---

### CQ-7: `RansomwareIoMonitor` Listed in DI but Class Location Unclear [LOW]

`RansomwareIoMonitor` is referenced in DI registration and the CoreDetection MonitorGroup, but its definition is in `src/Sentinel.Core/Monitors/CoreDetectionMonitors.cs` (not a standalone file). This is by design (group files), but makes discoverability harder given the root-level `RansomwareIoMonitor.cs` doesn't exist.

---

## Part 5: WIRING & INTEGRATION ISSUES

### WIRE-1: `SentinelService` Constructor Takes 26 Parameters

**File:** `src/Sentinel.Service/SentinelService.cs`

The constructor takes 26 injected dependencies. While .NET DI handles this, it's a code smell indicating this class has too many responsibilities. The `MonitorGroup` pattern was introduced to reduce flat service registrations, but `SentinelService` still manually manages lifecycle for 13+ singletons.

---

### WIRE-2: Late-Binding Pattern Has No Validation

Multiple components use `SetXxx()` methods for late-binding to avoid circular DI:
- `responseEngine.SetIncidentResponseService()`
- `responseEngine.SetDllUnloadEngine()`
- `responseEngine.SetChainTracer()`
- `responseEngine.SetReinfectionCorrelator()`
- `detectionEngine.SetOrchestrator()`

**Issue:** If any of these calls are missed (code change, refactor), the component operates in a degraded state with no runtime error. The `_orchestrator` null check in `HandleDetectionEventAsync` falls back to direct response engine (bypassing incident grouping), but this fallback is undocumented and could mask wiring bugs.

---

### WIRE-3: Agent Missing Several Detection Rules vs Service

**Agent DI registrations:**
```
LsassAccessRule, RansomwareDetectionRule, ReverseShellRule, UnsignedBinaryRule, 
VerdictGateRule, ClickFixDetectionRule, DllSideloadingDetectionRule, ChromeRemoteDebuggingRule,
DynamicRulesEvaluator
```

**Service DI registrations (additional):**
```
ThreatIntelInjectionRule, PrivilegeEscalationRule, AttackToolsRule, CampaignIocRule,
CampaignDetectionRule
```

**Impact:** The Agent (user-session process) cannot detect:
- Process injection (ThreatIntelInjectionRule)
- Privilege escalation (PrivilegeEscalationRule)
- Known attack tools (AttackToolsRule)
- Campaign IoCs (CampaignIocRule)

This may be intentional (Agent doesn't receive ThreatIntel ETW telemetry), but any user-session process telemetry flowing through the Agent's detection engine won't be evaluated against these critical rules.

---

## Part 6: TEST COVERAGE GAPS

### Tests Present (Good):
- AdvancedResponseEngine, AllowlistService, AntiTamperGuard, BehavioralCorrelationEngine
- ChainTracer, DetectionEngine, FileReputation, HashReputation, ScoringEngine
- SecurityValidation, IntegrationPipeline (end-to-end)

### Critical Tests MISSING:
| Component | Risk | Why It Matters |
|-----------|------|----------------|
| `DynamicRulesEvaluator` security | HIGH | No test for malicious rule injection |
| `HardeningModule.ApplyUserSetupScriptsHardening()` | HIGH | No test that embedded scripts are safe |
| `MonitorGroup` lifecycle management | MEDIUM | No test for double-start, restart behavior |
| `ConsultantSignalIngestor` file poisoning | MEDIUM | Owner-check bypass scenarios |
| `IsolationResponseEngine` input validation | LOW | Has some validation but no fuzzing tests |
| `BehavioralCorrelationEngine` Electron bypass | MEDIUM | No test that a supply-chain compromised Electron app is still caught |

---

## Part 7: RECOMMENDATIONS (Priority Ordered)

### P0 — Immediate (Sabotage Remediation)

1. **Remove `GorstaksEDR.ps1` from HardeningResources** — This script installs a parallel scheduled task, creates Defender exclusions, and auto-connects to public VPNs. It has no legitimate place in an EDR product.

2. **Audit ALL files in `HardeningResources/`** — Verify each `.ps1`, `.reg`, `.bat` file is actually needed and doesn't contain supply-chain compromises.

3. **Remove or gate `ApplyUserSetupScriptsHardening()`** — The blanket execution of all embedded scripts on every service start is dangerous. Either remove it entirely or add:
   - SHA-256 manifest of expected files
   - Signature verification before execution
   - Configuration flag to enable/disable

### P1 — Critical Security

4. **Add signature validation to `DynamicRulesEvaluator`** — HMAC-sign rule files with the installation entropy key. Reject unsigned rules.

5. **Fix ETW P/Invoke struct alignment and re-enable `UnifiedEtwSession`** — This is the single largest detection gap in the product.

6. **Remove `cmd`, `powershell`, and `pwsh` from `IsCriticalProcessName()`** — These are NOT BSOD-critical. They are the most common attack vectors. Sentinel's own detection rules authorize killing them, but the safety guard blocks it.

### P2 — High Priority

7. **Stop disabling FIPS** — Fix whatever internal crypto operation requires non-FIPS algorithms instead of weakening the entire system.

8. **Lock down the `rules/` directory ACL** — SYSTEM-only write access, same pattern as `ConsultantSignalIngestor`.

9. **Add compile-time wiring validation** — Create a startup check that verifies all `SetXxx()` late-bindings were called, logging CRITICAL if any are null after startup.

### P3 — Medium Priority

10. **Update design.md** — Remove references to consolidated monitors that no longer exist as separate classes.

11. **Add integration test for DynamicRulesEvaluator** — Test that malicious rules (targeting system processes, using reflection to access private fields) are rejected.

12. **Deduplicate network enumeration** — Share `GetExtendedTcpTable` results between `BeaconingDetector`, `AppNetworkPolicyMonitor`, `NetworkMonitor`, and `OutboundConnectionWhitelist`.

---

## Summary Table

| ID | Severity | Type | Component | One-Line Description |
|----|----------|------|-----------|---------------------|
| SAB-1 | CRITICAL | Sabotage | GorstaksEDR.ps1 | Embedded script installs parallel EDR with VPN, Defender exclusion, persistence |
| RT-CRIT-1 | CRITICAL | Security | DynamicRulesEvaluator | Unsigned rule files can inject arbitrary detections/kills |
| RT-CRIT-2 | CRITICAL | Security | UnifiedEtwSession | Disabled ETW = 1-15s detection blind window |
| RT-HIGH-1 | HIGH | Security | HardeningModule | FIPS algorithm policy disabled system-wide |
| RT-HIGH-2 | HIGH | Security | HardeningModule | cmd.exe protected from kill despite being primary attack vector |
| RT-HIGH-3 | HIGH | Security | HardeningModule | Embedded scripts executed without integrity validation |
| RT-HIGH-4 | HIGH | Wiring | Agent monitors | Late-binding orchestrator has no validation guarantee |
| RT-HIGH-5 | HIGH | Security | HardeningModule | powershell.exe/pwsh.exe protected from kill, contradicting detection rules |
| BT-HIGH-1 | HIGH | Dead Code | ThreatIntelInjectionRule | Rule NEVER fires (no ThreatIntelTelemetry source with ETW disabled) |
| BT-MEDIUM-1 | MEDIUM | Wiring | CredentialCanaryMonitor | May not be started (not in MonitorGroup, not IMonitor) |
| BT-MEDIUM-2 | MEDIUM | Wiring | ConnectivityCanaryMonitor | Potential double-registration lifecycle issue |
| CQ-1 | MEDIUM | Naming | Credential monitors | Multiple similar names create confusion |
| CQ-2 | MEDIUM | Documentation | design.md | References non-existent classes |
| CQ-3 | MEDIUM | Wiring | DI registration | Potential double-start for monitors |
| WIRE-1 | LOW | Design | SentinelService | 26-parameter constructor (too many responsibilities) |
| WIRE-2 | MEDIUM | Wiring | Late-binding | No runtime validation of SetXxx() calls |
| WIRE-3 | MEDIUM | Coverage | Agent rules | Agent missing 5 critical detection rules |

---

*This audit identifies the GorstaksEDR.ps1 finding as the most urgent issue requiring immediate remediation. Its presence in an EDR product's embedded resources — executing on every service start with SYSTEM privileges — represents either a deliberate supply chain compromise or a catastrophic integration mistake.*
