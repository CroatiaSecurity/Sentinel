# Sentinel EDR — Red/Blue Team Audit v1.6.0

**Date:** 2026-07-25  
**Scope:** Post-1.6.0 full-project review (service, agent, core, worker) + detection coverage gaps  
**Method:** Source review against current threat model; residual attack paths after 1.6.0 fixes; feature roadmap for blind spots  

---

## Executive Summary

**1.6.0 closed the P0 security-engineering gaps** from the prior audit (proxy auth, ActiveResponse boot, entropy/rules ACLs, kill rate limits). Those remediations hold under code review.

**Remaining risk is mostly:**
1. **Fundamental userland limits** (admin/kernel win) — documented, not bugs  
2. **Detection coverage holes** against modern tradecraft — the real product opportunity  
3. A handful of **residual MEDIUM** engineering issues  

| Severity | Count | Notes |
|----------|------:|-------|
| CRITICAL | 0 | Proxy/auth fixed in 1.6.0 |
| HIGH | 1 | ETW session kill still blinds most telemetry (detectable but not self-healing enough) |
| MEDIUM | 5 | NetworkIsolate unlimited; shared proxy secret; name-based baseline; BYOVD race; JIT allowlist |
| LOW | 3 | WFP netsh export, poll intervals, docs drift |
| INFO | — | Honest threat model remains a strength |

**Overall:** Conditional **PASS** as secondary EDR. Next value is **closing detection blind spots**, not more config hardening.

---

# Part 1 — RED TEAM (residual)

### RT-HIGH-1: Stop/hijack `SentinelUnifiedTrace` ETW session

**Attack:** Admin/SYSTEM calls `logman stop SentinelUnifiedTrace` or `ControlTrace(STOP)` on the session. Most monitors that depend on the unified session go dark while the process still “looks healthy.”

**Mitigation today:** WMI process fallback exists in places; anti-tamper on binary/service/ActiveResponse; not a dedicated “ETW session heartbeat → recreate + Tier1” loop called out as critical.

**Impact:** Silent reduction of detection surface without killing the service.

**Fix direction:** Critical-group monitor: if `UnifiedEtwSession.IsActive` false or event rate flatlines while OS is busy → recreate session + alert + temporary elevated response mode.

---

### RT-MEDIUM-1: NetworkIsolate not rate-limited (B14 residual)

Kill storms capped; attacker can still force **firewall rule spam** / collateral block of cloud IPs via induced NetworkIsolate (domain fronting false positives or decoy beacons).

**Fix:** Cap new isolate rules/min; coalesce by /24 or ASN; expire isolates; never isolate RFC1918 gateways / known CDN ranges without extra corroboration.

---

### RT-MEDIUM-2: Shared `ProxySharedSecret` in open source

Per-deployment secret works if set; default `null` fails closed (good). Shared secret across all installs = one leak burns all. No per-machine registration.

**Fix (feature):** Install-time enrollment: agent gets unique key from operator portal or local QR; worker stores install IDs.

---

### RT-MEDIUM-3: Process-name baseline / allowlist edges

`BehavioralBaselineService` still keys “established” on process **name**. Path checks exist elsewhere, but score reductions remain name-oriented.

**Attack:** Quiet name-squatting of established binaries from non-standard paths (partially mitigated).

---

### RT-MEDIUM-4: BYOVD race (15s poll)

`DriverLoadMonitor` cycles every 15s. Race: load vulnerable driver → kill EDR before next tick.

**Fix:** Subscribe kernel driver-load ETW / Event 7045 with near-real-time watcher; preemptive blocklist of known vulnerable hashes at service create (already partial).

---

### RT-MEDIUM-5: JIT / browser thread-start allowlist

`EtwThreatIntelMonitor` excludes chrome, node, dotnet, powershell, etc. from thread-start-outside-image detection — classic place for reflective loaders.

**Mitigation elsewhere:** MemoryBehaviorAnalyzer, sideload checks, beaconing. Still a deliberate hole.

---

### RT-LOW: WFP integrity still shells `netsh wfp show filters`

LOLBin / detectability / reliability. Prefer FWPM API.

### RT-INFO: Admin/kernel/pre-boot — still game over

Documented correctly. No security theater.

### Closed (spot-check, 1.6.0)

| Prior | Status |
|-------|--------|
| Client-key proxy HMAC | Closed |
| ActiveResponse false + reboot | Closed (EnforceActiveResponse) |
| Admin read entropy → sign rules | Closed (SYSTEM-only) |
| Kill storms | Closed (budget) |
| sc.exe driver disable | Closed (native SCM) |

---

# Part 2 — BLUE TEAM

### Strengths to keep
- Behavioral correlation + President’s Law (incl. C2)  
- Path-based self-exclusion  
- Fail-closed dynamic rules + SYSTEM entropy  
- Catalog Authenticode  
- Hardening without GSecurity.bat  
- WFP EDRSilencer awareness  
- DoH app bypass monitor  
- Credential / LSASS canaries  
- Honest THREAT_MODEL  

### Blue residual
| Gap | Ops impact |
|-----|------------|
| Proxy secret unset | Silent loss of VT/reporting — need health metric |
| Aggressive hardening | Remote admin locked out by design |
| FP kill budget | After 15 kills/min, true ransomware wave may LogOnly — alert when budget exhausted should be Tier1 |
| Dual Service/Agent response | Clarify agent never exceeds service policy |

### Detection engineering: coverage vs MITRE-ish gaps

| Area | Coverage now | Blind spot severity |
|------|--------------|---------------------|
| Ransomware (VSS + bulk IO) | Strong | Low |
| Classic LOLBins / PS / WMI persist | Strong | Low–Med |
| COM CLSID / regsvr32 | Present | Med (TreatAs/proxy less covered) |
| Named pipes (CS/beacon IPC) | IOC-ish only | **High** |
| RPC / DCOM lateral | Port block only | **High** |
| Thread-pool / APC / early-bird | Partial (TI/memory) | **High** |
| ETW blind / provider strip | Weak | **High** |
| Browser-as-C2 (extension, remote debug, DevTools) | Partial rules | **High** |
| Cloud sync exfil (OneDrive/Dropbox/rclone) | Weak | Med–High |
| Email/IM staging | Weak | Med |
| Container/WSL lateral | Partial | Med |
| Certificate / AD CS abuse | TLS root only | Med |
| Indirect syscalls / Hell’s Gate | Stub monitor partial | Med |
| Token theft / make_token / Rubeus | Partial | Med–High |
| PrintNightmare-class / spooler | Partial | Med |

---

# Part 3 — What to add (roadmap)

Prioritized by **blind-spot kill value** × **feasibility in userland** × **FP risk**.

---

## P0 — Highest impact blind-spot killers

### 1. `EtwSessionGuard` (Critical group) — **do this first**
**Blind spot:** Stopping the unified ETW session blinds process/file/registry/DNS/TI feeds.

**What:** Every 2–5s check `IsActive` + events/sec floor. On failure: `StartTrace` recreate, Tier1 `AntiTamper`, enter “degraded but angry” mode (more polling via WMI/Toolhelp, shorter intervals).

**Why first:** Without telemetry, every other monitor is theater.

---

### 2. `NamedPipeMonitor` — IPC C2 / lateral
**Blind spot:** Cobalt Strike, many implants, and privilege-escalation tools live on `\\.\pipe\*`. Campaign rules have weak regex only.

**What:**
- Enumerate pipes periodically + ETW if available  
- Alert on: new pipes with high-entropy names; non-system process creating pipes; cross-session pipe connect; known bad prefixes  
- Correlate pipe server PID with network beacon  

**Response:** LogOnly → NetworkIsolate + kill on pipe+beacon composite.

---

### 3. `BrowserC2Guard` (Agent + Service signals)
**Blind spot:** Extension compromise, remote debugging (`--remote-debugging-port`), headless chrome as proxy, cookie theft beyond current browser credential guard.

**What:**
- Watch browser command lines for remote-debug / disable-web-security / load-extension from user-writable paths  
- Extension install path + manifest integrity (Agent)  
- Correlate browser child with unusual long-lived TLS to rare domains (Service beaconing already helps)  

You already have `ChromeRemoteDebuggingRule` — **expand** into a full monitor with kill/isolate authorization on corroboration.

---

## P1 — Strong coverage upgrades

### 4. `RpcLateralMonitor`
**Blind spot:** Hardening blocks ports; doesn’t detect **outbound** lateral (WMI, DCOM, remote SCM, remote registry) from user tools.

**What:** ETW Microsoft-Windows-RPC or network connects to 135/445/5985 from office/script parents; `wmic /node:`, `Invoke-Command`, `winrs`, `sc \\host`.

---

### 5. `TokenTheftMonitor` (beyond TokenIntegrityMonitor)
**Blind spot:** Duplicate token / impersonate / make_token / steal from winlogon without classic integrity “escalation.”

**What:** Threat-Intelligence ETW for `OpenProcess`+`DuplicateToken`/`ImpersonateLoggedOnUser` chains; canary logon session; alert when non-SYSTEM opens SYSTEM tokens.

---

### 6. `CloudSyncExfilMonitor`
**Blind spot:** Mass copy into OneDrive/Dropbox/Google Drive/rclone/mega folders bypasses “large TCP upload” if throttled.

**What:** Watch sync root directories for burst creates; process=rclone/megasync with high file count; correlate with USB/MTP already covered.

---

### 7. `EtwProviderTamperMonitor`
**Blind spot:** Patching `ntdll!EtwEventWrite` in *other* processes or stripping providers via `logman`.

**What:** Periodic integrity of EtwEventWrite stubs in critical processes; detect `logman stop/start` of security sessions; session list diffs.

---

## P2 — Quality / depth

### 8. Real `Microsoft-Windows-Threat-Intelligence` consumer
Today `EtwThreatIntelMonitor` is largely **thread start address scanning**, not full TI keywords (ALLOCVM_REMOTE, PROTECTVM_REMOTE, QUEUEUSERAPC_REMOTE, SETTHREADCONTEXT, etc.).

**What:** Map TI events → injection composite signals. Biggest single upgrade to injection fidelity vs JIT allowlist holes.

---

### 9. `ComHijackDeepMonitor`
You scan new CLSIDs. Add: **TreatAs**, **ProgID**, **HKCU** hijacks of high-value CLSIDs (MMDevice, Taskbar, etc.), and **missing-DLL → search-order** sideload.

---

### 10. `BitsJobMonitor`
BITS jobs for persistence/exfil are classic; cmdline bitsadmin rules are not enough (COM API jobs).

---

### 11. Kill-budget exhaustion = Tier1 incident
When `MaxKillsPerMinute` hits, emit **AntiTamper/Incident** not only LogOnly — so an attacker-induced storm is visible and optional “burst mode” unlocks higher budget for 60s if ransomware signals present.

---

### 12. Service **PPL** / ELAM (long-term)
Not a monitor — product capability. Userland anti-tamper will never beat admin. Document as 2.0 epic; requires Microsoft signing path.

---

## P3 — Nice differentiators (your “Gorstak” niche)

| Idea | Why it’s cool |
|------|----------------|
| **Connectivity canary → auto-isolate** already exists; add **honeypot SMB share** tripwire | Zero-FP lateral detection on LAN |
| **Acoustic + webcam** already strong; add **screen OCR canary** (unique string on desktop) | Detect screen grab exfil |
| **PseudoSandbox** deepen with network deny-by-default for unknown unsigned | Contain first run |
| **Installer soak mode** 24h LogOnly then arm | Cut FP bloodbath for new users |
| **Local web UI** (localhost only, auth) for quarantine/allowlist | Ops without raw JSONL |

---

# Recommended 1.6.x → 1.7 plan (practical)

| Sprint | Deliverable | Closes |
|--------|-------------|--------|
| **1.6.1** | `EtwSessionGuard` + kill-budget Tier1 alert + NetworkIsolate rate limit | RT-HIGH-1, RT-MEDIUM-1, blue budget silence |
| **1.7.0** | `NamedPipeMonitor` + TI keyword injection pipeline | IPC C2 + injection blind spot |
| **1.7.1** | `BrowserC2Guard` expansion + `CloudSyncExfilMonitor` | Modern userland exfil |
| **1.8.0** | `RpcLateralMonitor` + `TokenTheftMonitor` | Post-compromise movement |
| Later | PPL research / per-install proxy keys | Admin resistance / multi-tenant TI |

---

## Scenario scorecard (v1.6.0)

| Scenario | Outcome |
|----------|---------|
| Commodity ransomware | Strong |
| Office → PS LOLBin | Strong |
| Signed supply-chain C2 beacon | NetworkIsolate floor — Strong |
| ActiveResponse false + reboot | Force-on — Strong |
| Forge cloud TI reports | Fail closed / server secret — Strong |
| Stop ETW session only | **Weak / HIGH residual** |
| Named-pipe implant IPC | **Weak** |
| Browser extension C2 | **Partial** |
| Admin sc stop / BYOVD | Win (documented) |

---

## Bottom line

**Security engineering posture after 1.6.0 is solid** for an open-source userland EDR.  
**The next wins are detection features**, especially:

1. **ETW session self-heal + alert** (stop the “silent blind”)  
2. **Named pipe visibility** (stop the “invisible implant channel”)  
3. **Real Threat-Intelligence ETW keywords** (stop living in the JIT allowlist hole)  
4. **Browser C2 / cloud sync exfil** (where real malware lives in 2025–26)

*Source-based analysis; not a live red-team engagement.*
