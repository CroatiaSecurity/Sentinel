# Sentinel EDR — Red/Blue Team Audit v1.5.9

**Date:** 2026-07-25  
**Scope:** Full-project security audit of Sentinel **1.5.9** (service, agent, core, worker, hardening, config)  
**Method:** Source review against stated threat model; attack-path analysis; defensive-correctness checks  
**Prior context:** Builds on `THREAT_MODEL.md`, `SECURITY.md`, CHANGELOG 1.5.4–1.5.9, and prior audits through v1.5.6

---

## Executive Summary

Sentinel is a **userland Windows EDR** (SYSTEM service + user-session agent) with deep ETW coverage, multi-signal correlation, automated kill/quarantine/isolate, and aggressive self-hardening. Documentation is unusually honest about limits (admin kill, kernel, pre-boot).

**Overall posture:** Strong layered detection and response for commodity / LOLBin threats; mature hardening history (1.4.4, 1.5.8, 1.5.9). Residual risk is dominated by **Windows userland physics** (admin wins) plus a few **design/implementation gaps** that are still actionable.

| Severity | Count | Themes |
|----------|------:|--------|
| **CRITICAL** | 1 | Threat-proxy auth model broken / forgeable |
| **HIGH** | 3 | ActiveResponse boot-time bypass; admin entropy→rules; aggressive auto-kill blast radius |
| **MEDIUM** | 5 | DPAPI scope, name-based baseline, LOLBin remnants, worker/client mismatch, config leakage |
| **LOW** | 4 | Tray shell-out, startup logs, handle-cost, process-name trust edges |
| **INFO** | 4 | Documented limits, positive design patterns |

**Verdict:** Suitable as a **second layer next to Defender** for power users / small teams. Not a substitute for kernel EDR or enterprise fleet controls. Fix the worker auth and ActiveResponse boot path before treating threat-intel reporting or “config self-heal” as reliable.

---

## System Under Review (attack surface map)

```
┌─ Windows (ring 0) ──────────────────────────┐  NO visibility (documented)
├─ Sentinel.Service (SYSTEM) ─────────────────┤  ETW, monitors, kill/quarantine, firewall, rules
├─ Sentinel.Agent (user session) ─────────────┤  Tray, clipboard/webcam/keystroke guards, partial response path
├─ ProgramData\Sentinel\Secure ───────────────┤  .install_entropy, caches, allowlist (ACL: SYSTEM+Admins)
├─ Install dir + rules\ ──────────────────────┤  Binaries, dynamic JSON rules (HMAC)
├─ Cloudflare Worker (threat proxy) ──────────┤  VT/abuse.ch proxy — keys server-side
└─ HardeningResources ────────────────────────┘  LGPO.exe + GSecurity.inf only (1.5.8+)
```

**Assumed attacker:** Has read the source (project philosophy). Privilege levels: standard user → local admin → SYSTEM → kernel.

---

# Part 1 — RED TEAM

### RT-CRITICAL-1: Threat proxy HMAC is client-key-driven (and client never sends the key)

**Where**
- `worker/src/index.js` — requires `X-Sentinel-Signature`, `X-Sentinel-Timestamp`, `X-Sentinel-Key`; verifies HMAC with **client-supplied** `X-Sentinel-Key`
- `ThreatReportService.cs` — signs with install entropy–derived key but **only** sets Timestamp + Signature headers (no `X-Sentinel-Key`)
- `SENTINEL_SHARED_SECRET` is **optional**

**Attack / impact**
1. **Auth design failure:** Anyone who can POST to the worker can generate a random key, HMAC-sign a body with it, send that key in `X-Sentinel-Key`, and pass signature verification. That enables:
   - Abuse of upstream API quotas (VirusTotal, AbuseIPDB, MalwareBazaar, URLhaus) if keys are configured
   - Pollution of abuse.ch / AbuseIPDB with forged reports
2. **Broken legitimate path:** Current agents omit `X-Sentinel-Key` → worker returns 400 → **reporting effectively dead** while config says `Enabled: true`

**Why severity is CRITICAL:** Open proxy to paid/shared TI APIs + false sense of signed telemetry.

**Remediation**
- Server-side only: store `SENTINEL_SHARED_SECRET` (or per-install registration secret); **never** accept signing material from the client
- Agent: send `X-Sentinel-Auth` (or sign with a derived key the worker already knows)
- Fail closed if shared secret unset in production
- Rate-limit by IP + install ID; CAPTCHA/quota for VT lookups
- Add integration test: agent → worker contract headers

---

### RT-HIGH-1: ActiveResponse “tamper detection” misses boot / file-based disable

**Where:** `AntiTamperGuard.CheckActiveResponseConfig()` — tracks only **in-memory** `true → false` transitions; initializes `_activeResponseLastKnown` from bound config at process start.

**Attack**
1. As admin: set `ActiveResponse: false` in `appsettings.json` (or replace file)
2. Restart service (`sc stop/start Sentinel` or reboot)
3. Service starts with `ActiveResponse=false`; no transition → **no alert, no force re-enable**
4. All kill/quarantine/isolate become LogOnly; product looks “alive”

**Impact:** Full neutralization of active defense while monitors still run (stealthy blindfold). Residual window is permanent until config fixed.

**Remediation**
- Policy: treat `ActiveResponse=false` at startup as either hard-fail, force-true, or Tier1 alert + force-true (except a signed offline “maintenance mode” token)
- Hash/monitor `appsettings.json` integrity (same cadence as binary integrity)
- Prefer registry/LSA secret policy over editable JSON for kill-switch

---

### RT-HIGH-2: Local admin can forge dynamic rules (entropy ACL includes Admins)

**Where:** `DynamicRulesEvaluator` HMAC from `%ProgramData%\Sentinel\Secure\.install_entropy`; rules dir ACL: SYSTEM + **Administrators** write; Secure dir same pattern.

**Attack (admin)**
1. Read `.install_entropy`
2. Derive rule signing key (`HMACSHA256(entropy, "sentinel-dynamic-rules-signing-v1")`)
3. Drop signed JSON rules that fire on trusted tools (DoS) or that never match (noise) — or craft high-confidence kill rules against competitors / user apps
4. Rules hot-reload via `FileSystemWatcher`

**Note:** Fail-closed on missing entropy (v1.5.9) is correct against entropy *deletion*, not against admin *read*.

**Impact:** Authorized false kills / detection theater under local admin. Aligns with “admin can kill Sentinel” but is quieter.

**Remediation**
- Entropy: SYSTEM-only DACL (remove Administrators)
- Sign rules offline at build/install with a private key not on the host; host only has public verify key
- Or disable dynamic rules entirely for consumer builds

---

### RT-HIGH-3: Automated response as offensive capability (false-positive weaponization)

**Where:** `AdvancedResponseEngine`, correlation composites, `ChainTracer`, `IsolationResponseEngine`, netsh/firewall blocks, aggressive port blocks in `HardeningModule`.

**Attack (standard user or low-priv malware)**
- Induce patterns that look like ransomware / reverse shell / injection (shadow-copy-like noise, Office→shell trees, synthetic ETW-visible behaviors) to cause **self-DoS** of security tools, IDEs, backups
- Trigger Cast/firewall blocks via spoofed private IPs if validation is weak
- Abuse correlation on high-noise processes post–svchost exemption removal (1.5.9) for kill storms

**Impact:** Availability attack against the host using Sentinel as the effector (SYSTEM privilege).

**Remediation**
- Stronger staged response: quarantine-first, kill after N corroborations / dwell
- Protected process list (security products, shell, update agents) with path+signature checks
- Dry-run / audit mode default for first 24–48h after install
- Rate-limit kills per minute and alert on threshold

---

### RT-MEDIUM-1: ThreatReportService ↔ worker contract mismatch

Already partially covered in RT-CRITICAL-1. Independently: comments claim “proxy validates installation-specific signatures,” but worker never binds signatures to install entropy. Documentation overclaims MITM/forge resistance.

---

### RT-MEDIUM-2: DPAPI in `SecureCacheStore` without `CRYPTPROTECT_LOCAL_MACHINE`

**Where:** `SecureCacheStore.Protect/Unprotect` uses only `CRYPTPROTECT_UI_FORBIDDEN`.

**Impact:** Under SYSTEM, ciphertext is still host-bound in practice, but inconsistent with `FileVerdictAds` (which defines `CRYPTPROTECT_LOCAL_MACHINE`). Any non-SYSTEM host process that can load the cache under wrong context fails closed (good); admin/SYSTEM still reads plaintext after HMAC verify with reconstructed key.

**Residual:** Cache poisoning still requires SYSTEM/Admin + entropy (as documented B4). Not a standard-user bypass.

---

### RT-MEDIUM-3: Baseline trust is process-name keyed

**Where:** `BehavioralBaselineService.IsEstablishedProcess(processName)` / detection history by name.

**Attack:** Name-squat a quiet established process name from a different path (partially mitigated by path checks elsewhere, but score reductions keyed on name remain).

**Mitigation already present:** path allowlist hardening; detection history revokes established (1.5.9); trust demotion caps.

**Residual:** MEDIUM for pure name-based scoring edges.

---

### RT-MEDIUM-4: Remaining LOLBin / shell surfaces

| Location | Issue |
|----------|--------|
| `DriverLoadMonitor.AttemptDriverDisableAsync` | Still shells `sc stop/config/delete` with interpolated `serviceName` (`UseShellExecute=false` limits shell metacharacters; prefer native SCM like `AntiTamperGuard`) |
| `CastDeviceGuard.EnsureFirewallBlock` | `remoteip={ip}` without strict `IPAddress.TryParse` / family check — malformed strings could confuse netsh |
| `TrayIconService.OnOpenConsole` | `cmd.exe` → `powershell -Command Get-Content` (path fixed under ProgramData; still noisy LOLBin pattern for an EDR) |
| `IsolationResponseEngine` | PowerShell `-EncodedCommand` (good vs 1.4.4 injection); still elevates PS as SYSTEM for ISO/VM actions |

**Attack:** Prefer native APIs; validate service names `[A-Za-z0-9_\-\.]{1,256}`; validate IPs; open log with Notepad/custom viewer without cmd.

---

### RT-MEDIUM-5: Hardening module attack surface & availability

**Where:** `HardeningModule` blocks RDP/WinRM/SSH/SMB-related ports, disables remote services, applies LGPO, registry mitigations.

**Attack / risk:** Not classic RCE, but **hostage / brick-remote-admin**: once installed, remote recovery may be impossible without physical access. Embedded `LGPO.exe` is a high-value binary to integrity-check.

**Remediation:** Document clearly; optional hardening tiers; sign/hash-check LGPO before exec.

---

### RT-LOW-1: Diagnostic log disclosure

`startup_trace.log` / `fatal_crash.log` / `agent_crash.log` under ProgramData may be world-readable depending on parent ACL — aids recon of service lifecycle.

---

### RT-LOW-2: Agent self-restart storms

Agent restarts on every exit (up to 5) + service watchdog. Admin kill → thrash; minor DoS/noise, not silent bypass.

---

### RT-LOW-3: Catalog / signer path cost (from 1.5.6)

High process churn → CryptCATAdmin cost; mitigated by `SignerTrustService` caching. Residual DoS: LOW.

---

### RT-INFO: Attacks correctly out of scope (confirmed)

| Vector | Assessment |
|--------|------------|
| Kernel / BYOVD with HVCI off | Game over — documented |
| `sc stop` / process kill as admin | Watchdog delay only |
| Offline disk / pre-boot | Out of scope |
| ETW blind from in-process | Detect attempt, hard to prevent |
| Encrypted C2 over legit CDN | NetworkIsolate may collateral-block |

---

# Part 2 — BLUE TEAM

### BT-PASS: Strong defensive patterns (keep these)

1. **Honest threat model** — no security theater about admin/kernel
2. **Path-based self-exclusion** (`Path.GetFullPath` + trailing `\` ) — blocks rename/prefix tricks
3. **President’s Law + C2 re-add (1.5.9)** — allowlist cannot silence C2Beaconing
4. **Beacon floor NetworkIsolate (1.5.9)** — signed supply-chain C2 still blocked
5. **Baseline poisoning fix (1.5.9)** — detections revoke established status
6. **Dynamic rules fail-closed (1.5.9)** — missing HMAC key rejects rules
7. **Catalog Authenticode fallback (1.5.6)** — stops self-quarantine of explorer/powershell
8. **Hardening 1.5.8** — removed GSecurity.bat / mass `.ps1` / wild `.reg` import (supply-chain win)
9. **Native SCM for service re-register** — less LOLBin dependency
10. **Monitor groups** — critical monitors restart indefinitely; host ignores single BackgroundService death
11. **Correlation composites** — kill on multi-signal, not single weak indicators
12. **Test suite** — broad unit/integration coverage (reputation, correlation, anti-tamper, pipeline)

### BT-HIGH-1: ActiveResponse integrity is incomplete

Same as RT-HIGH-1. Blue expectation: config kill-switch must not survive reboot without loud alert. Current design only catches live object mutation (~10s window if attacker can flip memory/config binding without restart — uncommon). **Boot-time false-negative for defense status.**

**Detection gap test:** Deploy with `ActiveResponse: false` → confirm no Anti-Tamper event → confirm kills never fire.

### BT-HIGH-2: Threat reporting is not operationally trustworthy

With worker requiring `X-Sentinel-Key` and agent not sending it, **outbound TI reporting is likely 100% failing**. Operators may believe community reporting is active (`ThreatReporting.Enabled: true`).

**Blue actions:** Check worker logs/metrics; fix contract; synthetic health: `POST /health` + signed canary report.

### BT-HIGH-3: Over-blocking / false-positive ops risk

Aggressive ActiveResponse + broad President’s Law categories (includes NetworkAnomaly, DnsAnomaly) → SOC noise and user pain. IDE exemptions improved in 1.5.8 (PhantomKeystroke/Clickjacking) but response path still high-blast.

**Blue actions:** Tune allowlist carefully (path-verified); start with observation mode; watch quarantine and firewall rule growth.

### BT-MEDIUM-1: Admin ACL on secrets

Entropy/cache/rules writable/readable by Administrators weakens “only SYSTEM” story. For home admin-as-user machines, malware that elevates UAC can read secrets.

**Blue:** Prefer running daily account as standard user; treat local admin compromise as full Sentinel compromise.

### BT-MEDIUM-2: Visibility gaps (detection engineering)

| Gap | Notes |
|-----|--------|
| Direct syscalls | Stub monitor helps unhook; pure direct syscalls still hard |
| Domain-fronted HTTPS C2 | Statistical beacon may catch timing; payload opaque |
| GPU-resident code | Documented |
| Living-in-signed-app without classic injection APIs | Sideload check improved 1.5.7; continuous coverage needed |
| WSL / containers | Monitors exist; isolation engine is best-effort |

### BT-MEDIUM-3: Committed machine-specific config

`appsettings.json` includes `C:\Users\Admin\...Kiro.exe` — environment leakage if repo is shared; also pins ApplicationIntegrity to one machine layout.

### BT-MEDIUM-4: Dual response stacks (Service + Agent)

Agent hosts `AdvancedResponseEngine` / orchestrator subset. Ensure user-session agent cannot take stronger actions than policy intends when service is down, and that duplicate responses don’t double-quarantine.

### BT-LOW-1: Observability

JSONL event logs are good for forensics; ensure rotation, ACL, and SIEM ship. Prefer structured fields for rule name, PID, path, action, ActiveResponse state.

### BT-LOW-2: Dependency / supply chain

- Cloudflare Worker secrets, abuse.ch, VT — third-party trust
- Embedded LGPO.exe — pin hash in build
- .NET single-file publish — verify Authenticode on installer releases

### BT-INFO: Prior closed items (spot-check status)

| Item | Status in 1.5.9 tree |
|------|----------------------|
| ISO/VM command injection | Mitigated (`-EncodedCommand` + validation) |
| Cache HMAC predictable boot/PID | Mitigated (entropy + machine GUID) |
| Dynamic rules fail-open | Mitigated fail-closed |
| Beacon LogOnly for signed PF apps | Mitigated NetworkIsolate floor |
| C2 allowlist suppress | Mitigated President’s Law |
| Catalog signature FP cascade | Mitigated |
| GSecurity.bat script runner | Removed |

---

## Severity-ranked remediation backlog

| Pri | ID | Action | Effort |
|----:|----|--------|--------|
| P0 | RT-CRITICAL-1 | Redesign worker auth; fix agent headers; require shared secret; rate-limit | M |
| P0 | RT-HIGH-1 / BT-HIGH-1 | Force or alert on `ActiveResponse=false` at startup; file integrity | S |
| P1 | RT-HIGH-2 | SYSTEM-only entropy; offline rule signing | M |
| P1 | RT-HIGH-3 | Kill rate limits + protected process list + install soak mode | M |
| P2 | RT-MEDIUM-4 | Native SCM for driver disable; IP/service name validation; drop cmd tray | S |
| P2 | BT-MEDIUM-3 | Sanitize machine-specific appsettings before publish | S |
| P3 | RT-MEDIUM-2 | Align DPAPI flags; document SYSTEM scope | S |
| P3 | Observability | ACL logs; health metric for proxy success rate | S |

---

## Red-team scenario scorecard (vs skilled local attacker)

| Scenario | Expected outcome | Confidence |
|----------|------------------|------------|
| Commodity ransomware (shadow + bulk encrypt) | Detect + kill/quarantine | HIGH |
| LSASS dump / canary trip | Detect + respond | HIGH |
| Office → PowerShell LOLBin | Detect / correlate | HIGH |
| Signed Program Files C2 beacon | NetworkIsolate (not LogOnly) | HIGH |
| User allowlist hides C2 | Should **not** fully suppress | HIGH |
| Disable ActiveResponse via JSON + restart | **Bypass active response** | HIGH (finding) |
| Admin `sc stop` / kill | Service dies; watchdog delay only | HIGH (limit) |
| Forge worker reports from internet | **Likely succeeds** if secret unset | HIGH (finding) |
| Inject unsigned dynamic kill rule without entropy | Rejected | HIGH |
| Inject signed dynamic rule as admin | Succeeds | HIGH (finding) |
| BYOVD / kernel | Win | HIGH (limit) |

---

## Blue-team operational checklist

1. Confirm service runs as SYSTEM; agent in user session; both version **1.5.9**
2. Verify `ActiveResponse` true **after reboot** (not just after install)
3. Confirm Secure dir ACL; consider tightening to SYSTEM-only for `.install_entropy`
4. Probe threat proxy: signed report must succeed; unauthenticated must fail
5. Review quarantine folder weekly; wire `events.jsonl` to SIEM
6. Keep HVCI / Memory Integrity on; Secure Boot on
7. Run as standard user day-to-day
8. After upgrades, re-run catalog/self-exclusion smoke tests (explorer, powershell not quarantined)
9. Document that remote admin ports may be blocked by hardening
10. Keep Defender (or equivalent) enabled — Sentinel is a layer, not a replacement

---

## Conclusion

**Red team:** Sentinel is hard to *quietly* evade as a **non-admin** living-off-the-land actor: ETW, correlation, canaries, and C2 floors are real. As **local admin**, the product can be stopped or neutered; the most interesting *remaining* quiet path is **ActiveResponse false at boot**, plus **abuse of the cloud threat proxy** if deployed with optional auth. Dynamic rules are well fixed against entropy *deletion* but not against admin *read* of entropy.

**Blue team:** Design maturity is high for an open-source userland EDR (fail-closed rules, path self-exclusion, President’s Law, post-1.5.8 hardening cleanup). Operational trust is undercut by a **broken reporting client/server contract** and incomplete **config integrity**. Prioritize those two before expanding monitor count.

**Audit disposition:** **CONDITIONAL PASS** — ship/use as secondary EDR with eyes open; **do not** claim secure community reporting or tamper-proof ActiveResponse until P0 items land.

---

## Remediation status (v1.6.0)

| Finding | Status in 1.6.0 |
|---------|-----------------|
| RT-CRITICAL-1 Threat proxy auth | **Fixed** — server-side secret HMAC; no `X-Sentinel-Key` |
| RT-HIGH-1 ActiveResponse boot | **Fixed** — force-enable at StartAsync + appsettings hash |
| RT-HIGH-2 Admin rule forgery | **Fixed** — SYSTEM-only entropy; rules dir write SYSTEM-only |
| RT-HIGH-3 Kill weaponization | **Fixed** — MaxKillsPerMinute + expanded protected processes |
| RT-MEDIUM worker/agent mismatch | **Fixed** — ProxyAuthHelper shared contract |
| RT-MEDIUM DPAPI scope | **Fixed** — LOCAL_MACHINE + legacy fallback |
| RT-MEDIUM LOLBins (sc/tray/cast) | **Fixed** — native SCM, notepad ArgumentList, IP validation |
| BT-MEDIUM machine-specific config | **Fixed** — ProtectedApps cleared in committed appsettings |

*Remediated in release 1.6.0 (2026-07-25).*
