# Sentinel — Security Audit (Normal / Red / Blue)

**Date:** 2026-08-12 (updated 2026-08-24 with v2.2.4 generic CVE-class coverage)  
**Scope:** Full source review of Sentinel.Core, Service, Agent, installer, Cloudflare Worker, and prior security docs.  
**Audience:** Gaming desktops, creator workstations, high-profile personal targets.  
**Method:** Manual adversarial + defensive review; fixes implemented in this release.

## v2.2.4 — generic CVE-class + quarantine browse

| Item | Honest limit |
|------|----------------|
| New Patch Tuesday CVEs | Hunt userland shape (exploit host, MOTW, MSI/winget, VS Code, unionfs). Not a kernel patch. |
| CISA KEV | Windows OS-class matches this workstation. Server roles only if installed. No fake PoC hashes. |
| Quarantine Explorer | Interactive this-folder-only List/Traverse. Sample blobs stay SYSTEM/Admin. |
| Namespace | All monitor types are `Sentinel.Core`. `Monitors/` is layout. |

## v2.2.3 — August 2026 Patch Tuesday (userland)

| Item | Honest limit |
|------|----------------|
| CVE-2026-68820 afd.sys | Cannot patch the race. Dream Job campaign pack + KEV UBR toast (KB5121003). |
| CVE-2026-62832 LegacyHive | Hive-load / custom HKU / hive reparse. Not a ProfSvc patch. |
| CVE-2026-62713 / ShieldBreak | Unknown CfApi sync roots + staging placeholders. OneDrive not disabled. |

## v2.2.0 — Honest remediations

Items previously marked fixed that were **not** in force, now actually shipped:

| ID | Severity | Finding | 2.2.0 fix |
|----|----------|---------|-----------|
| RT-2026-M3 | High | Bearer skipped on spoofed Referer; token never in HTML | Referer ignored; tray `?token=`; WS requires token |
| RT-2026-V217 | High | Amsi/EDR-killer/honeypot/pipe/kernel/token monitors never registered | Registered in MonitorGroups |
| RT-2026-HONEYPOT | High | 0-byte version.dll/winhttp.dll in install dir = self-sideload | Decoys in `honeypot\` only |
| RT-2026-GAME | High | User-writable `steamapps\common` skipped reputation | Profile/staging paths cannot skip |
| RT-2026-WINTEMP | High | `C:\Windows\` prefix skipped quarantine | System32/SysWOW64 only |
| RT-2026-WATCH | High | Name-only agent liveness; unsigned-pair allow | Install-path match; publisher pin; Debug-only unsigned |
| RT-2026-BYOVD | Medium | SYSTEM profile scan; PID 0; corrupt hash; silent RTCore baseline | User profiles; Event PID; hash removed; pre-existing logged |
| RT-2026-LGPO | High | GSecurity.inf disabled passwords/audit/FIPS | Real baseline; FIPS not touched |
| RT-2026-WORKER | Medium | RATE_LIMITER unused; MB `taginfo` fake-report | Called after HMAC; honest lookup |
| RT-2026-CFG | Medium | ObserveUntilChain bindable from leftover JSON; HMAC comment-only | Forced true; SCFG2 HMAC envelope |

## Executive summary

| Dimension | Rating |
|-----------|--------|
| Overall posture | **Strong** for open-source userland EDR |
| Gamer suitability | **Good** — observe-first, game/anti-cheat paths protected from reputation kills |
| High-profile suitability | **Good with hygiene** — evidence packs + dual trail; not kernel-immortal |
| Residual critical class | Local admin / kernel still wins (documented) |

v2.0.8 remediates SPKI pinning correctness, TI proxy replay, install-dir kill plant, rulepack trust-root swap, installer ACL race, and overly broad IPC/log ACLs.

## Red team findings addressed in 2.0.8

| ID | Severity | Finding | Fix |
|----|----------|---------|-----|
| RT-2026-02 | High | Pin hashed `GetPublicKey()` not SPKI | True SPKI encode + multi-candidate match |
| RT-2026-06 | Medium | Worker 5 min replay, no nonce | 60s + nonce cache; client signs `ts.nonce.path.body` |
| RT-2026-04 | High | Admin-writable rulepack pubkey | External pubkey ignored; embedded only |
| RT-2026-07 | Medium | SafeKill excluded any PE under install | SelfPathGuard known binaries only |
| RT-2026-03 | High | Full-tree installer ACL reset | Per-binary unlock only |
| RT-2026-01 | High | IPC token world-readable (Auth Users) | Interactive SID read; Secure dir SYSTEM+Admin |
| N-5 | Med | events.jsonl Users read | Interactive read only |

## v2.1.8 Red Team Audit — Additional Findings & Remediations

**Auditor:** AI-assisted red team (Kiro) — 2026-08-22  
**Scope:** Full codebase audit including sabotage scan, architecture review, and attack chain modeling.

### Findings FIXED in v2.1.8

| ID | Severity | Finding | Fix |
|----|----------|---------|-----|
| RT-2026-H1 | **High** | AgentWatchdog + Agent self-restart: no binary integrity check before launch (TOCTOU) | Authenticode verification before `CreateProcessAsUser`; unsigned builds require both binaries unsigned |
| RT-2026-H3 | **High** | AntiTamperGuard binary integrity only checks `File.Exists` (not hash/replacement) | SHA-256 baseline at startup; periodic comparison detects binary replacement while running |
| RT-2026-M1 | **Medium** | Worker nonce consumed before HMAC verification (DoS via pre-consumption) | Nonce consumed only AFTER successful HMAC verification |
| RT-2026-M2 | **Medium** | Kill budget exhaustion enables malware execution window | Chain-confirmed detections bypass per-minute rate limit (separate unlimited budget) |
| RT-2026-M3 | **Medium** | WebDashboard lacks auth beyond CSRF (any local process can toggle security) | Bearer token auth on all `/api/` endpoints; constant-time comparison |
| RT-2026-M4 | **Medium** | No input validation on Worker report endpoints (upstream API abuse) | Format validation: hash (MD5/SHA1/SHA256), URL (HTTP(S), no private), IP (valid, no RFC1918) |
| RT-2026-M5 | **Medium** | Worker rate limit + nonce cache reset on cold start | Added Cloudflare Rate Limiting binding in `wrangler.toml` |
| RT-2026-L6 | Low | Worker error handler leaks `err.message` to clients | Error detail removed from response |
| RT-2026-L7 | Low | Worker X-Forwarded-For fallback for IP identification | Removed; CF-Connecting-IP only |

### Findings FIXED in v2.1.9

| ID | Severity | Finding | Fix |
|----|----------|---------|-----|
| RT-2026-XSS1 | **Medium** | Stored XSS in WebDashboard via unsanitized innerHTML interpolation of detection event fields (ProcessName, RuleName, Evidence, file paths). Attacker runs process with crafted name → logged to events.jsonl → rendered raw in dashboard → JS executes in localhost:19845 context → bypasses bearer auth via Referer, gains CSRF token, can toggle hardened mode off. | Added `esc()` HTML entity encoder; all user-controlled data in innerHTML templates now encoded (`&<>"'` → entities). Affected: `renderEvents()`, `loadOps()`, `loadQuarantine()`, scan findings, `loadReportPacks()`. |

### Findings MITIGATED by new detection capabilities in v2.1.8

| Finding | Mitigation |
|---------|-----------|
| BYOVD driver loads bypass SCM events | `KernelModuleAuditMonitor` detects via `NtQuerySystemInformation` |
| EDR-killer tools (54+ in 2026) | `EdrKillerDetectionMonitor` — immediate President's Law fire on known tool names |
| AMSI bypass (VEH/patch) blinds script detection | `AmsiIntegrityCheck` detects function prologue modification |
| DLL sideloading against install directory | `HoneypotDllMonitor` — decoy DLLs trigger on any access |
| C2 pipe-based communication | `DecoyPipeMonitor` — honeypot pipes with CS/Metasploit names |
| Potato attacks / token theft | `TokenPrivilegeAuditMonitor` — dangerous privileges from user-writable paths |

### Sabotage Scan Result (v2.1.8)

**Status: CLEAN.** No backdoors, kill switches, hardcoded credentials, logic bombs, deliberate weakening, test-mode production leaks, suspicious network endpoints, or data exfiltration found. All crypto uses SHA-256/HMAC-SHA256/DPAPI (no weak algorithms).

## Residual accepted risks

1. Local admin can stop/delete the service (userland — no kernel driver by design).
2. Novel kernel / BYOVD with public CA-signed unknown driver may race monitors (mitigated by `KernelModuleAuditMonitor` and `EdrKillerDetectionMonitor`).
3. CIRCL / MalwareBazaar direct HTTPS still uses default trust (VT/report path pinned).
4. Dynamic rules remain host-HMAC (SYSTEM can still forge; fail-closed without entropy).
5. ~~Worker nonce cache is per-isolate~~ — **MITIGATED:** Cloudflare Rate Limiting binding deployed in wrangler.toml.
6. Installer ACL unlock window during upgrade still exists (documented; hardening re-applied on service start).

## Blue team notes

- Dual trail: `events.jsonl` + Windows Event Log Application/Sentinel.
- Chain-confirmed nukes produce integrity-sealed packs under IncidentReports.
- Back up packs off-host for high-profile users.
- Set unique `ProxySharedSecret` (≥16 chars) per deployment.
- Keep Defender + Secure Boot + HVCI where possible.
- New honeypot DLLs in install directory — do NOT delete `version.dll`/`winmm.dll` (they are intentional decoys).
- Decoy named pipes (`msagent_01`, `MSSE-1234-server`, etc.) are intentional — do NOT close them.

## Test coverage

- `V208SecurityHardeningTests`
- Updated `ProxyAuthHelperTests`
- Existing SelfPathGuard / IPC / quarantine suites remain in force.
- Full suite: 1786 tests passing (v2.1.8).

See CHANGELOG.md [2.1.8] for the operator-facing list.
