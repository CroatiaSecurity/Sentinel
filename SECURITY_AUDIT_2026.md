# Sentinel v2.0.8 — Security Audit (Normal / Red / Blue)

**Date:** 2026-08-12  
**Scope:** Full source review of Sentinel.Core, Service, Agent, installer, Cloudflare Worker, and prior security docs.  
**Audience:** Gaming desktops, creator workstations, high-profile personal targets.  
**Method:** Manual adversarial + defensive review; fixes implemented in this release.

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

## Residual accepted risks

1. Local admin can stop/delete the service (userland).
2. Novel kernel / BYOVD with public CA-signed unknown driver may race monitors.
3. CIRCL / MalwareBazaar direct HTTPS still uses default trust (VT/report path pinned).
4. Dynamic rules remain host-HMAC (SYSTEM can still forge; fail-closed without entropy).
5. Worker nonce cache is per-isolate (use CF Rate Limiting for durable production).

## Blue team notes

- Dual trail: `events.jsonl` + Windows Event Log Application/Sentinel.
- Chain-confirmed nukes produce integrity-sealed packs under IncidentReports.
- Back up packs off-host for high-profile users.
- Set unique `ProxySharedSecret` (≥16 chars) per deployment.
- Keep Defender + Secure Boot + HVCI where possible.

## Test coverage

- `V208SecurityHardeningTests`
- Updated `ProxyAuthHelperTests`
- Existing SelfPathGuard / IPC / quarantine suites remain in force.

See CHANGELOG.md [2.0.8] for the operator-facing list.
