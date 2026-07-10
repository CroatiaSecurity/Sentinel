## What's New in v1.3.0

### Security Hardening: 18 Patches from Red-Team Audit Pass 2

Comprehensive hardening of the scoring pipeline, response engine, exclusion lists, and trust verification across all monitors. This release fixes the most critical issue since inception: **Sentinel was detecting threats but refusing to act on most of them.**

#### CRITICAL — Response Engine Was Firing Blanks

- **Tier1 detections now KILL** — Previously, any Tier1 detection not in the "President's Law" categories was silently demoted to LogOnly. C2 Beaconing, Ghost Processes, DLL Sideloading, Attack Tools — all detected but never killed. Fixed.
- **Hash scanner no longer skips Temp/Cache dirs** — Malware staging areas were excluded from reputation scanning
- **API failures no longer mark files as "safe"** — Unknown verdicts are retried instead of permanently cached

#### HIGH — Name-Only Bypasses Eliminated

- **All allowlists now require signature or path verification** — NetworkAllowlist, DoH allowlist, browser checks, ephemeral process lists all previously used name-only matching. An attacker naming malware `chrome.exe` or `cloudflared.exe` bypassed detection entirely.
- **DNS trusted domains slashed** — Removed googleapis.com, amazonaws.com, cloudfront.net, github.com, and 15+ other CDN/cloud domains that attackers use for C2 hosting
- **Baseline trust harder to earn** — 10 executions required (was 3), scoring reductions capped at -20 (was uncapped at -70)
- **Dedup window tightened** — 10s for Tier1 (was 60s), attackers can't trigger one alert then operate freely

#### MEDIUM — Defense in Depth

- Signature cache invalidates when files are modified on disk
- PowerShell signature fallback removed (PATH poisoning vector)
- Telemetry chain buffer increased 5x to prevent evidence flooding
- Exfiltration detection threshold lowered 4x

#### LOW — Anti-Detection & Input Safety

- Sandbox job object names randomized (anti-fingerprinting)
- Docker/VM response inputs sanitized against command injection

**Full Changelog**: https://github.com/CroatiaSecurity/Sentinel/compare/v1.2.9...v1.3.0
