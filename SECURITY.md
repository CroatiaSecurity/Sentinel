# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | Yes (current: 2.0.4) |
| 1.9.x   | Security fixes only |
| 1.8.x   | Security fixes only |
| < 1.8   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in Sentinel, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **Email:** Send details to the repository owner via the email address listed on the [GitHub profile](https://github.com/croatiasecurity).

2. **GitHub Private Vulnerability Reporting:** Use GitHub's [private vulnerability reporting](https://github.com/croatiasecurity/sentinel/security/advisories/new) feature if available on the repository.

3. **Include the following in your report:**
   - Description of the vulnerability
   - Steps to reproduce
   - Impact assessment (what an attacker can achieve)
   - Affected version(s)
   - Suggested fix (if you have one)

### What to Expect

- **Acknowledgment:** Within 48 hours of receiving your report.
- **Assessment:** Within 7 days, we will confirm whether the issue is valid and its severity.
- **Fix timeline:** Critical vulnerabilities will be patched within 14 days. High-severity within 30 days.
- **Credit:** You will be credited in the CHANGELOG and release notes unless you prefer to remain anonymous.

### Scope

The following are in scope for security reports:

- Bypass of detection rules (attacker can evade Sentinel without kernel access)
- Self-exclusion bypass (attacker can make Sentinel ignore their process)
- Cache/HMAC poisoning (attacker can forge safe verdicts)
- Privilege escalation via Sentinel (Sentinel's actions can be leveraged by an attacker)
- Command injection via any input that reaches Process.Start or shell execution
- Denial of service against Sentinel (crash or resource exhaustion)
- Information disclosure from Sentinel's logs, cache, or quarantine
- Tampering with Sentinel's configuration or binaries without detection
- **IPC token theft or replay** — forging or replaying authenticated named-pipe commands (v2.0+)
- **Rule pack signature bypass** — loading unsigned or tampered `.pack.json` correlation rules (v2.0+)
- **Plugin registry abuse** — injecting malicious `IDetector` / `ICorrelationRule` / `IResponsePlugin` implementations (v2.0+)
- **Weighted correlation score manipulation** — crafting signals to trigger false chain-nukes via score cards (v2.0+)

The following are NOT in scope:

- Attacks requiring kernel-level access (documented limitation in THREAT_MODEL.md)
- Attacks requiring physical disk access while machine is powered off
- Social engineering of the machine operator
- Vulnerabilities in third-party dependencies (report upstream, notify us)

## Attack Surface (v2.0)

### Service-Agent IPC (`SentinelIpc-v2` named pipe)

- **Auth model:** HMAC-SHA256 over `timestamp|nonce|op|body` with a 32-byte random token stored at `%ProgramData%\Sentinel\Secure\.ipc_token`. Token file is ACL-locked (SYSTEM full, Admins full, Authenticated Users read).
- **Replay protection:** 60-second timestamp window.
- **Read-only commands only:** `ping`, `ops`, `health`. No ActiveResponse toggle over IPC.
- **Pipe ACL:** SYSTEM + Authenticated Users (user session Agent can connect).
- **v2.0.4:** Server-side nonce tracking prevents replay attacks within the 60s timestamp window.
- **v2.0.4:** Pipe name includes machine-unique suffix (anti-fingerprinting).
- **v2.0.4:** Rule packs now use RSA-SHA256 asymmetric signatures (private key never on endpoint).
- **v2.0.3:** Token file is now written atomically with pre-set ACL to eliminate creation-time race.

### Signed Rule Packs (`%ProgramData%\Sentinel\rules\packs\`)

- `.pack.json` files are verified via HMAC before loading.
- Fail-closed: unsigned or tampered packs are rejected and logged.
- Packs can only register `ICorrelationRule` implementations (no response actions or host mutations).
- The pack signer key is derived from the machine-bound DPAPI secret.

### Plugin Registry

- `IDetector`, `ITelemetryProvider`, `ICorrelationRule`, `IResponsePlugin` interfaces.
- Only in-process plugin registration (no disk DLL loading) — requires modifying the binary or rule packs.
- Response plugins cannot bypass `ResponsePolicy` tier law or `ObserveUntilChain` gates.

### Threat Intelligence Proxy

- HMAC-SHA256 authenticated requests (shared secret never transmitted in headers since v1.8.1).
- The Cloudflare Worker proxy fails closed if `SENTINEL_SHARED_SECRET` is unset.
- Minimum 16-character secret enforced client-side.

### Ops Metrics (`ops_metrics.json`)

- Written to `%ProgramData%\Sentinel\` (ACL-restricted directory).
- Contains operational counters only (no secrets, no event content, no detection evidence).
- Agent reads via IPC (preferred) or file fallback.

## Previously Fixed Vulnerabilities

See [CHANGELOG.md](CHANGELOG.md) for the full history of security fixes, including:

- v2.0.4: Full red team audit remediation (asymmetric rule pack signing, IPC nonce tracking, EncryptedConfigStore, cert pinning, FIPS enforcement removed)
- v2.0.3: IPC token ACL race fix (atomic write with pre-set security descriptor)
- v2.0.0: RT-CRIT-3 HMAC key derivation with DPAPI machine secret, RT-HIGH-2 SelfPathGuard hardlink-aware exclusion, RT-HIGH-4 authenticated named-pipe IPC
- v1.8.1: RT-CRIT-1 removed cleartext shared secret from request headers, RT-MED-3 restricted ProgramData ACLs
- v1.6.8: Browser C2 detection gaps, indirect syscall evasion, PrintNightmare exploitation, container escape blind spots
- v1.6.0: Threat-proxy auth redesign, ActiveResponse boot enforce, SYSTEM-only entropy, kill rate limits
- v1.4.5: LSA secret storage, Credential Guard monitoring, correlation engine fix
- v1.4.4: 15 red-team findings (command injection, HMAC weakness, handle leaks, self-exclusion bypass)
- v1.1.0: Cache poisoning, process name spoofing, self-exclusion bypass
- v1.0.1: RAM disk staging, WSL evasion, raw disk bypass

## Security Design Philosophy

Sentinel assumes the attacker has read the source code. Security decisions are documented in [THREAT_MODEL.md](THREAT_MODEL.md). We do not rely on security-by-obscurity for any detection or protection mechanism.

Key principles:
- **Fail-closed:** Unknown hashes return `Unknown` (not `Safe`); unsigned rule packs are rejected; unauthenticated IPC commands are dropped.
- **Minimum privilege:** `OpenProcess` requests only the rights actually used; Agent runs as user (not SYSTEM); IPC is read-only.
- **No static mutable state:** All shared state via `ConcurrentDictionary`, `Channel<T>`, or `SemaphoreSlim`.
- **Rate limiting:** Kill budget (15/min), isolate budget (10/min), log burst limiter (1000/5s), Event Log writes (30/min).
- **Graceful degradation:** Missing ETW, Event Log, or toast infrastructure disables features without crashing.
