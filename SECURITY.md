# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.5.x   | Yes       |
| 1.4.x   | Security fixes only |
| < 1.4   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in Windows Sentinel, please report it responsibly.

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

The following are NOT in scope:

- Attacks requiring kernel-level access (documented limitation in THREAT_MODEL.md)
- Attacks requiring physical disk access while machine is powered off
- Social engineering of the machine operator
- Vulnerabilities in third-party dependencies (report upstream, notify us)

### Previously Fixed Vulnerabilities

See [CHANGELOG.md](CHANGELOG.md) for the full history of security fixes, including:

- v1.4.5: LSA secret storage, Credential Guard monitoring, correlation engine fix
- v1.4.4: 15 red-team findings (command injection, HMAC weakness, handle leaks, self-exclusion bypass)
- v1.1.0: Cache poisoning, process name spoofing, self-exclusion bypass
- v1.0.1: RAM disk staging, WSL evasion, raw disk bypass

### Security Design Philosophy

Sentinel assumes the attacker has read the source code. Security decisions are documented in [THREAT_MODEL.md](THREAT_MODEL.md). We do not rely on security-by-obscurity for any detection or protection mechanism.
