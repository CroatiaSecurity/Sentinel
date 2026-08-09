$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.0.4.exe"

$notes = @"
Security hardening release — full red team audit remediation.

## Security Fixes (v2.0.4)

### Critical
- **CRIT-1:** IPC nonce replay prevention (server-side nonce tracking with bounded set)
- **CRIT-2:** Rule pack signing switched from HMAC (symmetric) to RSA-SHA256 (asymmetric) — private key never on endpoint
- **CRIT-3:** EnforceActiveResponse defaults to true — AntiTamperGuard force-re-enables if disabled

### High
- **HIGH-1:** Process-specific DPAPI entropy in SecureCacheStore (binary hash in key derivation)
- **HIGH-2:** Removed wildcard CORS from Cloudflare Worker proxy
- **HIGH-3:** Certificate pinning for Worker proxy endpoint (Cloudflare CA pins)
- **HIGH-4:** Removed FIPS Algorithm Policy enforcement (installer + AntiTamperGuard)
- **HIGH-5:** ReleaseUserWorkSurface scoped to Sentinel-created rules only

### Medium
- **MED-1:** Worker rate limit reduced to 30/min with cold-start documentation
- **MED-2:** IsSafeString now blocks &;|{}() shell metacharacters
- **MED-3:** Documented QueueUserAPC risks in DllUnloadEngine
- **MED-4:** Quarantine .meta files encrypted with DPAPI
- **MED-5:** Named pipe uses machine-unique suffix (anti-fingerprinting)
- **MED-6:** RulePackLoader reads with file lock (TOCTOU prevention)

### Low
- **LOW-1:** Proxy health monitoring (consecutive failure counter)
- **LOW-2:** ACL operation failures now logged (not silently swallowed)
- **LOW-4:** Documented process hollowing detection limitation

### Major Enhancement
- **Eliminated appsettings.json as attack surface** — all config uses compiled defaults + DPAPI-encrypted store
- New ``--set-config Key=Value`` CLI for secret management
- AntiTamperGuard alerts if unauthorized appsettings.json appears on disk

## Installation
Requires .NET Framework 4.8 (already present on most Windows 10/11 systems). Run as Administrator.

## Post-Install: Set Secrets
``Sentinel.Service.exe --set-config ProxySharedSecret=your-secret-here``
"@

& $gh release create v2.0.4 $installer --title "Sentinel 2.0.4" --notes $notes
