## What's New

### Fixed: AntiTamperGuard Service Name Mismatch

The anti-tamper self-protection module was continuously detecting a false "Service Registration Deleted" event every 10 seconds since initial install. This caused:

- ~8,640 false detection/response event pairs per day in `events.jsonl` (6 MB/day log bloat)
- Constant warning spam in the Windows Application Event Log
- Unnecessary CPU/IO overhead from repeated `sc.exe create` re-registration attempts

**Root cause:** The `ServiceName` constant was `"WindowsSentinel"` but the actual Windows service is registered as `"Windows Sentinel"` (with a space). The `ServiceController` lookup threw `InvalidOperationException` on every integrity check, which the anti-tamper logic interpreted as a deleted service registration.

**Fix:** Corrected the service name constant and quoted it in all `sc.exe` command invocations for proper space handling.

**Full Changelog**: https://github.com/CroatiaSecurity/Sentinel/compare/v1.2.7...v1.2.8
