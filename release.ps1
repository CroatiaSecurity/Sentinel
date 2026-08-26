$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.3.0.exe"

$notes = @"
## v2.3.0 — Dashboard Redesign (GBrowser Theme + IE11 Fix)

The embedded web dashboard has been completely rewritten with a new visual theme
and full IE11 WebBrowser control compatibility.

### What changed

- **Dashboard theme**: Redesigned with GBrowser-inspired dark/creamy/mica palette
  - Dark charcoal backgrounds (#202124), creamy blue accent (#8AB4F8)
  - Mica-style `backdrop-filter: blur()` on sidebar and header
  - Segoe UI font, tighter spacing, refined color hierarchy
- **IE11 compatibility fix**: All JavaScript rewritten to ES5
  - Replaced `fetch()` with `XMLHttpRequest`
  - Removed arrow functions, `const`/`let`, template literals, `async/await`
  - Navigation click handlers now use `onclick` + `getElementsByClassName`
  - `URLSearchParams` replaced with regex-based token extraction
  - `NodeList.forEach` replaced with classic `for` loops
- **Navigation fix**: Sidebar tabs now work correctly in the WebBrowser control
- All previous v2.2.9 features (WMI persistence, web dashboard, hardened mode) retained

### Previous features still included

- Unified web dashboard (REST API + WebSocket on localhost:19845)
- Bearer token authentication, CSRF protection, constant-time comparison
- WMI persistence triple snapshot, hostile consumer detection
- ETW provider #10 for WMI-Activity
- Hardened mode toggle from dashboard

## Installation
Requires .NET Framework 4.8. Run as Administrator.
Open Settings from the Sentinel tray icon.
"@

if (Test-Path $gh) {
    & $gh release create v2.3.0 $installer --title "Sentinel 2.3.0" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.3.0\"
}
