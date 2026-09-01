# VirusTotal / AV false-positive notes

## Goal

Installer uploads should ideally show **zero detections**. Reality for a full
userland EDR is harsher: many engines score *behavior capability* (process
inspection, service install, quarantine, hooks), not just malware signatures.

### ASR / "ransomware" blocks are not the same as VT

Microsoft Defender **Attack Surface Reduction** rule
`c1db55ab-…` is named *"Use advanced protection against ransomware"*. When it
fires (Event 1121), it is **blocking untrusted/low-prevalence EXEs** (often
Inno Setup extractors under `%TEMP%`) — **not** a classification that
"Sentinel is ransomware."

Still, Sentinel must **never enable that rule in Block mode** against itself
(see `HardeningModule.AsrRulesNeverBlock`). Unsigned Setup + that rule = Error 5
on upgrade. **Code signing** is what makes prevalence/trust pass for both ASR
and most VT engines.

## v2.3.6: AV false positive root causes fixed

Kaspersky flagged `Sentinel.Core.dll` (confirmed via `report.rpt` — path
`C:\Program Files (x86)\Sentinel\Sentinel.Core.dll`). Two patterns were the cause:

### 1. Split-string API name obfuscation (removed)

`NativeProcessMemory.cs` previously resolved Win32 API names at runtime by
concatenating string fragments:

```csharp
// Old approach — now removed
private static readonly Lazy<DOpen?> FnOpen = new(() => Resolve<DOpen>("kernel32.dll", J("Open", "Process")));
private static readonly Lazy<DQueue?> FnQueue = new(() => Resolve<DQueue>("kernel32.dll", J("QueueUser", "APC")));
```

The comment literally said *"Export names are never stored as contiguous literals
(AV / VT heuristics)"*. Modern ML-based AV engines (Kaspersky, Defender, etc.)
specifically detect this `J("Open","Process")` concatenation pattern as an
**evasion indicator**, scoring it *higher* than a plain import. It was
self-defeating.

**Fix (v2.3.6):** All APIs are declared with standard `[DllImport]` attributes.
The binary is now fully transparent and auditable — exactly what a legitimate
security product should be.

### 2. LGPO.exe embedded as assembly resource (removed)

`HardeningModule.cs` previously embedded `LGPO.exe` (Microsoft's Local Group
Policy Object utility) as an `EmbeddedResource` in `Sentinel.Core.dll` and
extracted it to `%ProgramData%\Sentinel\HardeningTemp\LGPO.exe` at runtime:

```csharp
// Old approach — now removed
string? lgpoPath = ExtractResource(assembly, "Sentinel.Core.HardeningResources.LGPO.exe", tempDir, "LGPO.exe");
using var proc = Process.Start(new ProcessStartInfo(lgpoPath, $"/s \"{infPath}\""));
```

A PE file hidden inside a DLL that drops itself to disk and executes is the
canonical **dropper/packer** signature. It doesn't matter that LGPO.exe is a
Microsoft utility — the *pattern* scores as malware.

**Fix (v2.3.6):** `LGPO.exe` and `GSecurity.inf` are shipped as plain files
alongside `Sentinel.Service.exe` in the installation directory. The build script
copies them from `src/Sentinel.Core/HardeningResources/` to both publish trees.
They are inspectable by any scanner at rest.

## What we do in the binary (v2.3.6+)

1. **Direct `[DllImport]` for all Win32 APIs** — `OpenProcess`, `ReadProcessMemory`,
   `VirtualProtectEx`, `VirtualQueryEx`, `OpenThread`, `QueueUserAPC`,
   `NtQuerySystemInformation`, `SetWindowsHookExW`, `DuplicateHandle` are all
   declared transparently. No runtime resolution, no split strings.
2. **LGPO.exe and GSecurity.inf shipped as plain files** — not embedded in the
   assembly. Located beside the service binary in the install directory.
3. **Observe-until-chain responses** — kill/quarantine only after multi-signal
   proof of terminal attack (C2/exfil/token/shell/cred-dump/BYOVD), reducing
   "EDR acts like malware" runtime telemetry that cloud AVs also use.
4. **Game / anti-cheat memory policy** — no `PROCESS_VM_READ` on Steam/Epic/…
   trees or known titles; fail-closed when path is unresolved.
5. **Installer uses `taskkill`** for process termination during upgrades (not
   PowerShell `-ExecutionPolicy Bypass` + `Stop-Process -Force`).
6. **Minimal ACL unlock** — `ResetInstallDirAcls` uses 2 targeted `icacls` calls
   instead of the previous 8-call `takeown /R` + `icacls` tree walk.

## What actually gets you near 0/70

| Factor | Impact |
|--------|--------|
| **Authenticode EV code signing** on `Sentinel.Service.exe`, `Sentinel.Agent.exe`, and `SentinelSetup-*.exe` | Highest. Most major engines suppress heuristics on EV-signed software with reputation age. |
| **Publisher reputation age** | First-day signed builds still get noise; reputation builds over downloads/time. |
| **Submit false-positive reports** to Microsoft, Sophos, Kaspersky, etc. with product description | Required; zero forever without vendor allowlists is rare for EDRs. |
| **Avoid packing / unusual compressors** beyond normal Inno + .NET | Prefer signed over custom packers. |

**Unsigned self-contained EDR installers almost never stay at 0/70.** Treat
signing as a release gate for VT cleanliness.

## How to sign (release pipeline)

```text
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a SentinelSetup-x.y.z.exe
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a publish\service\Sentinel.Service.exe
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a publish\agent\Sentinel.Agent.exe
```

Wire the same into `installer/build.ps1` after publish when a cert is available
(environment variable `SENTINEL_SIGN_THUMBPRINT` or similar).

## Submitting to Kaspersky

Kaspersky has a false-positive submission portal at
[opentip.kaspersky.com](https://opentip.kaspersky.com/). Upload the installer
EXE and describe the product as "Endpoint Detection and Response (EDR) security
tool." With the v2.3.6 fixes in place this submission should result in a clean
whitelist entry.

## After upload

1. Note engine names that still fire.
2. File FP reports with product name, homepage, and "endpoint security / EDR".
3. Do **not** "fix" detections by adding packers or obfuscation layers — that
   increases scores and violates product transparency.

## Local check before VT

After `build.ps1`, verify that API names are visible (expected — transparency
is correct for a legitimate security product):

```powershell
$dll = "publish\service\Sentinel.Core.dll"
$b = [IO.File]::ReadAllBytes($dll)
$a = [Text.Encoding]::ASCII.GetString($b)
@('OpenProcess','ReadProcessMemory','VirtualProtectEx','NtQuerySystemInformation',
  'SetWindowsHookExW','QueueUserAPC') | % { if ($a.Contains($_)) "VISIBLE: $_" else "MISSING: $_" }
```

All six should show `VISIBLE` — that is correct and expected. A legitimate EDR
declares its capabilities openly. Missing entries would indicate obfuscation
crept back in.

Also confirm LGPO.exe is **not** embedded in the DLL:

```powershell
$dll = "publish\service\Sentinel.Core.dll"
$b = [IO.File]::ReadAllBytes($dll)
$a = [Text.Encoding]::ASCII.GetString($b)
if ($a.Contains("MZ") -and $b.Length -gt 500000) { "WARNING: possible embedded PE" } else { "OK: no embedded PE detected" }
# Verify LGPO.exe ships as a file
Test-Path "publish\service\LGPO.exe"   # should be True
Test-Path "publish\service\GSecurity.inf"  # should be True
```
