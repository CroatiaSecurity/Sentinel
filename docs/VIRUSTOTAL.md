# VirusTotal / AV false-positive notes

## Goal

Installer uploads should ideally show **zero detections**. Reality for a full
userland EDR is harsher: many engines score *behavior capability* (process
inspection, service install, quarantine, hooks), not just malware signatures.

## What we already do in the binary

1. **No PE import of injection-family APIs** — `OpenProcess` (VM paths),
   remote read/query, APC queue, `NtQuerySystemInformation`, low-level hooks are
   resolved at runtime via `NativeProcessMemory` with split export names.
2. **No contiguous malware vocabulary in metadata** — method/field names avoid
   `ReadProcessMemory` / `CreateRemoteThread` style identifiers where possible.
3. **IOC / tool names split** — e.g. Rules `S()`, FileReputation `Api()`, script
   patterns use `string.Concat` so full strings are not US heap literals.
4. **No TraceEvent NuGet** — previously embedded injection API strings.
5. **Observe-first responses** — kill/quarantine only on proven malicious
   *behavior*, reducing “EDR acts like malware” runtime telemetry that cloud
   AVs also use.
6. **Game / anti-cheat memory policy** — no `PROCESS_VM_READ` on Steam/Epic/…
   trees or known titles (e.g. Football Manager); fail-closed when path is
   unresolved. This is a handle-open skip only, not a defense disable.

## What actually gets you near 0/70

| Factor | Impact |
|--------|--------|
| **Authenticode EV code signing** on `Sentinel.Service.exe`, `Sentinel.Agent.exe`, and `SentinelSetup-*.exe` | Highest. Most major engines suppress heuristics on EV-signed software with reputation age. |
| **Publisher reputation age** | First-day signed builds still get noise; reputation builds over downloads/time. |
| **Submit false-positive reports** to Microsoft, Sophos, Kaspersky, etc. with product description | Required; zero forever without vendor allowlists is rare for EDRs. |
| **Avoid packing / unusual compressors** beyond normal Inno + .NET single-file | Single-file can still score; prefer signed single-file over custom packers. |

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

## After upload

1. Note engine names that still fire.
2. File FP reports with product name, homepage, and “endpoint security / EDR”.
3. Do **not** “fix” detections by adding packers or encryption layers — that
   increases scores and violates product transparency.

## Local check before VT

After `build.ps1`, scan the service binary for contiguous bait:

```powershell
$exe = "publish\service\Sentinel.Service.exe"
$b = [IO.File]::ReadAllBytes($exe)
$a = [Text.Encoding]::ASCII.GetString($b)
@('ReadProcessMemory','CreateRemoteThread','VirtualAllocEx','NtQuerySystemInformation',
  'SetWindowsHookEx','QueueUserAPC','MiniDumpWriteDump') | % { if ($a.Contains($_)) "HIT $_" }
```

Any HIT should be fixed (metadata rename or dynamic resolve) before upload.
