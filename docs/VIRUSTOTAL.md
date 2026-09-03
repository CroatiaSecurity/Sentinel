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

## VT result: SentinelSetup-2.3.6.exe (2026-09-01)

VirusTotal reported **4/72** on `SentinelSetup-2.3.6.exe` (SHA-256 uploaded by
user). Engines visible in the community UI included:

| Engine | Label |
|--------|--------|
| AhnLab-V3 | `Trojan/Win.Generic.C5905083` |
| Alibaba | `Trojan:Win32/Generic` |
| Alyac | `Generic.MSIL.Ransom.Agent.A.C1F91A0E` |

Local reports also named **Microsoft Defender** and **Kaspersky**. These are
generic / ML labels on an **unsigned** Inno Setup carrier that installs a .NET
EDR (service + Run key + process inspection + DPAPI quarantine). They are not
proof of malware.

## v2.3.8: transparency over evasion (post-2.3.6 VT)

Project history showed two opposite “AV hygiene” strategies fighting each other:

- **v2.3.6:** removed split-string API hiding — Kaspersky ML treats
  `string.Concat("Open","Process")` as **evasion**.
- **v2.3.7:** re-introduced `GetProcAddress` resolution to scrub the IAT —
  Defender / generic ML often treat dynamic resolution of `OpenProcess` /
  `ReadProcessMemory` as **evasion** too.

**v2.3.8 policy:** be a normal, auditable EDR binary. No split-string assembly,
no `GetProcAddress` hiding of inspection APIs. Accept that unsigned EDR will
still draw a few generic hits until **Authenticode (ideally EV)** is applied.

### Changes

1. **`NativeResolver`** — plain `[DllImport]` for process-inspection APIs
   (no runtime export resolution).
2. **Detection vocab** — `Rules` / `FileReputationEngine` / script & agent
   monitors use contiguous literals again (no `S()` / `A()` Concat helpers).
3. **Quarantine vault** — blobs are `SENQ` magic + DPAPI under
   `%ProgramData%\Sentinel\Quarantine\*.senq` (structured EDR vault, not
   in-place user-file encryption). Targets Alyac `MSIL.Ransom.Agent`.
4. **Composite display name** — `Active Mass-Encryption Chain` (was
   `Active Ransomware Chain`) to reduce PE string bait; `SignalType.Ransomware`
   enum kept for compatibility.
5. **Installer** — `VersionInfo*` synced to 2.3.7+; fewer `icacls` trees on
   upgrade; description without `&` entity quirks.

## v2.3.6: AV false positive root causes fixed

Kaspersky flagged `Sentinel.Core.dll` (confirmed via `report.rpt` — path
`C:\Program Files (x86)\Sentinel\Sentinel.Core.dll`). Two patterns were the cause:

### 1. Split-string API name obfuscation (removed)

`NativeProcessMemory.cs` previously resolved Win32 API names at runtime by
concatenating string fragments. Modern ML-based AV engines specifically detect
this as an **evasion indicator**.

**Fix:** standard transparent API usage (see v2.3.8 `NativeResolver`).

### 2. LGPO.exe embedded as assembly resource (removed)

`HardeningModule.cs` previously embedded `LGPO.exe` as an `EmbeddedResource`
and extracted it at runtime — the classic dropper pattern.

**Fix:** `LGPO.exe` and `GSecurity.inf` ship as plain files in the install dir.

## v2.3.7: hooks / APC / installer compression

- Removed APC injection / `VirtualProtectEx` remote patching / global
  `WH_MOUSE_LL` / `WH_KEYBOARD_LL` hooks.
- Installer: non-solid `lzma/max`, full `VersionInfo`, `taskkill` instead of
  PowerShell `-ExecutionPolicy Bypass`.

## What we do in the binary (v2.3.8+)

1. **Read-only process inspection** via normal imports — `OpenProcess`,
   `ReadProcessMemory`, `VirtualQueryEx`, `NtQuerySystemInformation`,
   `DuplicateHandle`, `EnumModules`.
2. **Standard EDR containment** — `SafeKillProcessTree` + disk quarantine vault.
3. **LGPO.exe / GSecurity.inf** as plain files.
4. **Observe-until-chain** responses.
5. **Game / anti-cheat memory policy** — no `PROCESS_VM_READ` on those trees.
6. **Installer** uses `taskkill` + minimal `icacls` on upgrade.

## Local check before VT

After `installer\build.ps1`, verify evasion helpers are gone and vault magic exists:

```powershell
$dll = "publish\service\Sentinel.Core.dll"
$b = [IO.File]::ReadAllBytes($dll)
$a = [Text.Encoding]::ASCII.GetString($b)
@('GetProcAddress') | ForEach-Object {
    # GetProcAddress may still appear as a *scanned* import name string in reputation
    # tables; it must NOT be used to resolve OpenProcess in NativeResolver.
}
# NativeResolver source must use [DllImport], not GetProcAddress.
Select-String -Path src\Sentinel.Core\NativeResolver.cs -Pattern 'GetProcAddress'
# Expect: no matches

@('QueueUserAPC', 'VirtualProtectEx', 'SetWindowsHookExW') | ForEach-Object {
    if ($a.Contains($_)) { "NOTE: $_ present as detection vocabulary (OK if not imported for use)" }
}
```

## Path to 0/N detections

1. Rebuild after v2.3.8 hygiene → re-upload to VirusTotal.
2. Submit false-positive reports to AhnLab / Alibaba / Alyac / Kaspersky /
   Microsoft with publisher info + source URL.
3. **Sign** `SentinelSetup-*.exe`, `Sentinel.Service.exe`, `Sentinel.Agent.exe`,
   and `Sentinel.Core.dll` with an Authenticode certificate (EV preferred).
   Signing is the real prevalence/trust fix; code hygiene only reduces ML bait.
