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

## v2.3.7: Transition from APC Injection to EDR Process Containment & Zero-Detection Architecture

In v2.3.6, heuristic scanners (Microsoft `Wacatac.C!ml`, DeepInstinct, Kaspersky, Skyhigh `ObfuscatedPoly`) flagged the binary due to residual injection/hooking primitives and installer compression profile.

### 1. Removal of APC Injection & Cross-Process Memory Patching

`NativeProcessMemory.cs` and `DllUnloadEngine.cs` previously attempted to unmap hostile DLLs from live remote processes via `QueueUserAPC(FreeLibrary)` and stripped page execution permissions via `VirtualProtectEx`.
- In Windows userland, once a hostile DLL loads, `DllMain` has already run. Queuing `FreeLibrary` via `QueueUserAPC` into foreign threads is dangerous (causes target crashes) and unreliable (requires alertable sleep).
- Statically, `OpenThread(0x10)` + `QueueUserAPC` + `VirtualProtectEx` matches the exact signature of Early Bird APC injection droppers (triggering `Trojan:Win32/Wacatac.C!ml`).

**Fix (v2.3.7):**
- Replaced remote APC unloading with industry-standard EDR **Process Containment (`HardeningModule.SafeKillProcessTree`)** and **atomic disk quarantine (`QuarantineManager`)**.
- Completely removed `QueueUserAPC`, `OpenThread`, `VirtualProtectEx`, `FreeLibrary`, `SetWindowsHookExW`, and `UnhookWindowsHookEx` from `NativeProcessMemory.cs`.

### 2. Removal of Global Low-Level Windows Hooks

`ClickjackingGuard` (`WH_MOUSE_LL`) and `PhantomKeystrokeGuard` (`WH_KEYBOARD_LL`) previously installed global input hooks across the OS, matching keylogger and spyware heuristics (`HEUR:Trojan.Win32.Generic`).

**Fix (v2.3.7):**
- Removed global hooks. `ClickjackingGuard` uses non-intrusive window geometry analysis (`EnumWindows`, `GetWindowLong`, `GetLayeredWindowAttributes`, `GetWindowRect`) and fake UAC classification. `PhantomKeystrokeGuard` uses `LASTINPUTINFO` and process ancestry telemetry.

### 3. Installer Compression & Metadata Tuning

Skyhigh SWG heuristic `BehavesLike.Win32.ObfuscatedPoly.tc` scored Inno Setup's monolithic solid `lzma2` compression as packed/polymorphic.

**Fix (v2.3.7):**
- Tuned `setup.iss` to use non-solid `lzma/max` with complete `[VersionInfo]` properties (`VersionInfoCompany`, `VersionInfoDescription`, `VersionInfoVersion`, `VersionInfoCopyright`, `VersionInfoProductName`).

---

## What we do in the binary (v2.3.7+)

1. **Read-only process inspection primitives** — `OpenProcess` (Query/VMRead), `ReadProcessMemory`, `VirtualQueryEx`, `NtQuerySystemInformation`, `DuplicateHandle`, and `EnumModules`. No APC injection or remote memory patching APIs exist in the binary.
2. **Standard EDR containment** — Compromised processes with unauthorized modules are terminated via `SafeKillProcessTree` and hostile DLLs are quarantined on disk.
3. **LGPO.exe and GSecurity.inf shipped as plain files** — not embedded in assembly resources.
4. **Observe-until-chain responses** — kill/quarantine on multi-signal proof of terminal attack.
5. **Game / anti-cheat memory policy** — no `PROCESS_VM_READ` on Steam/Epic/… trees or known titles; fail-closed when path is unresolved.
6. **Installer uses `taskkill`** for process termination during upgrades.
7. **Clean Inno Setup profile** with non-solid stream compression and comprehensive PE metadata.

## Local check before VT

After `build.ps1`, verify that injection APIs are completely absent from `Sentinel.Core.dll`:

```powershell
$dll = "publish\service\Sentinel.Core.dll"
$b = [IO.File]::ReadAllBytes($dll)
$a = [Text.Encoding]::ASCII.GetString($b)
@('QueueUserAPC', 'VirtualProtectEx', 'SetWindowsHookExW') | ForEach-Object {
    if ($a.Contains($_)) { "WARNING: $_ present" } else { "PASS: $_ absent" }
}
```

All should report `PASS: absent`.
