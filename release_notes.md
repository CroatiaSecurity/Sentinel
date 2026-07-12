# v1.4.0 — NTLite/DISM Compatibility + Critical False Positive Fix

## Critical Fix: svchost and powershell Killed/Quarantined

`HardeningModule.IsCriticalProcessName` — the final kill gate used by every response path — was missing `svchost` and `powershell`/`pwsh`. Both existed in ChainTracer's internal exclusion lists, but anything that called `SafeKillProcessTree` directly (composite detections, implant hunters, etc.) bypassed those lists entirely.

**Added to `IsCriticalProcessName`**: `svchost`, `powershell`, `pwsh`

The path-verification guard still applies — a binary named `svchost.exe` running from `C:\Temp\` is **not** protected and will still be killed. Only processes verified to reside under `C:\Windows\` are shielded.

This release fixes two distinct issues that caused Sentinel to interfere with NTLite and DISM offline image servicing operations.

## What's Fixed

### 🔧 File Locking Inside Mounted WIM Images (Unmount Blocked)
NTLite mounts Windows images as a drive letter. Sentinel was extending `FileActivityMonitor` to those drives, causing Restart Manager handle scans on every file event inside the image — competing with NTLite's write locks and preventing unmount.

- **`VolumeMountMonitor`**: Skips `AddWatchPath` for CDRom-type drives (how Windows exposes mounted WIM images) and when any known servicing process (`dism`, `dismhost`, `ntlite`, `tiworker`, `trustedinstaller`) is running.
- **`FileVerdictScanner`**: No longer opens files inside WinSxS, Windows Servicing, CBS logs, or DISM temp directories for hash reputation checks when a servicing process is active.
- **`RawDiskAccessMonitor`**: Added `dismhost`, `ntlite`, `imagemounter`, `arsenalimager`, `aimdevice`, `aim_ll` to the allowed-processes list — these open virtual disk/volume handles during WIM mount/unmount.

### 🔧 Feature-Disable Stalling (Minutes-Long Hangs)
NTLite's feature-disable operation writes hundreds of manifests, deltas, and catalogs into WinSxS and DISM scratch directories. Each write was triggering a Restart Manager scan, creating a handle-contention storm that stalled operations for several minutes.

- **`FileActivityMonitor`**: CBS/component-store paths (`\windows\winsxs\`, `\windows\servicing\`, DISM temp/log dirs) now skip the Restart Manager call entirely.
- **`FileActivityMonitor`**: `ntlite` added to `IsTrustedSystemWriter()` — NTLite committing signed binaries into an offline image's System32 no longer triggers the System Integrity detection rule.

**Security**: All excluded paths remain covered by process-level monitoring (WMI/ETW) and `RawDiskAccessMonitor`. Only the per-file Restart Manager handle scan is skipped for OS-servicing tool paths.
