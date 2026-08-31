
$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.3.4.exe"

$notes = @"
## v2.3.4 — Full loadable-module-extension unload coverage

The DLL/module unloader now applies module identity to **every** mapped PE regardless
of file extension — not just ``.dll``.

### Changed

- **Module identity spans every loadable extension.** ``DllUnloadEngine`` enumerates every
  mapped module via ``EnumProcessModules`` regardless of extension and evaluates each through
  ``ModuleIdentity.Evaluate`` (path + Microsoft-family signature). A foreign / user-writable-drop /
  non-keep-tree module is unloaded whether it is a ``.dll``, a managed ``.winmd`` (WinRT metadata
  carrying MSIL), an ``.ocx``, ``.cpl``, ``.ax``, ``.node``, ``.drv``, ``.acm``, ``.tsp``, ``.mui``,
  or ``.efi``. System-provided metadata-only ``.winmd`` stays keep-tree.
- New ``ModuleIdentity.ModuleExtensions`` / ``IsModuleFileName`` and
  ``DllUnloadEngine.IsLoadableModuleFileName`` so filename-keyed helpers are no longer ``.dll``-only.
- Search-order hijack names (``dbghelp``/``version``/``winmm``/…) remain the classic ``.dll``
  ``SideloadTargets`` set — those names are only ever sideloaded as ``.dll``.
- ``ProductInfo.Version`` -> 2.3.4

## Installation
Requires .NET Framework 4.8. Run as Administrator.
Open Settings from the Sentinel tray icon.
"@

if (Test-Path $gh) {
    & $gh release create v2.3.4 $installer --title "Sentinel 2.3.4" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.3.4\"
}
