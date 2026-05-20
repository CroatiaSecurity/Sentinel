; Windows Sentinel - Inno Setup Installer Script
; Author: Gorstak
;
; Prerequisites:
;   - Inno Setup 6.x  (https://jrsoftware.org/isinfo.php)
;   - Publish the service first:
;       dotnet publish src\WindowsSentinel.Service\WindowsSentinel.Service.csproj ^
;           -c Release -r win-x64 --self-contained true ^
;           -p:PublishSingleFile=true -o installer\publish\service
;       dotnet publish src\WindowsSentinel.Agent\WindowsSentinel.Agent.csproj ^
;           -c Release -r win-x64 --self-contained true ^
;           -p:PublishSingleFile=true -o installer\publish\agent
;
; Output: installer\output\WindowsSentinelSetup.exe

#define AppName      "Windows Sentinel"
#define AppVersion   "2.8.0"
#define AppPublisher "Gorstak"
#define AppURL       "https://github.com/CroatiaSecurity/Sentinel"
#define ServiceName  "Windows Sentinel"
#define ServiceExe   "SentinelService.exe"
#define AgentExe     "SentinelAgent.exe"
#define AppDataDir   "{commonappdata}\WindowsSentinel"

[Setup]
AppId={{B4E2F1A3-7C9D-4E5F-8A2B-1D3C6E9F0B4A}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\WindowsSentinel
DisableDirPage=yes
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; No desktop shortcut option — Sentinel is a background service, not a user app
; DesktopIconPage is intentionally omitted
OutputDir=output
OutputBaseFilename=WindowsSentinelSetup-{#AppVersion}
SetupIconFile=assets\sentinel.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=
; Require Windows 10 1809+ (ETW APIs used by monitors)
MinVersion=10.0.17763
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
UninstallDisplayIcon={app}\{#ServiceExe}
UninstallDisplayName={#AppName}
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Service binary
Source: "publish\service\{#ServiceExe}"; DestDir: "{app}"; Flags: ignoreversion
; Agent binary (launched into user session by the service)
Source: "publish\agent\{#AgentExe}";    DestDir: "{app}"; Flags: ignoreversion
; Configuration
; v0.6.0: drop "onlyifdoesntexist" so upgrades pick up the new ActiveResponse=true default.
; If a user customized LogPath/WatchPath they will need to re-apply (logged in release notes).
Source: "publish\service\appsettings.json"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
; Create the quarantine and log directories under ProgramData upfront
; so they exist even before the first detection fires.
; SECURITY FIX: Removed everyone-full permissions. Now restricted to:
; - SYSTEM: Full control (service runs as SYSTEM or admin)
; - Administrators: Full control (admin management)
; - Users: Read/Execute only (normal users can read logs but not modify)
Name: "{commonappdata}\WindowsSentinel";           Permissions: system-full admins-full users-readexec
Name: "{commonappdata}\WindowsSentinel\Quarantine"; Permissions: system-full admins-full
; SECURITY: Quarantine is restricted - only SYSTEM and Admins can access
; This prevents tampering with quarantined malware
Name: "{commonappdata}\WindowsSentinel\Logs";       Permissions: system-full admins-full users-readexec

[Run]
; ── Service teardown is now handled in [Code] CurStepChanged(ssInstall)
; ── so it runs BEFORE file extraction. Only post-install steps remain here.

; ── Install and start the new service
Filename: "{sys}\sc.exe"; Parameters: "create ""{#ServiceName}"" binPath= ""{app}\{#ServiceExe}"" start= auto DisplayName= ""{#AppName}"""; Flags: runhidden waituntilterminated; StatusMsg: "Installing service..."
Filename: "{sys}\sc.exe"; Parameters: "description ""{#ServiceName}"" ""Windows Sentinel - Endpoint Detection and Response"""; Flags: runhidden waituntilterminated

; ── Start the service BEFORE applying tamper protection
; (BA needs SERVICE_START permission, which the tamper DACL removes)
Filename: "{sys}\sc.exe"; Parameters: "start ""{#ServiceName}"""; Flags: runhidden waituntilterminated; StatusMsg: "Starting service..."

; ── Tamper Protection (Service ACLs) — applied AFTER start
; SY: All access. BA/IU/SU: Read/Query only (no stop, no delete, no start).
Filename: "{sys}\sc.exe"; Parameters: "sdset ""{#ServiceName}"" D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"; Flags: runhidden waituntilterminated; StatusMsg: "Applying Tamper Protection..."

[UninstallRun]
; Reset DACL to allow uninstallation (admins back to full control)
Filename: "{sys}\sc.exe"; Parameters: "sdset ""{#ServiceName}"" D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"; Flags: runhidden waituntilterminated
; Kill agent first, then stop and remove the service
Filename: "{sys}\taskkill.exe"; Parameters: "/f /im {#AgentExe}"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "stop ""{#ServiceName}""";   Flags: runhidden waituntilterminated
Filename: "{sys}\taskkill.exe"; Parameters: "/f /im {#ServiceExe}"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "delete ""{#ServiceName}"""; Flags: runhidden waituntilterminated
; Remove Defender exclusions
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NonInteractive -WindowStyle Hidden -Command ""Remove-MpPreference -ExclusionPath '{app}' -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NonInteractive -WindowStyle Hidden -Command ""Remove-MpPreference -ExclusionPath '{commonappdata}\WindowsSentinel' -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NonInteractive -WindowStyle Hidden -Command ""Remove-MpPreference -ExclusionProcess 'SentinelService.exe' -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NonInteractive -WindowStyle Hidden -Command ""Remove-MpPreference -ExclusionProcess 'SentinelAgent.exe' -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated

[UninstallDelete]
; Remove the install directory
Type: filesandordirs; Name: "{app}"
; Leave {commonappdata}\WindowsSentinel intact so logs and quarantine survive uninstall.
; Uncomment the lines below to wipe everything on uninstall:
; Type: filesandordirs; Name: "{commonappdata}\WindowsSentinel\Quarantine"
; Type: filesandordirs; Name: "{commonappdata}\WindowsSentinel\Logs"
; Type: filesandordirs; Name: "{commonappdata}\WindowsSentinel"

[Code]
// Adds Defender exclusions BEFORE files are extracted (ssInstall step),
// so the binaries are never scanned as they land on disk.
procedure AddDefenderExclusions();
var
  AppDir    : String;
  DataDir   : String;
  ResultCode: Integer;
begin
  AppDir  := ExpandConstant('{autopf}\WindowsSentinel');
  DataDir := ExpandConstant('{commonappdata}\WindowsSentinel');

  // Path exclusion for install directory only (binaries)
  Exec('powershell.exe',
       '-NonInteractive -WindowStyle Hidden -Command ' +
       '"Add-MpPreference -ExclusionPath ''' + AppDir + ''' -ErrorAction SilentlyContinue"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // REMOVED: Broad %ProgramData%\WindowsSentinel exclusion.
  // Quarantined files are now DPAPI-encrypted so Defender won't flag them.
  // The quarantine directory is also ACL-hardened (SYSTEM + Admins only).
  // Excluding the entire data directory was a security risk — attackers could
  // drop malware there and Defender would never scan it.

  // Process exclusions
  Exec('powershell.exe',
       '-NonInteractive -WindowStyle Hidden -Command ' +
       '"Add-MpPreference -ExclusionProcess ''SentinelService.exe'' -ErrorAction SilentlyContinue"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  Exec('powershell.exe',
       '-NonInteractive -WindowStyle Hidden -Command ' +
       '"Add-MpPreference -ExclusionProcess ''SentinelAgent.exe'' -ErrorAction SilentlyContinue"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure RemoveDefenderExclusions();
var
  AppDir    : String;
  DataDir   : String;
  ResultCode: Integer;
begin
  AppDir  := ExpandConstant('{autopf}\WindowsSentinel');
  DataDir := ExpandConstant('{commonappdata}\WindowsSentinel');

  Exec('powershell.exe',
       '-NonInteractive -WindowStyle Hidden -Command ' +
       '"Remove-MpPreference -ExclusionPath ''' + AppDir + ''' -ErrorAction SilentlyContinue"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  Exec('powershell.exe',
       '-NonInteractive -WindowStyle Hidden -Command ' +
       '"Remove-MpPreference -ExclusionPath ''' + DataDir + ''' -ErrorAction SilentlyContinue"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  Exec('powershell.exe',
       '-NonInteractive -WindowStyle Hidden -Command ' +
       '"Remove-MpPreference -ExclusionProcess ''SentinelService.exe'' -ErrorAction SilentlyContinue"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  Exec('powershell.exe',
       '-NonInteractive -WindowStyle Hidden -Command ' +
       '"Remove-MpPreference -ExclusionProcess ''SentinelAgent.exe'' -ErrorAction SilentlyContinue"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// Check whether the service already exists before trying to stop/delete it.
function ServiceExists(): Boolean;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'query "' + '{#ServiceName}' + '"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := (ResultCode = 0);
end;

// Tear down the previous Sentinel installation BEFORE files are extracted.
// This must run in [Code] because [Run] fires AFTER file extraction,
// and the service EXE cannot be overwritten while the process is running.
procedure TearDownExistingService();
var
  ResultCode: Integer;
  Retries   : Integer;
  DataDir   : String;
begin
  if not ServiceExists() then
    Exit;

  Log('Upgrade: tearing down existing service...');

  // 1. Reset tamper-protected ACLs so we can interact with the service via SCM.
  //    (The hardened DACL strips BA's stop/delete rights.)
  Exec(ExpandConstant('{sys}\sc.exe'),
       'sdset "' + '{#ServiceName}' + '" D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('  ACL reset result: ' + IntToStr(ResultCode));

  // 2. Kill agent first — this typically crashes the service as well.
  Exec(ExpandConstant('{sys}\taskkill.exe'),
       '/f /im {#AgentExe}',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // 3. Try sc stop (may work now that ACLs are reset).
  Exec(ExpandConstant('{sys}\sc.exe'),
       'stop "' + '{#ServiceName}' + '"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // 4. Force-kill service process (belt and suspenders).
  Exec(ExpandConstant('{sys}\taskkill.exe'),
       '/f /im {#ServiceExe}',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // 5. Wait for processes to fully exit and release file handles.
  Sleep(3000);

  // 6. Delete the service from SCM.
  Exec(ExpandConstant('{sys}\sc.exe'),
       'delete "' + '{#ServiceName}' + '"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('  sc delete result: ' + IntToStr(ResultCode));

  // 7. Poll until SCM fully purges the service entry (max ~15 seconds).
  //    sc delete only marks for deletion; the entry lingers until all handles close.
  Retries := 0;
  while ServiceExists() and (Retries < 15) do
  begin
    Log('  Waiting for SCM to purge service entry (attempt ' + IntToStr(Retries + 1) + ')...');
    Sleep(1000);
    Retries := Retries + 1;
  end;

  if ServiceExists() then
    Log('  WARNING: Service entry still present after 15 seconds (SCM ghost) — will attempt sc create anyway')
  else
    Log('  Service entry fully purged from SCM.');

  // 8. Clean up stale log files that might be locked or have bad ACLs.
  //    This prevents the new service from crashing on startup due to
  //    UnauthorizedAccessException on events.jsonl left by previous installs.
  DataDir := ExpandConstant('{commonappdata}\WindowsSentinel');
  if FileExists(DataDir + '\events.jsonl') then
  begin
    Log('  Renaming stale events.jsonl to prevent startup failures...');
    if not RenameFile(DataDir + '\events.jsonl', DataDir + '\events.jsonl.upgrade-backup') then
    begin
      Log('  Rename failed — attempting delete...');
      DeleteFile(DataDir + '\events.jsonl');
    end;
  end;
end;

// CurStepChanged fires at well-defined points in the install lifecycle.
// ssInstall fires just before files are extracted — exactly what we need.
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
  begin
    TearDownExistingService();
    AddDefenderExclusions();
  end;
end;

// CurUninstallStepChanged fires during uninstall.
// usUninstall fires before files are removed.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RemoveDefenderExclusions();
end;


