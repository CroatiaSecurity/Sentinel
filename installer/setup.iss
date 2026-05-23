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
#ifndef AppVersion
  #define AppVersion   "3.5.0"
#endif
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
CloseApplications=no
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Service binary
Source: "publish\service\{#ServiceExe}"; DestDir: "{app}"; Flags: ignoreversion restartreplace uninsrestartdelete
; Agent binary (launched into user session by the service)
Source: "publish\agent\{#AgentExe}";    DestDir: "{app}"; Flags: ignoreversion restartreplace uninsrestartdelete
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
; ── Service teardown is handled in [Code] PrepareToInstall()
; ── which runs BEFORE file-lock checks and extraction. Only post-install steps remain here.

; ── Install and start the new service
Filename: "{sys}\sc.exe"; Parameters: "create ""{#ServiceName}"" binPath= ""{app}\{#ServiceExe}"" start= auto DisplayName= ""{#AppName}"""; Flags: runhidden waituntilterminated; StatusMsg: "Installing service..."
Filename: "{sys}\sc.exe"; Parameters: "description ""{#ServiceName}"" ""Windows Sentinel - Endpoint Detection and Response"""; Flags: runhidden waituntilterminated

; ── Start the service BEFORE applying tamper protection
; (BA needs SERVICE_START permission, which the tamper DACL removes)
Filename: "{sys}\sc.exe"; Parameters: "start ""{#ServiceName}"""; Flags: runhidden waituntilterminated; StatusMsg: "Starting service..."

; ── Tamper Protection (Service ACLs) — applied AFTER start
; SY: All access.
; BA: Read/Query + WRITE_DAC only. Stop/start/delete blocked, but WD is kept
;     so the installer can reset this DACL on future upgrades via sc sdset.
; IU/SU: Read/Query only.
Filename: "{sys}\sc.exe"; Parameters: "sdset ""{#ServiceName}"" D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRCWD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"; Flags: runhidden waituntilterminated; StatusMsg: "Applying Tamper Protection..."

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

// Check whether a process is still running by asking tasklist and piping
// through findstr. findstr exit code: 0 = found, 1 = not found.
function IsProcessRunning(ExeName: String): Boolean;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{cmd}'),
       '/c tasklist /fi "IMAGENAME eq ' + ExeName + '" 2>nul | findstr /i "' + ExeName + '" >nul 2>&1',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := (ResultCode = 0);
end;

// Polls until the named process disappears from the process list.
// Returns true once it is gone, false on timeout.
function WaitForProcessExit(ExeName: String; MaxSeconds: Integer): Boolean;
var
  Retries: Integer;
begin
  Retries := 0;
  while IsProcessRunning(ExeName) and (Retries < MaxSeconds) do
  begin
    Log('  ' + ExeName + ' still running (' + IntToStr(Retries + 1) + '/' + IntToStr(MaxSeconds) + 's)...');
    Sleep(1000);
    Retries := Retries + 1;
  end;
  Result := not IsProcessRunning(ExeName);
end;

// Tear down the previous Sentinel installation BEFORE files are extracted.
// This must run in [Code] because [Run] fires AFTER file extraction,
// and the service EXE cannot be overwritten while the process is running.
//
// STRATEGY: Kill the agent first. Empirically, when the agent dies the service
// shuts itself down. Then force-kill anything remaining via multiple methods.
// We use PowerShell Stop-Process as fallback because taskkill /f from an admin
// installer sometimes cannot terminate SYSTEM processes, while Stop-Process
// with -Force can (it uses TerminateProcess with PROCESS_TERMINATE access).
procedure TearDownExistingService();
var
  ResultCode : Integer;
  Retries    : Integer;
  DataDir    : String;
begin
  if not ServiceExists() then
  begin
    // Service doesn't exist but processes might be orphaned — kill them anyway
    Exec(ExpandConstant('{sys}\taskkill.exe'),
         '/f /im {#AgentExe}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\taskkill.exe'),
         '/f /im {#ServiceExe}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    WaitForProcessExit('{#ServiceExe}', 5);
    WaitForProcessExit('{#AgentExe}', 5);
    Exit;
  end;

  Log('Upgrade: tearing down existing service...');

  // 1. Reset tamper-protected ACLs so we can issue sc stop/delete.
  Exec(ExpandConstant('{sys}\sc.exe'),
       'sdset "' + '{#ServiceName}' + '" D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('  ACL reset result: ' + IntToStr(ResultCode));

  // 2. Kill agent — this is the primary kill mechanism.
  //    When the agent dies, the service detects it and shuts down.
  Exec(ExpandConstant('{sys}\taskkill.exe'),
       '/f /im {#AgentExe}',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('  taskkill agent result: ' + IntToStr(ResultCode));

  // Also try PowerShell Stop-Process (works when taskkill doesn't)
  Exec('powershell.exe',
       '-NonInteractive -WindowStyle Hidden -Command "Stop-Process -Name SentinelAgent -Force -ErrorAction SilentlyContinue"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // 3. Wait for service to self-terminate after agent death (up to 10s).
  //    This matches the observed behavior: kill agent → service stops.
  Log('  Waiting for service to self-terminate after agent kill...');
  if WaitForProcessExit('{#ServiceExe}', 10) then
  begin
    Log('  Service self-terminated after agent kill.');
  end
  else
  begin
    // 4. Service didn't self-terminate — force stop via SCM + kill.
    Log('  Service still running — forcing stop...');

    Exec(ExpandConstant('{sys}\sc.exe'),
         'stop "' + '{#ServiceName}' + '"',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Log('  sc stop result: ' + IntToStr(ResultCode));

    // Wait a bit for graceful stop
    WaitForProcessExit('{#ServiceExe}', 5);

    // Force kill via taskkill
    Exec(ExpandConstant('{sys}\taskkill.exe'),
         '/f /im {#ServiceExe}',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Log('  taskkill service result: ' + IntToStr(ResultCode));

    // Nuclear option: PowerShell Stop-Process -Force (uses TerminateProcess API)
    Exec('powershell.exe',
         '-NonInteractive -WindowStyle Hidden -Command "Stop-Process -Name SentinelService -Force -ErrorAction SilentlyContinue"',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Log('  PowerShell Stop-Process result: ' + IntToStr(ResultCode));

    // Last resort: wmic (deprecated but still works on most Windows 10/11)
    Exec(ExpandConstant('{cmd}'),
         '/c wmic process where "name=''SentinelService.exe''" call terminate >nul 2>&1',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  // 5. Mop-up: kill any respawned agent
  Exec(ExpandConstant('{sys}\taskkill.exe'),
       '/f /im {#AgentExe}',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('powershell.exe',
       '-NonInteractive -WindowStyle Hidden -Command "Stop-Process -Name SentinelAgent -Force -ErrorAction SilentlyContinue"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // 6. Final wait — MUST confirm both processes are gone before proceeding.
  Log('  Final wait for processes to fully exit...');
  if WaitForProcessExit('{#ServiceExe}', 30) then
    Log('  {#ServiceExe} exited.')
  else
    Log('  WARNING: {#ServiceExe} still running after 30 s — extraction WILL fail.');

  if WaitForProcessExit('{#AgentExe}', 10) then
    Log('  {#AgentExe} exited.')
  else
    Log('  WARNING: {#AgentExe} still running after 10 s.');

  // 7. Extra delay: even after process exit, Windows may hold file handles
  //    briefly (kernel object teardown, antivirus scanning, etc.).
  Sleep(2000);

  // 7b. Verify we can actually access the file before proceeding.
  //     If we can't rename it, the handle is still held.
  if FileExists(ExpandConstant('{app}\{#ServiceExe}')) then
  begin
    Retries := 0;
    while (Retries < 10) do
    begin
      if RenameFile(ExpandConstant('{app}\{#ServiceExe}'), ExpandConstant('{app}\{#ServiceExe}.old')) then
      begin
        Log('  File rename succeeded — handle released. Cleaning up.');
        DeleteFile(ExpandConstant('{app}\{#ServiceExe}.old'));
        Break;
      end;
      Log('  File still locked (attempt ' + IntToStr(Retries + 1) + '/10)...');
      Sleep(1000);
      Retries := Retries + 1;
    end;
  end;

  // 8. Delete the service from SCM.
  Exec(ExpandConstant('{sys}\sc.exe'),
       'delete "' + '{#ServiceName}' + '"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('  sc delete result: ' + IntToStr(ResultCode));

  // 8. Poll until SCM fully purges the service entry.
  Retries := 0;
  while ServiceExists() and (Retries < 15) do
  begin
    Log('  Waiting for SCM to purge service entry (attempt ' + IntToStr(Retries + 1) + ')...');
    Sleep(1000);
    Retries := Retries + 1;
  end;

  if ServiceExists() then
    Log('  WARNING: Service entry still present after 15 seconds (SCM ghost)')
  else
    Log('  Service entry fully purged from SCM.');

  // 9. Clean up stale log files.
  DataDir := ExpandConstant('{commonappdata}\WindowsSentinel');
  if FileExists(DataDir + '\events.jsonl') then
  begin
    Log('  Renaming stale events.jsonl...');
    if not RenameFile(DataDir + '\events.jsonl', DataDir + '\events.jsonl.upgrade-backup') then
    begin
      Log('  Rename failed — attempting delete...');
      DeleteFile(DataDir + '\events.jsonl');
    end;
  end;
end;

// PrepareToInstall fires BEFORE Inno Setup checks file locks.
// This is critical: if we wait until ssInstall, Inno Setup's file-lock
// detection shows a "retry" dialog before our teardown code runs.
// By tearing down here, the processes are already dead when Inno checks locks.
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';  // Empty string = no error, proceed with install
  NeedsRestart := False;
  TearDownExistingService();
  AddDefenderExclusions();
end;

// CurStepChanged kept for any future post-teardown logic.
procedure CurStepChanged(CurStep: TSetupStep);
begin
  // Teardown moved to PrepareToInstall (runs before file-lock checks).
  // This hook is kept for extensibility.
end;

// CurUninstallStepChanged fires during uninstall.
// usUninstall fires before files are removed.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RemoveDefenderExclusions();
end;


