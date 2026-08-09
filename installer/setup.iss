[Setup]
AppName=Sentinel
AppVersion=2.0.5
AppPublisher=Gorstak
AppPublisherURL=https://gorstak.eu
SourceDir=.
DefaultDirName={autopf}\Sentinel
DefaultGroupName=Sentinel
SetupIconFile=assets\Sentinel.ico
UninstallDisplayIcon={app}\Sentinel.ico
Compression=lzma2
SolidCompression=yes
OutputDir=.
OutputBaseFilename=SentinelSetup-2.0.5
PrivilegesRequired=admin
; One active Setup wizard at a time (elevation handoff still works: non-elevated exits first)
SetupMutex=Global\SentinelSetupMutex
; Allow upgrading over existing install
UsePreviousAppDir=yes
CloseApplications=no
RestartApplications=no


[Files]
; Framework-dependent net48 publish: all managed deps + exes (small installer; needs .NET 4.8)
Source: "assets\Sentinel.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\service\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\publish\agent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; v2.0.4: appsettings.json is no longer shipped — config uses compiled defaults + DPAPI-encrypted store.
; If the file exists from a prior install, it is ignored (but detected as suspicious by AntiTamperGuard).

[Icons]
Name: "{group}\Sentinel Agent"; Filename: "{app}\Sentinel.Agent.exe"; IconFilename: "{app}\Sentinel.ico"

[Registry]
; Auto-start agent on user login
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "SentinelAgent"; ValueData: """{app}\Sentinel.Agent.exe"""; Flags: uninsdeletevalue
; v1.4.2: Register service for Safe Mode (both Minimal and Network)
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\Sentinel"; ValueType: string; ValueName: ""; ValueData: "Service"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Sentinel"; ValueType: string; ValueName: ""; ValueData: "Service"; Flags: uninsdeletekey
; v2.0.4 HIGH-4: Removed FIPS Algorithm Policy manipulation. An EDR must not weaken
; system cryptographic posture. Organizations with FIPS compliance (FedRAMP, HIPAA, DoD)
; should not have their policy overridden by security tooling.

[Run]
; Clean up .old files from rename-on-upgrade fallback (ignore failures — silent)
; Force exit 0 even if no .old files — avoids post-install error popup
Filename: "{sys}\cmd.exe"; Parameters: "/c del /f /q ""{app}\*.old"" 2>nul & exit /b 0"; Flags: runhidden waituntilterminated
; Service install + agent start run from Pascal (ssPostInstall) so upgrades never show
; "sc create failed" / "service already running" error dialogs.

[UninstallRun]
; Stop and delete the service
Filename: "{sys}\sc.exe"; Parameters: "stop ""Sentinel"""; Flags: runhidden; RunOnceId: "StopService"
Filename: "{sys}\sc.exe"; Parameters: "delete ""Sentinel"""; Flags: runhidden; RunOnceId: "DeleteService"

[UninstallDelete]
; Remove application directory (but NOT ProgramData logs)
Type: filesandordirs; Name: "{app}"
; Remove Program Files (x86) leftovers if previous install was there
Type: filesandordirs; Name: "{commonpf32}\Sentinel"

[Code]
// Pascal Script for upgrade/uninstall logic
//
// Dual-process Inno flow (outer EXE + elevated/temp "2nd" setup):
// After a successful install, close leftover sibling Setup processes and stamp
// completion so a leftover first wizard cannot run install again.

const
  SetupStampKey = 'Software\Sentinel\Setup';
  // How long a leftover first wizard is blocked after the real install finishes
  SetupSiblingBlockMinutes = 30;

function GetCurrentProcessId: Cardinal;
  external 'GetCurrentProcessId@kernel32.dll stdcall';

function GetTickCount: Cardinal;
  external 'GetTickCount@kernel32.dll stdcall';

procedure MarkInstallCompleted();
var
  Ver: String;
begin
  Ver := ExpandConstant('{#SetupSetting("AppVersion")}');
  // Tick count is enough for "recent sibling" detection within one boot session
  RegWriteStringValue(HKLM, SetupStampKey, 'LastCompletedVersion', Ver);
  RegWriteDWordValue(HKLM, SetupStampKey, 'LastCompletedTicks', GetTickCount());
end;

procedure ClearInstallCompletedStamp();
begin
  RegDeleteValue(HKLM, SetupStampKey, 'LastCompletedVersion');
  RegDeleteValue(HKLM, SetupStampKey, 'LastCompletedTicks');
  RegDeleteKeyIfEmpty(HKLM, SetupStampKey);
end;

function WasSameVersionJustInstalled(): Boolean;
var
  Ver, CompletedVer: String;
  Ticks, NowTicks, WindowMs, Elapsed: Cardinal;
begin
  Result := False;
  Ver := ExpandConstant('{#SetupSetting("AppVersion")}');

  if not RegQueryStringValue(HKLM, SetupStampKey, 'LastCompletedVersion', CompletedVer) then
    Exit;
  if not SameText(CompletedVer, Ver) then
    Exit;
  if not RegQueryDWordValue(HKLM, SetupStampKey, 'LastCompletedTicks', Ticks) then
    Exit;

  NowTicks := GetTickCount();
  // Unsigned wrap-safe elapsed (GetTickCount wraps ~49 days)
  Elapsed := NowTicks - Ticks;
  WindowMs := SetupSiblingBlockMinutes * 60 * 1000;
  if Elapsed <= WindowMs then
    Result := True;
end;

// Close other SentinelSetup*.exe / *.tmp processes so a leftover first wizard
// cannot continue after the elevated/temp install finished.
procedure CloseSiblingSetupProcesses();
var
  ResultCode: Integer;
  PsPath: String;
  Cmd: String;
  MyPid: String;
begin
  MyPid := IntToStr(GetCurrentProcessId());
  PsPath := ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe');
  // Only SentinelSetup* images — do not touch unrelated Inno installers (Git, etc.)
  Cmd :=
    '-ExecutionPolicy Bypass -Command "' +
    '$exclude = ' + MyPid + '; ' +
    'Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { ' +
    '  $_.ProcessId -ne $exclude -and ( ' +
    '    $_.Name -like ''SentinelSetup*'' -or ' +
    '    ($_.ExecutablePath -and ($_.ExecutablePath -like ''*SentinelSetup*'')) ' +
    '  ) ' +
    '} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"';
  Exec(PsPath, Cmd, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// .NET Framework 4.8 (Release DWORD >= 528040). Framework-dependent install.
function IsDotNet48OrHigher(): Boolean;
var
  Release: Cardinal;
begin
  Result := False;
  // Prefer 64-bit view of the registry (Inno 32-bit setup on x64 Windows)
  if IsWin64 then
  begin
    if RegQueryDWordValue(HKLM64, 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', Release) then
    begin
      Result := Release >= 528040;
      Exit;
    end;
  end;
  if RegQueryDWordValue(HKLM, 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', Release) then
    Result := Release >= 528040;
end;

function OfferDotNet48Download(): Boolean;
var
  ErrCode: Integer;
  Choice: Integer;
begin
  // Returns True if setup should continue (4.8 present or user insisted).
  Result := False;
  Choice := MsgBox(
    'Sentinel requires .NET Framework 4.8, which was not found on this PC.' + #13#10#13#10 +
    'Most Windows 10/11 systems already have it. If Setup cannot detect it, install ' +
    'the official Microsoft runtime, then run this installer again.' + #13#10#13#10 +
    'Yes = open the Microsoft .NET Framework 4.8 download page' + #13#10 +
    'No  = cancel Setup',
    mbConfirmation, MB_YESNO);
  if Choice = IDYES then
  begin
    // Official download hub (web installer / offline packages)
    ShellExec('open',
      'https://dotnet.microsoft.com/download/dotnet-framework/net48',
      '', '', SW_SHOWNORMAL, ewNoWait, ErrCode);
    MsgBox(
      'After .NET Framework 4.8 finishes installing, run SentinelSetup again.' + #13#10 +
      'A reboot may be required before Setup can detect the runtime.',
      mbInformation, MB_OK);
  end;
  Result := False;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  // Leftover first wizard after a successful 2nd install: refuse to install again
  if WasSameVersionJustInstalled() then
  begin
    MsgBox(
      'Sentinel ' + ExpandConstant('{#SetupSetting("AppVersion")}') +
      ' was already installed successfully.' + #13#10#13#10 +
      'This leftover Setup window cannot install again. Click OK to close it.',
      mbInformation, MB_OK);
    Result := False;
    Exit;
  end;

  // Minimum runtime: .NET Framework 4.8 (assume present; offer download if missing)
  if not IsDotNet48OrHigher() then
  begin
    Result := OfferDotNet48Download();
  end;
end;

// Idempotent service install — never surface sc.exe exit codes to the user.
// create fails (1073) when service exists; start fails (1056) when already running.
procedure InstallOrUpdateService();
var
  ResultCode: Integer;
  Sc: String;
  BinPath: String;
begin
  Sc := ExpandConstant('{sysnative}\sc.exe');
  if not FileExists(Sc) then
    Sc := ExpandConstant('{sys}\sc.exe');
  BinPath := ExpandConstant('{app}\Sentinel.Service.exe');

  // create (fresh) or config (upgrade / reinstall)
  Exec(Sc, 'create "Sentinel" start= auto binPath= "' + BinPath + '"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if ResultCode <> 0 then
    Exec(Sc, 'config "Sentinel" binPath= "' + BinPath + '" start= auto',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  Exec(Sc, 'description "Sentinel" "Userland Endpoint Detection & Response (EDR) Service"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(Sc, 'failure "Sentinel" reset= 86400 actions= restart/1000/restart/5000/restart/30000',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // start — ignore "already running"
  Exec(Sc, 'start "Sentinel"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// Start tray agent in the interactive user session without error dialogs.
procedure LaunchAgentSilent();
var
  AgentPath: String;
  ErrCode: Integer;
begin
  AgentPath := ExpandConstant('{app}\Sentinel.Agent.exe');
  if not FileExists(AgentPath) then
    Exit;
  // ShellExec + no wait: Process.Start style; does not treat non-zero as setup failure
  ShellExec('open', AgentPath, '', ExpandConstant('{app}'), SW_HIDE, ewNoWait, ErrCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  // After files are in place: register service, start agent tray, stamp success
  if CurStep = ssPostInstall then
  begin
    InstallOrUpdateService();
    LaunchAgentSilent();
    MarkInstallCompleted();
    CloseSiblingSetupProcesses();
  end;
end;

procedure StopServiceByName(const ServiceName: String);
var
  ResultCode: Integer;
  PsPath: String;
  Cmd: String;
begin
  PsPath := ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe');

  // CRITICAL: Disable failure recovery first so sc stop does not auto-restart.
  Exec(ExpandConstant('{sysnative}\sc.exe'), 'failure "' + ServiceName + '" reset= 86400 actions= ""', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\sc.exe'), 'stop "' + ServiceName + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // Poll until STOPPED (or timeout ~10s)
  Cmd := '-ExecutionPolicy Bypass -Command "for ($i = 0; $i -lt 20; $i++) { $out = & sc.exe queryex ''' + ServiceName + ''' 2>&1; if ($out -match ''STOPPED'') { break }; Start-Sleep -Milliseconds 500 }"';
  Exec(PsPath, Cmd, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure ResetInstallDirAcls(const DirPath: String);
var
  ResultCode: Integer;
begin
  if not DirExists(DirPath) then
    Exit;

  Exec(ExpandConstant('{sysnative}\takeown.exe'), '/F "' + DirPath + '" /R /A /D Y', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\icacls.exe'), '"' + DirPath + '" /grant Administrators:F /T /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\icacls.exe'), '"' + DirPath + '" /grant SYSTEM:F /T /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\icacls.exe'), '"' + DirPath + '" /remove:d Users /T /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\icacls.exe'), '"' + DirPath + '" /remove:d *S-1-5-32-545 /T /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\icacls.exe'), '"' + DirPath + '" /remove:d Everyone /T /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\icacls.exe'), '"' + DirPath + '" /reset /T /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure StopExistingService();
var
  ResultCode: Integer;
  PsPath: String;
begin
  // Use {sysnative} to bypass WOW64 redirection — ensures we reach the real 64-bit
  // PowerShell and sc.exe even when the installer runs as a 32-bit process.
  PsPath := ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe');

  StopServiceByName('Sentinel');

  // Kill any remaining Sentinel processes
  Exec(PsPath, '-ExecutionPolicy Bypass -Command "foreach ($i in 1..5) { $procs = Get-Process -Name ''Sentinel.Service'',''Sentinel.Agent'' -ErrorAction SilentlyContinue; if (-not $procs) { break }; $procs | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 500 }"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1000);
  Exec(PsPath, '-ExecutionPolicy Bypass -Command "Get-Process -Name ''Sentinel.Service'',''Sentinel.Agent'' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(500);

  // Reset ACLs on install directories
  ResetInstallDirAcls(ExpandConstant('{app}'));
  ResetInstallDirAcls(ExpandConstant('{commonpf32}\Sentinel'));

  // NOW try rename as final fallback (ACLs are reset, file should be writable)
  if FileExists(ExpandConstant('{app}\Sentinel.Service.exe')) then
    RenameFile(ExpandConstant('{app}\Sentinel.Service.exe'), ExpandConstant('{app}\Sentinel.Service.exe.old'));
  if FileExists(ExpandConstant('{app}\Sentinel.Agent.exe')) then
    RenameFile(ExpandConstant('{app}\Sentinel.Agent.exe'), ExpandConstant('{app}\Sentinel.Agent.exe.old'));
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';

  // Leftover first wizard already past InitializeSetup when the 2nd finished:
  // block the actual install step (sibling kill should already have closed this).
  if WasSameVersionJustInstalled() then
  begin
    Result :=
      'Sentinel was already installed successfully by another Setup window. ' +
      'Close this leftover Setup; do not install again from here.';
    Exit;
  end;

  // If upgrading (existing install present), stop service and reset ACLs
  if RegValueExists(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SentinelAgent') or
     RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\Sentinel') or
     DirExists(ExpandConstant('{app}')) or
     DirExists(ExpandConstant('{commonpf32}\Sentinel')) then
  begin
    StopExistingService();
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    // Stop service before uninstall
    StopExistingService();

    // Allow a fresh Setup after uninstall (clear sibling-block stamp)
    ClearInstallCompletedStamp();

    // Remove Sentinel registry keys
    RegDeleteValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SentinelAgent');

    // Delete service via SCM
    Exec(ExpandConstant('{sys}\sc.exe'), 'delete "Sentinel"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // Remove Program Files leftovers
    DelTree(ExpandConstant('{pf32}\Sentinel'), True, True, True);

    // Clean up persistent items created by the app
    // 1. Delete ShowAllTrayIcons scheduled task
    Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /TN "ShowAllTrayIcons" /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // 2. Delete GSecurity IPSec policy
    Exec(ExpandConstant('{sys}\netsh.exe'), 'ipsec static delete policy name=GSecurity', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // 3. Delete RPC dynamic ports blocker firewall rule
    Exec(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall delete rule name="Sentinel-Block-Remote-RPC-Ephemeral"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // NOTE: ProgramData\Sentinel logs are intentionally PRESERVED
  end;
end;
