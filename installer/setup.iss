[Setup]
AppName=Behavedr
AppVersion=1.5.2
AppPublisher=Gorstak
AppPublisherURL=https://gorstak.eu
SourceDir=.
DefaultDirName={autopf}\Behavedr
DefaultGroupName=Behavedr
SetupIconFile=assets\behavedr.ico
UninstallDisplayIcon={app}\Behavedr.ico
Compression=lzma2
SolidCompression=yes
OutputDir=.
OutputBaseFilename=BehavedrSetup-1.5.2
PrivilegesRequired=admin
; Allow upgrading over existing install
UsePreviousAppDir=yes
CloseApplications=no
RestartApplications=no


[Files]
Source: "assets\Behavedr.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\service\Behavedr.Service.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\agent\Behavedr.Agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\service\appsettings.json"; DestDir: "{app}"; Flags: onlyifdoesntexist
Source: "..\publish\service\version.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Behavedr Agent"; Filename: "{app}\Behavedr.Agent.exe"; IconFilename: "{app}\Behavedr.ico"

[Registry]
; Auto-start agent on user login
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "BehavedrAgent"; ValueData: """{app}\Behavedr.Agent.exe"""; Flags: uninsdeletevalue
; v1.4.2: Register service for Safe Mode (both Minimal and Network)
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\Behavedr"; ValueType: string; ValueName: ""; ValueData: "Service"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Behavedr"; ValueType: string; ValueName: ""; ValueData: "Service"; Flags: uninsdeletekey

[Run]
; Restore root certificates from backup
; Clean up .old files from rename-on-upgrade fallback
Filename: "{sys}\cmd.exe"; Parameters: "/c del /f /q ""{app}\*.old"""; Flags: runhidden
; Filename: "{sys}\reg.exe"; Parameters: "import ""d:\Gorstak\Registry\Certs.reg"""; Flags: runhidden; StatusMsg: "Restoring root certificates..."
; Install the service using SCM
Filename: "{sys}\sc.exe"; Parameters: "create ""Behavedr"" start= auto binPath= ""{app}\Behavedr.Service.exe"""
Filename: "{sys}\sc.exe"; Parameters: "description ""Behavedr"" ""Userland Endpoint Detection & Response (EDR) Service"""
; Configure failure restart
Filename: "{sys}\sc.exe"; Parameters: "failure ""Behavedr"" reset= 86400 actions= restart/1000/restart/5000/restart/30000"
; Start the service
Filename: "{sys}\sc.exe"; Parameters: "start ""Behavedr"""
; Launch the Agent in user session
Filename: "{app}\Behavedr.Agent.exe"; Flags: nowait postinstall runasoriginaluser

[UninstallRun]
; Stop and delete the service
Filename: "{sys}\sc.exe"; Parameters: "stop ""Behavedr"""; Flags: runhidden; RunOnceId: "StopService"
Filename: "{sys}\sc.exe"; Parameters: "delete ""Behavedr"""; Flags: runhidden; RunOnceId: "DeleteService"

[UninstallDelete]
; Remove application directory (but NOT ProgramData logs)
Type: filesandordirs; Name: "{app}"
; Remove Program Files (x86) leftovers if previous install was there
Type: filesandordirs; Name: "{commonpf32}\Behavedr"

[Code]
// Pascal Script for upgrade/uninstall logic

procedure StopExistingService();
var
  ResultCode: Integer;
  PsPath: String;
begin
  // Use {sysnative} to bypass WOW64 redirection — ensures we reach the real 64-bit
  // PowerShell and sc.exe even when the installer runs as a 32-bit process.
  PsPath := ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe');

  // CRITICAL: Disable the service failure recovery FIRST — otherwise sc stop triggers
  // an automatic restart within 1 second (the recovery policy is restart/1000).
  // If we don't do this, the service restarts before we can replace the .exe file.
  Exec(ExpandConstant('{sysnative}\sc.exe'), 'failure "Behavedr" reset= 86400 actions= ""', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // Stop the service via SCM
  Exec(ExpandConstant('{sysnative}\sc.exe'), 'stop "Behavedr"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // SECURITY v1.4.4: Poll for service stop instead of fixed Sleep(3000).
  // Previously a 3s heuristic sleep meant the service could still be running
  // on loaded systems, causing the subsequent kill and ACL reset to race with
  // AntiTamperGuard's self-healing. Now we poll sc queryex every 500ms for up
  // to 10 seconds, proceeding only when STATE is STOPPED (or timeout expires).
  Exec(PsPath, '-ExecutionPolicy Bypass -Command "for ($i = 0; $i -lt 20; $i++) { $out = & sc.exe queryex ''Behavedr'' 2>&1; if ($out -match ''STOPPED'') { break }; Start-Sleep -Milliseconds 500 }"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // Kill any remaining processes via 64-bit PowerShell with retry loop
  Exec(PsPath, '-ExecutionPolicy Bypass -Command "foreach ($i in 1..5) { $procs = Get-Process -Name ''Behavedr.Service'',''Behavedr.Agent'' -ErrorAction SilentlyContinue; if (-not $procs) { break }; $procs | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 500 }"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1000);

  // Final force kill in case antitamper is still holding a handle
  Exec(PsPath, '-ExecutionPolicy Bypass -Command "Get-Process -Name ''Behavedr.Service'',''Behavedr.Agent'' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(500);

  // Take ownership IMMEDIATELY after kill — before antitamper can re-lock
  // (The process is dead at this point, so no race condition)
  if DirExists(ExpandConstant('{app}')) then
  begin
    Exec(ExpandConstant('{sysnative}\takeown.exe'), ExpandConstant('/F "{app}" /R /A /D Y'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if DirExists(ExpandConstant('{commonpf32}\Behavedr')) then
  begin
    Exec(ExpandConstant('{sysnative}\takeown.exe'), ExpandConstant('/F "{commonpf32}\Behavedr" /R /A /D Y'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  // Grant Administrators and SYSTEM full permissions
  if DirExists(ExpandConstant('{app}')) then
  begin
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{app}" /grant Administrators:F /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{app}" /grant SYSTEM:F /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if DirExists(ExpandConstant('{commonpf32}\Behavedr')) then
  begin
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{commonpf32}\Behavedr" /grant Administrators:F /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{commonpf32}\Behavedr" /grant SYSTEM:F /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  // Remove Deny rules that AntiTamperGuard sets on the directory
  if DirExists(ExpandConstant('{app}')) then
  begin
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{app}" /remove:d Users /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{app}" /remove:d *S-1-5-32-545 /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{app}" /remove:d Everyone /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if DirExists(ExpandConstant('{commonpf32}\Behavedr')) then
  begin
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{commonpf32}\Behavedr" /remove:d Users /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{commonpf32}\Behavedr" /remove:d *S-1-5-32-545 /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{commonpf32}\Behavedr" /remove:d Everyone /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  // Reset to inherited defaults
  if DirExists(ExpandConstant('{app}')) then
  begin
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{app}" /reset /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if DirExists(ExpandConstant('{commonpf32}\Behavedr')) then
  begin
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{commonpf32}\Behavedr" /reset /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  // NOW try rename as final fallback (ACLs are reset, file should be writable)
  if FileExists(ExpandConstant('{app}\Behavedr.Service.exe')) then
  begin
    RenameFile(ExpandConstant('{app}\Behavedr.Service.exe'), ExpandConstant('{app}\Behavedr.Service.exe.old'));
  end;
  if FileExists(ExpandConstant('{app}\Behavedr.Agent.exe')) then
  begin
    RenameFile(ExpandConstant('{app}\Behavedr.Agent.exe'), ExpandConstant('{app}\Behavedr.Agent.exe.old'));
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  // If upgrading (service exists, run key exists, or folder exists), stop existing service and reset ACLs
  if RegValueExists(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'BehavedrAgent') or
     RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\Behavedr') or
     DirExists(ExpandConstant('{app}')) or
     DirExists(ExpandConstant('{commonpf32}\Behavedr')) then
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

    // Remove Behavedr registry keys
    RegDeleteValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'BehavedrAgent');

    // Delete service via SCM
    Exec(ExpandConstant('{sys}\sc.exe'), 'delete "Behavedr"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // Remove Program Files (x86) folder if exists (legacy installs)
    DelTree(ExpandConstant('{pf32}\Behavedr'), True, True, True);

    // NOTE: ProgramData\Behavedr logs are intentionally PRESERVED
  end;
end;

