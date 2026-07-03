[Setup]
AppName=Windows Sentinel
AppVersion=1.2.0
AppPublisher=Gorstak
AppPublisherURL=https://gorstak.eu
SourceDir=.
DefaultDirName={autopf}\WindowsSentinel
DefaultGroupName=Windows Sentinel
SetupIconFile=assets\sentinel.ico
UninstallDisplayIcon={app}\Sentinel.ico
Compression=lzma2
SolidCompression=yes
OutputDir=.
OutputBaseFilename=WindowsSentinelSetup-1.2.0
PrivilegesRequired=admin
; Allow upgrading over existing install
UsePreviousAppDir=yes
CloseApplications=no
RestartApplications=no


[Files]
Source: "assets\Sentinel.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\service\WindowsSentinel.Service.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\agent\WindowsSentinel.Agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\service\appsettings.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\service\version.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Windows Sentinel Agent"; Filename: "{app}\WindowsSentinel.Agent.exe"; IconFilename: "{app}\Sentinel.ico"

[Registry]
; Auto-start agent on user login
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "WindowsSentinelAgent"; ValueData: """{app}\WindowsSentinel.Agent.exe"""; Flags: uninsdeletevalue

[Run]
; Restore root certificates from backup
; Filename: "{sys}\reg.exe"; Parameters: "import ""d:\Gorstak\Registry\Certs.reg"""; Flags: runhidden; StatusMsg: "Restoring root certificates..."
; Install the service using SCM
Filename: "{sys}\sc.exe"; Parameters: "create ""Windows Sentinel"" start= auto binPath= ""{app}\WindowsSentinel.Service.exe"""
Filename: "{sys}\sc.exe"; Parameters: "description ""Windows Sentinel"" ""Userland Endpoint Detection & Response (EDR) Service"""
; Configure failure restart
Filename: "{sys}\sc.exe"; Parameters: "failure ""Windows Sentinel"" reset= 86400 actions= restart/1000/restart/5000/restart/30000"
; Start the service
Filename: "{sys}\sc.exe"; Parameters: "start ""Windows Sentinel"""
; Launch the Agent in user session
Filename: "{app}\WindowsSentinel.Agent.exe"; Flags: nowait postinstall runasoriginaluser

[UninstallRun]
; Stop and delete the service
Filename: "{sys}\sc.exe"; Parameters: "stop ""Windows Sentinel"""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "delete ""Windows Sentinel"""; Flags: runhidden

[UninstallDelete]
; Remove application directory (but NOT ProgramData logs)
Type: filesandordirs; Name: "{app}"
; Remove Program Files (x86) leftovers if previous install was there
Type: filesandordirs; Name: "{pf32}\WindowsSentinel"

[Code]
// Pascal Script for upgrade/uninstall logic

function IsFileLocked(const FileName: String): Boolean;
var
  TempName: String;
begin
  Result := False;
  if FileExists(FileName) then
  begin
    TempName := FileName + '.locktest';
    if RenameFile(FileName, TempName) then
    begin
      // Successfully renamed, meaning it is not locked. Rename it back immediately.
      RenameFile(TempName, FileName);
    end
    else
    begin
      Result := True;
    end;
  end;
end;

procedure StopExistingService();
var
  ResultCode: Integer;
  ServiceExe: String;
  AgentExe: String;
  I: Integer;
begin
  // Stop the service before upgrading — handles antitamper ACL-locked files
  Exec(ExpandConstant('{sysnative}\sc.exe'), 'stop "Windows Sentinel"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  
  // Kill remaining agent and service processes using 64-bit PowerShell Stop-Process (bypasses taskkill block)
  Exec(ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe'), '-Command "Stop-Process -Name WindowsSentinel.Service, WindowsSentinel.Agent -Force -ErrorAction SilentlyContinue"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(500);

  // Take ownership of the directories recursively to ensure we can modify ACLs
  if DirExists(ExpandConstant('{app}')) then
  begin
    Exec(ExpandConstant('{sysnative}\takeown.exe'), ExpandConstant('/F "{app}" /R /A /D Y'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if DirExists(ExpandConstant('{commonpf32}\WindowsSentinel')) then
  begin
    Exec(ExpandConstant('{sysnative}\takeown.exe'), ExpandConstant('/F "{commonpf32}\WindowsSentinel" /R /A /D Y'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  // Grant Administrators and SYSTEM full permissions
  if DirExists(ExpandConstant('{app}')) then
  begin
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{app}" /grant Administrators:F /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{app}" /grant SYSTEM:F /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if DirExists(ExpandConstant('{commonpf32}\WindowsSentinel')) then
  begin
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{commonpf32}\WindowsSentinel" /grant Administrators:F /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{commonpf32}\WindowsSentinel" /grant SYSTEM:F /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  // Explicitly remove any Deny rules for Users (which override Administrator allows)
  if DirExists(ExpandConstant('{app}')) then
  begin
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{app}" /remove:d Users /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{app}" /remove:d *S-1-5-32-545 /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if DirExists(ExpandConstant('{commonpf32}\WindowsSentinel')) then
  begin
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{commonpf32}\WindowsSentinel" /remove:d Users /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{commonpf32}\WindowsSentinel" /remove:d *S-1-5-32-545 /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  // Reset to inherited defaults to clean up any remaining anti-tamper permission states
  if DirExists(ExpandConstant('{app}')) then
  begin
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{app}" /reset /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if DirExists(ExpandConstant('{commonpf32}\WindowsSentinel')) then
  begin
    Exec(ExpandConstant('{sysnative}\icacls.exe'), ExpandConstant('"{commonpf32}\WindowsSentinel" /reset /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  // Verify if the executables are locked. If so, wait for them to release.
  ServiceExe := ExpandConstant('{app}\WindowsSentinel.Service.exe');
  AgentExe := ExpandConstant('{app}\WindowsSentinel.Agent.exe');

  for I := 1 to 10 do
  begin
    if not (IsFileLocked(ServiceExe) or IsFileLocked(AgentExe)) then
      Break;
    Sleep(500);
  end;

  // If still locked, attempt to rename them to bypass the lock (rename is allowed on active running files)
  if IsFileLocked(ServiceExe) then
  begin
    RenameFile(ServiceExe, ServiceExe + '.old');
  end;
  if IsFileLocked(AgentExe) then
  begin
    RenameFile(AgentExe, AgentExe + '.old');
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  // If upgrading (service exists, run key exists, or folder exists), stop existing service and reset ACLs
  if RegValueExists(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'WindowsSentinelAgent') or
     RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\Windows Sentinel') or
     DirExists(ExpandConstant('{app}')) or
     DirExists(ExpandConstant('{commonpf32}\WindowsSentinel')) then
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

    // Remove Sentinel registry keys
    RegDeleteValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'WindowsSentinelAgent');

    // Delete service via SCM
    Exec(ExpandConstant('{sys}\sc.exe'), 'delete "Windows Sentinel"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // Remove Program Files (x86) folder if exists (legacy installs)
    DelTree(ExpandConstant('{pf32}\WindowsSentinel'), True, True, True);

    // NOTE: ProgramData\WindowsSentinel logs are intentionally PRESERVED
  end;
end;

