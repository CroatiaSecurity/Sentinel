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

procedure StopExistingService();
var
  ResultCode: Integer;
begin
  // Stop the service before upgrading — handles antitamper ACL-locked files
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop "Windows Sentinel"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  // Wait for service to stop
  Sleep(2000);
  // Kill any remaining agent and service processes using PowerShell
  Exec(ExpandConstant('{win}\System32\WindowsPowerShell\v1.0\powershell.exe'), '-Command "Get-Process -Name WindowsSentinel.Agent, WindowsSentinel.Service -ErrorAction SilentlyContinue | Stop-Process -Force"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1000);

  // Take ownership of the directories recursively to ensure we can modify ACLs
  if DirExists(ExpandConstant('{app}')) then
  begin
    Exec(ExpandConstant('{sys}\takeown.exe'), ExpandConstant('/F "{app}" /R /A /D Y'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if DirExists(ExpandConstant('{commonpf32}\WindowsSentinel')) then
  begin
    Exec(ExpandConstant('{sys}\takeown.exe'), ExpandConstant('/F "{commonpf32}\WindowsSentinel" /R /A /D Y'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  // Grant Administrators and SYSTEM full permissions
  if DirExists(ExpandConstant('{app}')) then
  begin
    Exec(ExpandConstant('{sys}\icacls.exe'), ExpandConstant('"{app}" /grant Administrators:F /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\icacls.exe'), ExpandConstant('"{app}" /grant SYSTEM:F /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if DirExists(ExpandConstant('{commonpf32}\WindowsSentinel')) then
  begin
    Exec(ExpandConstant('{sys}\icacls.exe'), ExpandConstant('"{commonpf32}\WindowsSentinel" /grant Administrators:F /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\icacls.exe'), ExpandConstant('"{commonpf32}\WindowsSentinel" /grant SYSTEM:F /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  // Explicitly remove any Deny rules for Users (which override Administrator allows)
  if DirExists(ExpandConstant('{app}')) then
  begin
    Exec(ExpandConstant('{sys}\icacls.exe'), ExpandConstant('"{app}" /remove:d Users /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\icacls.exe'), ExpandConstant('"{app}" /remove:d *S-1-5-32-545 /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if DirExists(ExpandConstant('{commonpf32}\WindowsSentinel')) then
  begin
    Exec(ExpandConstant('{sys}\icacls.exe'), ExpandConstant('"{commonpf32}\WindowsSentinel" /remove:d Users /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\icacls.exe'), ExpandConstant('"{commonpf32}\WindowsSentinel" /remove:d *S-1-5-32-545 /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  // Reset to inherited defaults to clean up any remaining anti-tamper permission states
  if DirExists(ExpandConstant('{app}')) then
  begin
    Exec(ExpandConstant('{sys}\icacls.exe'), ExpandConstant('"{app}" /reset /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if DirExists(ExpandConstant('{commonpf32}\WindowsSentinel')) then
  begin
    Exec(ExpandConstant('{sys}\icacls.exe'), ExpandConstant('"{commonpf32}\WindowsSentinel" /reset /T /C /Q'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
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

