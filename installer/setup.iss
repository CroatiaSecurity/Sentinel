[Setup]
AppName=Windows Sentinel
AppVersion=6.9.0
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
OutputBaseFilename=WindowsSentinelSetup-6.9.0
PrivilegesRequired=admin
; Allow upgrading over existing install
UsePreviousAppDir=yes

[Files]
Source: "assets\Sentinel.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\service\WindowsSentinel.Service.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\agent\WindowsSentinel.Agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\service\appsettings.json"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Windows Sentinel Agent"; Filename: "{app}\WindowsSentinel.Agent.exe"; IconFilename: "{app}\Sentinel.ico"

[Registry]
; Auto-start agent on user login
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "WindowsSentinelAgent"; ValueData: """{app}\WindowsSentinel.Agent.exe"""; Flags: uninsdeletevalue

[Run]
; Restore root certificates from backup
Filename: "{sys}\reg.exe"; Parameters: "import ""d:\Gorstak\Registry\Certs.reg"""; Flags: runhidden; StatusMsg: "Restoring root certificates..."
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
  // Stop the service before upgrading � handles antitamper ACL-locked files
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop "Windows Sentinel"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  // Wait for service to stop
  Sleep(2000);
  // Kill any remaining agent processes
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM WindowsSentinel.Agent.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM WindowsSentinel.Service.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1000);
  // Reset directory ACLs so installer can overwrite files (antitamper hardens ACLs)
  Exec(ExpandConstant('{sys}\icacls.exe'),
    ExpandConstant('"{app}" /reset /T /C /Q'),
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  // If upgrading, stop existing service and reset ACLs
  if RegValueExists(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'WindowsSentinelAgent') then
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

