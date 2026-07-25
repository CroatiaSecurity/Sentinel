[Setup]
AppName=Sentinel
AppVersion=1.6.0
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
OutputBaseFilename=SentinelSetup-1.6.0
PrivilegesRequired=admin
; Allow upgrading over existing install
UsePreviousAppDir=yes
CloseApplications=no
RestartApplications=no


[Files]
Source: "assets\Sentinel.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\service\Sentinel.Service.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\agent\Sentinel.Agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\service\appsettings.json"; DestDir: "{app}"; Flags: onlyifdoesntexist
Source: "..\publish\service\version.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Sentinel Agent"; Filename: "{app}\Sentinel.Agent.exe"; IconFilename: "{app}\Sentinel.ico"

[Registry]
; Auto-start agent on user login
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "SentinelAgent"; ValueData: """{app}\Sentinel.Agent.exe"""; Flags: uninsdeletevalue
; v1.4.2: Register service for Safe Mode (both Minimal and Network)
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\Sentinel"; ValueType: string; ValueName: ""; ValueData: "Service"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Sentinel"; ValueType: string; ValueName: ""; ValueData: "Service"; Flags: uninsdeletekey
; Disable FIPS Algorithm Policy
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"; ValueType: dword; ValueName: "Enabled"; ValueData: 0
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Lsa"; ValueType: dword; ValueName: "FipsAlgorithmPolicy"; ValueData: 0

[Run]
; Restore root certificates from backup
; Clean up .old files from rename-on-upgrade fallback
Filename: "{sys}\cmd.exe"; Parameters: "/c del /f /q ""{app}\*.old"""; Flags: runhidden
; Filename: "{sys}\reg.exe"; Parameters: "import ""d:\Gorstak\Registry\Certs.reg"""; Flags: runhidden; StatusMsg: "Restoring root certificates..."
; Install the service using SCM
Filename: "{sys}\sc.exe"; Parameters: "create ""Sentinel"" start= auto binPath= ""{app}\Sentinel.Service.exe"""
Filename: "{sys}\sc.exe"; Parameters: "description ""Sentinel"" ""Userland Endpoint Detection & Response (EDR) Service"""
; Configure failure restart
Filename: "{sys}\sc.exe"; Parameters: "failure ""Sentinel"" reset= 86400 actions= restart/1000/restart/5000/restart/30000"
; Start the service
Filename: "{sys}\sc.exe"; Parameters: "start ""Sentinel"""
; Launch the Agent in user session
Filename: "{app}\Sentinel.Agent.exe"; Flags: nowait postinstall runasoriginaluser

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
