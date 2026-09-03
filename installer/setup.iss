[Setup]
AppName=Sentinel
AppVersion=2.3.9
AppPublisher=Gorstak
AppPublisherURL=https://gorstak.eu
AppCopyright=Copyright (C) 2026 Gorstak
VersionInfoVersion=2.3.9.0
VersionInfoCompany=Gorstak
VersionInfoDescription=Sentinel Endpoint Detection and Response Setup
VersionInfoCopyright=Copyright (C) 2026 Gorstak
VersionInfoProductName=Sentinel EDR
VersionInfoProductVersion=2.3.9.0
VersionInfoOriginalFileName=SentinelSetup-2.3.9.exe
SourceDir=.
DefaultDirName={autopf}\Sentinel
DefaultGroupName=Sentinel
SetupIconFile=assets\Sentinel.ico
UninstallDisplayIcon={app}\Sentinel.ico
Compression=lzma/max
SolidCompression=no
OutputDir=.
OutputBaseFilename=SentinelSetup-2.3.9
PrivilegesRequired=admin
SetupMutex=Global\SentinelSetupMutex
UsePreviousAppDir=yes
CloseApplications=no
RestartApplications=no

[Files]
Source: "assets\Sentinel.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\service\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "appsettings.json"
Source: "..\publish\agent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "appsettings.json"

[Icons]
Name: "{group}\Sentinel Agent"; Filename: "{app}\Sentinel.Agent.exe"; IconFilename: "{app}\Sentinel.ico"

; v2.3.9: No [Registry] Run / SafeBoot here — Sentinel.Service.exe --install owns those.
; v2.3.9: No Pascal sc/taskkill/icacls — upgrade stop + post-install via Service CLI.

[Run]
; After files are on disk: register service, Run key, SafeBoot, start service+agent
Filename: "{app}\Sentinel.Service.exe"; Parameters: "--install"; Flags: runhidden waituntilterminated; StatusMsg: "Starting Sentinel..."
; Clean leftover .old rename stubs from upgrade
Filename: "{sys}\cmd.exe"; Parameters: "/c del /f /q ""{app}\*.old"" 2>nul & exit /b 0"; Flags: runhidden waituntilterminated

[UninstallRun]
Filename: "{app}\Sentinel.Service.exe"; Parameters: "--prepare-upgrade"; Flags: runhidden; RunOnceId: "StopService"
Filename: "{sys}\sc.exe"; Parameters: "delete ""Sentinel"""; Flags: runhidden; RunOnceId: "DeleteService"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
Type: filesandordirs; Name: "{commonpf32}\Sentinel"

[Code]
// Minimal Pascal: .NET 4.8 gate + upgrade prepare via Service.exe (no sc/taskkill/icacls).

function IsDotNet48OrHigher(): Boolean;
var
  Release: Cardinal;
begin
  Result := False;
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
begin
  Result := False;
  if MsgBox(
    'Sentinel requires .NET Framework 4.8.' + #13#10#13#10 +
    'Yes = open the Microsoft download page' + #13#10 +
    'No  = cancel Setup',
    mbConfirmation, MB_YESNO) = IDYES then
  begin
    ShellExec('open',
      'https://dotnet.microsoft.com/download/dotnet-framework/net48',
      '', '', SW_SHOWNORMAL, ewNoWait, ErrCode);
    MsgBox('After installing .NET Framework 4.8, run SentinelSetup again.', mbInformation, MB_OK);
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsDotNet48OrHigher() then
    Result := OfferDotNet48Download();
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  Svc: String;
begin
  Result := '';
  NeedsRestart := False;

  // Prefer in-tree Service.exe (upgrade) to stop cleanly without taskkill/icacls.
  Svc := ExpandConstant('{app}\Sentinel.Service.exe');
  if FileExists(Svc) then
  begin
    Exec(Svc, '--prepare-upgrade', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(800);
  end;

  // Rename locked PE so Setup can replace (no ACL strip)
  if FileExists(ExpandConstant('{app}\Sentinel.Service.exe')) then
    RenameFile(ExpandConstant('{app}\Sentinel.Service.exe'), ExpandConstant('{app}\Sentinel.Service.exe.old'));
  if FileExists(ExpandConstant('{app}\Sentinel.Agent.exe')) then
    renameFile(ExpandConstant('{app}\Sentinel.Agent.exe'), ExpandConstant('{app}\Sentinel.Agent.exe.old'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    RegDeleteValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SentinelAgent');
    RegDeleteKeyIncludingSubkeys(HKLM, 'SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\Sentinel');
    RegDeleteKeyIncludingSubkeys(HKLM, 'SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Sentinel');
    Exec(ExpandConstant('{sys}\netsh.exe'), 'ipsec static delete policy name=GSecurity', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall delete rule name="Sentinel-Block-Remote-RPC-Ephemeral"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
