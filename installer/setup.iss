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
#define AppVersion   "2.5.0"
#define AppPublisher "Gorstak"
#define AppURL       "https://github.com/tandrlemandrle/Sentinel"
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
; ── Stop and remove any previous installation of the service
Filename: "{sys}\sc.exe"; Parameters: "stop ""{#ServiceName}""";   Flags: runhidden waituntilterminated; StatusMsg: "Stopping existing service..."; Check: ServiceExists
; Wait for service to fully stop and release file handles
Filename: "{sys}\timeout.exe"; Parameters: "/t 3 /nobreak"; Flags: runhidden waituntilterminated
; Kill any lingering process (handles race condition with crashing service)
Filename: "{sys}\taskkill.exe"; Parameters: "/f /im {#ServiceExe}"; Flags: runhidden waituntilterminated
Filename: "{sys}\taskkill.exe"; Parameters: "/f /im {#AgentExe}"; Flags: runhidden waituntilterminated
; Wait again for handles to release
Filename: "{sys}\timeout.exe"; Parameters: "/t 2 /nobreak"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "delete ""{#ServiceName}"""; Flags: runhidden waituntilterminated; StatusMsg: "Removing existing service..."; Check: ServiceExists

; ── Install and start the new service
Filename: "{sys}\sc.exe"; Parameters: "create ""{#ServiceName}"" binPath= ""{app}\{#ServiceExe}"" start= auto DisplayName= ""{#AppName}"""; Flags: runhidden waituntilterminated; StatusMsg: "Installing service..."
Filename: "{sys}\sc.exe"; Parameters: "description ""{#ServiceName}"" ""Windows Sentinel - Endpoint Detection and Response"""; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "start ""{#ServiceName}"""; Flags: runhidden waituntilterminated; StatusMsg: "Starting service..."

[UninstallRun]
; Stop and remove the service
Filename: "{sys}\sc.exe"; Parameters: "stop ""{#ServiceName}""";   Flags: runhidden waituntilterminated
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

// CurStepChanged fires at well-defined points in the install lifecycle.
// ssInstall fires just before files are extracted — exactly what we need.
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    AddDefenderExclusions();
end;

// CurUninstallStepChanged fires during uninstall.
// usUninstall fires before files are removed.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RemoveDefenderExclusions();
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
