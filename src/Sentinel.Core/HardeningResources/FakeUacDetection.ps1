#Requires -RunAsAdministrator
# FakeUacDetection.ps1
# Author: Gorstak (gorstak.eu)
# Description: Detects possible fake UAC/system dialog windows by scanning process window
#              titles for keywords like "user account control", "windows security", etc.
#              Excludes trusted system processes. Persistent via scheduled task.
# Window-title heuristics for possible fake system/UAC dialogs. High false-positive rate.

param(
    [hashtable]$ModuleConfig,
    [switch]$Install,
    [switch]$Uninstall
)

# -- Persistence ------------------------------------------------
$Script:ServiceConfig = @{
    TaskName    = "FakeUacDetection"
    InstallDir  = "C:\ProgramData\Antivirus"
    ScriptName  = "FakeUacDetection.ps1"
}

function Install-Persistence {
    $dir = $Script:ServiceConfig.InstallDir
    $dest = Join-Path $dir $Script:ServiceConfig.ScriptName
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Copy-Item -Path $PSCommandPath -Destination $dest -Force
    Write-Host "Copied to $dest" -ForegroundColor Gray

    $existing = Get-ScheduledTask -TaskName $Script:ServiceConfig.TaskName -ErrorAction SilentlyContinue
    if ($existing) { Unregister-ScheduledTask -TaskName $Script:ServiceConfig.TaskName -Confirm:$false }

    $pwshArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest`""
    $installed = $false

    # Method 1: PowerShell cmdlets
    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

        Register-ScheduledTask -TaskName $Script:ServiceConfig.TaskName `
            -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
            -Description "Fake UAC dialog detection monitor (Gorstak)" | Out-Null
        Write-Host "[OK] $($Script:ServiceConfig.TaskName) installed via Register-ScheduledTask." -ForegroundColor Green
        $installed = $true
    } catch {
        Write-Host "[WARN] Register-ScheduledTask failed: $_" -ForegroundColor Yellow
    }

    # Method 2: schtasks.exe fallback
    if (-not $installed) {
        try {
            $cmd = "schtasks /Create /TN `"$($Script:ServiceConfig.TaskName)`" /TR `"powershell.exe $pwshArgs`" /SC ONLOGON /RL HIGHEST /F"
            $result = cmd /c $cmd 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[OK] $($Script:ServiceConfig.TaskName) installed via schtasks.exe fallback." -ForegroundColor Green
            } else {
                Write-Host "[ERROR] schtasks fallback failed: $result" -ForegroundColor Red
            }
        } catch {
            Write-Host "[ERROR] schtasks exception: $_" -ForegroundColor Red
        }
    }
    exit 0
}

function Uninstall-Persistence {
    $task = Get-ScheduledTask -TaskName $Script:ServiceConfig.TaskName -ErrorAction SilentlyContinue
    if ($task) {
        if ($task.State -eq "Running") { Stop-ScheduledTask -TaskName $Script:ServiceConfig.TaskName -ErrorAction SilentlyContinue }
        Unregister-ScheduledTask -TaskName $Script:ServiceConfig.TaskName -Confirm:$false
        Write-Host "Task removed." -ForegroundColor Gray
    }
    $dest = Join-Path $Script:ServiceConfig.InstallDir $Script:ServiceConfig.ScriptName
    if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
    Write-Host "[OK] $($Script:ServiceConfig.TaskName) uninstalled." -ForegroundColor Green
    exit 0
}

if ($Install)   { Install-Persistence }
if ($Uninstall) { Uninstall-Persistence }

# -- Logging ----------------------------------------------------
$AgentsAvBin = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Bin'))
$jobLogPath = Join-Path $AgentsAvBin '_JobLog.ps1'
if (Test-Path $jobLogPath) {
    . $jobLogPath
} else {
    function Write-JobLog { param([string]$Message, [string]$Level = "INFO", [string]$LogFile = "log.txt")
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $entry = "[$ts] [$Level] $Message"
        $logDir = "C:\ProgramData\Antivirus\Logs"
        if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        Add-Content -Path (Join-Path $logDir $LogFile) -Value $entry
    }
}

# -- Detection --------------------------------------------------
function Invoke-FakeUacDetection {
    try {
        $susPatterns = @("user account control","do you want to allow","windows security","microsoft defender","critical update","windows update")
        $trusted = @("consent","explorer","dwm","applicationframehost","securityhealthservice","msmpeng")
        $procs = Get-Process -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            try {
                if (-not $p.MainWindowTitle) { continue }
                $name = ($p.ProcessName | Out-String).Trim().ToLowerInvariant()
                if ($trusted -contains $name) { continue }
                $title = $p.MainWindowTitle.ToLowerInvariant()
                $hits = 0
                foreach ($pat in $susPatterns) { if ($title -like "*$pat*") { $hits++ } }
                if ($hits -ge 1) {
                    Write-JobLog "Possible fake UAC/system dialog: $($p.ProcessName) (PID: $($p.Id)) | $($p.MainWindowTitle)" "THREAT" "user_protection.log"
                }
            } catch {}
        }
    } catch {
        Write-JobLog "FakeUacDetection error: $_" "ERROR" "user_protection.log"
    }
}

# -- Main loop --------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    $installedDir = $Script:ServiceConfig.InstallDir
    if ($PSCommandPath -and $PSCommandPath.StartsWith($installedDir, [System.StringComparison]::OrdinalIgnoreCase)) {
        while ($true) {
            Invoke-FakeUacDetection
            Start-Sleep -Seconds 10
        }
    } else {
        # First run: install persistence and do a single check, then exit
        Invoke-FakeUacDetection
        Write-Host "[OK] FakeUacDetection installed. Monitor runs via scheduled task." -ForegroundColor Green
    }
}
