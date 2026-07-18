# RansomwareScarewareDetection.ps1
# Author: Gorstak (gorstak.eu)
# Description: Scans running process window titles for ransomware/scareware keyword patterns
#              (e.g. "encrypted", "bitcoin", "decrypt", "pay to unlock"). Alerts on 2+ keyword
#              matches and kills suspicious processes. Runs persistently via scheduled task.
#Requires -RunAsAdministrator

param(
    [switch]$Install,
    [switch]$Uninstall
)

$Script:TaskName = "RansomwareScarewareDetection"
$Script:InstallDir = "$env:ProgramData\RansomwareScarewareDetection"
$Script:ScriptName = "RansomwareScarewareDetection.ps1"

# -- Persistence ------------------------------------------------
function Install-Persistence {
    $dir = $Script:InstallDir
    $dest = Join-Path $dir $Script:ScriptName
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Copy-Item -Path $PSCommandPath -Destination $dest -Force

    $existing = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($existing) { Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false }

    $pwshArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest`""
    $installed = $false

    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Ransomware/scareware window title monitor (Gorstak)" -Force | Out-Null
        Write-Host "[OK] Persistence installed." -ForegroundColor Green
        $installed = $true
    } catch {}

    if (-not $installed) {
        try {
            schtasks /Create /TN "$($Script:TaskName)" /TR "powershell.exe $pwshArgs" /SC ONLOGON /RL HIGHEST /F 2>&1 | Out-Null
            Write-Host "[OK] Persistence installed via schtasks." -ForegroundColor Green
            $installed = $true
        } catch {}
    }

    if (-not $installed) { Write-Host "[ERROR] Could not install persistence." -ForegroundColor Red }
    exit 0
}

function Uninstall-Persistence {
    $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($task) {
        if ($task.State -eq "Running") { Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue }
        Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
    } else {
        schtasks /Delete /TN "$($Script:TaskName)" /F 2>&1 | Out-Null
    }
    $dest = Join-Path $Script:InstallDir $Script:ScriptName
    if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
    if (Test-Path $Script:InstallDir) { Remove-Item $Script:InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "[OK] RansomwareScarewareDetection uninstalled." -ForegroundColor Green
    exit 0
}

if ($Install)   { Install-Persistence }
if ($Uninstall) { Uninstall-Persistence }

# Auto-install on first run (schtasks fallback for debloated Windows where WMI is broken)
$taskExists = (schtasks /Query /TN $Script:TaskName 2>$null) -match $Script:TaskName
if (-not $taskExists) { Install-Persistence }

# -- Main Logic -------------------------------------------------
$patterns = @("encrypted","bitcoin","decrypt","ransom","pay to unlock","your files have been","restore your files","microsoft support","pay fine")
$allow = @("explorer","logonui","lockapp","consent","applicationframehost","steam","epicgameslauncher")
$logFile = Join-Path $Script:InstallDir "detections.log"

function Write-Detection {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $entry -ForegroundColor Red
    $entry | Out-File -FilePath $logFile -Append -Encoding UTF8
}

while ($true) {
    try {
        foreach ($p in Get-Process -ErrorAction SilentlyContinue) {
            try {
                if (-not $p.MainWindowTitle) { continue }
                $n = $p.ProcessName.ToLower()
                if ($allow -contains $n) { continue }
                $t = $p.MainWindowTitle.ToLowerInvariant()
                $hits = 0
                foreach ($pat in $patterns) { if ($t -like "*$pat*") { $hits++ } }
                if ($hits -ge 2) {
                    Write-Detection "THREAT: $($p.ProcessName) (PID: $($p.Id)) | $($p.MainWindowTitle)"
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    } catch {}
    Start-Sleep -Seconds 10
}
