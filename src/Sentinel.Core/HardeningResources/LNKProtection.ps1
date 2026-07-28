# LNKProtection.ps1
# Author: Gorstak (gorstak.eu)
# Description: Monitors Desktop, Start Menu, and Taskbar for malicious .lnk shortcut files
#              that point to UNC/network paths (common malware delivery vector). Deletes them
#              on detection. Runs persistently via scheduled task.
#Requires -RunAsAdministrator

param(
    [switch]$Install,
    [switch]$Uninstall
)

$Script:TaskName = "LNKProtection"
$Script:InstallDir = "$env:ProgramData\LNKProtection"
$Script:ScriptName = "LNKProtection.ps1"
$Script:LogFile = "$Script:InstallDir\lnkprotection.log"

# -- Logging ----------------------------------------------------
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    if (!(Test-Path $Script:InstallDir)) { New-Item -ItemType Directory -Path $Script:InstallDir -Force | Out-Null }
    Add-Content -Path $Script:LogFile -Value $entry -ErrorAction SilentlyContinue
    if ($Level -eq "THREAT") { Write-Host $entry -ForegroundColor Red }
    elseif ($Level -eq "WARN") { Write-Host $entry -ForegroundColor Yellow }
    else { Write-Host $entry }
}

# -- Persistence ------------------------------------------------
function Install-Persistence {
    $dir = $Script:InstallDir
    $dest = Join-Path $dir $Script:ScriptName
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Copy-Item -Path $PSCommandPath -Destination $dest -Force
    Write-Log "Script installed to $dest"

    $existing = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($existing) { Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false }

    $pwshArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest`""
    $installed = $false

    # Method 1: PowerShell cmdlets
    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings `
            -Description "LNK shortcut protection - removes malicious network shortcuts (Gorstak)" -Force | Out-Null
        Write-Log "Persistence installed via Register-ScheduledTask."
        $installed = $true
    } catch {
        Write-Log "Register-ScheduledTask failed: $_" "WARN"
    }

    # Method 2: schtasks.exe fallback
    if (-not $installed) {
        try {
            $cmd = "schtasks /Create /TN `"$($Script:TaskName)`" /TR `"powershell.exe $pwshArgs`" /SC ONLOGON /RU SYSTEM /RL HIGHEST /F"
            $result = cmd /c $cmd 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Persistence installed via schtasks.exe fallback."
                $installed = $true
            } else {
                Write-Log "schtasks fallback failed: $result" "WARN"
            }
        } catch {
            Write-Log "schtasks fallback exception: $_" "WARN"
        }
    }

    if (-not $installed) {
        Write-Log "WARNING: Could not install persistence via any method." "WARN"
    } else {
        Write-Log "[OK] LNKProtection installed and will run at logon." 
    }
    exit 0
}

function Uninstall-Persistence {
    # Try cmdlet first
    $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($task) {
        if ($task.State -eq "Running") { Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue }
        Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log "Task removed via cmdlet."
    } else {
        # Fallback to schtasks
        schtasks /Delete /TN "$($Script:TaskName)" /F 2>&1 | Out-Null
        Write-Log "Task removed via schtasks."
    }
    $dest = Join-Path $Script:InstallDir $Script:ScriptName
    if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
    Write-Log "[OK] LNKProtection uninstalled."
    exit 0
}

if ($Install)   { Install-Persistence }
if ($Uninstall) { Uninstall-Persistence }

# -- Auto-install on first run (schtasks fallback for debloated Windows where WMI is broken) --
$taskExists = (schtasks /Query /TN $Script:TaskName 2>$null) -match $Script:TaskName
if (-not $taskExists) {
    Write-Log "First run detected, installing persistence..."
    # Don't exit - install inline then continue
    $dir = $Script:InstallDir
    $dest = Join-Path $dir $Script:ScriptName
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if ($PSCommandPath -ne $dest) {
        Copy-Item -Path $PSCommandPath -Destination $dest -Force
    }
    $pwshArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest`""
    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "LNK shortcut protection (Gorstak)" -Force | Out-Null
        Write-Log "Persistence auto-installed via Register-ScheduledTask."
    } catch {
        schtasks /Create /TN "$($Script:TaskName)" /TR "powershell.exe $pwshArgs" /SC ONLOGON /RU SYSTEM /RL HIGHEST /F 2>&1 | Out-Null
        Write-Log "Persistence auto-installed via schtasks fallback."
    }
}

# -- Main Protection Loop --------------------------------------
Write-Log "LNKProtection starting..."

$shell = New-Object -ComObject WScript.Shell
$paths = @(
    "$env:USERPROFILE\Desktop",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
    "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar",
    "$env:PUBLIC\Desktop"
)

# Only enter blocking loop if running from installed location (scheduled task)
$installedDir = $Script:InstallDir
if ($PSCommandPath -and $PSCommandPath.StartsWith($installedDir, [System.StringComparison]::OrdinalIgnoreCase)) {
    while ($true) {
        foreach ($path in $paths) {
            if (!(Test-Path $path)) { continue }
            Get-ChildItem $path -Recurse -Include *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $target = $shell.CreateShortcut($_.FullName).TargetPath
                    if ($target -like "\\*") {
                        Write-Log "REMOVED malicious LNK pointing to UNC path: $($_.FullName) -> $target" "THREAT"
                        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                    }
                } catch {}
            }
        }
        Start-Sleep -Seconds 300  # Check every 5 minutes
    }
} else {
    # First run: do a single scan pass and exit
    foreach ($path in $paths) {
        if (!(Test-Path $path)) { continue }
        Get-ChildItem $path -Recurse -Include *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $target = $shell.CreateShortcut($_.FullName).TargetPath
                if ($target -like "\\*") {
                    Write-Log "REMOVED malicious LNK pointing to UNC path: $($_.FullName) -> $target" "THREAT"
                    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    }
    Write-Log "LNKProtection installed. Monitor runs via scheduled task."
}
