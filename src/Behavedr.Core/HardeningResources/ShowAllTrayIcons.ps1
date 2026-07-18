# Show All Tray Icons - Windows 10/11
# Forces ALL notification area icons to always be visible, including system icons.
# Removes policies that block tray icon visibility.
# Registers a scheduled task to re-apply on every logon (catches new icons).

$ErrorActionPreference = 'SilentlyContinue'

# --- Step 1: Remove policies that block tray icon visibility ---

# TaskbarNoNotification = 1 suppresses notification popups and hides icons
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'TaskbarNoNotification' -Force
# NoNetConnectDisconnect hides the network tray icon context menu
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoNetConnectDisconnect' -Force

# --- Step 2: Global "always show all icons" toggle ---

# EnableAutoTray = 0 means "always show all icons in notification area"
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' -Name 'EnableAutoTray' -Value 0 -Type DWord -Force

# --- Step 3: Promote every individual tray icon entry ---

# Each app that has ever shown a tray icon gets an entry under NotifyIconSettings.
# IsPromoted = 1 means "show in the visible tray area, not hidden in overflow"
$notifyPath = 'HKCU:\Control Panel\NotifyIconSettings'
if (Test-Path $notifyPath) {
    Get-ChildItem -Path $notifyPath | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name 'IsPromoted' -Value 1 -Type DWord -Force
    }
}

# --- Step 4: Windows 11 system tray corner icons ---

# Windows 11 moved system icons (network, volume, battery) to "corner overflow"
# controlled by a different registry path. Force the chevron to show all.
$trayNotify = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify'
if (Test-Path $trayNotify) {
    # SystemTrayChevronVisibility: 0 = no chevron (all icons visible), 1 = chevron shown (some hidden)
    Set-ItemProperty -Path $trayNotify -Name 'SystemTrayChevronVisibility' -Value 0 -Type DWord -Force
}

# Delete icon stream caches so Windows rebuilds with all icons visible
# (since EnableAutoTray=0 is set, rebuild will show everything)
Remove-ItemProperty -Path $trayNotify -Name 'IconStreams' -Force
Remove-ItemProperty -Path $trayNotify -Name 'PastIconsStream' -Force

# --- Step 5: Set defaults for new user profiles ---

$defaultNtuser = "$env:SystemDrive\Users\Default\NTUSER.DAT"
$tempHive = 'HKU\DefaultUser_Temp'
$loaded = $false

if (Test-Path $defaultNtuser) {
    reg load $tempHive $defaultNtuser 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $loaded = $true
        reg add "$tempHive\Software\Microsoft\Windows\CurrentVersion\Explorer" /v EnableAutoTray /t REG_DWORD /d 0 /f 2>&1 | Out-Null
    }
}

# --- Step 6: Register a logon task to promote new icons on every login ---

$taskName = 'ShowAllTrayIcons'

$cmd = "Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'TaskbarNoNotification' -Force -ErrorAction SilentlyContinue; Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' -Name 'EnableAutoTray' -Value 0 -Type DWord -Force; Get-ChildItem 'HKCU:\Control Panel\NotifyIconSettings' -ErrorAction SilentlyContinue | ForEach-Object { Set-ItemProperty -Path `$_.PSPath -Name 'IsPromoted' -Value 1 -Type DWord -Force }; `$tn = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify'; Set-ItemProperty -Path `$tn -Name 'SystemTrayChevronVisibility' -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue; Remove-ItemProperty -Path `$tn -Name 'IconStreams' -Force -ErrorAction SilentlyContinue; Remove-ItemProperty -Path `$tn -Name 'PastIconsStream' -Force -ErrorAction SilentlyContinue;"

# Try cmdlet first, fall back to schtasks
try {
    $action = New-ScheduledTaskAction -Execute "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -Command `"$cmd`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
} catch {
    schtasks /Create /TN $taskName /SC ONLOGON /RL LIMITED /TR "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command `"$cmd`"" /F 2>&1 | Out-Null
}

# --- Step 7: Unload default hive ---

if ($loaded) {
    [gc]::Collect()
    Start-Sleep -Seconds 1
    reg unload $tempHive 2>&1 | Out-Null
}

# --- Step 8: Restart Explorer to apply immediately ---

$explorer = Get-Process -Name explorer -ErrorAction SilentlyContinue
if ($explorer) {
    Stop-Process -Name explorer -Force
    Start-Sleep -Seconds 2
    Start-Process explorer.exe
}
