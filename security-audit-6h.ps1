# ============================================================
# SENTINEL SECURITY AUDIT - Past 6 Hours
# Run this in an elevated PowerShell (Run as Administrator)
# ============================================================

$start = (Get-Date).AddHours(-6)
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " SECURITY AUDIT - Last 6 Hours" -ForegroundColor Cyan
Write-Host " Started: $start" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# --- 1. FAILED LOGON ATTEMPTS ---
Write-Host "--- [1] FAILED LOGON ATTEMPTS ---" -ForegroundColor Yellow
$failed = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$start} -ErrorAction SilentlyContinue
if ($failed) {
    $failed | Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, @{N='SourceIP';E={$_.Properties[19].Value}} | Format-Table -AutoSize
} else {
    Write-Host "  None found.`n" -ForegroundColor Green
}

# --- 2. SUCCESSFUL LOGONS ---
Write-Host "--- [2] SUCCESSFUL LOGONS ---" -ForegroundColor Yellow
$logons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$start} -ErrorAction SilentlyContinue
if ($logons) {
    $logons | Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, @{N='LogonType';E={$_.Properties[8].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}} | Format-Table -AutoSize
    Write-Host "  LogonType key: 2=Interactive, 3=Network, 7=Unlock, 10=RDP, 11=CachedCreds`n" -ForegroundColor DarkGray
} else {
    Write-Host "  None found.`n" -ForegroundColor Green
}

# --- 3. WEBCAM ACCESS ---
Write-Host "--- [3] WEBCAM ACCESS (Registry) ---" -ForegroundColor Yellow
$camPackaged = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
    Select-Object PSChildName, LastUsedTimeStart, LastUsedTimeStop, Value
$camNonPkg = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged" -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
    Select-Object PSChildName, LastUsedTimeStart, LastUsedTimeStop, Value

if ($camPackaged -or $camNonPkg) {
    if ($camPackaged) { $camPackaged | Format-Table -AutoSize }
    if ($camNonPkg) { Write-Host "  Non-packaged apps:" -ForegroundColor DarkGray; $camNonPkg | Format-Table -AutoSize }
} else {
    Write-Host "  No webcam access entries found.`n" -ForegroundColor Green
}

# --- 4. MICROPHONE ACCESS ---
Write-Host "--- [4] MICROPHONE ACCESS (Registry) ---" -ForegroundColor Yellow
$micPackaged = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
    Select-Object PSChildName, LastUsedTimeStart, LastUsedTimeStop, Value
$micNonPkg = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged" -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
    Select-Object PSChildName, LastUsedTimeStart, LastUsedTimeStop, Value

if ($micPackaged -or $micNonPkg) {
    if ($micPackaged) { $micPackaged | Format-Table -AutoSize }
    if ($micNonPkg) { Write-Host "  Non-packaged apps:" -ForegroundColor DarkGray; $micNonPkg | Format-Table -AutoSize }
} else {
    Write-Host "  No microphone access entries found.`n" -ForegroundColor Green
}

# --- 5. PROCESSES STARTED IN LAST 6H ---
Write-Host "--- [5] PROCESSES STARTED IN LAST 6 HOURS ---" -ForegroundColor Yellow
$procs = Get-Process | Where-Object { $_.StartTime -gt $start } -ErrorAction SilentlyContinue |
    Sort-Object StartTime |
    Select-Object ProcessName, Id, StartTime, Path
if ($procs) {
    $procs | Format-Table -AutoSize
} else {
    Write-Host "  None found.`n" -ForegroundColor Green
}

# --- 6. ACTIVE NETWORK CONNECTIONS ---
Write-Host "--- [6] ESTABLISHED NETWORK CONNECTIONS ---" -ForegroundColor Yellow
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Select-Object LocalPort, RemoteAddress, RemotePort, @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
    Sort-Object RemoteAddress | Format-Table -AutoSize

# --- 7. NEW SERVICES INSTALLED ---
Write-Host "--- [7] NEW SERVICES INSTALLED (Last 6h) ---" -ForegroundColor Yellow
$svc = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$start} -ErrorAction SilentlyContinue
if ($svc) {
    $svc | Select-Object TimeCreated, @{N='ServiceName';E={$_.Properties[0].Value}}, @{N='ImagePath';E={$_.Properties[1].Value}} | Format-Table -Wrap
} else {
    Write-Host "  None found.`n" -ForegroundColor Green
}

# --- 8. SCHEDULED TASKS CREATED RECENTLY ---
Write-Host "--- [8] RECENTLY CREATED SCHEDULED TASKS ---" -ForegroundColor Yellow
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.Date -and $_.Date -gt $start.ToString('yyyy-MM-ddTHH:mm:ss') }
if ($tasks) {
    $tasks | Select-Object TaskName, TaskPath, Date, Author | Format-Table -AutoSize
} else {
    Write-Host "  None found.`n" -ForegroundColor Green
}

# --- DONE ---
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " AUDIT COMPLETE" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
Write-Host "Red flags to look for:" -ForegroundColor Red
Write-Host "  - Failed logons from unknown accounts or external IPs"
Write-Host "  - LogonType 10 (RDP) you didn't initiate"
Write-Host "  - Webcam/mic timestamps you don't recognize"
Write-Host "  - Processes with random names or paths in Temp/AppData"
Write-Host "  - Unknown remote IPs (resolve with: nslookup <IP>)"
Write-Host "  - Services or scheduled tasks you didn't create`n"
pause
