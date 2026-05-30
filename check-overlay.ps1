# Check Agent log locations
$paths = @(
    (Join-Path $env:LOCALAPPDATA "WindowsSentinel"),
    (Join-Path $env:APPDATA "WindowsSentinel"),
    (Join-Path $env:ProgramData "WindowsSentinel"),
    "C:\Program Files\WindowsSentinel"
)

Write-Host "=== Searching for Agent logs ==="
foreach ($p in $paths) {
    if (Test-Path $p) {
        Write-Host "`nDirectory: $p"
        Get-ChildItem $p -Recurse -File | Where-Object { $_.Name -match "log|event|agent" } | ForEach-Object {
            Write-Host ("  " + $_.FullName + " (" + [math]::Round($_.Length/1KB,1) + " KB, " + $_.LastWriteTime + ")")
        }
    }
}

Write-Host "`n=== Checking Agent event log in ProgramData ==="
$agentLog = Join-Path $env:ProgramData "WindowsSentinel\agent-events.jsonl"
if (Test-Path $agentLog) {
    Write-Host "Found: $agentLog"
    $lines = Get-Content $agentLog -Tail 50
    $overlayOrKill = $lines | Where-Object { $_ -match "[Oo]verlay|[Kk]ill|[Tt]erminate|fm" }
    $overlayOrKill | ForEach-Object { Write-Host $_; Write-Host "---" }
} else {
    Write-Host "Not found."
}

Write-Host "`n=== Checking Windows Event Log for Sentinel ==="
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Windows Sentinel'; StartTime=(Get-Date).AddHours(-1)} -MaxEvents 20 -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Message -match "overlay|kill|fm|terminat") {
        Write-Host ("[" + $_.TimeCreated + "] " + $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length)))
        Write-Host "---"
    }
}
