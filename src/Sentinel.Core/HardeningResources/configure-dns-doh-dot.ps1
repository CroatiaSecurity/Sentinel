#Requires -RunAsAdministrator
# Configures DoH (Cloudflare primary, Google secondary) with DoT on both

# Register DoH server templates in Windows
$servers = @(
    @{ IP = "1.1.1.1";              DohTemplate = "https://cloudflare-dns.com/dns-query" },
    @{ IP = "1.0.0.1";              DohTemplate = "https://cloudflare-dns.com/dns-query" },
    @{ IP = "2606:4700:4700::1111"; DohTemplate = "https://cloudflare-dns.com/dns-query" },
    @{ IP = "2606:4700:4700::1001"; DohTemplate = "https://cloudflare-dns.com/dns-query" },
    @{ IP = "8.8.8.8";              DohTemplate = "https://dns.google/dns-query" },
    @{ IP = "8.8.4.4";              DohTemplate = "https://dns.google/dns-query" },
    @{ IP = "2001:4860:4860::8888"; DohTemplate = "https://dns.google/dns-query" },
    @{ IP = "2001:4860:4860::8844"; DohTemplate = "https://dns.google/dns-query" }
)

Write-Host "Registering DoH server templates..." -ForegroundColor Cyan
foreach ($server in $servers) {
    try {
        Add-DnsClientDohServerAddress -ServerAddress $server.IP -DohTemplate $server.DohTemplate -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop
        Write-Host "  Added: $($server.IP)" -ForegroundColor Green
    } catch {
        Set-DnsClientDohServerAddress -ServerAddress $server.IP -DohTemplate $server.DohTemplate -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue
        Write-Host "  Updated: $($server.IP)" -ForegroundColor Yellow
    }
}

# Get active network adapter
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notmatch "Virtual|Loopback|Bluetooth" } | Select-Object -First 1

if (-not $adapter) {
    Write-Host "No active network adapter found!" -ForegroundColor Red
    exit 1
}

Write-Host "`nConfiguring adapter: $($adapter.Name) [$($adapter.InterfaceGuid)]" -ForegroundColor Cyan

# Set DNS servers via netsh (more reliable for triggering Settings UI update)
Write-Host "`nSetting IPv4 DNS servers..." -ForegroundColor Cyan
netsh interface ipv4 set dnsservers name="$($adapter.Name)" static 1.1.1.1 primary validate=no
netsh interface ipv4 add dnsservers name="$($adapter.Name)" 8.8.8.8 index=2 validate=no

Write-Host "Setting IPv6 DNS servers..." -ForegroundColor Cyan
netsh interface ipv6 set dnsservers name="$($adapter.Name)" static 2606:4700:4700::1111 primary validate=no
netsh interface ipv6 add dnsservers name="$($adapter.Name)" 2001:4860:4860::8888 index=2 validate=no

# Configure DoH per-interface via registry (this controls the dropdown in Settings)
$guid = $adapter.InterfaceGuid
$basePath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$guid\DohInterfaceSettings"

Write-Host "`nEnabling DoH for each DNS server..." -ForegroundColor Cyan

# IPv4 uses Doh\, IPv6 uses Doh6\
$dohServers = @(
    @{ IP = "1.1.1.1";              Template = "https://cloudflare-dns.com/dns-query"; Path = "Doh" },
    @{ IP = "8.8.8.8";              Template = "https://dns.google/dns-query";         Path = "Doh" },
    @{ IP = "2606:4700:4700::1111"; Template = "https://cloudflare-dns.com/dns-query"; Path = "Doh6" },
    @{ IP = "2001:4860:4860::8888"; Template = "https://dns.google/dns-query";         Path = "Doh6" }
)
foreach ($doh in $dohServers) {
    $dohPath = "$basePath\$($doh.Path)\$($doh.IP)"
    New-Item -Path $dohPath -Force | Out-Null
    # DohFlags: 0x11 (17) as QWORD = On (automatic)
    Set-ItemProperty -Path $dohPath -Name "DohFlags" -Value 0x11 -Type QWord
    Set-ItemProperty -Path $dohPath -Name "DohTemplate" -Value $doh.Template -Type String
    Write-Host "  Enabled DoH: $($doh.IP)" -ForegroundColor Green
}

# Configure DoT via registry (Dot\ for IPv4, Dot6\ for IPv6)
Write-Host "`nEnabling DoT for each DNS server..." -ForegroundColor Cyan
$dotBasePath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$guid\DotInterfaceSettings"
$dotServers = @(
    @{ IP = "1.1.1.1";              Host = "cloudflare-dns.com"; Path = "Dot" },
    @{ IP = "8.8.8.8";              Host = "dns.google";         Path = "Dot" },
    @{ IP = "2606:4700:4700::1111"; Host = "cloudflare-dns.com"; Path = "Dot6" },
    @{ IP = "2001:4860:4860::8888"; Host = "dns.google";         Path = "Dot6" }
)
foreach ($dot in $dotServers) {
    $serverPath = "$dotBasePath\$($dot.Path)\$($dot.IP)"
    New-Item -Path $serverPath -Force | Out-Null
    Set-ItemProperty -Path $serverPath -Name "DotFlags" -Value 0x11 -Type QWord
    Set-ItemProperty -Path $serverPath -Name "DotHost" -Value $dot.Host -Type String
    Write-Host "  Enabled DoT: $($dot.IP) -> $($dot.Host)" -ForegroundColor Green
}

# Flush and restart
Write-Host "`nApplying changes..." -ForegroundColor Yellow
Clear-DnsClientCache
Stop-Service -Name Dnscache -Force -ErrorAction SilentlyContinue
Start-Service -Name Dnscache

Write-Host "`n========================================" -ForegroundColor White
Write-Host "Configuration Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor White
Write-Host "Primary:   Cloudflare 1.1.1.1 / 2606:4700:4700::1111"
Write-Host "Secondary: Google     8.8.8.8 / 2001:4860:4860::8888"
Write-Host "DoH: Enabled (Automatic) | DoT: Enabled"
Write-Host "`nReopen Settings > Network > DNS to verify the dropdowns show 'On (automatic)'" -ForegroundColor Cyan
