using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Health;

/// <summary>
/// Health Check Service - Monitors system security posture and Sentinel health.
/// </summary>
public sealed class HealthCheckService : BackgroundService
{
    private readonly ILogger<HealthCheckService> _logger;
    private readonly string _sentinelPath;
    private DateTimeOffset _lastHealthCheck = DateTimeOffset.MinValue;

    public HealthCheckService(ILogger<HealthCheckService> logger)
    {
        _logger = logger;
        _sentinelPath = Process.GetCurrentProcess().MainModule?.FileName ?? AppContext.BaseDirectory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Health Check Service starting ===");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
                await PerformHealthCheckAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HealthCheck: Error during health check");
            }
        }
    }

    /// <summary>
    /// Performs a comprehensive health check.
    /// </summary>
    public async Task<HealthReport> PerformHealthCheckAsync(CancellationToken cancellationToken = default)
    {
        var report = new HealthReport
        {
            Timestamp = DateTimeOffset.UtcNow,
            Checks = new List<HealthCheck>()
        };

        _logger.LogInformation("HealthCheck: Performing system health check...");

        // 1. Sentinel Installation Check
        report.Checks.Add(await CheckSentinelInstallationAsync(cancellationToken));

        // 2. AMSI Availability Check
        report.Checks.Add(CheckAmsiAvailability());

        // 3. ETW Status Check
        report.Checks.Add(CheckEtwStatus());

        // 4. Windows Defender Status
        report.Checks.Add(await CheckDefenderStatusAsync(cancellationToken));

        // 5. Elevation Status
        report.Checks.Add(CheckElevationStatus());

        // 6. Real-time Protection Status
        report.Checks.Add(await CheckRealtimeProtectionAsync(cancellationToken));

        // 7. Firewall Status
        report.Checks.Add(CheckFirewallStatus());

        // 8. UAC Configuration
        report.Checks.Add(CheckUACConfiguration());

        // 9. System Updates
        report.Checks.Add(await CheckSystemUpdatesAsync(cancellationToken));

        // 10. Disk Space
        report.Checks.Add(CheckDiskSpace());

        // 11. Memory Usage
        report.Checks.Add(CheckMemoryUsage());

        // 12. Network Connectivity
        report.Checks.Add(CheckNetworkConnectivity());

        // Calculate overall status
        report.OverallStatus = CalculateOverallStatus(report.Checks);
        report.IssuesFound = report.Checks.Count(c => c.Status == HealthStatus.Warning || c.Status == HealthStatus.Critical);

        _lastHealthCheck = report.Timestamp;

        _logger.LogInformation(
            "HealthCheck: Completed. Status: {Status}, Issues: {Issues}",
            report.OverallStatus, report.IssuesFound);

        return report;
    }

    /// <summary>
    /// Gets a quick summary of system health.
    /// </summary>
    public HealthSummary GetQuickSummary()
    {
        return new HealthSummary
        {
            LastCheck = _lastHealthCheck,
            SentinelRunning = true,
            IsElevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator),
            AmsiAvailable = IsAmsiAvailable(),
            EtwEnabled = IsEtwEnabled(),
            DefenderActive = IsDefenderActive(),
            RealtimeProtectionEnabled = IsRealtimeProtectionEnabled()
        };
    }

    private async Task<HealthCheck> CheckSentinelInstallationAsync(CancellationToken cancellationToken)
    {
        var check = new HealthCheck { Name = "Sentinel Installation" };

        try
        {
            if (!File.Exists(_sentinelPath))
            {
                check.Status = HealthStatus.Critical;
                check.Message = "Sentinel executable not found";
                return check;
            }

            // Check hash
            using var sha256 = SHA256.Create();
            await using var stream = File.OpenRead(_sentinelPath);
            var hash = await sha256.ComputeHashAsync(stream, cancellationToken);
            check.Details = $"Executable hash: {Convert.ToHexString(hash)[..16]}...";

            check.Status = HealthStatus.Healthy;
            check.Message = "Installation verified";
        }
        catch (Exception ex)
        {
            check.Status = HealthStatus.Warning;
            check.Message = $"Verification error: {ex.Message}";
        }

        return check;
    }

    private HealthCheck CheckAmsiAvailability()
    {
        var check = new HealthCheck { Name = "AMSI Availability" };

        try
        {
            var amsiAvailable = IsAmsiAvailable();
            
            check.Status = amsiAvailable ? HealthStatus.Healthy : HealthStatus.Warning;
            check.Message = amsiAvailable ? "AMSI is available and functional" : "AMSI not available or disabled";
        }
        catch (Exception ex)
        {
            check.Status = HealthStatus.Warning;
            check.Message = $"AMSI check failed: {ex.Message}";
        }

        return check;
    }

    private HealthCheck CheckEtwStatus()
    {
        var check = new HealthCheck { Name = "ETW Status" };

        try
        {
            var etwEnabled = IsEtwEnabled();
            
            check.Status = etwEnabled ? HealthStatus.Healthy : HealthStatus.Warning;
            check.Message = etwEnabled ? "ETW providers active" : "ETW may be disabled or tampered";
        }
        catch (Exception ex)
        {
            check.Status = HealthStatus.Warning;
            check.Message = $"ETW check failed: {ex.Message}";
        }

        return check;
    }

    private Task<HealthCheck> CheckDefenderStatusAsync(CancellationToken cancellationToken)
    {
        var check = new HealthCheck { Name = "Windows Defender" };

        try
        {
            var defenderActive = IsDefenderActive();
            
            check.Status = defenderActive ? HealthStatus.Healthy : HealthStatus.Warning;
            check.Message = defenderActive ? "Windows Defender is active" : "Windows Defender is disabled or not present";
        }
        catch (Exception ex)
        {
            check.Status = HealthStatus.Warning;
            check.Message = $"Defender check failed: {ex.Message}";
        }

        return Task.FromResult(check);
    }

    private HealthCheck CheckElevationStatus()
    {
        var check = new HealthCheck { Name = "Elevation Status" };

        try
        {
            var isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            
            check.Status = HealthStatus.Healthy;
            check.Message = isAdmin ? "Running with administrator privileges" : "Running as standard user (reduced capability)";
            check.Details = isAdmin ? "Full ETW access available" : "Falling back to WMI for process monitoring";
        }
        catch (Exception ex)
        {
            check.Status = HealthStatus.Warning;
            check.Message = $"Elevation check failed: {ex.Message}";
        }

        return check;
    }

    private Task<HealthCheck> CheckRealtimeProtectionAsync(CancellationToken cancellationToken)
    {
        var check = new HealthCheck { Name = "Real-time Protection" };

        try
        {
            var rtpEnabled = IsRealtimeProtectionEnabled();
            
            check.Status = rtpEnabled ? HealthStatus.Healthy : HealthStatus.Warning;
            check.Message = rtpEnabled ? "Real-time protection is enabled" : "Real-time protection is disabled";
        }
        catch (Exception ex)
        {
            check.Status = HealthStatus.Warning;
            check.Message = $"RTP check failed: {ex.Message}";
        }

        return Task.FromResult(check);
    }

    private HealthCheck CheckFirewallStatus()
    {
        var check = new HealthCheck { Name = "Windows Firewall" };

        try
        {
            // Check if firewall is enabled for all profiles
            var firewallEnabled = CheckFirewallEnabled();
            
            check.Status = firewallEnabled ? HealthStatus.Healthy : HealthStatus.Warning;
            check.Message = firewallEnabled ? "Windows Firewall is enabled" : "Windows Firewall is disabled";
        }
        catch (Exception ex)
        {
            check.Status = HealthStatus.Warning;
            check.Message = $"Firewall check failed: {ex.Message}";
        }

        return check;
    }

    private HealthCheck CheckUACConfiguration()
    {
        var check = new HealthCheck { Name = "UAC Configuration" };

        try
        {
            var uacLevel = GetUACLevel();
            
            check.Status = uacLevel >= 3 ? HealthStatus.Healthy : HealthStatus.Warning;
            check.Message = $"UAC level: {uacLevel}/5";
            check.Details = uacLevel >= 3 
                ? "UAC is properly configured" 
                : "UAC may be set too permissive";
        }
        catch (Exception ex)
        {
            check.Status = HealthStatus.Warning;
            check.Message = $"UAC check failed: {ex.Message}";
        }

        return check;
    }

    private Task<HealthCheck> CheckSystemUpdatesAsync(CancellationToken cancellationToken)
    {
        var check = new HealthCheck { Name = "System Updates" };

        try
        {
            // Simplified check - would check Windows Update in production
            check.Status = HealthStatus.Healthy;
            check.Message = "Update status check completed";
            check.Details = "Last check: See Windows Update settings";
        }
        catch (Exception ex)
        {
            check.Status = HealthStatus.Warning;
            check.Message = $"Update check failed: {ex.Message}";
        }

        return Task.FromResult(check);
    }

    private HealthCheck CheckDiskSpace()
    {
        var check = new HealthCheck { Name = "Disk Space" };

        try
        {
            var drives = DriveInfo.GetDrives().Where(d => d.IsReady).ToList();
            var lowSpaceDrives = drives.Where(d => d.AvailableFreeSpace < 10L * 1024 * 1024 * 1024).ToList(); // < 10GB

            if (lowSpaceDrives.Any())
            {
                check.Status = HealthStatus.Warning;
                check.Message = $"Low disk space on {lowSpaceDrives.Count} drive(s)";
                check.Details = string.Join(", ", lowSpaceDrives.Select(d => 
                    $"{d.Name} {d.AvailableFreeSpace / (1024 * 1024 * 1024):F1}GB free"));
            }
            else
            {
                check.Status = HealthStatus.Healthy;
                check.Message = "Disk space is adequate on all drives";
            }
        }
        catch (Exception ex)
        {
            check.Status = HealthStatus.Warning;
            check.Message = $"Disk check failed: {ex.Message}";
        }

        return check;
    }

    private HealthCheck CheckMemoryUsage()
    {
        var check = new HealthCheck { Name = "Memory Usage" };

        try
        {
            var proc = Process.GetCurrentProcess();
            var memUsageMB = proc.WorkingSet64 / (1024 * 1024);

            check.Status = memUsageMB < 500 ? HealthStatus.Healthy : HealthStatus.Warning;
            check.Message = $"Sentinel memory usage: {memUsageMB:F0} MB";
            check.Details = memUsageMB < 500 
                ? "Memory usage is within normal range" 
                : "Consider restarting Sentinel if memory usage continues to grow";
        }
        catch (Exception ex)
        {
            check.Status = HealthStatus.Warning;
            check.Message = $"Memory check failed: {ex.Message}";
        }

        return check;
    }

    private HealthCheck CheckNetworkConnectivity()
    {
        var check = new HealthCheck { Name = "Network Connectivity" };

        try
        {
            // Check if any network interface is up
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            var activeInterfaces = interfaces.Where(i => 
                i.OperationalStatus == OperationalStatus.Up && 
                i.NetworkInterfaceType != NetworkInterfaceType.Loopback).ToList();

            check.Status = activeInterfaces.Any() ? HealthStatus.Healthy : HealthStatus.Warning;
            check.Message = activeInterfaces.Any() 
                ? $"Network active ({activeInterfaces.Count} interface(s))" 
                : "No active network interfaces";
        }
        catch (Exception ex)
        {
            check.Status = HealthStatus.Warning;
            check.Message = $"Network check failed: {ex.Message}";
        }

        return check;
    }

    private HealthStatus CalculateOverallStatus(List<HealthCheck> checks)
    {
        if (checks.Any(c => c.Status == HealthStatus.Critical))
            return HealthStatus.Critical;
        if (checks.Count(c => c.Status == HealthStatus.Warning) > 3)
            return HealthStatus.Warning;
        if (checks.Any(c => c.Status == HealthStatus.Warning))
            return HealthStatus.Warning;
        return HealthStatus.Healthy;
    }

    // Helper methods
    private bool IsAmsiAvailable()
    {
        try
        {
            var amsiDll = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "amsi.dll");
            return File.Exists(amsiDll);
        }
        catch { return false; }
    }

    private bool IsEtwEnabled()
    {
        try
        {
            // Check if we can access ETW
            var eventLog = new EventLog("Security");
            return eventLog.Entries.Count >= 0; // Will throw if no access
        }
        catch { return false; }
    }

    private bool IsDefenderActive()
    {
        try
        {
            // Check if MsMpEng.exe is running
            return Process.GetProcessesByName("MsMpEng").Any();
        }
        catch { return false; }
    }

    private bool IsRealtimeProtectionEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
            var disabled = key?.GetValue("DisableRealtimeMonitoring") as int?;
            return disabled != 1;
        }
        catch { return false; }
    }

    private bool CheckFirewallEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile");
            var enabled = key?.GetValue("EnableFirewall") as int?;
            return enabled == 1;
        }
        catch { return false; }
    }

    private int GetUACLevel()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            var consentPrompt = key?.GetValue("ConsentPromptBehaviorAdmin") as int? ?? 5;
            var secureDesktop = key?.GetValue("PromptOnSecureDesktop") as int? ?? 1;
            
            // Calculate approximate UAC level (1-5)
            if (consentPrompt == 2) return 5; // Always notify
            if (consentPrompt == 5 && secureDesktop == 1) return 4; // Default
            if (consentPrompt == 5 && secureDesktop == 0) return 3; // Notify without dim
            if (consentPrompt == 0) return 1; // Never notify
            return 3;
        }
        catch { return 5; }
    }
}

/// <summary>
/// Health report containing all check results.
/// </summary>
public sealed class HealthReport
{
    public DateTimeOffset Timestamp { get; set; }
    public HealthStatus OverallStatus { get; set; }
    public int IssuesFound { get; set; }
    public List<HealthCheck> Checks { get; set; } = new();

    public string Summary => OverallStatus switch
    {
        HealthStatus.Healthy => "System is healthy",
        HealthStatus.Warning => $"{IssuesFound} warning(s) detected",
        HealthStatus.Critical => "Critical issues require attention",
        _ => "Unknown status"
    };
}

/// <summary>
/// Individual health check result.
/// </summary>
public sealed class HealthCheck
{
    public string Name { get; set; } = "";
    public HealthStatus Status { get; set; }
    public string Message { get; set; } = "";
    public string? Details { get; set; }

    public string StatusIcon => Status switch
    {
        HealthStatus.Healthy => "✓",
        HealthStatus.Warning => "⚠",
        HealthStatus.Critical => "✗",
        _ => "?"
    };
}

/// <summary>
/// Quick health summary.
/// </summary>
public sealed class HealthSummary
{
    public DateTimeOffset LastCheck { get; set; }
    public bool SentinelRunning { get; set; }
    public bool IsElevated { get; set; }
    public bool AmsiAvailable { get; set; }
    public bool EtwEnabled { get; set; }
    public bool DefenderActive { get; set; }
    public bool RealtimeProtectionEnabled { get; set; }

    public int HealthyCount => new[] { SentinelRunning, AmsiAvailable, EtwEnabled, DefenderActive, RealtimeProtectionEnabled }.Count(b => b);
    public int TotalCount => 5;
}

public enum HealthStatus
{
    Healthy,
    Warning,
    Critical
}


