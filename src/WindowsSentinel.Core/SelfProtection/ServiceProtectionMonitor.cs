using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.SelfProtection;

/// <summary>
/// CRITICAL SECURITY: Monitors and protects Sentinel service from tampering.
/// 
/// Protects against:
/// - Service stop attempts (sc.exe stop, Stop-Service, net stop)
/// - Registry key modification (HKLM\SYSTEM\CurrentControlSet\Services\Windows Sentinel)
/// - Service configuration changes (startup type, binary path)
/// - Service deletion
/// 
/// Detection methods:
/// - Registry change monitoring via polling
/// - SCM (Service Control Manager) event detection
/// - Service status monitoring
/// </summary>
public sealed class ServiceProtectionMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<ServiceProtectionMonitor> _logger;
    private readonly string _serviceName;
    private readonly string _serviceRegistryKey;
    private readonly string _executablePath;
    
    // Baseline values
    private string? _baselineImagePath;
    private int _baselineStartType = -1;
    private string? _baselineObjectName;
    private byte[]? _baselineSecurityDescriptor;
    private DateTime _lastRegistryCheck = DateTime.MinValue;
    private int _lastKnownStatus = 4; // Running = 4

    // Check intervals
    private static readonly TimeSpan RegistryCheckInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan StatusCheckInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan SdCheckInterval = TimeSpan.FromMinutes(1);

    // SCM native methods
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint dwAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceConfig(IntPtr hService, IntPtr lpServiceConfig, int cbBufSize, out int pcbBytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SERVICE_QUERY_CONFIG = 0x0001;
    private const uint SERVICE_QUERY_STATUS = 0x0004;

    public ServiceProtectionMonitor(
        IDetectionEngine detectionEngine,
        ILogger<ServiceProtectionMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _serviceName = "Windows Sentinel";
        _serviceRegistryKey = $"SYSTEM\\CurrentControlSet\\Services\\{_serviceName}";
        _executablePath = Process.GetCurrentProcess().MainModule?.FileName ?? 
            Path.Combine(AppContext.BaseDirectory, "WindowsSentinel.Service.exe");
        _lastKnownStatus = 4; // Running = 4
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Service Protection Monitor starting ===");
        _logger.LogInformation("Monitoring service: {ServiceName}", _serviceName);

        // Initialize baselines
        await InitializeBaselinesAsync(stoppingToken);

        // Start monitoring loops
        var registryTask = RunRegistryMonitoringAsync(stoppingToken);
        var statusTask = RunStatusMonitoringAsync(stoppingToken);
        var sdTask = RunSecurityDescriptorMonitoringAsync(stoppingToken);

        await Task.WhenAll(registryTask, statusTask, sdTask);
    }

    private async Task InitializeBaselinesAsync(CancellationToken ct)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(_serviceRegistryKey);
            if (key != null)
            {
                _baselineImagePath = key.GetValue("ImagePath") as string;
                _baselineStartType = Convert.ToInt32(key.GetValue("Start") ?? 2);
                _baselineObjectName = key.GetValue("ObjectName") as string;
                
                // Get security descriptor
                var sdBytes = key.GetAccessControl().GetSecurityDescriptorBinaryForm();
                _baselineSecurityDescriptor = sdBytes;

                _logger.LogDebug("ServiceProtection: Baseline established");
                _logger.LogDebug("  ImagePath: {Path}", _baselineImagePath);
                _logger.LogDebug("  StartType: {Type}", _baselineStartType);
            }
            else
            {
                _logger.LogError("ServiceProtection: Cannot open service registry key!");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "ServiceProtection: Failed to initialize baselines");
        }

        await Task.CompletedTask;
    }

    private async Task RunRegistryMonitoringAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(RegistryCheckInterval, ct);

                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(_serviceRegistryKey);
                if (key == null)
                {
                    // CRITICAL: Service key was deleted!
                    _logger.LogCritical("ServiceProtection: SERVICE REGISTRY KEY DELETED!");
                    
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "CRITICAL: Service Registry Key Deleted",
                        Evidence = $"The Windows Sentinel service registry key was deleted from HKLM\\{_serviceRegistryKey}",
                        Reasoning = "The service registry key has been deleted. This is a severe tampering attempt that will prevent Sentinel from starting on reboot. This is typically done by malware or attackers to permanently disable security software.",
                        Confidence = 0.99,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "N/A",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new()
                        {
                            ["technique"] = "T1562.001 - Impair Defenses: Disable or Modify Tools",
                            ["registry_key"] = $"HKLM\\{_serviceRegistryKey}",
                            ["severity"] = "CRITICAL"
                        }
                    }, ct);

                    continue;
                }

                // Check for key value changes
                var currentImagePath = key.GetValue("ImagePath") as string;
                var currentStartType = Convert.ToInt32(key.GetValue("Start") ?? 2);
                var currentObjectName = key.GetValue("ObjectName") as string;

                // Detect ImagePath tampering (binary replacement)
                if (_baselineImagePath != null && currentImagePath != _baselineImagePath)
                {
                    _logger.LogCritical("ServiceProtection: ImagePath changed from '{Old}' to '{New}'!",
                        _baselineImagePath, currentImagePath);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "CRITICAL: Service Binary Path Tampered",
                        Evidence = $"Service ImagePath changed from '{_baselineImagePath}' to '{currentImagePath}'",
                        Reasoning = "The service binary path has been modified. This is a severe tampering attempt that may cause Sentinel to load a malicious binary on restart.",
                        Confidence = 0.98,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "N/A",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new()
                        {
                            ["technique"] = "T1543.003 - Create or Modify System Process: Windows Service",
                            ["old_path"] = _baselineImagePath,
                            ["new_path"] = currentImagePath ?? "NULL"
                        }
                    }, ct);

                    _baselineImagePath = currentImagePath; // Update to prevent spam
                }

                // Detect startup type change (disable on boot)
                if (_baselineStartType != -1 && currentStartType != _baselineStartType)
                {
                    var oldType = GetStartTypeName(_baselineStartType);
                    var newType = GetStartTypeName(currentStartType);
                    
                    _logger.LogCritical("ServiceProtection: Start type changed from {Old} ({OldVal}) to {New} ({NewVal})!",
                        oldType, _baselineStartType, newType, currentStartType);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "CRITICAL: Service Startup Type Modified",
                        Evidence = $"Service startup type changed from {oldType} to {newType}",
                        Reasoning = currentStartType == 4 
                            ? "The service has been set to DISABLED. Sentinel will not start automatically on boot, effectively disabling protection."
                            : "The service startup type has been modified. This may prevent Sentinel from starting properly.",
                        Confidence = 0.95,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "N/A",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new()
                        {
                            ["technique"] = "T1562.001 - Impair Defenses: Disable or Modify Tools",
                            ["old_start_type"] = oldType,
                            ["new_start_type"] = newType,
                            ["start_type_value"] = currentStartType.ToString()
                        }
                    }, ct);

                    _baselineStartType = currentStartType;
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "ServiceProtection: Registry monitoring error");
            }
        }
    }

    private async Task RunStatusMonitoringAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(StatusCheckInterval, ct);

                using var sc = new ServiceController(_serviceName);
                sc.Refresh();

                // Detect unexpected stop (4 = Running, 1 = Stopped, 3 = StopPending)
                var statusValue = (int)sc.Status;
                if (_lastKnownStatus == 4 &&
                    (statusValue == 1 || statusValue == 3))
                {
                    _logger.LogCritical("ServiceProtection: Service stopped unexpectedly!");

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "CRITICAL: Service Stopped Unexpectedly",
                        Evidence = $"Windows Sentinel service transitioned from Running to {sc.Status}",
                        Reasoning = "The Sentinel service has been stopped. If this was not initiated by an administrator, this may indicate a tampering attempt. The service should be restarted immediately.",
                        Confidence = 0.90,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "services.exe",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new()
                        {
                            ["technique"] = "T1489 - Service Stop",
                            ["previous_status"] = _lastKnownStatus.ToString(),
                            ["current_status"] = sc.Status.ToString()
                        }
                    }, ct);
                }

                // Detect pause (unusual for this service) - 7 = Paused, 6 = PausePending
                if (statusValue == 7 || statusValue == 6)
                {
                    _logger.LogCritical("ServiceProtection: Service paused!");

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "HIGH: Service Paused",
                        Evidence = "Windows Sentinel service has been paused",
                        Reasoning = "The Sentinel service has been paused. While paused, detection capabilities may be degraded. This is an unusual state for Sentinel.",
                        Confidence = 0.85,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "services.exe",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new()
                        {
                            ["technique"] = "T1489 - Service Stop",
                            ["action"] = "pause"
                        }
                    }, ct);
                }

                _lastKnownStatus = (int)sc.Status;
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (InvalidOperationException)
            {
                // Service not found - critical!
                _logger.LogCritical("ServiceProtection: Service not found in SCM!");
                
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "CRITICAL: Service Removed from SCM",
                    Evidence = "Windows Sentinel service is not registered in the Service Control Manager",
                    Reasoning = "The Sentinel service has been removed from the Service Control Manager. This is a severe tampering attempt that completely disables Sentinel.",
                    Confidence = 0.99,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "N/A",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new()
                    {
                        ["technique"] = "T1543.003 - Create or Modify System Process: Windows Service",
                        ["action"] = "service_deletion"
                    }
                }, ct);
                
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "ServiceProtection: Status monitoring error");
            }
        }
    }

    private async Task RunSecurityDescriptorMonitoringAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(SdCheckInterval, ct);

                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(_serviceRegistryKey);
                if (key == null) continue;

                var currentSd = key.GetAccessControl().GetSecurityDescriptorBinaryForm();
                
                if (_baselineSecurityDescriptor != null && 
                    !currentSd.SequenceEqual(_baselineSecurityDescriptor))
                {
                    _logger.LogCritical("ServiceProtection: Registry ACLs modified!");

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "HIGH: Service Registry ACL Modified",
                        Evidence = "The security descriptor (ACL) of the Sentinel service registry key has been modified",
                        Reasoning = "The registry ACLs for the Sentinel service have been modified. This may allow unauthorized users to modify service configuration, potentially enabling disablement or tampering.",
                        Confidence = 0.88,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "N/A",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new()
                        {
                            ["technique"] = "T1222 - File and Directory Permissions Modification",
                            ["target"] = $"HKLM\\{_serviceRegistryKey}"
                        }
                    }, ct);

                    _baselineSecurityDescriptor = currentSd;
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "ServiceProtection: SD monitoring error");
            }
        }
    }

    private static string GetStartTypeName(int startType)
    {
        return startType switch
        {
            0 => "Boot",
            1 => "System",
            2 => "Automatic",
            3 => "Manual",
            4 => "Disabled",
            _ => $"Unknown({startType})"
        };
    }
}
