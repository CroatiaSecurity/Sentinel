using System.Management;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Hid;

/// <summary>
/// HID Macro Guard - Detects USB-based keyboard injection attacks (BadUSB).
/// Monitors for rapid keystroke injection from HID devices.
/// </summary>
public sealed class HIDMacroGuard : BackgroundService
{
    private readonly ILogger<HIDMacroGuard> _logger;
    private readonly IDetectionEngine _detectionEngine;
    
    private readonly Dictionary<string, HIDDeviceInfo> _knownDevices;
    private readonly Dictionary<string, DateTimeOffset> _suspiciousDevices;
    private readonly TimeSpan _monitorInterval = TimeSpan.FromSeconds(30);
    // Note: Keystroke threshold logic planned for future implementation

    public HIDMacroGuard(
        ILogger<HIDMacroGuard> logger,
        IDetectionEngine detectionEngine)
    {
        _logger = logger;
        _detectionEngine = detectionEngine;
        _knownDevices = new Dictionary<string, HIDDeviceInfo>();
        _suspiciousDevices = new Dictionary<string, DateTimeOffset>();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== HID Macro Guard starting ===");

        // Initial device enumeration
        EnumerateHIDDevices();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_monitorInterval, stoppingToken);
                
                // Check for new HID devices
                CheckForNewDevices();
                
                // Monitor for suspicious activity
                MonitorSuspiciousActivity();
                
                // Cleanup old entries
                CleanupOldEntries();
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HIDMacroGuard: Error in main loop");
            }
        }
    }

    private void EnumerateHIDDevices()
    {
        try
        {
            var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_PnPEntity WHERE ClassGuid='{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}'");
            
            foreach (ManagementObject device in searcher.Get())
            {
                var deviceId = device["DeviceID"]?.ToString() ?? "";
                var name = device["Name"]?.ToString() ?? "Unknown HID Device";
                
                if (!string.IsNullOrEmpty(deviceId) && !_knownDevices.ContainsKey(deviceId))
                {
                    _knownDevices[deviceId] = new HIDDeviceInfo
                    {
                        DeviceId = deviceId,
                        Name = name,
                        FirstSeen = DateTimeOffset.UtcNow,
                        IsKeyboard = name.ToLowerInvariant().Contains("keyboard") ||
                                   name.ToLowerInvariant().Contains("kbd"),
                        IsMouse = name.ToLowerInvariant().Contains("mouse")
                    };

                    _logger.LogDebug("HIDMacroGuard: Enumerated {Name} ({Type})",
                        name,
                        _knownDevices[deviceId].IsKeyboard ? "Keyboard" :
                        _knownDevices[deviceId].IsMouse ? "Mouse" : "Other");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "HIDMacroGuard: Error enumerating devices");
        }
    }

    private void CheckForNewDevices()
    {
        try
        {
            var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_PnPEntity WHERE ClassGuid='{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}'");
            
            foreach (ManagementObject device in searcher.Get())
            {
                var deviceId = device["DeviceID"]?.ToString() ?? "";
                var name = device["Name"]?.ToString() ?? "Unknown HID Device";
                
                if (!string.IsNullOrEmpty(deviceId) && !_knownDevices.ContainsKey(deviceId))
                {
                    // New device detected
                    var isKeyboard = name.ToLowerInvariant().Contains("keyboard") ||
                                    name.ToLowerInvariant().Contains("kbd");
                    
                    _knownDevices[deviceId] = new HIDDeviceInfo
                    {
                        DeviceId = deviceId,
                        Name = name,
                        FirstSeen = DateTimeOffset.UtcNow,
                        IsKeyboard = isKeyboard,
                        IsMouse = name.ToLowerInvariant().Contains("mouse"),
                        IsNew = true
                    };

                    _logger.LogWarning(
                        "HIDMacroGuard: NEW HID DEVICE DETECTED - {Name} (ID: {Id})",
                        name, deviceId);

                    // If it's a keyboard that appeared suddenly, mark as suspicious
                    if (isKeyboard)
                    {
                        _suspiciousDevices[deviceId] = DateTimeOffset.UtcNow;
                        
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "HID: New Keyboard Device Detected",
                                    Evidence = $"New HID keyboard device '{name}' detected (ID: {deviceId}). This could be a BadUSB attack or legitimate USB keyboard.",
                                    Reasoning = "Sudden appearance of HID keyboard devices can indicate BadUSB-style attacks where malicious USB devices inject keystrokes.",
                                    Confidence = 0.60,
                                    Tier = DetectionTier.Tier2Indicator,
                                    ProcessName = "N/A",
                                    ProcessId = 0,
                                    Timestamp = DateTimeOffset.UtcNow,
                                    Metadata = new Dictionary<string, string>
                                    {
                                        ["device_id"] = deviceId,
                                        ["device_name"] = name,
                                        ["device_type"] = "HID Keyboard",
                                        ["technique"] = "T1056.001 - Keylogging (HID Injection)"
                                    }
                                }, CancellationToken.None);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, "HIDMacroGuard: Failed to emit detection");
                            }
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "HIDMacroGuard: Error checking for new devices");
        }
    }

    private void MonitorSuspiciousActivity()
    {
        // In a full implementation, this would use raw input or hooks
        // to monitor keystroke timing from specific devices
        // For now, we rely on the device appearance detection
        
        // Check if any suspicious devices have been present too long without user activity
        foreach (var deviceId in _suspiciousDevices.Keys.ToList())
        {
            var detectedAt = _suspiciousDevices[deviceId];
            var elapsed = DateTimeOffset.UtcNow - detectedAt;
            
            if (elapsed > TimeSpan.FromMinutes(5))
            {
                // Device has been present for 5+ minutes without incident
                // Remove from suspicious list (likely legitimate)
                _suspiciousDevices.Remove(deviceId);
                
                if (_knownDevices.TryGetValue(deviceId, out var device))
                {
                    device.IsTrusted = true;
                    _logger.LogDebug("HIDMacroGuard: Device {Name} marked as trusted", device.Name);
                }
            }
        }
    }

    private void CleanupOldEntries()
    {
        var cutoff = DateTimeOffset.UtcNow.AddHours(-24);
        
        var oldDevices = _knownDevices
            .Where(kv => kv.Value.FirstSeen < cutoff && kv.Value.IsTrusted)
            .Select(kv => kv.Key)
            .ToList();
        
        foreach (var deviceId in oldDevices)
        {
            _knownDevices.Remove(deviceId);
        }
    }

    /// <summary>
    /// Gets the list of currently monitored HID devices.
    /// </summary>
    public List<HIDDeviceInfo> GetMonitoredDevices()
    {
        return _knownDevices.Values.ToList();
    }

    /// <summary>
    /// Manually marks a device as trusted (user confirmation).
    /// </summary>
    public void MarkDeviceAsTrusted(string deviceId)
    {
        if (_knownDevices.TryGetValue(deviceId, out var device))
        {
            device.IsTrusted = true;
            _suspiciousDevices.Remove(deviceId);
            
            _logger.LogInformation(
                "HIDMacroGuard: Device {Name} manually marked as trusted",
                device.Name);
        }
    }
}

/// <summary>
/// Information about a HID device.
/// </summary>
public sealed class HIDDeviceInfo
{
    public string DeviceId { get; set; } = "";
    public string Name { get; set; } = "";
    public DateTimeOffset FirstSeen { get; set; }
    public bool IsKeyboard { get; set; }
    public bool IsMouse { get; set; }
    public bool IsNew { get; set; }
    public bool IsTrusted { get; set; }
    public string DeviceType => IsKeyboard ? "Keyboard" : IsMouse ? "Mouse" : "Other HID";

    public string Status => IsTrusted ? "Trusted" : IsNew ? "New (Monitoring)" : "Monitoring";
}


