using System.Collections.Concurrent;
using System.Management;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// USB Device Fingerprinter — Baselines USB devices by VID:PID:Serial and detects suspicious new devices.
///
/// Detects:
///   1. BadUSB: Unknown HID (keyboard) devices with unusual VID/PID → Tier1, 0.80
///   2. Composite devices (keyboard + storage = suspicious) → Tier1, 0.75
///   3. New mass storage devices → Tier2, 0.50 (informational)
///   4. Any other new USB device → Tier2, 0.40
///
/// Uses WMI (Win32_PnPEntity) to enumerate USB devices.
/// Polls every 30 seconds for new devices.
/// </summary>
public sealed class UsbDeviceFingerprinter : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<UsbDeviceFingerprinter> _logger;

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);

    // Baseline: DeviceID → UsbDeviceRecord
    private readonly ConcurrentDictionary<string, UsbDeviceRecord> _baseline = new(StringComparer.OrdinalIgnoreCase);

    // Known-good keyboard VIDs (legitimate peripheral manufacturers)
    private static readonly HashSet<int> KnownGoodKeyboardVids = new()
    {
        0x046D, // Logitech
        0x045E, // Microsoft
        0x04F2, // Chicony
        0x1B1C, // Corsair
        0x1532, // Razer
        0x258A, // SINO WEALTH
        0x0951, // Kingston/HyperX
        0x3434, // Keychron
        0x05AC, // Apple
    };

    public UsbDeviceFingerprinter(
        IDetectionEngine detectionEngine,
        ILogger<UsbDeviceFingerprinter> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== USB Device Fingerprinter starting ===");

        // Initial delay to let system stabilize
        await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);

        // Build initial baseline
        try
        {
            var initialDevices = EnumerateUsbDevices();
            foreach (var device in initialDevices)
            {
                _baseline[device.DeviceId] = device;
            }
            _logger.LogInformation("USB Fingerprinter: Baselined {Count} USB devices", _baseline.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "USB Fingerprinter: Failed to build initial baseline");
        }

        // Poll loop
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PollForNewDevicesAsync(stoppingToken);
                await Task.Delay(PollInterval, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "UsbDeviceFingerprinter: Poll error");
                await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
            }
        }
    }

    private async Task PollForNewDevicesAsync(CancellationToken ct)
    {
        var currentDevices = EnumerateUsbDevices();
        var now = DateTimeOffset.UtcNow;

        foreach (var device in currentDevices)
        {
            // Update LastSeen for known devices
            if (_baseline.TryGetValue(device.DeviceId, out var existing))
            {
                existing.LastSeen = now;
                continue;
            }

            // New device detected
            device.FirstSeen = now;
            device.LastSeen = now;
            _baseline[device.DeviceId] = device;

            await AnalyzeNewDevice(device, ct);
        }
    }

    private async Task AnalyzeNewDevice(UsbDeviceRecord device, CancellationToken ct)
    {
        // Check 1: Unknown HID (keyboard) device with unusual VID
        if (IsHidDevice(device) && !IsKnownGoodKeyboardVid(device.Vid))
        {
            await EmitDetection(
                "BadUSB: Unknown HID Device",
                $"New USB HID device detected with unknown VID:PID {device.Vid:X4}:{device.Pid:X4}. " +
                $"DeviceID: {device.DeviceId}. Description: {device.Description}. " +
                "This device claims to be a keyboard/HID but is not from a known peripheral manufacturer.",
                "USB devices claiming to be keyboards (HID class) but with unrecognized VID/PID are a " +
                "strong indicator of BadUSB attacks. Malicious USB devices (Rubber Ducky, Bash Bunny, " +
                "O.MG Cable) present as keyboards to inject keystrokes and execute commands. " +
                "Legitimate keyboards come from well-known manufacturers with recognized VIDs.",
                0.80,
                DetectionTier.Tier1Behavioral,
                device, ct);
            return;
        }

        // Check 2: Composite device (multiple interfaces — keyboard + storage is suspicious)
        if (IsCompositeDevice(device))
        {
            await EmitDetection(
                "BadUSB: Suspicious Composite Device",
                $"New composite USB device detected: {device.DeviceId}. " +
                $"Description: {device.Description}. VID:PID {device.Vid:X4}:{device.Pid:X4}. " +
                "Composite devices with multiple interfaces (e.g., keyboard + storage) are suspicious.",
                "Composite USB devices that combine keyboard/HID with mass storage interfaces are a " +
                "hallmark of attack tools like Bash Bunny and USB Armory. These devices can inject " +
                "keystrokes while simultaneously exfiltrating data to their storage partition. " +
                "Legitimate peripherals rarely combine keyboard and storage interfaces.",
                0.75,
                DetectionTier.Tier1Behavioral,
                device, ct);
            return;
        }

        // Check 3: New mass storage device (informational)
        if (IsMassStorageDevice(device))
        {
            await EmitDetection(
                "USB: New Mass Storage Device",
                $"New USB mass storage device connected: {device.DeviceId}. " +
                $"Description: {device.Description}. VID:PID {device.Vid:X4}:{device.Pid:X4}.",
                "A new USB mass storage device was connected that was not in the baseline. " +
                "While this is often legitimate (flash drives, external HDDs), it can also indicate " +
                "unauthorized data transfer attempts or supply-chain attacks via pre-loaded USB devices.",
                0.50,
                DetectionTier.Tier2Indicator,
                device, ct);
            return;
        }

        // Check 4: Any other new USB device
        await EmitDetection(
            "USB: New Device Detected",
            $"New USB device connected: {device.DeviceId}. " +
            $"Description: {device.Description}. Class: {device.DeviceClass}. " +
            $"VID:PID {device.Vid:X4}:{device.Pid:X4}.",
            "A new USB device was connected that was not present in the baseline. " +
            "This is informational — tracking new device connections helps detect " +
            "unauthorized hardware additions to the system.",
            0.40,
            DetectionTier.Tier2Indicator,
            device, ct);
    }

    private async Task EmitDetection(
        string ruleName, string evidence, string reasoning,
        double confidence, DetectionTier tier,
        UsbDeviceRecord device, CancellationToken ct)
    {
        _logger.LogWarning("USB Fingerprinter: {Rule} — {DeviceId}", ruleName, device.DeviceId);

        await _detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = ruleName,
            Evidence = evidence,
            Reasoning = reasoning,
            Confidence = confidence,
            Tier = tier,
            ProcessName = "UsbDeviceFingerprinter",
            ProcessId = Environment.ProcessId,
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["device_id"] = device.DeviceId,
                ["vid"] = device.Vid.ToString("X4"),
                ["pid"] = device.Pid.ToString("X4"),
                ["serial"] = device.Serial ?? "unknown",
                ["description"] = device.Description ?? "unknown",
                ["device_class"] = device.DeviceClass ?? "unknown",
                ["technique"] = "T1200 - Hardware Additions"
            }
        }, ct);
    }

    private List<UsbDeviceRecord> EnumerateUsbDevices()
    {
        var devices = new List<UsbDeviceRecord>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT DeviceID, Name, Description, PNPClass, Service, ConfigManagerErrorCode " +
                "FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB\\\\%'");

            using var results = searcher.Get();

            foreach (ManagementObject obj in results)
            {
                var deviceId = obj["DeviceID"]?.ToString();
                if (string.IsNullOrEmpty(deviceId))
                    continue;

                var (vid, pid, serial) = ParseDeviceId(deviceId);

                devices.Add(new UsbDeviceRecord
                {
                    DeviceId = deviceId,
                    Vid = vid,
                    Pid = pid,
                    Serial = serial,
                    Description = obj["Description"]?.ToString() ?? obj["Name"]?.ToString(),
                    DeviceClass = obj["PNPClass"]?.ToString(),
                    FirstSeen = DateTimeOffset.UtcNow,
                    LastSeen = DateTimeOffset.UtcNow,
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "USB enumeration error");
        }

        return devices;
    }

    private static (int vid, int pid, string? serial) ParseDeviceId(string deviceId)
    {
        // DeviceID format: USB\VID_XXXX&PID_XXXX\SerialNumber
        int vid = 0, pid = 0;
        string? serial = null;

        try
        {
            var parts = deviceId.Split('\\');

            if (parts.Length >= 2)
            {
                var idPart = parts[1]; // VID_XXXX&PID_XXXX or VID_XXXX&PID_XXXX&MI_XX

                var vidIdx = idPart.IndexOf("VID_", StringComparison.OrdinalIgnoreCase);
                if (vidIdx >= 0 && vidIdx + 8 <= idPart.Length)
                {
                    var vidStr = idPart.Substring(vidIdx + 4, 4);
                    int.TryParse(vidStr, System.Globalization.NumberStyles.HexNumber, null, out vid);
                }

                var pidIdx = idPart.IndexOf("PID_", StringComparison.OrdinalIgnoreCase);
                if (pidIdx >= 0 && pidIdx + 8 <= idPart.Length)
                {
                    var pidStr = idPart.Substring(pidIdx + 4, 4);
                    int.TryParse(pidStr, System.Globalization.NumberStyles.HexNumber, null, out pid);
                }
            }

            if (parts.Length >= 3)
            {
                serial = parts[2];
            }
        }
        catch
        {
            // Best-effort parsing
        }

        return (vid, pid, serial);
    }

    private static bool IsHidDevice(UsbDeviceRecord device)
    {
        // Check PNPClass or description for HID/Keyboard indicators
        if (device.DeviceClass != null)
        {
            var cls = device.DeviceClass;
            if (cls.Contains("Keyboard", StringComparison.OrdinalIgnoreCase) ||
                cls.Contains("HIDClass", StringComparison.OrdinalIgnoreCase) ||
                cls.Equals("HID", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        if (device.Description != null)
        {
            if (device.Description.Contains("Keyboard", StringComparison.OrdinalIgnoreCase) ||
                device.Description.Contains("HID", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static bool IsKnownGoodKeyboardVid(int vid)
    {
        return KnownGoodKeyboardVids.Contains(vid);
    }

    private static bool IsCompositeDevice(UsbDeviceRecord device)
    {
        // Composite devices have MI_ (Multiple Interface) in their DeviceID
        // or their description mentions "Composite"
        if (device.DeviceId.Contains("&MI_", StringComparison.OrdinalIgnoreCase))
            return false; // Individual interface of a composite — not the composite itself

        if (device.Description != null &&
            device.Description.Contains("Composite", StringComparison.OrdinalIgnoreCase))
            return true;

        // Check if DeviceID pattern suggests composite (VID&PID without MI_ but with multiple children)
        // A USB composite device typically has "USB Composite Device" as description
        return false;
    }

    private static bool IsMassStorageDevice(UsbDeviceRecord device)
    {
        if (device.DeviceClass != null)
        {
            if (device.DeviceClass.Contains("DiskDrive", StringComparison.OrdinalIgnoreCase) ||
                device.DeviceClass.Contains("USB", StringComparison.OrdinalIgnoreCase) &&
                device.Description != null &&
                device.Description.Contains("Mass Storage", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        if (device.Description != null)
        {
            if (device.Description.Contains("Mass Storage", StringComparison.OrdinalIgnoreCase) ||
                device.Description.Contains("USB Storage", StringComparison.OrdinalIgnoreCase) ||
                device.Description.Contains("Flash Drive", StringComparison.OrdinalIgnoreCase) ||
                device.Description.Contains("Disk Drive", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}

/// <summary>
/// Record of a USB device for fingerprinting and baseline tracking.
/// </summary>
public sealed class UsbDeviceRecord
{
    public required string DeviceId { get; init; }
    public int Vid { get; init; }
    public int Pid { get; init; }
    public string? Serial { get; init; }
    public string? Description { get; init; }
    public string? DeviceClass { get; init; }
    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
}
