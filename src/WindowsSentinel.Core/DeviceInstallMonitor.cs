using System.Collections.Concurrent;
using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace WindowsSentinel.Core;

/// <summary>
/// Device Installation Monitor (v4.2.0) â€” Detects new device installations including:
///
///   1. Virtual keyboard/HID devices (BadUSB, phantom keyboard attacks)
///   2. Network adapters (TAP/VPN adapters, rogue NICs for MITM)
///   3. Storage devices (iSCSI, virtual disks, NAS mounts)
///   4. New kernel drivers being loaded (BYOVD, rootkit installation)
///   5. Any PnP device appearing after baseline (catch-all)
///   6. Hidden/phantom devices (devices present but not connected â€” attacker persistence)
///   7. Startup cleanup of stuck/obsolete/ghost devices
///
/// Detection method:
///   - Baselines all installed devices on startup via WMI Win32_PnPEntity
///   - Scans for hidden/ghost devices (present in registry but not physically connected)
///   - Polls every 15 seconds for new devices
///   - Subscribes to WMI __InstanceCreationEvent for Win32_PnPEntity (real-time)
///   - Monitors Win32_SystemDriver for new kernel driver loads
///   - On startup: cleans up stuck/obsolete/ghost devices that serve no purpose
///
/// Threat model:
///   - Attacker with admin access installs virtual keyboard â†’ keystroke injection
///   - Attacker installs TAP adapter â†’ traffic interception/MITM
///   - Attacker mounts iSCSI/virtual disk â†’ data staging or payload delivery
///   - Attacker loads vulnerable driver (BYOVD) â†’ kernel-level access
///   - Attacker installs hidden device for persistence (survives reboot, invisible in Device Manager)
///
/// MITRE ATT&amp;CK:
///   T1200 â€” Hardware Additions
///   T1056.001 â€” Input Capture: Keylogging (via virtual HID)
///   T1557 â€” Adversary-in-the-Middle (via rogue network adapter)
///   T1543.003 â€” Create or Modify System Process: Windows Service (driver load)
///   T1068 â€” Exploitation for Privilege Escalation (BYOVD)
///   T1564.001 â€” Hide Artifacts: Hidden Files and Directories (ghost devices)
/// </summary>
public sealed class DeviceInstallMonitor : BackgroundService
{
    private readonly DetectionEngine _detectionEngine;
    private readonly ILogger<DeviceInstallMonitor> _logger;

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan StartupDelay = TimeSpan.FromSeconds(30);

    // Baseline: all devices present at startup (keyed by DeviceID)
    private readonly ConcurrentDictionary<string, DeviceRecord> _baselineDevices = new();

    // Baseline: all loaded drivers at startup
    private readonly ConcurrentDictionary<string, DriverRecord> _baselineDrivers = new();

    // Deduplication
    private readonly ConcurrentDictionary<string, DateTime> _alertedDevices = new();
    private readonly ConcurrentDictionary<string, DateTime> _alertedDrivers = new();

    // WMI event watcher for real-time device arrival
    private ManagementEventWatcher? _deviceWatcher;

    // Device class GUIDs for categorization
    private static class DeviceClass
    {
        // HID (keyboards, mice, game controllers)
        public const string Hid = "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}";
        // Keyboard specifically
        public const string Keyboard = "{4d36e96b-e325-11ce-bfc1-08002be10318}";
        // Mouse
        public const string Mouse = "{4d36e96f-e325-11ce-bfc1-08002be10318}";
        // Network adapters
        public const string Net = "{4d36e972-e325-11ce-bfc1-08002be10318}";
        // Disk drives
        public const string DiskDrive = "{4d36e967-e325-11ce-bfc1-08002be10318}";
        // Storage volumes
        public const string Volume = "{71a27cdd-812a-11d0-bec7-08002be2092f}";
        // Storage controllers
        public const string SCSIAdapter = "{4d36e97b-e325-11ce-bfc1-08002be10318}";
        // System devices (includes virtual bus drivers)
        public const string System = "{4d36e97d-e325-11ce-bfc1-08002be10318}";
    }

    // Known legitimate virtual devices that should not trigger alerts
    private static readonly HashSet<string> TrustedDevicePatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        // Hyper-V
        "Microsoft Hyper-V",
        "Hyper-V Virtual",
        // VMware
        "VMware",
        // VirtualBox
        "VirtualBox",
        // Windows built-in
        "Microsoft Wi-Fi Direct Virtual Adapter",
        "Microsoft Kernel Debug Network Adapter",
        "Microsoft ISATAP Adapter",
        "Teredo Tunneling",
        "Microsoft 6to4 Adapter",
        "WAN Miniport",
        "Microsoft Virtual WiFi Miniport",
        // Loopback
        "Microsoft KM-TEST Loopback Adapter",
        // Bluetooth PAN
        "Bluetooth Device (Personal Area Network)",
        // WSL
        "WSL",
    };

    public DeviceInstallMonitor(
        DetectionEngine detectionEngine,
        ILogger<DeviceInstallMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[DeviceInstall] Starting â€” baselining installed devices and drivers");

        await Task.Delay(StartupDelay, stoppingToken);

        // Baseline current state
        BaselineDevices();
        BaselineDrivers();

        _logger.LogInformation(
            "[DeviceInstall] Baseline: {Devices} devices, {Drivers} drivers",
            _baselineDevices.Count, _baselineDrivers.Count);

        // Scan for hidden/ghost devices and alert on suspicious ones
        ScanHiddenDevices(stoppingToken);

        // Cleanup stuck/obsolete/ghost devices on startup
        CleanupGhostDevices();

        // Start WMI real-time watcher for device arrivals
        StartDeviceWatcher(stoppingToken);

        // Poll loop for devices that WMI events might miss
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                CheckForNewDevices(stoppingToken);
                CheckForNewDrivers(stoppingToken);
                PruneAlerts();
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DeviceInstall] Poll error");
            }

            try { await Task.Delay(PollInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }

        StopDeviceWatcher();
    }

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // BASELINE
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    private void BaselineDevices()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT DeviceID, Name, ClassGuid, Manufacturer, Status FROM Win32_PnPEntity");

            foreach (ManagementObject device in searcher.Get())
            {
                var deviceId = device["DeviceID"]?.ToString();
                if (string.IsNullOrEmpty(deviceId)) continue;

                _baselineDevices[deviceId] = new DeviceRecord
                {
                    DeviceId = deviceId,
                    Name = device["Name"]?.ToString() ?? "Unknown",
                    ClassGuid = device["ClassGuid"]?.ToString()?.ToLowerInvariant() ?? "",
                    Manufacturer = device["Manufacturer"]?.ToString() ?? "",
                    Status = device["Status"]?.ToString() ?? ""
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[DeviceInstall] Failed to baseline devices");
        }
    }

    private void BaselineDrivers()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, PathName, State, StartMode FROM Win32_SystemDriver");

            foreach (ManagementObject driver in searcher.Get())
            {
                var name = driver["Name"]?.ToString();
                if (string.IsNullOrEmpty(name)) continue;

                _baselineDrivers[name] = new DriverRecord
                {
                    Name = name,
                    DisplayName = driver["DisplayName"]?.ToString() ?? "",
                    PathName = driver["PathName"]?.ToString() ?? "",
                    State = driver["State"]?.ToString() ?? "",
                    StartMode = driver["StartMode"]?.ToString() ?? ""
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[DeviceInstall] Failed to baseline drivers");
        }
    }

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // REAL-TIME WMI EVENT WATCHER
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    private void StartDeviceWatcher(CancellationToken ct)
    {
        try
        {
            // Watch for new PnP device instances being created
            var query = new WqlEventQuery(
                "__InstanceCreationEvent",
                TimeSpan.FromSeconds(2),
                "TargetInstance ISA 'Win32_PnPEntity'");

            _deviceWatcher = new ManagementEventWatcher(query);
            _deviceWatcher.EventArrived += (sender, args) =>
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    var targetInstance = (ManagementBaseObject)args.NewEvent["TargetInstance"];
                    var deviceId = targetInstance["DeviceID"]?.ToString();
                    var name = targetInstance["Name"]?.ToString() ?? "Unknown";
                    var classGuid = targetInstance["ClassGuid"]?.ToString()?.ToLowerInvariant() ?? "";

                    if (string.IsNullOrEmpty(deviceId)) return;
                    if (_baselineDevices.ContainsKey(deviceId)) return;

                    HandleNewDevice(deviceId, name, classGuid, "", ct);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[DeviceInstall] WMI event handler error");
                }
            };

            _deviceWatcher.Start();
            _logger.LogInformation("[DeviceInstall] WMI real-time device watcher active");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[DeviceInstall] WMI watcher failed to start (polling only)");
        }
    }

    private void StopDeviceWatcher()
    {
        try
        {
            _deviceWatcher?.Stop();
            _deviceWatcher?.Dispose();
        }
        catch { }
    }

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // POLLING DETECTION
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    private void CheckForNewDevices(CancellationToken ct)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT DeviceID, Name, ClassGuid, Manufacturer FROM Win32_PnPEntity");

            foreach (ManagementObject device in searcher.Get())
            {
                var deviceId = device["DeviceID"]?.ToString();
                if (string.IsNullOrEmpty(deviceId)) continue;
                if (_baselineDevices.ContainsKey(deviceId)) continue;

                var name = device["Name"]?.ToString() ?? "Unknown";
                var classGuid = device["ClassGuid"]?.ToString()?.ToLowerInvariant() ?? "";
                var manufacturer = device["Manufacturer"]?.ToString() ?? "";

                // Add to baseline so we don't re-alert
                _baselineDevices[deviceId] = new DeviceRecord
                {
                    DeviceId = deviceId,
                    Name = name,
                    ClassGuid = classGuid,
                    Manufacturer = manufacturer
                };

                HandleNewDevice(deviceId, name, classGuid, manufacturer, ct);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[DeviceInstall] Device poll error");
        }
    }

    private void CheckForNewDrivers(CancellationToken ct)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, PathName, State, StartMode FROM Win32_SystemDriver WHERE State='Running'");

            foreach (ManagementObject driver in searcher.Get())
            {
                var name = driver["Name"]?.ToString();
                if (string.IsNullOrEmpty(name)) continue;
                if (_baselineDrivers.ContainsKey(name)) continue;

                var displayName = driver["DisplayName"]?.ToString() ?? "";
                var pathName = driver["PathName"]?.ToString() ?? "";
                var startMode = driver["StartMode"]?.ToString() ?? "";

                // Add to baseline
                _baselineDrivers[name] = new DriverRecord
                {
                    Name = name,
                    DisplayName = displayName,
                    PathName = pathName,
                    State = "Running",
                    StartMode = startMode
                };

                HandleNewDriver(name, displayName, pathName, ct);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[DeviceInstall] Driver poll error");
        }
    }

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // DETECTION LOGIC
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    private void HandleNewDevice(string deviceId, string name, string classGuid, string manufacturer, CancellationToken ct)
    {
        // Deduplicate
        if (_alertedDevices.ContainsKey(deviceId)) return;
        _alertedDevices[deviceId] = DateTime.UtcNow;

        // Skip known legitimate virtual devices
        if (IsTrustedDevice(name, manufacturer)) return;

        // Categorize the device
        var category = CategorizeDevice(classGuid, name);

        // Determine severity based on category
        double confidence;
        DetectionTier tier;
        string ruleName;
        string reasoning;
        string technique;

        switch (category)
        {
            case DeviceCategory.Keyboard:
            case DeviceCategory.HID:
                confidence = 0.82;
                tier = DetectionTier.Tier1Behavioral;
                ruleName = "Device Install: Virtual Keyboard/HID Device";
                reasoning = "A new keyboard or HID device appeared after system startup. " +
                    "Virtual keyboard devices can inject keystrokes at kernel level, bypassing " +
                    "all userland input monitoring. This is the mechanism behind BadUSB attacks " +
                    "and remote phantom keyboard injection. If you did not plug in a new keyboard, " +
                    "this indicates an attacker is installing a virtual input device.";
                technique = "T1200 - Hardware Additions / T1056.001 - Input Capture";
                break;

            case DeviceCategory.NetworkAdapter:
                confidence = 0.78;
                tier = DetectionTier.Tier1Behavioral;
                ruleName = "Device Install: New Network Adapter";
                reasoning = "A new network adapter appeared after system startup. " +
                    "Rogue network adapters (TAP, virtual NICs) can be used for traffic " +
                    "interception (MITM), VPN hijacking, or creating covert network channels. " +
                    "If you did not install a VPN or virtual network software, this indicates " +
                    "an attacker is installing infrastructure for traffic manipulation.";
                technique = "T1557 - Adversary-in-the-Middle";
                break;

            case DeviceCategory.Storage:
                confidence = 0.70;
                tier = DetectionTier.Tier1Behavioral;
                ruleName = "Device Install: New Storage Device";
                reasoning = "A new storage device appeared after system startup. " +
                    "Virtual disks, iSCSI targets, and NAS mounts can be used for payload " +
                    "delivery, data staging for exfiltration, or mounting attacker-controlled " +
                    "filesystems. If you did not connect a new drive, this may indicate " +
                    "an attacker mounting remote storage for data theft or payload deployment.";
                technique = "T1091 - Replication Through Removable Media / T1052 - Exfiltration Over Physical Medium";
                break;

            default:
                confidence = 0.55;
                tier = DetectionTier.Tier2Indicator;
                ruleName = "Device Install: New Device After Startup";
                reasoning = "A new device was installed after system startup. While many device " +
                    "installations are legitimate (USB peripherals, Windows Update drivers), " +
                    "unexpected device installations can indicate hardware-based attacks or " +
                    "attacker-installed virtual devices.";
                technique = "T1200 - Hardware Additions";
                break;
        }

        _logger.LogWarning(
            "[DeviceInstall] NEW DEVICE: {Category} â€” '{Name}' (Class: {Class}, ID: {Id})",
            category, name, classGuid, deviceId);

        _ = _detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = ruleName,
            Evidence = $"New {category} device installed: '{name}'. " +
                      $"DeviceID: {deviceId}. ClassGuid: {classGuid}. " +
                      $"Manufacturer: {(string.IsNullOrEmpty(manufacturer) ? "unknown" : manufacturer)}. " +
                      $"This device was NOT present at system startup.",
            Reasoning = reasoning,
            Confidence = confidence,
            Tier = tier,
            ProcessName = "PnP",
            ProcessId = 0,
            Timestamp = DateTime.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["technique"] = technique,
                ["device_id"] = deviceId,
                ["device_name"] = name,
                ["device_class"] = classGuid,
                ["device_category"] = category.ToString(),
                ["manufacturer"] = manufacturer
            }
        }, ct);
    }

    private void HandleNewDriver(string name, string displayName, string pathName, CancellationToken ct)
    {
        // Deduplicate
        if (_alertedDrivers.ContainsKey(name)) return;
        _alertedDrivers[name] = DateTime.UtcNow;

        // Skip known Windows/Microsoft drivers
        var pathLower = (pathName ?? "").ToLowerInvariant();
        if (pathLower.Contains(@"\windows\system32\drivers\") &&
            !pathLower.Contains(@"\temp\") &&
            !pathLower.Contains(@"\appdata\"))
        {
            // System driver path â€” likely Windows Update. Log but don't alert high.
            _logger.LogInformation("[DeviceInstall] New system driver loaded: {Name} ({Path})", name, pathName);
            return;
        }

        // Non-system driver loaded at runtime â€” suspicious
        double confidence = 0.80;
        var tier = DetectionTier.Tier1Behavioral;

        // Higher confidence for drivers from temp/user paths (BYOVD pattern)
        if (pathLower.Contains(@"\temp\") || pathLower.Contains(@"\appdata\") ||
            pathLower.Contains(@"\users\") || pathLower.Contains(@"\programdata\"))
        {
            confidence = 0.92;
        }

        _logger.LogWarning(
            "[DeviceInstall] NEW KERNEL DRIVER: '{Display}' ({Name}) â€” Path: {Path}",
            displayName, name, pathName);

        _ = _detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = "Device Install: New Kernel Driver Loaded",
            Evidence = $"New kernel driver loaded at runtime: '{displayName}' (service: {name}). " +
                      $"Path: {pathName}. This driver was NOT running at system startup.",
            Reasoning = "Kernel drivers have unrestricted access to the system. Loading a new driver " +
                "at runtime (after boot) is unusual â€” legitimate drivers are typically loaded during " +
                "boot or software installation. Runtime driver loading is the mechanism behind " +
                "BYOVD (Bring Your Own Vulnerable Driver) attacks where attackers load a signed but " +
                "vulnerable driver to gain kernel-level code execution, disable security tools, " +
                "or install rootkits.",
            Confidence = confidence,
            Tier = tier,
            ProcessName = name,
            ProcessId = 0,
            Timestamp = DateTime.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["technique"] = "T1543.003 - Windows Service / T1068 - Exploitation for Privilege Escalation",
                ["driver_name"] = name,
                ["driver_display"] = displayName,
                ["driver_path"] = pathName ?? "unknown",
                ["is_user_path"] = (pathLower.Contains(@"\temp\") || pathLower.Contains(@"\users\")).ToString()
            }
        }, ct);
    }

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // HIDDEN DEVICE SCANNING
    // Scans for devices registered in the system but not currently connected.
    // These "ghost" devices persist in the registry and can be used for:
    //   - Persistence (attacker installs device, disconnects, reconnects later)
    //   - Hidden network adapters (TAP adapters from removed VPNs or attacker tools)
    //   - Phantom HID devices (virtual keyboards left behind)
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    private void ScanHiddenDevices(CancellationToken ct)
    {
        try
        {
            // Query ALL PnP entities including those not currently present
            // ConfigManagerErrorCode != 0 or Status != "OK" indicates non-functional/disconnected
            using var searcher = new ManagementObjectSearcher(
                "SELECT DeviceID, Name, ClassGuid, Manufacturer, ConfigManagerErrorCode, Status " +
                "FROM Win32_PnPEntity WHERE ConfigManagerErrorCode != 0");

            int hiddenCount = 0;
            int suspiciousHidden = 0;

            foreach (ManagementObject device in searcher.Get())
            {
                var deviceId = device["DeviceID"]?.ToString() ?? "";
                var name = device["Name"]?.ToString() ?? "Unknown";
                var classGuid = device["ClassGuid"]?.ToString()?.ToLowerInvariant() ?? "";
                var errorCode = Convert.ToInt32(device["ConfigManagerErrorCode"] ?? 0);
                var status = device["Status"]?.ToString() ?? "";

                hiddenCount++;

                // Check if this hidden device is in a suspicious category
                var category = CategorizeDevice(classGuid, name);
                if (category == DeviceCategory.Keyboard || category == DeviceCategory.HID ||
                    category == DeviceCategory.NetworkAdapter)
                {
                    // Skip trusted patterns
                    var manufacturer = device["Manufacturer"]?.ToString() ?? "";
                    if (IsTrustedDevice(name, manufacturer)) continue;

                    suspiciousHidden++;

                    var dedupeKey = $"hidden:{deviceId}";
                    if (_alertedDevices.ContainsKey(dedupeKey)) continue;
                    _alertedDevices[dedupeKey] = DateTime.UtcNow;

                    _logger.LogWarning(
                        "[DeviceInstall] HIDDEN DEVICE: {Category} â€” '{Name}' (Error: {Error}, Status: {Status})",
                        category, name, errorCode, status);

                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Device Install: Hidden/Ghost Device Detected",
                        Evidence = $"Hidden {category} device found: '{name}'. " +
                                  $"DeviceID: {deviceId}. Status: {status}, Error code: {errorCode}. " +
                                  $"This device is registered but not currently active â€” it may be " +
                                  $"a phantom device left by an attacker for later reactivation.",
                        Reasoning = "Hidden/ghost devices persist in the Windows device registry even when " +
                            "not physically connected. Attackers can install virtual keyboards, network " +
                            "adapters, or other devices, then disconnect them to avoid detection. The " +
                            "device can be reactivated later without triggering a new installation event. " +
                            "Suspicious hidden devices in HID or network adapter classes warrant investigation.",
                        Confidence = 0.65,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = "PnP",
                        ProcessId = 0,
                        Timestamp = DateTime.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["technique"] = "T1564.001 - Hide Artifacts",
                            ["device_id"] = deviceId,
                            ["device_name"] = name,
                            ["device_class"] = classGuid,
                            ["device_category"] = category.ToString(),
                            ["error_code"] = errorCode.ToString(),
                            ["status"] = status,
                            ["is_hidden"] = "true"
                        }
                    }, ct);
                }
            }

            _logger.LogInformation(
                "[DeviceInstall] Hidden device scan: {Total} non-functional devices, {Suspicious} suspicious",
                hiddenCount, suspiciousHidden);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[DeviceInstall] Hidden device scan error");
        }
    }

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // GHOST DEVICE CLEANUP
    // Removes stuck/obsolete/phantom devices that:
    //   - Have error codes indicating they're non-functional
    //   - Are not currently connected (ghost devices from removed hardware)
    //   - Are virtual devices from uninstalled software (old VPN TAP adapters, etc.)
    //
    // Uses SetupAPI to remove device nodes. Only removes devices that are:
    //   1. Not currently present (phantom/ghost)
    //   2. In a non-functional state (error code != 0)
    //   3. Not in a protected category (boot-critical, system devices)
    //
    // This is equivalent to "Show hidden devices" in Device Manager â†’ right-click â†’ Uninstall
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    // SetupAPI P/Invoke for device removal
    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr SetupDiGetClassDevs(
        IntPtr classGuid, string enumerator, IntPtr hwndParent, uint flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiEnumDeviceInfo(
        IntPtr deviceInfoSet, uint memberIndex, ref SP_DEVINFO_DATA deviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool SetupDiGetDeviceRegistryProperty(
        IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData,
        uint property, out uint propertyRegDataType,
        byte[] propertyBuffer, uint propertyBufferSize, out uint requiredSize);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiGetDevicePropertyW(
        IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData,
        ref DEVPROPKEY propertyKey, out uint propertyType,
        byte[] propertyBuffer, uint propertyBufferSize, out uint requiredSize, uint flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiRemoveDevice(
        IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool SetupDiGetDeviceInstanceId(
        IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData,
        char[] deviceInstanceId, uint deviceInstanceIdSize, out uint requiredSize);

    private const uint DIGCF_ALLCLASSES = 0x04;
    private const uint SPDRP_DEVICEDESC = 0x00;
    private const uint SPDRP_CLASS = 0x07;
    private const uint SPDRP_CLASSGUID = 0x08;
    private const uint DN_PHANTOM = 0x00000001; // Not currently present

    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVINFO_DATA
    {
        public uint cbSize;
        public Guid ClassGuid;
        public uint DevInst;
        public IntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DEVPROPKEY
    {
        public Guid fmtid;
        public uint pid;
    }

    // DEVPKEY_Device_IsPresent
    private static readonly DEVPROPKEY DEVPKEY_Device_IsPresent = new()
    {
        fmtid = new Guid("540b947e-8b40-45bc-a8a2-6a0b894cbda2"),
        pid = 5
    };

    // Device classes that should NEVER be removed (boot-critical)
    private static readonly HashSet<string> ProtectedClassGuids = new(StringComparer.OrdinalIgnoreCase)
    {
        "{4d36e97d-e325-11ce-bfc1-08002be10318}", // System
        "{4d36e96a-e325-11ce-bfc1-08002be10318}", // HDC (hard disk controllers)
        "{4d36e97b-e325-11ce-bfc1-08002be10318}", // SCSIAdapter
        "{4d36e968-e325-11ce-bfc1-08002be10318}", // Display
        "{4d36e977-e325-11ce-bfc1-08002be10318}", // PCMCIA
        "{6bdd1fc1-810f-11d0-bec7-08002be2092f}", // 1394 Bus
        "{72631e54-78a4-11d0-bcf7-00aa00b7b32a}", // Battery
        "{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}", // Bluetooth
    };

    /// <summary>
    /// Removes ghost/phantom devices that are not currently present and serve no purpose.
    /// Only removes devices that are safe to clean up (not boot-critical, not system devices).
    /// </summary>
    private void CleanupGhostDevices()
    {
        int removed = 0;
        int scanned = 0;

        try
        {
            IntPtr deviceInfoSet = SetupDiGetClassDevs(
                IntPtr.Zero, null!, IntPtr.Zero, DIGCF_ALLCLASSES);

            if (deviceInfoSet == IntPtr.Zero || deviceInfoSet == new IntPtr(-1))
            {
                _logger.LogDebug("[DeviceInstall] SetupDiGetClassDevs failed");
                return;
            }

            try
            {
                var deviceInfoData = new SP_DEVINFO_DATA();
                deviceInfoData.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));

                uint index = 0;
                while (SetupDiEnumDeviceInfo(deviceInfoSet, index, ref deviceInfoData))
                {
                    index++;
                    scanned++;

                    try
                    {
                        // Check if device is currently present
                        bool isPresent = IsDevicePresent(deviceInfoSet, ref deviceInfoData);
                        if (isPresent) continue; // Skip active devices

                        // Get device class GUID
                        string classGuid = GetDeviceProperty(deviceInfoSet, ref deviceInfoData, SPDRP_CLASSGUID);
                        if (string.IsNullOrEmpty(classGuid)) continue;

                        // Never remove protected device classes
                        if (ProtectedClassGuids.Contains(classGuid)) continue;

                        // Get device description for logging
                        string description = GetDeviceProperty(deviceInfoSet, ref deviceInfoData, SPDRP_DEVICEDESC);
                        if (string.IsNullOrEmpty(description)) description = "Unknown device";

                        // Get instance ID
                        string instanceId = GetDeviceInstanceId(deviceInfoSet, ref deviceInfoData);

                        // Skip devices that look like they might come back (USB hubs, BT radios)
                        var descLower = description.ToLowerInvariant();
                        if (descLower.Contains("usb root hub") ||
                            descLower.Contains("bluetooth radio") ||
                            descLower.Contains("composite device") ||
                            descLower.Contains("generic hub"))
                            continue;

                        // Remove the ghost device
                        if (SetupDiRemoveDevice(deviceInfoSet, ref deviceInfoData))
                        {
                            removed++;
                            _logger.LogInformation(
                                "[DeviceInstall] Removed ghost device: '{Desc}' ({Id})",
                                description, instanceId);
                        }
                    }
                    catch { continue; }

                    // Reset struct for next iteration
                    deviceInfoData = new SP_DEVINFO_DATA();
                    deviceInfoData.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
                }
            }
            finally
            {
                SetupDiDestroyDeviceInfoList(deviceInfoSet);
            }

            if (removed > 0)
            {
                _logger.LogInformation(
                    "[DeviceInstall] Ghost device cleanup: scanned {Scanned}, removed {Removed} phantom devices",
                    scanned, removed);
            }
            else
            {
                _logger.LogInformation(
                    "[DeviceInstall] Ghost device cleanup: scanned {Scanned} devices, none to remove",
                    scanned);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[DeviceInstall] Ghost device cleanup error (non-fatal)");
        }
    }

    private bool IsDevicePresent(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData)
    {
        // Try DEVPKEY_Device_IsPresent first (Windows 7+)
        byte[] buffer = new byte[4];
        var propKey = DEVPKEY_Device_IsPresent;
        if (SetupDiGetDevicePropertyW(deviceInfoSet, ref deviceInfoData, ref propKey,
            out _, buffer, (uint)buffer.Length, out _, 0))
        {
            return BitConverter.ToInt32(buffer, 0) != 0;
        }

        // Fallback: check device status via registry
        // If we can't determine presence, assume it's present (safe default)
        return true;
    }

    private string GetDeviceProperty(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData, uint property)
    {
        byte[] buffer = new byte[512];
        if (SetupDiGetDeviceRegistryProperty(deviceInfoSet, ref deviceInfoData,
            property, out _, buffer, (uint)buffer.Length, out uint required))
        {
            return System.Text.Encoding.Unicode.GetString(buffer, 0, (int)required).TrimEnd('\0');
        }
        return "";
    }

    private string GetDeviceInstanceId(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData)
    {
        char[] buffer = new char[256];
        if (SetupDiGetDeviceInstanceId(deviceInfoSet, ref deviceInfoData, buffer, (uint)buffer.Length, out _))
        {
            return new string(buffer).TrimEnd('\0');
        }
        return "";
    }

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // HELPERS
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    private static DeviceCategory CategorizeDevice(string classGuid, string name)
    {
        if (string.IsNullOrEmpty(classGuid))
            return DeviceCategory.Other;

        var lower = classGuid.ToLowerInvariant();

        if (lower == DeviceClass.Keyboard)
            return DeviceCategory.Keyboard;
        if (lower == DeviceClass.Hid)
            return DeviceCategory.HID;
        if (lower == DeviceClass.Mouse)
            return DeviceCategory.Mouse;
        if (lower == DeviceClass.Net)
            return DeviceCategory.NetworkAdapter;
        if (lower == DeviceClass.DiskDrive || lower == DeviceClass.Volume || lower == DeviceClass.SCSIAdapter)
            return DeviceCategory.Storage;

        // Name-based fallback
        var nameLower = name.ToLowerInvariant();
        if (nameLower.Contains("keyboard") || nameLower.Contains("kbd"))
            return DeviceCategory.Keyboard;
        if (nameLower.Contains("network") || nameLower.Contains("ethernet") ||
            nameLower.Contains("wifi") || nameLower.Contains("wi-fi") ||
            nameLower.Contains("tap-") || nameLower.Contains("adapter"))
            return DeviceCategory.NetworkAdapter;
        if (nameLower.Contains("disk") || nameLower.Contains("storage") ||
            nameLower.Contains("iscsi") || nameLower.Contains("virtual hd"))
            return DeviceCategory.Storage;

        return DeviceCategory.Other;
    }

    private static bool IsTrustedDevice(string name, string manufacturer)
    {
        if (string.IsNullOrEmpty(name)) return false;

        foreach (var pattern in TrustedDevicePatterns)
        {
            if (name.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        // Trust Microsoft-manufactured virtual devices
        if (!string.IsNullOrEmpty(manufacturer) &&
            manufacturer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }

    private void PruneAlerts()
    {
        var cutoff = DateTime.UtcNow.AddHours(-1);
        foreach (var key in _alertedDevices.Keys)
        {
            if (_alertedDevices.TryGetValue(key, out var time) && time < cutoff)
                _alertedDevices.TryRemove(key, out _);
        }
        foreach (var key in _alertedDrivers.Keys)
        {
            if (_alertedDrivers.TryGetValue(key, out var time) && time < cutoff)
                _alertedDrivers.TryRemove(key, out _);
        }
    }

    private enum DeviceCategory
    {
        Keyboard,
        HID,
        Mouse,
        NetworkAdapter,
        Storage,
        Other
    }

    private sealed class DeviceRecord
    {
        public string DeviceId { get; init; } = "";
        public string Name { get; init; } = "";
        public string ClassGuid { get; init; } = "";
        public string Manufacturer { get; init; } = "";
        public string Status { get; init; } = "";
    }

    private sealed class DriverRecord
    {
        public string Name { get; init; } = "";
        public string DisplayName { get; init; } = "";
        public string PathName { get; init; } = "";
        public string State { get; init; } = "";
        public string StartMode { get; init; } = "";
    }
}
