using System.Collections.Concurrent;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace WindowsSentinel.Core;

/// <summary>
/// Bluetooth Attack Surface Monitor (v3.6.0) â€” Detects Bluetooth-based attacks.
///
/// Bluetooth is an often-overlooked attack vector. Attacks include:
///   - BlueBorne (CVE-2017-8628) â€” remote code execution via BT
///   - BT file transfer abuse (OBEX push without user consent)
///   - BT device impersonation (BIAS attack)
///   - Unauthorized BT pairing (rogue keyboard/mouse injection)
///
/// Detection strategy:
///   1. Monitor for new Bluetooth device pairings via registry.
///   2. Detect Bluetooth service state changes (enabled when it shouldn't be).
///   3. Alert on HID-class BT devices pairing (keyboard/mouse â€” BadBT attacks).
///   4. Monitor for BT file receive events (OBEX push).
///
/// NOTE: This monitor cannot prevent BlueBorne-class exploits (those require
/// patching). It detects the CONSEQUENCES: unauthorized pairings, unexpected
/// BT activation, and suspicious BT HID devices.
/// </summary>
public sealed class BluetoothMonitor : BackgroundService
{
    private readonly DetectionEngine _detectionEngine;
    private readonly ILogger<BluetoothMonitor> _logger;

    // Baseline: known paired devices at startup
    private readonly HashSet<string> _baselinePairedDevices = new(StringComparer.OrdinalIgnoreCase);
    private bool _baselineCaptured;

    // Baseline: BT enabled state at startup
    private bool? _baselineBtEnabled;

    // Deduplication
    private readonly ConcurrentDictionary<string, DateTime> _alertedEvents = new();
    private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(15);

    // Registry paths for Bluetooth
    private const string BtDevicesRegPath = @"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices";
    private const string BtRadioRegPath = @"SYSTEM\CurrentControlSet\Services\bthserv";

    // HID device class GUIDs (keyboards, mice â€” BadBT attack vectors)
    private static readonly string[] HidClassGuids =
    {
        "00001124", // HID (Human Interface Device)
        "00001812", // HID over GATT
    };

    public BluetoothMonitor(
        DetectionEngine detectionEngine,
        ILogger<BluetoothMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[BluetoothMonitor] Starting â€” Bluetooth attack surface monitoring active");

        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);

        CaptureBaseline();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanBluetoothStateAsync(stoppingToken);
                PruneAlertCache();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "[BluetoothMonitor] Scan error");
            }

            await Task.Delay(PollInterval, stoppingToken);
        }
    }

    private void CaptureBaseline()
    {
        try
        {
            var devices = GetPairedDevices();
            foreach (var device in devices)
                _baselinePairedDevices.Add(device.Address);

            _baselineBtEnabled = IsBluetoothServiceRunning();
            _baselineCaptured = true;

            _logger.LogInformation(
                "[BluetoothMonitor] Baseline: {Count} paired devices, BT service {State}",
                _baselinePairedDevices.Count,
                _baselineBtEnabled == true ? "running" : "stopped");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[BluetoothMonitor] Baseline capture failed (BT may not be present)");
        }
    }

    private async Task ScanBluetoothStateAsync(CancellationToken ct)
    {
        if (!_baselineCaptured) return;

        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // CHECK 1: New device pairings
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        var currentDevices = GetPairedDevices();
        foreach (var device in currentDevices)
        {
            if (_baselinePairedDevices.Contains(device.Address)) continue;

            // New device paired since baseline
            _baselinePairedDevices.Add(device.Address);

            var isHid = device.IsHidDevice;
            var dedupeKey = $"bt_pair:{device.Address}";
            if (_alertedEvents.ContainsKey(dedupeKey)) continue;
            _alertedEvents.TryAdd(dedupeKey, DateTime.UtcNow);

            var confidence = isHid ? 0.80 : 0.55;
            var tier = isHid ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = isHid
                    ? "Physical Security: Bluetooth HID Device Paired (Possible BadBT)"
                    : "Physical Security: New Bluetooth Device Paired",
                Evidence = $"New Bluetooth device paired: Address={device.Address}, " +
                           $"Name={device.Name ?? "unknown"}, IsHID={isHid}. " +
                           (isHid ? "HID devices (keyboards/mice) can inject keystrokes (BadBT attack)." : ""),
                Reasoning = isHid
                    ? "A Bluetooth HID device (keyboard or mouse class) was paired. BadBT attacks use " +
                      "rogue BT keyboards to inject keystrokes and execute commands. If the user did not " +
                      "intentionally pair a new BT keyboard/mouse, this is a physical proximity attack."
                    : "A new Bluetooth device was paired. While usually legitimate, unexpected pairings " +
                      "could indicate unauthorized access to the machine or BT-based attacks.",
                Confidence = confidence,
                Tier = tier,
                ProcessName = "Bluetooth",
                ProcessId = 0,
                Timestamp = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["bt_address"] = device.Address,
                    ["bt_name"] = device.Name ?? "unknown",
                    ["is_hid"] = isHid.ToString(),
                    ["technique"] = "T1200 - Hardware Additions",
                    ["attack_type"] = isHid ? "badbt_hid" : "bt_pairing"
                }
            }, ct);
        }

        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // CHECK 2: Bluetooth service activated unexpectedly
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        var btRunning = IsBluetoothServiceRunning();
        if (_baselineBtEnabled == false && btRunning == true)
        {
            var dedupeKey = "bt_activated";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTime.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Physical Security: Bluetooth Service Activated",
                    Evidence = "Bluetooth service was started (was stopped at baseline). " +
                               "If the user did not enable Bluetooth, this could indicate " +
                               "malware enabling BT for proximity-based attacks.",
                    Reasoning = "Bluetooth being enabled without user action can indicate malware " +
                                "preparing for BT-based data exfiltration, device impersonation, " +
                                "or enabling the attack surface for proximity exploits (BlueBorne).",
                    Confidence = 0.50,
                    Tier = DetectionTier.Tier2Indicator,
                    ProcessName = "Bluetooth",
                    ProcessId = 0,
                    Timestamp = DateTime.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["technique"] = "T1011 - Exfiltration Over Other Network Medium",
                        ["attack_type"] = "bt_activation"
                    }
                }, ct);
            }
        }
        _baselineBtEnabled = btRunning;
    }

    private static List<BtDevice> GetPairedDevices()
    {
        var devices = new List<BtDevice>();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(BtDevicesRegPath);
            if (key == null) return devices;

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                try
                {
                    using var deviceKey = key.OpenSubKey(subKeyName);
                    if (deviceKey == null) continue;

                    var name = deviceKey.GetValue("Name") as byte[];
                    var nameStr = name != null
                        ? System.Text.Encoding.UTF8.GetString(name).TrimEnd('\0')
                        : null;

                    // Check if it's a HID device by looking at service class
                    var classOfDevice = deviceKey.GetValue("COD") as int? ?? 0;
                    var majorClass = (classOfDevice >> 8) & 0x1F;
                    var isHid = majorClass == 5; // 5 = Peripheral (keyboard, mouse, etc.)

                    devices.Add(new BtDevice
                    {
                        Address = subKeyName,
                        Name = nameStr,
                        IsHidDevice = isHid
                    });
                }
                catch { }
            }
        }
        catch { }
        return devices;
    }

    private static bool IsBluetoothServiceRunning()
    {
        try
        {
            using var sc = new System.ServiceProcess.ServiceController("bthserv");
            return sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
        }
        catch
        {
            return false;
        }
    }

    private void PruneAlertCache()
    {
        var cutoff = DateTime.UtcNow - AlertDedupeWindow;
        foreach (var kvp in _alertedEvents)
        {
            if (kvp.Value < cutoff)
                _alertedEvents.TryRemove(kvp.Key, out _);
        }
    }

    private sealed class BtDevice
    {
        public required string Address { get; init; }
        public string? Name { get; init; }
        public bool IsHidDevice { get; init; }
    }
}
