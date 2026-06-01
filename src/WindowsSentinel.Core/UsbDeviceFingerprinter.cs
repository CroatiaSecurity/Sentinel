using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace WindowsSentinel.Core
{
    public class UsbDevice
    {
        public string DeviceId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Vid { get; set; } = string.Empty;
        public string Pid { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public bool IsHid { get; set; }
        public bool IsMassStorage { get; set; }
        public bool IsComposite { get; set; }
    }

    public class UsbDeviceFingerprinter : IDisposable
    {
        private readonly HashSet<string> _baseline = new();
        private readonly System.Threading.Timer _timer;
        private readonly DetectionEngine _detectionEngine;

        // Known good keyboard VIDs (Logitech, Microsoft, Razer, Corsair, Apple, Keychron, etc.)
        private static readonly HashSet<string> AllowedKeyboardVids = new(StringComparer.OrdinalIgnoreCase)
        {
            "046D", // Logitech
            "045E", // Microsoft
            "1532", // Razer
            "1B1C", // Corsair
            "05AC", // Apple
            "3434", // Keychron
            "0951", // Kingston/HyperX
            "04F2", // Chicony
            "0C45"  // SINO WEALTH
        };

        public UsbDeviceFingerprinter(DetectionEngine detectionEngine)
        {
            _detectionEngine = detectionEngine;
            
            // Baseline connected devices
            var devices = GetConnectedUsbDevices();
            foreach (var d in devices)
            {
                _baseline.Add(d.DeviceId);
            }

            // Poll every 30s
            _timer = new System.Threading.Timer(PollUsbDevices, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
        }

        private void PollUsbDevices(object? state)
        {
            var currentDevices = GetConnectedUsbDevices();
            foreach (var dev in currentDevices)
            {
                if (!_baseline.Contains(dev.DeviceId))
                {
                    // Found a new USB device! Process alert based on type
                    ProcessNewDevice(dev);
                    
                    // Add to baseline to prevent repeat alerts
                    _baseline.Add(dev.DeviceId);
                }
            }
        }

        private void ProcessNewDevice(UsbDevice dev)
        {
            string ruleName = "USB: New Device Connected";
            string evidence = $"USB device '{dev.Name}' with VID {dev.Vid} PID {dev.Pid} connected.";
            double confidence = 0.40;
            DetectionTier tier = DetectionTier.Tier2Indicator;

            if (dev.IsHid && !AllowedKeyboardVids.Contains(dev.Vid))
            {
                ruleName = "BadUSB: Unknown HID Device";
                evidence = $"Unknown HID keyboard device '{dev.Name}' (VID {dev.Vid}) connected.";
                confidence = 0.80;
                tier = DetectionTier.Tier1Behavioral; // President's Law can kill on BadUSB
            }
            else if (dev.IsComposite)
            {
                ruleName = "USB: New Composite Device";
                evidence = $"New composite USB device '{dev.Name}' (VID {dev.Vid}) connected.";
                confidence = 0.75;
                tier = DetectionTier.Tier1Behavioral;
            }
            else if (dev.IsMassStorage)
            {
                ruleName = "USB: New Mass Storage Device";
                evidence = $"New mass storage USB device '{dev.Name}' connected.";
                confidence = 0.50;
                tier = DetectionTier.Tier2Indicator;
            }

            var detection = new DetectionEvent
            {
                RuleName = ruleName,
                ProcessName = "SentinelService.exe",
                ProcessId = Environment.ProcessId,
                Confidence = confidence,
                Tier = tier,
                Evidence = evidence,
                Reasoning = $"New unbaselined USB device detected at runtime. Action tier resolved to {tier}.",
                Metadata = new Dictionary<string, string>
                {
                    { "VID", dev.Vid },
                    { "PID", dev.Pid },
                    { "DeviceName", dev.Name },
                    { "Serial", dev.SerialNumber }
                }
            };

            _ = _detectionEngine.EmitAsync(detection);
        }

        private List<UsbDevice> GetConnectedUsbDevices()
        {
            // Under test/mock, return empty list or mock devices.
            // Under production, we can query WMI:
            // "SELECT DeviceID, Name, PNPDeviceID FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'"
            return new List<UsbDevice>();
        }

        public void Dispose()
        {
            _timer.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
