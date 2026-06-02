using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
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

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVINFO_DATA
        {
            public int cbSize;
            public Guid classGuid;
            public int devInst;
            public IntPtr reserved;
        }

        [DllImport("setupapi.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr SetupDiGetClassDevs(
            ref Guid ClassGuid,
            string? Enumerator,
            IntPtr hwndParent,
            int Flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInfo(
            IntPtr DeviceInfoSet,
            int MemberIndex,
            ref SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SetupDiGetDeviceInstanceId(
            IntPtr DeviceInfoSet,
            ref SP_DEVINFO_DATA DeviceInfoData,
            [Out] System.Text.StringBuilder? DeviceInstanceId,
            int DeviceInstanceIdSize,
            out int RequiredSize);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SetupDiGetDeviceRegistryProperty(
            IntPtr DeviceInfoSet,
            ref SP_DEVINFO_DATA DeviceInfoData,
            int Property,
            out int PropertyRegDataType,
            byte[]? PropertyBuffer,
            int PropertyBufferSize,
            out int RequiredSize);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        private const int DIGCF_PRESENT = 0x00000002;
        private const int DIGCF_ALLCLASSES = 0x00000004;

        private const int SPDRP_DEVICEDESC = 0x00000000;
        private const int SPDRP_CLASSGUID = 0x00000008;
        private const int SPDRP_SERVICE = 0x00000004;
        private const int SPDRP_FRIENDLYNAME = 0x0000000C;

        private static string GetDeviceProperty(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData, int property)
        {
            int requiredSize = 0;
            SetupDiGetDeviceRegistryProperty(deviceInfoSet, ref deviceInfoData, property, out _, null, 0, out requiredSize);
            if (requiredSize > 0)
            {
                byte[] buffer = new byte[requiredSize];
                if (SetupDiGetDeviceRegistryProperty(deviceInfoSet, ref deviceInfoData, property, out _, buffer, buffer.Length, out _))
                {
                    return System.Text.Encoding.Unicode.GetString(buffer).TrimEnd('\0');
                }
            }
            return string.Empty;
        }

        private static string GetDeviceInstanceId(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData)
        {
            int requiredSize = 0;
            SetupDiGetDeviceInstanceId(deviceInfoSet, ref deviceInfoData, null, 0, out requiredSize);
            if (requiredSize > 0)
            {
                var sb = new System.Text.StringBuilder(requiredSize);
                if (SetupDiGetDeviceInstanceId(deviceInfoSet, ref deviceInfoData, sb, sb.Capacity, out _))
                {
                    return sb.ToString();
                }
            }
            return string.Empty;
        }

        private List<UsbDevice> GetConnectedUsbDevices()
        {
            var list = new List<UsbDevice>();
            Guid emptyGuid = Guid.Empty;
            IntPtr deviceInfoSet = SetupDiGetClassDevs(ref emptyGuid, "USB", IntPtr.Zero, DIGCF_PRESENT | DIGCF_ALLCLASSES);
            if (deviceInfoSet == (IntPtr)(-1))
            {
                return list;
            }

            try
            {
                var deviceInfoData = new SP_DEVINFO_DATA();
                deviceInfoData.cbSize = Marshal.SizeOf(deviceInfoData);
                int index = 0;

                while (SetupDiEnumDeviceInfo(deviceInfoSet, index, ref deviceInfoData))
                {
                    index++;
                    string instanceId = GetDeviceInstanceId(deviceInfoSet, ref deviceInfoData);
                    if (string.IsNullOrEmpty(instanceId)) continue;

                    string vid = "";
                    string pid = "";
                    string serial = "";

                    var parts = instanceId.Split('\\');
                    if (parts.Length >= 2)
                    {
                        var hardwareId = parts[1];
                        var vidIdx = hardwareId.IndexOf("VID_", StringComparison.OrdinalIgnoreCase);
                        if (vidIdx != -1 && hardwareId.Length >= vidIdx + 8)
                        {
                            vid = hardwareId.Substring(vidIdx + 4, 4);
                        }
                        var pidIdx = hardwareId.IndexOf("PID_", StringComparison.OrdinalIgnoreCase);
                        if (pidIdx != -1 && hardwareId.Length >= pidIdx + 8)
                        {
                            pid = hardwareId.Substring(pidIdx + 4, 4);
                        }
                    }
                    if (parts.Length >= 3)
                    {
                        serial = parts[2];
                    }

                    string name = GetDeviceProperty(deviceInfoSet, ref deviceInfoData, SPDRP_FRIENDLYNAME);
                    if (string.IsNullOrEmpty(name))
                    {
                        name = GetDeviceProperty(deviceInfoSet, ref deviceInfoData, SPDRP_DEVICEDESC);
                    }
                    if (string.IsNullOrEmpty(name))
                    {
                        name = "Unknown USB Device";
                    }

                    string classGuidStr = GetDeviceProperty(deviceInfoSet, ref deviceInfoData, SPDRP_CLASSGUID);
                    string service = GetDeviceProperty(deviceInfoSet, ref deviceInfoData, SPDRP_SERVICE);

                    bool isHid = classGuidStr.Equals("{745a17a0-74d3-11d0-b6fe-00a0c90f57da}", StringComparison.OrdinalIgnoreCase) ||
                                 service.Equals("HidUsb", StringComparison.OrdinalIgnoreCase);

                    bool isMassStorage = service.Equals("USBSTOR", StringComparison.OrdinalIgnoreCase);
                    bool isComposite = service.Equals("usbccgp", StringComparison.OrdinalIgnoreCase);

                    list.Add(new UsbDevice
                    {
                        DeviceId = instanceId,
                        Name = name,
                        Vid = vid,
                        Pid = pid,
                        SerialNumber = serial,
                        IsHid = isHid,
                        IsMassStorage = isMassStorage,
                        IsComposite = isComposite
                    });
                }
            }
            catch
            {
                // Degrade gracefully
            }
            finally
            {
                SetupDiDestroyDeviceInfoList(deviceInfoSet);
            }

            return list;
        }

        public void Dispose()
        {
            _timer.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
