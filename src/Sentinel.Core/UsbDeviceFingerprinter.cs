using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
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
        public bool IsFailedEnumeration { get; set; }
    }

    public class UsbDeviceFingerprinter : IDisposable
    {
        private readonly HashSet<string> _baseline = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _trustedVidPid;
        private readonly System.Threading.Timer _timer;
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<UsbDeviceFingerprinter>? _logger;

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

        // Built-in trusted storage VID:PID (operator can extend via Sentinel:TrustedUsbDevices)
        private static readonly string[] DefaultTrustedUsb = new[]
        {
            "0951:1666", // Kingston DataTraveler 3.0 (common Ventoy stick)
        };

        public UsbDeviceFingerprinter(
            DetectionEngine detectionEngine,
            SentinelConfig? config = null,
            ILogger<UsbDeviceFingerprinter>? logger = null)
        {
            _detectionEngine = detectionEngine;
            _config = config ?? new SentinelConfig();
            _logger = logger;
            _trustedVidPid = BuildTrustedSet(_config.TrustedUsbDevices);

            // Baseline connected devices
            var devices = GetConnectedUsbDevices();
            foreach (var d in devices)
            {
                _baseline.Add(d.DeviceId);
            }

            _logger?.LogInformation(
                "[UsbDeviceFingerprinter] Baseline {Count} USB devices; {Trusted} trusted VID:PID; AutoDisableFailedEnum={Auto}",
                _baseline.Count, _trustedVidPid.Count, _config.AutoDisableFailedUsbEnumeration);

            // Poll every 30s
            _timer = new System.Threading.Timer(PollUsbDevices, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
        }

        private static HashSet<string> BuildTrustedSet(string[]? configured)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in DefaultTrustedUsb.Concat(configured ?? Array.Empty<string>()))
            {
                var normalized = NormalizeVidPid(entry);
                if (normalized != null)
                    set.Add(normalized);
            }
            return set;
        }

        /// <summary>Accepts "0951:1666", "VID_0951&PID_1666", "0951-1666".</summary>
        internal static string? NormalizeVidPid(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            var s = raw.Trim().ToUpperInvariant()
                .Replace("VID_", "", StringComparison.Ordinal)
                .Replace("PID_", "", StringComparison.Ordinal)
                .Replace("&", ":", StringComparison.Ordinal)
                .Replace("-", ":", StringComparison.Ordinal)
                .Replace(" ", "", StringComparison.Ordinal);
            var parts = s.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length != 2) return null;
            if (parts[0].Length != 4 || parts[1].Length != 4) return null;
            return $"{parts[0]}:{parts[1]}";
        }

        private void PollUsbDevices(object? state)
        {
            try
            {
                var currentDevices = GetConnectedUsbDevices();
                foreach (var dev in currentDevices)
                {
                    if (!_baseline.Contains(dev.DeviceId))
                    {
                        ProcessNewDevice(dev);
                        _baseline.Add(dev.DeviceId);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "[UsbDeviceFingerprinter] Poll error");
            }
        }

        private void ProcessNewDevice(UsbDevice dev)
        {
            string ruleName = "USB: New Device Connected";
            string evidence = $"USB device '{dev.Name}' with VID {dev.Vid} PID {dev.Pid} connected.";
            double confidence = 0.40;
            DetectionTier tier = DetectionTier.Tier2Indicator;
            ResponseAction response = ResponseAction.LogOnly;
            bool disabled = false;
            var vidPid = $"{dev.Vid}:{dev.Pid}";

            // v1.6.3: Failed enumeration / VID_0000 — high interest, auto-disable
            if (dev.IsFailedEnumeration ||
                dev.Vid.Equals("0000", StringComparison.OrdinalIgnoreCase) ||
                (dev.Name?.Contains("Device Descriptor Request Failed", StringComparison.OrdinalIgnoreCase) ?? false) ||
                (dev.Name?.Contains("Unknown USB Device", StringComparison.OrdinalIgnoreCase) ?? false))
            {
                ruleName = "USB: Failed Device Enumeration";
                evidence = $"USB device failed descriptor enumeration: '{dev.Name}' " +
                           $"(VID {dev.Vid} PID {dev.Pid}, InstanceId={dev.DeviceId}). " +
                           "Windows could not read the device identity — flaky port/cable, " +
                           "or hostile hardware that refuses to identify.";
                confidence = 0.82;
                tier = DetectionTier.Tier1Behavioral;
                response = ResponseAction.LogOnly;

                if (_config.AutoDisableFailedUsbEnumeration)
                {
                    disabled = DisableUsbDevice(dev.DeviceId);
                    evidence += disabled
                        ? " Device disabled via registry ConfigFlags."
                        : " Auto-disable attempted but registry write failed.";
                }
            }
            else if (_trustedVidPid.Contains(vidPid))
            {
                ruleName = "USB: Trusted Device Connected";
                evidence = $"Trusted USB device '{dev.Name}' (VID {dev.Vid} PID {dev.Pid}) connected — allowlisted.";
                confidence = 0.15;
                tier = DetectionTier.Tier2Indicator;
                response = ResponseAction.LogOnly;
            }
            else if (dev.IsHid && !AllowedKeyboardVids.Contains(dev.Vid))
            {
                ruleName = "BadUSB: Unknown HID Device";
                evidence = $"Unknown HID keyboard device '{dev.Name}' (VID {dev.Vid}) connected.";
                confidence = 0.80;
                tier = DetectionTier.Tier1Behavioral;
                response = ResponseAction.LogOnly;
                // Best-effort disable unknown HID keyboards (UsbHidWhitelist also covers Enum\HID)
                disabled = DisableUsbDevice(dev.DeviceId);
                if (disabled)
                    evidence += " Device disabled via registry ConfigFlags.";
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
                evidence = $"New mass storage USB device '{dev.Name}' (VID {dev.Vid} PID {dev.Pid}) connected.";
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
                AuthorizedResponse = response,
                Evidence = evidence,
                Reasoning = $"New unbaselined USB device detected at runtime. Action tier resolved to {tier}." +
                            (disabled ? " Auto-disabled." : ""),
                Metadata = new Dictionary<string, string>
                {
                    { "VID", dev.Vid },
                    { "PID", dev.Pid },
                    { "DeviceName", dev.Name ?? "" },
                    { "Serial", dev.SerialNumber ?? "" },
                    { "DeviceId", dev.DeviceId ?? "" },
                    { "FailedEnumeration", dev.IsFailedEnumeration.ToString() },
                    { "Disabled", disabled.ToString() },
                    { "Trusted", _trustedVidPid.Contains(vidPid).ToString() }
                }
            };

            _ = _detectionEngine.EmitAsync(detection);
        }

        /// <summary>
        /// Disables a PnP device by setting ConfigFlags=CONFIGFLAG_DISABLED (1) under Enum.
        /// Same technique as UsbHidWhitelist — requires service to run as SYSTEM/admin.
        /// </summary>
        internal bool DisableUsbDevice(string deviceInstanceId)
        {
            if (string.IsNullOrWhiteSpace(deviceInstanceId)) return false;
            try
            {
                // Instance IDs look like: USB\VID_0000&PID_0002\5&230b5917&0&1
                var regPath = $@"SYSTEM\CurrentControlSet\Enum\{deviceInstanceId}";
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: true);
                if (key == null)
                {
                    _logger?.LogDebug("[UsbDeviceFingerprinter] Enum key not found for disable: {Id}", deviceInstanceId);
                    return false;
                }

                key.SetValue("ConfigFlags", 1, RegistryValueKind.DWord);
                _logger?.LogWarning("[UsbDeviceFingerprinter] Disabled USB device via ConfigFlags: {Id}", deviceInstanceId);
                return true;
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "[UsbDeviceFingerprinter] Failed to disable {Id}", deviceInstanceId);
                return false;
            }
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

                    bool isFailedEnum =
                        vid.Equals("0000", StringComparison.OrdinalIgnoreCase) ||
                        pid.Equals("0000", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("Device Descriptor Request Failed", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("Device Descriptor Failure", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("Unknown USB Device", StringComparison.OrdinalIgnoreCase);

                    list.Add(new UsbDevice
                    {
                        DeviceId = instanceId,
                        Name = name,
                        Vid = vid,
                        Pid = pid,
                        SerialNumber = serial,
                        IsHid = isHid,
                        IsMassStorage = isMassStorage,
                        IsComposite = isComposite,
                        IsFailedEnumeration = isFailedEnum
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
