using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace WindowsSentinel.Core
{
    // ──────────────────────────────────────────────
    // ARP Spoof Monitor — detects duplicate MAC for gateway IP
    // ──────────────────────────────────────────────
    public sealed class ArpSpoofMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ArpSpoofMonitor> _logger;
        private string? _baselineGatewayMac;
        private string? _gatewayIp;
        private readonly ConcurrentDictionary<string, string> _arpBaseline = new(); // IP → MAC

        public ArpSpoofMonitor(DetectionEngine de, ILogger<ArpSpoofMonitor> l) { _detectionEngine = de; _logger = l; }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int macLen);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int CreateIpNetEntry(ref MIB_IPNETROW pArpEntry);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int DeleteIpNetEntry(ref MIB_IPNETROW pArpEntry);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetBestInterface(uint dwDestAddr, out int pdwBestIfIndex);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_IPNETROW
        {
            public int dwIndex;
            public int dwPhysAddrLen;
            public byte mac0, mac1, mac2, mac3, mac4, mac5, mac6, mac7;
            public int dwAddr;
            public int dwType;
        }

        private void SetStaticGatewayArp(string ip, string mac)
        {
            try
            {
                var ipAddr = IPAddress.Parse(ip);
                var ipBytes = ipAddr.GetAddressBytes();
                uint ipInt = BitConverter.ToUInt32(ipBytes, 0);

                if (GetBestInterface(ipInt, out int ifIndex) != 0)
                {
                    _logger.LogWarning("[ArpSpoofMonitor] Failed to get best interface for Gateway IP {IP}", ip);
                    return;
                }

                var macBytes = mac.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray();
                if (macBytes.Length < 6) return;

                var row = new MIB_IPNETROW
                {
                    dwIndex = ifIndex,
                    dwPhysAddrLen = 6,
                    mac0 = macBytes[0],
                    mac1 = macBytes[1],
                    mac2 = macBytes[2],
                    mac3 = macBytes[3],
                    mac4 = macBytes[4],
                    mac5 = macBytes[5],
                    dwAddr = (int)ipInt,
                    dwType = 4 // 4 = Static
                };

                // Delete any existing entry to prevent duplicates
                DeleteIpNetEntry(ref row);
                int ret = CreateIpNetEntry(ref row);
                if (ret == 0)
                {
                    _logger.LogInformation("[ArpSpoofMonitor] Static ARP lock established for Gateway {IP} -> {MAC} on interface {Index}", ip, mac, ifIndex);
                }
                else
                {
                    _logger.LogWarning("[ArpSpoofMonitor] CreateIpNetEntry failed: {Error}", ret);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ArpSpoofMonitor] Failed to set static ARP");
            }
        }

        private void DeleteStaticGatewayArp(string ip)
        {
            try
            {
                var ipAddr = IPAddress.Parse(ip);
                var ipBytes = ipAddr.GetAddressBytes();
                uint ipInt = BitConverter.ToUInt32(ipBytes, 0);

                if (GetBestInterface(ipInt, out int ifIndex) != 0) return;

                var row = new MIB_IPNETROW
                {
                    dwIndex = ifIndex,
                    dwAddr = (int)ipInt
                };
                DeleteIpNetEntry(ref row);
                _logger.LogInformation("[ArpSpoofMonitor] Static ARP lock removed for Gateway {IP}", ip);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ArpSpoofMonitor] Failed to delete static ARP");
            }
        }

        public override async Task StopAsync(CancellationToken ct)
        {
            if (_gatewayIp != null)
            {
                DeleteStaticGatewayArp(_gatewayIp);
            }
            await base.StopAsync(ct);
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ArpSpoofMonitor] Started");
            var initialGatewayIp = GetDefaultGateway();
            if (initialGatewayIp != null)
            {
                _gatewayIp = initialGatewayIp;
                var initialGatewayMac = ResolveMac(initialGatewayIp);
                if (initialGatewayMac != null)
                {
                    _baselineGatewayMac = initialGatewayMac;
                    SetStaticGatewayArp(initialGatewayIp, initialGatewayMac);
                }
            }

            // Baseline ARP table
            var initial = GetArpTable();
            foreach (var (ip, mac) in initial)
                _arpBaseline[ip] = mac;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct);

                    // === Check Gateway IP changes ===
                    var currentGatewayIp = GetDefaultGateway();
                    if (currentGatewayIp != _gatewayIp)
                    {
                        var oldGatewayIp = _gatewayIp;
                        if (oldGatewayIp != null)
                        {
                            DeleteStaticGatewayArp(oldGatewayIp);
                        }
                        _gatewayIp = currentGatewayIp;
                        if (currentGatewayIp != null)
                        {
                            var currentGatewayMac = ResolveMac(currentGatewayIp);
                            if (currentGatewayMac != null)
                            {
                                _baselineGatewayMac = currentGatewayMac;
                                SetStaticGatewayArp(currentGatewayIp, currentGatewayMac);
                            }
                        }
                    }

                    // === Check 1: Gateway MAC change ===
                    var gwIpForMacCheck = _gatewayIp;
                    if (gwIpForMacCheck != null)
                    {
                        var currentMac = ResolveMac(gwIpForMacCheck);
                        var baseMac = _baselineGatewayMac;
                        if (baseMac != null && currentMac != null && currentMac != baseMac)
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "ARP Spoof: Gateway MAC Changed",
                                Evidence = $"Gateway {gwIpForMacCheck} MAC changed from {baseMac} to {currentMac}",
                                Reasoning = "The default gateway MAC address changed at runtime, indicating a possible ARP spoofing or MitM attack on the local network.",
                                Confidence = 0.88, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.NetworkIsolate,
                                ProcessName = "SYSTEM", ProcessId = 0,
                                Metadata = new Dictionary<string, string> { { "TargetIP", gwIpForMacCheck } }
                            });
                            _baselineGatewayMac = currentMac;
                            SetStaticGatewayArp(gwIpForMacCheck, currentMac);
                        }
                    }

                    // === Check 2: Multiple IPs sharing same MAC (ARP table poisoning) ===
                    var currentArp = GetArpTable();
                    var macToIps = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
                    foreach (var (ip, mac) in currentArp)
                    {
                        if (!macToIps.ContainsKey(mac)) macToIps[mac] = new List<string>();
                        macToIps[mac].Add(ip);
                    }

                    foreach (var (mac, ips) in macToIps)
                    {
                        if (ips.Count < 3) continue; // Normal: 1 IP per MAC. 2 = maybe DHCP transition. 3+ = poisoning
                        if (mac == "FF-FF-FF-FF-FF-FF") continue;
                        if (mac.StartsWith("01-00-5E")) continue; // Multicast

                        // Is the gateway IP one of them? That's the worst case.
                        bool includesGateway = _gatewayIp != null && ips.Contains(_gatewayIp);

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "ARP Spoof: Multiple IPs Sharing MAC",
                            Evidence = $"MAC {mac} is associated with {ips.Count} IPs: [{string.Join(", ", ips.Take(5))}]{(includesGateway ? " (INCLUDES GATEWAY)" : "")}",
                            Reasoning = "Multiple IP addresses resolve to the same MAC address in the ARP table. " +
                                        "This is a strong indicator of ARP table poisoning, where an attacker responds " +
                                        "to ARP requests for multiple IPs with their own MAC to intercept traffic. " +
                                        (includesGateway ? "The gateway IP is affected — all outbound traffic may be intercepted." : ""),
                            Confidence = includesGateway ? 0.92 : 0.80,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = includesGateway ? ResponseAction.NetworkIsolate : ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0,
                            Metadata = new Dictionary<string, string>
                            {
                                ["MAC"] = mac,
                                ["AffectedIPs"] = string.Join(";", ips),
                                ["IncludesGateway"] = includesGateway.ToString(),
                                ["TargetIP"] = includesGateway ? (_gatewayIp ?? "") : ""
                            }
                        });
                    }

                    // === Check 3: IP-to-MAC change for known hosts ===
                    foreach (var (ip, mac) in currentArp)
                    {
                        if (_arpBaseline.TryGetValue(ip, out var prevMac) && prevMac != mac)
                        {
                            // Skip gateway (handled above with higher confidence)
                            if (ip == _gatewayIp) continue;

                            // MAC changed for a known host — possible targeted spoof
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "ARP Spoof: Host MAC Changed",
                                Evidence = $"Host {ip} MAC changed from {prevMac} to {mac}",
                                Reasoning = "A known network host's MAC address changed, which may indicate ARP spoofing targeting that specific host for traffic interception.",
                                Confidence = 0.65, Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                        }
                        _arpBaseline[ip] = mac;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[ArpSpoofMonitor] Error"); }
            }
        }

        private static List<(string Ip, string Mac)> GetArpTable()
        {
            var results = new List<(string, string)>();
            try
            {
                int size = 0;
                GetIpNetTable(IntPtr.Zero, ref size, false);
                if (size == 0) return results;
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    if (GetIpNetTable(buffer, ref size, false) != 0) return results;
                    int entries = Marshal.ReadInt32(buffer);
                    int entrySize = Marshal.SizeOf<MIB_IPNETROW>();
                    for (int i = 0; i < entries; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_IPNETROW>(IntPtr.Add(buffer, 4 + i * entrySize));
                        if (row.dwType == 2) continue; // Invalid entry
                        var ip = new IPAddress(BitConverter.GetBytes(row.dwAddr)).ToString();
                        if (ip.StartsWith("224.") || ip == "255.255.255.255") continue;
                        var mac = $"{row.mac0:X2}-{row.mac1:X2}-{row.mac2:X2}-{row.mac3:X2}-{row.mac4:X2}-{row.mac5:X2}";
                        if (mac == "00-00-00-00-00-00") continue;
                        results.Add((ip, mac));
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            catch { }
            return results;
        }

        private static string? GetDefaultGateway()
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    var gw = ni.GetIPProperties().GatewayAddresses
                        .FirstOrDefault(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                    if (gw != null) return gw.Address.ToString();
                }
            }
            catch { }
            return null;
        }

        private static string? ResolveMac(string ip)
        {
            try
            {
                var addr = IPAddress.Parse(ip);
                var ipBytes = addr.GetAddressBytes();
                uint ipInt = BitConverter.ToUInt32(ipBytes, 0);
                var mac = new byte[6];
                int macLen = mac.Length;
                if (SendARP(ipInt, 0, mac, ref macLen) == 0)
                    return BitConverter.ToString(mac, 0, macLen);
            }
            catch { }
            return null;
        }
    }

    // ──────────────────────────────────────────────
    // Bluetooth Monitor — detects new unknown BT devices
    // ──────────────────────────────────────────────
    public sealed class BluetoothMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<BluetoothMonitor> _logger;
        private readonly HashSet<string> _baselineDevices = new(StringComparer.OrdinalIgnoreCase);

        public BluetoothMonitor(DetectionEngine de, ILogger<BluetoothMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BluetoothMonitor] Started");
            SnapshotBluetoothDevices(_baselineDevices);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    SnapshotBluetoothDevices(current);
                    foreach (var dev in current.Except(_baselineDevices))
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Bluetooth: New Device Detected",
                            Evidence = $"New Bluetooth device appeared: {dev}",
                            Reasoning = "A previously unseen Bluetooth device was detected. This could indicate unauthorized peripheral pairing.",
                            Confidence = 0.40, Tier = DetectionTier.Tier2Indicator,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                        _baselineDevices.Add(dev);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[BluetoothMonitor] Error"); }
            }
        }

        private static void SnapshotBluetoothDevices(HashSet<string> target)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices");
                if (key == null) return;
                foreach (var sub in key.GetSubKeyNames()) target.Add(sub);
            }
            catch { }
        }
    }

    // ──────────────────────────────────────────────
    // Canary File Monitor — honeypot files in sensitive directories
    // ──────────────────────────────────────────────
    public sealed class CanaryFileMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<CanaryFileMonitor> _logger;
        private readonly List<string> _canaryPaths = new();

        public CanaryFileMonitor(DetectionEngine de, ILogger<CanaryFileMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[CanaryFileMonitor] Started");
            PlantCanaryFiles();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(10000, ct);
                    foreach (var path in _canaryPaths)
                    {
                        if (!File.Exists(path))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Canary File: Deleted",
                                Evidence = $"Canary file was deleted: {path}",
                                Reasoning = "A honeypot canary file planted in a sensitive directory was deleted, indicating possible ransomware or unauthorized file manipulation.",
                                Confidence = 0.90, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                            _canaryPaths.Remove(path);
                            break;
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[CanaryFileMonitor] Error"); }
            }
        }

        private void PlantCanaryFiles()
        {
            var dirs = new[] { Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                               Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) };
            foreach (var dir in dirs)
            {
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
                try
                {
                    var canary = Path.Combine(dir, ".~sentinel_canary.tmp");
                    if (!File.Exists(canary))
                    {
                        File.WriteAllText(canary, "SENTINEL_CANARY");
                        File.SetAttributes(canary, FileAttributes.Hidden | FileAttributes.System);
                    }
                    _canaryPaths.Add(canary);
                }
                catch { }
            }
        }
    }

    // ──────────────────────────────────────────────
    // Browser Credential Guard — unified monitor for browser credential/session theft
    // Covers Chrome, Edge, and Firefox credential stores and cookie databases
    // ──────────────────────────────────────────────
    public sealed class BrowserCredentialGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<BrowserCredentialGuard> _logger;
        private readonly Dictionary<string, DateTime> _baselines = new();

        public BrowserCredentialGuard(DetectionEngine de, ILogger<BrowserCredentialGuard> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BrowserCredentialGuard] Started");

            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            // Define all browser targets: (BrowserName, FilePath, ProcessName, Description)
            var targets = new List<(string BrowserName, string FilePath, string ProcessName, string Description)>();

            // Chrome Login Data (credential theft)
            if (!string.IsNullOrEmpty(localAppData))
            {
                targets.Add(("Chrome", Path.Combine(localAppData, @"Google\Chrome\User Data\Default\Login Data"), "chrome", "credential theft"));
                targets.Add(("Chrome", Path.Combine(localAppData, @"Google\Chrome\User Data\Default\Network\Cookies"), "chrome", "session theft"));
                targets.Add(("Edge", Path.Combine(localAppData, @"Microsoft\Edge\User Data\Default\Login Data"), "msedge", "credential theft"));
                targets.Add(("Edge", Path.Combine(localAppData, @"Microsoft\Edge\User Data\Default\Network\Cookies"), "msedge", "session theft"));
            }

            // Firefox logins.json — multiple profiles possible
            if (!string.IsNullOrEmpty(roamingAppData))
            {
                var profilesDir = Path.Combine(roamingAppData, @"Mozilla\Firefox\Profiles");
                if (Directory.Exists(profilesDir))
                {
                    foreach (var prof in Directory.GetDirectories(profilesDir))
                    {
                        var loginJson = Path.Combine(prof, "logins.json");
                        targets.Add(("Firefox", loginJson, "firefox", "credential theft"));
                    }
                }
            }

            // Baseline all existing files
            foreach (var (_, filePath, _, _) in targets)
            {
                if (File.Exists(filePath))
                    _baselines[filePath] = File.GetLastWriteTimeUtc(filePath);
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);

                    foreach (var (browserName, filePath, processName, description) in targets)
                    {
                        if (!File.Exists(filePath)) continue;

                        var current = File.GetLastWriteTimeUtc(filePath);
                        if (_baselines.TryGetValue(filePath, out var prev) && current != prev)
                        {
                            var browserRunning = Process.GetProcessesByName(processName).Length > 0;
                            if (!browserRunning)
                            {
                                var dataType = description == "session theft" ? "Session" : "Credential";
                                var fileName = Path.GetFileName(filePath);
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = $"Browser {dataType} Theft: {browserName} {fileName} Modified While Browser Closed",
                                    Evidence = $"{browserName} {fileName} modified at {current:O} while {processName}.exe is not running",
                                    Reasoning = $"{browserName} {description} store was modified while the browser was not running, indicating {description}.",
                                    Confidence = 0.85, Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = ResponseAction.KillProcessTree,
                                    ProcessName = "SYSTEM", ProcessId = 0
                                });
                            }
                        }
                        _baselines[filePath] = current;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[BrowserCredentialGuard] Error"); }
            }
        }
    }

    // ──────────────────────────────────────────────
    // Device Install Monitor — new device class installs via SetupAPI
    // ──────────────────────────────────────────────
    public sealed class DeviceInstallMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DeviceInstallMonitor> _logger;
        private DateTime _lastCheck;

        public DeviceInstallMonitor(DetectionEngine de, ILogger<DeviceInstallMonitor> l) { _detectionEngine = de; _logger = l; }

        private static bool IsWindowsDriverPath(string imagePath)
        {
            // Normalize: many driver ImagePaths use \SystemRoot\, system32\, or relative paths
            var normalized = imagePath.TrimStart('\\');
            // Absolute Windows paths
            if (imagePath.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase)) return true;
            // \SystemRoot\ prefix (kernel notation for %SystemRoot%)
            if (normalized.StartsWith("SystemRoot\\", StringComparison.OrdinalIgnoreCase)) return true;
            // Relative system32 paths like "system32\drivers\pacer.sys" or "System32\DRIVERS\tdx.sys"
            if (normalized.StartsWith("system32\\", StringComparison.OrdinalIgnoreCase)) return true;
            // DriverStore path (inbox/WHQL drivers)
            if (imagePath.Contains(@"\DriverStore\", StringComparison.OrdinalIgnoreCase)) return true;
            // Program Files (legitimate third-party drivers like GPU, antivirus)
            if (imagePath.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DeviceInstallMonitor] Started");
            _lastCheck = DateTime.UtcNow;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                    if (key == null) continue;
                    foreach (var svcName in key.GetSubKeyNames())
                    {
                        try
                        {
                            using var svc = key.OpenSubKey(svcName);
                            if (svc == null) continue;
                            var startVal = svc.GetValue("Start");
                            var typeVal = svc.GetValue("Type");
                            if (startVal is int start && typeVal is int type && start == 1 && type == 1)
                            {
                                var imagePath = svc.GetValue("ImagePath")?.ToString() ?? "";
                                if (!string.IsNullOrEmpty(imagePath) && !IsWindowsDriverPath(imagePath))
                                {
                                    await _detectionEngine.EmitAsync(new DetectionEvent
                                    {
                                        RuleName = "Device Install: Non-Windows Kernel Driver",
                                        Evidence = $"Kernel driver service '{svcName}' with ImagePath '{imagePath}'",
                                        Reasoning = "A kernel-mode driver service was registered from a non-Windows directory, potentially a rootkit or malicious driver.",
                                        Confidence = 0.70, Tier = DetectionTier.Tier1Behavioral,
                                        AuthorizedResponse = ResponseAction.LogOnly,
                                        ProcessName = "SYSTEM", ProcessId = 0
                                    });
                                }
                            }
                        }
                        catch { }
                    }
                    _lastCheck = DateTime.UtcNow;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DeviceInstallMonitor] Error"); }
            }
        }
    }

    // ──────────────────────────────────────────────
    // DiskWideDllScanner — finds DLLs planted outside trusted directories
    // ──────────────────────────────────────────────
    public sealed class DiskWideDllScanner : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DiskWideDllScanner> _logger;

        public DiskWideDllScanner(DetectionEngine de, ILogger<DiskWideDllScanner> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DiskWideDllScanner] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(120000, ct);
                    // Scan user temp directories for suspicious DLLs
                    var tempDir = Path.GetTempPath();
                    if (Directory.Exists(tempDir))
                    {
                        foreach (var dll in Directory.EnumerateFiles(tempDir, "*.dll", SearchOption.TopDirectoryOnly))
                        {
                            try
                            {
                                var fi = new FileInfo(dll);
                                if (fi.Length > 0 && fi.CreationTimeUtc > DateTime.UtcNow.AddMinutes(-3))
                                {
                                    await _detectionEngine.EmitAsync(new DetectionEvent
                                    {
                                        RuleName = "DLL Sideloading: DLL in Temp Directory",
                                        Evidence = $"Recently created DLL in temp: {dll} ({fi.Length} bytes)",
                                        Reasoning = "A DLL was recently dropped into a temporary directory, which is a common DLL sideloading or injection staging technique.",
                                        Confidence = 0.65, Tier = DetectionTier.Tier2Indicator,
                                        ProcessName = "SYSTEM", ProcessId = 0
                                    });
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DiskWideDllScanner] Error"); }
            }
        }
    }

    // ──────────────────────────────────────────────
    // DLL Entropy Analyzer — detects packed/encrypted DLLs
    // ──────────────────────────────────────────────
    public sealed class DllEntropyAnalyzer : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DllEntropyAnalyzer> _logger;
        private readonly HashSet<string> _scanned = new(StringComparer.OrdinalIgnoreCase);

        public DllEntropyAnalyzer(DetectionEngine de, ILogger<DllEntropyAnalyzer> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DllEntropyAnalyzer] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(180000, ct);
                    var tempDir = Path.GetTempPath();
                    var downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
                    foreach (var dir in new[] { tempDir, downloadsDir })
                    {
                        if (!Directory.Exists(dir)) continue;
                        foreach (var file in Directory.EnumerateFiles(dir, "*.dll", SearchOption.TopDirectoryOnly))
                        {
                            if (_scanned.Contains(file)) continue;
                            _scanned.Add(file);
                            try
                            {
                                var entropy = CalculateEntropy(file);
                                if (entropy > 7.2) // High entropy = likely packed/encrypted
                                {
                                    await _detectionEngine.EmitAsync(new DetectionEvent
                                    {
                                        RuleName = "DLL Entropy: High Entropy DLL",
                                        Evidence = $"DLL '{file}' has entropy {entropy:F2} (threshold 7.2)",
                                        Reasoning = "A DLL with abnormally high entropy was found, suggesting it is packed or encrypted — common for malware payloads.",
                                        Confidence = 0.70, Tier = DetectionTier.Tier2Indicator,
                                        ProcessName = "SYSTEM", ProcessId = 0
                                    });
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DllEntropyAnalyzer] Error"); }
            }
        }

        private static double CalculateEntropy(string filePath)
        {
            var freq = new long[256];
            long total = 0;
            using (var fs = File.OpenRead(filePath))
            {
                var buf = new byte[8192];
                int read;
                while ((read = fs.Read(buf, 0, buf.Length)) > 0)
                {
                    for (int i = 0; i < read; i++) freq[buf[i]]++;
                    total += read;
                    if (total > 1_000_000) break; // Sample first 1MB
                }
            }
            if (total == 0) return 0;
            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = (double)freq[i] / total;
                entropy -= p * Math.Log2(p);
            }
            return entropy;
        }
    }

    // ──────────────────────────────────────────────
    // DLL Load Failure Monitor — watches Windows event log for load failures
    // ──────────────────────────────────────────────
    public sealed class DllLoadFailureMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DllLoadFailureMonitor> _logger;

        public DllLoadFailureMonitor(DetectionEngine de, ILogger<DllLoadFailureMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DllLoadFailureMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct);
                    // Check Application event log for SideBySide errors (Event ID 33, 59, 80)
                    try
                    {
                        var log = new EventLog("Application");
                        var cutoff = DateTime.UtcNow.AddSeconds(-20);
                        foreach (EventLogEntry entry in log.Entries)
                        {
                            if (entry.TimeGenerated.ToUniversalTime() < cutoff) continue;
                            if (entry.Source == "SideBySide" && entry.EntryType == EventLogEntryType.Error)
                            {
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "DLL Load Failure: SideBySide Error",
                                    Evidence = $"SideBySide error at {entry.TimeGenerated}: {entry.Message?.Substring(0, Math.Min(200, entry.Message?.Length ?? 0))}",
                                    Reasoning = "A DLL side-by-side loading failure was detected, which may indicate DLL hijacking or corruption.",
                                    Confidence = 0.50, Tier = DetectionTier.Tier2Indicator,
                                    ProcessName = "SYSTEM", ProcessId = 0
                                });
                                break; // One per cycle
                            }
                        }
                    }
                    catch { }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DllLoadFailureMonitor] Error"); }
            }
        }
    }

    // ──────────────────────────────────────────────
    // DNS Response Validation Monitor — detects DNS poisoning via TTL anomalies
    // ──────────────────────────────────────────────
    public sealed class DnsResponseValidationMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DnsResponseValidationMonitor> _logger;
        private readonly ConcurrentDictionary<string, IPAddress[]> _baselineResolutions = new();

        public DnsResponseValidationMonitor(DetectionEngine de, ILogger<DnsResponseValidationMonitor> l) { _detectionEngine = de; _logger = l; }

        // Accumulates all known-good IPs per domain across CDN rotations
        private readonly ConcurrentDictionary<string, HashSet<string>> _knownSubnets = new();

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DnsResponseValidationMonitor] Started");
            var watchDomains = new[] { "login.microsoftonline.com", "accounts.google.com", "github.com" };

            // Pre-populate known Microsoft, Google, and GitHub subnets to prevent false positives from global CDNs
            var msSubnets = _knownSubnets.GetOrAdd("login.microsoftonline.com", _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            foreach (var net in new[] { "20.190", "40.126", "20.20", "20.231", "20.150", "20.50", "52.150", "52.160", "2603:1036", "2603:1026", "2603:1046" })
                msSubnets.Add(net);

            var googleSubnets = _knownSubnets.GetOrAdd("accounts.google.com", _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            foreach (var net in new[] { "172.217", "142.250", "142.251", "216.58", "74.125", "172.253", "108.177", "64.233", "2607:f8b0" })
                googleSubnets.Add(net);

            var githubSubnets = _knownSubnets.GetOrAdd("github.com", _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            foreach (var net in new[] { "140.82", "192.30", "185.199", "20.200", "20.201", "20.205", "4.225", "143.204", "2600:9000", "2a04:4e42" })
                githubSubnets.Add(net);

            // Resolve each domain multiple times over 2 minutes to build a robust baseline
            // CDN/anycast services rotate IPs frequently — single-shot baselines cause false positives
            for (int round = 0; round < 3; round++)
            {
                foreach (var d in watchDomains)
                {
                    try
                    {
                        var addrs = await Dns.GetHostAddressesAsync(d, ct);
                        _baselineResolutions[d] = addrs;
                        var subnets = _knownSubnets.GetOrAdd(d, _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                        foreach (var a in addrs)
                        {
                            subnets.Add(GetSubnet(a.ToString()));
                        }
                    }
                    catch { }
                }
                if (round < 2) await Task.Delay(40000, ct);
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    foreach (var domain in watchDomains)
                    {
                        try
                        {
                            var current = await Dns.GetHostAddressesAsync(domain, ct);
                            if (_baselineResolutions.TryGetValue(domain, out var baseline))
                            {
                                var currentSet = new HashSet<string>(current.Select(a => a.ToString()));
                                var baselineSet = new HashSet<string>(baseline.Select(a => a.ToString()));

                                // Phase 1: Check exact IP overlap (normal case)
                                if (currentSet.Overlaps(baselineSet))
                                {
                                    // IPs overlap — normal CDN rotation, update baseline
                                    _baselineResolutions[domain] = current;
                                    var subnets = _knownSubnets.GetOrAdd(domain, _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                                    foreach (var a in current) subnets.Add(GetSubnet(a.ToString()));
                                    continue;
                                }

                                // Phase 2: No exact overlap — check if new IPs are in known subnets
                                var knownNets = _knownSubnets.GetOrAdd(domain, _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                                var newSubnets = current.Select(a => GetSubnet(a.ToString())).ToHashSet();
                                bool allInKnownSubnets = newSubnets.All(s => knownNets.Contains(s));

                                if (allInKnownSubnets)
                                {
                                    // Same /16 or /32 subnets — CDN rotation, not poisoning
                                    _baselineResolutions[domain] = current;
                                    foreach (var a in current) knownNets.Add(GetSubnet(a.ToString()));
                                    continue;
                                }

                                // Phase 3: IPs moved to a completely different subnet — likely poisoning
                                var suspiciousIps = currentSet.Except(baselineSet).ToList();
                                var metadata = new Dictionary<string, string>
                                {
                                    { "Domain", domain },
                                    { "TargetIP", suspiciousIps.FirstOrDefault() ?? "" },
                                    { "AllNewIPs", string.Join(";", suspiciousIps) }
                                };

                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "DNS Poisoning: Critical Domain Resolution Changed",
                                    Evidence = $"Domain '{domain}' resolved to {string.Join(",", currentSet)} (baseline: {string.Join(",", baselineSet)}, known subnets: {string.Join(",", knownNets)})",
                                    Reasoning = "A critical authentication domain resolved to IPs in completely different subnets from all previously observed addresses, indicating possible DNS poisoning.",
                                    Confidence = 0.90, Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = ResponseAction.NetworkIsolate,
                                    ProcessName = "SYSTEM", ProcessId = 0,
                                    Metadata = metadata
                                });
                            }
                            _baselineResolutions[domain] = current;
                        }
                        catch { }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DnsResponseValidationMonitor] Error"); }
            }
        }

        /// <summary>Extract subnet prefix (first two octets for IPv4 /16, or first two segments for IPv6 /32) for CDN rotation tolerance.</summary>
        private static string GetSubnet(string ip)
        {
            if (ip.Contains(':'))
            {
                var parts = ip.Split(':');
                return parts.Length >= 2 ? $"{parts[0]}:{parts[1]}" : ip;
            }
            else
            {
                var parts = ip.Split('.');
                return parts.Length >= 2 ? $"{parts[0]}.{parts[1]}" : ip;
            }
        }
    }


    // ──────────────────────────────────────────────
    // Firewall Integrity Monitor — detects firewall rule tampering
    // ──────────────────────────────────────────────
    public sealed class FirewallIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<FirewallIntegrityMonitor> _logger;
        private int _baselineRuleCount;

        public FirewallIntegrityMonitor(DetectionEngine de, ILogger<FirewallIntegrityMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[FirewallIntegrityMonitor] Started");
            _baselineRuleCount = CountFirewallRules();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    var current = CountFirewallRules();
                    if (_baselineRuleCount > 0 && current > _baselineRuleCount + 5)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Firewall Integrity: Bulk Rule Addition",
                            Evidence = $"Firewall rules increased from {_baselineRuleCount} to {current}",
                            Reasoning = "A significant number of firewall rules were added since baseline, indicating possible malware creating exceptions.",
                            Confidence = 0.70, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                    }
                    _baselineRuleCount = current;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[FirewallIntegrityMonitor] Error"); }
            }
        }

        private static int CountFirewallRules()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules");
                return key?.ValueCount ?? 0;
            }
            catch { return 0; }
        }
    }

    // ──────────────────────────────────────────────
    // Gateway Fingerprint Monitor — detects gateway change (rogue AP)
    // ──────────────────────────────────────────────
    public sealed class GatewayFingerprintMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<GatewayFingerprintMonitor> _logger;
        private string? _baselineGateway;

        public GatewayFingerprintMonitor(DetectionEngine de, ILogger<GatewayFingerprintMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[GatewayFingerprintMonitor] Started");
            _baselineGateway = GetDefaultGateway();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    var current = GetDefaultGateway();
                    if (_baselineGateway != null && current != null && current != _baselineGateway)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Network: Default Gateway Changed",
                            Evidence = $"Gateway changed from {_baselineGateway} to {current}",
                            Reasoning = "The default network gateway changed at runtime, possibly indicating a rogue access point or network hijack.",
                            Confidence = 0.75, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.NetworkIsolate,
                            ProcessName = "SYSTEM", ProcessId = 0,
                            Metadata = new Dictionary<string, string> { { "TargetIP", current ?? "" } }
                        });
                        _baselineGateway = current;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[GatewayFingerprintMonitor] Error"); }
            }
        }

        private static string? GetDefaultGateway()
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    var gw = ni.GetIPProperties().GatewayAddresses
                        .FirstOrDefault(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                    if (gw != null) return gw.Address.ToString();
                }
            }
            catch { }
            return null;
        }
    }

    // ──────────────────────────────────────────────
    // Microsoft Account Guard — watches for token files
    // ──────────────────────────────────────────────
    public sealed class MicrosoftAccountGuardMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<MicrosoftAccountGuardMonitor> _logger;
        private readonly HashSet<string> _alertedFiles = new(StringComparer.OrdinalIgnoreCase);

        public MicrosoftAccountGuardMonitor(DetectionEngine de, ILogger<MicrosoftAccountGuardMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[MicrosoftAccountGuardMonitor] Started");
            var tokenCachePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                @"Microsoft\TokenBroker\Cache");
            DateTime lastScan = DateTime.UtcNow;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    if (!Directory.Exists(tokenCachePath)) continue;

                    foreach (var file in Directory.EnumerateFiles(tokenCachePath, "*.tbres"))
                    {
                        var fi = new FileInfo(file);
                        if (fi.LastWriteTimeUtc > lastScan)
                        {
                            // Check which process has the token file open
                            // If a non-browser, non-system process is touching token files, alert
                            var fileName = Path.GetFileName(file);
                            if (_alertedFiles.Contains(fileName)) continue;

                            // Look for processes that might be reading token files
                            foreach (var proc in Process.GetProcesses())
                            {
                                try
                                {
                                    var name = proc.ProcessName;
                                    // Skip known legitimate token consumers
                                    if (name.Contains("RuntimeBroker", StringComparison.OrdinalIgnoreCase) ||
                                        name.Contains("svchost", StringComparison.OrdinalIgnoreCase) ||
                                        name.Contains("TokenBroker", StringComparison.OrdinalIgnoreCase) ||
                                        name.Contains("msedge", StringComparison.OrdinalIgnoreCase) ||
                                        name.Contains("chrome", StringComparison.OrdinalIgnoreCase) ||
                                        name.Contains("Teams", StringComparison.OrdinalIgnoreCase) ||
                                        name.Contains("OneDrive", StringComparison.OrdinalIgnoreCase) ||
                                        name.Contains("explorer", StringComparison.OrdinalIgnoreCase))
                                        continue;

                                    // Check if process is from temp/suspicious path
                                    string? imagePath = null;
                                    try { imagePath = proc.MainModule?.FileName; } catch { }
                                    if (!string.IsNullOrEmpty(imagePath) &&
                                        (imagePath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                                         imagePath.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase)))
                                    {
                                        _alertedFiles.Add(fileName);
                                        await _detectionEngine.EmitAsync(new DetectionEvent
                                        {
                                            RuleName = "Credential Theft: Microsoft Token Cache Accessed",
                                            Evidence = $"Token cache file '{fileName}' modified while suspicious process '{name}' (PID {proc.Id}) from '{imagePath}' is running",
                                            Reasoning = "The Microsoft TokenBroker cache was accessed while a process from a suspicious path is active, which may indicate token theft.",
                                            Confidence = 0.70, Tier = DetectionTier.Tier1Behavioral,
                                            AuthorizedResponse = ResponseAction.KillProcessTree,
                                            ProcessName = name, ProcessId = proc.Id
                                        });
                                        break;
                                    }
                                }
                                catch { }
                                finally { proc.Dispose(); }
                            }
                        }
                    }
                    lastScan = DateTime.UtcNow;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[MicrosoftAccountGuardMonitor] Error"); }
            }
        }
    }

    // ──────────────────────────────────────────────
    // Module Validation Monitor — checks loaded DLL integrity via hash
    // ──────────────────────────────────────────────
    public sealed class ModuleValidationMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ModuleValidationMonitor> _logger;
        private readonly ConcurrentDictionary<string, string> _baselineHashes = new(StringComparer.OrdinalIgnoreCase);

        public ModuleValidationMonitor(DetectionEngine de, ILogger<ModuleValidationMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ModuleValidationMonitor] Started");
            // Baseline our own modules
            var selfDir = AppContext.BaseDirectory;
            foreach (var dll in Directory.EnumerateFiles(selfDir, "*.dll"))
            {
                try { _baselineHashes[dll] = HashFile(dll); } catch { }
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    foreach (var (path, expectedHash) in _baselineHashes)
                    {
                        if (!File.Exists(path))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Self-Protection: Sentinel Module Deleted",
                                Evidence = $"Module was deleted: {path}",
                                Reasoning = "A Sentinel runtime module was removed from disk, indicating active tampering.",
                                Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                            continue;
                        }
                        var currentHash = HashFile(path);
                        if (currentHash != expectedHash)
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Self-Protection: Sentinel Module Tampered",
                                Evidence = $"Module hash mismatch: {path} (expected {expectedHash}, got {currentHash})",
                                Reasoning = "A Sentinel runtime module was modified on disk, indicating active tampering or DLL replacement.",
                                Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                            _baselineHashes[path] = currentHash;
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[ModuleValidationMonitor] Error"); }
            }
        }

        private static string HashFile(string path)
        {
            using var fs = File.OpenRead(path);
            var hash = SHA256.HashData(fs);
            return Convert.ToHexString(hash);
        }
    }

    // ──────────────────────────────────────────────
    // Public IP Monitor — detects VPN/proxy changes
    // ──────────────────────────────────────────────
    public sealed class PublicIpMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<PublicIpMonitor> _logger;
        private string? _baselineIp;

        public PublicIpMonitor(DetectionEngine de, ILogger<PublicIpMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[PublicIpMonitor] Started");
            _baselineIp = await GetPublicIp(ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(300000, ct);
                    var currentIp = await GetPublicIp(ct);
                    if (_baselineIp != null && currentIp != null && currentIp != _baselineIp)
                    {
                        _logger.LogInformation("[PublicIpMonitor] Public IP changed from {Old} to {New}", _baselineIp, currentIp);
                        _baselineIp = currentIp;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[PublicIpMonitor] Error"); }
            }
        }

        private static async Task<string?> GetPublicIp(CancellationToken ct)
        {
            try
            {
                using var http = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                return (await http.GetStringAsync("https://api.ipify.org", ct)).Trim();
            }
            catch { return null; }
        }
    }

    // ──────────────────────────────────────────────
    // Remote Access Monitor — detects RAT indicators (RDP, VNC, etc.)
    // ──────────────────────────────────────────────
    public sealed class RemoteAccessMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<RemoteAccessMonitor> _logger;

        // 35+ known remote access tools — both legitimate and commonly abused
        // Detection is Tier2 (LogOnly) because running these isn't proof of compromise.
        // Trust model: detect presence, let correlation engine decide if suspicious context exists.
        private static readonly string[] RemoteAccessProcessNames =
        {
            // Commercial remote desktop/support
            "teamviewer", "teamviewer_service", "tv_w32", "tv_x64",
            "anydesk", "anydesk.exe",
            "rustdesk", "rustdesk-service",
            "radmin", "rserver3", "radminserver",
            "logmein", "logmeinrescue", "lmi_rescue",
            "bomgar", "bomgar-scc", "bomgar-rdp",
            "connectwise", "screenconnect",
            "splashtop", "splashtopstreamer", "srmanager",
            "supremo", "supremoservice",
            "ammyy", "ammyyadmin", "aa_v3",
            "ultraviewer", "ultraviewerservice",
            "parsec", "parsecd",
            "chrome remote desktop", "remoting_host",
            "dwservice", "dwagent",
            "meshagent", "meshcentral",
            "getscreen", "getscreen.me",
            // VNC implementations
            "vnc", "vncserver", "vncviewer", "winvnc", "tvnserver", "uvnc",
            "tightvnc", "tigervnc", "realvnc",
            // RDP-related (non-standard)
            "rdpwrap", "rdpcheck", "rdpclip",
            // Potentially unwanted — often deployed by attackers
            "ngrok", "frpc", "frps", "cloudflared", // Tunneling
            "chisel", "rathole", "bore", // Reverse tunnels
            "mstsc", // Standard RDP client - context matters
        };

        public RemoteAccessMonitor(DetectionEngine de, ILogger<RemoteAccessMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[RemoteAccessMonitor] Started — monitoring {Count} known remote access tools", RemoteAccessProcessNames.Length);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    foreach (var proc in Process.GetProcesses())
                    {
                        try
                        {
                            var name = proc.ProcessName.ToLowerInvariant();
                            if (RemoteAccessProcessNames.Any(r => name.Contains(r)))
                            {
                                // Higher confidence for tunneling tools (ngrok, frpc, chisel)
                                // — these are almost never legitimate on endpoints
                                bool isTunnel = name.Contains("ngrok") || name.Contains("frpc") ||
                                                name.Contains("chisel") || name.Contains("rathole") ||
                                                name.Contains("bore") || name.Contains("cloudflared");

                                string? imagePath = null;
                                try { imagePath = proc.MainModule?.FileName; } catch { }

                                // Tunneling from Temp/Downloads = very suspicious
                                bool fromSuspiciousPath = imagePath != null &&
                                    (imagePath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                                     imagePath.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase));

                                var confidence = isTunnel ? (fromSuspiciousPath ? 0.85 : 0.75) : 0.55;
                                var tier = (isTunnel && fromSuspiciousPath)
                                    ? DetectionTier.Tier1Behavioral
                                    : DetectionTier.Tier2Indicator;

                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = isTunnel
                                        ? "Remote Access: Tunneling Tool Detected"
                                        : "Remote Access: Known RAT Process Running",
                                    Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) running{(imagePath != null ? $" from '{imagePath}'" : "")}",
                                    Reasoning = isTunnel
                                        ? "A reverse tunneling tool was detected. These are rarely legitimate on endpoints and are commonly used to bypass firewalls for C2 or unauthorized access."
                                        : "A remote access tool process was detected. While some are legitimate, they are commonly abused for unauthorized access.",
                                    Confidence = confidence, Tier = tier,
                                    AuthorizedResponse = (isTunnel && fromSuspiciousPath)
                                        ? ResponseAction.KillProcessTree
                                        : ResponseAction.LogOnly,
                                    ProcessName = proc.ProcessName, ProcessId = proc.Id
                                });
                            }
                        }
                        catch { }
                        finally { proc.Dispose(); }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[RemoteAccessMonitor] Error"); }
            }
        }
    }

    // ──────────────────────────────────────────────
    // Runtime Module Integrity Monitor — checks loaded module paths
    // ──────────────────────────────────────────────
    public sealed class RuntimeModuleIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<RuntimeModuleIntegrityMonitor> _logger;

        public RuntimeModuleIntegrityMonitor(DetectionEngine de, ILogger<RuntimeModuleIntegrityMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[RuntimeModuleIntegrityMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    // Check that the Sentinel service's own loaded modules are from expected paths
                    var selfProc = Process.GetCurrentProcess();
                    foreach (ProcessModule mod in selfProc.Modules)
                    {
                        try
                        {
                            var modPath = mod.FileName ?? "";
                            if (!modPath.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase) &&
                                !modPath.Contains(AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase) &&
                                !modPath.Contains(@"\dotnet\", StringComparison.OrdinalIgnoreCase) &&
                                !modPath.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase) &&
                                !modPath.Contains(@"\Microsoft\Windows Defender\", StringComparison.OrdinalIgnoreCase))
                            {
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "Self-Protection: Unexpected Module Loaded",
                                    Evidence = $"Unexpected module loaded into Sentinel process: {modPath}",
                                    Reasoning = "A module from an untrusted path was loaded into the Sentinel service process, indicating possible DLL injection.",
                                    Confidence = 0.85, Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = ResponseAction.KillProcessTree,
                                    ProcessName = "WindowsSentinel.Service", ProcessId = Environment.ProcessId
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[RuntimeModuleIntegrityMonitor] Error"); }
            }
        }
    }

    // ──────────────────────────────────────────────
    // Scheduled Task Monitor — detects new/modified scheduled tasks
    // ──────────────────────────────────────────────
    public sealed class ScheduledTaskMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ScheduledTaskMonitor> _logger;
        private readonly HashSet<string> _baselineTasks = new(StringComparer.OrdinalIgnoreCase);

        public ScheduledTaskMonitor(DetectionEngine de, ILogger<ScheduledTaskMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ScheduledTaskMonitor] Started");
            SnapshotTasks(_baselineTasks);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    SnapshotTasks(current);
                    foreach (var task in current.Except(_baselineTasks))
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Persistence: New Scheduled Task",
                            Evidence = $"New scheduled task: {task}",
                            Reasoning = "A new scheduled task was created, which is a common persistence mechanism for malware.",
                            Confidence = 0.65, Tier = DetectionTier.Tier2Indicator,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                        _baselineTasks.Add(task);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[ScheduledTaskMonitor] Error"); }
            }
        }

        private static void SnapshotTasks(HashSet<string> target)
        {
            var taskDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\Tasks");
            if (!Directory.Exists(taskDir)) return;
            try
            {
                foreach (var f in Directory.EnumerateFiles(taskDir, "*", SearchOption.AllDirectories))
                    target.Add(f);
            }
            catch { }
        }
    }

    // ──────────────────────────────────────────────
    // Secure Boot Integrity Monitor — checks Secure Boot state
    // ──────────────────────────────────────────────
    public sealed class SecureBootIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<SecureBootIntegrityMonitor> _logger;

        public SecureBootIntegrityMonitor(DetectionEngine de, ILogger<SecureBootIntegrityMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[SecureBootIntegrityMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(300000, ct);
                    try
                    {
                        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
                        var val = key?.GetValue("UEFISecureBootEnabled");
                        if (val is int enabled && enabled == 0)
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Secure Boot: Disabled",
                                Evidence = "UEFI Secure Boot is disabled on this system",
                                Reasoning = "Secure Boot being disabled allows unsigned bootloaders and rootkits to load before the OS.",
                                Confidence = 0.50, Tier = DetectionTier.Tier2Indicator,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                        }
                    }
                    catch { }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[SecureBootIntegrityMonitor] Error"); }
            }
        }
    }

    // ──────────────────────────────────────────────
    // Syscall Stub Monitor — detects ntdll syscall hook/unhook
    // ──────────────────────────────────────────────
    public sealed class SyscallStubMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<SyscallStubMonitor> _logger;
        private byte[]? _baselineNtdllHash;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        public SyscallStubMonitor(DetectionEngine de, ILogger<SyscallStubMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[SyscallStubMonitor] Started");
            var ntdllPath = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
            if (File.Exists(ntdllPath))
            {
                try { _baselineNtdllHash = SHA256.HashData(File.ReadAllBytes(ntdllPath)); } catch { }
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    if (_baselineNtdllHash == null || !File.Exists(ntdllPath)) continue;
                    var currentHash = SHA256.HashData(File.ReadAllBytes(ntdllPath));
                    if (!currentHash.SequenceEqual(_baselineNtdllHash))
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "ETW Tampering: ntdll.dll On-Disk Hash Changed",
                            Evidence = $"ntdll.dll hash changed from {Convert.ToHexString(_baselineNtdllHash)} to {Convert.ToHexString(currentHash)}",
                            Reasoning = "The on-disk ntdll.dll hash changed, which should never happen during normal operation.",
                            Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                        _baselineNtdllHash = currentHash;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[SyscallStubMonitor] Error"); }
            }
        }
    }

    // ──────────────────────────────────────────────
    // TLS Certificate Monitor — detects NEW root certificates added after baseline.
    // Startup: silently baselines all existing certs. Never alerts or removes.
    // Runtime: detects new certs not in baseline. Emits Tier2 log-only alerts.
    // Never auto-removes any certificate — alerts only for admin review.
    // ──────────────────────────────────────────────
    public sealed class TlsCertificateMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<TlsCertificateMonitor> _logger;
        private readonly HashSet<string> _baselineThumbprints = new(StringComparer.OrdinalIgnoreCase);

        // Known enterprise TLS inspection CA subject patterns — these are legitimate
        // but still logged as Tier2 indicators for visibility
        private static readonly string[] KnownEnterpriseCAs =
        {
            "Zscaler", "Blue Coat", "BlueCoat", "Palo Alto", "Fortinet", "FortiGate",
            "Symantec WSS", "Cisco Umbrella", "McAfee", "Sophos", "Barracuda",
            "WatchGuard", "Check Point", "SonicWall", "Trend Micro", "iboss",
            "Websense", "Forcepoint", "Netskope", "Clearswift"
        };

        // Known developer/debugging tool CA patterns — Tier2 only, no removal
        private static readonly string[] KnownDevToolCAs =
        {
            "Fiddler", "DO_NOT_TRUST_FiddlerRoot", "Charles", "mitmproxy",
            "Burp", "BurpSuite", "OWASP ZAP", "Telerik"
        };

        public TlsCertificateMonitor(
            DetectionEngine de, SentinelConfig config, JsonlEventLogger logger,
            ILogger<TlsCertificateMonitor> l)
        {
            _detectionEngine = de; _config = config; _eventLogger = logger; _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[TlsCertificateMonitor] Started — performing startup full-store audit");

            // Phase 1: Startup scan — audit every existing cert, flag unknowns
            try
            {
                await AuditAndBaselineStoreAsync(ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[TlsCertificateMonitor] Startup audit failed");
            }

            _logger.LogInformation("[TlsCertificateMonitor] Audit complete: {Count} certs baselined", _baselineThumbprints.Count);

            // Phase 2: Runtime polling — detect new certs
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    await PollForNewCertsAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[TlsCertificateMonitor] Poll error"); }
            }
        }

        /// <summary>
        /// Startup audit: score every existing cert. Known public CAs are silently baselined.
        /// Unknown/suspicious certs that were present before Sentinel started get flagged as
        /// Tier2 indicators (can't auto-remove because we don't know if user installed them).
        /// This prevents the "race the baseline" attack from going completely unnoticed.
        /// </summary>
        private async Task AuditAndBaselineStoreAsync(CancellationToken ct)
        {
            using var store = new System.Security.Cryptography.X509Certificates.X509Store(
                System.Security.Cryptography.X509Certificates.StoreName.Root,
                System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);
            store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);

            foreach (var cert in store.Certificates)
            {
                if (ct.IsCancellationRequested) break;
                _baselineThumbprints.Add(cert.Thumbprint);

                var analysis = AnalyzeCert(cert);

                // Known public root CAs: fully trusted, no alert
                if (analysis.IsPublicRootCa) continue;

                // Known enterprise/dev tool CAs: log as Tier2 for visibility but no action
                if (analysis.IsEnterpriseCa || analysis.IsDevTool)
                {
                    await EmitCertDetectionAsync(cert, analysis, null, isStartupScan: true);
                    continue;
                }

                // Unknown cert with suspicious signals: flag it even though it was pre-existing
                // This catches the "install cert before Sentinel starts" attack
                if (analysis.Confidence >= 0.70)
                {
                    _logger.LogWarning("[TlsCertificateMonitor] Startup: suspicious pre-existing cert: {Subject} (confidence {Conf:F2})",
                        cert.Subject, analysis.Confidence);

                    // Very high confidence at startup (>=0.90): actively remove
                    // These are almost certainly attacker MitM certs planted before Sentinel started
                    ResponseAction? startupResponse = null;
                    if (analysis.Confidence >= 0.90 && _config.ActiveResponse)
                    {
                        startupResponse = ResponseAction.RemoveCert;
                        _logger.LogWarning("[TlsCertificateMonitor] REMOVING malicious pre-existing cert: {Subject}", cert.Subject);
                    }

                    await EmitCertDetectionAsync(cert, analysis, null, isStartupScan: false, startupResponse);
                    // Note: isStartupScan=false here so the response engine actually processes the removal
                }
            }
        }

        /// <summary>
        /// Runtime polling: detect new certs added after baseline.
        /// New unknown certs with high confidence → remove + notify.
        /// New known public CAs → baseline silently.
        /// Monitors Root AND TrustedPublisher stores (BYOVD attack vector).
        /// </summary>
        private async Task PollForNewCertsAsync(CancellationToken ct)
        {
            await PollStoreAsync(
                System.Security.Cryptography.X509Certificates.StoreName.Root,
                "Root", ct);
            await PollStoreAsync(
                System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher,
                "TrustedPublisher", ct);
        }

        private async Task PollStoreAsync(
            System.Security.Cryptography.X509Certificates.StoreName storeName,
            string storeLabel,
            CancellationToken ct)
        {
            try
            {
                using var store = new System.Security.Cryptography.X509Certificates.X509Store(
                    storeName,
                    System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);
                store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);

                foreach (var cert in store.Certificates)
                {
                    if (ct.IsCancellationRequested) break;
                    var key = $"{storeLabel}:{cert.Thumbprint}";
                    if (_baselineThumbprints.Contains(key)) continue;

                    var analysis = AnalyzeCert(cert);
                    var adderInfo = TraceAdderProcess(cert.Thumbprint);

                    // Known public root CAs: baseline silently
                    if (analysis.IsPublicRootCa && analysis.Confidence <= 0.50)
                    {
                        _baselineThumbprints.Add(key);
                        continue;
                    }

                    // TrustedPublisher additions are extra suspicious — used for BYOVD
                    if (storeLabel == "TrustedPublisher")
                    {
                        analysis.Confidence = Math.Max(analysis.Confidence, 0.75);
                        analysis.Reasons.Add("Added to TrustedPublisher store (BYOVD/driver signing attack vector)");
                    }

                    _logger.LogWarning("[TlsCertificateMonitor] New cert in {Store}: Subject={Subject}, Confidence={Conf:F2}",
                        storeLabel, cert.Subject, analysis.Confidence);

                    ResponseAction response;
                    if (analysis.Confidence >= 0.80)
                    {
                        response = adderInfo != null ? ResponseAction.RemoveCertAndKillAdder : ResponseAction.RemoveCert;
                    }
                    else if (analysis.Confidence >= 0.65 && !analysis.IsEnterpriseCa && !analysis.IsDevTool)
                    {
                        response = ResponseAction.RemoveCert;
                    }
                    else
                    {
                        response = ResponseAction.LogOnly;
                    }

                    await EmitCertDetectionAsync(cert, analysis, adderInfo, isStartupScan: false, response);

                    // BYOVD chain trace: if a TrustedPublisher cert was removed,
                    // scan for drivers signed by this cert and quarantine them.
                    if (storeLabel == "TrustedPublisher" && response != ResponseAction.LogOnly)
                    {
                        await ScanAndQuarantineSignedDriversAsync(cert.Thumbprint, cert.Subject);
                    }

                    _baselineThumbprints.Add(key);
                }
            }
            catch { }
        }

        /// <summary>
        /// After removing a malicious code-signing cert from TrustedPublisher,
        /// scan the drivers directory for any .sys files signed by that cert.
        /// Quarantine the driver + remove its service registration.
        /// </summary>
        private async Task ScanAndQuarantineSignedDriversAsync(string certThumbprint, string certSubject)
        {
            try
            {
                var driversDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers");
                if (!Directory.Exists(driversDir)) return;

                foreach (var driverPath in Directory.EnumerateFiles(driversDir, "*.sys"))
                {
                    try
                    {
                        // Check if this driver is signed by the removed cert
                        var signerCert = GetFileCertificate(driverPath);
                        if (signerCert == null) continue;

                        bool matchesThumbprint = signerCert.Thumbprint?.Equals(certThumbprint, StringComparison.OrdinalIgnoreCase) == true;
                        bool matchesSubject = signerCert.Subject?.Contains(ExtractCN(certSubject), StringComparison.OrdinalIgnoreCase) == true;

                        if (!matchesThumbprint && !matchesSubject) continue;

                        var driverName = Path.GetFileNameWithoutExtension(driverPath);

                        _logger.LogWarning("[TlsCertificateMonitor] BYOVD: driver '{Driver}' signed by removed cert. Quarantining.", driverName);

                        // Quarantine the driver file
                        await _eventLogger.LogEventAsync("response", new ResponseEvent
                        {
                            ProcessId = 0,
                            ProcessName = "TlsCertificateMonitor",
                            ActionTaken = "QUARANTINE_BYOVD_DRIVER",
                            Reason = $"Driver '{driverPath}' signed by removed TrustedPublisher cert '{certSubject}'. Quarantining."
                        });

                        // Try to stop the driver service first
                        try
                        {
                            using var sc = new System.ServiceProcess.ServiceController(driverName);
                            if (sc.Status == System.ServiceProcess.ServiceControllerStatus.Running)
                                sc.Stop();
                        }
                        catch { }

                        // Remove the service registration
                        try
                        {
                            using var servicesKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                                @"SYSTEM\CurrentControlSet\Services", writable: true);
                            servicesKey?.DeleteSubKeyTree(driverName, throwOnMissingSubKey: false);
                        }
                        catch { }

                        // Quarantine the driver file (small delay for handle release)
                        await Task.Delay(500);
                        try
                        {
                            if (File.Exists(driverPath))
                            {
                                var quarantinePath = Path.Combine(
                                    Path.GetDirectoryName(_eventLogger.LogFilePath) ?? "",
                                    "Quarantine",
                                    $"byovd_{driverName}_{DateTime.UtcNow:yyyyMMddHHmmss}.sys.quarantine");
                                Directory.CreateDirectory(Path.GetDirectoryName(quarantinePath)!);

                                // XOR encrypt to quarantine
                                var bytes = await File.ReadAllBytesAsync(driverPath);
                                for (int i = 0; i < bytes.Length; i++) bytes[i] ^= 0x5A;
                                await File.WriteAllBytesAsync(quarantinePath, bytes);

                                File.SetAttributes(driverPath, FileAttributes.Normal);
                                File.Delete(driverPath);

                                _logger.LogWarning("[TlsCertificateMonitor] BYOVD driver quarantined: {Driver} → {Quarantine}",
                                    driverPath, quarantinePath);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "[TlsCertificateMonitor] Failed to quarantine BYOVD driver: {Driver}", driverPath);
                        }

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "BYOVD: Vulnerable Driver Quarantined",
                            Evidence = $"Driver '{driverName}.sys' was signed by removed TrustedPublisher cert '{ExtractCN(certSubject)}'. Service registration removed, driver quarantined.",
                            Reasoning = "A driver signed by a cert that was just removed from TrustedPublisher has been neutralized. " +
                                        "BYOVD (Bring Your Own Vulnerable Driver) attacks plant a signed-but-vulnerable driver " +
                                        "to gain kernel access. Removing the cert + driver + service registration closes the attack path.",
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly, // Already handled
                            ProcessName = driverName,
                            ProcessId = 0
                        });
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[TlsCertificateMonitor] BYOVD driver scan error");
            }
        }

        private static System.Security.Cryptography.X509Certificates.X509Certificate2? GetFileCertificate(string filePath)
        {
            try
            {
                var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                    System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath));
                return cert;
            }
            catch { return null; }
        }

        // Known legitimate public root CA patterns — these are trusted global CAs
        private static readonly string[] KnownPublicRootCAs =
        {
            "DigiCert", "GlobalSign", "VeriSign", "Verizon", "Entrust", "GeoTrust",
            "GoDaddy", "Thawte", "Comodo", "Sectigo", "Starfield", "Let's Encrypt",
            "ISRG Root", "IdenTrust", "Baltimore", "CyberTrust", "QuoVadis",
            "Trustwave", "GTS Root", "GlobalTrust", "SwissSign", "Certum",
            "AffirmTrust", "Amazon Root", "Apple Root", "Microsoft Root", "Microsoft Corporation",
            "Chunghwa Telecom", "Hongkong Post", "Japan Registry", "WISeKey",
            "Buypass", "D-TRUST", "Telia", "Telekom", "Deutsche Telekom",
            "Staat der", "Government", "eID", "Network Solutions",
            "AddTrust", "USERTrust", "SECOM", "Unizeto", "TÜRKTRUST", "AC RAIZ",
            "Autoridad de Certificacion", "Certigna", "Certinomis", "ACCV",
            "ANF", "A-Trust", "BGC", "BNA", "CFCA", "China Internet", "CNNIC",
            "E-Tugra", "GDCA", "Hellenic", "HongKong Post", "Izenpe", "KISA",
            "KOICA", "Microsec", "NetLock", "OISTE", "PSC", "SK ID", "SSC",
            "StartCom", "TÜB", "TWCA", "VRK", "WoSign", "SecureSign", "Macao"
        };

        /// <summary>
        /// Analyzes a certificate and returns a confidence score + tier + reasoning.
        /// Key insight: ALL root CAs are self-signed by definition, so self-signed alone is NOT suspicious.
        /// We look for multiple corroborating attack indicators: short validity + no CRL + random name + expired.
        /// </summary>
        internal static CertAnalysisResult AnalyzeCert(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
        {
            // Start with LOW base confidence — require MULTIPLE strong indicators to reach action threshold
            double confidence = 0.40;
            var tier = DetectionTier.Tier2Indicator;
            var reasons = new List<string>();

            var subject = cert.Subject ?? string.Empty;
            var issuer = cert.Issuer ?? string.Empty;

            // 1. Self-signed check (Subject == Issuer)
            // NOTE: All root CAs are self-signed! This is NORMAL, not suspicious.
            bool isSelfSigned = subject.Equals(issuer, StringComparison.OrdinalIgnoreCase);
            // DO NOT add confidence for self-signed — this is expected for root certs

            // 2. Check for known legitimate public root CA — downgrade to Tier2 immediately
            bool isPublicRootCA = KnownPublicRootCAs.Any(ca =>
                subject.Contains(ca, StringComparison.OrdinalIgnoreCase));

            // 3. Known enterprise CA — downgrade to Tier2, reduce confidence
            bool isEnterpriseCa = KnownEnterpriseCAs.Any(ca =>
                subject.Contains(ca, StringComparison.OrdinalIgnoreCase));

            // 4. Known dev tool — downgrade to Tier2, reduce confidence
            bool isDevTool = KnownDevToolCAs.Any(dt =>
                subject.Contains(dt, StringComparison.OrdinalIgnoreCase));

            // If it's a known legitimate CA (public, enterprise, or dev tool), cap confidence and downgrade tier
            if (isPublicRootCA)
            {
                tier = DetectionTier.Tier2Indicator;
                confidence = Math.Min(confidence, 0.50);
                reasons.Add("Known public root CA");
            }
            else if (isEnterpriseCa)
            {
                tier = DetectionTier.Tier2Indicator;
                confidence = Math.Min(confidence, 0.65);
                reasons.Add("Known enterprise TLS inspection CA");
            }
            else if (isDevTool)
            {
                tier = DetectionTier.Tier2Indicator;
                confidence = Math.Min(confidence, 0.55);
                reasons.Add("Known developer/debugging tool CA");
            }

            // Only apply suspicion signals if NOT a known legitimate CA
            if (!isPublicRootCA && !isEnterpriseCa && !isDevTool)
            {
                // 5. Short validity period (< 1 year — real root CAs are 10-25 years)
                var validity = cert.NotAfter - cert.NotBefore;
                if (validity.TotalDays < 365)
                {
                    confidence += 0.15; // Increased from 0.10 — this is a strong signal
                    reasons.Add($"Short validity ({validity.TotalDays:F0} days, expected 3650+)");
                }

                // 6. Very short validity (< 90 days — highly suspicious for a root CA)
                if (validity.TotalDays < 90)
                {
                    confidence += 0.10; // Increased from 0.05
                    reasons.Add("Extremely short validity (<90 days)");
                }

                // 7. No CRL Distribution Points or Authority Info Access (OCSP) — suspicious for a real CA
                bool hasCrl = false;
                bool hasOcsp = false;
                foreach (var ext in cert.Extensions)
                {
                    // OID 2.5.29.31 = CRL Distribution Points
                    if (ext.Oid?.Value == "2.5.29.31") hasCrl = true;
                    // OID 1.3.6.1.5.5.7.1.1 = Authority Information Access (OCSP)
                    if (ext.Oid?.Value == "1.3.6.1.5.5.7.1.1") hasOcsp = true;
                }

                if (!hasCrl && !hasOcsp)
                {
                    confidence += 0.15; // Increased from 0.10 — missing revocation is serious
                    reasons.Add("No CRL/OCSP distribution points");
                }

                // 8. Generic/random Subject CN — real CAs have well-known names
                var cn = ExtractCN(subject);
                if (!string.IsNullOrEmpty(cn))
                {
                    // Check for very short generic names or hex-like random strings
                    if (cn.Length <= 4)
                    {
                        confidence += 0.10;
                        reasons.Add($"Very short Subject CN: '{cn}'");
                    }
                    else if (cn.Length > 6 && IsHexLike(cn))
                    {
                        confidence += 0.15;
                        reasons.Add($"Random/hex-like Subject CN: '{cn}'");
                    }
                }

                // 9. Already expired — suspicious to install an expired root cert
                if (cert.NotAfter < DateTime.UtcNow)
                {
                    confidence += 0.10;
                    reasons.Add($"Already expired (NotAfter={cert.NotAfter:u})");
                }

                // 10. Suspicious keywords in subject — some malware uses obvious names
                var lowerSubject = subject.ToLowerInvariant();
                if (lowerSubject.Contains("test") || lowerSubject.Contains("fake") ||
                    lowerSubject.Contains("evil") || lowerSubject.Contains("malware") ||
                    lowerSubject.Contains("mitm") || lowerSubject.Contains("proxy"))
                {
                    confidence += 0.10;
                    reasons.Add("Suspicious keywords in Subject");
                }

                // 11. Machine-name CN (hostname pattern) — MitM certs generated by RDP/attack tools
                // Real CAs never have bare hostnames as their CN
                if (!string.IsNullOrEmpty(cn) && IsHostnameLike(cn))
                {
                    confidence += 0.25;
                    reasons.Add($"CN looks like a machine hostname: '{cn}'");
                }

                // 12. Absurd validity (>100 years) — attack certs use 999-year validity
                // No legitimate CA issues certs for more than 25 years
                if (validity.TotalDays > 36500) // >100 years
                {
                    confidence += 0.20;
                    reasons.Add($"Absurd validity period ({validity.TotalDays / 365:F0} years)");
                }

                // 13. Server Authentication EKU in root store — root CAs should NOT have
                // server auth EKU. Only leaf/intermediate certs need it. A root cert with
                // server auth EKU is designed for direct TLS interception.
                bool hasServerAuthEku = false;
                foreach (var ext in cert.Extensions)
                {
                    if (ext.Oid?.Value == "2.5.29.37") // Enhanced Key Usage
                    {
                        var ekuText = ext.Format(false);
                        if (ekuText.Contains("Server Authentication") || ekuText.Contains("1.3.6.1.5.5.7.3.1"))
                        {
                            hasServerAuthEku = true;
                            break;
                        }
                    }
                }
                if (hasServerAuthEku)
                {
                    confidence += 0.20;
                    reasons.Add("Root cert has Server Authentication EKU (designed for TLS interception)");
                }
            }

            // Cap confidence at 0.99
            confidence = Math.Min(confidence, 0.99);

            // High confidence unknown certs: promote to Tier1 so response engine acts on them
            if (!isPublicRootCA && !isEnterpriseCa && !isDevTool && confidence >= 0.80)
            {
                tier = DetectionTier.Tier1Behavioral;
            }

            return new CertAnalysisResult
            {
                Confidence = confidence,
                Tier = tier,
                Reasons = reasons,
                IsSelfSigned = isSelfSigned,
                IsPublicRootCa = isPublicRootCA,
                IsEnterpriseCa = isEnterpriseCa,
                IsDevTool = isDevTool,
                HasRevocationInfo = true // Simplified for this refactor
            };
        }

        /// <summary>
        /// Extracts the CN value from a distinguished name string.
        /// </summary>
        private static string ExtractCN(string distinguishedName)
        {
            // Subject format: "CN=Name, O=Org, ..." — extract CN value
            var parts = distinguishedName.Split(',');
            foreach (var part in parts)
            {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                    return trimmed.Substring(3).Trim();
            }
            return string.Empty;
        }

        /// <summary>
        /// Checks if a string looks like a random hex/GUID string (common in attack certs).
        /// </summary>
        private static bool IsHexLike(string s)
        {
            int hexChars = 0;
            foreach (char c in s)
            {
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-')
                    hexChars++;
            }
            return hexChars > s.Length * 0.7;
        }

        /// <summary>
        /// Checks if a CN looks like a machine hostname rather than a CA organization name.
        /// Hostnames are typically: DESKTOP-XXXXXXX, WIN-XXXXXXX, LAPTOP-XXXXXXX, or short
        /// uppercase alphanumeric strings without spaces or organization-like structure.
        /// </summary>
        private static bool IsHostnameLike(string cn)
        {
            if (string.IsNullOrEmpty(cn)) return false;
            // Contains spaces/commas/dots = org name, not hostname
            if (cn.Contains(' ') || cn.Contains(',') || cn.Contains('.')) return false;
            // Contains CA-like words = not a hostname
            var lower = cn.ToLowerInvariant();
            if (lower.Contains("root") || lower.Contains("ca") || lower.Contains("cert") ||
                lower.Contains("authority") || lower.Contains("trust") || lower.Contains("sign"))
                return false;

            var upper = cn.ToUpperInvariant();
            // Common Windows auto-generated hostname prefixes
            if (upper.StartsWith("WIN-") || upper.StartsWith("DESKTOP-") ||
                upper.StartsWith("LAPTOP-") || upper.StartsWith("WORKSTATION-") ||
                upper.StartsWith("PC-") || upper.StartsWith("SERVER-"))
                return true;
            // Matches local machine name — definitely a self-signed MitM cert
            try
            {
                var machineName = Environment.MachineName;
                if (cn.Equals(machineName, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch { }
            // All-caps with dash, 8-15 chars = likely Windows auto-generated hostname
            if (cn.Length >= 8 && cn.Length <= 15 && cn.Contains('-') &&
                cn.All(c => char.IsLetterOrDigit(c) || c == '-'))
                return true;
            return false;
        }

        /// <summary>
        /// Attempts to trace which process added a cert by querying the Security Event Log
        /// for recent registry write events to the cert store path.
        /// Returns the adder process info if found.
        /// </summary>
        private AdderProcessInfo? TraceAdderProcess(string thumbprint)
        {
            try
            {
                // Security Event ID 4657: A registry value was modified
                // The cert store is at: HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\{thumbprint}
                var log = new System.Diagnostics.EventLog("Security");
                var cutoff = DateTime.UtcNow.AddMinutes(-5);

                // Iterate backwards (most recent first) for efficiency
                for (int i = log.Entries.Count - 1; i >= 0 && i >= log.Entries.Count - 500; i--)
                {
                    try
                    {
                        var entry = log.Entries[i];
                        if (entry.TimeGenerated.ToUniversalTime() < cutoff) break;

                        // Event ID 4657 = Registry value modified (WRITE only)
                        // Do NOT use 4663 (Object access) - it fires on READS too, causing misattribution
                        if (entry.InstanceId != 4657) continue;

                        var message = entry.Message ?? string.Empty;

                        // Check if this event relates to the cert store
                        if (!message.Contains("SystemCertificates", StringComparison.OrdinalIgnoreCase) &&
                            !message.Contains("ROOT\\Certificates", StringComparison.OrdinalIgnoreCase))
                            continue;

                        // ONLY match events that contain our specific thumbprint
                        // Do NOT fall back to generic "ROOT\Certificates" matching - that causes
                        // misattribution when legitimate processes (browsers) touch the cert store
                        if (!string.IsNullOrEmpty(thumbprint) &&
                            !message.Contains(thumbprint, StringComparison.OrdinalIgnoreCase))
                            continue;

                        // Extract process info from the event
                        var processId = ExtractFieldFromEventMessage(message, "Process ID");
                        var processName = ExtractFieldFromEventMessage(message, "Process Name");

                        if (int.TryParse(processId?.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out int pid) && pid > 4)
                        {
                            return new AdderProcessInfo
                            {
                                ProcessId = pid,
                                ProcessName = processName ?? "Unknown",
                                EventTimestamp = entry.TimeGenerated.ToUniversalTime()
                            };
                        }
                    }
                    catch { continue; }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[TlsCertificateMonitor] Failed to trace cert adder process");
            }

            return null;
        }

        /// <summary>
        /// Extracts a field value from a Windows Event Log message by field label.
        /// Event messages have format "Label:\t\tValue" or "Label:  Value".
        /// </summary>
        private static string? ExtractFieldFromEventMessage(string message, string fieldName)
        {
            var idx = message.IndexOf(fieldName + ":", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return null;

            var start = idx + fieldName.Length + 1;
            if (start >= message.Length) return null;

            // Skip whitespace/tabs
            while (start < message.Length && (message[start] == ' ' || message[start] == '\t'))
                start++;

            var end = start;
            while (end < message.Length && message[end] != '\r' && message[end] != '\n')
                end++;

            return message.Substring(start, end - start).Trim();
        }

        /// <summary>
        /// Emits a detection event for a suspicious certificate.
        /// </summary>
        private async Task EmitCertDetectionAsync(
            System.Security.Cryptography.X509Certificates.X509Certificate2 cert,
            CertAnalysisResult analysis,
            AdderProcessInfo? adderInfo,
            bool isStartupScan,
            ResponseAction? overrideResponse = null)
        {
            var cn = ExtractCN(cert.Subject);
            var scanPhase = isStartupScan ? "Startup scan" : "Runtime detection";
            var reasonsList = string.Join("; ", analysis.Reasons);

            var evidence = $"{scanPhase}: Root cert Subject='{cert.Subject}', " +
                           $"Thumbprint={cert.Thumbprint}, " +
                           $"Validity={cert.NotBefore:yyyy-MM-dd}→{cert.NotAfter:yyyy-MM-dd}, " +
                           $"Signals=[{reasonsList}]";

            if (adderInfo != null)
            {
                evidence += $", Adder='{adderInfo.ProcessName}' PID={adderInfo.ProcessId} at {adderInfo.EventTimestamp:u}";
            }

            var reasoning = $"A new root certificate '{cn}' was added to the machine trust store. ";
            reasoning += "If unauthorized, this could enable TLS interception of HTTPS traffic. ";
            reasoning += $"Assessment signals: {reasonsList}.";

            var metadata = new Dictionary<string, string>
            {
                { "CertThumbprint", cert.Thumbprint },
                { "CertSubject", cert.Subject },
                { "CertIssuer", cert.Issuer },
                { "CertNotBefore", cert.NotBefore.ToString("o") },
                { "CertNotAfter", cert.NotAfter.ToString("o") },
                { "IsSelfSigned", analysis.IsSelfSigned.ToString() },
                { "IsEnterpriseCa", analysis.IsEnterpriseCa.ToString() },
                { "IsDevTool", analysis.IsDevTool.ToString() },
                { "HasRevocationInfo", analysis.HasRevocationInfo.ToString() },
                { "ScanPhase", isStartupScan ? "Startup" : "Runtime" }
            };

            if (adderInfo != null)
            {
                metadata["AdderProcessId"] = adderInfo.ProcessId.ToString();
                metadata["AdderProcessName"] = adderInfo.ProcessName;
            }

            var authorizedResponse = overrideResponse ?? ResponseAction.LogOnly;

            // Startup scans never auto-remove (user may have installed them intentionally)
            if (isStartupScan) authorizedResponse = ResponseAction.LogOnly;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "TLS: Suspicious Root Certificate Detected",
                Evidence = evidence,
                Reasoning = reasoning,
                Confidence = analysis.Confidence,
                Tier = analysis.Tier,
                AuthorizedResponse = authorizedResponse,
                ProcessName = adderInfo?.ProcessName ?? "SYSTEM",
                ProcessId = adderInfo?.ProcessId ?? 0,
                Metadata = metadata
            });
        }


        /// <summary>Result of analyzing a single certificate.</summary>
        internal class CertAnalysisResult
        {
            public double Confidence { get; set; }
            public DetectionTier Tier { get; set; }
            public List<string> Reasons { get; set; } = new();
            public bool IsSelfSigned { get; set; }
            public bool IsPublicRootCa { get; set; }
            public bool IsEnterpriseCa { get; set; }
            public bool IsDevTool { get; set; }
            public bool HasRevocationInfo { get; set; }
        }

        /// <summary>Info about the process that added a cert to the store.</summary>
        private class AdderProcessInfo
        {
            public int ProcessId { get; set; }
            public string ProcessName { get; set; } = string.Empty;
            public DateTime EventTimestamp { get; set; }
        }
    }

    // ──────────────────────────────────────────────
    // UAC Bypass Surface Monitor — detects autoelevate binary abuse
    // ──────────────────────────────────────────────
    public sealed class UacBypassSurfaceMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<UacBypassSurfaceMonitor> _logger;

        // Auto-elevate binaries commonly abused for UAC bypass
        private static readonly string[] AutoElevateBinaries = {
            "fodhelper.exe", "computerdefaults.exe", "sdclt.exe", "eventvwr.exe", "slui.exe"
        };

        public UacBypassSurfaceMonitor(DetectionEngine de, ILogger<UacBypassSurfaceMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[UacBypassSurfaceMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct);
                    foreach (var binName in AutoElevateBinaries)
                    {
                        var procs = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(binName));
                        foreach (var proc in procs)
                        {
                            try
                            {
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "UAC Bypass: Auto-Elevate Binary Launched",
                                    Evidence = $"Auto-elevate binary '{proc.ProcessName}' running (PID {proc.Id})",
                                    Reasoning = "A Windows auto-elevate binary known to be abused for UAC bypass was detected running. Correlate with registry changes.",
                                    Confidence = 0.60, Tier = DetectionTier.Tier2Indicator,
                                    ProcessName = proc.ProcessName, ProcessId = proc.Id
                                });
                            }
                            catch { }
                            finally { proc.Dispose(); }
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[UacBypassSurfaceMonitor] Error"); }
            }
        }
    }

    // ──────────────────────────────────────────────
    // WiFi Security Monitor — detects open/WEP networks
    // ──────────────────────────────────────────────
    public sealed class WifiSecurityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WifiSecurityMonitor> _logger;
        private readonly HashSet<string> _alertedProfiles = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<DateTimeOffset> _disconnectHistory = new();
        private string? _baselineBssid;
        private string? _baselineSsid;

        private const int DeauthThreshold = 4;         // 4+ disconnects in window = deauth flood
        private static readonly TimeSpan DeauthWindow = TimeSpan.FromMinutes(2);

        public WifiSecurityMonitor(DetectionEngine de, ILogger<WifiSecurityMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WifiSecurityMonitor] Started");

            // Capture initial SSID/BSSID baseline
            var initial = GetCurrentWifiState();
            _baselineSsid = initial.ssid;
            _baselineBssid = initial.bssid;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct); // 15s scan interval

                    var current = GetCurrentWifiState();

                    // === Check 1: Deauth flood detection ===
                    // If we were connected and now disconnected, record it
                    if (_baselineSsid != null && current.ssid == null)
                    {
                        _disconnectHistory.Add(DateTimeOffset.UtcNow);

                        // Prune old disconnects
                        var cutoff = DateTimeOffset.UtcNow - DeauthWindow;
                        _disconnectHistory.RemoveAll(t => t < cutoff);

                        if (_disconnectHistory.Count >= DeauthThreshold)
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "WiFi Security: Deauthentication Flood Detected",
                                Evidence = $"Wi-Fi disconnected {_disconnectHistory.Count} times in {DeauthWindow.TotalMinutes} minutes (SSID: '{_baselineSsid}')",
                                Reasoning = "Repeated Wi-Fi disconnections in rapid succession indicate a deauthentication flood attack. " +
                                            "Attackers send forged deauth frames to force clients off the network, often as a precursor " +
                                            "to evil twin AP deployment or WPA handshake capture.",
                                Confidence = 0.85, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["SSID"] = _baselineSsid ?? "",
                                    ["DisconnectCount"] = _disconnectHistory.Count.ToString()
                                }
                            });
                            _disconnectHistory.Clear(); // Reset after alert
                            _ = ToggleWifiAdapterAsync(ct);
                        }
                    }

                    // === Check 2: BSSID change on same SSID (evil twin) ===
                    if (current.ssid != null && current.bssid != null &&
                        current.ssid == _baselineSsid && _baselineBssid != null &&
                        current.bssid != _baselineBssid)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "WiFi Security: BSSID Changed (Possible Evil Twin)",
                            Evidence = $"BSSID changed from {_baselineBssid} to {current.bssid} while SSID remains '{current.ssid}'",
                            Reasoning = "The access point's hardware address (BSSID) changed while connected to the same SSID. " +
                                        "This can indicate an evil twin attack where the attacker creates a fake AP with the same name, " +
                                        "or a legitimate roaming event between APs. Correlate with deauth events.",
                            Confidence = 0.60, Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0,
                            Metadata = new Dictionary<string, string>
                            {
                                ["SSID"] = current.ssid,
                                ["OldBSSID"] = _baselineBssid,
                                ["NewBSSID"] = current.bssid
                            }
                        });
                        _baselineBssid = current.bssid;
                    }

                    // === Check 3: Encryption downgrade ===
                    if (current.ssid != null && current.auth != null)
                    {
                        bool isInsecure = current.auth.Contains("Open", StringComparison.OrdinalIgnoreCase) ||
                                          current.auth.Contains("WEP", StringComparison.OrdinalIgnoreCase);
                        if (isInsecure && !_alertedProfiles.Contains(current.ssid))
                        {
                            _alertedProfiles.Add(current.ssid);
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "WiFi Security: Insecure/Open Network Connected",
                                Evidence = $"Connected to '{current.ssid}' with authentication: {current.auth}",
                                Reasoning = "System is connected to a Wi-Fi network with weak or no encryption. " +
                                            "Open and WEP networks allow trivial traffic interception. If this was previously " +
                                            "a WPA2 network, it may indicate an encryption downgrade attack.",
                                Confidence = 0.55, Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                        }
                    }

                    // === Check 4: Public network profile (registry-based, original check) ===
                    CheckPublicNetworkProfiles();

                    // Update baseline
                    if (current.ssid != null)
                    {
                        _baselineSsid = current.ssid;
                        if (current.bssid != null) _baselineBssid = current.bssid;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WifiSecurityMonitor] Error"); }
            }
        }

        private void CheckPublicNetworkProfiles()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles");
                if (key == null) return;

                foreach (var profileName in key.GetSubKeyNames())
                {
                    try
                    {
                        using var profile = key.OpenSubKey(profileName);
                        if (profile == null) continue;

                        var name = profile.GetValue("ProfileName")?.ToString();
                        var category = profile.GetValue("Category");

                        if (category is int cat && cat == 0 && !string.IsNullOrEmpty(name))
                        {
                            if (_alertedProfiles.Contains(name)) continue;
                            _alertedProfiles.Add(name);

                            _ = _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "WiFi Security: Public/Unsecured Network Connected",
                                Evidence = $"Connected to public network profile: '{name}'",
                                Reasoning = "System is connected to a network categorized as Public, which may lack encryption and be vulnerable to traffic interception.",
                                Confidence = 0.45, Tier = DetectionTier.Tier2Indicator,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        /// <summary>
        /// Gets current Wi-Fi state from the WLAN interface registry.
        /// Uses the Windows WLAN AutoConfig service state stored in registry.
        /// </summary>
        private static (string? ssid, string? bssid, string? auth) GetCurrentWifiState()
        {
            try
            {
                // Read current wireless connection from the Wlansvc Interfaces registry
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\Wlansvc\Parameters\Interfaces");
                if (key == null) return (null, null, null);

                foreach (var ifGuid in key.GetSubKeyNames())
                {
                    using var ifKey = key.OpenSubKey(ifGuid);
                    if (ifKey == null) continue;

                    // CurrentConnection subkey has SSID and BSSID
                    using var connKey = ifKey.OpenSubKey("CurrentConnection");
                    if (connKey == null) continue;

                    var ssidBytes = connKey.GetValue("SSID") as byte[];
                    var bssidBytes = connKey.GetValue("BSSID") as byte[];
                    var authMode = connKey.GetValue("AuthMode")?.ToString();

                    string? ssid = ssidBytes != null
                        ? System.Text.Encoding.UTF8.GetString(ssidBytes).TrimEnd('\0')
                        : null;
                    string? bssid = bssidBytes != null && bssidBytes.Length >= 6
                        ? BitConverter.ToString(bssidBytes, 0, 6)
                        : null;

                    if (!string.IsNullOrEmpty(ssid))
                        return (ssid, bssid, authMode);
                }
            }
            catch { }

            // Fallback: check NetworkList for connected interface info
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 &&
                        ni.OperationalStatus == OperationalStatus.Up)
                    {
                        return (ni.Name, null, null); // At least we know we're connected to Wi-Fi
                    }
                }
            }
            catch { }

            return (null, null, null);
        }

        private async Task ToggleWifiAdapterAsync(CancellationToken ct)
        {
            try
            {
                var wifiInterface = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(ni => ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211);
                
                if (wifiInterface == null) return;
                
                int ifIndex = wifiInterface.GetIPProperties().GetIPv4Properties().Index;
                _logger.LogInformation("[WifiSecurityMonitor] Deauth flood recovery: Toggling Wi-Fi adapter '{Name}' (Index {Index})", wifiInterface.Name, ifIndex);

                // Use WMI to disable and enable the adapter
                var scope = new ManagementScope(@"root\StandardCimv2");
                scope.Connect();
                var query = new ObjectQuery($"SELECT * FROM MSFT_NetAdapter WHERE InterfaceIndex = {ifIndex}");
                using var searcher = new ManagementObjectSearcher(scope, query);
                foreach (ManagementObject obj in searcher.Get())
                {
                    _logger.LogInformation("[WifiSecurityMonitor] Disabling adapter...");
                    obj.InvokeMethod("Disable", null);
                    await Task.Delay(2000, ct);
                    _logger.LogInformation("[WifiSecurityMonitor] Re-enabling adapter...");
                    obj.InvokeMethod("Enable", null);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[WifiSecurityMonitor] Failed to toggle Wi-Fi adapter");
            }
        }
    }

    // ──────────────────────────────────────────────
    // Windows Update Integrity Monitor — checks WU tampering
    // ──────────────────────────────────────────────
    public sealed class WindowsUpdateIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WindowsUpdateIntegrityMonitor> _logger;

        public WindowsUpdateIntegrityMonitor(DetectionEngine de, ILogger<WindowsUpdateIntegrityMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WindowsUpdateIntegrityMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(600000, ct);
                    // Check if Windows Update service is disabled
                    try
                    {
                        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\wuauserv");
                        var startVal = key?.GetValue("Start");
                        if (startVal is int start && start == 4) // Disabled
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Tampering: Windows Update Service Disabled",
                                Evidence = "wuauserv service Start value is 4 (Disabled)",
                                Reasoning = "The Windows Update service was disabled, which prevents security patches and is a common malware persistence technique.",
                                Confidence = 0.75, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                        }
                    }
                    catch { }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WindowsUpdateIntegrityMonitor] Error"); }
            }
        }
    }

    // ──────────────────────────────────────────────
    // WMI Persistence Monitor — detects WMI event subscriptions
    // ──────────────────────────────────────────────
    public sealed class WmiPersistenceMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WmiPersistenceMonitor> _logger;
        private int _baselineSubscriptionCount;

        public WmiPersistenceMonitor(DetectionEngine de, ILogger<WmiPersistenceMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WmiPersistenceMonitor] Started");
            _baselineSubscriptionCount = CountWmiSubscriptions();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    var current = CountWmiSubscriptions();
                    if (current > _baselineSubscriptionCount)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Persistence: New WMI Event Subscription",
                            Evidence = $"WMI event subscriptions increased from {_baselineSubscriptionCount} to {current}",
                            Reasoning = "New WMI event subscriptions were created, which is a common persistence and living-off-the-land technique.",
                            Confidence = 0.75, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                        _baselineSubscriptionCount = current;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WmiPersistenceMonitor] Error"); }
            }
        }

        private static int CountWmiSubscriptions()
        {
            int count = 0;
            try
            {
                using var searcher = new ManagementObjectSearcher("root\\subscription",
                    "SELECT * FROM __EventConsumer");
                foreach (var _ in searcher.Get()) count++;
            }
            catch { }
            return count;
        }
    }

    // ──────────────────────────────────────────────
    // Work Folders Exfil Monitor — detects mass file sync
    // ──────────────────────────────────────────────
    public sealed class WorkFoldersExfilMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WorkFoldersExfilMonitor> _logger;
        private long _baselineFileCount;

        public WorkFoldersExfilMonitor(DetectionEngine de, ILogger<WorkFoldersExfilMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WorkFoldersExfilMonitor] Started");
            var workFolders = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Work Folders");

            // Baseline file count
            if (Directory.Exists(workFolders))
            {
                try { _baselineFileCount = Directory.EnumerateFiles(workFolders, "*", SearchOption.AllDirectories).LongCount(); }
                catch { _baselineFileCount = 0; }
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    if (!Directory.Exists(workFolders)) continue;

                    long currentCount = 0;
                    try { currentCount = Directory.EnumerateFiles(workFolders, "*", SearchOption.AllDirectories).LongCount(); }
                    catch { continue; }

                    // If file count suddenly drops by 50+ files, possible bulk exfiltration/deletion
                    if (_baselineFileCount > 50 && currentCount < _baselineFileCount - 50)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Data Exfiltration: Work Folders Mass File Removal",
                            Evidence = $"Work Folders file count dropped from {_baselineFileCount} to {currentCount} ({_baselineFileCount - currentCount} files removed)",
                            Reasoning = "A large number of files were removed from the Work Folders sync directory in a short period, which may indicate data exfiltration via sync or ransomware activity.",
                            Confidence = 0.70, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                    }
                    // If file count increases dramatically (100+ new files added quickly) — staging for sync exfil
                    else if (currentCount > _baselineFileCount + 100)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Data Exfiltration: Work Folders Mass File Addition",
                            Evidence = $"Work Folders file count increased from {_baselineFileCount} to {currentCount} ({currentCount - _baselineFileCount} files added)",
                            Reasoning = "A large number of files were rapidly added to the Work Folders sync directory, which may indicate data staging for cloud exfiltration.",
                            Confidence = 0.60, Tier = DetectionTier.Tier2Indicator,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                    }

                    _baselineFileCount = currentCount;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WorkFoldersExfilMonitor] Error"); }
            }
        }
    }

    // ──────────────────────────────────────────────
    // ADS Data Staging Monitor — detects NTFS Alternate Data Streams abuse
    // ──────────────────────────────────────────────
    public sealed class AdsDataStagingMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<AdsDataStagingMonitor> _logger;
        private readonly HashSet<string> _alertedFiles = new(StringComparer.OrdinalIgnoreCase);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr FindFirstStreamW(string lpFileName, int infoLevel, out WIN32_FIND_STREAM_DATA lpFindStreamData, int dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindNextStreamW(IntPtr hFindStream, out WIN32_FIND_STREAM_DATA lpFindStreamData);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindClose(IntPtr hFindFile);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WIN32_FIND_STREAM_DATA
        {
            public long StreamSize;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
            public string cStreamName;
        }

        private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

        public AdsDataStagingMonitor(DetectionEngine de, ILogger<AdsDataStagingMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[AdsDataStagingMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    // Scan temp + downloads for files with suspicious ADS streams
                    var tempDir = Path.GetTempPath();
                    var downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

                    foreach (var dir in new[] { tempDir, downloadsDir })
                    {
                        if (!Directory.Exists(dir)) continue;
                        try
                        {
                            foreach (var file in Directory.EnumerateFiles(dir, "*.*", SearchOption.TopDirectoryOnly))
                            {
                                if (_alertedFiles.Contains(file)) continue;
                                try
                                {
                                    var streams = GetAlternateDataStreams(file);
                                    // Zone.Identifier is normal (Mark of the Web). Others are suspicious.
                                    foreach (var stream in streams)
                                    {
                                        if (stream.Name.Contains("Zone.Identifier", StringComparison.OrdinalIgnoreCase)) continue;
                                        if (stream.Name == "::$DATA") continue; // Primary data stream

                                        if (stream.Size > 1024) // Only flag ADS > 1KB (payload-sized)
                                        {
                                            _alertedFiles.Add(file);
                                            await _detectionEngine.EmitAsync(new DetectionEvent
                                            {
                                                RuleName = "ADS Staging: Hidden Data in Alternate Data Stream",
                                                Evidence = $"File '{file}' has a suspicious ADS '{stream.Name}' ({stream.Size} bytes)",
                                                Reasoning = "A file in a user-writable directory has a non-standard Alternate Data Stream larger than 1KB. ADS is used to hide payloads, exfiltration data, or persistence mechanisms from normal file listings.",
                                                Confidence = 0.65, Tier = DetectionTier.Tier2Indicator,
                                                ProcessName = "SYSTEM", ProcessId = 0
                                            });
                                            break;
                                        }
                                    }
                                }
                                catch { }
                            }
                        }
                        catch { }
                    }

                    // Limit alertedFiles growth
                    if (_alertedFiles.Count > 500) _alertedFiles.Clear();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[AdsDataStagingMonitor] Error"); }
            }
        }

        private static List<(string Name, long Size)> GetAlternateDataStreams(string filePath)
        {
            var streams = new List<(string, long)>();
            var handle = FindFirstStreamW(filePath, 0, out var data, 0);
            if (handle == INVALID_HANDLE_VALUE) return streams;

            try
            {
                do
                {
                    streams.Add((data.cStreamName, data.StreamSize));
                } while (FindNextStreamW(handle, out data));
            }
            finally
            {
                FindClose(handle);
            }
            return streams;
        }
    }

    // ──────────────────────────────────────────────
    // Null Session Guard — actively blocks blank-password network logon exposure
    // by enforcing security policy that restricts network access without credentials.
    // Also hardens against FCM push-triggered tab opens following MitM cert attacks.
    // ──────────────────────────────────────────────
    public sealed class NullSessionGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<NullSessionGuard> _logger;
        private bool _policyApplied;
        private bool _fcmBlocked;

        private const string LimitBlankPasswordUseKey = @"SYSTEM\CurrentControlSet\Control\Lsa";
        private const string LimitBlankPasswordUseValue = "LimitBlankPasswordUse";
        private const string RestrictNullSessAccessValue = "RestrictAnonymous";
        private const string EveryoneIncludesAnonValue = "EveryoneIncludesAnonymous";
        private const string RestrictRemoteSamKey = @"SYSTEM\CurrentControlSet\Control\Lsa";

        // Google FCM/GCM IPs use port 5228. Blocking this port via Windows Firewall
        // prevents push-triggered tab opens ("Send Tab to Self") that attackers can
        // abuse after stealing Chrome session tokens via MitM cert interception.
        private const string FcmFirewallRuleName = "Sentinel-FCM-Push-Block";
        private const int FcmPort = 5228;

        public NullSessionGuard(DetectionEngine de, ILogger<NullSessionGuard> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[NullSessionGuard] Started — enforcing blank-password network restrictions and FCM push protection");

            // Initial delay to let other monitors start
            await Task.Delay(15000, ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await EnforceNullSessionProtection(ct);
                    await EnforceFcmPushBlock(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[NullSessionGuard] Error"); }

                // Re-check every 60s (policy may be reverted by attacker/GPO)
                await Task.Delay(60000, ct);
            }
        }

        /// <summary>
        /// Enforces Windows security policies that prevent blank-password accounts from
        /// being accessed over the network. This is the ACTIVE protection:
        /// 
        /// 1. LimitBlankPasswordUse = 1 — blocks network logon for accounts with empty passwords
        ///    (prevents SMB null-session, RDP without password, WinRM without password)
        /// 2. RestrictAnonymous = 1 — prevents anonymous enumeration of SAM accounts and shares
        /// 3. EveryoneIncludesAnonymous = 0 — anonymous tokens excluded from Everyone group
        ///
        /// If an attacker reverts these, the monitor detects and re-applies within 60s.
        /// </summary>
        private async Task EnforceNullSessionProtection(CancellationToken ct)
        {
            bool anyChanged = false;

            try
            {
                using var lsaKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(LimitBlankPasswordUseKey, true);
                if (lsaKey != null)
                {
                    // Enforce LimitBlankPasswordUse = 1
                    var current = lsaKey.GetValue(LimitBlankPasswordUseValue);
                    if (current == null || (int)current != 1)
                    {
                        lsaKey.SetValue(LimitBlankPasswordUseValue, 1, Microsoft.Win32.RegistryValueKind.DWord);
                        anyChanged = true;
                        _logger.LogWarning("[NullSessionGuard] Enforced LimitBlankPasswordUse=1 (was {Old})", current);
                    }

                    // Enforce RestrictAnonymous = 1
                    var restrictAnon = lsaKey.GetValue(RestrictNullSessAccessValue);
                    if (restrictAnon == null || (int)restrictAnon < 1)
                    {
                        lsaKey.SetValue(RestrictNullSessAccessValue, 1, Microsoft.Win32.RegistryValueKind.DWord);
                        anyChanged = true;
                        _logger.LogWarning("[NullSessionGuard] Enforced RestrictAnonymous=1 (was {Old})", restrictAnon);
                    }

                    // Enforce EveryoneIncludesAnonymous = 0
                    var everyoneAnon = lsaKey.GetValue(EveryoneIncludesAnonValue);
                    if (everyoneAnon != null && (int)everyoneAnon != 0)
                    {
                        lsaKey.SetValue(EveryoneIncludesAnonValue, 0, Microsoft.Win32.RegistryValueKind.DWord);
                        anyChanged = true;
                        _logger.LogWarning("[NullSessionGuard] Enforced EveryoneIncludesAnonymous=0 (was {Old})", everyoneAnon);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NullSessionGuard] Failed to enforce LSA policy");
            }

            if (anyChanged && !_policyApplied)
            {
                _policyApplied = true;
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Hardening: Null Session Network Access Blocked",
                    Evidence = "Enforced LimitBlankPasswordUse=1, RestrictAnonymous=1, EveryoneIncludesAnonymous=0",
                    Reasoning = "Active protection applied: blank-password accounts are now blocked from network logon " +
                                "(SMB, RDP, WinRM). Anonymous enumeration of user accounts and shares is restricted. " +
                                "This prevents attackers from exploiting the blank local password via null-session authentication, " +
                                "pass-the-hash with the well-known empty NTLM hash (31D6CFE0D16AE931B73C59D7E0C089C0), " +
                                "or anonymous share/user enumeration for lateral movement.",
                    Confidence = 0.99,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0,
                    SignalType = SignalType.SecurityEvasion,
                    Metadata = new Dictionary<string, string>
                    {
                        { "Action", "PolicyEnforced" },
                        { "LimitBlankPasswordUse", "1" },
                        { "RestrictAnonymous", "1" }
                    }
                });
            }
            else if (anyChanged)
            {
                // Policy was reverted by something — attacker or GPO. Re-applied.
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Anti-Tamper: Null Session Policy Reverted and Re-Applied",
                    Evidence = "Null-session restriction policy was found reverted and has been re-enforced",
                    Reasoning = "The LimitBlankPasswordUse or RestrictAnonymous policy was found in a weakened state. " +
                                "This could indicate an attacker disabling the protection to enable null-session access, " +
                                "or a Group Policy override. Sentinel has re-applied the hardened settings.",
                    Confidence = 0.85,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0,
                    SignalType = SignalType.SecurityEvasion
                });
            }
        }

        /// <summary>
        /// Blocks outbound traffic to Google FCM port 5228 via Windows Firewall.
        ///
        /// Attack chain:
        ///   1. Attacker plants MitM root cert → intercepts HTTPS → steals Chrome sync tokens
        ///   2. With stolen tokens, attacker uses "Send Tab to Self" via FCM push
        ///   3. Chrome receives FCM push on port 5228 → opens attacker-controlled URL
        ///   4. URL exploits browser or phishes credentials
        ///
        /// By blocking port 5228, we sever the FCM push channel completely.
        /// Chrome still functions normally (browsing, sync of bookmarks/passwords works
        /// via HTTPS on 443). Only real-time push notifications are lost.
        ///
        /// This is acceptable because:
        ///   - No AV/EDR is installed (Defender removed on debloated Windows)
        ///   - MitM certs WERE detected and removed, but token theft may have already occurred
        ///   - The user's Google account is "well secured" but tokens can outlive password changes
        ///   - Better to lose push notifications than allow remote tab injection
        /// </summary>
        private async Task EnforceFcmPushBlock(CancellationToken ct)
        {
            if (_fcmBlocked) return;

            try
            {
                // Check if the firewall rule already exists
                bool ruleExists = false;
                try
                {
                    var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                    if (policyType == null) throw new InvalidOperationException("COM type not found");
                    dynamic? policy = Activator.CreateInstance(policyType);
                    if (policy == null) throw new InvalidOperationException("COM instance failed");

                    foreach (dynamic rule in policy.Rules)
                    {
                        if ((string)rule.Name == FcmFirewallRuleName)
                        {
                            ruleExists = true;
                            break;
                        }
                    }

                    if (!ruleExists)
                    {
                        var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                        if (ruleType == null) throw new InvalidOperationException("COM rule type not found");
                        dynamic? newRule = Activator.CreateInstance(ruleType);
                        if (newRule == null) throw new InvalidOperationException("COM rule instance failed");

                        newRule.Name = FcmFirewallRuleName;
                        newRule.Description = "Sentinel: Blocks Google FCM push notifications (port 5228) " +
                                              "to prevent remote tab injection via stolen sync tokens";
                        newRule.Protocol = 6; // TCP
                        newRule.RemotePorts = FcmPort.ToString();
                        newRule.Direction = 2; // Outbound
                        newRule.Action = 0; // Block
                        newRule.Enabled = true;
                        newRule.Profiles = 0x7FFFFFFF; // All profiles

                        policy.Rules.Add(newRule);

                        _logger.LogWarning("[NullSessionGuard] BLOCKED outbound port {Port} (Google FCM push) — prevents remote tab injection", FcmPort);

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Hardening: FCM Push Channel Blocked",
                            Evidence = $"Firewall rule '{FcmFirewallRuleName}' created blocking outbound TCP port {FcmPort}",
                            Reasoning = "Blocked Google Firebase Cloud Messaging (FCM) port 5228 outbound. " +
                                        "Attack chain: MitM cert → HTTPS intercept → Chrome token theft → FCM 'Send Tab to Self' → " +
                                        "arbitrary URL opens on this machine. Blocking FCM severs this attack vector permanently. " +
                                        "Chrome browsing, bookmark sync, and password sync continue to work normally via HTTPS (port 443). " +
                                        "Only real-time push notifications are disabled.",
                            Confidence = 0.99,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.NetworkC2,
                            Metadata = new Dictionary<string, string>
                            {
                                { "Action", "FirewallBlock" },
                                { "Port", FcmPort.ToString() },
                                { "RuleName", FcmFirewallRuleName },
                                { "Impact", "Push notifications disabled; browsing unaffected" }
                            }
                        });
                    }
                    else
                    {
                        _logger.LogInformation("[NullSessionGuard] FCM block rule already exists");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[NullSessionGuard] Failed to create FCM block via COM, falling back to netsh");

                    // Fallback: use netsh directly
                    var psi = new ProcessStartInfo("netsh",
                        $"advfirewall firewall add rule name=\"{FcmFirewallRuleName}\" " +
                        $"dir=out action=block protocol=tcp remoteport={FcmPort}")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        WindowStyle = ProcessWindowStyle.Hidden
                    };
                    using var proc = Process.Start(psi);
                    proc?.WaitForExit(5000);

                    if (proc?.ExitCode == 0)
                    {
                        _logger.LogWarning("[NullSessionGuard] BLOCKED FCM port {Port} via netsh fallback", FcmPort);
                    }
                }

                _fcmBlocked = true;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NullSessionGuard] FCM block enforcement failed");
            }
        }
    }

    // ──────────────────────────────────────────────
    // Phantom Device Monitor — detects & blocks unauthorized network devices
    // ──────────────────────────────────────────────
    public sealed class PhantomDeviceMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<PhantomDeviceMonitor> _logger;
        private readonly ConcurrentDictionary<string, NetworkDevice> _knownDevices = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, DateTime> _blockedIps = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _trustedIps = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Returns true if the given IP has been identified and blocked as a phantom/rogue device.
        /// Used by GhostProcessMonitor to escalate ghost processes connecting to blocked devices
        /// from NetworkIsolate to KillProcessTree.
        /// </summary>
        public bool IsBlockedDevice(string ip) => _blockedIps.ContainsKey(ip);

        /// <summary>
        /// Returns true if the given IP belongs to a device that was detected after startup
        /// (regardless of whether it was blocked). Used for correlation.
        /// </summary>
        public bool IsPhantomDevice(string ip) => _knownDevices.Values.Any(d => d.Ip == ip) && !_trustedIps.Contains(ip);

        private static readonly int[] SuspiciousPorts = { 8008, 8009, 8443, 5555, 5353, 9222, 2323, 4443 };

        private static readonly Dictionary<string, string> OuiLookup = new(StringComparer.OrdinalIgnoreCase)
        {
            { "B0-B3-69", "Google" }, { "F4-F5-D8", "Google" }, { "54-60-09", "Google" },
            { "A4-77-33", "Google" }, { "30-FD-38", "Google" }, { "48-D6-D5", "Google" },
            { "E8-DE-27", "TP-Link" }, { "50-C7-BF", "TP-Link" },
            { "DC-A6-32", "Raspberry Pi" }, { "B8-27-EB", "Raspberry Pi" }, { "E4-5F-01", "Raspberry Pi" },
            { "00-0C-29", "VMware" }, { "00-50-56", "VMware" },
            { "08-00-27", "VirtualBox" },
        };

        public PhantomDeviceMonitor(
            DetectionEngine de, SentinelConfig config, JsonlEventLogger logger,
            ILogger<PhantomDeviceMonitor> l)
        {
            _detectionEngine = de; _config = config; _eventLogger = logger; _logger = l;
        }

        [DllImport("iphlpapi.dll")]
        private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[PhantomDeviceMonitor] Started");

            // Always trust the default gateway and local machine IPs — never alert on them
            foreach (var gw in GetDefaultGatewayIps())
                _trustedIps.Add(gw);
            foreach (var localIp in GetLocalIps())
                _trustedIps.Add(localIp);

            var initial = GetArpTable();
            foreach (var dev in initial)
                _knownDevices[dev.Mac] = dev;
            _logger.LogInformation("[PhantomDeviceMonitor] Baseline: {Count} devices, {Trusted} trusted IPs", _knownDevices.Count, _trustedIps.Count);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(45000, ct);

                    var current = GetArpTable();
                    foreach (var dev in current)
                    {
                        if (dev.Mac == "FF-FF-FF-FF-FF-FF") continue;
                        if (dev.Mac.StartsWith("01-00-5E", StringComparison.OrdinalIgnoreCase)) continue;
                        if (dev.Mac.StartsWith("33-33-", StringComparison.OrdinalIgnoreCase)) continue;
                        if (_trustedIps.Contains(dev.Ip)) continue;

                        if (!_knownDevices.ContainsKey(dev.Mac))
                        {
                            _knownDevices[dev.Mac] = dev;

                            var manufacturer = LookupManufacturer(dev.Mac);
                            var suspiciousService = await ProbeSuspiciousPorts(dev.Ip, ct);

                            var confidence = 0.75;
                            var tier = DetectionTier.Tier1Behavioral;
                            var reasoning = $"A new network device appeared that was not present at Sentinel startup. Manufacturer: {manufacturer}.";

                            if (suspiciousService != null)
                            {
                                // High-risk ports that always warrant blocking
                                bool isHighRisk = suspiciousService.Contains("ADB", StringComparison.OrdinalIgnoreCase) || 
                                                  suspiciousService.Contains("Telnet", StringComparison.OrdinalIgnoreCase) || 
                                                  suspiciousService.Contains("DevTools", StringComparison.OrdinalIgnoreCase) || 
                                                  suspiciousService.Contains("Pharos", StringComparison.OrdinalIgnoreCase);

                                if (isHighRisk)
                                {
                                    confidence = 0.90;
                                }

                                // Cast ports (8008/8009) on a new device: check if any ghost/empty-name
                                // process is actively connecting to this device IP. If yes, this isn't a
                                // Chromecast — it's a C2 relay masquerading as one (PlugX technique).
                                // If no ghost connection, treat as normal consumer device (log only).
                                if (!isHighRisk && 
                                    (suspiciousService.Contains("Cast", StringComparison.OrdinalIgnoreCase) ||
                                     suspiciousService.Contains("8008", StringComparison.OrdinalIgnoreCase)))
                                {
                                    if (HasGhostConnectionTo(dev.Ip))
                                    {
                                        confidence = 0.92;
                                        reasoning += " CORRELATED: An unresolvable/empty-name process has active connections to this device, indicating C2 relay masquerading as a casting device.";
                                    }
                                }

                                reasoning += $" Device has an open {suspiciousService} port, which is commonly used for screen casting, debugging, or remote access.";
                            }

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Phantom Device: New Unauthorized Network Device",
                                Evidence = $"New device: IP={dev.Ip}, MAC={dev.Mac}, Manufacturer={manufacturer}{(suspiciousService != null ? $", Open={suspiciousService}" : "")}",
                                Reasoning = reasoning,
                                Confidence = confidence, Tier = tier,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });

                            if (_config.ActiveResponse && confidence >= 0.85)
                                await BlockDevice(dev.Ip, dev.Mac, manufacturer, suspiciousService);
                        }
                        else
                        {
                            var known = _knownDevices[dev.Mac];
                            if (known.Ip != dev.Ip)
                                _knownDevices[dev.Mac] = dev;
                        }
                    }

                    await CleanupDepartedBlocks(current);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[PhantomDeviceMonitor] Error"); }
            }
        }

        private async Task BlockDevice(string ip, string mac, string manufacturer, string? suspiciousService)
        {
            try
            {
                if (_blockedIps.ContainsKey(ip)) return;
                var ruleName = $"Sentinel-Block-PhantomDevice-{ip.Replace('.', '_')}";

                // Use Windows Firewall COM API instead of shelling to netsh
                AddFirewallRule($"{ruleName}-OUT", ip, 2); // Outbound block
                AddFirewallRule($"{ruleName}-IN", ip, 1);  // Inbound block
                // Block mDNS/SSDP discovery to prevent auto-reconnection
                AddFirewallRule($"{ruleName}-MDNS", "224.0.0.251", 2, protocol: 17, remotePort: 5353);
                AddFirewallRule($"{ruleName}-SSDP", "239.255.255.250", 2, protocol: 17, remotePort: 1900);

                _blockedIps[ip] = DateTime.UtcNow;

                await _eventLogger.LogEventAsync("response", new ResponseEvent
                {
                    ProcessId = 0,
                    ProcessName = "PhantomDeviceMonitor",
                    ActionTaken = "FIREWALL_BLOCK+DISCOVERY_BLOCK",
                    Reason = $"Blocked phantom device IP={ip} MAC={mac} Manufacturer={manufacturer} SuspiciousPort={suspiciousService ?? "none"}"
                });

                _logger.LogWarning("[PhantomDeviceMonitor] BLOCKED device IP={Ip} MAC={Mac} Manufacturer={Mfg}", ip, mac, manufacturer);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[PhantomDeviceMonitor] Failed to block device {Ip}", ip);
            }
        }

        private static void AddFirewallRule(string name, string remoteIp, int direction, int protocol = 256, int remotePort = 0)
        {
            try
            {
                var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType == null) return;
                dynamic? policy = Activator.CreateInstance(policyType);
                if (policy == null) return;

                var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                if (ruleType == null) return;

                dynamic? rule = Activator.CreateInstance(ruleType);
                if (rule == null) return;

                rule.Name = name;
                rule.Direction = direction;
                rule.Action = 0; // Block
                rule.RemoteAddresses = remoteIp;
                rule.Enabled = true;
                rule.Profiles = 0x7FFFFFFF; // All profiles

                if (protocol != 256) // 256 = Any
                {
                    rule.Protocol = protocol; // 17 = UDP, 6 = TCP
                    if (remotePort > 0) rule.RemotePorts = remotePort.ToString();
                }

                policy.Rules.Add(rule);
            }
            catch { }
        }

        private static void RemoveFirewallRule(string name)
        {
            try
            {
                var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType == null) return;
                dynamic? policy = Activator.CreateInstance(policyType);
                if (policy == null) return;
                policy.Rules.Remove(name);
            }
            catch { }
        }

        private Task CleanupDepartedBlocks(List<NetworkDevice> currentDevices)
        {
            var currentIps = new HashSet<string>(currentDevices.Select(d => d.Ip));
            var toRemove = new List<string>();
            foreach (var kvp in _blockedIps)
            {
                if (!currentIps.Contains(kvp.Key) && DateTime.UtcNow - kvp.Value > TimeSpan.FromMinutes(10))
                {
                    try
                    {
                        var ruleName = $"Sentinel-Block-PhantomDevice-{kvp.Key.Replace('.', '_')}";
                        RemoveFirewallRule($"{ruleName}-OUT");
                        RemoveFirewallRule($"{ruleName}-IN");
                        RemoveFirewallRule($"{ruleName}-MDNS");
                        RemoveFirewallRule($"{ruleName}-SSDP");
                        toRemove.Add(kvp.Key);
                        _logger.LogInformation("[PhantomDeviceMonitor] Removed block for departed device {Ip}", kvp.Key);
                    }
                    catch { }
                }
            }
            foreach (var ip in toRemove) _blockedIps.TryRemove(ip, out _);
            return Task.CompletedTask;
        }

        private static async Task<string?> ProbeSuspiciousPorts(string ip, CancellationToken ct)
        {
            foreach (var port in SuspiciousPorts)
            {
                try
                {
                    using var client = new System.Net.Sockets.TcpClient();
                    using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
                    using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
                    await client.ConnectAsync(IPAddress.Parse(ip), port, linked.Token);
                    var serviceName = port switch
                    {
                        8008 => "HTTP-Alt (Cast discovery)",
                        8009 => "Google Cast",
                        8443 => "HTTPS-Alt",
                        5555 => "ADB (Android Debug Bridge)",
                        5353 => "mDNS",
                        9222 => "Chrome DevTools Protocol",
                        2323 => "Telnet-Alt",
                        4443 => "Pharos",
                        _ => $"Port {port}"
                    };
                    return $"{serviceName} (port {port})";
                }
                catch { }
            }
            return null;
        }

        private static string LookupManufacturer(string mac)
        {
            if (mac.Length >= 8)
            {
                var prefix = mac[..8];
                if (OuiLookup.TryGetValue(prefix, out var mfg))
                    return mfg;
            }
            return "Unknown";
        }

        private static List<NetworkDevice> GetArpTable()
        {
            var devices = new List<NetworkDevice>();
            try
            {
                int size = 0;
                GetIpNetTable(IntPtr.Zero, ref size, false);
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    if (GetIpNetTable(buffer, ref size, false) == 0)
                    {
                        int entries = Marshal.ReadInt32(buffer);
                        var entryPtr = buffer + 4;
                        int entrySize = Marshal.SizeOf<MIB_IPNETROW>();
                        for (int i = 0; i < entries; i++)
                        {
                            var row = Marshal.PtrToStructure<MIB_IPNETROW>(entryPtr + (i * entrySize));
                            if (row.dwType == 2) continue;
                            var ip = new IPAddress(BitConverter.GetBytes(row.dwAddr)).ToString();
                            var mac = $"{row.mac0:X2}-{row.mac1:X2}-{row.mac2:X2}-{row.mac3:X2}-{row.mac4:X2}-{row.mac5:X2}";
                            if (mac != "00-00-00-00-00-00")
                                devices.Add(new NetworkDevice { Ip = ip, Mac = mac, EntryType = row.dwType });
                        }
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            catch { }
            return devices;
        }

        private static IEnumerable<string> GetDefaultGatewayIps()
        {
            foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                foreach (var gw in nic.GetIPProperties().GatewayAddresses)
                {
                    var addr = gw.Address.ToString();
                    if (addr != "0.0.0.0" && addr != "::")
                        yield return addr;
                }
            }
        }

        private static IEnumerable<string> GetLocalIps()
        {
            foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                    yield return ua.Address.ToString();
            }
        }

        /// <summary>
        /// Checks if any unresolvable/empty-name process has active TCP connections to the given IP.
        /// This correlates phantom device detection with ghost process behavior — if a process we
        /// can't identify is talking to the new device, it's likely C2, not a Chromecast.
        /// </summary>
        private static bool HasGhostConnectionTo(string targetIp)
        {
            try
            {
                int size = 0;
                var ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2, 5 /* TCP_TABLE_OWNER_PID_ALL */, 0);
                if (ret != 122) return false;

                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    ret = GetExtendedTcpTable(buffer, ref size, true, 2, 5, 0);
                    if (ret != 0) return false;

                    int numEntries = Marshal.ReadInt32(buffer);
                    int structSize = 24; // sizeof MIB_TCPROW_OWNER_PID (6 uint = 24 bytes)
                    int myPid = Environment.ProcessId;

                    for (int i = 0; i < numEntries; i++)
                    {
                        var rowPtr = IntPtr.Add(buffer, 4 + i * structSize);
                        uint state = (uint)Marshal.ReadInt32(rowPtr, 0);
                        uint remoteAddr = (uint)Marshal.ReadInt32(rowPtr, 12);
                        uint owningPid = (uint)Marshal.ReadInt32(rowPtr, 20);

                        if (state != 5) continue; // Established only
                        if (owningPid <= 4 || owningPid == myPid) continue;

                        var remoteIp = new IPAddress(BitConverter.GetBytes(remoteAddr)).ToString();
                        if (!remoteIp.Equals(targetIp, StringComparison.Ordinal)) continue;

                        // Found a connection to the target IP — check if the owning process is resolvable
                        try
                        {
                            using var proc = Process.GetProcessById((int)owningPid);
                            var name = proc.ProcessName;
                            if (string.IsNullOrEmpty(name)) return true; // Empty name = ghost
                        }
                        catch (ArgumentException) { return true; } // Process doesn't exist = ghost
                        catch (InvalidOperationException) { return true; }
                        catch { }
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            catch { }
            return false;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize,
            bool bOrder, int ulAf, int tableClass, uint reserved);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_IPNETROW
        {
            public int dwIndex;
            public int dwPhysAddrLen;
            public byte mac0, mac1, mac2, mac3, mac4, mac5, mac6, mac7;
            public int dwAddr;
            public int dwType;
        }

        internal class NetworkDevice
        {
            public string Ip { get; set; } = "";
            public string Mac { get; set; } = "";
            public int EntryType { get; set; }
        }
    }

    // ──────────────────────────────────────────────
    // MTP Transfer Guard — blocks writing non-media files to portable devices (phones)
    // ──────────────────────────────────────────────
    public sealed class MtpTransferGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<MtpTransferGuard> _logger;

        // Allowed file extensions for MTP transfers (media + apps only)
        private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            // Images
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".heif",
            ".tiff", ".tif", ".svg", ".ico", ".raw", ".cr2", ".nef", ".arw", ".dng",
            // Videos
            ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v",
            ".mpg", ".mpeg", ".3gp", ".3g2", ".ts", ".vob",
            // Audio
            ".mp3", ".flac", ".wav", ".aac", ".ogg", ".wma", ".m4a", ".opus",
            ".alac", ".aiff", ".mid", ".midi",
            // Android apps
            ".apk", ".xapk", ".apks", ".aab",
            // iOS apps
            ".ipa",
            // Documents (common non-threatening transfers)
            ".pdf", ".txt",
        };

        // WPD COM interfaces
        [DllImport("ole32.dll")]
        private static extern int CoCreateInstance(
            [In] ref Guid rclsid, IntPtr pUnkOuter, uint dwClsContext,
            [In] ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out object ppv);

        // WPD GUIDs
        private static readonly Guid CLSID_PortableDeviceManager = new("0af10cec-2ecd-4b92-9581-34f6ae0637f3");
        private static readonly Guid IID_IPortableDeviceManager = new("a1567595-4c2f-4574-a6fa-ecef917b9a40");

        // Track known MTP devices
        private readonly ConcurrentDictionary<string, string> _connectedDevices = new();

        // Shell copy monitoring — watch temp staging paths
        private readonly ConcurrentDictionary<string, DateTime> _blockedTransfers = new();

        public MtpTransferGuard(DetectionEngine de, ILogger<MtpTransferGuard> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[MtpTransferGuard] Started — blocking non-media file transfers to MTP devices");

            await Task.Delay(15000, ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    // 1. Enumerate connected MTP/WPD devices
                    EnumeratePortableDevices();

                    // 2. Scan for processes actively transferring TO MTP devices (PC→Phone)
                    if (_connectedDevices.Count > 0)
                    {
                        await ScanForUnauthorizedTransfersAsync(ct);
                    }

                    // 3. Scan for dangerous files arriving FROM MTP devices (Phone→PC)
                    await ScanForInboundThreatsAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[MtpTransferGuard] Error"); }

                await Task.Delay(5000, ct);
            }
        }

        private void EnumeratePortableDevices()
        {
            try
            {
                var riid = IID_IPortableDeviceManager;
                var clsid = CLSID_PortableDeviceManager;
                int hr = CoCreateInstance(ref clsid, IntPtr.Zero, 1 /* CLSCTX_INPROC_SERVER */, ref riid, out var obj);
                if (hr != 0 || obj == null) return;

                // Use reflection to call GetDevices since we can't reference the WPD interop directly
                // Instead, enumerate via registry (more reliable for userland EDR)
                Marshal.ReleaseComObject(obj);
            }
            catch { }

            // Fallback: enumerate WPD devices via registry
            EnumerateViaRegistry();
        }

        private void EnumerateViaRegistry()
        {
            try
            {
                // WPD devices are registered under this key
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM");
                if (key == null) return;

                _connectedDevices.Clear();
                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    try
                    {
                        using var deviceKey = key.OpenSubKey(subKeyName);
                        if (deviceKey == null) continue;

                        var friendlyName = deviceKey.GetValue("FriendlyName") as string;
                        var deviceDesc = deviceKey.GetValue("DeviceDesc") as string ?? "";

                        // Only track actual portable devices (phones, tablets)
                        if (deviceDesc.Contains("MTP", StringComparison.OrdinalIgnoreCase) ||
                            deviceDesc.Contains("Portable", StringComparison.OrdinalIgnoreCase) ||
                            deviceDesc.Contains("Phone", StringComparison.OrdinalIgnoreCase) ||
                            deviceDesc.Contains("Android", StringComparison.OrdinalIgnoreCase) ||
                            deviceDesc.Contains("Apple", StringComparison.OrdinalIgnoreCase) ||
                            deviceDesc.Contains("iPhone", StringComparison.OrdinalIgnoreCase))
                        {
                            _connectedDevices[subKeyName] = friendlyName ?? subKeyName;
                        }
                    }
                    catch { }
                }

                if (_connectedDevices.Count > 0)
                    _logger.LogDebug("[MtpTransferGuard] {Count} MTP device(s) connected", _connectedDevices.Count);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[MtpTransferGuard] Registry enumeration failed");
            }
        }

        private async Task ScanForUnauthorizedTransfersAsync(CancellationToken ct)
        {
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        // Look for processes that are actively using WPD APIs
                        // Key indicator: process has loaded PortableDeviceApi.dll or wpdshext.dll
                        if (!IsWpdProcess(proc)) continue;

                        // Check what files this process has open — look for non-media files
                        // being staged for transfer
                        var suspiciousFiles = GetStagedNonMediaFiles(proc);
                        foreach (var file in suspiciousFiles)
                        {
                            var key = $"{proc.Id}:{file}";
                            if (_blockedTransfers.ContainsKey(key)) continue;

                            _blockedTransfers[key] = DateTime.UtcNow;

                            _logger.LogWarning(
                                "[MtpTransferGuard] Blocked non-media transfer: {File} by {Process} (PID {Pid})",
                                Path.GetFileName(file), proc.ProcessName, proc.Id);

                            // Kill the transfer process
                            try { proc.Kill(); } catch { }

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "MTP Guard: Non-Media File Transfer Blocked",
                                Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) attempted to transfer " +
                                           $"'{Path.GetFileName(file)}' to a connected MTP device. " +
                                           $"Extension '{Path.GetExtension(file)}' is not in the allowed media/app list. " +
                                           $"Connected devices: {string.Join(", ", _connectedDevices.Values)}",
                                Reasoning = "MTP file transfer of non-media content (executables, scripts, archives, DLLs) " +
                                            "to a connected phone can be used to infect the mobile device from a compromised PC. " +
                                            "Only media files (images, video, audio) and mobile app packages (APK, IPA) are permitted. " +
                                            "The transferring process has been terminated.",
                                Confidence = 0.90,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = proc.ProcessName,
                                ProcessId = proc.Id,
                                SignalType = SignalType.Generic,
                                Metadata = new Dictionary<string, string>
                                {
                                    { "File", Path.GetFileName(file) },
                                    { "Extension", Path.GetExtension(file) },
                                    { "Devices", string.Join(", ", _connectedDevices.Values) },
                                    { "Action", "ProcessKilled" }
                                }
                            });
                        }
                    }
                    catch { }
                }

                // Prune old blocked transfer records (older than 5 minutes)
                var stale = _blockedTransfers.Where(kv => DateTime.UtcNow - kv.Value > TimeSpan.FromMinutes(5))
                    .Select(kv => kv.Key).ToList();
                foreach (var key in stale) _blockedTransfers.TryRemove(key, out _);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[MtpTransferGuard] Scan error");
            }
        }

        private static bool IsWpdProcess(Process proc)
        {
            try
            {
                foreach (ProcessModule mod in proc.Modules)
                {
                    var name = mod.ModuleName.ToLowerInvariant();
                    if (name == "portabledeviceapi.dll" || name == "wpdshext.dll" ||
                        name == "wpdmtp.dll" || name == "wpdmtpus.dll")
                    {
                        return true;
                    }
                }
            }
            catch { } // Access denied for system processes — fine
            return false;
        }

        private static List<string> GetStagedNonMediaFiles(Process proc)
        {
            var results = new List<string>();
            try
            {
                // Check the process command line for file paths
                var cmdLine = GetProcessCommandLine(proc.Id);
                if (!string.IsNullOrEmpty(cmdLine))
                {
                    // Extract file paths from command line
                    var paths = ExtractFilePaths(cmdLine);
                    foreach (var path in paths)
                    {
                        if (!IsAllowedExtension(path))
                            results.Add(path);
                    }
                }

                // Also check the process's current directory and recently opened files
                // by scanning file handles in temp/staging directories
                var procPath = proc.MainModule?.FileName;
                if (procPath != null)
                {
                    // Explorer.exe doing drag-drop to MTP device — check clipboard/drag data
                    // This is handled by the WPD shell extension (wpdshext.dll)
                    if (proc.ProcessName.Equals("explorer", StringComparison.OrdinalIgnoreCase))
                    {
                        // For Explorer, scan recent file operation cache
                        ScanExplorerRecentTransfers(results);
                    }
                }
            }
            catch { }
            return results;
        }

        private static void ScanExplorerRecentTransfers(List<string> results)
        {
            // Monitor the WPD temp staging directory
            // When Explorer copies to MTP, it stages files through a temp path
            var tempPaths = new[]
            {
                Path.Combine(Path.GetTempPath(), "WPDNSE"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Temp", "WPDNSE")
            };

            foreach (var tempPath in tempPaths)
            {
                if (!Directory.Exists(tempPath)) continue;
                try
                {
                    foreach (var file in Directory.GetFiles(tempPath, "*", SearchOption.AllDirectories))
                    {
                        // Only flag if the file was created/modified recently (last 30s)
                        var info = new FileInfo(file);
                        if (DateTime.UtcNow - info.LastWriteTimeUtc < TimeSpan.FromSeconds(30) &&
                            !IsAllowedExtension(file))
                        {
                            results.Add(file);
                        }
                    }
                }
                catch { }
            }
        }

        private static bool IsAllowedExtension(string filePath)
        {
            var ext = Path.GetExtension(filePath);
            if (string.IsNullOrEmpty(ext)) return true; // No extension = probably not a real file path
            return AllowedExtensions.Contains(ext);
        }

        private static List<string> ExtractFilePaths(string cmdLine)
        {
            var paths = new List<string>();
            // Simple extraction: find tokens that look like file paths
            var parts = cmdLine.Split('"', StringSplitOptions.RemoveEmptyEntries);
            foreach (var part in parts)
            {
                var trimmed = part.Trim();
                if ((trimmed.Length > 3 && trimmed[1] == ':' && trimmed[2] == '\\') ||
                    trimmed.StartsWith(@"\\"))
                {
                    if (File.Exists(trimmed))
                        paths.Add(trimmed);
                }
            }
            return paths;
        }

        private static string GetProcessCommandLine(int pid)
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (var obj in searcher.Get())
                {
                    return obj["CommandLine"]?.ToString() ?? "";
                }
            }
            catch { }
            return "";
        }

        // ── Inbound threat detection (Phone → PC) ──

        // Dangerous extensions that should NEVER arrive from MTP to PC
        private static readonly HashSet<string> DangerousExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            // Executables
            ".exe", ".dll", ".sys", ".drv", ".scr", ".com", ".pif",
            // Scripts
            ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".vbs", ".vbe",
            ".js", ".jse", ".wsf", ".wsh", ".msh", ".msh1", ".msh2",
            // Compiled/managed
            ".msi", ".msp", ".mst", ".cpl", ".hta", ".inf", ".ins",
            // Office macros
            ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",
            // Archives (can contain executables)
            ".zip", ".rar", ".7z", ".tar", ".gz", ".cab", ".iso", ".img", ".vhd", ".vhdx",
            // Shortcuts and links
            ".lnk", ".url", ".scf",
            // Registry
            ".reg",
            // Certificate
            ".cer", ".crt", ".p12", ".pfx",
            // DLL sideloading / hijack
            ".ocx", ".ax",
            // Java
            ".jar", ".class",
            // Python
            ".py", ".pyc", ".pyw",
        };

        // Track already-quarantined files to avoid duplicate alerts
        private readonly ConcurrentDictionary<string, DateTime> _quarantinedInbound = new(StringComparer.OrdinalIgnoreCase);

        private async Task ScanForInboundThreatsAsync(CancellationToken ct)
        {
            // Monitor WPDNSE staging directories — files transiting FROM MTP device TO PC
            var tempPaths = new[]
            {
                Path.Combine(Path.GetTempPath(), "WPDNSE"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Temp", "WPDNSE")
            };

            // Also monitor common drop targets (Downloads, Desktop, Documents)
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var dropTargets = new[]
            {
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Desktop"),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
            };

            // Scan WPDNSE staging — anything dangerous here is in-transit from phone
            foreach (var tempPath in tempPaths)
            {
                if (!Directory.Exists(tempPath)) continue;
                try
                {
                    foreach (var file in Directory.GetFiles(tempPath, "*", SearchOption.AllDirectories))
                    {
                        if (!IsDangerousExtension(file)) continue;
                        if (_quarantinedInbound.ContainsKey(file)) continue;

                        var info = new FileInfo(file);
                        // Only react to recently created files (last 60s)
                        if (DateTime.UtcNow - info.CreationTimeUtc > TimeSpan.FromSeconds(60)) continue;

                        _quarantinedInbound[file] = DateTime.UtcNow;

                        // Delete the dangerous file immediately
                        try { File.Delete(file); } catch { }

                        _logger.LogWarning("[MtpTransferGuard] Quarantined inbound threat from MTP: {File}", Path.GetFileName(file));

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "MTP Guard: Dangerous Inbound File Blocked (Phone→PC)",
                            Evidence = $"File '{Path.GetFileName(file)}' with dangerous extension '{Path.GetExtension(file)}' " +
                                       $"was being transferred from an MTP device to this PC via WPDNSE staging. " +
                                       $"File deleted to prevent execution.",
                            Reasoning = "A connected phone/tablet attempted to transfer a potentially dangerous file " +
                                        "(executable, script, archive, macro document) to this PC. This is a known " +
                                        "infection vector where a compromised mobile device pushes malware to the PC " +
                                        "during file sync or manual transfer. The file was deleted before it could be executed.",
                            Confidence = 0.92,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.Quarantine,
                            ProcessName = "MTP Transfer",
                            ProcessId = 0,
                            SignalType = SignalType.Generic,
                            Metadata = new Dictionary<string, string>
                            {
                                { "File", Path.GetFileName(file) },
                                { "Extension", Path.GetExtension(file) },
                                { "Direction", "Inbound (Phone→PC)" },
                                { "StagingPath", tempPath },
                                { "Action", "Deleted" }
                            }
                        });
                    }
                }
                catch { }
            }

            // Scan drop targets only when MTP devices are connected
            if (_connectedDevices.Count > 0)
            {
                foreach (var dropDir in dropTargets)
                {
                    if (!Directory.Exists(dropDir)) continue;
                    try
                    {
                        // Only check top-level files created in the last 10 seconds
                        // (tight window to catch active transfers without false positives on normal use)
                        foreach (var file in Directory.GetFiles(dropDir))
                        {
                            if (!IsDangerousExtension(file)) continue;
                            if (_quarantinedInbound.ContainsKey(file)) continue;

                            var info = new FileInfo(file);
                            if (DateTime.UtcNow - info.CreationTimeUtc > TimeSpan.FromSeconds(10)) continue;

                            // Check if the file was created by a WPD-related process
                            var (pid, procName) = GetCreatorProcess(file);
                            if (!IsWpdRelatedProcess(procName)) continue;

                            _quarantinedInbound[file] = DateTime.UtcNow;

                            try { File.Delete(file); } catch { }

                            _logger.LogWarning("[MtpTransferGuard] Blocked inbound MTP threat in {Dir}: {File}",
                                Path.GetFileName(dropDir), Path.GetFileName(file));

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "MTP Guard: Dangerous Inbound File Blocked (Phone→PC)",
                                Evidence = $"File '{Path.GetFileName(file)}' landed in {Path.GetFileName(dropDir)} " +
                                           $"from MTP device via process '{procName}' (PID {pid}). Deleted.",
                                Reasoning = "A dangerous file type was transferred from a connected MTP device to a " +
                                            "common user directory. Only media files are safe to receive from phones.",
                                Confidence = 0.88,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.Quarantine,
                                ProcessName = procName,
                                ProcessId = pid,
                                SignalType = SignalType.Generic,
                                Metadata = new Dictionary<string, string>
                                {
                                    { "File", Path.GetFileName(file) },
                                    { "Extension", Path.GetExtension(file) },
                                    { "DropTarget", dropDir },
                                    { "Direction", "Inbound (Phone→PC)" },
                                    { "Action", "Deleted" }
                                }
                            });
                        }
                    }
                    catch { }
                }
            }

            // Prune old quarantine records
            var stale = _quarantinedInbound.Where(kv => DateTime.UtcNow - kv.Value > TimeSpan.FromMinutes(10))
                .Select(kv => kv.Key).ToList();
            foreach (var key in stale) _quarantinedInbound.TryRemove(key, out _);
        }

        private static bool IsDangerousExtension(string filePath)
        {
            var ext = Path.GetExtension(filePath);
            if (string.IsNullOrEmpty(ext)) return false;
            return DangerousExtensions.Contains(ext);
        }

        private static bool IsWpdRelatedProcess(string processName)
        {
            var lower = processName.ToLowerInvariant();
            return lower.Contains("explorer") || lower.Contains("wpd") ||
                   lower.Contains("portable") || lower.Contains("mtp") ||
                   lower.Contains("shell");
        }

        private static (int pid, string name) GetCreatorProcess(string filePath)
        {
            try
            {
                var lastWrite = File.GetLastWriteTimeUtc(filePath);
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (proc.StartTime.ToUniversalTime() <= lastWrite &&
                            proc.StartTime.ToUniversalTime() > lastWrite.AddSeconds(-10) &&
                            proc.Id > 4)
                        {
                            return (proc.Id, proc.ProcessName);
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return (0, "Unknown");
        }
    }

    // ──────────────────────────────────────────────
    // Browser DNS Policy Guard — forces ALL apps to use OS DNS resolver (respects hosts file)
    // ──────────────────────────────────────────────
    public sealed class BrowserDnsPolicyGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<BrowserDnsPolicyGuard> _logger;
        private bool _initialEnforcement;
        private DateTime _lastTamperAlert = DateTime.MinValue;

        // Chromium-based browser policy keys (HKLM\SOFTWARE\Policies\...)
        private static readonly (string Key, string Name)[] ChromiumBrowsers = new[]
        {
            (@"SOFTWARE\Policies\Google\Chrome", "Chrome"),
            (@"SOFTWARE\Policies\Microsoft\Edge", "Edge"),
            (@"SOFTWARE\Policies\BraveSoftware\Brave", "Brave"),
            (@"SOFTWARE\Policies\Vivaldi", "Vivaldi"),
            (@"SOFTWARE\Policies\Opera Software\Opera", "Opera"),
            (@"SOFTWARE\Policies\Chromium", "Chromium"),
        };

        // Windows system-level DoH registry
        private const string DnsCacheParamsKey = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
        private const string EnableAutoDohValue = "EnableAutoDoh";

        // Firefox uses a different mechanism — policies.json or registry
        private const string FirefoxPolicyKey = @"SOFTWARE\Policies\Mozilla\Firefox";
        private const string FirefoxDnsOverHttpsKey = @"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS";

        public BrowserDnsPolicyGuard(DetectionEngine de, ILogger<BrowserDnsPolicyGuard> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BrowserDnsPolicyGuard] Started — enforcing OS DNS resolver for all browsers and disabling system DoH");

            await Task.Delay(10000, ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    bool anyChanged = false;

                    // 1. Disable Windows system-level DoH (EnableAutoDoh = 0)
                    anyChanged |= EnforceSystemDoh();

                    // 2. Enforce all Chromium browsers
                    foreach (var (key, name) in ChromiumBrowsers)
                        anyChanged |= EnforceChromiumPolicy(key, name);

                    // 3. Enforce Firefox
                    anyChanged |= EnforceFirefoxPolicy();

                    if (anyChanged && !_initialEnforcement)
                    {
                        _initialEnforcement = true;
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Hardening: System-Wide DNS Policy Enforced",
                            Evidence = "Disabled DNS-over-HTTPS system-wide (Windows DoH + all browser policies). " +
                                       "All DNS resolution now goes through the OS resolver which respects the hosts file.",
                            Reasoning = "DNS-over-HTTPS in browsers and at the OS level bypasses the local hosts file entirely. " +
                                        "Any hosts-file-based blocking (ads, trackers, malware domains) has zero effect when " +
                                        "DoH is active. Sentinel disables DoH at every layer: Windows DNS client, Chrome, Edge, " +
                                        "Brave, Vivaldi, Opera, Chromium, and Firefox. The hosts file becomes the single " +
                                        "authoritative DNS override point.",
                            Confidence = 0.99,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.SecurityEvasion,
                            Metadata = new Dictionary<string, string>
                            {
                                { "Action", "PolicyEnforced" },
                                { "EnableAutoDoh", "0" },
                                { "BuiltInDnsClientEnabled", "0" },
                                { "DnsOverHttpsMode", "off" },
                                { "Firefox.DNSOverHTTPS.Enabled", "false" }
                            }
                        });
                    }
                    else if (anyChanged && DateTime.UtcNow - _lastTamperAlert > TimeSpan.FromHours(1))
                    {
                        _lastTamperAlert = DateTime.UtcNow;
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: DNS Policy Reverted and Re-Applied",
                            Evidence = "DNS-over-HTTPS was found re-enabled (system or browser level). Re-enforced.",
                            Reasoning = "Something re-enabled DoH, bypassing the hosts file. Could be a Windows update, " +
                                        "browser update, user action, or malware circumventing DNS-level blocking.",
                            Confidence = 0.80,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.SecurityEvasion
                        });
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[BrowserDnsPolicyGuard] Error"); }

                await Task.Delay(15000, ct);
            }
        }

        /// <summary>
        /// Disables Windows system-level DNS-over-HTTPS.
        /// EnableAutoDoh: 0 = disabled, 2 = enabled.
        /// This ensures the OS DNS client uses plain DNS which reads the hosts file first.
        /// </summary>
        private bool EnforceSystemDoh()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(DnsCacheParamsKey, true);
                if (key == null) return false;

                var current = key.GetValue(EnableAutoDohValue);
                if (current != null && (int)current != 0)
                {
                    key.SetValue(EnableAutoDohValue, 0, RegistryValueKind.DWord);
                    _logger.LogWarning("[BrowserDnsPolicyGuard] Disabled system-level DoH (EnableAutoDoh=0)");
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[BrowserDnsPolicyGuard] Failed to enforce system DoH");
            }
            return false;
        }

        /// <summary>
        /// Enforces Chromium-based browser policies:
        /// - BuiltInDnsClientEnabled = 0 (use OS resolver)
        /// - DnsOverHttpsMode = "off"
        /// </summary>
        private bool EnforceChromiumPolicy(string policyKey, string browserName)
        {
            bool changed = false;
            try
            {
                // Only create the policy key if the browser is actually installed
                // (check if the parent policy path or browser exe exists)
                using var existingKey = Registry.LocalMachine.OpenSubKey(policyKey, true);
                var key = existingKey ?? Registry.LocalMachine.CreateSubKey(policyKey, true);
                if (key == null) return false;
                // If we created the key fresh, don't report as "changed" (avoids alert spam for uninstalled browsers)
                bool isNewKey = existingKey == null;

                var dnsClient = key.GetValue("BuiltInDnsClientEnabled");
                if (dnsClient == null || (int)dnsClient != 0)
                {
                    key.SetValue("BuiltInDnsClientEnabled", 0, RegistryValueKind.DWord);
                    if (!isNewKey) changed = true;
                    else _logger.LogDebug("[BrowserDnsPolicyGuard] Set BuiltInDnsClientEnabled=0 for {Browser} (new key)", browserName);
                }

                var dohMode = key.GetValue("DnsOverHttpsMode") as string;
                if (dohMode == null || !string.Equals(dohMode, "off", StringComparison.OrdinalIgnoreCase))
                {
                    key.SetValue("DnsOverHttpsMode", "off", RegistryValueKind.String);
                    if (!isNewKey) changed = true;
                    else _logger.LogDebug("[BrowserDnsPolicyGuard] Set DnsOverHttpsMode=off for {Browser} (new key)", browserName);
                }

                if (existingKey == null) key.Dispose();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[BrowserDnsPolicyGuard] Failed to enforce policy for {Browser}", browserName);
            }
            return changed;
        }

        /// <summary>
        /// Enforces Firefox DNS policy via registry:
        /// - DNSOverHTTPS\Enabled = 0 (disable DoH)
        /// - DNSOverHTTPS\Locked = 1 (prevent user from re-enabling)
        /// </summary>
        private bool EnforceFirefoxPolicy()
        {
            bool changed = false;
            try
            {
                using var key = Registry.LocalMachine.CreateSubKey(FirefoxDnsOverHttpsKey, true);
                if (key == null) return false;

                var enabled = key.GetValue("Enabled");
                if (enabled == null || (int)enabled != 0)
                {
                    key.SetValue("Enabled", 0, RegistryValueKind.DWord);
                    changed = true;
                    _logger.LogWarning("[BrowserDnsPolicyGuard] Enforced DNSOverHTTPS.Enabled=0 for Firefox");
                }

                var locked = key.GetValue("Locked");
                if (locked == null || (int)locked != 1)
                {
                    key.SetValue("Locked", 1, RegistryValueKind.DWord);
                    changed = true;
                    _logger.LogWarning("[BrowserDnsPolicyGuard] Enforced DNSOverHTTPS.Locked=1 for Firefox");
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[BrowserDnsPolicyGuard] Failed to enforce Firefox policy");
            }
            return changed;
        }
    }

    // ──────────────────────────────────────────────
    // Hosts File Guard — enforces embedded hosts content, deletes all other files in drivers\etc
    // ──────────────────────────────────────────────
    public sealed class HostsFileGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<HostsFileGuard> _logger;
        private FileSystemWatcher? _watcher;

        // The directory being protected
        private static readonly string DriversEtcPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "drivers", "etc");

        private static readonly string HostsFilePath = Path.Combine(DriversEtcPath, "hosts");

        // Debounce to avoid revert loops (our own writes trigger watcher events)
        private readonly ConcurrentDictionary<string, DateTime> _revertCooldown = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan CooldownPeriod = TimeSpan.FromSeconds(3);

        private readonly SemaphoreSlim _enforceLock = new(1, 1);

        // Precomputed SHA-256 of the trusted content for fast comparison
        private readonly string _trustedHash;

        public HostsFileGuard(DetectionEngine de, ILogger<HostsFileGuard> l)
        {
            _detectionEngine = de;
            _logger = l;
            using var sha = SHA256.Create();
            _trustedHash = Convert.ToHexString(sha.ComputeHash(new UTF8Encoding(false).GetBytes(TrustedHostsContent)));
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[HostsFileGuard] Started — enforcing hosts content and purging unauthorized files in {Path}", DriversEtcPath);

            if (!Directory.Exists(DriversEtcPath))
            {
                _logger.LogError("[HostsFileGuard] Directory not found: {Path}", DriversEtcPath);
                return;
            }

            // Initial enforcement
            await EnforceAsync("Startup", ct);

            // Set up FileSystemWatcher for the entire directory
            StartWatcher();

            // Periodic integrity verification (catches offline modifications)
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    await EnforceAsync("PeriodicIntegrityCheck", ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[HostsFileGuard] Periodic check error");
                }
            }

            DisposeWatcher();
        }

        /// <summary>
        /// Core enforcement: write trusted content to hosts, delete everything else.
        /// </summary>
        private async Task EnforceAsync(string trigger, CancellationToken ct)
        {
            await _enforceLock.WaitAsync(ct);
            try
            {
                // 1. Enforce hosts file content
                await EnforceHostsFileAsync(trigger, ct);

                // 2. Delete all other files in the directory
                await DeleteUnauthorizedFilesAsync(trigger, ct);
            }
            finally
            {
                _enforceLock.Release();
            }
        }

        private async Task EnforceHostsFileAsync(string trigger, CancellationToken ct)
        {
            try
            {
                // Check if hosts file matches trusted content
                if (File.Exists(HostsFilePath))
                {
                    var currentHash = ComputeFileHash(HostsFilePath);
                    if (string.Equals(currentHash, _trustedHash, StringComparison.OrdinalIgnoreCase))
                        return; // Already correct
                }

                // File is modified or missing — revert
                _logger.LogWarning("[HostsFileGuard] hosts file diverged from trusted baseline (trigger: {Trigger})", trigger);

                var (pid, processName) = GetModifyingProcess(HostsFilePath);

                bool reverted = false;
                for (int i = 0; i < 3 && !reverted; i++)
                {
                    try
                    {
                        File.WriteAllText(HostsFilePath, TrustedHostsContent, new UTF8Encoding(false));
                        reverted = true;
                    }
                    catch (IOException) when (i < 2)
                    {
                        await Task.Delay(500, ct);
                    }
                }

                _revertCooldown[HostsFilePath] = DateTime.UtcNow;

                if (reverted)
                    _logger.LogWarning("[HostsFileGuard] Reverted hosts to trusted baseline");
                else
                    _logger.LogError("[HostsFileGuard] Failed to revert hosts after 3 attempts");

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Anti-Tamper: Hosts File Modification Reverted",
                    Evidence = $"hosts file was modified (trigger: {trigger}). " +
                               $"Reverted to embedded trusted baseline. Modifier: {processName} (PID {pid})",
                    Reasoning = "The Windows hosts file controls local DNS resolution. Malware modifies it " +
                                "to redirect traffic to C2 servers, block security updates, or perform DNS poisoning. " +
                                "Sentinel enforces the hardcoded trusted baseline at all times.",
                    Confidence = 0.95,
                    Tier = DetectionTier.Tier1Behavioral,
                    // Never kill on Startup — hosts file is expected to differ on first boot/install.
                    // Only kill if we have a valid PID and this isn't the initial enforcement.
                    AuthorizedResponse = (pid > 0 && trigger != "Startup") ? ResponseAction.KillProcessTree : ResponseAction.LogOnly,
                    ProcessName = processName,
                    ProcessId = pid,
                    SignalType = SignalType.AntiTamper,
                    Metadata = new Dictionary<string, string>
                    {
                        { "File", "hosts" },
                        { "Trigger", trigger },
                        { "Reverted", reverted.ToString() }
                    }
                });
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[HostsFileGuard] EnforceHostsFile error");
            }
        }

        private async Task DeleteUnauthorizedFilesAsync(string trigger, CancellationToken ct)
        {
            try
            {
                foreach (var file in Directory.GetFiles(DriversEtcPath))
                {
                    var fileName = Path.GetFileName(file);
                    if (string.Equals(fileName, "hosts", StringComparison.OrdinalIgnoreCase))
                        continue; // This is the one we enforce, not delete

                    // Delete it
                    try
                    {
                        File.Delete(file);
                        _logger.LogWarning("[HostsFileGuard] Deleted unauthorized file: {File}", fileName);

                        _revertCooldown[file] = DateTime.UtcNow;

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: Unauthorized File Deleted from drivers\\etc",
                            Evidence = $"File '{fileName}' existed in drivers\\etc and was deleted (trigger: {trigger}). " +
                                       "Only the 'hosts' file is permitted in this directory.",
                            Reasoning = "Files like hosts.ics, lmhosts.sam, and others in drivers\\etc can be " +
                                        "abused as DNS resolution bypass vectors. hosts.ics is loaded by the DNS " +
                                        "client alongside hosts and is a known attack surface. Sentinel removes " +
                                        "all files except the enforced hosts file.",
                            Confidence = 0.90,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.AntiTamper,
                            Metadata = new Dictionary<string, string>
                            {
                                { "File", fileName },
                                { "Trigger", trigger },
                                { "Action", "Deleted" }
                            }
                        });
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[HostsFileGuard] Failed to delete {File}", fileName);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[HostsFileGuard] DeleteUnauthorizedFiles error");
            }
        }

        private void StartWatcher()
        {
            try
            {
                _watcher = new FileSystemWatcher(DriversEtcPath)
                {
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName |
                                   NotifyFilters.CreationTime | NotifyFilters.Size,
                    Filter = "*",
                    IncludeSubdirectories = false,
                    EnableRaisingEvents = true
                };

                _watcher.Changed += OnFileEvent;
                _watcher.Created += OnFileEvent;
                _watcher.Renamed += (s, e) => OnFileEvent(s, e);

                _logger.LogInformation("[HostsFileGuard] Watcher active on {Path}", DriversEtcPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[HostsFileGuard] Failed to start watcher");
            }
        }

        private async void OnFileEvent(object sender, FileSystemEventArgs e)
        {
            try
            {
                // Cooldown check
                if (_revertCooldown.TryGetValue(e.FullPath, out var lastAction) &&
                    DateTime.UtcNow - lastAction < CooldownPeriod)
                    return;

                await EnforceAsync(e.ChangeType.ToString(), CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[HostsFileGuard] OnFileEvent error for {File}", e.FullPath);
            }
        }

        private static (int pid, string name) GetModifyingProcess(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return (0, "Unknown");
                var lastWrite = File.GetLastWriteTimeUtc(filePath);
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        // Never target critical system processes — killing these causes BSOD
                        var name = proc.ProcessName;
                        if (string.Equals(name, "csrss", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "wininit", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "services", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "smss", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "lsass", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "svchost", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "winlogon", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "explorer", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "dwm", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "System", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "msiexec", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "TrustedInstaller", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        if (proc.StartTime.ToUniversalTime() <= lastWrite &&
                            proc.StartTime.ToUniversalTime() > lastWrite.AddSeconds(-5) &&
                            proc.Id > 4)
                        {
                            return (proc.Id, name);
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return (0, "Unknown");
        }

        private static string ComputeFileHash(string path)
        {
            try
            {
                using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sha = SHA256.Create();
                return Convert.ToHexString(sha.ComputeHash(stream));
            }
            catch { return string.Empty; }
        }

        private void DisposeWatcher()
        {
            if (_watcher != null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Dispose();
                _watcher = null;
            }
        }

        public override async Task StopAsync(CancellationToken ct)
        {
            DisposeWatcher();
            await base.StopAsync(ct);
        }

        // ── Embedded trusted hosts file content (no external file dependency) ──
        private const string TrustedHostsContent =
            "# Windows Sentinel hosts file\r\n" +
            "127.0.0.1 localhost\r\n" +
            "127.0.0.1 localhost.localdomain\r\n" +
            "127.0.0.1 local\r\n" +
            "255.255.255.255 broadcasthost\r\n" +
            "::1 localhost\r\n" +
            "::1 ip6-localhost\r\n" +
            "::1 ip6-loopback\r\n" +
            "fe80::1%lo0 localhost\r\n" +
            "ff00::0 ip6-localnet\r\n" +
            "ff00::0 ip6-mcastprefix\r\n" +
            "ff02::1 ip6-allnodes\r\n" +
            "ff02::2 ip6-allrouters\r\n" +
            "ff02::3 ip6-allhosts\r\n" +
            "0.0.0.0 0.0.0.0\r\n" +
            "0.0.0.0 forum.hr\r\n" +
            "0.0.0.0 www.forum.hr\r\n" +
            "0.0.0.0 m.forum.hr\r\n" +
            "0.0.0.0 cdn.forum.hr\r\n" +
            "0.0.0.0 static.forum.hr\r\n" +
            "0.0.0.0 api.forum.hr\r\n" +
            "0.0.0.0 img.forum.hr\r\n" +
            "0.0.0.0 mail.forum.hr\r\n" +
            "0.0.0.0 ads.forum.hr\r\n" +
            "0.0.0.0 tracker.forum.hr\r\n" +
            "0.0.0.0 adtago.s3.amazonaws.com\r\n" +
            "0.0.0.0 analyticsengine.s3.amazonaws.com\r\n" +
            "0.0.0.0 advice-ads.s3.amazonaws.com\r\n" +
            "0.0.0.0 affiliationjs.s3.amazonaws.com\r\n" +
            "0.0.0.0 advertising-api-eu.amazon.com\r\n" +
            "0.0.0.0 ssl.google-analytics.com\r\n" +
            "0.0.0.0 fastclick.com\r\n" +
            "0.0.0.0 fastclick.net\r\n" +
            "0.0.0.0 media.fastclick.net\r\n" +
            "0.0.0.0 cdn.fastclick.net\r\n" +
            "0.0.0.0 analytics.yahoo.com\r\n" +
            "0.0.0.0 global.adserver.yahoo.com\r\n" +
            "0.0.0.0 ads.yap.yahoo.com\r\n" +
            "0.0.0.0 appmetrica.yandex.com\r\n" +
            "0.0.0.0 yandexadexchange.net\r\n" +
            "0.0.0.0 analytics.mobile.yandex.net\r\n" +
            "0.0.0.0 extmaps-api.yandex.net\r\n" +
            "0.0.0.0 adsdk.yandex.ru\r\n" +
            "0.0.0.0 appmetrica.yandex.com\r\n" +
            "0.0.0.0 hotjar.com\r\n" +
            "0.0.0.0 static.hotjar.com\r\n" +
            "0.0.0.0 api-hotjar.com\r\n" +
            "0.0.0.0 jotjar-analytics.com\r\n" +
            "0.0.0.0 mouseflow.com\r\n" +
            "0.0.0.0 freshmarketer.com\r\n" +
            "0.0.0.0 luckyorange.com\r\n" +
            "0.0.0.0 cdn.luckyorange.com\r\n" +
            "0.0.0.0 w1.luckyorange.com\r\n" +
            "0.0.0.0 upload.luckyorange.com\r\n" +
            "0.0.0.0 cs.luckyorange.com\r\n" +
            "0.0.0.0 settings.luckyorange.com\r\n" +
            "0.0.0.0 stats.wp.com\r\n" +
            "0.0.0.0 app.bugsnag.com\r\n" +
            "0.0.0.0 api.bugsnag.com\r\n" +
            "0.0.0.0 notify.bugsnag.com\r\n" +
            "0.0.0.0 sessions.bugsnag.com\r\n" +
            "0.0.0.0 browser.sentry-cdn.com\r\n" +
            "0.0.0.0 app.getsentry.com\r\n" +
            "0.0.0.0 amazonaws.com\r\n" +
            "0.0.0.0 amazonaax.com\r\n" +
            "0.0.0.0 amazonclix.com\r\n" +
            "0.0.0.0 assoc-amazon.com\r\n" +
            "0.0.0.0 ads.google.com\r\n" +
            "0.0.0.0 pagead2.googlesyndication.com\r\n" +
            "0.0.0.0 pagead2.googleadservices.com\r\n" +
            "# 0.0.0.0 facebook.com\r\n" +
            "0.0.0.0 amazon-adsystem.com\r\n" +
            "0.0.0.0 googleadservices.com\r\n" +
            "0.0.0.0 doubleclick.net\r\n" +
            "0.0.0.0 ad.doubleclick.net\r\n" +
            "0.0.0.0 static.doubleclick.net\r\n" +
            "0.0.0.0 m.doubleclick.net\r\n" +
            "0.0.0.0 mediavisor.doubleclick.net\r\n" +
            "0.0.0.0 googleads.g.doubleclick.net\r\n" +
            "0.0.0.0 adclick.g.doubleclick.net\r\n" +
            "0.0.0.0 carbonads.net\r\n" +
            "0.0.0.0 advertising.amazon.com\r\n" +
            "0.0.0.0 advertising.amazon.ca\r\n" +
            "0.0.0.0 google-analytics.com\r\n" +
            "0.0.0.0 doubleclick.net\r\n" +
            "0.0.0.0 doubleclick.com\r\n" +
            "0.0.0.0 doubleclick.de\r\n" +
            "0.0.0.0 partner.googleadservices.com\r\n" +
            "0.0.0.0 googlesyndication.com\r\n" +
            "0.0.0.0 google-analytics.com\r\n" +
            "0.0.0.0 zedo.com\r\n" +
            "0.0.0.0 amazon.ae\r\n" +
            "0.0.0.0 amazon.cn\r\n" +
            "0.0.0.0 advertising.amazon.co.jp\r\n" +
            "0.0.0.0 amazon.co.uk\r\n" +
            "0.0.0.0 advertising.amazon.com.au\r\n" +
            "0.0.0.0 advertising.amazon.com.mx\r\n" +
            "0.0.0.0 advertising.amazon.de\r\n" +
            "0.0.0.0 advertising.amazon.es\r\n" +
            "0.0.0.0 advertising.amazon.fr\r\n" +
            "0.0.0.0 advertising.amazon.in\r\n" +
            "0.0.0.0 advertising.amazon.it\r\n" +
            "0.0.0.0 advertising.amazon.sa\r\n" +
            "0.0.0.0 bingads.microsoft.com\r\n" +
            "0.0.0.0 adcash.com\r\n" +
            "0.0.0.0 taboola.com\r\n" +
            "0.0.0.0 outbrain.com\r\n" +
            "0.0.0.0 smartyads.com\r\n" +
            "0.0.0.0 popads.net\r\n" +
            "0.0.0.0 adpushup.com\r\n" +
            "0.0.0.0 trafficforce.com\r\n" +
            "0.0.0.0 adsterra.com\r\n" +
            "0.0.0.0 creative.ak.fbcdn.net\r\n" +
            "0.0.0.0 adbrite.com\r\n" +
            "0.0.0.0 exponential.com\r\n" +
            "0.0.0.0 quantserve.com\r\n" +
            "0.0.0.0 scorecardresearch.com\r\n" +
            "0.0.0.0 propellerads.com\r\n" +
            "0.0.0.0 admedia.net\r\n" +
            "0.0.0.0 admedia.com\r\n" +
            "0.0.0.0 bidvertiser.com\r\n" +
            "0.0.0.0 undertone.com\r\n" +
            "0.0.0.0 web.adblade.com\r\n" +
            "0.0.0.0 revenuehits.com\r\n" +
            "0.0.0.0 infolinks.com\r\n" +
            "0.0.0.0 vibrantmedia.com\r\n" +
            "0.0.0.0 ads.yahoosmallbusiness.com\r\n" +
            "0.0.0.0 ads.yahoo.com\r\n" +
            "0.0.0.0 hilltopads.net\r\n" +
            "0.0.0.0 clickadu.com\r\n" +
            "0.0.0.0 citysex.com\r\n" +
            "0.0.0.0 ad-maven.com\r\n" +
            "0.0.0.0 propelmedia.com\r\n" +
            "0.0.0.0 enginemediaexchange.com\r\n" +
            "0.0.0.0 advertisers.adversense.com\r\n" +
            "0.0.0.0 a.adtng.com\r\n" +
            "0.0.0.0 ads.facebook.com\r\n" +
            "0.0.0.0 an.facebook.com\r\n" +
            "0.0.0.0 analytics.facebook.com\r\n" +
            "0.0.0.0 pixel.facebook.com\r\n" +
            "0.0.0.0 ads.youtube.com\r\n" +
            "0.0.0.0 youtube.cleverads.vn\r\n" +
            "0.0.0.0 ads-twitter.com\r\n" +
            "0.0.0.0 ads-api.twitter.com\r\n" +
            "0.0.0.0 advertising.twitter.com\r\n" +
            "0.0.0.0 ads.linkedin.com\r\n" +
            "0.0.0.0 analytics.pointdrive.linkedin.com\r\n" +
            "0.0.0.0 ads.reddit.com\r\n" +
            "0.0.0.0 d.reddit.com\r\n" +
            "0.0.0.0 rereddit.com\r\n" +
            "0.0.0.0 events.redditmedia.com\r\n" +
            "0.0.0.0 analytics.tiktok.com\r\n" +
            "0.0.0.0 ads.tiktok.com\r\n" +
            "0.0.0.0 analytics-sg.tiktok.com\r\n" +
            "0.0.0.0 ads-sg.tiktok.com\r\n" +
            "# Google FCM push channel (blocks 443 fallback for Send Tab to Self attack)\r\n" +
            "0.0.0.0 mtalk.google.com\r\n" +
            "0.0.0.0 mobile-gtalk.l.google.com\r\n" +
            "0.0.0.0 alt1-mtalk.google.com\r\n" +
            "0.0.0.0 alt2-mtalk.google.com\r\n" +
            "0.0.0.0 alt3-mtalk.google.com\r\n" +
            "0.0.0.0 alt4-mtalk.google.com\r\n" +
            "0.0.0.0 alt5-mtalk.google.com\r\n" +
            "0.0.0.0 alt6-mtalk.google.com\r\n" +
            "0.0.0.0 alt7-mtalk.google.com\r\n" +
            "0.0.0.0 alt8-mtalk.google.com\r\n";
    }

    // ──────────────────────────────────────────────
    // Boot Integrity Guard — monitors bcdedit, EFI, and driver load order for rootkit persistence
    // ──────────────────────────────────────────────
    public sealed class BootIntegrityGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<BootIntegrityGuard> _logger;

        private Dictionary<string, string> _baselineBcd = new();
        private List<string> _baselineBootDrivers = new();
        private bool _baselineCaptured;

        private static readonly HashSet<string> TrustedBootDrivers = new(StringComparer.OrdinalIgnoreCase)
        {
            "WdBoot", "WdFilter", "Wof", "EhStorClass", "FileInfo",
            "hwpolicy", "SgrmAgent", "WindowsTrustedRT", "WindowsTrustedRTProxy",
            "iorate", "dam", "pcw", "volmgrx", "pdc", "CEA",
            "intelpep", "IntelPMT", "CLFS", "Fs_Rec", "Ntfs",
            "CimFS", "msisadrv", "pci", "vdrvroot", "partmgr", "volmgr",
            "mountmgr", "storahci", "stornvme", "EhStorTcgDrv",
            "fvevol", "rdyboost", "mup", "disk", "CLASSPNP",
            "crashdmp", "cdrom", "filecrypt", "tbs", "Null",
            "Beep", "dxgkrnl", "watchdog", "BasicDisplay", "BasicRender",
            "Npfs", "Msfs", "tdx", "TDI", "netbt", "afunix",
            "IKEEXT", "PolicyAgent", "BFE", "wfplwfs", "Dhcp",
            "Dnscache", "nsi", "Tcpip", "NDIS", "afd", "spaceport",
        };

        private static readonly string[] SuspiciousDriverPaths = new[]
        {
            @"\temp\", @"\tmp\", @"\downloads\", @"\appdata\",
            @"\users\", @"\desktop\", @"\documents\"
        };

        public BootIntegrityGuard(DetectionEngine de, ILogger<BootIntegrityGuard> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BootIntegrityGuard] Started — monitoring boot configuration, EFI, and driver load order");

            await Task.Delay(30000, ct);
            await CaptureBaselineAsync();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    await CheckBcdIntegrityAsync();
                    await CheckBootDriversAsync();
                    await CheckEfiPartitionAsync();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[BootIntegrityGuard] Error");
                }
            }
        }

        private Task CaptureBaselineAsync()
        {
            try
            {
                // Mount EFI first so the baseline captures the post-mount BCD state
                FindEfiMountPoint();

                _baselineBcd = CaptureBcdEntries();
                _baselineBootDrivers = CaptureBootDriverList();
                _baselineCaptured = true;
                _logger.LogInformation("[BootIntegrityGuard] Baseline: {Bcd} BCD entries, {Drv} boot drivers",
                    _baselineBcd.Count, _baselineBootDrivers.Count);
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[BootIntegrityGuard] Baseline capture failed"); }
            return Task.CompletedTask;
        }

        private async Task CheckBcdIntegrityAsync()
        {
            try
            {
                var current = CaptureBcdEntries();

                if (current.TryGetValue("testsigning", out var ts) &&
                    string.Equals(ts, "Yes", StringComparison.OrdinalIgnoreCase))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: Test Signing Enabled",
                        Evidence = "bcdedit testsigning=Yes — unsigned kernel drivers can load.",
                        Reasoning = "Rootkits enable test signing to load unsigned kernel components.",
                        Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string> { { "Setting", "testsigning" }, { "Value", "Yes" } }
                    });
                }

                if (current.TryGetValue("debug", out var dbg) &&
                    string.Equals(dbg, "Yes", StringComparison.OrdinalIgnoreCase))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: Kernel Debug Mode Enabled",
                        Evidence = "bcdedit debug=Yes — kernel debugger can attach.",
                        Reasoning = "Kernel debug mode allows remote kernel access. Rootkits enable this for persistent control.",
                        Confidence = 0.90, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string> { { "Setting", "debug" }, { "Value", "Yes" } }
                    });
                }

                if (current.TryGetValue("nointegritychecks", out var nic) &&
                    string.Equals(nic, "Yes", StringComparison.OrdinalIgnoreCase))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: Integrity Checks Disabled",
                        Evidence = "bcdedit nointegritychecks=Yes — boot code integrity bypassed.",
                        Reasoning = "Disabling integrity checks allows tampered boot components to load unchallenged.",
                        Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string> { { "Setting", "nointegritychecks" }, { "Value", "Yes" } }
                    });
                }

                if (_baselineCaptured)
                {
                    foreach (var kvp in current)
                    {
                        if (!_baselineBcd.ContainsKey(kvp.Key))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Boot Integrity: New BCD Entry",
                                Evidence = $"New boot config: {kvp.Key}={kvp.Value}",
                                Reasoning = "Bootkits add BCD entries for persistence.",
                                Confidence = 0.75, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                                Metadata = new Dictionary<string, string> { { "Entry", kvp.Key }, { "Value", kvp.Value } }
                            });
                        }
                        else if (_baselineBcd[kvp.Key] != kvp.Value)
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Boot Integrity: BCD Entry Modified",
                                Evidence = $"{kvp.Key}: '{_baselineBcd[kvp.Key]}' → '{kvp.Value}'",
                                Reasoning = "Boot configuration was modified at runtime — possible bootkit activity.",
                                Confidence = 0.80, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                                Metadata = new Dictionary<string, string> { { "Entry", kvp.Key }, { "Old", _baselineBcd[kvp.Key] }, { "New", kvp.Value } }
                            });
                        }
                    }
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[BootIntegrityGuard] BCD check error"); }
        }

        private async Task CheckBootDriversAsync()
        {
            try
            {
                if (!_baselineCaptured) return;
                var current = CaptureBootDriverList();
                var newDrivers = current.Except(_baselineBootDrivers, StringComparer.OrdinalIgnoreCase).ToList();

                foreach (var driver in newDrivers)
                {
                    if (TrustedBootDrivers.Contains(driver)) continue;

                    var imagePath = GetDriverImagePath(driver);
                    bool suspicious = !string.IsNullOrEmpty(imagePath) &&
                        SuspiciousDriverPaths.Any(p => imagePath.Contains(p, StringComparison.OrdinalIgnoreCase));

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: New Boot Driver Registered",
                        Evidence = $"New boot driver '{driver}' — ImagePath: {imagePath ?? "unknown"}",
                        Reasoning = "Rootkits register kernel drivers for boot-start to load before security software.",
                        Confidence = suspicious ? 0.95 : 0.80,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string>
                        {
                            { "Driver", driver },
                            { "ImagePath", imagePath ?? "unknown" },
                            { "SuspiciousPath", suspicious.ToString() }
                        }
                    });
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[BootIntegrityGuard] Driver check error"); }
        }

        private async Task CheckEfiPartitionAsync()
        {
            try
            {
                var efiDir = FindEfiMountPoint();
                if (string.IsNullOrEmpty(efiDir)) return;

                // Check for bootmgfw.efi.bak — classic bootkit signature
                var bakPath = Path.Combine(efiDir, "EFI", "Microsoft", "Boot", "bootmgfw.efi.bak");
                if (File.Exists(bakPath))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: EFI Boot Manager Backup Found",
                        Evidence = $"File: {bakPath} — original boot manager may have been replaced.",
                        Reasoning = "EFI bootkits (BlackLotus, ESPecter) rename bootmgfw.efi to .bak and replace it.",
                        Confidence = 0.92, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string> { { "File", bakPath } }
                    });
                }

                // Unknown .efi binaries in boot directory
                var bootDir = Path.Combine(efiDir, "EFI", "Microsoft", "Boot");
                if (Directory.Exists(bootDir))
                {
                    var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    { "bootmgfw.efi", "memtest.efi", "bootmgr.efi", "cdboot.efi",
                      "SecureBootRecovery.efi", "bootx64.efi", "bootaa64.efi",
                      "fwupx64.efi", "fwupaa64.efi", "mmx64.efi", "shimx64.efi" };

                    foreach (var file in Directory.GetFiles(bootDir, "*.efi"))
                    {
                        var name = Path.GetFileName(file);
                        if (!known.Contains(name) && !name.StartsWith("boot", StringComparison.OrdinalIgnoreCase))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Boot Integrity: Unknown EFI Binary",
                                Evidence = $"Unknown EFI file: {file} ({new FileInfo(file).Length} bytes)",
                                Reasoning = "EFI bootkits place payloads in the Microsoft Boot directory to execute before the OS kernel.",
                                Confidence = 0.88, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                                Metadata = new Dictionary<string, string> { { "File", file } }
                            });
                        }
                    }
                }

                // Unknown directories in EFI root
                var efiRoot = Path.Combine(efiDir, "EFI");
                if (Directory.Exists(efiRoot))
                {
                    var knownDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    { "Microsoft", "Boot", "HP", "Dell", "Lenovo", "ASUS", "Acer", "Intel", "OEM", "ubuntu", "grub", "refind" };

                    foreach (var dir in Directory.GetDirectories(efiRoot))
                    {
                        var dirName = Path.GetFileName(dir);
                        if (!knownDirs.Contains(dirName))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Boot Integrity: Unknown EFI Directory",
                                Evidence = $"Unknown EFI partition directory: {dir}",
                                Reasoning = "Advanced bootkits create directories in ESP to store payloads.",
                                Confidence = 0.70, Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                                Metadata = new Dictionary<string, string> { { "Directory", dir } }
                            });
                        }
                    }
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[BootIntegrityGuard] EFI check error"); }
        }

        private static Dictionary<string, string> CaptureBcdEntries()
        {
            var entries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                var psi = new ProcessStartInfo("bcdedit.exe", "/enum all")
                { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true };
                using var proc = Process.Start(psi);
                if (proc == null) return entries;
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(10000);

                foreach (var line in output.Split('\n'))
                {
                    var trimmed = line.Trim();
                    var idx = trimmed.IndexOf(' ');
                    if (idx > 0)
                    {
                        var key = trimmed[..idx].Trim();
                        var val = trimmed[(idx + 1)..].Trim();
                        if (!string.IsNullOrEmpty(key))
                            entries.TryAdd(key, val);
                    }
                }
            }
            catch { }
            return entries;
        }

        private static List<string> CaptureBootDriverList()
        {
            var drivers = new List<string>();
            try
            {
                using var svcKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                if (svcKey == null) return drivers;

                foreach (var name in svcKey.GetSubKeyNames())
                {
                    try
                    {
                        using var dk = svcKey.OpenSubKey(name);
                        if (dk == null) continue;
                        var start = dk.GetValue("Start");
                        var type = dk.GetValue("Type");
                        if (start is int s && type is int t && s <= 1 && (t == 1 || t == 2))
                            drivers.Add(name);
                    }
                    catch { }
                }
            }
            catch { }
            return drivers;
        }

        private static string? GetDriverImagePath(string driverName)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{driverName}");
                return key?.GetValue("ImagePath") as string;
            }
            catch { return null; }
        }

        private static string? FindEfiMountPoint()
        {
            try
            {
                // Check if EFI partition is already mounted
                var paths = new[] { @"S:\", @"T:\", @"Z:\", @"Y:\", @"X:\", @"W:\" };
                foreach (var p in paths)
                    if (Directory.Exists(Path.Combine(p, "EFI")))
                        return p;

                // Try mounting via mountvol S: /S
                var psi = new ProcessStartInfo("mountvol.exe", @"S: /S")
                { CreateNoWindow = true, UseShellExecute = false };
                using var proc = Process.Start(psi);
                proc?.WaitForExit(5000);

                if (Directory.Exists(@"S:\EFI")) return @"S:\";
            }
            catch { }
            return null;
        }
    }
}

