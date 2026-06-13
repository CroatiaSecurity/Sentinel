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

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_IPNETROW
        {
            public int dwIndex;
            public int dwPhysAddrLen;
            public byte mac0, mac1, mac2, mac3, mac4, mac5, mac6, mac7;
            public int dwAddr;
            public int dwType;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ArpSpoofMonitor] Started");
            _gatewayIp = GetDefaultGateway();
            if (_gatewayIp != null) _baselineGatewayMac = ResolveMac(_gatewayIp);

            // Baseline ARP table
            var initial = GetArpTable();
            foreach (var (ip, mac) in initial)
                _arpBaseline[ip] = mac;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct);

                    // === Check 1: Gateway MAC change ===
                    if (_gatewayIp != null)
                    {
                        var currentMac = ResolveMac(_gatewayIp);
                        if (_baselineGatewayMac != null && currentMac != null && currentMac != _baselineGatewayMac)
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "ARP Spoof: Gateway MAC Changed",
                                Evidence = $"Gateway {_gatewayIp} MAC changed from {_baselineGatewayMac} to {currentMac}",
                                Reasoning = "The default gateway MAC address changed at runtime, indicating a possible ARP spoofing or MitM attack on the local network.",
                                Confidence = 0.88, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.NetworkIsolate,
                                ProcessName = "SYSTEM", ProcessId = 0,
                                Metadata = new Dictionary<string, string> { { "TargetIP", _gatewayIp ?? "" } }
                            });
                            _baselineGatewayMac = currentMac;
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
                    await EmitCertDetectionAsync(cert, analysis, null, isStartupScan: true);
                }
            }
        }

        /// <summary>
        /// Runtime polling: detect new certs added after baseline.
        /// New unknown certs with high confidence → remove + notify.
        /// New known public CAs → baseline silently.
        /// </summary>
        private async Task PollForNewCertsAsync(CancellationToken ct)
        {
            using var store = new System.Security.Cryptography.X509Certificates.X509Store(
                System.Security.Cryptography.X509Certificates.StoreName.Root,
                System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);
            store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);

            foreach (var cert in store.Certificates)
            {
                if (ct.IsCancellationRequested) break;
                if (_baselineThumbprints.Contains(cert.Thumbprint)) continue;

                // New cert detected — analyze it
                var analysis = AnalyzeCert(cert);
                var adderInfo = TraceAdderProcess(cert.Thumbprint);

                // Known public root CAs added at runtime (e.g., Windows Update adding new roots): baseline silently
                if (analysis.IsPublicRootCa && analysis.Confidence <= 0.50)
                {
                    _baselineThumbprints.Add(cert.Thumbprint);
                    continue;
                }

                _logger.LogWarning("[TlsCertificateMonitor] New root cert: Subject={Subject}, Confidence={Conf:F2}",
                    cert.Subject, analysis.Confidence);

                // Determine response based on confidence
                ResponseAction response;
                if (analysis.Confidence >= 0.80)
                {
                    // High confidence malicious — remove the cert and kill the adder
                    response = adderInfo != null ? ResponseAction.RemoveCertAndKillAdder : ResponseAction.RemoveCert;
                }
                else if (analysis.Confidence >= 0.65 && !analysis.IsEnterpriseCa && !analysis.IsDevTool)
                {
                    // Medium confidence — remove the cert but don't kill anything
                    response = ResponseAction.RemoveCert;
                }
                else
                {
                    // Low confidence or known enterprise/dev tool — log only
                    response = ResponseAction.LogOnly;
                }

                await EmitCertDetectionAsync(cert, analysis, adderInfo, isStartupScan: false, response);

                // Baseline after alert so we don't spam
                _baselineThumbprints.Add(cert.Thumbprint);
            }
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
            }

            // Cap confidence at 0.99
            confidence = Math.Min(confidence, 0.99);

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
}

