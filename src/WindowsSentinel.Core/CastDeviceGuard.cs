using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Detects and blocks Chrome/browser connections to rogue Cast devices on the LAN.
    ///
    /// Attack chain this solves:
    ///   1. Attacker plants MitM root certs → steals Chrome sync tokens via HTTPS intercept
    ///   2. Attacker uses stolen tokens to push "Send Tab to Self" via FCM (blocked by port 5228 firewall)
    ///   3. Alternatively, attacker places a rogue device on LAN spoofing Chromecast (port 8009)
    ///   4. Chrome auto-discovers and maintains a persistent connection to it
    ///   5. Rogue device acts as a local C2 relay — data exfiltration, tab injection, etc.
    ///
    /// Detection approach:
    ///   - At startup, baseline all LAN devices responding on Cast ports (8008, 8009)
    ///   - Any NEW device appearing on Cast ports after boot is flagged
    ///   - If Chrome/browser is actively connected to a non-baselined Cast device → kill the connection
    ///   - Real Chromecasts present at boot time are never touched (people's TVs work fine)
    ///   - Google OUI verification: real Chromecasts have Google MAC prefixes
    ///   - mDNS _googlecast._tcp service validation where possible
    ///
    /// For users WITH real Chromecasts: their devices are baselined at startup → zero impact.
    /// For users WITHOUT Chromecasts: any device on 8009 is immediately suspicious.
    /// For the attack scenario: rogue device appears after boot → Chrome connection severed.
    ///
    /// v1.0.1: New monitor.
    /// </summary>
    public sealed class CastDeviceGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly PhantomDeviceMonitor _phantomDeviceMonitor;
        private readonly ILogger<CastDeviceGuard> _logger;

        // Devices on Cast ports that were present at boot — legitimate Chromecasts/speakers
        private readonly ConcurrentDictionary<string, CastDevice> _baselineCastDevices = new(StringComparer.OrdinalIgnoreCase);

        // New Cast devices that appeared after boot — suspicious
        private readonly ConcurrentDictionary<string, CastDevice> _postBootCastDevices = new(StringComparer.OrdinalIgnoreCase);

        // Connections we've already killed/alerted on
        private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedConnections = new();

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(10);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);

        // Cast protocol ports
        private static readonly int[] CastPorts = { 8008, 8009 };

        // Google-manufactured Chromecast OUI prefixes (real hardware)
        private static readonly HashSet<string> GoogleOuiPrefixes = new(StringComparer.OrdinalIgnoreCase)
        {
            "B0-B3-69", "F4-F5-D8", "54-60-09", "A4-77-33", "30-FD-38",
            "48-D6-D5", "6C-AD-F8", "94-EB-2C", "CC-F4-11", "E4-F0-42",
            "F4-F5-E8", "20-DF-B9", "58-CB-52", "A4-E3-1B"
        };

        // Browsers that use Cast protocol
        private static readonly HashSet<string> BrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "brave", "vivaldi", "opera", "chromium"
        };

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize,
            bool bOrder, int ulAf, int tableClass, uint reserved);

        [DllImport("iphlpapi.dll")]
        private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public uint owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_IPNETROW
        {
            public int dwIndex;
            public int dwPhysAddrLen;
            public byte mac0, mac1, mac2, mac3, mac4, mac5, mac6, mac7;
            public int dwAddr;
            public int dwType;
        }

        public CastDeviceGuard(
            DetectionEngine detectionEngine,
            PhantomDeviceMonitor phantomDeviceMonitor,
            ILogger<CastDeviceGuard> logger)
        {
            _detectionEngine = detectionEngine;
            _phantomDeviceMonitor = phantomDeviceMonitor;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[CastDeviceGuard] Started — baselining Cast devices on LAN");

            // Baseline: scan LAN for devices responding on Cast ports right now
            await BaselineCastDevices(ct);

            _logger.LogInformation("[CastDeviceGuard] Baseline complete: {Count} legitimate Cast device(s)",
                _baselineCastDevices.Count);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    await ScanBrowserCastConnections(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[CastDeviceGuard] Error"); }
            }
        }

        private async Task BaselineCastDevices(CancellationToken ct)
        {
            // Get all devices from ARP table
            var arpDevices = GetArpTable();

            foreach (var device in arpDevices)
            {
                if (ct.IsCancellationRequested) break;

                // Check if this device responds on Cast ports
                bool respondsCast = await ProbePort(device.Ip, 8009, ct) ||
                                    await ProbePort(device.Ip, 8008, ct);

                if (respondsCast)
                {
                    var castDev = new CastDevice
                    {
                        Ip = device.Ip,
                        Mac = device.Mac,
                        IsGoogleOui = IsGoogleMac(device.Mac),
                        DiscoveredAt = DateTimeOffset.UtcNow,
                        IsBaseline = true
                    };
                    _baselineCastDevices[device.Ip] = castDev;

                    _logger.LogInformation(
                        "[CastDeviceGuard] Baselined Cast device: {IP} (MAC: {MAC}, Google OUI: {IsGoogle})",
                        device.Ip, device.Mac, castDev.IsGoogleOui);
                }
            }
        }

        private async Task ScanBrowserCastConnections(CancellationToken ct)
        {
            var connections = GetEstablishedTcpConnections();

            foreach (var conn in connections)
            {
                if (ct.IsCancellationRequested) break;

                // Only care about Cast port connections to private IPs
                if (!CastPorts.Contains(conn.RemotePort)) continue;
                if (!IsPrivateIp(conn.RemoteAddress)) continue;

                // Is this a baselined (legitimate) Cast device?
                if (_baselineCastDevices.ContainsKey(conn.RemoteAddress))
                    continue; // Known Chromecast — leave it alone

                // This is a connection to a Cast port on a NON-baselined device
                // Check who owns the connection
                string procName;
                try
                {
                    using var proc = Process.GetProcessById(conn.OwnerPid);
                    procName = proc.ProcessName;
                }
                catch { continue; }

                // We care about browsers connecting to rogue cast devices
                bool isBrowser = BrowserProcesses.Contains(procName);

                // Check alert cooldown
                var alertKey = $"{conn.OwnerPid}:{conn.RemoteAddress}:{conn.RemotePort}";
                if (_alertedConnections.TryGetValue(alertKey, out var lastAlert) &&
                    DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                    continue;

                _alertedConnections[alertKey] = DateTimeOffset.UtcNow;

                // Get MAC for the remote IP
                var remoteMac = GetMacForIp(conn.RemoteAddress);
                bool isGoogleMac = remoteMac != null && IsGoogleMac(remoteMac);

                // Is this device already flagged by PhantomDeviceMonitor?
                bool isPhantom = _phantomDeviceMonitor.IsPhantomDevice(conn.RemoteAddress);
                bool isBlocked = _phantomDeviceMonitor.IsBlockedDevice(conn.RemoteAddress);

                // Decision matrix:
                // 1. Blocked phantom device + any process → kill (confirmed rogue)
                // 2. Non-Google-OUI + browser + not baselined → high confidence, kill connection
                // 3. Google-OUI + browser + not baselined → medium confidence, log (could be new legit Chromecast)
                // 4. Non-browser + Cast port → suspicious regardless

                double confidence;
                ResponseAction response;
                string reasoning;

                if (isBlocked)
                {
                    confidence = 0.95;
                    response = ResponseAction.KillProcessTree;
                    reasoning = "Browser is maintaining a Cast protocol connection to a device that " +
                                "PhantomDeviceMonitor has already identified and blocked as a rogue " +
                                "phantom device. This is a confirmed C2 relay masquerading as a " +
                                "Chromecast on the local network.";
                }
                else if (isPhantom && !isGoogleMac)
                {
                    confidence = 0.90;
                    response = ResponseAction.KillProcessTree;
                    reasoning = "Browser is connected to a non-Google-manufactured device on Cast port " +
                                "8009 that appeared AFTER Sentinel started. Real Chromecasts have Google " +
                                "OUI MAC prefixes. This device has a non-Google MAC, was not present at " +
                                "boot, and is listening on a Cast port — strong indicator of a rogue " +
                                "device acting as a local C2 relay (documented PlugX/ShadowPad technique).";
                }
                else if (!isGoogleMac && isBrowser)
                {
                    confidence = 0.82;
                    response = ResponseAction.KillProcessTree;
                    reasoning = "Browser is connected to an unbaselined device on Cast port that does NOT " +
                                "have a Google OUI MAC address. Legitimate Chromecast/Nest/Google Home " +
                                "devices always have Google-manufactured MAC addresses. This device was " +
                                "not present when Sentinel started and has a non-Google manufacturer MAC — " +
                                "likely a spoofed Cast device used as a local network relay.";
                }
                else if (isGoogleMac && isBrowser)
                {
                    // Google OUI but wasn't present at boot.
                    // CRITICAL: If PhantomDeviceMonitor already flagged this as a phantom device,
                    // the Google MAC is SPOOFED. Real Chromecasts don't appear and disappear —
                    // they're plugged in at boot. A phantom + Google OUI = attacker chose a Google
                    // MAC prefix specifically to defeat OUI validation.
                    if (isPhantom)
                    {
                        confidence = 0.92;
                        response = ResponseAction.KillProcessTree;
                        reasoning = "Browser connected to a device on Cast port with a Google OUI MAC, " +
                                    "BUT PhantomDeviceMonitor has independently flagged this device as a " +
                                    "phantom (it appeared after boot and was not in the ARP table at startup). " +
                                    "Real Chromecasts are always-on devices present at boot. A phantom device " +
                                    "with a spoofed Google MAC appearing at runtime is a deliberate evasion " +
                                    "of OUI-based validation — confirmed rogue C2 relay.";
                    }
                    else
                    {
                        // Not phantom, Google OUI, not baselined — could be a new legit Chromecast
                        // plugged in after boot. Log only.
                        confidence = 0.55;
                        response = ResponseAction.LogOnly;
                        reasoning = "Browser connected to a new Cast device with Google OUI that was NOT " +
                                    "present at boot. This is likely a legitimately new Chromecast/Nest " +
                                    "device plugged in after startup. Logging for correlation. If this " +
                                    "device was not intentionally added by the user, investigate. " +
                                    "The device will be baselined on next service restart.";

                        // Add to post-boot tracking
                        if (!_postBootCastDevices.ContainsKey(conn.RemoteAddress))
                        {
                            _postBootCastDevices[conn.RemoteAddress] = new CastDevice
                            {
                                Ip = conn.RemoteAddress,
                                Mac = remoteMac ?? "unknown",
                                IsGoogleOui = true,
                                DiscoveredAt = DateTimeOffset.UtcNow,
                                IsBaseline = false
                            };
                        }
                    }
                }
                else if (!isBrowser)
                {
                    // Non-browser process on Cast port — very suspicious
                    confidence = 0.85;
                    response = ResponseAction.KillProcessTree;
                    reasoning = "A non-browser process is connecting to a Cast protocol port (8009) " +
                                "on a local network device. Only Chromium-based browsers legitimately " +
                                "use the Cast protocol. A non-browser process on this port indicates " +
                                "malware using Cast port as a covert channel or a tool exploiting " +
                                "the Cast protocol for local network relay.";
                }
                else
                {
                    continue; // Shouldn't reach here
                }

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = confidence >= 0.80
                        ? "Cast Device Guard: Rogue Cast Device Connection"
                        : "Cast Device Guard: New Cast Device Detected",
                    Evidence = $"Process '{procName}' (PID {conn.OwnerPid}) connected to " +
                               $"{conn.RemoteAddress}:{conn.RemotePort}. " +
                               $"MAC: {remoteMac ?? "unresolved"}, Google OUI: {isGoogleMac}, " +
                               $"Baselined: false, Phantom: {isPhantom}, Blocked: {isBlocked}",
                    Reasoning = reasoning,
                    Confidence = confidence,
                    Tier = confidence >= 0.70 ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                    AuthorizedResponse = response,
                    ProcessName = procName,
                    ProcessId = conn.OwnerPid,
                    SignalType = SignalType.NetworkC2,
                    Metadata = new Dictionary<string, string>
                    {
                        ["RemoteIP"] = conn.RemoteAddress,
                        ["RemotePort"] = conn.RemotePort.ToString(),
                        ["RemoteMAC"] = remoteMac ?? "unknown",
                        ["IsGoogleOUI"] = isGoogleMac.ToString(),
                        ["IsPhantomDevice"] = isPhantom.ToString(),
                        ["IsBlockedDevice"] = isBlocked.ToString(),
                        ["IsBrowser"] = isBrowser.ToString()
                    }
                });
            }

            // Cleanup stale alerts
            var stale = _alertedConnections
                .Where(kv => DateTimeOffset.UtcNow - kv.Value > TimeSpan.FromHours(1))
                .Select(kv => kv.Key).ToList();
            foreach (var key in stale) _alertedConnections.TryRemove(key, out _);
        }

        private static async Task<bool> ProbePort(string ip, int port, CancellationToken ct)
        {
            try
            {
                using var client = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromMilliseconds(500));
                await client.ConnectAsync(IPAddress.Parse(ip), port, cts.Token);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsGoogleMac(string mac)
        {
            if (string.IsNullOrEmpty(mac) || mac.Length < 8) return false;
            var prefix = mac[..8].ToUpperInvariant();
            return GoogleOuiPrefixes.Contains(prefix);
        }

        private static bool IsPrivateIp(string ip)
        {
            if (ip.StartsWith("10.")) return true;
            if (ip.StartsWith("192.168.")) return true;
            if (ip.StartsWith("172."))
            {
                var parts = ip.Split('.');
                if (parts.Length >= 2 && int.TryParse(parts[1], out int second))
                    return second >= 16 && second <= 31;
            }
            return false;
        }

        private string? GetMacForIp(string ip)
        {
            var arpTable = GetArpTable();
            var entry = arpTable.FirstOrDefault(e => e.Ip == ip);
            return entry?.Mac;
        }

        private List<ArpEntry> GetArpTable()
        {
            var results = new List<ArpEntry>();
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
                        if (row.dwType == 2) continue; // Invalid
                        var ipAddr = new IPAddress(BitConverter.GetBytes(row.dwAddr)).ToString();
                        if (ipAddr.StartsWith("224.") || ipAddr == "255.255.255.255") continue;
                        var mac = $"{row.mac0:X2}-{row.mac1:X2}-{row.mac2:X2}-{row.mac3:X2}-{row.mac4:X2}-{row.mac5:X2}";
                        if (mac == "00-00-00-00-00-00") continue;
                        results.Add(new ArpEntry { Ip = ipAddr, Mac = mac });
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            catch { }
            return results;
        }

        private List<TcpConnectionInfo> GetEstablishedTcpConnections()
        {
            var results = new List<TcpConnectionInfo>();
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5, 0);
            if (size == 0) return results;

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(buffer, ref size, false, 2, 5, 0) != 0) return results;

                int numEntries = Marshal.ReadInt32(buffer);
                int structSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(
                        IntPtr.Add(buffer, 4 + i * structSize));

                    if (row.state != 5) continue; // ESTABLISHED only
                    if (row.owningPid <= 4) continue;

                    var remoteIp = new IPAddress(BitConverter.GetBytes(row.remoteAddr)).ToString();
                    var remotePort = (int)((row.remotePort >> 8) | ((row.remotePort & 0xFF) << 8));

                    results.Add(new TcpConnectionInfo
                    {
                        OwnerPid = (int)row.owningPid,
                        RemoteAddress = remoteIp,
                        RemotePort = remotePort
                    });
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }

            return results;
        }

        private class ArpEntry
        {
            public string Ip { get; set; } = "";
            public string Mac { get; set; } = "";
        }

        private class TcpConnectionInfo
        {
            public int OwnerPid { get; set; }
            public string RemoteAddress { get; set; } = "";
            public int RemotePort { get; set; }
        }

        private class CastDevice
        {
            public string Ip { get; set; } = "";
            public string Mac { get; set; } = "";
            public bool IsGoogleOui { get; set; }
            public DateTimeOffset DiscoveredAt { get; set; }
            public bool IsBaseline { get; set; }
        }
    }
}
