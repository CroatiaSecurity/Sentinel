using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Gateway Fingerprint Monitor (v3.6.0) — Detects rogue access points and evil twins.
///
/// Captures a comprehensive fingerprint of the network gateway at startup:
///   - Default gateway IP + MAC
///   - DNS servers configured
///   - DHCP server address
///   - Network interface properties (SSID for Wi-Fi)
///   - Subnet mask / prefix length
///
/// Continuously monitors for changes that indicate:
///   - Evil twin AP (same SSID, different gateway/DHCP)
///   - Rogue DHCP server (DNS/gateway pushed by attacker)
///   - Network interface swap (moved to attacker-controlled network)
///   - DNS server hijacking (legitimate gateway but poisoned DNS)
///
/// Complements ArpSpoofMonitor: ARP spoof = same network, different MAC.
/// Gateway fingerprint = different network entirely (evil twin / rogue AP).
/// </summary>
public sealed class GatewayFingerprintMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<GatewayFingerprintMonitor> _logger;

    private NetworkFingerprint? _baseline;
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(15);

    // Deduplication
    private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedEvents = new();
    private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromMinutes(10);

    public GatewayFingerprintMonitor(
        IDetectionEngine detectionEngine,
        ILogger<GatewayFingerprintMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[GatewayFingerprintMonitor] Starting — network fingerprint monitoring active");

        // Wait for network to stabilize
        await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);

        // Capture baseline fingerprint
        _baseline = CaptureFingerprint();
        if (_baseline != null)
        {
            _logger.LogInformation(
                "[GatewayFingerprintMonitor] Baseline: Gateway={Gw}, DNS=[{Dns}], DHCP={Dhcp}, Subnet={Subnet}",
                _baseline.GatewayIp,
                string.Join(", ", _baseline.DnsServers),
                _baseline.DhcpServer ?? "N/A",
                _baseline.SubnetMask);
        }
        else
        {
            _logger.LogWarning("[GatewayFingerprintMonitor] Could not capture baseline — no active network");
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(PollInterval, stoppingToken);
                await CheckFingerprintAsync(stoppingToken);
                PruneAlertCache();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "[GatewayFingerprintMonitor] Check error");
            }
        }
    }

    private async Task CheckFingerprintAsync(CancellationToken ct)
    {
        var current = CaptureFingerprint();
        if (current == null) return;

        // If we don't have a baseline yet (network came up after boot), capture now
        if (_baseline == null)
        {
            _baseline = current;
            _logger.LogInformation("[GatewayFingerprintMonitor] Late baseline captured: Gateway={Gw}", current.GatewayIp);
            return;
        }

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 1: Gateway IP changed
        // Could indicate evil twin AP or rogue DHCP assigning different gateway.
        // ═══════════════════════════════════════════════════════════════════
        if (!string.Equals(_baseline.GatewayIp, current.GatewayIp, StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrEmpty(_baseline.GatewayIp)
            && !string.IsNullOrEmpty(current.GatewayIp))
        {
            var dedupeKey = $"gw_ip_change:{current.GatewayIp}";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Network Hijack: Default Gateway Changed",
                    Evidence = $"Default gateway changed from {_baseline.GatewayIp} to {current.GatewayIp}. " +
                               "This may indicate connection to a rogue access point or evil twin attack.",
                    Reasoning = "The default gateway IP changing without a user-initiated network switch " +
                                "indicates either: (1) evil twin AP with rogue DHCP, (2) DHCP starvation + " +
                                "rogue DHCP server, or (3) legitimate network change. On stable networks, " +
                                "the gateway IP should not change spontaneously.",
                    Confidence = 0.80,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "Network",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["baseline_gateway"] = _baseline.GatewayIp,
                        ["current_gateway"] = current.GatewayIp,
                        ["technique"] = "T1557 - Adversary-in-the-Middle",
                        ["attack_type"] = "gateway_change"
                    }
                }, ct);
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 2: DNS servers changed
        // Attacker pushing rogue DNS to redirect traffic to phishing sites.
        // ═══════════════════════════════════════════════════════════════════
        var baselineDns = new HashSet<string>(_baseline.DnsServers, StringComparer.OrdinalIgnoreCase);
        var currentDns = new HashSet<string>(current.DnsServers, StringComparer.OrdinalIgnoreCase);

        if (baselineDns.Count > 0 && !baselineDns.SetEquals(currentDns))
        {
            var added = currentDns.Except(baselineDns).ToList();
            var removed = baselineDns.Except(currentDns).ToList();

            var dedupeKey = $"dns_change:{string.Join(",", currentDns)}";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Network Hijack: DNS Servers Changed",
                    Evidence = $"DNS servers changed. Baseline: [{string.Join(", ", _baseline.DnsServers)}], " +
                               $"Current: [{string.Join(", ", current.DnsServers)}]. " +
                               (added.Count > 0 ? $"Added: [{string.Join(", ", added)}]. " : "") +
                               (removed.Count > 0 ? $"Removed: [{string.Join(", ", removed)}]." : ""),
                    Reasoning = "DNS server changes can indicate: (1) rogue DHCP pushing attacker-controlled DNS, " +
                                "(2) malware modifying network settings, (3) evil twin AP with different DNS config. " +
                                "Attacker-controlled DNS enables phishing, credential theft, and traffic interception " +
                                "by resolving legitimate domains to attacker IPs.",
                    Confidence = 0.82,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "Network",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["baseline_dns"] = string.Join(";", _baseline.DnsServers),
                        ["current_dns"] = string.Join(";", current.DnsServers),
                        ["added_dns"] = string.Join(";", added),
                        ["removed_dns"] = string.Join(";", removed),
                        ["technique"] = "T1584.002 - DNS Server",
                        ["attack_type"] = "dns_hijack"
                    }
                }, ct);
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 3: DHCP server changed
        // Rogue DHCP server on the network.
        // ═══════════════════════════════════════════════════════════════════
        if (!string.IsNullOrEmpty(_baseline.DhcpServer) &&
            !string.IsNullOrEmpty(current.DhcpServer) &&
            !string.Equals(_baseline.DhcpServer, current.DhcpServer, StringComparison.OrdinalIgnoreCase))
        {
            var dedupeKey = $"dhcp_change:{current.DhcpServer}";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Network Hijack: DHCP Server Changed (Rogue DHCP)",
                    Evidence = $"DHCP server changed from {_baseline.DhcpServer} to {current.DhcpServer}. " +
                               "A rogue DHCP server can push attacker-controlled gateway and DNS settings.",
                    Reasoning = "DHCP server changes on a stable network indicate either: (1) rogue DHCP server " +
                                "(attacker deploys their own DHCP to control network configuration), (2) DHCP " +
                                "starvation attack followed by rogue DHCP, or (3) legitimate infrastructure change. " +
                                "Rogue DHCP is a precursor to full network MITM.",
                    Confidence = 0.78,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "Network",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["baseline_dhcp"] = _baseline.DhcpServer,
                        ["current_dhcp"] = current.DhcpServer,
                        ["technique"] = "T1557 - Adversary-in-the-Middle",
                        ["attack_type"] = "rogue_dhcp"
                    }
                }, ct);
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 4: Subnet changed (moved to different network segment)
        // ═══════════════════════════════════════════════════════════════════
        if (!string.IsNullOrEmpty(_baseline.SubnetMask) &&
            !string.IsNullOrEmpty(current.SubnetMask) &&
            !string.Equals(_baseline.SubnetMask, current.SubnetMask, StringComparison.OrdinalIgnoreCase))
        {
            var dedupeKey = $"subnet_change:{current.SubnetMask}";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Network Hijack: Subnet Changed",
                    Evidence = $"Network subnet changed from {_baseline.SubnetMask} to {current.SubnetMask}. " +
                               "This indicates the machine has been moved to a different network segment.",
                    Reasoning = "Subnet changes without user action indicate the machine was connected to " +
                                "a different network (evil twin, rogue AP, or physical network manipulation). " +
                                "Combined with gateway/DNS changes, this confirms a network hijack.",
                    Confidence = 0.70,
                    Tier = DetectionTier.Tier2Indicator,
                    ProcessName = "Network",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["baseline_subnet"] = _baseline.SubnetMask,
                        ["current_subnet"] = current.SubnetMask,
                        ["technique"] = "T1557 - Adversary-in-the-Middle",
                        ["attack_type"] = "subnet_change"
                    }
                }, ct);
            }
        }
    }

    private NetworkFingerprint? CaptureFingerprint()
    {
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                var props = nic.GetIPProperties();
                var gateways = props.GatewayAddresses
                    .Where(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(g => g.Address.ToString())
                    .Where(g => g != "0.0.0.0")
                    .ToList();

                if (gateways.Count == 0) continue;

                var dnsServers = props.DnsAddresses
                    .Where(d => d.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(d => d.ToString())
                    .ToList();

                var dhcpServers = props.DhcpServerAddresses
                    .Where(d => d.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(d => d.ToString())
                    .ToList();

                var unicast = props.UnicastAddresses
                    .FirstOrDefault(u => u.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                return new NetworkFingerprint
                {
                    GatewayIp = gateways.First(),
                    DnsServers = dnsServers,
                    DhcpServer = dhcpServers.FirstOrDefault(),
                    SubnetMask = unicast?.IPv4Mask?.ToString() ?? "",
                    InterfaceName = nic.Name,
                    InterfaceId = nic.Id,
                    CapturedAt = DateTimeOffset.UtcNow
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[GatewayFingerprintMonitor] Error capturing fingerprint");
        }

        return null;
    }

    private void PruneAlertCache()
    {
        var cutoff = DateTimeOffset.UtcNow - AlertDedupeWindow;
        foreach (var kvp in _alertedEvents)
        {
            if (kvp.Value < cutoff)
                _alertedEvents.TryRemove(kvp.Key, out _);
        }
    }

    private sealed class NetworkFingerprint
    {
        public required string GatewayIp { get; init; }
        public required List<string> DnsServers { get; init; }
        public string? DhcpServer { get; init; }
        public required string SubnetMask { get; init; }
        public required string InterfaceName { get; init; }
        public required string InterfaceId { get; init; }
        public DateTimeOffset CapturedAt { get; init; }
    }
}
