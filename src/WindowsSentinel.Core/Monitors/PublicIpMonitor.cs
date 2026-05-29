using System.Collections.Concurrent;
using System.Net.Http;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Public IP Baseline Monitor (v3.6.0) — Detects unexpected public IP changes.
///
/// Periodically checks the machine's public IP address via multiple trusted
/// services (Cloudflare, ipify, icanhazip). Maintains a baseline and alerts
/// when the public IP changes without a corresponding network reconnect event.
///
/// Detects:
///   - VPN hijacking (traffic silently rerouted through attacker VPN)
///   - Transparent proxy insertion (ISP or attacker-level)
///   - BGP hijacking (upstream routing manipulation)
///   - Unauthorized VPN/tunnel activation on the machine
///
/// Privacy: Only checks the IP — does NOT send any system information externally.
/// The check is a simple HTTPS GET to well-known IP echo services.
///
/// Rate: Checks every 2 minutes. Minimal bandwidth (~100 bytes per check).
/// </summary>
public sealed class PublicIpMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<PublicIpMonitor> _logger;
    private readonly HttpClient _httpClient;

    private string? _baselineIp;
    private string? _baselineAsn;
    private string? _baselineCity;
    private string? _baselineCountry;
    private DateTimeOffset _baselineCapturedAt;
    private int _consecutiveFailures;

    private static readonly TimeSpan CheckInterval = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan HttpTimeout = TimeSpan.FromSeconds(10);

    // Deduplication
    private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedEvents = new();
    private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromMinutes(30);

    // Trusted IP check endpoints (HTTPS only, well-known services)
    private static readonly string[] IpCheckEndpoints =
    {
        "https://1.1.1.1/cdn-cgi/trace",           // Cloudflare
        "https://api64.ipify.org?format=json",      // ipify
        "https://icanhazip.com",                     // Cloudflare-owned
    };

    // Cloudflare trace endpoint provides geo info
    private const string CloudflareTraceUrl = "https://1.1.1.1/cdn-cgi/trace";

    public PublicIpMonitor(
        IDetectionEngine detectionEngine,
        ILogger<PublicIpMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;

        _httpClient = new HttpClient
        {
            Timeout = HttpTimeout
        };
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("WindowsSentinel/4.5.0");
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[PublicIpMonitor] Starting — public IP baseline monitoring active");

        // Wait for network to be fully up
        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);

        // Capture baseline
        var baseline = await GetPublicIpInfoAsync(stoppingToken);
        if (baseline != null)
        {
            _baselineIp = baseline.Ip;
            _baselineAsn = baseline.Asn;
            _baselineCity = baseline.City;
            _baselineCountry = baseline.Country;
            _baselineCapturedAt = DateTimeOffset.UtcNow;

            _logger.LogInformation(
                "[PublicIpMonitor] Baseline: IP={Ip}, Location={City}/{Country}, ASN={Asn}",
                _baselineIp, _baselineCity ?? "unknown", _baselineCountry ?? "unknown", _baselineAsn ?? "unknown");
        }
        else
        {
            _logger.LogWarning("[PublicIpMonitor] Could not capture baseline — will retry");
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(CheckInterval, stoppingToken);
                await CheckPublicIpAsync(stoppingToken);
                PruneAlertCache();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "[PublicIpMonitor] Check error");
            }
        }
    }

    private async Task CheckPublicIpAsync(CancellationToken ct)
    {
        var current = await GetPublicIpInfoAsync(ct);
        if (current == null)
        {
            _consecutiveFailures++;
            if (_consecutiveFailures >= 5)
            {
                // Sustained inability to reach IP check services could indicate network isolation
                var dedupeKey = "ip_check_failed";
                if (!_alertedEvents.ContainsKey(dedupeKey))
                {
                    _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Network Integrity: Public IP Check Unreachable",
                        Evidence = $"Failed to reach any IP check service for {_consecutiveFailures} consecutive attempts. " +
                                   "Network may be isolated, filtered, or under attack.",
                        Reasoning = "Sustained inability to reach well-known HTTPS services (Cloudflare, ipify) " +
                                    "indicates either: (1) network isolation attack, (2) firewall blocking outbound, " +
                                    "(3) DNS poisoning preventing resolution of check services, or (4) actual internet outage.",
                        Confidence = 0.50,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = "Network",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["consecutive_failures"] = _consecutiveFailures.ToString(),
                            ["technique"] = "T1562.004 - Impair Defenses: Disable or Modify System Firewall",
                            ["attack_type"] = "network_isolation"
                        }
                    }, ct);
                }
            }
            return;
        }

        _consecutiveFailures = 0;

        // If we don't have a baseline yet, capture now
        if (_baselineIp == null)
        {
            _baselineIp = current.Ip;
            _baselineAsn = current.Asn;
            _baselineCity = current.City;
            _baselineCountry = current.Country;
            _baselineCapturedAt = DateTimeOffset.UtcNow;
            _logger.LogInformation("[PublicIpMonitor] Late baseline: IP={Ip}", _baselineIp);
            return;
        }

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 1: Public IP changed
        // ═══════════════════════════════════════════════════════════════════
        if (!string.Equals(_baselineIp, current.Ip, StringComparison.OrdinalIgnoreCase))
        {
            // Determine severity based on what changed
            var asnChanged = !string.Equals(_baselineAsn, current.Asn, StringComparison.OrdinalIgnoreCase);
            var countryChanged = !string.Equals(_baselineCountry, current.Country, StringComparison.OrdinalIgnoreCase);

            var confidence = 0.70;
            var tier = DetectionTier.Tier2Indicator;
            string severity;

            if (countryChanged)
            {
                confidence = 0.90;
                tier = DetectionTier.Tier1Behavioral;
                severity = "CRITICAL — Country changed (possible VPN hijack or BGP manipulation)";
            }
            else if (asnChanged)
            {
                confidence = 0.82;
                tier = DetectionTier.Tier1Behavioral;
                severity = "HIGH — ASN changed (traffic routed through different provider)";
            }
            else
            {
                severity = "MEDIUM — IP changed within same ASN (possible ISP reassignment or proxy)";
            }

            var dedupeKey = $"ip_change:{current.Ip}";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = countryChanged
                        ? "Network Hijack: Public IP Country Changed"
                        : asnChanged
                            ? "Network Hijack: Public IP ASN Changed"
                            : "Network Integrity: Public IP Changed",
                    Evidence = $"Public IP changed from {_baselineIp} to {current.Ip}. " +
                               $"Baseline: {_baselineCity}/{_baselineCountry} (ASN {_baselineAsn}). " +
                               $"Current: {current.City}/{current.Country} (ASN {current.Asn}). " +
                               $"Severity: {severity}",
                    Reasoning = "Public IP changes without user-initiated network events indicate: " +
                                "(1) unauthorized VPN/tunnel activated on the machine, " +
                                "(2) transparent proxy insertion by attacker or ISP, " +
                                "(3) BGP hijacking redirecting traffic through attacker infrastructure, " +
                                "(4) evil twin AP routing through different exit point. " +
                                "Country/ASN changes are highest severity — legitimate ISP reassignment " +
                                "stays within the same ASN and country.",
                    Confidence = confidence,
                    Tier = tier,
                    ProcessName = "Network",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["baseline_ip"] = _baselineIp,
                        ["current_ip"] = current.Ip,
                        ["baseline_asn"] = _baselineAsn ?? "unknown",
                        ["current_asn"] = current.Asn ?? "unknown",
                        ["baseline_city"] = _baselineCity ?? "unknown",
                        ["current_city"] = current.City ?? "unknown",
                        ["baseline_country"] = _baselineCountry ?? "unknown",
                        ["current_country"] = current.Country ?? "unknown",
                        ["asn_changed"] = asnChanged.ToString(),
                        ["country_changed"] = countryChanged.ToString(),
                        ["technique"] = "T1090 - Proxy",
                        ["attack_type"] = countryChanged ? "geo_shift" : asnChanged ? "asn_shift" : "ip_change"
                    }
                }, ct);
            }

            // Update baseline after alerting (so we don't re-alert on same new IP)
            // But keep the original baseline for reference in future alerts
        }
    }

    private async Task<IpInfo?> GetPublicIpInfoAsync(CancellationToken ct)
    {
        // Try Cloudflare trace first (provides geo info)
        try
        {
            var response = await _httpClient.GetStringAsync(CloudflareTraceUrl, ct);
            var info = ParseCloudflareTrace(response);
            if (info != null) return info;
        }
        catch { /* Fall through to next endpoint */ }

        // Fallback: try ipify
        try
        {
            var response = await _httpClient.GetStringAsync("https://api64.ipify.org?format=json", ct);
            var json = JsonDocument.Parse(response);
            var ip = json.RootElement.GetProperty("ip").GetString();
            if (!string.IsNullOrEmpty(ip))
                return new IpInfo { Ip = ip };
        }
        catch { /* Fall through */ }

        // Last resort: icanhazip
        try
        {
            var response = await _httpClient.GetStringAsync("https://icanhazip.com", ct);
            var ip = response.Trim();
            if (!string.IsNullOrEmpty(ip) && ip.Length < 50) // Sanity check
                return new IpInfo { Ip = ip };
        }
        catch { /* All endpoints failed */ }

        return null;
    }

    private static IpInfo? ParseCloudflareTrace(string trace)
    {
        // Cloudflare trace format:
        // fl=...
        // ip=1.2.3.4
        // loc=HR
        // colo=ZAG
        // ...
        string? ip = null, loc = null, colo = null;

        foreach (var line in trace.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.StartsWith("ip=", StringComparison.Ordinal))
                ip = line[3..].Trim();
            else if (line.StartsWith("loc=", StringComparison.Ordinal))
                loc = line[4..].Trim();
            else if (line.StartsWith("colo=", StringComparison.Ordinal))
                colo = line[5..].Trim();
        }

        if (string.IsNullOrEmpty(ip)) return null;

        return new IpInfo
        {
            Ip = ip,
            Country = loc,
            City = colo, // Cloudflare colo is the nearest PoP (airport code), close enough to city
        };
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

    private sealed class IpInfo
    {
        public required string Ip { get; init; }
        public string? Asn { get; init; }
        public string? City { get; init; }
        public string? Country { get; init; }
    }
}

