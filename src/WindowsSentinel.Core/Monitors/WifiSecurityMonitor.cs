using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Wi-Fi Security Monitor (v3.6.0) — Detects Wi-Fi attacks and insecure connections.
///
/// Monitors the wireless network state for:
///   1. Connection to open (unencrypted) networks — traffic visible to anyone nearby
///   2. Downgrade from WPA3/WPA2 to WEP or Open — possible deauth + evil twin
///   3. SSID changes without user action — possible evil twin AP
///   4. Frequent disconnections — possible deauthentication attack
///   5. Connection to networks with weak encryption (WEP)
///
/// Uses the native Windows WLAN API (wlanapi.dll) via netsh output parsing
/// for simplicity and reliability across Windows versions.
///
/// NOTE: Cannot detect deauth frames directly (requires monitor mode).
/// Instead detects the SYMPTOM: rapid disconnect/reconnect cycles.
/// </summary>
public sealed class WifiSecurityMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<WifiSecurityMonitor> _logger;

    // Baseline Wi-Fi state
    private string? _baselineSsid;
    private string? _baselineAuth;
    private string? _baselineBssid;

    // Disconnect tracking (deauth detection)
    private readonly Queue<DateTimeOffset> _disconnectTimes = new();
    private bool _wasConnected;

    // Deduplication
    private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedEvents = new();
    private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);

    // Deauth detection: X disconnects in Y seconds = attack
    private const int DeauthDisconnectThreshold = 4;
    private static readonly TimeSpan DeauthTimeWindow = TimeSpan.FromMinutes(2);

    public WifiSecurityMonitor(
        IDetectionEngine detectionEngine,
        ILogger<WifiSecurityMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[WifiSecurityMonitor] Starting — Wi-Fi security monitoring active");

        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);

        // Capture baseline
        var state = GetWifiState();
        if (state != null)
        {
            _baselineSsid = state.Ssid;
            _baselineAuth = state.Authentication;
            _baselineBssid = state.Bssid;
            _wasConnected = true;
            _logger.LogInformation(
                "[WifiSecurityMonitor] Baseline: SSID={Ssid}, Auth={Auth}, BSSID={Bssid}",
                state.Ssid, state.Authentication, state.Bssid);
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckWifiStateAsync(stoppingToken);
                PruneAlertCache();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "[WifiSecurityMonitor] Check error");
            }

            await Task.Delay(PollInterval, stoppingToken);
        }
    }

    private async Task CheckWifiStateAsync(CancellationToken ct)
    {
        var state = GetWifiState();

        // ═══════════════════════════════════════════════════════════════════
        // DISCONNECT TRACKING (deauth attack detection)
        // ═══════════════════════════════════════════════════════════════════
        if (_wasConnected && state == null)
        {
            // Just disconnected
            _disconnectTimes.Enqueue(DateTimeOffset.UtcNow);
            _wasConnected = false;

            // Prune old disconnect events
            while (_disconnectTimes.Count > 0 &&
                   DateTimeOffset.UtcNow - _disconnectTimes.Peek() > DeauthTimeWindow)
                _disconnectTimes.Dequeue();

            // Check for deauth pattern
            if (_disconnectTimes.Count >= DeauthDisconnectThreshold)
            {
                var dedupeKey = "deauth_attack";
                if (!_alertedEvents.ContainsKey(dedupeKey))
                {
                    _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Wi-Fi Attack: Deauthentication Flood Detected",
                        Evidence = $"Wi-Fi disconnected {_disconnectTimes.Count} times in " +
                                   $"{DeauthTimeWindow.TotalSeconds}s. This pattern indicates a " +
                                   "deauthentication attack (aireplay-ng, mdk3/mdk4).",
                        Reasoning = "Rapid Wi-Fi disconnections are the hallmark of a deauthentication " +
                                    "attack. Attackers send forged deauth frames to force the client off " +
                                    "the legitimate AP, then present an evil twin AP for the client to " +
                                    "reconnect to. This enables full traffic interception.",
                        Confidence = 0.85,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "WiFi",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["disconnect_count"] = _disconnectTimes.Count.ToString(),
                            ["window_seconds"] = DeauthTimeWindow.TotalSeconds.ToString(),
                            ["last_ssid"] = _baselineSsid ?? "unknown",
                            ["technique"] = "T1557 - Adversary-in-the-Middle",
                            ["attack_type"] = "wifi_deauth"
                        }
                    }, ct);
                }
            }
        }

        if (state == null)
        {
            _wasConnected = false;
            return;
        }

        _wasConnected = true;

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 1: Connected to open (unencrypted) network
        // ═══════════════════════════════════════════════════════════════════
        if (IsOpenNetwork(state.Authentication))
        {
            var dedupeKey = $"open_wifi:{state.Ssid}";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Wi-Fi Security: Connected to Open Network (No Encryption)",
                    Evidence = $"Connected to unencrypted Wi-Fi network: SSID='{state.Ssid}', " +
                               $"Auth={state.Authentication}, BSSID={state.Bssid}. " +
                               "All traffic is visible to anyone within radio range.",
                    Reasoning = "Open Wi-Fi networks provide zero encryption. Any device within range " +
                                "can capture all traffic (credentials, emails, browsing). This is also " +
                                "the typical state after a successful evil twin attack — the rogue AP " +
                                "doesn't require a password.",
                    Confidence = 0.75,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "WiFi",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["ssid"] = state.Ssid ?? "hidden",
                        ["authentication"] = state.Authentication ?? "unknown",
                        ["bssid"] = state.Bssid ?? "unknown",
                        ["technique"] = "T1040 - Network Sniffing",
                        ["attack_type"] = "open_wifi"
                    }
                }, ct);
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 2: Encryption downgrade (WPA2/3 → WEP or Open)
        // ═══════════════════════════════════════════════════════════════════
        if (_baselineAuth != null && state.Authentication != null &&
            string.Equals(_baselineSsid, state.Ssid, StringComparison.OrdinalIgnoreCase))
        {
            if (IsStrongAuth(_baselineAuth) && IsWeakAuth(state.Authentication))
            {
                var dedupeKey = $"auth_downgrade:{state.Ssid}";
                if (!_alertedEvents.ContainsKey(dedupeKey))
                {
                    _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Wi-Fi Attack: Encryption Downgrade (Possible Evil Twin)",
                        Evidence = $"Wi-Fi encryption downgraded on SSID '{state.Ssid}': " +
                                   $"was {_baselineAuth}, now {state.Authentication}. " +
                                   "Same SSID with weaker encryption = evil twin AP.",
                        Reasoning = "Connecting to the same SSID but with weaker encryption indicates " +
                                    "an evil twin attack. The attacker creates an AP with the same name " +
                                    "but without proper encryption, then deauths the client from the " +
                                    "legitimate AP. The client auto-reconnects to the stronger-signal " +
                                    "rogue AP.",
                        Confidence = 0.88,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "WiFi",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["ssid"] = state.Ssid ?? "unknown",
                            ["baseline_auth"] = _baselineAuth,
                            ["current_auth"] = state.Authentication,
                            ["technique"] = "T1557 - Adversary-in-the-Middle",
                            ["attack_type"] = "wifi_downgrade"
                        }
                    }, ct);
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 3: BSSID changed for same SSID (different AP — possible evil twin)
        // ═══════════════════════════════════════════════════════════════════
        if (_baselineBssid != null && state.Bssid != null &&
            string.Equals(_baselineSsid, state.Ssid, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(_baselineBssid, state.Bssid, StringComparison.OrdinalIgnoreCase))
        {
            var dedupeKey = $"bssid_change:{state.Ssid}:{state.Bssid}";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Wi-Fi Security: AP Changed (BSSID Mismatch)",
                    Evidence = $"Connected to SSID '{state.Ssid}' but BSSID changed from " +
                               $"{_baselineBssid} to {state.Bssid}. Different physical access point.",
                    Reasoning = "The BSSID (AP's MAC address) changed while connected to the same SSID. " +
                                "This can be legitimate (roaming between APs in enterprise) or indicate " +
                                "an evil twin attack (rogue AP with same SSID, different hardware). " +
                                "Combined with encryption downgrade or deauth events, this confirms an attack.",
                    Confidence = 0.55,
                    Tier = DetectionTier.Tier2Indicator,
                    ProcessName = "WiFi",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["ssid"] = state.Ssid ?? "unknown",
                        ["baseline_bssid"] = _baselineBssid,
                        ["current_bssid"] = state.Bssid,
                        ["technique"] = "T1557 - Adversary-in-the-Middle",
                        ["attack_type"] = "bssid_change"
                    }
                }, ct);
            }

            _baselineBssid = state.Bssid;
        }

        // Update baseline
        if (state.Ssid != null) _baselineSsid = state.Ssid;
        if (state.Authentication != null) _baselineAuth = state.Authentication;
    }

    private static WifiState? GetWifiState()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = "wlan show interfaces",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc == null) return null;

            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            if (string.IsNullOrWhiteSpace(output)) return null;
            if (!output.Contains("State", StringComparison.OrdinalIgnoreCase)) return null;

            // Check if connected
            if (!output.Contains("connected", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("disconnected", StringComparison.OrdinalIgnoreCase))
                return null;

            return new WifiState
            {
                Ssid = ExtractField(output, "SSID"),
                Bssid = ExtractField(output, "BSSID"),
                Authentication = ExtractField(output, "Authentication"),
                Cipher = ExtractField(output, "Cipher"),
                Channel = ExtractField(output, "Channel"),
                Signal = ExtractField(output, "Signal"),
            };
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractField(string output, string fieldName)
    {
        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith(fieldName, StringComparison.OrdinalIgnoreCase) &&
                trimmed.Contains(':'))
            {
                var value = trimmed[(trimmed.IndexOf(':') + 1)..].Trim();
                return string.IsNullOrEmpty(value) ? null : value;
            }
        }
        return null;
    }

    private static bool IsOpenNetwork(string? auth)
    {
        if (string.IsNullOrEmpty(auth)) return false;
        var lower = auth.ToLowerInvariant();
        return lower.Contains("open") || lower == "none";
    }

    private static bool IsWeakAuth(string? auth)
    {
        if (string.IsNullOrEmpty(auth)) return false;
        var lower = auth.ToLowerInvariant();
        return lower.Contains("open") || lower.Contains("wep") || lower == "none";
    }

    private static bool IsStrongAuth(string? auth)
    {
        if (string.IsNullOrEmpty(auth)) return false;
        var lower = auth.ToLowerInvariant();
        return lower.Contains("wpa2") || lower.Contains("wpa3") || lower.Contains("rsna");
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

    private sealed class WifiState
    {
        public string? Ssid { get; init; }
        public string? Bssid { get; init; }
        public string? Authentication { get; init; }
        public string? Cipher { get; init; }
        public string? Channel { get; init; }
        public string? Signal { get; init; }
    }
}
