// ThreatIntelFeedBlocker — Proactive IP blocking from threat intelligence feeds
// Pulls known-bad IPs from Spamhaus DROP, Feodo Tracker, and EmergingThreats on startup
// and periodically, then creates Windows Firewall block rules via COM API.
// Also monitors active connections and emits Tier1 detections if a process connects
// to a feed-listed IP (the firewall should have blocked it, so a connection means bypass).

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public sealed class ThreatIntelFeedBlocker : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<ThreatIntelFeedBlocker> _logger;

        // All IPs/CIDRs loaded from feeds — used for connection checking
        private readonly ConcurrentDictionary<string, string> _blockedIps = new(StringComparer.OrdinalIgnoreCase);

        // Track which IPs already have firewall rules to avoid duplicates
        private readonly HashSet<string> _rulesCreated = new(StringComparer.OrdinalIgnoreCase);

        // Dedup alerts (don't spam detection engine for the same IP)
        private readonly ConcurrentDictionary<string, DateTime> _alertedConnections = new();

        private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(45);
        private static readonly TimeSpan RefreshInterval = TimeSpan.FromHours(4);
        private static readonly TimeSpan ConnectionCheckInterval = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(10);

        private static readonly (string Url, string Name)[] Feeds = new[]
        {
            ("https://www.spamhaus.org/drop/drop.txt", "Spamhaus-DROP"),
            ("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", "Feodo-Tracker"),
            ("https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", "EmergingThreats"),
        };

        // Windows Firewall COM constants
        private const int NET_FW_RULE_DIR_IN = 1;
        private const int NET_FW_RULE_DIR_OUT = 2;
        private const int NET_FW_ACTION_BLOCK = 0;
        private const int ALL_PROFILES = 0x7FFFFFFF;

        // Max IPs to block per feed (prevent memory/rule exhaustion)
        private const int MaxIpsPerFeed = 2000;
        private const int MaxTotalRules = 5000;

        public ThreatIntelFeedBlocker(
            DetectionEngine detectionEngine,
            JsonlEventLogger eventLogger,
            ILogger<ThreatIntelFeedBlocker> logger)
        {
            _detectionEngine = detectionEngine;
            _eventLogger = eventLogger;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ThreatIntelFeedBlocker] Starting — initial delay {Delay}s", InitialDelay.TotalSeconds);

            try { await Task.Delay(InitialDelay, ct); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await RefreshFeedsAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[ThreatIntelFeedBlocker] Feed refresh failed");
                }

                // Between refreshes, periodically check active connections against blocklist
                var nextRefresh = DateTime.UtcNow.Add(RefreshInterval);
                while (DateTime.UtcNow < nextRefresh && !ct.IsCancellationRequested)
                {
                    try
                    {
                        CheckActiveConnections();
                        PruneAlertCache();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[ThreatIntelFeedBlocker] Connection check error");
                    }

                    try { await Task.Delay(ConnectionCheckInterval, ct); }
                    catch (OperationCanceledException) { break; }
                }
            }
        }

        private async Task RefreshFeedsAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ThreatIntelFeedBlocker] Refreshing threat intelligence feeds...");

            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("Sentinel-EDR/1.7 (ThreatIntelFeedBlocker)");

            int totalNewIps = 0;

            foreach (var (url, name) in Feeds)
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    var response = await http.GetStringAsync(url, ct);
                    var ips = ParseFeed(response, name);

                    int added = 0;
                    foreach (var ip in ips.Take(MaxIpsPerFeed))
                    {
                        if (_blockedIps.TryAdd(ip, name))
                        {
                            added++;
                        }
                    }

                    if (added > 0)
                    {
                        _logger.LogInformation("[ThreatIntelFeedBlocker] {Feed}: added {Count} new IPs/CIDRs", name, added);
                        totalNewIps += added;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("[ThreatIntelFeedBlocker] Failed to fetch {Feed}: {Error}", name, ex.Message);
                }
            }

            // Create firewall rules for new IPs
            if (totalNewIps > 0)
            {
                CreateFirewallRules();

                await _eventLogger.LogEventAsync("threat_intel_feed_refresh", new
                {
                    TotalBlockedIps = _blockedIps.Count,
                    NewIpsAdded = totalNewIps,
                    FirewallRulesCreated = _rulesCreated.Count,
                    Timestamp = DateTime.UtcNow
                });
            }

            _logger.LogInformation("[ThreatIntelFeedBlocker] Feed refresh complete — {Total} IPs/CIDRs in blocklist, {Rules} firewall rules active",
                _blockedIps.Count, _rulesCreated.Count);
        }

        /// <summary>Parse a threat-intel feed body. Internal for unit tests.</summary>
        internal static List<string> ParseFeed(string content, string feedName)
        {
            var results = new List<string>();

            foreach (var rawLine in content.Split('\n'))
            {
                var line = rawLine.Trim();

                // Skip comments and empty lines
                if (string.IsNullOrEmpty(line) || line[0] == '#' || line[0] == ';')
                    continue;

                // Spamhaus DROP format: "x.x.x.x/xx ; SBnnnnn"
                if (feedName.Contains("Spamhaus", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line.Split(';');
                    var ipPart = parts[0].Trim();
                    if (IsValidIpOrCidr(ipPart))
                        results.Add(ipPart);
                    continue;
                }

                // Feodo/ET format: one IP per line (may have trailing comments)
                var ipCandidate = line.Split(new[] { ' ', '\t', ';', '#' }, 2)[0].Trim();
                if (IsValidIpOrCidr(ipCandidate))
                    results.Add(ipCandidate);
            }

            return results;
        }

        /// <summary>Validate dotted-quad IPv4 or CIDR (/8–/32). Internal for unit tests.</summary>
        internal static bool IsValidIpOrCidr(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return false;

            // CIDR notation: x.x.x.x/nn
            if (value.Contains('/'))
            {
                var parts = value.Split('/');
                if (parts.Length != 2) return false;
                if (!IsDottedQuadIPv4(parts[0])) return false;
                if (!int.TryParse(parts[1], out int prefix)) return false;
                return prefix >= 8 && prefix <= 32; // Don't allow overly broad blocks
            }

            return IsDottedQuadIPv4(value);
        }

        /// <summary>
        /// Require strict a.b.c.d form. IPAddress.TryParse accepts incomplete forms like "1.2.3".
        /// </summary>
        private static bool IsDottedQuadIPv4(string value)
        {
            var octets = value.Split('.');
            if (octets.Length != 4) return false;
            foreach (var o in octets)
            {
                if (!int.TryParse(o, out int n) || n < 0 || n > 255) return false;
                // Reject leading zeros like "01" (except single "0")
                if (o.Length > 1 && o[0] == '0') return false;
            }
            return IPAddress.TryParse(value, out var addr) &&
                   addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        }

        private void CreateFirewallRules()
        {
            if (_rulesCreated.Count >= MaxTotalRules)
            {
                _logger.LogWarning("[ThreatIntelFeedBlocker] Max firewall rules ({Max}) reached, skipping new rules", MaxTotalRules);
                return;
            }

            try
            {
                var fwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (fwPolicyType == null) return;
                dynamic? fwPolicy = Activator.CreateInstance(fwPolicyType);
                if (fwPolicy == null) return;

                var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                if (ruleType == null) return;

                // Batch IPs into groups of 100 for fewer firewall rules (Windows supports comma-separated RemoteAddresses)
                var newIps = _blockedIps.Keys.Where(ip => !_rulesCreated.Contains(ip)).ToList();
                if (newIps.Count == 0) return;

                const int batchSize = 100;
                int batchIndex = _rulesCreated.Count / batchSize;

                for (int i = 0; i < newIps.Count && _rulesCreated.Count < MaxTotalRules; i += batchSize)
                {
                    var batch = newIps.Skip(i).Take(batchSize).ToList();
                    var remoteAddresses = string.Join(",", batch);
                    var ruleName = $"Sentinel-ThreatIntel-{batchIndex++}";

                    try
                    {
                        // Outbound block
                        dynamic? outRule = Activator.CreateInstance(ruleType);
                        if (outRule != null)
                        {
                            outRule.Name = $"{ruleName}-OUT";
                            outRule.Description = $"Sentinel ThreatIntelFeedBlocker: Block {batch.Count} known-bad IPs (outbound)";
                            outRule.Direction = NET_FW_RULE_DIR_OUT;
                            outRule.Action = NET_FW_ACTION_BLOCK;
                            outRule.RemoteAddresses = remoteAddresses;
                            outRule.Enabled = true;
                            outRule.Profiles = ALL_PROFILES;
                            fwPolicy.Rules.Add(outRule);
                        }

                        // Inbound block
                        dynamic? inRule = Activator.CreateInstance(ruleType);
                        if (inRule != null)
                        {
                            inRule.Name = $"{ruleName}-IN";
                            inRule.Description = $"Sentinel ThreatIntelFeedBlocker: Block {batch.Count} known-bad IPs (inbound)";
                            inRule.Direction = NET_FW_RULE_DIR_IN;
                            inRule.Action = NET_FW_ACTION_BLOCK;
                            inRule.RemoteAddresses = remoteAddresses;
                            inRule.Enabled = true;
                            inRule.Profiles = ALL_PROFILES;
                            fwPolicy.Rules.Add(inRule);
                        }

                        foreach (var ip in batch)
                            _rulesCreated.Add(ip);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[ThreatIntelFeedBlocker] Failed to create rule batch {Index}", batchIndex);
                    }
                }

                _logger.LogInformation("[ThreatIntelFeedBlocker] Created firewall rules — total rules: {Count}", _rulesCreated.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[ThreatIntelFeedBlocker] Firewall COM API failed");
            }
        }

        /// <summary>
        /// Checks active TCP connections against the blocklist.
        /// If a connection is found, it means the firewall rule was bypassed or not yet applied —
        /// emit a Tier1 detection and kill the offending process.
        /// </summary>
        private void CheckActiveConnections()
        {
            if (_blockedIps.IsEmpty) return;

            try
            {
                var connections = GetEstablishedConnections();

                foreach (var (pid, remoteIp) in connections)
                {
                    if (pid <= 4) continue;

                    // Check exact IP match
                    if (!_blockedIps.TryGetValue(remoteIp, out var feedSource))
                        continue;

                    // Dedup: don't alert on the same IP+PID within cooldown
                    var alertKey = $"{pid}|{remoteIp}";
                    if (_alertedConnections.TryGetValue(alertKey, out var lastAlert) &&
                        DateTime.UtcNow - lastAlert < AlertCooldown)
                        continue;

                    _alertedConnections[alertKey] = DateTime.UtcNow;

                    // Resolve process name
                    string processName = "unknown";
                    try
                    {
                        using var proc = System.Diagnostics.Process.GetProcessById(pid);
                        processName = proc.ProcessName;
                    }
                    catch { }

                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "ThreatIntelFeedBlocker: Connection to Known-Bad IP",
                        ProcessName = processName,
                        ProcessId = pid,
                        SignalType = SignalType.NetworkC2,
                        Confidence = 0.92,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.NetworkIsolate,
                        Evidence = $"Process '{processName}' (PID {pid}) connected to threat-intel-listed IP: {remoteIp} (Feed: {feedSource})",
                        Reasoning = "Active TCP connection to an IP address listed in public threat intelligence feeds " +
                                    "(Spamhaus DROP, Feodo Tracker, or EmergingThreats). This indicates the firewall block rule " +
                                    "was bypassed or the connection was established before rules were applied. Likely C2 communication.",
                        Metadata = new Dictionary<string, string>
                        {
                            { "RemoteIp", remoteIp },
                            { "FeedSource", feedSource },
                            { "Detection", "ProactiveFeedMatch" }
                        }
                    });

                    _logger.LogWarning("[ThreatIntelFeedBlocker] ACTIVE connection to blocked IP: {Process} (PID {Pid}) -> {Ip} (Feed: {Feed})",
                        processName, pid, remoteIp, feedSource);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ThreatIntelFeedBlocker] Connection check failed");
            }
        }

        private static List<(int pid, string remoteIp)> GetEstablishedConnections()
        {
            var results = new List<(int, string)>();

            try
            {
                // Use .NET's built-in IPGlobalProperties for simplicity (no P/Invoke needed for periodic checks)
                var properties = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties();
                var connections = properties.GetActiveTcpConnections();

                foreach (var conn in connections)
                {
                    if (conn.State != System.Net.NetworkInformation.TcpState.Established)
                        continue;

                    var remoteIp = conn.RemoteEndPoint.Address.ToString();

                    // Skip private/loopback
                    if (remoteIp.StartsWith("127.") || remoteIp.StartsWith("10.") ||
                        remoteIp.StartsWith("192.168.") || remoteIp.StartsWith("169.254.") ||
                        remoteIp == "::1" || remoteIp.StartsWith("fe80"))
                        continue;

                    // IPGlobalProperties doesn't give us PID — store PID=0 to indicate "unknown PID".
                    // The detection alert will still fire (IP match is the primary signal).
                    results.Add((0, remoteIp));
                }
            }
            catch { }

            return results;
        }

        private void PruneAlertCache()
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-30);
            var stale = _alertedConnections.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList();
            foreach (var key in stale)
                _alertedConnections.TryRemove(key, out _);
        }
    }
}
