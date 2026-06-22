using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Monitors DNS queries for beaconing/tunneling behavior.
    /// 
    /// Previously used ETW (Microsoft-Windows-DNS-Client) via TraceEvent.
    /// Now uses Windows DNS Client event log + periodic polling as telemetry source
    /// to avoid embedding TraceEvent's injection API strings in the binary.
    /// 
    /// Detects:
    /// - Rapid query volume to single domains (beaconing/tunneling)
    /// - High-entropy domain names (DGA — domain generation algorithms)
    /// </summary>
    public sealed class DnsQueryMonitor : IMonitor
    {
        public string Name => "DnsQueryMonitor";

        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DnsQueryMonitor> _logger;
        private readonly PersistentConnectionMonitor? _persistentConnMon;
        private CancellationTokenSource? _cts;
        private Task? _monitorTask;

        private readonly ConcurrentDictionary<string, DomainStats> _domainStats = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(15);
        private const int RapidQueryThreshold = 50;
        private const double EntropyThreshold = 4.0;

        private static readonly HashSet<string> TrustedBaseDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            "microsoft.com", "windows.com", "windowsupdate.com", "azure.com",
            "office.com", "office365.com", "live.com", "msn.com", "bing.com",
            "google.com", "googleapis.com", "gstatic.com", "googlevideo.com",
            "youtube.com", "ytimg.com", "googleusercontent.com",
            "cloudflare.com", "cloudflare-dns.com", "cloudfront.net",
            "amazonaws.com", "aws.amazon.com",
            "github.com", "githubusercontent.com", "github.io",
            "steam-chat.com", "steamcontent.com", "steampowered.com", "steamstatic.com",
            "discord.com", "discord.gg", "discordapp.com",
            "spotify.com", "scdn.co",
            "azurefd.net", "akamai.net", "akamaized.net",
            "wpad", "local", "localhost", "mshome.net",
            "gorstak.eu",
        };

        private static readonly HashSet<string> LocalHostNames = BuildLocalHostNames();

        private static HashSet<string> BuildLocalHostNames()
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "localhost", "wpad" };
            try { names.Add(Dns.GetHostName()); } catch { }
            try { names.Add(Environment.MachineName); } catch { }
            return names;
        }

        public DnsQueryMonitor(
            DetectionEngine detectionEngine,
            ILogger<DnsQueryMonitor> logger,
            PersistentConnectionMonitor? persistentConnMon = null)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _persistentConnMon = persistentConnMon;
        }

        public Task StartAsync(CancellationToken ct)
        {
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            _monitorTask = Task.Run(() => PollLoop(_cts.Token), _cts.Token);
            _logger.LogInformation("[{Monitor}] Started (event log polling mode)", Name);
            return Task.CompletedTask;
        }

        private async Task PollLoop(CancellationToken ct)
        {
            // Monitor DNS Client event log (Event ID 3006 = DNS query completed)
            long lastRecordId = 0;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(PollInterval, ct);
                    PruneStats();

                    // Read recent DNS Client Operational log events
                    try
                    {
                        using var eventLog = new EventLog("Microsoft-Windows-DNS Client Events/Operational");
                        foreach (EventLogEntry entry in eventLog.Entries)
                        {
                            if (entry.Index <= lastRecordId) continue;
                            lastRecordId = entry.Index;

                            if (entry.InstanceId == 3006 || entry.InstanceId == 3008)
                            {
                                var domain = entry.Message?.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                    .FirstOrDefault()?.Trim() ?? "";
                                if (!string.IsNullOrEmpty(domain))
                                {
                                    ProcessDnsQuery(domain, 0);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[{Monitor}] DNS event log read failed, using cache-based detection only", Name);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[{Monitor}] Poll error", Name);
                }
            }
        }

        private void ProcessDnsQuery(string domain, int pid)
        {
            if (string.IsNullOrWhiteSpace(domain)) return;
            if (LocalHostNames.Contains(domain)) return;

            var baseDomain = GetBaseDomain(domain);
            if (TrustedBaseDomains.Contains(baseDomain)) return;

            _persistentConnMon?.RecordDnsQuery(pid, domain);

            var stats = _domainStats.GetOrAdd(baseDomain, _ => new DomainStats());
            stats.QueryCount++;
            stats.LastSeen = DateTime.UtcNow;

            // Rapid query volume detection
            if (stats.QueryCount >= RapidQueryThreshold && !stats.Alerted)
            {
                stats.Alerted = true;
                _ = _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "DNS: Rapid Query Volume (Beaconing/Tunneling)",
                    Evidence = $"Base domain '{baseDomain}' received {stats.QueryCount} queries in current window",
                    Reasoning = "An abnormally high volume of DNS queries to a single base domain was detected, consistent with DNS tunneling or C2 beaconing.",
                    Confidence = 0.75,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "SYSTEM", ProcessId = pid
                });
            }

            // DGA detection via entropy
            var labels = domain.Split('.');
            if (labels.Length > 2)
            {
                var subdomain = labels[0];
                if (subdomain.Length > 12 && CalculateEntropy(subdomain) > EntropyThreshold)
                {
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "DNS: High-Entropy Subdomain (DGA Indicator)",
                        Evidence = $"Domain '{domain}' has high-entropy subdomain (entropy={CalculateEntropy(subdomain):F2})",
                        Reasoning = "The queried domain contains a high-entropy subdomain label, consistent with domain generation algorithms used by malware to evade domain blocklists.",
                        Confidence = 0.65,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = "SYSTEM", ProcessId = pid
                    });
                }
            }
        }

        private void PruneStats()
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-5);
            foreach (var key in _domainStats.Keys.ToList())
            {
                if (_domainStats.TryGetValue(key, out var stats) && stats.LastSeen < cutoff)
                    _domainStats.TryRemove(key, out _);
            }
        }

        private static double CalculateEntropy(string s)
        {
            var freq = new Dictionary<char, int>();
            foreach (var c in s) { freq[c] = freq.GetValueOrDefault(c) + 1; }
            double entropy = 0;
            foreach (var count in freq.Values)
            {
                double p = (double)count / s.Length;
                entropy -= p * Math.Log2(p);
            }
            return entropy;
        }

        private static string GetBaseDomain(string domain)
        {
            var parts = domain.TrimEnd('.').Split('.');
            return parts.Length >= 2 ? $"{parts[^2]}.{parts[^1]}" : domain;
        }

        public Task StopAsync()
        {
            _cts?.Cancel();
            _logger.LogInformation("[{Monitor}] Stopped", Name);
            return Task.CompletedTask;
        }

        private class DomainStats
        {
            public int QueryCount;
            public DateTime LastSeen = DateTime.UtcNow;
            public bool Alerted;
        }
    }
}
