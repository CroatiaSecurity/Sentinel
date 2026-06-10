using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Monitors DNS queries via ETW (Microsoft-Windows-DNS-Client) for behavioral anomalies:
    /// - DGA-like domain patterns (high entropy, unusual length)
    /// - DNS tunneling indicators (long subdomains, high query rate to single base domain)
    /// - Rapid unique domain resolution (beaconing via random subdomains)
    /// Purely behavioral — no domain blocklists.
    /// </summary>
    public sealed class DnsQueryMonitor : IMonitor
    {
        public string Name => "DnsQueryMonitor";

        private readonly DetectionEngine _detectionEngine;
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly ILogger<DnsQueryMonitor> _logger;
        private CancellationTokenSource? _cts;
        private TraceEventSession? _session;

        // Per-base-domain query count in sliding window
        private readonly ConcurrentDictionary<string, int> _queryStats = new();
        private DateTime _lastPrune = DateTime.UtcNow;

        private const double DgaEntropyThreshold = 4.0;
        private const int DgaMinLength = 14;
        private const int RapidQueryThreshold = 50; // queries per base domain per window

        // Dynamically resolved at startup — the local machine's own hostname and FQDN
        private static readonly HashSet<string> LocalHostNames = BuildLocalHostNames();
        private static HashSet<string> BuildLocalHostNames()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                var name = System.Net.Dns.GetHostName();
                set.Add(name);
                set.Add(name.Split('.')[0]); // short name
            }
            catch { }
            return set;
        }

        // Domains with naturally high-entropy subdomains or high query volumes
        private static readonly HashSet<string> TrustedBaseDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            // CDN / Cloud
            "akamaiedge.net", "akamai.net", "cloudfront.net", "cloudflare.com",
            "azureedge.net", "azure.com", "msedge.net", "trafficmanager.net",
            "googleapis.com", "gstatic.com", "googlevideo.com",
            "gvt1.com", "gvt2.com", "googleusercontent.com",
            // Microsoft
            "microsoft.com", "microsoftonline.com", "windows.net", "office.com", "live.com",
            "msidentity.com", "windowsupdate.com", "windowsupdate.org", "msftncsi.com",
            "s-msft.com", "s-microsoft.com",
            // Gaming
            "steamserver.net", "steamcontent.com", "steampowered.com", "valve.net",
            "epicgames.com", "unrealengine.com",
            // IDE / Dev tooling
            "codeium.com", "agentclientprotocol.com", "github.com", "github.io",
            "githubusercontent.com", "npmjs.org", "nuget.org",
            "visualstudio.com", "vsassets.io", "kiro.dev",
            // Reputations & Certs (safe lookup domains)
            "abuse.ch", "lencr.org", "amazontrust.com", "digicert.com", "globalsign.com",
            // Other common
            "spotify.com", "scdn.co", "discord.gg", "discordapp.com",
            // Windows internals — high-volume by design, not C2
            "wpad",
        };
        private const string SessionName = "SentinelDnsMonitor";
        private static readonly Guid DnsClientProvider = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");

        public DnsQueryMonitor(
            DetectionEngine detectionEngine,
            TelemetryFusionEngine fusionEngine,
            ILogger<DnsQueryMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _fusionEngine = fusionEngine;
            _logger = logger;
        }

        public Task StartAsync(CancellationToken ct)
        {
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            Task.Run(() => RunEtwSession(_cts.Token), _cts.Token);
            _logger.LogInformation("[{Monitor}] Started", Name);
            return Task.CompletedTask;
        }

        private void RunEtwSession(CancellationToken ct)
        {
            try
            {
                _session = new TraceEventSession(SessionName, TraceEventSessionOptions.Create);
                _session.EnableProvider(DnsClientProvider, TraceEventLevel.Informational);

                _session.Source.Dynamic.All += (TraceEvent data) =>
                {
                    if (ct.IsCancellationRequested) return;

                    // Event ID 3006 = DNS query completed; payload field "QueryName"
                    var queryName = data.PayloadStringByName("QueryName");
                    if (string.IsNullOrWhiteSpace(queryName)) return;

                    ProcessDnsQuery(queryName, data.ProcessID);
                };

                // Prune timer
                Task.Run(async () =>
                {
                    while (!ct.IsCancellationRequested)
                    {
                        await Task.Delay(60_000, ct);
                        PruneStats();
                    }
                }, ct);

                ct.Register(() => _session?.Stop());
                _session.Source.Process();
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[{Monitor}] ETW session failed, DNS monitoring degraded", Name);
            }
        }

        private void ProcessDnsQuery(string domain, int pid)
        {
            domain = domain.TrimEnd('.').ToLowerInvariant();
            if (string.IsNullOrEmpty(domain)) return;

            // Extract base domain (last two labels)
            var labels = domain.Split('.');
            var baseDomain = labels.Length >= 2
                ? $"{labels[^2]}.{labels[^1]}"
                : domain;

            // Track query frequency per base domain
            _queryStats.AddOrUpdate(baseDomain, 1, (_, c) => c + 1);

            // Check for DGA-like patterns on subdomain portion
            if (labels.Length > 2 && !TrustedBaseDomains.Contains(baseDomain) && !LocalHostNames.Contains(baseDomain))
            {
                var subdomain = string.Join(".", labels.Take(labels.Length - 2));
                if (subdomain.Length >= DgaMinLength)
                {
                    var entropy = CalculateEntropy(subdomain.Replace(".", ""));
                    if (entropy >= DgaEntropyThreshold)
                    {
                        _ = _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "DNS: DGA-like Domain Query",
                            Evidence = $"High-entropy subdomain queried: {domain} (entropy {entropy:F2}, PID {pid})",
                            Reasoning = "A DNS query was made to a domain with a high-entropy subdomain pattern consistent with domain generation algorithm (DGA) malware communication.",
                            Confidence = 0.70, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = pid
                        });
                    }
                }
            }

            // Check for rapid unique queries to same base domain (DNS tunneling / beaconing)
            if (_queryStats.TryGetValue(baseDomain, out var count) && count == RapidQueryThreshold && !TrustedBaseDomains.Contains(baseDomain) && !LocalHostNames.Contains(baseDomain))
            {
                _ = _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "DNS: Rapid Query Volume (Beaconing/Tunneling)",
                    Evidence = $"Base domain '{baseDomain}' received {count} queries in current window",
                    Reasoning = "An abnormally high volume of DNS queries to a single base domain was detected, consistent with DNS tunneling or C2 beaconing.",
                    Confidence = 0.75, Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM", ProcessId = pid
                });
            }
        }

        private void PruneStats()
        {
            _queryStats.Clear();
            _lastPrune = DateTime.UtcNow;
        }

        private static double CalculateEntropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            var freq = new int[256];
            foreach (var c in s) freq[c]++;
            double entropy = 0;
            double len = s.Length;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = freq[i] / len;
                entropy -= p * Math.Log2(p);
            }
            return entropy;
        }

        public Task StopAsync()
        {
            _cts?.Cancel();
            try { _session?.Stop(); } catch { }
            try { _session?.Dispose(); } catch { }
            return Task.CompletedTask;
        }
    }
}
