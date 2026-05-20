using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// DNS Query Monitor — Subscribes to the Microsoft-Windows-DNS-Client ETW provider
/// to observe every DNS resolution on the system.
///
/// This catches:
///   - C2 over DNS (iodine, dnscat2, dns2tcp)
///   - DGA domains (high-entropy random names)
///   - Process → domain correlation ("process X resolved suspicious.domain then connected")
///   - DNS tunneling (high query volume from a single process)
///
/// The DNS-Client provider fires on EVERY resolution regardless of how it's made
/// (getaddrinfo, DnsQuery, browser, .NET HttpClient, etc.). No bypass short of
/// implementing a custom DNS resolver over raw sockets.
///
/// Requires elevation for ETW session. Degrades gracefully if unavailable.
/// </summary>
public sealed class DnsQueryMonitor : IMonitor
{
    public string Name => "DNS Query Monitor";

    private readonly IDetectionEngine _detectionEngine;
    private readonly TelemetryFusionEngine? _fusionEngine;
    private readonly ILogger<DnsQueryMonitor> _logger;

    private TraceEventSession? _session;
    private Task? _sessionTask;

    // Microsoft-Windows-DNS-Client provider GUID
    private static readonly Guid DnsClientProviderGuid =
        new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");

    // DGA detection: domains with Shannon entropy above this threshold are suspicious
    private const double DgaEntropyThreshold = 3.8;
    private const int DgaMinLength = 12;

    // Known DNS tunneling indicators
    private static readonly HashSet<string> DnsTunnelingPatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        "dnscat", "iodine", "dns2tcp", "dnsexfil", "dnstunnel"
    };

    // Known exfiltration / file-sharing / paste service domains (v1.8.0)
    // Resolution of these by non-browser processes = immediate Tier1 exfil alert
    private static readonly HashSet<string> ExfilServiceDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        // File sharing / upload services
        "mega.nz", "mega.co.nz", "transfer.sh", "file.io", "0x0.st",
        "anonfiles.com", "gofile.io", "pixeldrain.com", "catbox.moe",
        "temp.sh", "uguu.se", "pomf.cat",
        "send-anywhere.com", "wetransfer.com", "filebin.net",
        "uploadfiles.io", "bayfiles.com",
        "zippyshare.com", "1fichier.com", "rapidgator.net",
        "turbobit.net", "nitroflare.com", "uploaded.net",
        // Paste services (credential exfil)
        "pastebin.com", "paste.ee", "dpaste.org", "hastebin.com",
        "ghostbin.com", "rentry.co", "privatebin.net",
        // Telegram bot API (common infostealer exfil channel)
        "api.telegram.org",
        // Discord webhooks (common infostealer exfil channel)
        "discord.com", "discordapp.com",
        // Ngrok / tunneling services (reverse tunnel exfil)
        "ngrok.io", "ngrok-free.app", "trycloudflare.com",
        "localhost.run", "serveo.net", "bore.digital",
        // Known C2/exfil infrastructure
        "interactsh.com", "oast.fun", "oast.live", "oast.site",
        "burpcollaborator.net", "canarytokens.com",
    };

    // Legitimate high-query domains to ignore
    private static readonly HashSet<string> SafeDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "localhost", "wpad", "isatap",
        "microsoft.com", "windows.com", "windowsupdate.com", "msftconnecttest.com",
        "office.com", "office365.com", "live.com", "outlook.com",
        "google.com", "googleapis.com", "gstatic.com", "googlevideo.com",
        "cloudflare.com", "cloudflare-dns.com",
        "github.com", "githubusercontent.com",
        "steam-chat.com", "steamcommunity.com", "steampowered.com",
        "discord.gg", "discord.com", "discordapp.com",
        "akamai.net", "akamaized.net", "cloudfront.net", "amazonaws.com"
    };

    // Track query counts per process for tunneling detection
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, DnsQueryStats> _processStats = new();
    private DateTimeOffset _lastCleanup = DateTimeOffset.UtcNow;

    public DnsQueryMonitor(
        IDetectionEngine detectionEngine,
        ILogger<DnsQueryMonitor> logger,
        TelemetryFusionEngine? fusionEngine = null)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _fusionEngine = fusionEngine;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("[{Monitor}] Starting (requires elevation).", Name);

        try
        {
            _session = new TraceEventSession("WindowsSentinel-DnsClient");
            _session.EnableProvider(DnsClientProviderGuid, TraceEventLevel.Informational, 0x8000000000000000);

            _session.Source.Dynamic.All += data =>
            {
                if (cancellationToken.IsCancellationRequested) return;
                try { HandleDnsEvent(data, cancellationToken); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogDebug(ex, "[{Monitor}] Error handling DNS event.", Name);
                }
            };

            _sessionTask = Task.Run(() =>
            {
                try { _session.Source.Process(); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "[{Monitor}] DNS ETW session ended.", Name);
                }
            }, cancellationToken);

            _logger.LogInformation("[{Monitor}] DNS-Client ETW provider active.", Name);
        }
        catch (UnauthorizedAccessException)
        {
            _logger.LogWarning(
                "[{Monitor}] Access denied — elevation required. DNS monitoring disabled.", Name);
            _session?.Dispose();
            _session = null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[{Monitor}] Failed to start DNS ETW provider.", Name);
            _session?.Dispose();
            _session = null;
        }

        return Task.CompletedTask;
    }

    private void HandleDnsEvent(TraceEvent data, CancellationToken ct)
    {
        // Event ID 3006 = DNS query completed (contains the queried name)
        if ((int)data.ID != 3006 && (int)data.ID != 3008) return;

        string? queryName = null;
        int processPid = data.ProcessID;

        try
        {
            queryName = data.PayloadByName("QueryName")?.ToString();
        }
        catch { return; }

        if (string.IsNullOrWhiteSpace(queryName)) return;
        if (queryName.Length < 4) return;

        // Skip safe domains
        if (IsSafeDomain(queryName)) return;

        // Cleanup old stats periodically
        if ((DateTimeOffset.UtcNow - _lastCleanup).TotalMinutes > 2)
        {
            CleanupStats();
            _lastCleanup = DateTimeOffset.UtcNow;
        }

        // Track per-process query stats
        var stats = _processStats.GetOrAdd(processPid, _ => new DnsQueryStats());
        stats.TotalQueries++;
        stats.LastQuery = DateTimeOffset.UtcNow;
        stats.RecentDomains.Enqueue(queryName);
        while (stats.RecentDomains.Count > 100)
            stats.RecentDomains.TryDequeue(out _);

        // ═══════════════════════════════════════════════════════════════════
        // v1.8.0: EXFILTRATION SERVICE DETECTION
        // If a non-browser process resolves a known exfil/upload/paste domain,
        // emit Tier2 signal. Correlation engine combines with network for kill.
        // Browsers are allowlisted because users legitimately visit these sites.
        // ═══════════════════════════════════════════════════════════════════
        if (IsExfilServiceDomain(queryName))
        {
            var processName = GetProcessNameSafe(processPid);
            if (!IsBrowserOrAllowlisted(processName))
            {
                stats.ExfilDomainHits++;

                _ = _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Data Exfiltration: Upload Service DNS",
                    Evidence = $"Process '{processName}' (PID {processPid}) resolved known exfiltration domain: {queryName}. " +
                              $"Total exfil domain lookups from this process: {stats.ExfilDomainHits}",
                    Reasoning = "Non-browser processes resolving file-sharing, paste, or upload service domains " +
                               "indicates potential data exfiltration staging. This is a corroborating signal — " +
                               "combined with outbound network activity, it confirms active exfil.",
                    Confidence = Math.Min(0.70 + (stats.ExfilDomainHits * 0.05), 0.85),
                    Tier = DetectionTier.Tier2Indicator, // Corroborating — needs network correlation to kill
                    ProcessName = processName ?? processPid.ToString(),
                    ProcessId = processPid,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["domain"] = queryName,
                        ["exfil_hits"] = stats.ExfilDomainHits.ToString(),
                        ["process_name"] = processName ?? "unknown",
                        ["technique"] = "T1567 - Exfiltration Over Web Service",
                        ["remote_address"] = queryName
                    }
                }, ct);
            }
        }

        // Check 1: DGA detection (high-entropy domain names)
        var domainPart = GetSecondLevelDomain(queryName);
        if (domainPart.Length >= DgaMinLength)
        {
            var entropy = CalculateShannonEntropy(domainPart);
            if (entropy >= DgaEntropyThreshold)
            {
                stats.DgaHits++;

                // Only alert after 3+ DGA-like queries from same process (reduces FPs)
                if (stats.DgaHits >= 3)
                {
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "DNS: DGA Domain Pattern",
                        Evidence = $"Process PID {processPid} resolved {stats.DgaHits} high-entropy domains. " +
                                  $"Latest: '{queryName}' (entropy: {entropy:F2}). " +
                                  $"Recent: {string.Join(", ", stats.RecentDomains.TakeLast(5))}",
                        Reasoning = "Domain Generation Algorithms (DGA) produce random-looking domain names " +
                                   "to evade static blocklists. Multiple high-entropy DNS queries from a single " +
                                   "process is a strong indicator of malware C2 communication.",
                        Confidence = Math.Min(0.60 + (stats.DgaHits * 0.05), 0.90),
                        Tier = DetectionTier.Tier2Indicator, // Corroborating signal — needs correlation to kill
                        ProcessName = processPid.ToString(),
                        ProcessId = processPid,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["domain"] = queryName,
                            ["entropy"] = entropy.ToString("F2"),
                            ["dga_hits"] = stats.DgaHits.ToString(),
                            ["technique"] = "T1568.002 - Dynamic Resolution: Domain Generation Algorithms"
                        }
                    }, ct);
                }
            }
        }

        // Check 2: DNS tunneling (extremely high query rate from single process)
        if (stats.TotalQueries > 50)
        {
            var elapsed = (DateTimeOffset.UtcNow - stats.FirstSeen).TotalMinutes;
            if (elapsed > 0)
            {
                var queriesPerMinute = stats.TotalQueries / elapsed;
                if (queriesPerMinute > 30 && !stats.TunnelingAlerted)
                {
                    stats.TunnelingAlerted = true;

                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "DNS: Possible Tunneling",
                        Evidence = $"Process PID {processPid} made {stats.TotalQueries} DNS queries " +
                                  $"in {elapsed:F1} minutes ({queriesPerMinute:F0}/min). " +
                                  $"Recent: {string.Join(", ", stats.RecentDomains.TakeLast(5))}",
                        Reasoning = "DNS tunneling tools (iodine, dnscat2, dns2tcp) encode data in DNS queries " +
                                   "to exfiltrate information or maintain C2 channels. Normal processes rarely " +
                                   "exceed 30 DNS queries per minute sustained.",
                        Confidence = 0.75,
                        Tier = DetectionTier.Tier2Indicator, // Corroborating signal — needs correlation to kill
                        ProcessName = processPid.ToString(),
                        ProcessId = processPid,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["queries_total"] = stats.TotalQueries.ToString(),
                            ["queries_per_minute"] = queriesPerMinute.ToString("F1"),
                            ["technique"] = "T1071.004 - Application Layer Protocol: DNS"
                        }
                    }, ct);
                }
            }
        }
    }

    private bool IsSafeDomain(string domain)
    {
        var lower = domain.ToLowerInvariant().TrimEnd('.');
        foreach (var safe in SafeDomains)
        {
            if (lower == safe || lower.EndsWith("." + safe))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Checks if the resolved domain matches a known exfiltration/upload service.
    /// </summary>
    private static bool IsExfilServiceDomain(string domain)
    {
        var lower = domain.ToLowerInvariant().TrimEnd('.');
        foreach (var exfil in ExfilServiceDomains)
        {
            if (lower == exfil || lower.EndsWith("." + exfil))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Browsers and known legitimate apps that may resolve exfil domains as part of normal browsing.
    /// Only these are allowed to resolve exfil domains without triggering a kill.
    /// </summary>
    private static bool IsBrowserOrAllowlisted(string? processName)
    {
        if (string.IsNullOrEmpty(processName)) return false;
        var lower = processName.ToLowerInvariant();
        var allowlisted = new HashSet<string>
        {
            "chrome", "firefox", "msedge", "brave", "opera", "vivaldi",
            "iexplore", "safari", "chromium", "waterfox", "librewolf",
            "explorer", // Windows Explorer (user clicking links)
            "teams", "slack", "discord", // Chat apps where users share links
            "sentinelservice", "sentinelagent" // Ourselves
        };
        return allowlisted.Contains(lower);
    }

    private static string? GetProcessNameSafe(int pid)
    {
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(pid);
            return proc.ProcessName;
        }
        catch
        {
            return null;
        }
    }

    private static string GetSecondLevelDomain(string domain)
    {
        var parts = domain.TrimEnd('.').Split('.');
        if (parts.Length >= 2)
            return parts[^2]; // e.g., "randomchars" from "randomchars.evil.com"
        return domain;
    }

    private static double CalculateShannonEntropy(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0;
        var freq = new Dictionary<char, int>();
        foreach (var c in s)
            freq[c] = freq.GetValueOrDefault(c) + 1;

        double entropy = 0;
        foreach (var count in freq.Values)
        {
            var p = (double)count / s.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private void CleanupStats()
    {
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-5);
        var stale = _processStats.Where(kv => kv.Value.LastQuery < cutoff).Select(kv => kv.Key).ToList();
        foreach (var key in stale)
            _processStats.TryRemove(key, out _);
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("[{Monitor}] Stopping.", Name);
        _session?.Stop();
        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        _session?.Dispose();
        if (_sessionTask is not null)
        {
            try { await _sessionTask.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch { /* best-effort */ }
        }
    }
}

internal sealed class DnsQueryStats
{
    public int TotalQueries { get; set; }
    public int DgaHits { get; set; }
    public int ExfilDomainHits { get; set; }
    public bool TunnelingAlerted { get; set; }
    public DateTimeOffset FirstSeen { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastQuery { get; set; } = DateTimeOffset.UtcNow;
    public System.Collections.Concurrent.ConcurrentQueue<string> RecentDomains { get; } = new();
}

