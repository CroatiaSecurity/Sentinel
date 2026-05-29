using System.Collections.Concurrent;
using System.Net.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// DNS Blocklist Engine — Fetches and maintains malicious domain blocklists from
/// well-known community threat intelligence feeds. Provides O(1) lookup for the
/// DnsQueryMonitor to check resolved domains against known-malicious entries.
///
/// SCOPE: Only domains that deliver payloads, host C2 infrastructure, steal
/// credentials via phishing, or serve exploit kits. Explicitly NOT included:
///   - Ad networks / trackers (annoying but not a security threat)
///   - Piracy / torrent sites (not Sentinel's job)
///   - "Potentially unwanted" gray-area domains
///   - Coin miners running in-browser (nuisance, not compromise)
///
/// Feeds (all free, no API key required):
///   - URLhaus (abuse.ch) — actively exploited malware distribution domains
///   - ThreatFox (abuse.ch) — active C2 and malware infrastructure
///   - Feodo Tracker (abuse.ch) — banking trojan / botnet C2 domains
///   - PhishTank (mitchellkrogza) — confirmed credential-stealing phishing domains
///   - openphish — machine-verified phishing URLs/domains
///   - Botvrij.eu — verified botnet/C2/malware domains from Dutch CERT
///
/// Refresh: every 4 hours (configurable). On failure, retains last-good list.
/// Storage: DPAPI-protected via SecureCacheStore (survives reboot, tamper-resistant).
///
/// This engine is PASSIVE — it only provides lookup. The DnsQueryMonitor handles
/// detection emission and the response engine handles blocking.
///
/// MITRE ATT&CK:
///   T1566.002 — Phishing: Spearphishing Link
///   T1204.001 — User Execution: Malicious Link
///   T1071.001 — Application Layer Protocol: Web Protocols
///   T1105    — Ingress Tool Transfer (payload download)
/// </summary>
public sealed class DnsBlocklistEngine : BackgroundService
{
    private readonly ILogger<DnsBlocklistEngine> _logger;
    private readonly SecureCacheStore _store;
    private readonly HttpClient _httpClient;

    private volatile HashSet<string> _blockedDomains = new(StringComparer.OrdinalIgnoreCase);
    private volatile HashSet<string> _phishingDomains = new(StringComparer.OrdinalIgnoreCase);
    private volatile HashSet<string> _malwareDomains = new(StringComparer.OrdinalIgnoreCase);

    private DateTimeOffset _lastRefresh = DateTimeOffset.MinValue;
    private int _totalDomains;

    /// <summary>
    /// How often to refresh blocklists from upstream feeds.
    /// </summary>
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromHours(4);

    /// <summary>
    /// Initial delay before first fetch (let other monitors start first).
    /// </summary>
    private static readonly TimeSpan StartupDelay = TimeSpan.FromSeconds(45);

    /// <summary>
    /// HTTP timeout for individual feed downloads.
    /// </summary>
    private static readonly TimeSpan FeedTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Maximum domains to load per feed (safety cap to prevent memory exhaustion).
    /// </summary>
    private const int MaxDomainsPerFeed = 500_000;

    /// <summary>
    /// Feed definitions: URL, parser type, category.
    /// 
    /// CURATION POLICY: Only feeds that track CONFIRMED malicious infrastructure:
    ///   - Malware payload delivery (droppers, loaders, exploit kits)
    ///   - Command & Control (C2) servers and domains
    ///   - Credential-stealing phishing pages
    ///   - Botnet infrastructure
    ///
    /// EXCLUDED: Ad networks, trackers, piracy, coin miners, "PUP" gray areas.
    /// If a feed mixes categories, it's excluded entirely.
    /// </summary>
    private static readonly BlocklistFeed[] Feeds =
    {
        // URLhaus — actively exploited malware DISTRIBUTION domains only
        // (sites hosting payloads: droppers, ransomware, trojans, exploit kits)
        new("https://urlhaus.abuse.ch/downloads/hostfile/",
            FeedFormat.HostsFile, BlocklistCategory.Malware, "URLhaus (abuse.ch)"),

        // ThreatFox — active C2 infrastructure and malware domains
        // (confirmed C2 servers, botnet controllers, RAT infrastructure)
        new("https://threatfox.abuse.ch/downloads/hostfile/",
            FeedFormat.HostsFile, BlocklistCategory.C2, "ThreatFox (abuse.ch)"),

        // Feodo Tracker — banking trojan C2 domains (Dridex, Emotet, TrickBot, QakBot)
        new("https://feodotracker.abuse.ch/downloads/domainblocklist.txt",
            FeedFormat.CommentedDomainList, BlocklistCategory.C2, "Feodo Tracker (abuse.ch)"),

        // PhishTank active phishing domains — confirmed credential theft pages
        new("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
            FeedFormat.DomainList, BlocklistCategory.Phishing, "PhishTank Active"),

        // OpenPhish — machine-verified phishing (high confidence, low FP)
        new("https://openphish.com/feed.txt",
            FeedFormat.UrlList, BlocklistCategory.Phishing, "OpenPhish"),

        // Botvrij.eu — Dutch National CERT verified botnet/C2/malware domains
        new("https://www.botvrij.eu/data/ioclist.domain.raw",
            FeedFormat.CommentedDomainList, BlocklistCategory.C2, "Botvrij.eu (Dutch CERT)"),
    };

    public DnsBlocklistEngine(ILogger<DnsBlocklistEngine> logger)
    {
        _logger = logger;
        _store = new SecureCacheStore(logger, "dns_blocklist");

        // Create a dedicated HttpClient for blocklist fetching
        // No domain allowlist restriction — these are public community feeds
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 3,
            UseCookies = false
        };
        _httpClient = new HttpClient(handler)
        {
            Timeout = FeedTimeout
        };
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("WindowsSentinel-EDR/4.4.0");

        // Load cached blocklist immediately (before first network fetch)
        LoadFromCache();
    }

    /// <summary>
    /// Checks if a domain is on any blocklist. O(1) lookup.
    /// Returns the category and source feed name if blocked.
    /// </summary>
    public bool IsBlocked(string domain, out BlocklistCategory category, out string reason)
    {
        category = BlocklistCategory.Unknown;
        reason = "";

        if (string.IsNullOrWhiteSpace(domain)) return false;

        var normalized = NormalizeDomain(domain);

        // Check exact match first, then parent domains
        if (TryMatch(normalized, out category, out reason))
            return true;

        // Check parent domain (e.g., "sub.evil.com" matches "evil.com")
        var parts = normalized.Split('.');
        for (int i = 1; i < parts.Length - 1; i++)
        {
            var parent = string.Join('.', parts[i..]);
            if (TryMatch(parent, out category, out reason))
            {
                reason += $" (matched via parent: {parent})";
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Returns current blocklist statistics.
    /// </summary>
    public BlocklistStats GetStats() => new()
    {
        TotalDomains = _totalDomains,
        MalwareDomains = _malwareDomains.Count,
        PhishingDomains = _phishingDomains.Count,
        LastRefresh = _lastRefresh,
        NextRefresh = _lastRefresh + RefreshInterval
    };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[DnsBlocklist] Starting — {Count} cached domains loaded", _totalDomains);

        // Wait for system to stabilize before hitting the network
        await Task.Delay(StartupDelay, stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RefreshBlocklistsAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[DnsBlocklist] Refresh cycle failed (will retry in {Interval})",
                    RefreshInterval);
            }

            try { await Task.Delay(RefreshInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task RefreshBlocklistsAsync(CancellationToken ct)
    {
        _logger.LogInformation("[DnsBlocklist] Refreshing from {Count} feeds...", Feeds.Length);

        var malware = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var phishing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var allBlocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        int successCount = 0;
        int failCount = 0;

        foreach (var feed in Feeds)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                var domains = await FetchFeedAsync(feed, ct);

                foreach (var domain in domains)
                {
                    allBlocked.Add(domain);

                    switch (feed.Category)
                    {
                        case BlocklistCategory.Malware:
                        case BlocklistCategory.C2:
                            malware.Add(domain);
                            break;
                        case BlocklistCategory.Phishing:
                            phishing.Add(domain);
                            break;
                    }
                }

                _logger.LogInformation("[DnsBlocklist] {Feed}: {Count} domains loaded",
                    feed.Name, domains.Count);
                successCount++;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[DnsBlocklist] Failed to fetch {Feed}", feed.Name);
                failCount++;
            }
        }

        // Only update if we got at least one feed successfully
        if (successCount > 0)
        {
            _blockedDomains = allBlocked;
            _malwareDomains = malware;
            _phishingDomains = phishing;
            _totalDomains = allBlocked.Count;
            _lastRefresh = DateTimeOffset.UtcNow;

            // Persist to secure cache
            SaveToCache();

            _logger.LogInformation(
                "[DnsBlocklist] Refresh complete: {Total} domains ({Malware} malware, {Phishing} phishing). " +
                "Feeds: {Success} OK, {Fail} failed.",
                _totalDomains, malware.Count, phishing.Count, successCount, failCount);
        }
        else
        {
            _logger.LogWarning("[DnsBlocklist] All feeds failed — retaining {Count} cached domains", _totalDomains);
        }
    }

    private async Task<List<string>> FetchFeedAsync(BlocklistFeed feed, CancellationToken ct)
    {
        using var response = await _httpClient.GetAsync(feed.Url, ct);
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync(ct);
        var domains = new List<string>();

        using var reader = new StringReader(content);
        string? line;
        int count = 0;

        while ((line = await reader.ReadLineAsync(ct)) != null && count < MaxDomainsPerFeed)
        {
            var domain = ParseLine(line, feed.Format);
            if (domain != null)
            {
                domains.Add(domain);
                count++;
            }
        }

        return domains;
    }

    private static string? ParseLine(string line, FeedFormat format)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;

        var trimmed = line.Trim();

        // Skip comments
        if (trimmed.StartsWith('#') || trimmed.StartsWith("//")) return null;

        switch (format)
        {
            case FeedFormat.HostsFile:
                // Format: "0.0.0.0 malicious.domain" or "127.0.0.1 malicious.domain"
                var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) return null;
                if (parts[0] != "0.0.0.0" && parts[0] != "127.0.0.1") return null;
                var domain = parts[1].ToLowerInvariant().TrimEnd('.');
                // Skip localhost entries
                if (domain == "localhost" || domain == "localhost.localdomain" ||
                    domain == "local" || domain == "broadcasthost" ||
                    domain == "0.0.0.0" || domain.Length < 4)
                    return null;
                // Skip inline comments
                if (domain.Contains('#')) domain = domain.Split('#')[0].Trim();
                return IsValidDomain(domain) ? domain : null;

            case FeedFormat.DomainList:
                // One domain per line, no prefix
                var d = trimmed.ToLowerInvariant().TrimEnd('.');
                return IsValidDomain(d) ? d : null;

            case FeedFormat.CommentedDomainList:
                // One domain per line, # comments
                if (trimmed.StartsWith('#')) return null;
                var cd = trimmed.ToLowerInvariant().TrimEnd('.');
                return IsValidDomain(cd) ? cd : null;

            case FeedFormat.UrlList:
                // Full URLs — extract domain only (e.g., "https://evil.com/payload.exe" → "evil.com")
                try
                {
                    // Handle lines that are just URLs
                    var url = trimmed;
                    if (!url.StartsWith("http://") && !url.StartsWith("https://"))
                        url = "https://" + url;
                    var uri = new Uri(url);
                    var host = uri.Host.ToLowerInvariant().TrimEnd('.');
                    return IsValidDomain(host) ? host : null;
                }
                catch
                {
                    return null;
                }

            default:
                return null;
        }
    }

    private static bool IsValidDomain(string domain)
    {
        if (string.IsNullOrEmpty(domain) || domain.Length < 4 || domain.Length > 253)
            return false;
        if (!domain.Contains('.')) return false;
        // Basic validation: no spaces, no special chars except hyphen and dot
        foreach (var c in domain)
        {
            if (!char.IsLetterOrDigit(c) && c != '.' && c != '-')
                return false;
        }
        return true;
    }

    private bool TryMatch(string domain, out BlocklistCategory category, out string reason)
    {
        category = BlocklistCategory.Unknown;
        reason = "";

        if (!_blockedDomains.Contains(domain)) return false;

        if (_malwareDomains.Contains(domain))
        {
            category = BlocklistCategory.Malware;
            reason = "Known malware/C2 infrastructure (payload delivery or command & control)";
        }
        else if (_phishingDomains.Contains(domain))
        {
            category = BlocklistCategory.Phishing;
            reason = "Confirmed credential-stealing phishing domain";
        }
        else
        {
            category = BlocklistCategory.Malware;
            reason = "Blocked domain (confirmed malicious infrastructure)";
        }

        return true;
    }

    private static string NormalizeDomain(string domain)
        => domain.ToLowerInvariant().TrimEnd('.');

    private void LoadFromCache()
    {
        try
        {
            var snapshot = _store.TryLoad<BlocklistSnapshot>();
            if (snapshot is null)
            {
                _logger.LogInformation("[DnsBlocklist] No cached blocklist found — will fetch on first cycle");
                return;
            }

            _blockedDomains = new HashSet<string>(snapshot.AllDomains ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
            _malwareDomains = new HashSet<string>(snapshot.MalwareDomains ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
            _phishingDomains = new HashSet<string>(snapshot.PhishingDomains ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
            _totalDomains = _blockedDomains.Count;
            _lastRefresh = snapshot.LastRefresh;

            _logger.LogInformation("[DnsBlocklist] Loaded {Count} cached domains (last refresh: {Time})",
                _totalDomains, _lastRefresh);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[DnsBlocklist] Cache load failed — starting empty");
        }
    }

    private void SaveToCache()
    {
        try
        {
            var snapshot = new BlocklistSnapshot
            {
                AllDomains = _blockedDomains.ToArray(),
                MalwareDomains = _malwareDomains.ToArray(),
                PhishingDomains = _phishingDomains.ToArray(),
                LastRefresh = _lastRefresh
            };
            if (!_store.TrySave(snapshot))
                _logger.LogWarning("[DnsBlocklist] Cache save failed");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[DnsBlocklist] Cache save error");
        }
    }

    public override void Dispose()
    {
        _httpClient.Dispose();
        base.Dispose();
    }
}

// ── Supporting types ─────────────────────────────────────────────────────────

public enum BlocklistCategory
{
    Unknown,
    Malware,    // Payload delivery: droppers, exploit kits, ransomware hosting
    Phishing,   // Credential theft: fake login pages, social engineering
    C2          // Command & Control: botnet controllers, RAT infrastructure
}

public sealed class BlocklistStats
{
    public int TotalDomains { get; init; }
    public int MalwareDomains { get; init; }
    public int PhishingDomains { get; init; }
    public DateTimeOffset LastRefresh { get; init; }
    public DateTimeOffset NextRefresh { get; init; }
}

internal sealed class BlocklistSnapshot
{
    public string[] AllDomains { get; set; } = Array.Empty<string>();
    public string[] MalwareDomains { get; set; } = Array.Empty<string>();
    public string[] PhishingDomains { get; set; } = Array.Empty<string>();
    public DateTimeOffset LastRefresh { get; set; }
}

internal sealed record BlocklistFeed(
    string Url,
    FeedFormat Format,
    BlocklistCategory Category,
    string Name);

internal enum FeedFormat
{
    HostsFile,          // "0.0.0.0 domain" or "127.0.0.1 domain"
    DomainList,         // One domain per line
    CommentedDomainList,// One domain per line, # comments
    UrlList             // Full URLs — domain is extracted (e.g., OpenPhish)
}
