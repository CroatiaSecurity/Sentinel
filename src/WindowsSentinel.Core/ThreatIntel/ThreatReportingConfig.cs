namespace WindowsSentinel.Core.ThreatIntel;

/// <summary>
/// Configuration for threat intelligence reporting.
/// v3.9.0: Enabled by default. No API keys required for basic hash logging.
/// </summary>
public class ThreatReportingConfig
{
    /// <summary>
    /// Enable/disable threat intelligence reporting (default: true since v3.9.0)
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// API key for AbuseIPDB (optional — reporting skipped if empty)
    /// </summary>
    public string? AbuseIPDBApiKey { get; set; }

    /// <summary>
    /// API key for MalwareBazaar (optional)
    /// </summary>
    public string? MalwareBazaarApiKey { get; set; }

    /// <summary>
    /// API key for URLhaus (optional — reporting skipped if empty)
    /// </summary>
    public string? URLhausApiKey { get; set; }

    /// <summary>
    /// Report C2 IPs to AbuseIPDB (default: true, requires AbuseIPDBApiKey)
    /// </summary>
    public bool ReportC2ToAbuseIPDB { get; set; } = true;

    /// <summary>
    /// Report file hashes to MalwareBazaar (default: true, no key needed for hash logging)
    /// </summary>
    public bool ReportHashesToMalwareBazaar { get; set; } = true;

    /// <summary>
    /// Report URLs to URLhaus (default: true, requires URLhausApiKey)
    /// </summary>
    public bool ReportUrlsToURLhaus { get; set; } = true;

    /// <summary>
    /// Minimum confidence threshold for reporting (default: 0.8)
    /// </summary>
    public double MinimumConfidence { get; set; } = 0.8;
}
