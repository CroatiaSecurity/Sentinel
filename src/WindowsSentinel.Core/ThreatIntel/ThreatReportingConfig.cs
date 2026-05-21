namespace WindowsSentinel.Core.ThreatIntel;

/// <summary>
/// Configuration for threat intelligence reporting
/// </summary>
public class ThreatReportingConfig
{
    /// <summary>
    /// Enable/disable threat intelligence reporting (default: true)
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// API key for AbuseIPDB (optional)
    /// </summary>
    public string? AbuseIPDBApiKey { get; set; }

    /// <summary>
    /// API key for MalwareBazaar (optional)
    /// </summary>
    public string? MalwareBazaarApiKey { get; set; }

    /// <summary>
    /// API key for URLhaus (optional)
    /// </summary>
    public string? URLhausApiKey { get; set; }

    /// <summary>
    /// Report C2 IPs to AbuseIPDB (default: true)
    /// </summary>
    public bool ReportC2ToAbuseIPDB { get; set; } = true;

    /// <summary>
    /// Report file hashes to MalwareBazaar (default: true)
    /// </summary>
    public bool ReportHashesToMalwareBazaar { get; set; } = true;

    /// <summary>
    /// Report URLs to URLhaus (default: true)
    /// </summary>
    public bool ReportUrlsToURLhaus { get; set; } = true;

    /// <summary>
    /// Minimum confidence threshold for reporting (default: 0.8)
    /// </summary>
    public double MinimumConfidence { get; set; } = 0.8;
}
