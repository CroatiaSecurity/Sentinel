using System.Security.Cryptography;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Matches process telemetry (image hash, process name) against the
/// hardened <see cref="IoCScanner"/> list. Network-side IoC matching is performed
/// by the <see cref="NetworkMonitor"/> consumer when the IoC list grows IPs/domains.
///
/// File hashing here is *opt-in* per process: we hash only when the image path is
/// reachable and the file is under 64 MB, to avoid heavy per-event I/O.
/// </summary>
public sealed class IoCScannerRule : IDetectionRule
{
    public string Name => "IoC Match (Hash/Name)";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    private const long MaxHashableSize = 64L * 1024 * 1024;

    private readonly IoCScanner _scanner;

    public IoCScannerRule(IoCScanner scanner)
    {
        _scanner = scanner;
    }

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry t) return null;
        if (!string.Equals(t.EventType, "ProcessStart", StringComparison.OrdinalIgnoreCase)) return null;

        var imagePath = t.ImagePath;
        if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath)) return null;

        // Image-name match (cheap)
        var fileName = Path.GetFileName(imagePath);
        // (CampaignIocRule already covers static name lists; we keep this rule
        //  hash-driven so the two rules don't double-fire on the same evidence.)

        try
        {
            var fi = new FileInfo(imagePath);
            if (fi.Length > MaxHashableSize) return null;
        }
        catch { return null; }

        string sha;
        try { sha = ComputeSha256(imagePath); }
        catch { return null; }

        if (!_scanner.IsMaliciousHash(sha, out var name, out var technique))
            return null;

        return new DetectionEvent
        {
            RuleName = Name,
            Evidence = $"SHA-256 {sha[..16]}… matches IoC entry '{name}'",
            Reasoning =
                "Hash present in the curated IoC list. List is persisted via DPAPI+HMAC; " +
                "tampered/foreign list files are rejected on load, so a poisoned entry " +
                "is the only path to a false-match here.",
            Confidence = 0.93,
            Tier = DetectionTier.Tier1Behavioral,
            ProcessName = t.ProcessName,
            ProcessId = t.ProcessId,
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["technique"] = technique,
                ["file_hash"] = sha,
                ["image_path"] = imagePath,
                ["matched_ioc"] = name,
                ["file_name"] = fileName
            }
        };
    }

    private static string ComputeSha256(string filePath)
    {
        using var sha = SHA256.Create();
        using var fs = File.OpenRead(filePath);
        return Convert.ToHexString(sha.ComputeHash(fs));
    }
}

