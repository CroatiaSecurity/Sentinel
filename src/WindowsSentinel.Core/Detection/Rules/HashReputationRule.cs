using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Checks file hashes against multi-source reputation APIs (CIRCL, Cymru, MalwareBazaar).
/// No API authentication required.
/// 
/// Features: Rate limiting, circuit breaker pattern, persistent cache,
/// confidence scoring from multiple sources.
/// </summary>
public sealed class HashReputationRule : IAsyncDetectionRule
{
    public string Name => "Hash Reputation (Multi-Source)";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    private readonly HashReputationService _reputationService;
    private readonly ILogger<HashReputationRule> _logger;
    
    // File extensions to check
    private static readonly HashSet<string> TargetExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".vbs", ".js",
        ".jse", ".wsh", ".wsf", ".hta", ".msi", ".msp", ".ps1", ".psm1"
    };

    // Minimum confidence threshold to trigger detection
    private const int MinimumConfidence = 50;

    // Suspicious paths - higher priority for these
    private static readonly string[] HighPriorityPaths = new[]
    {
        @"\temp\", @"\tmp\", @"\downloads\", @"\desktop\", @"\appdata\"
    };

    public HashReputationRule(HashReputationService reputationService, ILogger<HashReputationRule> logger)
    {
        _reputationService = reputationService;
        _logger = logger;
    }

    public DetectionEvent? Evaluate(object telemetry)
    {
        // Synchronous evaluation cannot perform network calls.
        // Async evaluation is handled via IAsyncDetectionRule.EvaluateAsync.
        return null;
    }

    /// <summary>
    /// IAsyncDetectionRule implementation — called by DetectionEngine after Evaluate.
    /// Performs hash reputation lookup against external APIs.
    /// </summary>
    public async Task<DetectionEvent?> EvaluateAsync(object telemetry, CancellationToken ct = default)
    {
        if (telemetry is not FileActivityTelemetry file) return null;
        return await EvaluateFileAsync(file, ct);
    }

    /// <summary>
    /// Internal async evaluation for file activity telemetry.
    /// Called by the detection engine when a new file is detected.
    /// </summary>
    private async Task<DetectionEvent?> EvaluateFileAsync(FileActivityTelemetry file, CancellationToken ct = default)
    {
        // Check the new/renamed file path for reputation
        var filePath = file.NewPath;
        var extension = Path.GetExtension(filePath);

        // Only check executable/script extensions
        if (!TargetExtensions.Contains(extension))
            return null;

        // Check if file exists and is accessible
        if (!File.Exists(filePath))
            return null;

        try
        {
            // Calculate SHA256 hash
            string hash;
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            using (var stream = File.OpenRead(filePath))
            {
                var hashBytes = sha256.ComputeHash(stream);
                hash = Convert.ToHexString(hashBytes);
            }

            // Query reputation service
            var reputation = await _reputationService.CheckHashAsync(hash, ct);

            // Check if malicious with sufficient confidence
            if (!reputation.IsMalicious || reputation.Confidence < MinimumConfidence)
                return null;

            // Build detection event
            var pathLower = filePath.ToLowerInvariant();
            bool inHighPriorityPath = HighPriorityPaths.Any(p => pathLower.Contains(p));

            double confidence = reputation.Confidence / 100.0;
            if (inHighPriorityPath)
                confidence = Math.Min(confidence + 0.05, 0.98);

            var sources = string.Join(", ", reputation.Sources);
            
            return new DetectionEvent
            {
                RuleName = Name,
                Evidence = $"File '{Path.GetFileName(filePath)}' matches known malware hash (SHA256: {hash[..16]}...) | " +
                          $"Reputation sources: {sources} | Confidence: {reputation.Confidence}% | " +
                          $"Path: {filePath}",
                Reasoning = "File hash (SHA256) matches entries in malware reputation databases: " +
                    $"{sources}. These services aggregate malware samples from security researchers " +
                    "and honeypots. Confidence is calculated based on the number of sources confirming " +
                    "the hash as malicious. Files in temp/downloads directories receive higher priority.",
                Confidence = confidence,
                Tier = Tier,
                ProcessName = "FileSystem",
                ProcessId = 0,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new()
                {
                    ["FilePath"] = filePath,
                    ["SHA256"] = hash,
                    ["Sources"] = sources,
                    ["Confidence"] = reputation.Confidence.ToString(),
                    ["InHighPriorityPath"] = inHighPriorityPath.ToString()
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Hash reputation check failed for {File}", filePath);
            return null;
        }
    }
}
