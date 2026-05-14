using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier2 — Detects high-entropy process names, which are a strong indicator of
/// randomly-generated binary names used by malware to avoid signature detection.
///
/// Uses Shannon entropy on the filename stem (without extension).
/// Excludes known-legitimate high-entropy names (GUIDs, hash-named installers, etc.)
/// by checking against a whitelist of common patterns.
/// </summary>
public sealed class HighEntropyRule : IDetectionRule
{
    public string Name => "High Entropy Binary Name";
    public DetectionTier Tier => DetectionTier.Tier2Indicator;

    // Threshold tuned to catch random 8–16 char names while avoiding false positives
    // on legitimate software with long descriptive names.
    private const double EntropyThreshold = 4.2;

    // Minimum length — very short names can have high entropy by chance.
    private const int MinLength = 6;

    // Known-legitimate high-entropy name patterns (prefix match, case-insensitive).
    private static readonly string[] LegitimateHighEntropyPrefixes =
    {
        // Windows Update / CBS temp files
        "kb", "hotfix", "update",
        // .NET runtime generated
        "clr", "mscor",
        // Visual Studio / MSBuild
        "vctip", "msbuild",
        // Common installer patterns
        "setup", "install", "uninstall",
        // Sysinternals
        "procexp", "procmon", "autoruns",
    };

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;
        if (string.IsNullOrWhiteSpace(proc.ProcessName)) return null;

        // Strip extension, work on the stem only
        var stem = Path.GetFileNameWithoutExtension(proc.ProcessName);
        if (stem.Length < MinLength) return null;

        // Skip known-legitimate prefixes
        if (LegitimateHighEntropyPrefixes.Any(p =>
                stem.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            return null;

        // Skip if the name looks like a GUID (common in temp installers)
        if (IsGuidLike(stem)) return null;

        double entropy = CalculateShannonEntropy(stem);
        if (entropy < EntropyThreshold) return null;

        // Boost confidence if the binary is also in a suspicious path
        bool inSuspiciousPath =
            proc.ImagePath.Contains(@"\Temp\",    StringComparison.OrdinalIgnoreCase) ||
            proc.ImagePath.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase) ||
            proc.ImagePath.Contains(@"\Users\",   StringComparison.OrdinalIgnoreCase) ||
            proc.ImagePath.Contains(@"\ProgramData\", StringComparison.OrdinalIgnoreCase);

        double confidence = Math.Min(0.30 + (entropy - EntropyThreshold) * 0.12, 0.72);
        if (inSuspiciousPath) confidence = Math.Min(confidence + 0.15, 0.85);

        return new DetectionEvent
        {
            RuleName    = Name,
            Evidence    = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) has Shannon entropy " +
                          $"{entropy:F2} (threshold: {EntropyThreshold}). Path: {proc.ImagePath}",
            Reasoning   = "Malware frequently generates random binary names (e.g. 'xK9mP2qR7v.exe') " +
                          "to avoid signature-based detection. High entropy combined with execution " +
                          "from a user-writable path is a strong indicator of a dropped payload.",
            Confidence  = confidence,
            Tier        = Tier,
            ProcessName = proc.ProcessName,
            ProcessId   = proc.ProcessId,
            Timestamp   = proc.Timestamp,
            Metadata    = new()
            {
                ["Entropy"]          = entropy.ToString("F2"),
                ["ImagePath"]        = proc.ImagePath,
                ["InSuspiciousPath"] = inSuspiciousPath.ToString()
            }
        };
    }

    private static bool IsGuidLike(string name)
    {
        // GUIDs are 32 hex chars, optionally with hyphens
        var stripped = name.Replace("-", "").Replace("{", "").Replace("}", "");
        return stripped.Length == 32 &&
               stripped.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
    }

    private static double CalculateShannonEntropy(string input)
    {
        if (string.IsNullOrEmpty(input)) return 0;

        var freq = new Dictionary<char, int>();
        foreach (char c in input)
            freq[c] = freq.TryGetValue(c, out int v) ? v + 1 : 1;

        double entropy = 0;
        int len = input.Length;
        foreach (var count in freq.Values)
        {
            double p = (double)count / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
