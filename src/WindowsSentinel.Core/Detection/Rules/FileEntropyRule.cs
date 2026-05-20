using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Detects high-entropy files that may be packed, encrypted, or obfuscated.
/// 
/// High entropy (>7.0) indicates compressed/encrypted data, common in:
/// - Packed malware (UPX, custom packers)
/// - Encrypted payloads
/// - Obfuscated scripts
/// 
/// Whitelists legitimate high-entropy files (compressed archives, media files).
/// </summary>
public sealed class FileEntropyRule : IDetectionRule
{
    public string Name => "High File Entropy (Packed/Encrypted)";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    // Entropy threshold (0-8 scale, Shannon entropy)
    private const double EntropyThreshold = 7.0;
    private const double CriticalEntropyThreshold = 7.5;

    // File size limits to avoid scanning huge files
    private const long MinFileSize = 1024;      // 1 KB (skip tiny files)
    private const long MaxFileSize = 10 * 1024 * 1024; // 10 MB max

    // Legitimate high-entropy extensions (expected to be compressed/encrypted)
    private static readonly HashSet<string> WhitelistedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        // Compressed archives
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".lz4", ".zst",
        // Media files
        ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".avi", ".mov",
        ".mkv", ".flv", ".wmv", ".m4v", ".mpg", ".mpeg", ".webm",
        // Document formats
        ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
        // Other known formats
        ".exe", // Exes are expected to have moderate entropy
        ".msi", ".msp", // Installers are compressed
    };

    // Suspicious paths where high entropy is more concerning
    private static readonly string[] SuspiciousPaths = new[]
    {
        @"\temp\", @"\tmp\", @"\appdata\local\temp", @"\downloads\",
        @"\desktop\", @"\public\", @"\programdata\", @"\appdata\roaming\"
    };

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not FileActivityTelemetry file) return null;
        
        // Check the destination file (NewPath) for high entropy.
        // This covers both new files AND renames (ransomware encrypts then renames).
        var filePath = file.NewPath;
        var extension = Path.GetExtension(filePath);

        // Skip whitelisted extensions
        if (WhitelistedExtensions.Contains(extension))
            return null;

        // Check file size
        try
        {
            var fileInfo = new FileInfo(filePath);
            if (!fileInfo.Exists) return null;
            if (fileInfo.Length < MinFileSize || fileInfo.Length > MaxFileSize)
                return null;

            // Calculate entropy
            var entropy = CalculateEntropy(filePath);
            if (entropy < EntropyThreshold)
                return null;

            // Higher entropy in suspicious paths = higher confidence
            var pathLower = filePath.ToLowerInvariant();
            bool inSuspiciousPath = SuspiciousPaths.Any(sp => pathLower.Contains(sp));
            
            double confidence = entropy >= CriticalEntropyThreshold ? 0.85 : 0.72;
            if (inSuspiciousPath && entropy >= CriticalEntropyThreshold)
                confidence = 0.92;

            var evidence = $"High entropy file detected: '{Path.GetFileName(filePath)}' | " +
                          $"Entropy: {entropy:F2}/8.0 | Size: {fileInfo.Length / 1024} KB | " +
                          $"Path: {filePath}";

            if (inSuspiciousPath)
                evidence += " | Located in suspicious path";

            return new DetectionEvent
            {
                RuleName = Name,
                Evidence = evidence,
                Reasoning = "High entropy (Shannon entropy > 7.0) indicates compressed, encrypted, or obfuscated data. " +
                    "Malware commonly uses packers (UPX, custom) to evade signature detection. " +
                    "Entropy measures randomness - legitimate executables typically have entropy 5.0-6.5, " +
                    "while packed/encrypted data exceeds 7.0. Files in temp/downloads directories with " +
                    "high entropy are particularly suspicious.",
                Confidence = confidence,
                Tier = Tier,
                ProcessName = "FileSystem",
                ProcessId = 0,
                Timestamp = file.Timestamp,
                Metadata = new()
                {
                    ["FilePath"] = filePath,
                    ["Entropy"] = entropy.ToString("F4"),
                    ["FileSize"] = fileInfo.Length.ToString(),
                    ["Extension"] = extension,
                    ["SuspiciousPath"] = inSuspiciousPath.ToString()
                }
            };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Calculates Shannon entropy of a file (0-8 scale for bytes).
    /// </summary>
    private static double CalculateEntropy(string filePath)
    {
        try
        {
            // Read first 4KB for performance (entropy is consistent across file)
            byte[] bytes;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                var buffer = new byte[4096];
                int read = fs.Read(buffer, 0, buffer.Length);
                bytes = new byte[read];
                Buffer.BlockCopy(buffer, 0, bytes, 0, read);
            }

            if (bytes.Length == 0) return 0;

            // Calculate frequency of each byte value
            var frequencies = new int[256];
            foreach (byte b in bytes)
            {
                frequencies[b]++;
            }

            // Calculate Shannon entropy: -Σ(p(x) * log2(p(x)))
            double entropy = 0;
            int length = bytes.Length;
            
            foreach (var freq in frequencies)
            {
                if (freq == 0) continue;
                
                double probability = (double)freq / length;
                entropy -= probability * Math.Log2(probability);
            }

            return entropy;
        }
        catch
        {
            return 0;
        }
    }
}


