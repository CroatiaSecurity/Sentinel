using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// False Positive Tracker - Learns from user-restored files to reduce future false positives.
/// Tracks patterns that were previously flagged but found to be legitimate.
///
/// SECURITY HARDENING (v0.4.0): persistence routed through <see cref="SecureCacheStore"/>.
/// Pre-0.4 wrote a plain-text JSON under %LOCALAPPDATA% — an attacker could plant FP
/// records to whitelist their payload via the FP-reduction path. The store now requires
/// DPAPI machine-binding + HMAC; tampered/foreign files are rejected on load.
/// </summary>
public sealed class FalsePositiveTracker
{
    private readonly ILogger<FalsePositiveTracker> _logger;
    private readonly SecureCacheStore _store;

    private readonly ConcurrentDictionary<string, FalsePositiveRecord> _fpHashes;
    private readonly ConcurrentDictionary<string, int> _fpProcessPatterns;
    private readonly ConcurrentDictionary<string, int> _fpSignerPatterns;
    private readonly ConcurrentDictionary<string, int> _fpPathPatterns;

    private readonly int _minPatternOccurrences = 3;

    public FalsePositiveTracker(ILogger<FalsePositiveTracker> logger)
    {
        _logger = logger;
        _store = new SecureCacheStore(logger, "false_positive_data");

        _fpHashes = new ConcurrentDictionary<string, FalsePositiveRecord>();
        _fpProcessPatterns = new ConcurrentDictionary<string, int>();
        _fpSignerPatterns = new ConcurrentDictionary<string, int>();
        _fpPathPatterns = new ConcurrentDictionary<string, int>();

        LoadData();
    }

    /// <summary>
    /// Records a false positive - when a file was quarantined but restored by user.
    /// </summary>
    public void RecordFalsePositive(
        string fileHash,
        string filePath,
        string processName,
        string? signerName,
        string ruleName)
    {
        if (string.IsNullOrEmpty(fileHash)) return;

        _logger.LogInformation(
            "FPTracker: Recording false positive for {Process} ({Hash}) - Rule: {Rule}",
            processName, fileHash[..16] + "...", ruleName);

        // Record the hash
        _fpHashes[fileHash.ToUpperInvariant()] = new FalsePositiveRecord
        {
            Hash = fileHash,
            FilePath = filePath,
            ProcessName = processName,
            SignerName = signerName ?? "",
            RuleName = ruleName,
            Timestamp = DateTimeOffset.UtcNow,
            OccurrenceCount = 1
        };

        // Update pattern counts
        if (!string.IsNullOrEmpty(processName))
        {
            _fpProcessPatterns.AddOrUpdate(processName.ToLowerInvariant(), 1, (_, count) => count + 1);
        }

        if (!string.IsNullOrEmpty(signerName))
        {
            _fpSignerPatterns.AddOrUpdate(signerName.ToLowerInvariant(), 1, (_, count) => count + 1);
        }

        // Extract and record path pattern
        var pathPattern = ExtractPathPattern(filePath);
        if (!string.IsNullOrEmpty(pathPattern))
        {
            _fpPathPatterns.AddOrUpdate(pathPattern.ToLowerInvariant(), 1, (_, count) => count + 1);
        }

        // Save to disk
        _ = Task.Run(SaveData);
    }

    /// <summary>
    /// Checks if a hash is a known false positive.
    /// </summary>
    public bool IsKnownFalsePositiveHash(string hash)
    {
        if (string.IsNullOrEmpty(hash)) return false;
        return _fpHashes.ContainsKey(hash.ToUpperInvariant());
    }

    /// <summary>
    /// Checks if a process pattern is frequently a false positive.
    /// </summary>
    public bool IsFrequentFalsePositiveProcess(string processName)
    {
        if (string.IsNullOrEmpty(processName)) return false;
        
        if (_fpProcessPatterns.TryGetValue(processName.ToLowerInvariant(), out var count))
        {
            return count >= _minPatternOccurrences;
        }
        
        return false;
    }

    /// <summary>
    /// Checks if a signer is frequently a false positive.
    /// </summary>
    public bool IsFrequentFalsePositiveSigner(string signerName)
    {
        if (string.IsNullOrEmpty(signerName)) return false;
        
        if (_fpSignerPatterns.TryGetValue(signerName.ToLowerInvariant(), out var count))
        {
            return count >= _minPatternOccurrences;
        }
        
        return false;
    }

    /// <summary>
    /// Checks if a path pattern is frequently a false positive.
    /// </summary>
    public bool IsFrequentFalsePositivePath(string filePath)
    {
        if (string.IsNullOrEmpty(filePath)) return false;
        
        var pattern = ExtractPathPattern(filePath);
        if (string.IsNullOrEmpty(pattern)) return false;
        
        if (_fpPathPatterns.TryGetValue(pattern.ToLowerInvariant(), out var count))
        {
            return count >= _minPatternOccurrences;
        }
        
        return false;
    }

    /// <summary>
    /// Gets the suspicion reduction for a file based on FP history.
    /// Returns a negative number to subtract from suspicion score.
    /// </summary>
    public int GetSuspicionReduction(
        string? hash,
        string? processName,
        string? signerName,
        string? filePath)
    {
        int reduction = 0;

        // Known FP hash provides strong reduction
        if (!string.IsNullOrEmpty(hash) && IsKnownFalsePositiveHash(hash))
        {
            reduction += 30;
        }

        // Frequent FP process
        if (!string.IsNullOrEmpty(processName) && IsFrequentFalsePositiveProcess(processName))
        {
            reduction += 15;
        }

        // Frequent FP signer
        if (!string.IsNullOrEmpty(signerName) && IsFrequentFalsePositiveSigner(signerName))
        {
            reduction += 20;
        }

        // Frequent FP path
        if (!string.IsNullOrEmpty(filePath) && IsFrequentFalsePositivePath(filePath))
        {
            reduction += 10;
        }

        // Cap reduction at -30 (don't go below 0 suspicion)
        return Math.Max(-30, reduction);
    }

    /// <summary>
    /// Estimates the confidence that a detection is a false positive.
    /// Returns 0-100 where higher means more likely to be FP.
    /// </summary>
    public int EstimateFalsePositiveConfidence(
        string? hash,
        string? filePath,
        string? processName,
        string? signerName)
    {
        int confidence = 0;

        if (!string.IsNullOrEmpty(hash) && IsKnownFalsePositiveHash(hash))
        {
            confidence += 40;
        }

        if (!string.IsNullOrEmpty(processName) && IsFrequentFalsePositiveProcess(processName))
        {
            confidence += 20;
        }

        if (!string.IsNullOrEmpty(signerName) && IsFrequentFalsePositiveSigner(signerName))
        {
            confidence += 25;
        }

        if (!string.IsNullOrEmpty(filePath) && IsFrequentFalsePositivePath(filePath))
        {
            confidence += 15;
        }

        return Math.Min(100, confidence);
    }

    /// <summary>
    /// Gets FP statistics.
    /// </summary>
    public FalsePositiveStatistics GetStatistics()
    {
        return new FalsePositiveStatistics
        {
            KnownFalsePositiveHashes = _fpHashes.Count,
            FrequentProcessPatterns = _fpProcessPatterns.Count(p => p.Value >= _minPatternOccurrences),
            FrequentSignerPatterns = _fpSignerPatterns.Count(p => p.Value >= _minPatternOccurrences),
            FrequentPathPatterns = _fpPathPatterns.Count(p => p.Value >= _minPatternOccurrences),
            TotalProcessPatterns = _fpProcessPatterns.Count,
            TotalSignerPatterns = _fpSignerPatterns.Count,
            TotalPathPatterns = _fpPathPatterns.Count
        };
    }

    /// <summary>
    /// Clears all FP data (use with caution).
    /// </summary>
    public void ClearData()
    {
        _fpHashes.Clear();
        _fpProcessPatterns.Clear();
        _fpSignerPatterns.Clear();
        _fpPathPatterns.Clear();

        _store.Delete();

        _logger.LogWarning("FPTracker: All false positive data cleared");
    }

    /// <summary>
    /// Exports FP data to JSON.
    /// </summary>
    public string ExportToJson()
    {
        var data = new FalsePositiveData
        {
            Hashes = _fpHashes.Values.ToList(),
            ProcessPatterns = _fpProcessPatterns.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
            SignerPatterns = _fpSignerPatterns.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
            PathPatterns = _fpPathPatterns.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
            ExportedAt = DateTimeOffset.UtcNow
        };

        return JsonSerializer.Serialize(data, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
    }

    private string? ExtractPathPattern(string path)
    {
        if (string.IsNullOrEmpty(path)) return null;

        try
        {
            // Extract folder pattern
            var dir = Path.GetDirectoryName(path);
            if (string.IsNullOrEmpty(dir)) return null;

            // Return parent folder as pattern
            // e.g., "C:\Program Files\MyApp\bin\app.exe" -> "C:\Program Files\MyApp"
            var parts = dir.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                return string.Join(Path.DirectorySeparatorChar, parts.Take(3));
            }

            return dir;
        }
        catch
        {
            return null;
        }
    }

    private void LoadData()
    {
        var data = _store.TryLoad<FalsePositiveData>();
        if (data is null)
        {
            _logger.LogInformation("FPTracker: No trusted FP data loaded — starting clean");
            return;
        }

        foreach (var record in data.Hashes)
            _fpHashes[record.Hash.ToUpperInvariant()] = record;
        foreach (var pattern in data.ProcessPatterns)
            _fpProcessPatterns[pattern.Key] = pattern.Value;
        foreach (var pattern in data.SignerPatterns)
            _fpSignerPatterns[pattern.Key] = pattern.Value;
        foreach (var pattern in data.PathPatterns)
            _fpPathPatterns[pattern.Key] = pattern.Value;

        _logger.LogInformation(
            "FPTracker: Loaded {Hashes} FP hashes, {Proc} process patterns, {Sig} signer patterns, {Path} path patterns",
            _fpHashes.Count, _fpProcessPatterns.Count, _fpSignerPatterns.Count, _fpPathPatterns.Count);
    }

    private void SaveData()
    {
        var data = new FalsePositiveData
        {
            Hashes = _fpHashes.Values.ToList(),
            ProcessPatterns = _fpProcessPatterns.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
            SignerPatterns = _fpSignerPatterns.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
            PathPatterns = _fpPathPatterns.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
            ExportedAt = DateTimeOffset.UtcNow
        };
        if (!_store.TrySave(data))
            _logger.LogWarning("FPTracker: Save failed");
    }
}

// Data models

public sealed class FalsePositiveRecord
{
    public string Hash { get; set; } = "";
    public string FilePath { get; set; } = "";
    public string ProcessName { get; set; } = "";
    public string SignerName { get; set; } = "";
    public string RuleName { get; set; } = "";
    public DateTimeOffset Timestamp { get; set; }
    public int OccurrenceCount { get; set; }
}

public sealed class FalsePositiveData
{
    public List<FalsePositiveRecord> Hashes { get; set; } = new();
    public Dictionary<string, int> ProcessPatterns { get; set; } = new();
    public Dictionary<string, int> SignerPatterns { get; set; } = new();
    public Dictionary<string, int> PathPatterns { get; set; } = new();
    public DateTimeOffset ExportedAt { get; set; }
}

public sealed class FalsePositiveStatistics
{
    public int KnownFalsePositiveHashes { get; set; }
    public int FrequentProcessPatterns { get; set; }
    public int FrequentSignerPatterns { get; set; }
    public int FrequentPathPatterns { get; set; }
    public int TotalProcessPatterns { get; set; }
    public int TotalSignerPatterns { get; set; }
    public int TotalPathPatterns { get; set; }
}

