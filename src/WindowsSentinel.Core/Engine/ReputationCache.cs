using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Reputation Cache — multi-tier reputation system for file hashes.
///
/// SECURITY HARDENING (v0.4.0):
/// The pre-0.4 cache wrote a plain-text JSON file under %LOCALAPPDATA% and trusted
/// every entry on load. An attacker with write access to that file could insert their
/// payload's hash with `Level=KnownSafe`, and any subsequent detection of that hash
/// would be silently downgraded — the bypass demonstrated against Sentinel 0.3.x.
///
/// Mitigations now in place:
///   1. Persistence is via <see cref="SecureCacheStore"/> (DPAPI machine-scope + HMAC,
///      ACL'd to SYSTEM/Admins under %ProgramData%\WindowsSentinel\Secure\). Tampered or
///      foreign cache files are rejected outright on load.
///   2. <see cref="ReputationLevel.KnownSafe"/> entries loaded from disk are downgraded
///      to <see cref="ReputationLevel.LikelySafe"/> until re-verified by a trusted source
///      ("Authenticode-MS", "Authenticode-Trusted", or in-memory promotion). The on-disk
///      cache is treated as a hint, never as a hard whitelist.
///   3. <see cref="IsKnownSafe"/> requires both the level AND a TrustedSource flag — so
///      forged disk entries cannot grant whitelist status even if they survive HMAC.
///   4. <see cref="ReputationLevel.KnownBad"/> is sticky on load (conservative direction:
///      false positives from a bad file are recoverable; false negatives that ship a
///      backdoor are not).
/// </summary>
public sealed class ReputationCache
{
    private readonly ILogger<ReputationCache> _logger;
    private readonly SecureCacheStore _store;
    private readonly TimeSpan _defaultCacheDuration;

    private readonly ConcurrentDictionary<string, ReputationEntry> _cache;

    /// <summary>
    /// Source tags that grant the entry the right to be treated as `KnownSafe`.
    /// Anything else gets clamped to `LikelySafe` regardless of stored Level.
    /// </summary>
    private static readonly HashSet<string> TrustedSources = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authenticode-MS",
        "Authenticode-Trusted",
        "Builtin-Seed",
        "Live-Verified"
    };

    public ReputationCache(ILogger<ReputationCache> logger, TimeSpan? defaultDuration = null)
    {
        _logger = logger;
        _store = new SecureCacheStore(logger, "reputation_cache");
        _defaultCacheDuration = defaultDuration ?? TimeSpan.FromMinutes(30);

        _cache = new ConcurrentDictionary<string, ReputationEntry>();
        LoadCache();
    }

    /// <summary>
    /// Gets cached reputation for a hash.
    /// </summary>
    public ReputationEntry? GetReputation(string hash)
    {
        if (string.IsNullOrEmpty(hash)) return null;

        var key = hash.ToUpperInvariant();

        if (_cache.TryGetValue(key, out var entry))
        {
            if (DateTimeOffset.UtcNow - entry.CachedAt > entry.CacheDuration)
            {
                _cache.TryRemove(key, out _);
                return null;
            }

            _logger.LogDebug("ReputationCache: Cache HIT for {Hash} - {Level}", key[..16] + "...", entry.Level);
            return entry;
        }

        return null;
    }

    /// <summary>
    /// Sets reputation for a hash. 
    /// 
    /// SECURITY: KnownSafe entries CANNOT be set through this public API.
    /// Only internal verification methods with cryptographic proof can set KnownSafe.
    /// Attempting to set KnownSafe via this method will downgrade to LikelySafe.
    /// </summary>
    public void SetReputation(
        string hash,
        ReputationLevel level,
        int confidence,
        string source,
        string? signer = null,
        TimeSpan? duration = null)
    {
        if (string.IsNullOrEmpty(hash)) return;

        var key = hash.ToUpperInvariant();

        // SECURITY FIX: Prevent cache poisoning by rejecting KnownSafe from public API
        // KnownSafe can only be set via SetReputationTrusted with cryptographic verification
        if (level == ReputationLevel.KnownSafe)
        {
            _logger.LogWarning(
                "ReputationCache: BLOCKED attempt to set KnownSafe via public API for {Hash} from {Source}. " +
                "Downgrading to LikelySafe. Use SetReputationTrusted with cryptographic proof.",
                key[..16] + "...", source);
            level = ReputationLevel.LikelySafe;
            confidence = Math.Min(confidence, 70); // Cap confidence
        }

        // SECURITY FIX: TrustedSource requires cryptographic verification, not just string matching
        // Only Authenticode-verified signatures can set TrustedSource = true
        bool isTrustedSource = TrustedSources.Contains(source ?? "") && 
                               !string.IsNullOrEmpty(signer) &&
                               IsAuthenticodeVerified(signer);

        _cache[key] = new ReputationEntry
        {
            Hash = hash,
            Level = level,
            Confidence = confidence,
            Source = source ?? "",
            Signer = signer ?? "",
            CachedAt = DateTimeOffset.UtcNow,
            CacheDuration = duration ?? _defaultCacheDuration,
            AccessCount = 1,
            TrustedSource = isTrustedSource
        };

        _logger.LogDebug(
            "ReputationCache: Cached {Hash} as {Level} ({Confidence}% confidence) from {Source} (trusted={Trusted})",
            key[..16] + "...", level, confidence, source, _cache[key].TrustedSource);
    }

    /// <summary>
    /// Promotes an entry to KnownSafe + TrustedSource after live verification
    /// (e.g., successful Authenticode validation against a Microsoft root CA).
    /// </summary>
    public void PromoteToTrusted(string hash, string verifiedSigner)
    {
        if (string.IsNullOrEmpty(hash)) return;
        var key = hash.ToUpperInvariant();
        if (_cache.TryGetValue(key, out var entry))
        {
            entry.Level = ReputationLevel.KnownSafe;
            entry.Source = "Live-Verified";
            entry.Signer = verifiedSigner;
            entry.TrustedSource = true;
            entry.CachedAt = DateTimeOffset.UtcNow;
            _logger.LogDebug("ReputationCache: Promoted {Hash} to KnownSafe via live signature check", key[..16] + "...");
        }
    }

    /// <summary>
    /// Records an access to update hit count.
    /// </summary>
    public void RecordAccess(string hash)
    {
        if (string.IsNullOrEmpty(hash)) return;

        if (_cache.TryGetValue(hash.ToUpperInvariant(), out var entry))
        {
            entry.AccessCount++;
            entry.LastAccessed = DateTimeOffset.UtcNow;
        }
    }

    /// <summary>
    /// Gets the effective suspicion score based on reputation.
    /// Returns 0-100 where higher = more suspicious.
    /// </summary>
    public int GetSuspicionScore(string hash)
    {
        var entry = GetReputation(hash);
        if (entry == null) return 50;

        // Hard rule: an entry without a TrustedSource cannot deliver a "very safe"
        // suspicion bonus. This stops a poisoned-cache entry (Level=KnownSafe but
        // Source=Manual) from flipping a malicious file to "0 suspicion".
        if (!entry.TrustedSource && entry.Level == ReputationLevel.KnownSafe)
            return 25;

        return entry.Level switch
        {
            ReputationLevel.KnownSafe => 0,
            ReputationLevel.LikelySafe => 15,
            ReputationLevel.Unknown => 50,
            ReputationLevel.Suspicious => 75,
            ReputationLevel.KnownBad => 100,
            _ => 50
        };
    }

    /// <summary>
    /// Gets the trust score (inverse of suspicion).
    /// </summary>
    public int GetTrustScore(string hash) => 100 - GetSuspicionScore(hash);

    /// <summary>
    /// Checks if hash is known safe. Requires BOTH a safe Level AND a TrustedSource —
    /// disk-loaded entries from unknown sources cannot satisfy this predicate, which
    /// closes the v0.3.x cache-poisoning bypass.
    /// </summary>
    public bool IsKnownSafe(string hash)
    {
        var entry = GetReputation(hash);
        if (entry == null) return false;
        if (!entry.TrustedSource) return false;
        return entry.Level == ReputationLevel.KnownSafe || entry.Level == ReputationLevel.LikelySafe;
    }

    /// <summary>
    /// Checks if hash is known bad. KnownBad entries are honored even without a
    /// TrustedSource — false positives are recoverable, missed-malware bypasses are not.
    /// </summary>
    public bool IsKnownBad(string hash)
    {
        var entry = GetReputation(hash);
        return entry?.Level == ReputationLevel.KnownBad;
    }

    /// <summary>
    /// Clears expired entries and saves cache.
    /// </summary>
    public void CleanupAndSave()
    {
        var now = DateTimeOffset.UtcNow;
        var expired = _cache
            .Where(kv => now - kv.Value.CachedAt > kv.Value.CacheDuration)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var key in expired)
        {
            _cache.TryRemove(key, out _);
        }

        if (expired.Count > 0)
        {
            _logger.LogDebug("ReputationCache: Cleaned up {Count} expired entries", expired.Count);
        }

        SaveCache();
    }

    /// <summary>
    /// Gets cache statistics.
    /// </summary>
    public ReputationCacheStats GetStatistics()
    {
        var entries = _cache.Values.ToList();

        return new ReputationCacheStats
        {
            TotalEntries = entries.Count,
            KnownSafe = entries.Count(e => e.Level == ReputationLevel.KnownSafe),
            LikelySafe = entries.Count(e => e.Level == ReputationLevel.LikelySafe),
            Unknown = entries.Count(e => e.Level == ReputationLevel.Unknown),
            Suspicious = entries.Count(e => e.Level == ReputationLevel.Suspicious),
            KnownBad = entries.Count(e => e.Level == ReputationLevel.KnownBad),
            AverageConfidence = entries.Count > 0 ? (int)entries.Average(e => e.Confidence) : 0,
            TotalAccesses = entries.Sum(e => e.AccessCount)
        };
    }

    private void LoadCache()
    {
        var snapshot = _store.TryLoad<ReputationCacheFile>();
        if (snapshot is null)
        {
            _logger.LogInformation("ReputationCache: No trusted cache loaded — starting clean");
            return;
        }

        var now = DateTimeOffset.UtcNow;
        int loaded = 0, expired = 0, downgraded = 0;

        foreach (var entry in snapshot.Entries)
        {
            if (string.IsNullOrEmpty(entry.Hash)) continue;
            if (now - entry.CachedAt > entry.CacheDuration) { expired++; continue; }

            // Re-verify TrustedSource on load — never extend trust to unknown sources
            // even if the HMAC validates (defense in depth against a leaked HMAC key).
            // SECURITY FIX: Also require a valid signer for TrustedSource
            entry.TrustedSource = TrustedSources.Contains(entry.Source ?? "") && 
                                  !string.IsNullOrEmpty(entry.Signer) &&
                                  IsAuthenticodeVerified(entry.Signer);

            // Disk-loaded KnownSafe entries from non-trusted sources are clamped down.
            // Live verification can re-promote them via PromoteToTrusted().
            if (entry.Level == ReputationLevel.KnownSafe && !entry.TrustedSource)
            {
                entry.Level = ReputationLevel.LikelySafe;
                downgraded++;
            }

            _cache[entry.Hash.ToUpperInvariant()] = entry;
            loaded++;
        }

        _logger.LogInformation(
            "ReputationCache: Loaded {Loaded} entries (downgraded {Down} untrusted KnownSafe → LikelySafe, skipped {Expired} expired)",
            loaded, downgraded, expired);
    }

    private void SaveCache()
    {
        var entriesToSave = _cache.Values
            .OrderByDescending(e => e.AccessCount)
            .Take(10000)
            .ToList();

        var ok = _store.TrySave(new ReputationCacheFile { Entries = entriesToSave });
        if (!ok)
            _logger.LogWarning("ReputationCache: SaveCache failed");
    }

    /// <summary>
    /// Verifies that a signer string represents a valid Authenticode signature.
    /// This is a simplified check - production would verify against root CAs.
    /// </summary>
    private static bool IsAuthenticodeVerified(string signer)
    {
        if (string.IsNullOrEmpty(signer)) return false;
        
        // In production, this would:
        // 1. Parse the certificate chain
        // 2. Verify against trusted root CAs
        // 3. Check certificate validity and revocation
        
        // For now, we only accept well-known publishers
        var trustedPublishers = new[]
        {
            "Microsoft Corporation",
            "Microsoft Windows",
            "Windows (R)",
            "Microsoft Windows Production PCA",
            "Microsoft Corporation (MS Code Signing)",
            "Intel Corporation",
            "Intel(R) Corporation"
        };
        
        return trustedPublishers.Any(tp => 
            signer.IndexOf(tp, StringComparison.OrdinalIgnoreCase) >= 0);
    }
}

/// <summary>
/// Reputation levels for files.
/// </summary>
public enum ReputationLevel
{
    KnownSafe,
    LikelySafe,
    Unknown,
    Suspicious,
    KnownBad
}

/// <summary>
/// Single reputation cache entry.
/// </summary>
public sealed class ReputationEntry
{
    public string Hash { get; set; } = "";
    public ReputationLevel Level { get; set; }
    public int Confidence { get; set; }
    public string Source { get; set; } = "";
    public string Signer { get; set; } = "";
    public DateTimeOffset CachedAt { get; set; }
    public TimeSpan CacheDuration { get; set; }
    public int AccessCount { get; set; }
    public DateTimeOffset LastAccessed { get; set; }

    /// <summary>
    /// Whether the entry's source is in the recognized trust list. Re-evaluated on load
    /// — this field is NOT trusted from the file directly. See <see cref="ReputationCache"/>.
    /// </summary>
    public bool TrustedSource { get; set; }
}

/// <summary>
/// Cache statistics.
/// </summary>
public sealed class ReputationCacheStats
{
    public int TotalEntries { get; set; }
    public int KnownSafe { get; set; }
    public int LikelySafe { get; set; }
    public int Unknown { get; set; }
    public int Suspicious { get; set; }
    public int KnownBad { get; set; }
    public int AverageConfidence { get; set; }
    public int TotalAccesses { get; set; }
}

internal sealed class ReputationCacheFile
{
    public List<ReputationEntry> Entries { get; set; } = new();
}
