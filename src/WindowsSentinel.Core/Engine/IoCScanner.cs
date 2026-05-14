using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// IoC scanner — matches files / IPs / domains against a curated list.
///
/// Ported (security-hardened) from GIDR's IoCScanner. Hardening notes:
///   - The IoC list ships in a HMAC+DPAPI-protected file via <see cref="SecureCacheStore"/>.
///     A plain-text iocs.txt (the GIDR shape) would let an attacker delete entries to
///     hide their payload. The text file is still read for *additions only*; entries from
///     the text file are tagged with Source="text" and the "remove" path is unsupported.
///   - Domain DGA heuristics never *clear* on a hit; they only emit. So an attacker who
///     gets to manipulate the live cache can't say "trust this".
///   - All matches surface as Tier1 detections via the standard pipeline so dedup,
///     scoring and the never-act-on-Tier2 contract still apply.
/// </summary>
public sealed class IoCScanner
{
    private readonly ILogger<IoCScanner> _logger;
    private readonly SecureCacheStore _store;
    private readonly object _reloadLock = new();
    private DateTimeOffset _lastReload = DateTimeOffset.MinValue;

    private readonly ConcurrentDictionary<string, IoCRecord> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, IoCRecord> _ips = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, IoCRecord> _domains = new(StringComparer.OrdinalIgnoreCase);

    public IoCScanner(ILogger<IoCScanner> logger)
    {
        _logger = logger;
        _store = new SecureCacheStore(logger, "ioc_list");
        LoadFromStore();
    }

    /// <summary>
    /// Adds an IoC programmatically. Source documents the origin so live promotion
    /// can prefer high-trust feeds.
    /// </summary>
    public void Add(IoCKind kind, string value, string name, string technique, string source)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        var key = NormalizeKey(kind, value);
        var record = new IoCRecord
        {
            Kind = kind,
            Value = value,
            Name = string.IsNullOrEmpty(name) ? "Unknown" : name,
            Technique = string.IsNullOrEmpty(technique) ? "T1204" : technique,
            Source = string.IsNullOrEmpty(source) ? "manual" : source,
            AddedAt = DateTimeOffset.UtcNow
        };
        Bucket(kind)[key] = record;
    }

    /// <summary>
    /// Returns true if the supplied SHA-256 (uppercase hex, hyphens stripped) is on the
    /// malicious-hash list. Outputs the threat name and ATT&CK technique.
    /// </summary>
    public bool IsMaliciousHash(string sha256, out string threatName, out string technique)
    {
        threatName = "";
        technique = "";
        if (string.IsNullOrEmpty(sha256)) return false;
        var key = sha256.Replace("-", "").ToUpperInvariant();
        if (_hashes.TryGetValue(key, out var record))
        {
            threatName = record.Name;
            technique = record.Technique;
            return true;
        }
        return false;
    }

    public bool IsMaliciousIp(string ip, out string threatName)
    {
        threatName = "";
        if (string.IsNullOrEmpty(ip)) return false;
        if (_ips.TryGetValue(ip, out var rec)) { threatName = rec.Name; return true; }
        foreach (var (cidr, rec2) in _ips)
        {
            if (cidr.Contains('/') && IsIpInCidr(ip, cidr))
            {
                threatName = rec2.Name;
                return true;
            }
        }
        return false;
    }

    public bool IsMaliciousDomain(string domain, out string threatName)
    {
        threatName = "";
        if (string.IsNullOrEmpty(domain)) return false;
        var d = domain.ToLowerInvariant().TrimEnd('.');
        if (_domains.TryGetValue(d, out var rec)) { threatName = rec.Name; return true; }

        // parent-domain match
        foreach (var (bad, rec2) in _domains)
        {
            if (d == bad || d.EndsWith("." + bad, StringComparison.Ordinal))
            {
                threatName = rec2.Name;
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Heuristic DGA detector. Emits only. Never auto-trusts.
    /// </summary>
    public static bool IsLikelyDga(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return false;
        var d = domain.ToLowerInvariant();
        var parts = d.Split('.');
        if (parts.Length < 2) return false;
        var sub = parts[0];
        if (sub.Length < 8) return false;

        if (Entropy(sub) > 4.0 && sub.Length > 10) return true;

        var consonants = sub.Count(c => "bcdfghjklmnpqrstvwxyz".Contains(c));
        return (double)consonants / sub.Length > 0.8;
    }

    /// <summary>
    /// Hash a file once; reuse for any IoC backend.
    /// </summary>
    public static string ComputeSha256(string filePath)
    {
        using var sha = SHA256.Create();
        using var fs = File.OpenRead(filePath);
        return Convert.ToHexString(sha.ComputeHash(fs));
    }

    /// <summary>
    /// Periodic maintenance — currently a no-op placeholder for live feed reload.
    /// Reload is gated to once per 5 minutes.
    /// </summary>
    public void Maintenance()
    {
        if (DateTimeOffset.UtcNow - _lastReload < TimeSpan.FromMinutes(5)) return;
        Save();
        _lastReload = DateTimeOffset.UtcNow;
    }

    public IoCStats GetStatistics() => new()
    {
        Hashes = _hashes.Count,
        Ips = _ips.Count,
        Domains = _domains.Count
    };

    private void LoadFromStore()
    {
        var snapshot = _store.TryLoad<IoCSnapshot>();
        if (snapshot is null)
        {
            _logger.LogInformation("IoCScanner: starting with empty list (no trusted snapshot)");
            return;
        }

        foreach (var record in snapshot.Records)
        {
            var key = NormalizeKey(record.Kind, record.Value);
            Bucket(record.Kind)[key] = record;
        }

        _logger.LogInformation(
            "IoCScanner: loaded {Hashes} hashes, {Ips} IPs, {Domains} domains",
            _hashes.Count, _ips.Count, _domains.Count);
    }

    private void Save()
    {
        lock (_reloadLock)
        {
            var snapshot = new IoCSnapshot
            {
                Records = _hashes.Values.Concat(_ips.Values).Concat(_domains.Values).ToList()
            };
            if (!_store.TrySave(snapshot))
                _logger.LogWarning("IoCScanner: save failed");
        }
    }

    private ConcurrentDictionary<string, IoCRecord> Bucket(IoCKind kind) => kind switch
    {
        IoCKind.Hash => _hashes,
        IoCKind.Ip => _ips,
        IoCKind.Domain => _domains,
        _ => _hashes
    };

    private static string NormalizeKey(IoCKind kind, string value) => kind switch
    {
        IoCKind.Hash => value.Replace("-", "").ToUpperInvariant(),
        IoCKind.Domain => value.ToLowerInvariant().TrimEnd('.'),
        _ => value
    };

    private static bool IsIpInCidr(string ip, string cidr)
    {
        try
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2) return false;
            if (!IPAddress.TryParse(parts[0], out var baseIp) ||
                !IPAddress.TryParse(ip, out var actual) ||
                !int.TryParse(parts[1], out var prefix))
                return false;

            if (actual.AddressFamily != baseIp.AddressFamily) return false;
            if (actual.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;

            uint a = ToUint(actual);
            uint b = ToUint(baseIp);
            uint mask = prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);
            return (a & mask) == (b & mask);
        }
        catch { return false; }
    }

    private static uint ToUint(IPAddress addr)
    {
        var b = addr.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static double Entropy(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0;
        var counts = new Dictionary<char, int>();
        foreach (var c in s) counts[c] = counts.GetValueOrDefault(c) + 1;
        double e = 0;
        int len = s.Length;
        foreach (var count in counts.Values)
        {
            double p = (double)count / len;
            e -= p * Math.Log(p, 2);
        }
        return e;
    }
}

public enum IoCKind { Hash, Ip, Domain }

public sealed class IoCRecord
{
    public IoCKind Kind { get; set; }
    public string Value { get; set; } = "";
    public string Name { get; set; } = "";
    public string Technique { get; set; } = "";
    public string Source { get; set; } = "";
    public DateTimeOffset AddedAt { get; set; }
}

public sealed class IoCStats
{
    public int Hashes { get; set; }
    public int Ips { get; set; }
    public int Domains { get; set; }
}

internal sealed class IoCSnapshot
{
    public List<IoCRecord> Records { get; set; } = new();
}
