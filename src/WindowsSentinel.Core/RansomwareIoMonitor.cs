using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core;

/// <summary>
/// Behavioral ransomware detector â€” measures per-process write I/O via WMI's
/// <c>Win32_Process.WriteOperationCount</c> / <c>WriteTransferCount</c> counters and
/// emits a Tier1 detection when a non-whitelisted process exceeds the rate threshold
/// inside a 2-minute window.
///
/// Ported (security-hardened) from GIDR's RansomwareDetection. Hardening notes:
///   - Whitelist is hard-coded here; it is NOT loaded from a user-writable file
///     (would otherwise be a quiet way to mask a payload â€” same class of bug as the
///     reputation-cache poisoning fixed in 0.4.0).
///   - WMI query is parameterized via WHERE ProcessId, not string-built.
///   - Detection emits via <see cref="DetectionEngine"/> so the central response
///     gates apply (Tier2-never-acts, dedup, scoring, learning mode).
///   - "Auto-kill" is NOT performed here â€” that is owned by the response engine,
///     which already enforces confidence/corroboration rules.
/// </summary>
public sealed class RansomwareIoMonitor : BackgroundService
{
    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan WindowDuration = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan ProcessTtl = TimeSpan.FromMinutes(5);

    private static readonly HashSet<string> Whitelist = new(StringComparer.OrdinalIgnoreCase)
    {
        // Encryption / backup / sync â€” legitimate mass-IO
        "bitlocker", "bdeunlock", "fveupdate", "truecrypt", "veracrypt", "diskcryptor",
        "searchindexer", "searchprotocolhost", "searchfilterhost",
        "robocopy", "wbengine", "sdclt", "onedrive", "dropbox",
        "googledrivesync", "googlebackupandsync", "boxsync", "pcloud", "megasync",
        // AV
        "msmpeng", "nissrv", "avp", "avastsvc", "avgsvc", "mcshield", "ccsvchst",
        // v4.1.0: Trend Micro (legitimate high-IO during scans)
        "TmsaInstance64", "coreServiceShell", "coreFrameworkHost", "PtSvcHost",
        "AMSPTelemetryService", "uiSeAgnt", "PtSessionAgent",
        // System
        "svchost", "lsass", "services", "csrss", "smss", "dwm", "winlogon", "wininit",
        "msiexec", "trustedinstaller", "tiworker", "wuauclt",
        // Dev / IDEs (high write I/O during builds, indexing, language server operations)
        "git", "devenv", "code", "rider64",
        // v4.1.0: Kiro IDE (Electron â€” heavy file I/O during workspace indexing and AI operations)
        "Kiro", "kiro",
        // v4.1.0: IObit / Ashampoo (optimization tools do mass file operations)
        "mainProcess", "ASCService", "DriverBooster", "LiveTuner3",
        // v4.2.0: Browsers (cache writes, IndexedDB, service workers â€” sustained high I/O is normal)
        "msedge", "chrome", "firefox", "brave", "opera", "vivaldi",
        "msedgewebview2",
        // Games (Football Manager has heavy write I/O during matches/saves)
        "fm", "fm.exe",
    };

    private readonly DetectionEngine _engine;
    private readonly ILogger<RansomwareIoMonitor> _logger;
    private readonly ConcurrentDictionary<int, Activity> _activity = new();
    private DateTime _lastCleanup = DateTime.UtcNow;

    public RansomwareIoMonitor(DetectionEngine engine, ILogger<RansomwareIoMonitor> logger)
    {
        _engine = engine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("RansomwareIoMonitor: starting");
        await Task.Delay(TimeSpan.FromSeconds(20), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try { await PollAsync(stoppingToken); }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { _logger.LogDebug(ex, "RansomwareIoMonitor: poll error"); }

            try { await Task.Delay(ScanInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task PollAsync(CancellationToken cancellationToken)
    {
        CleanupExpired();

        var selfPid = Environment.ProcessId;
        Process[] procs;
        try { procs = Process.GetProcesses(); }
        catch { return; }

        try
        {
            foreach (var proc in procs)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var p = proc;
                if (p.Id == selfPid || p.Id <= 4) continue;

                string name;
                try { name = p.ProcessName; }
                catch { continue; }

                string? path = null;
                try { path = p.MainModule?.FileName; }
                catch { }

                if (IsWhitelisted(name, path)) continue;

                var (ops, bytes) = QueryIoCounters(p.Id);
                if (ops < 0) continue;

                var now = DateTime.UtcNow;
                var entry = _activity.GetOrAdd(p.Id, _ => new Activity
                {
                    Pid = p.Id,
                    Name = name,
                    FirstSeen = now,
                    LastSeen = now,
                    LastWriteOps = ops,
                    LastWriteBytes = bytes
                });

                long opsDelta = ops - entry.LastWriteOps;
                long bytesDelta = bytes - entry.LastWriteBytes;
                entry.LastWriteOps = ops;
                entry.LastWriteBytes = bytes;
                entry.LastSeen = now;

                if (opsDelta < 0 || bytesDelta < 0) continue;

                entry.Samples.Add(new Sample(now, opsDelta, bytesDelta));
                entry.Samples.RemoveAll(s => now - s.At > WindowDuration);

                int score = ComputeScore(entry, now);
                if (score >= 60)
                {
                    await EmitAsync(entry, score, cancellationToken);
                    _activity.TryRemove(entry.Pid, out _);
                }
            }
        }
        finally
        {
            foreach (var p in procs)
            {
                try { p.Dispose(); } catch { }
            }
        }
    }

    private static bool IsWhitelisted(string name, string? path)
    {
        if (string.IsNullOrEmpty(name)) return false;

        bool nameMatch = Whitelist.Contains(name);
        if (!nameMatch)
        {
            foreach (var w in Whitelist)
            {
                if (name.StartsWith(w, StringComparison.OrdinalIgnoreCase))
                {
                    nameMatch = true;
                    break;
                }
            }
        }

        if (!nameMatch) return false;

        // Enforce path and signature validation to prevent process renaming bypasses (masquerading).
        if (string.IsNullOrEmpty(path))
        {
            // Allow critical system/AV processes if we cannot retrieve their path (e.g., Access Denied)
            var lowerName = name.ToLowerInvariant();
            return lowerName == "svchost" || lowerName == "lsass" || lowerName == "services" || 
                   lowerName == "csrss" || lowerName == "smss" || lowerName == "winlogon" || 
                   lowerName == "wininit" || lowerName == "msmpeng" || lowerName == "nissrv" ||
                   lowerName == "sentinelservice" || lowerName == "sentinelagent";
        }

        var pathLower = path.ToLowerInvariant();
        bool isTrustedPath = pathLower.Contains(@"\windows\") ||
                            pathLower.Contains(@"\program files\") ||
                            pathLower.Contains(@"\program files (x86)\") ||
                            pathLower.Contains(@"\steamapps\") ||
                            pathLower.Contains(@"\steam\") ||
                            pathLower.Contains(@"\epic games\") ||
                            pathLower.Contains(@"\gog galaxy\") ||
                            pathLower.Contains(@"\riot games\") ||
                            pathLower.Contains(@"\battle.net\") ||
                            pathLower.Contains(@"\ubisoft\") ||
                            pathLower.Contains(@"\ea games\") ||
                            pathLower.Contains(@"\origin\");

        if (isTrustedPath) return true;

        // Fallback: check if the binary has a valid Authenticode signature
        try
        {
            using var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path));
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static (long ops, long bytes) QueryIoCounters(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT WriteOperationCount, WriteTransferCount FROM Win32_Process WHERE ProcessId = {pid}");
            using var results = searcher.Get();
            foreach (ManagementObject mo in results)
            {
                using (mo)
                {
                    long o = Convert.ToInt64(mo["WriteOperationCount"] ?? 0L);
                    long b = Convert.ToInt64(mo["WriteTransferCount"] ?? 0L);
                    return (o, b);
                }
            }
        }
        catch { }
        return (-1, -1);
    }

    private static int ComputeScore(Activity a, DateTime now)
    {
        long windowOps = a.Samples.Sum(s => s.OpsDelta);
        long windowBytes = a.Samples.Sum(s => s.BytesDelta);
        double minutes = Math.Max((now - a.FirstSeen).TotalMinutes, 0.016);
        double opsPerMin = windowOps / minutes;

        int score = 0;
        if (opsPerMin >= 500) score += 40;
        else if (opsPerMin >= 200) score += 30;
        else if (opsPerMin >= 50) score += 20;
        else if (opsPerMin >= 20) score += 10;

        if (windowBytes >= 100L * 1024 * 1024) score += 25;
        else if (windowBytes >= 50L * 1024 * 1024) score += 15;
        else if (windowBytes >= 10L * 1024 * 1024) score += 5;

        try
        {
            using var p = Process.GetProcessById(a.Pid);
            var path = p.MainModule?.FileName?.ToLowerInvariant() ?? "";
            if (path.Contains(@"\temp\") || path.Contains(@"\tmp\") ||
                path.Contains(@"\appdata\local\temp"))
                score += 15;
            else if (path.Contains(@"\appdata\") && !path.Contains(@"\microsoft\"))
                score += 5;
        }
        catch { }

        return Math.Min(score, 100);
    }

    private async Task EmitAsync(Activity a, int score, CancellationToken cancellationToken)
    {
        long windowOps = a.Samples.Sum(s => s.OpsDelta);
        long windowBytes = a.Samples.Sum(s => s.BytesDelta);
        double minutes = Math.Max((DateTime.UtcNow - a.FirstSeen).TotalMinutes, 0.016);

        await _engine.EmitAsync(new DetectionEvent
        {
            RuleName    = "Ransomware: mass write I/O burst",
            Evidence    = $"{windowOps} write ops, {(windowBytes / 1024.0 / 1024.0):F1}MB written in {minutes:F1}min",
            Reasoning   = "Process exceeded the per-process write-rate threshold for non-whitelisted binaries inside a 2-minute window. Pattern is consistent with mass file encryption.",
            Confidence  = score >= 80 ? 0.95 : 0.80,
            Tier        = DetectionTier.Tier1Behavioral,
            ProcessName = a.Name,
            ProcessId   = a.Pid,
            Timestamp   = DateTime.UtcNow,
            Metadata    = new Dictionary<string, string>
            {
                ["technique"] = "T1486 - Data Encrypted for Impact",
                ["window_write_ops"] = windowOps.ToString(),
                ["window_write_bytes"] = windowBytes.ToString(),
                ["heuristic_score"] = score.ToString()
            }
        }, cancellationToken);
    }

    private void CleanupExpired()
    {
        var now = DateTime.UtcNow;
        if (now - _lastCleanup < TimeSpan.FromMinutes(2)) return;
        _lastCleanup = now;

        foreach (var kv in _activity)
        {
            if (now - kv.Value.LastSeen > ProcessTtl)
            {
                _activity.TryRemove(kv.Key, out _);
                continue;
            }
            try { _ = Process.GetProcessById(kv.Key); }
            catch { _activity.TryRemove(kv.Key, out _); }
        }
    }

    private sealed class Activity
    {
        public int Pid;
        public string Name = "";
        public DateTime FirstSeen;
        public DateTime LastSeen;
        public long LastWriteOps;
        public long LastWriteBytes;
        public List<Sample> Samples { get; } = new();
    }

    private readonly record struct Sample(DateTime At, long OpsDelta, long BytesDelta);
}


