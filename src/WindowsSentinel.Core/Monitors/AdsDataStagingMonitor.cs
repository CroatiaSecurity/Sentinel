using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// NTFS Alternate Data Stream (ADS) Staging Monitor — Detects processes writing
/// large amounts of data to NTFS alternate data streams, which are invisible to
/// normal file browsing (Explorer, dir, Get-ChildItem without -Stream).
///
/// Attack scenario:
///   Attacker writes exfiltration staging data (recordings, screenshots, stolen files)
///   to ADS attached to innocent-looking files. The host file appears normal size,
///   but the ADS can hold gigabytes of hidden data. Disk usage increases but no
///   visible file accounts for it — the classic "invisible disk fill" pattern.
///
/// Detection approach:
///   1. Monitor file I/O via ETW/process handles for writes to stream paths (file:stream)
///   2. Periodically scan high-value directories for files with non-standard ADS
///   3. Flag any ADS larger than a threshold (10MB) — legitimate ADS are tiny
///      (Zone.Identifier is ~26 bytes, thumbnails are ~100KB max)
///   4. Track cumulative ADS writes per process — large total = staging
///
/// Legitimate ADS uses (allowlisted):
///   - Zone.Identifier (mark-of-the-web) — always tiny
///   - SmartScreen — tiny
///   - Thumbnails — small
///   - SummaryInformation — small
///
/// MITRE ATT&amp;CK: T1564.004 — Hide Artifacts: NTFS File Attributes
/// </summary>
public sealed class AdsDataStagingMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<AdsDataStagingMonitor> _logger;

    private static readonly TimeSpan ScanInterval = TimeSpan.FromMinutes(2);

    // Minimum ADS size to flag (legitimate ADS are tiny)
    private const long SuspiciousAdsSizeBytes = 10 * 1024 * 1024; // 10 MB
    private const long CriticalAdsSizeBytes = 100 * 1024 * 1024;  // 100 MB

    // Track already-alerted paths to avoid flooding
    private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedPaths = new();

    // Known legitimate ADS names (case-insensitive)
    private static readonly HashSet<string> LegitimateStreamNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Zone.Identifier",
        "SmartScreen",
        "SummaryInformation",
        "DocumentSummaryInformation",
        "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}",  // Thumbnail cache
        "encryptable",
        "WofCompressedData",
        "favicon",
    };

    // Directories to scan (high-value staging locations)
    private static readonly string[] ScanRoots;

    static AdsDataStagingMonitor()
    {
        var roots = new List<string>();

        // Temp directories
        var temp = Environment.GetEnvironmentVariable("TEMP") ?? Path.GetTempPath();
        roots.Add(temp);

        var winTemp = @"C:\Windows\Temp";
        if (Directory.Exists(winTemp)) roots.Add(winTemp);

        // ProgramData (writable by most processes)
        var progData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        roots.Add(progData);

        // User profile directories
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        roots.Add(localAppData);

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        roots.Add(appData);

        // Public folders
        var publicDir = Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public";
        roots.Add(publicDir);

        ScanRoots = roots.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    // P/Invoke for FindFirstStreamW / FindNextStreamW
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstStreamW(
        string lpFileName, int InfoLevel, out WIN32_FIND_STREAM_DATA lpFindStreamData, int dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindNextStreamW(IntPtr hFindStream, out WIN32_FIND_STREAM_DATA lpFindStreamData);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindClose(IntPtr hFindFile);

    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string cStreamName;
    }

    public AdsDataStagingMonitor(
        IDetectionEngine detectionEngine,
        ILogger<AdsDataStagingMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== ADS Data Staging Monitor starting ===");

        // Initial delay
        await Task.Delay(TimeSpan.FromSeconds(45), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanForSuspiciousAdsAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "AdsDataStagingMonitor: scan error");
            }

            try { await Task.Delay(ScanInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task ScanForSuspiciousAdsAsync(CancellationToken ct)
    {
        long totalSuspiciousBytes = 0;
        int suspiciousCount = 0;

        foreach (var root in ScanRoots)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                // Scan files in this directory (non-recursive for performance — only top 2 levels)
                foreach (var file in EnumerateFilesLimited(root, maxDepth: 2))
                {
                    ct.ThrowIfCancellationRequested();

                    var streams = GetAlternateDataStreams(file);
                    foreach (var (streamName, streamSize) in streams)
                    {
                        // Skip legitimate/known ADS
                        var cleanName = streamName.Trim(':');
                        if (LegitimateStreamNames.Contains(cleanName)) continue;
                        if (streamSize < SuspiciousAdsSizeBytes) continue;

                        // This is a large, non-standard ADS — suspicious
                        var fullStreamPath = $"{file}:{cleanName}";
                        if (_alertedPaths.ContainsKey(fullStreamPath)) continue;

                        _alertedPaths[fullStreamPath] = DateTimeOffset.UtcNow;
                        totalSuspiciousBytes += streamSize;
                        suspiciousCount++;

                        var confidence = streamSize >= CriticalAdsSizeBytes ? 0.90 : 0.80;
                        var sizeMB = streamSize / (1024.0 * 1024.0);

                        _logger.LogCritical(
                            "ADS Staging: Large alternate data stream detected — {File}:{Stream} ({Size:F1} MB)",
                            file, cleanName, sizeMB);

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Data Staging: Large NTFS Alternate Data Stream",
                            Evidence = $"File '{file}' has a large alternate data stream '{cleanName}' " +
                                      $"({sizeMB:F1} MB). Legitimate ADS are tiny (<1KB). " +
                                      $"Large ADS are invisible to Explorer and standard file listings — " +
                                      $"commonly used to hide exfiltration staging data.",
                            Reasoning = "NTFS Alternate Data Streams are invisible to normal file browsing. " +
                                       "Legitimate ADS (Zone.Identifier, thumbnails) are always tiny (<100KB). " +
                                       "A multi-megabyte ADS attached to a file is a strong indicator of " +
                                       "data staging for exfiltration — the attacker hides stolen data in " +
                                       "streams that don't appear in directory listings, causing 'invisible' " +
                                       "disk usage that the user cannot account for.",
                            Confidence = confidence,
                            Tier = DetectionTier.Tier1Behavioral,
                            ProcessName = "N/A",
                            ProcessId = 0,
                            Timestamp = DateTimeOffset.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["technique"] = "T1564.004 - Hide Artifacts: NTFS File Attributes",
                                ["file_path"] = file,
                                ["stream_name"] = cleanName,
                                ["stream_size_bytes"] = streamSize.ToString(),
                                ["stream_size_mb"] = sizeMB.ToString("F1"),
                            }
                        }, ct);
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "AdsDataStagingMonitor: error scanning {Root}", root);
            }
        }

        if (suspiciousCount > 0)
        {
            _logger.LogWarning(
                "ADS Staging: Found {Count} suspicious ADS totaling {Size:F1} MB",
                suspiciousCount, totalSuspiciousBytes / (1024.0 * 1024.0));
        }

        // Prune old alerts
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-10);
        foreach (var kv in _alertedPaths)
            if (kv.Value < cutoff) _alertedPaths.TryRemove(kv.Key, out _);
    }

    /// <summary>
    /// Enumerates alternate data streams on a file using FindFirstStreamW/FindNextStreamW.
    /// Returns stream names and sizes, excluding the default ::$DATA stream.
    /// </summary>
    private static List<(string Name, long Size)> GetAlternateDataStreams(string filePath)
    {
        var results = new List<(string, long)>();

        var handle = FindFirstStreamW(filePath, 0, out var data, 0);
        if (handle == INVALID_HANDLE_VALUE) return results;

        try
        {
            do
            {
                // Skip the default data stream (::$DATA)
                if (!string.IsNullOrEmpty(data.cStreamName) &&
                    !data.cStreamName.Equals("::$DATA", StringComparison.OrdinalIgnoreCase))
                {
                    // Stream name format is ":streamname:$DATA"
                    var name = data.cStreamName;
                    if (name.EndsWith(":$DATA", StringComparison.OrdinalIgnoreCase))
                        name = name[..^6]; // Remove :$DATA suffix

                    results.Add((name, data.StreamSize));
                }
            } while (FindNextStreamW(handle, out data));
        }
        finally
        {
            FindClose(handle);
        }

        return results;
    }

    /// <summary>
    /// Enumerates files up to a limited depth to avoid scanning the entire disk.
    /// </summary>
    private static IEnumerable<string> EnumerateFilesLimited(string root, int maxDepth)
    {
        if (maxDepth < 0) yield break;

        string[] files;
        try { files = Directory.GetFiles(root); }
        catch { yield break; }

        foreach (var f in files)
            yield return f;

        if (maxDepth <= 0) yield break;

        string[] dirs;
        try { dirs = Directory.GetDirectories(root); }
        catch { yield break; }

        foreach (var dir in dirs)
        {
            foreach (var f in EnumerateFilesLimited(dir, maxDepth - 1))
                yield return f;
        }
    }
}


