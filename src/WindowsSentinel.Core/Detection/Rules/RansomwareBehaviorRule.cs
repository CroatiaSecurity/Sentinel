using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Behavioral ransomware detection via file I/O rate tracking.
/// Ported from GIDR's RansomwareDetection with security hardening.
/// 
/// Detects ransomware by monitoring process file modification patterns:
/// - High rate of file modifications (50+ files in 2 minutes)
/// - Targeting user document directories
/// - Ignores known-good processes (backup software, etc.)
/// </summary>
public sealed class RansomwareBehaviorRule : IDetectionRule
{
    public string Name => "Ransomware Behavior (I/O Rate)";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    private readonly ILogger<RansomwareBehaviorRule> _logger;

    // Process activity tracking
    private readonly ConcurrentDictionary<int, ProcessFileActivity> _processActivity = new();
    private readonly object _cleanupLock = new();
    private DateTime _lastCleanup = DateTime.UtcNow;

    // Thresholds
    private const int SuspiciousFileCount = 50;        // Files touched in window
    private const int SuspiciousFileRate = 10;         // Files per minute
    private const int DetectionWindowMinutes = 2;      // Time window
    private const int MaxPathLength = 260;             // Windows MAX_PATH

    // Whitelisted processes that do mass file operations legitimately
    private static readonly HashSet<string> WhitelistedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Encryption/Security
        "bitlocker", "bdeunlock", "fveupdate", "fveskybackup",
        "truecrypt", "veracrypt", "diskcryptor",
        
        // Windows Search/Indexing
        "searchindexer", "searchprotocolhost", "searchfilterhost",
        "mobsync", "onesync", "backgroundtaskhost",
        
        // Backup/Sync
        "robocopy", "wbengine", "sdclt",
        "onedrive", "dropbox", "googlebackupandsync", "googledrivesync",
        "boxsync", "pcloud", "megasync", "sync",
        
        // Antivirus/Security
        "msmpeng", "mmc", "mpuxsrv", "nissrv",
        "avp", "avastsvc", "avgsvc", "mcshield", "ccsvchst",
        
        // System
        "svchost", "lsass", "services", "csrss", "smss",
        "dwm", "winlogon", "wininit",
        
        // Installers/Updates
        "msiexec", "trustedinstaller", "tiworker", "wusa",
        "wuauclt", "usoclient", "musnotification",
        
        // Development tools
        "git", "tfs", "devenv", "code", "rider64"
    };

    // Document extensions that ransomware typically targets
    private static readonly HashSet<string> TargetExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".docx", ".docm", ".dot", ".dotx", ".dotm",
        ".xls", ".xlsx", ".xlsm", ".xlsb", ".xltx", ".xltm",
        ".ppt", ".pptx", ".pptm", ".pot", ".potx", ".potm", ".pps", ".ppsx",
        ".pdf", ".txt", ".rtf", ".odt", ".ods", ".odp",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".raw", ".psd",
        ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv",
        ".zip", ".rar", ".7z", ".tar", ".gz",
        ".db", ".sql", ".sqlite", ".mdb", ".accdb",
        ".pst", ".ost", ".eml", ".msg",
        ".dwg", ".dxf",
        ".php", ".asp", ".aspx", ".jsp", ".html", ".htm", ".css", ".js",
        ".java", ".py", ".cs", ".cpp", ".c", ".h", ".go", ".rb", ".pl"
    };

    public RansomwareBehaviorRule(ILogger<RansomwareBehaviorRule> logger)
    {
        _logger = logger;
    }

    public DetectionEvent? Evaluate(object telemetry)
    {
        // Periodic cleanup of old entries
        CleanupOldEntries();

        if (telemetry is not FileActivityTelemetry file) return null;

        // Only monitor rename operations (ransomware renames files)
        if (string.IsNullOrEmpty(file.OldPath) || string.IsNullOrEmpty(file.NewPath))
            return null;

        // SECURITY: Validate file paths length
        if (file.OldPath.Length > MaxPathLength || file.NewPath.Length > MaxPathLength)
        {
            _logger.LogDebug("File path exceeds max length, skipping");
            return null;
        }

        // Get process info from metadata
        int processId = 0;
        string processName = "Unknown";
        
        if (file.Metadata.TryGetValue("ProcessId", out var pidStr) && int.TryParse(pidStr, out var pid))
        {
            processId = pid;
        }
        if (file.Metadata.TryGetValue("ProcessName", out var procName))
        {
            processName = procName;
        }

        // Skip if we can't identify the process
        if (processId == 0 || string.IsNullOrEmpty(processName))
            return null;

        // Skip whitelisted processes
        if (WhitelistedProcesses.Contains(processName))
            return null;

        // Skip system processes
        if (processId <= 4)
            return null;

        try
        {
            // Update file activity tracking
            var activity = _processActivity.GetOrAdd(processId, _ => new ProcessFileActivity
            {
                ProcessName = processName,
                ProcessId = processId
            });

            lock (activity)
            {
                // Add file to tracking
                string filePath = file.NewPath.ToLowerInvariant();
                string extension = Path.GetExtension(filePath);

                activity.ModifiedFiles[filePath] = DateTime.UtcNow;
                activity.LastUpdate = DateTime.UtcNow;

                // Check if targeting document files
                if (TargetExtensions.Contains(extension))
                {
                    activity.DocumentFilesModified++;
                }

                // Check thresholds
                int recentFileCount = activity.ModifiedFiles.Count(f => 
                    (DateTime.UtcNow - f.Value).TotalMinutes <= DetectionWindowMinutes);

                double filesPerMinute = recentFileCount / DetectionWindowMinutes;

                // Detection: high file rate targeting documents
                if (recentFileCount >= SuspiciousFileCount || 
                    (filesPerMinute >= SuspiciousFileRate && activity.DocumentFilesModified >= 10))
                {
                    // Remove from tracking to prevent duplicate alerts
                    _processActivity.TryRemove(processId, out _);

                    string evidence = $"Process '{processName}' (PID {processId}) performed {recentFileCount} " +
                        $"file modifications in {DetectionWindowMinutes} minutes " +
                        $"({activity.DocumentFilesModified} document files). " +
                        $"Rate: {filesPerMinute:F1} files/minute.";

                    return new DetectionEvent
                    {
                        RuleName = Name,
                        Evidence = evidence,
                        Reasoning = "Ransomware encrypts files in bulk by reading, encrypting, and renaming " +
                            "them with new extensions. This detection monitors file modification rates per " +
                            "process, flagging suspiciously high activity targeting document files. " +
                            "Legitimate backup software and Windows processes are allowlisted. " +
                            "The observed rate significantly exceeds normal application behavior.",
                        Confidence = recentFileCount >= SuspiciousFileCount * 2 ? 0.94 : 0.87,
                        Tier = Tier,
                        ProcessName = processName,
                        ProcessId = processId,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new()
                        {
                            ["RecentFileCount"] = recentFileCount.ToString(),
                            ["DocumentFilesModified"] = activity.DocumentFilesModified.ToString(),
                            ["FilesPerMinute"] = filesPerMinute.ToString("F2"),
                            ["SampleFiles"] = string.Join(";", activity.ModifiedFiles.Keys.Take(5)),
                            ["DetectionWindowMinutes"] = DetectionWindowMinutes.ToString()
                        }
                    };
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Ransomware behavior detection failed for {Process} PID {Pid}",
                processName, processId);
        }

        return null;
    }

    /// <summary>
    /// Remove old entries to prevent memory growth
    /// </summary>
    private void CleanupOldEntries()
    {
        // Run cleanup every 5 minutes
        lock (_cleanupLock)
        {
            if ((DateTime.UtcNow - _lastCleanup).TotalMinutes < 5)
                return;
            _lastCleanup = DateTime.UtcNow;
        }

        try
        {
            var keysToRemove = new List<int>();
            var cutoff = DateTime.UtcNow.AddMinutes(-DetectionWindowMinutes * 2);

            foreach (var kvp in _processActivity)
            {
                if (kvp.Value.LastUpdate < cutoff)
                {
                    keysToRemove.Add(kvp.Key);
                }
            }

            foreach (var key in keysToRemove)
            {
                _processActivity.TryRemove(key, out _);
            }

            if (keysToRemove.Count > 0)
            {
                _logger.LogDebug("Cleaned up {Count} old process activity entries", keysToRemove.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Cleanup of process activity failed");
        }
    }

    /// <summary>
    /// File activity tracking for a single process
    /// </summary>
    private class ProcessFileActivity
    {
        public string ProcessName { get; set; } = "";
        public int ProcessId { get; set; }
        public Dictionary<string, DateTime> ModifiedFiles { get; set; } = new();
        public int DocumentFilesModified { get; set; }
        public DateTime LastUpdate { get; set; } = DateTime.UtcNow;
    }
}
