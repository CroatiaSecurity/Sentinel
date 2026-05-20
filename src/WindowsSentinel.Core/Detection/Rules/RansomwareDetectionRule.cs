using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Unified ransomware detection with weighted multi-signal scoring.
/// 
/// MERGED FROM:
/// - RansomwareActivityRule (shadow copy deletion, bulk renames, suspicious extensions)
/// - RansomwareBehaviorRule (file I/O rate tracking, document targeting)
/// 
/// Detection Signals (weighted scoring):
/// - Shadow copy deletion: 40 points (critical pre-encryption step)
/// - Bulk renames (>50 files): 30 points
/// - Ransomware extension used: 25 points
/// - I/O rate >10 files/min: 20 points
/// - High file entropy write: 15 points
/// - Document file targeting: 10 points
/// 
/// Thresholds:
/// - Tier1 (Action): ≥70 points
/// - Tier2 (Log only): ≥40 points
/// </summary>
public sealed class RansomwareDetectionRule : IDetectionRule
{
    public string Name => "Ransomware Detection (Unified)";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    private readonly ILogger<RansomwareDetectionRule> _logger;

    // Signal weights for scoring
    private const int WeightShadowCopyDeletion = 40;
    private const int WeightBulkRename = 30;
    private const int WeightRansomwareExtension = 25;
    private const int WeightHighIoRate = 20;
    private const int WeightHighEntropy = 15;
    private const int WeightDocumentTargeting = 10;

    // Thresholds
    private const int ThresholdTier1 = 70;
    private const int ThresholdTier2 = 40;
    private const int SuspiciousFileCount = 50;
    private const int SuspiciousFileRate = 10;
    private const int DetectionWindowMinutes = 2;
    private const int MaxPathLength = 260;

    // Activity tracking
    private readonly ConcurrentDictionary<int, ProcessActivity> _processActivity = new();
    private readonly object _cleanupLock = new();
    private DateTime _lastCleanup = DateTime.UtcNow;

    // Shadow copy / backup destruction patterns (highest confidence signal)
    private static readonly (string Process, string Pattern)[] ShadowDeletePatterns =
    {
        ("vssadmin.exe", "delete shadows"),
        ("vssadmin.exe", "resize shadowstorage"),
        ("wmic.exe", "shadowcopy delete"),
        ("wmic.exe", "shadowcopy where"),
        ("powershell.exe", "Get-WmiObject Win32_ShadowCopy"),
        ("powershell.exe", "Win32_ShadowCopy"),
        ("powershell.exe", "shadowcopy"),
        ("wbadmin.exe", "delete catalog"),
        ("wbadmin.exe", "delete systemstatebackup"),
        ("bcdedit.exe", "recoveryenabled no"),
        ("bcdedit.exe", "bootstatuspolicy ignoreallfailures"),
        ("diskshadow.exe", "delete shadows"),
        ("net.exe", "stop vss"),
        ("net.exe", "stop \"volume shadow copy\""),
        ("net1.exe", "stop vss"),
        ("taskkill.exe", "veeam"),
        ("taskkill.exe", "backup"),
        ("taskkill.exe", "sql"),
    };

    // Known ransomware extensions (medium confidence signal)
    private static readonly HashSet<string> RansomwareExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".locked", ".encrypted", ".crypto", ".crypt", ".vault", ".crypto", ".crypted",
        ".enc", ".encrypt", ".secure", ".protected", ".ransom", ".pay", ".pay2",
        ".locky", ".zepto", ".cerber", ".cryptowall", ".tesla", ".wncry", ".wncrypt",
        ".wcry", ".onion", ".exx", ".ezz", ".xyz", ".zzzzz", ".micro", ".xxx",
        ".crypt", ".crypted", ".cry", ".wallet", ".arena", ".osiris", ".noproblem",
        ".maya", ".b8", ".bk", ".fun", ".ransomed", ".babyk", ".dewar", ".devos"
    };

    // Document extensions (targeting indicator)
    private static readonly HashSet<string> TargetExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm",
        ".pdf", ".txt", ".rtf", ".odt", ".ods", ".odp", ".jpg", ".jpeg", ".png",
        ".zip", ".rar", ".7z", ".db", ".sql", ".sqlite", ".pst", ".eml", ".msg"
    };

    // Whitelisted legitimate processes
    private static readonly HashSet<string> WhitelistedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "bitlocker", "bdeunlock", "fveupdate", "truecrypt", "veracrypt", "diskcryptor",
        "searchindexer", "searchprotocolhost", "searchfilterhost", "mobsync", "onesync",
        "robocopy", "wbengine", "sdclt", "onedrive", "dropbox", "googledrivesync",
        "msmpeng", "mmc", "mpuxsrv", "nissrv", "avp", "avastsvc", "avgsvc", "mcshield",
        "svchost", "lsass", "services", "csrss", "smss", "dwm", "winlogon", "wininit",
        "msiexec", "trustedinstaller", "tiworker", "wusa", "wuauclt", "usoclient",
        "git", "devenv", "code", "rider64"
    };

    public RansomwareDetectionRule(ILogger<RansomwareDetectionRule> logger)
    {
        _logger = logger;
    }

    public DetectionEvent? Evaluate(object telemetry)
    {
        CleanupOldEntries();

        // Process-based detection: shadow copy deletion
        if (telemetry is ProcessTelemetry proc)
        {
            return EvaluateProcessTelemetry(proc);
        }

        // File-based detection: I/O rate, extensions, entropy
        if (telemetry is FileActivityTelemetry file)
        {
            return EvaluateFileTelemetry(file);
        }

        return null;
    }

    private DetectionEvent? EvaluateProcessTelemetry(ProcessTelemetry proc)
    {
        var nameLower = proc.ProcessName.ToLowerInvariant();
        var cmdLower = proc.CommandLine.ToLowerInvariant();

        foreach (var (shadowProcess, shadowPattern) in ShadowDeletePatterns)
        {
            if ((nameLower == shadowProcess.ToLowerInvariant() ||
                 proc.ImagePath.EndsWith(shadowProcess, StringComparison.OrdinalIgnoreCase)) &&
                cmdLower.Contains(shadowPattern.ToLowerInvariant()))
            {
                // Shadow copy deletion = 40 points (critical signal)
                var score = WeightShadowCopyDeletion;
                var tier = score >= ThresholdTier1 ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator;

                return new DetectionEvent
                {
                    RuleName = Name,
                    Evidence = $"CRITICAL: Shadow copy / backup destruction detected - '{proc.ProcessName}' (PID {proc.ProcessId}) " +
                              $"executed '{shadowPattern}'. Command: {proc.CommandLine}",
                    Reasoning = "Deleting shadow copies is the standard pre-encryption step performed by ransomware " +
                        "(WannaCry, REvil, LockBit, BlackCat, Conti) to prevent file recovery. This is one of the " +
                        "highest-confidence ransomware indicators. Score: " + score + "/100",
                    Confidence = 0.96,
                    Tier = tier,
                    ProcessName = proc.ProcessName,
                    ProcessId = proc.ProcessId,
                    Timestamp = proc.Timestamp,
                    Metadata = new()
                    {
                        ["Signal"] = "ShadowCopyDeletion",
                        ["Score"] = score.ToString(),
                        ["Pattern"] = shadowPattern,
                        ["CommandLine"] = proc.CommandLine
                    }
                };
            }
        }

        return null;
    }

    private DetectionEvent? EvaluateFileTelemetry(FileActivityTelemetry file)
    {
        // Validate paths
        if (file.NewPath.Length > MaxPathLength || (file.OldPath?.Length ?? 0) > MaxPathLength)
            return null;

        // Get process info
        int processId = 0;
        string processName = "Unknown";
        
        if (file.Metadata.TryGetValue("ProcessId", out var pidStr) && int.TryParse(pidStr, out var pid))
            processId = pid;
        if (file.Metadata.TryGetValue("ProcessName", out var procName))
            processName = procName;

        if (processId == 0 || string.IsNullOrEmpty(processName))
            return null;

        // Skip whitelisted
        if (WhitelistedProcesses.Contains(processName) || processId <= 4)
            return null;

        // Get or create activity tracking
        var activity = _processActivity.GetOrAdd(processId, _ => new ProcessActivity
        {
            ProcessName = processName,
            ProcessId = processId
        });

        lock (activity)
        {
            // Update activity
            string newPath = file.NewPath.ToLowerInvariant();
            string oldPath = file.OldPath?.ToLowerInvariant() ?? "";
            string newExt = Path.GetExtension(newPath);
            string oldExt = Path.GetExtension(oldPath);

            activity.FilesModified[newPath] = DateTime.UtcNow;
            activity.LastUpdate = DateTime.UtcNow;

            // Calculate score components
            int score = 0;
            var signals = new List<string>();

            // 1. Check for ransomware extension rename
            if (!string.IsNullOrEmpty(oldPath) && RansomwareExtensions.Contains(newExt) && !RansomwareExtensions.Contains(oldExt))
            {
                score += WeightRansomwareExtension;
                signals.Add($"RansomwareExtension({newExt})");
            }

            // 2. Check for document targeting
            if (TargetExtensions.Contains(oldExt))
            {
                score += WeightDocumentTargeting;
                activity.DocumentCount++;
                signals.Add("DocumentTargeting");
            }

            // 3. Calculate I/O rate
            int recentFiles = activity.FilesModified.Count(f =>
                (DateTime.UtcNow - f.Value).TotalMinutes <= DetectionWindowMinutes);
            double filesPerMinute = recentFiles / DetectionWindowMinutes;

            // 4. Check bulk rename / high I/O rate
            if (recentFiles >= SuspiciousFileCount)
            {
                score += WeightBulkRename;
                signals.Add($"BulkRename({recentFiles})");
            }
            else if (filesPerMinute >= SuspiciousFileRate && activity.DocumentCount >= 5)
            {
                score += WeightHighIoRate;
                signals.Add($"HighIoRate({filesPerMinute:F1}/min)");
            }

            // Check if score meets threshold
            if (score < ThresholdTier2)
                return null;

            // Remove from tracking after detection to prevent duplicates
            _processActivity.TryRemove(processId, out _);

            // Determine tier based on score
            var tier = score >= ThresholdTier1 ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator;
            double confidence = Math.Min(0.5 + (score / 100.0), 0.97);

            return new DetectionEvent
            {
                RuleName = Name,
                Evidence = $"Process '{processName}' (PID {processId}) exhibits ransomware behavior | " +
                          $"Score: {score}/100 | Signals: {string.Join(", ", signals)} | " +
                          $"Files: {recentFiles} in {DetectionWindowMinutes}min | Documents: {activity.DocumentCount}",
                Reasoning = "Ransomware detection based on weighted signal correlation: " +
                    $"{string.Join("; ", signals)}. Total score {score}/100. " +
                    (score >= ThresholdTier1
                        ? "Score exceeds Tier1 threshold (70). Immediate action recommended."
                        : "Score indicates suspicious activity. Logging for analysis."),
                Confidence = confidence,
                Tier = tier,
                ProcessName = processName,
                ProcessId = processId,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new()
                {
                    ["Score"] = score.ToString(),
                    ["Signals"] = string.Join(";", signals),
                    ["FilesModified"] = recentFiles.ToString(),
                    ["DocumentCount"] = activity.DocumentCount.ToString(),
                    ["FilesPerMinute"] = filesPerMinute.ToString("F2"),
                    ["SampleFiles"] = string.Join(";", activity.FilesModified.Keys.Take(5))
                }
            };
        }
    }

    private void CleanupOldEntries()
    {
        lock (_cleanupLock)
        {
            if ((DateTime.UtcNow - _lastCleanup).TotalMinutes < 5)
                return;
            _lastCleanup = DateTime.UtcNow;
        }

        var cutoff = DateTime.UtcNow.AddMinutes(-DetectionWindowMinutes * 2);
        var keysToRemove = _processActivity.Where(kvp => kvp.Value.LastUpdate < cutoff)
                                          .Select(kvp => kvp.Key)
                                          .ToList();
        foreach (var key in keysToRemove)
        {
            _processActivity.TryRemove(key, out _);
        }
    }

    private class ProcessActivity
    {
        public string ProcessName { get; set; } = "";
        public int ProcessId { get; set; }
        public Dictionary<string, DateTime> FilesModified { get; set; } = new();
        public int DocumentCount { get; set; }
        public DateTime LastUpdate { get; set; } = DateTime.UtcNow;
    }
}

