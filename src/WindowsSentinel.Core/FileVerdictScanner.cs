using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    public class FileVerdictScanner : BackgroundService
    {
        private readonly HashReputationService _reputationService;
        private readonly FileVerdictAds _verdictAds;
        private readonly FileReputationEngine _reputationEngine;
        private readonly ILogger<FileVerdictScanner> _logger;
        private readonly List<FileSystemWatcher> _watchers = new();

        // All scannable extensions — matches Antivirus.ps1 coverage
        private static readonly HashSet<string> ScanExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi"
        };

        // Directories to exclude from scanning (build artifacts, browser updates ONLY)
        // HARDENING v1.3.0: Removed "temp", "tmp", "cache" — these are primary malware staging areas.
        // Previously excluded "downloads" too (removed in 1.2.9). Now only skip paths that are
        // genuinely never attack vectors: build tool intermediates and auto-updater working dirs.
        private static readonly HashSet<string> ExcludedPaths = new(StringComparer.OrdinalIgnoreCase)
        {
            "uupdump", "ntlite", "mount", "extracted",
            "opera autoupdate", "google\\update", "edge\\update"
        };

        // Throttle: max concurrent API lookups to avoid hammering CIRCL/MalwareBazaar
        private readonly SemaphoreSlim _apiThrottle = new(4, 4);

        public FileVerdictScanner(
            HashReputationService reputationService,
            FileVerdictAds verdictAds,
            FileReputationEngine reputationEngine,
            ILogger<FileVerdictScanner> logger)
        {
            _reputationService = reputationService;
            _verdictAds = verdictAds;
            _reputationEngine = reputationEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[FileVerdictScanner] Starting lazy verdict scan and file watchers...");

            // Start drive watchers for all scannable file types — PRIORITY: new files scanned immediately
            var drives = DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady);
            foreach (var drive in drives)
            {
                try
                {
                    // FileSystemWatcher doesn't support multiple filters natively,
                    // so we watch all files and filter in the event handler
                    var watcher = new FileSystemWatcher(drive.RootDirectory.FullName)
                    {
                        IncludeSubdirectories = true,
                        Filter = "*.*",
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite
                    };
                    watcher.Created += OnFileCreated;
                    watcher.Renamed += OnFileRenamed;
                    watcher.EnableRaisingEvents = true;
                    _watchers.Add(watcher);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to start FileSystemWatcher for drive {Drive}", drive.Name);
                }
            }

            // Lazy background walk — scans every file on every NTFS volume, skipping those already marked
            _ = Task.Run(async () => await WalkDrivesAsync(stoppingToken), stoppingToken);
        }

        private static bool IsScannable(string filePath)
        {
            var ext = Path.GetExtension(filePath);
            if (!string.IsNullOrEmpty(ext) && ScanExtensions.Contains(ext))
                return true;

            // HARDENING: Files without extensions (or unknown extensions) may still be
            // Windows PE executables — MalwareBazaar dumps, renamed payloads, and staged
            // binaries often lack extensions to evade extension-based scanning.
            // Check PE magic bytes (MZ header) for extensionless files.
            if (string.IsNullOrEmpty(ext) || !ext.Contains('.'))
            {
                return HasPeMagicBytes(filePath);
            }

            return false;
        }

        /// <summary>
        /// Checks if a file starts with the MZ magic bytes (0x4D 0x5A) indicating
        /// a Windows PE executable. Used to detect extensionless malware on disk.
        /// </summary>
        private static bool HasPeMagicBytes(string filePath)
        {
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                if (fs.Length < 2) return false;
                var b1 = fs.ReadByte();
                var b2 = fs.ReadByte();
                return b1 == 0x4D && b2 == 0x5A; // 'M' 'Z'
            }
            catch
            {
                return false;
            }
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            if (IsScannable(e.FullPath))
                _ = Task.Run(async () => await ScanNewFileAsync(e.FullPath));
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            if (IsScannable(e.FullPath))
                _ = Task.Run(async () => await ScanNewFileAsync(e.FullPath));
        }

        /// <summary>
        /// Fast-path for new/renamed files. Minimal delay, no lazy throttle.
        /// Goal: tag known-malicious files BEFORE they can execute for the first time.
        /// </summary>
        private async Task ScanNewFileAsync(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !IsScannable(filePath)) return;

            var pathLower = filePath.ToLowerInvariant();
            if (ExcludedPaths.Any(excluded => pathLower.Contains(excluded))) return;

            // Brief stabilization wait — just enough for the write to finish
            await Task.Delay(500);

            int retries = 3;
            while (retries > 0)
            {
                try
                {
                    if (!File.Exists(filePath)) return;

                    var lastWrite = File.GetLastWriteTimeUtc(filePath);
                    if (DateTime.UtcNow - lastWrite < TimeSpan.FromMilliseconds(300))
                    {
                        throw new IOException("File is still being modified");
                    }

                    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        await ScanFileInternalAsync(filePath);
                        return;
                    }
                }
                catch (IOException)
                {
                    retries--;
                    await Task.Delay(800);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Fast scan failed for new file: {FilePath}", filePath);
                    return;
                }
            }

            // If fast path failed, fall back to lazy scan with longer backoff
            await ScanFileWithBackoffAsync(filePath);
        }

        private async Task ScanFileWithBackoffAsync(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !IsScannable(filePath)) return;

            // Skip excluded paths
            var pathLower = filePath.ToLowerInvariant();
            if (ExcludedPaths.Any(excluded => pathLower.Contains(excluded)))
            {
                return;
            }

            // Wait for file to stabilize
            await Task.Delay(2000);

            int retries = 5;
            while (retries > 0)
            {
                try
                {
                    if (!File.Exists(filePath)) return;

                    var lastWrite = File.GetLastWriteTimeUtc(filePath);
                    if (DateTime.UtcNow - lastWrite < TimeSpan.FromSeconds(1))
                    {
                        throw new IOException("File is still being modified");
                    }

                    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        await ScanFileInternalAsync(filePath);
                        return;
                    }
                }
                catch (IOException)
                {
                    retries--;
                    await Task.Delay(2000);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Failed to scan file: {FilePath}", filePath);
                    return;
                }
            }

            _logger.LogDebug("File scan abandoned after retries (file likely in use): {FilePath}", filePath);
        }

        private async Task ScanFileInternalAsync(string filePath)
        {
            try
            {
                string hash;
                using (var sha = SHA256.Create())
                await using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    var hashBytes = await sha.ComputeHashAsync(fs);
                    hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
                }

                // Lazy: skip if already marked (ADS verdict exists and hash matches)
                var existingVerdict = _verdictAds.GetVerdict(filePath, hash);
                if (existingVerdict != HashVerdict.Unknown) return;

                // v1.3.1: Use the multi-signal FileReputationEngine for composite scoring
                var reputationResult = await _reputationEngine.EvaluateFileAsync(filePath);

                // Map composite verdict to legacy HashVerdict for ADS tagging
                HashVerdict verdict;
                switch (reputationResult.Verdict)
                {
                    case FileVerdict.Malicious:
                    case FileVerdict.HighRisk:
                        verdict = HashVerdict.Unsafe;
                        break;
                    case FileVerdict.Trusted:
                    case FileVerdict.LowRisk:
                        verdict = HashVerdict.Safe;
                        break;
                    default:
                        verdict = HashVerdict.Unknown;
                        break;
                }

                // Only persist definitive verdicts (not Unknown — will be retried)
                if (verdict != HashVerdict.Unknown)
                {
                    _verdictAds.SetVerdict(filePath, hash, verdict);
                }

                // If malicious/high-risk, deny execute permission immediately
                if (verdict == HashVerdict.Unsafe)
                {
                    DenyExecution(filePath);
                    _logger.LogWarning(
                        "[FileVerdictScanner] Blocked file: {FilePath} (SHA256: {Hash}, Score={Score}, Verdict={Verdict})",
                        filePath, hash, reputationResult.CompositeScore, reputationResult.Verdict);
                }
                else if (reputationResult.Verdict == FileVerdict.Suspicious && reputationResult.CompositeScore >= 55)
                {
                    // Log suspicious files for analyst review without blocking
                    _logger.LogInformation(
                        "[FileVerdictScanner] Suspicious file: {FilePath} (Score={Score}, Entropy={Entropy:F2}, Signed={Signed})",
                        filePath, reputationResult.CompositeScore,
                        reputationResult.StaticAnalysis.Entropy, reputationResult.IsSigned);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error in ScanFileInternalAsync for {FilePath}", filePath);
            }
        }

        /// <summary>
        /// Adds a Deny Execute ACL for Everyone on a malicious file, preventing execution.
        /// </summary>
        private void DenyExecution(string filePath)
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                var acl = fileInfo.GetAccessControl();
                var rule = new System.Security.AccessControl.FileSystemAccessRule(
                    new System.Security.Principal.SecurityIdentifier(
                        System.Security.Principal.WellKnownSidType.WorldSid, null),
                    System.Security.AccessControl.FileSystemRights.ExecuteFile,
                    System.Security.AccessControl.AccessControlType.Deny);
                acl.AddAccessRule(rule);
                fileInfo.SetAccessControl(acl);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to deny execution on file: {FilePath}", filePath);
            }
        }

        private async Task WalkDrivesAsync(CancellationToken ct)
        {
            // Wait a bit after startup to let higher-priority monitors initialize
            await Task.Delay(TimeSpan.FromSeconds(30), ct);

            var drives = DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady);
            foreach (var drive in drives)
            {
                if (ct.IsCancellationRequested) break;
                _logger.LogInformation("[FileVerdictScanner] Starting lazy walk of {Drive}", drive.Name);
                try
                {
                    await TraverseDirectoryAsync(drive.RootDirectory.FullName, ct);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error initiating drive walk for {Drive}", drive.Name);
                }
            }
            _logger.LogInformation("[FileVerdictScanner] Lazy walk complete on all volumes.");
        }

        private async Task TraverseDirectoryAsync(string rootDir, CancellationToken ct)
        {
            var queue = new Queue<string>();
            queue.Enqueue(rootDir);

            while (queue.Count > 0)
            {
                if (ct.IsCancellationRequested) break;
                var currentDir = queue.Dequeue();

                // Skip excluded directories
                var dirLower = currentDir.ToLowerInvariant();
                if (ExcludedPaths.Any(excluded => dirLower.Contains(excluded))) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(currentDir))
                    {
                        if (ct.IsCancellationRequested) break;
                        if (!IsScannable(file)) continue;

                        await ScanFileWithBackoffAsync(file);

                        // Lazy throttle: yield between files to keep system responsive
                        await Task.Delay(50, ct);
                    }

                    foreach (var subDir in Directory.EnumerateDirectories(currentDir))
                    {
                        if (ct.IsCancellationRequested) break;
                        var name = Path.GetFileName(subDir).ToLowerInvariant();
                        if (name == "$recycle.bin" || name == "system volume information") continue;

                        queue.Enqueue(subDir);
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (DirectoryNotFoundException) { }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error traversing directory: {Directory}", currentDir);
                }
            }
        }

        public override void Dispose()
        {
            _apiThrottle.Dispose();
            foreach (var watcher in _watchers)
            {
                watcher.Created -= OnFileCreated;
                watcher.Renamed -= OnFileRenamed;
                watcher.Dispose();
            }
            base.Dispose();
        }
    }
}
