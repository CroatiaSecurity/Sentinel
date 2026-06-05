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
        private readonly ILogger<FileVerdictScanner> _logger;
        private readonly List<FileSystemWatcher> _watchers = new();

        // Directories to exclude from real-time scanning (temp downloads, NTLite work dirs, etc.)
        private static readonly HashSet<string> ExcludedPaths = new(StringComparer.OrdinalIgnoreCase)
        {
            "temp", "tmp", "downloads", "uupdump", "ntlite", "mount", "extracted",
            "cache", "localcache", "opera autoupdate", "google\\update", "edge\\update"
        };

        public FileVerdictScanner(
            HashReputationService reputationService,
            FileVerdictAds verdictAds,
            ILogger<FileVerdictScanner> logger)
        {
            _reputationService = reputationService;
            _verdictAds = verdictAds;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[FileVerdictScanner] Starting consensus pre-scan and file watchers...");

            // Start drive watchers
            var drives = DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady);
            foreach (var drive in drives)
            {
                try
                {
                    var watcher = new FileSystemWatcher(drive.RootDirectory.FullName)
                    {
                        IncludeSubdirectories = true,
                        Filter = "*.exe",
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite
                    };
                    watcher.Created += OnFileChanged;
                    watcher.Renamed += OnFileRenamed;
                    watcher.EnableRaisingEvents = true;
                    _watchers.Add(watcher);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to start FileSystemWatcher for drive {Drive}", drive.Name);
                }
            }

            // Start pre-scanning existing executables in background
            _ = Task.Run(async () => await WalkDrivesAsync(stoppingToken), stoppingToken);
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            _ = Task.Run(async () => await ScanFileWithBackoffAsync(e.FullPath));
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            _ = Task.Run(async () => await ScanFileWithBackoffAsync(e.FullPath));
        }

        private async Task ScanFileWithBackoffAsync(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !filePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return;

            // Skip excluded paths (temp dirs, download dirs, NTLite work dirs, etc.)
            var pathLower = filePath.ToLowerInvariant();
            if (ExcludedPaths.Any(excluded => pathLower.Contains(excluded)))
            {
                _logger.LogDebug("Skipping scan for file in excluded path: {FilePath}", filePath);
                return;
            }

            // Wait for file to stabilize - don't scan files that are actively being written
            // This prevents "file in use" errors during downloads/UUP extraction/NTLite operations
            await Task.Delay(2000);

            int retries = 5;
            while (retries > 0)
            {
                try
                {
                    if (!File.Exists(filePath)) return;

                    // Check if file has been stable (not modified) for at least 1 second
                    // If it's still being written to, skip this scan attempt
                    var lastWrite = File.GetLastWriteTimeUtc(filePath);
                    if (DateTime.UtcNow - lastWrite < TimeSpan.FromSeconds(1))
                    {
                        throw new IOException("File is still being modified");
                    }

                    // Try to open file with read sharing to ensure it is not locked for writing
                    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        await ScanFileInternalAsync(filePath);
                        return;
                    }
                }
                catch (IOException)
                {
                    retries--;
                    // Longer backoff: 2 seconds between retries (total max wait: ~12 seconds)
                    await Task.Delay(2000);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Failed to scan file: {FilePath}", filePath);
                    return;
                }
            }

            // If all retries failed, log it but don't interfere with the file operation
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

                var existingVerdict = _verdictAds.GetVerdict(filePath, hash);
                if (existingVerdict != HashVerdict.Unknown) return;

                var verdict = await _reputationService.GetVerdictAsync(hash);
                _verdictAds.SetVerdict(filePath, hash, verdict);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error in ScanFileInternalAsync for {FilePath}", filePath);
            }
        }

        private async Task WalkDrivesAsync(CancellationToken ct)
        {
            var drives = DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady);
            foreach (var drive in drives)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    await TraverseDirectoryAsync(drive.RootDirectory.FullName, ct);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error initiating drive walk for {Drive}", drive.Name);
                }
            }
        }

        private async Task TraverseDirectoryAsync(string rootDir, CancellationToken ct)
        {
            var queue = new Queue<string>();
            queue.Enqueue(rootDir);

            while (queue.Count > 0)
            {
                if (ct.IsCancellationRequested) break;
                var currentDir = queue.Dequeue();

                try
                {
                    foreach (var file in Directory.EnumerateFiles(currentDir, "*.exe"))
                    {
                        if (ct.IsCancellationRequested) break;
                        await ScanFileWithBackoffAsync(file);

                        // Throttle execution slightly to prevent CPU starvation
                        await Task.Delay(5, ct);
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
            foreach (var watcher in _watchers)
            {
                watcher.Created -= OnFileChanged;
                watcher.Renamed -= OnFileRenamed;
                watcher.Dispose();
            }
            base.Dispose();
        }
    }
}
