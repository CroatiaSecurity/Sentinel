using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Response;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Disk-Wide DLL Scanner — Scans all drives for unsigned/suspicious DLLs that are
/// NOT currently loaded into any process. This catches:
///   - Dropped payloads waiting to be loaded (pre-execution stage)
///   - Persistence DLLs planted for future hijacking
///   - Dormant implants in user-writable directories
///   - DLLs planted alongside vulnerable auto-elevate binaries
///
/// Ported from Antivirus.ps1's Invoke-UnsignedDLLRemover disk scanning logic.
///
/// Scanning strategy:
///   - High-risk paths (AppData, Temp, Downloads): every 5 minutes
///   - Drive roots (shallow, depth 2): every 15 minutes
///   - Results cached by SHA-256 hash to avoid re-scanning unchanged files
///   - Max 500 files per scan cycle to limit I/O impact
///
/// Response: Detected malicious DLLs are reported. If they're loaded in any process,
/// the DllUnloadEngine is invoked to unload them.
///
/// MITRE ATT&CK:
///   T1574 — Hijack Execution Flow
///   T1036 — Masquerading
///   T1027 — Obfuscated Files or Information
/// </summary>
public sealed class DiskWideDllScanner : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<DiskWideDllScanner> _logger;
    private readonly DllUnloadEngine? _unloadEngine;
    private readonly HashReputationService? _reputationService;
    private readonly IoCScanner? _iocScanner;

    private static readonly TimeSpan HighRiskScanInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan DriveRootScanInterval = TimeSpan.FromMinutes(15);
    private const int MaxFilesPerScan = 500;
    private const int DriveRootScanDepth = 2;

    private DateTimeOffset _lastHighRiskScan = DateTimeOffset.MinValue;
    private DateTimeOffset _lastDriveRootScan = DateTimeOffset.MinValue;

    // Hash → (isValid signature, scanTime)
    private readonly ConcurrentDictionary<string, ScannedDllRecord> _scannedHashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _alertedFiles = new();

    // Paths to exclude from scanning
    private static readonly string[] ExcludedPathSegments =
    {
        @"\windows\system32\",
        @"\windows\syswow64\",
        @"\windows\winsxs\",
        @"\windows\assembly\",
        @"\program files\",
        @"\program files (x86)\",
        @"\windowssentinel\quarantine\"
    };

    public DiskWideDllScanner(
        IDetectionEngine detectionEngine,
        ILogger<DiskWideDllScanner> logger,
        DllUnloadEngine? unloadEngine = null,
        HashReputationService? reputationService = null,
        IoCScanner? iocScanner = null)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _unloadEngine = unloadEngine;
        _reputationService = reputationService;
        _iocScanner = iocScanner;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("DiskWideDllScanner: Starting (high-risk: 5min, drives: 15min)");

        // Wait for system to stabilize
        await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var now = DateTimeOffset.UtcNow;

                if (now - _lastHighRiskScan >= HighRiskScanInterval)
                {
                    await ScanHighRiskPathsAsync(stoppingToken);
                    _lastHighRiskScan = now;
                }

                if (now - _lastDriveRootScan >= DriveRootScanInterval)
                {
                    await ScanDriveRootsAsync(stoppingToken);
                    _lastDriveRootScan = now;
                }

                PruneCache();
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "DiskWideDllScanner: Scan loop error");
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
            }
        }
    }

    /// <summary>
    /// Scans high-risk user-writable directories for suspicious DLLs.
    /// </summary>
    private async Task ScanHighRiskPathsAsync(CancellationToken ct)
    {
        var highRiskPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\Downloads",
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Temp",
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            @"C:\Users\Public"
        };

        int scannedCount = 0;

        foreach (var path in highRiskPaths)
        {
            if (scannedCount >= MaxFilesPerScan) break;
            if (!Directory.Exists(path)) continue;

            ct.ThrowIfCancellationRequested();

            try
            {
                var files = Directory.EnumerateFiles(path, "*.dll", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(path, "*.winmd", SearchOption.AllDirectories))
                    .Take(MaxFilesPerScan - scannedCount);

                foreach (var filePath in files)
                {
                    ct.ThrowIfCancellationRequested();
                    scannedCount++;

                    if (ShouldExclude(filePath)) continue;

                    await AnalyzeDllOnDiskAsync(filePath, "HighRiskPath", ct);
                }
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (DirectoryNotFoundException) { continue; }
            catch { continue; }
        }
    }

    /// <summary>
    /// Scans drive roots (shallow) for suspicious DLLs in unexpected locations.
    /// </summary>
    private async Task ScanDriveRootsAsync(CancellationToken ct)
    {
        var drives = DriveInfo.GetDrives()
            .Where(d => d.IsReady && d.DriveType is DriveType.Fixed or DriveType.Removable or DriveType.Network)
            .Select(d => d.RootDirectory.FullName);

        int scannedCount = 0;

        foreach (var root in drives)
        {
            if (scannedCount >= MaxFilesPerScan) break;
            ct.ThrowIfCancellationRequested();

            try
            {
                // Shallow scan (depth limited)
                var files = EnumerateFilesWithDepth(root, new[] { "*.dll", "*.winmd" }, DriveRootScanDepth)
                    .Take(MaxFilesPerScan - scannedCount);

                foreach (var filePath in files)
                {
                    ct.ThrowIfCancellationRequested();
                    scannedCount++;

                    if (ShouldExclude(filePath)) continue;

                    await AnalyzeDllOnDiskAsync(filePath, "DriveRoot", ct);
                }
            }
            catch { continue; }
        }
    }

    /// <summary>
    /// Analyzes a single DLL file on disk for suspicious characteristics.
    /// </summary>
    private async Task AnalyzeDllOnDiskAsync(string filePath, string scanContext, CancellationToken ct)
    {
        try
        {
            if (!File.Exists(filePath)) return;

            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Length == 0 || fileInfo.Length > 100 * 1024 * 1024) return; // Skip empty or >100MB

            // Compute hash
            string hash;
            try
            {
                using var sha = SHA256.Create();
                using var fs = File.OpenRead(filePath);
                hash = Convert.ToHexString(sha.ComputeHash(fs));
            }
            catch { return; }

            // Check cache
            if (_scannedHashes.TryGetValue(hash, out var cached) && cached.IsValid)
                return; // Already scanned and clean

            // Check local IoC scanner
            bool iocMatch = false;
            string iocName = "", iocTech = "";
            if (_iocScanner != null)
                iocMatch = _iocScanner.IsMaliciousHash(hash, out iocName, out iocTech);

            // Check signature
            bool isSigned = false;
            string? publisher = null;
            try
            {
                using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
                isSigned = true;
                publisher = cert.GetNameInfo(X509NameType.SimpleName, false);
            }
            catch { isSigned = false; }

            // Cache the result
            _scannedHashes[hash] = new ScannedDllRecord
            {
                IsValid = isSigned && !iocMatch,
                ScannedAt = DateTimeOffset.UtcNow
            };

            // If signed and not IoC match, skip
            if (isSigned && !iocMatch) return;

            // Check external reputation (if available and not already IoC)
            if (!iocMatch && _reputationService != null)
            {
                try
                {
                    var repResult = await _reputationService.CheckHashAsync(hash, ct);
                    if (repResult.IsMalicious && repResult.Confidence >= 70)
                    {
                        iocMatch = true;
                        iocName = $"Reputation match (confidence: {repResult.Confidence}%, sources: {string.Join(",", repResult.Sources)})";
                        iocTech = "T1204";
                    }
                    else if (!repResult.IsMalicious && repResult.Confidence >= 80)
                    {
                        // High-confidence clean — skip
                        _scannedHashes[hash] = new ScannedDllRecord { IsValid = true, ScannedAt = DateTimeOffset.UtcNow };
                        return;
                    }
                }
                catch { /* Network failure — continue with local analysis */ }
            }

            // Score the file
            var fileName = Path.GetFileName(filePath);
            int score = 0;
            var reasons = new List<string>();

            if (!isSigned)
            {
                score += 30;
                reasons.Add("unsigned DLL");
            }

            if (iocMatch)
            {
                score += 60;
                reasons.Add($"IoC match: {iocName}");
            }

            // Random hex name
            if (System.Text.RegularExpressions.Regex.IsMatch(fileName, @"^[a-f0-9]{8,}\.(dll|winmd)$",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            {
                score += 35;
                reasons.Add("random hex-named DLL");
            }

            // Suspicious location
            var pathLower = filePath.ToLowerInvariant();
            if (pathLower.Contains(@"\temp\") || pathLower.Contains(@"\tmp\"))
            {
                score += 25;
                reasons.Add("in temp directory");
            }
            else if (pathLower.Contains(@"\downloads\") || pathLower.Contains(@"\desktop\"))
            {
                score += 20;
                reasons.Add("in user downloads/desktop");
            }

            // High entropy (packed/encrypted)
            var entropy = DllEntropyAnalyzer.CalculateEntropy(filePath);
            if (entropy.HasValue && entropy.Value >= 7.2)
            {
                score += 30;
                reasons.Add($"high entropy ({entropy.Value:F2})");
            }

            // Small file size (stub loader)
            if (fileInfo.Length < 10240)
            {
                score += 15;
                reasons.Add($"tiny file ({fileInfo.Length} bytes)");
            }

            // Only alert if score is significant
            if (score < 40) return;

            var alertKey = $"disk:{hash}:{filePath}";
            if (!_alertedFiles.TryAdd(alertKey, 0)) return;

            double confidence = iocMatch ? 0.95 : (score >= 70 ? 0.88 : 0.75);

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = iocMatch
                    ? "Disk DLL Scan: Known Malicious DLL on Disk"
                    : "Disk DLL Scan: Suspicious Unsigned DLL on Disk",
                Evidence = $"Suspicious DLL found on disk: '{fileName}' at '{filePath}'. " +
                          $"Score: {score}. Signed: {isSigned}. " +
                          $"Reasons: {string.Join("; ", reasons)}.",
                Reasoning = "A suspicious DLL was found on disk in a user-writable location. " +
                           "Unsigned DLLs in temp/downloads/desktop directories are commonly " +
                           "dropped by malware downloaders, phishing attachments, or exploit kits. " +
                           "Even if not currently loaded, these DLLs may be staged for future " +
                           "execution via DLL hijacking, scheduled tasks, or COM object abuse. " +
                           $"Specific indicators: {string.Join("; ", reasons)}.",
                Confidence = confidence,
                Tier = iocMatch ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                ProcessName = "DiskDllScanner",
                ProcessId = Environment.ProcessId,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["technique"] = iocMatch ? iocTech : "T1574 - Hijack Execution Flow",
                    ["file_path"] = filePath,
                    ["file_name"] = fileName,
                    ["file_hash"] = hash,
                    ["file_size"] = fileInfo.Length.ToString(),
                    ["is_signed"] = isSigned.ToString(),
                    ["publisher"] = publisher ?? "unsigned",
                    ["score"] = score.ToString(),
                    ["entropy"] = entropy?.ToString("F2") ?? "unknown",
                    ["scan_context"] = scanContext,
                    ["reasons"] = string.Join("; ", reasons)
                }
            }, ct);

            _logger.LogWarning(
                "DiskWideDllScanner: SUSPICIOUS DLL on disk: '{File}' (score={Score}, signed={Signed})",
                fileName, score, isSigned);

            // If IoC match and DLL is loaded somewhere, unload it
            if (iocMatch && _unloadEngine != null)
            {
                var unloadResults = _unloadEngine.UnloadDllFromAllProcesses(
                    filePath, $"IoC match on disk scan: {iocName}");

                foreach (var result in unloadResults.Where(r => r.Success))
                {
                    _logger.LogCritical(
                        "DiskWideDllScanner: UNLOADED malicious DLL '{File}' from PID {Pid}",
                        fileName, result.ProcessId);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "DiskWideDllScanner: Error analyzing {File}", filePath);
        }
    }

    private static bool ShouldExclude(string filePath)
    {
        var lower = filePath.ToLowerInvariant();
        return ExcludedPathSegments.Any(seg => lower.Contains(seg));
    }

    /// <summary>
    /// Enumerates files with a maximum directory depth.
    /// </summary>
    private static IEnumerable<string> EnumerateFilesWithDepth(string root, string[] patterns, int maxDepth)
    {
        if (maxDepth < 0) yield break;

        foreach (var pattern in patterns)
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(root, pattern); }
            catch { yield break; }

            foreach (var file in files)
                yield return file;
        }

        if (maxDepth == 0) yield break;

        IEnumerable<string> dirs;
        try { dirs = Directory.EnumerateDirectories(root); }
        catch { yield break; }

        foreach (var dir in dirs)
        {
            // Skip system/hidden directories
            try
            {
                var attrs = File.GetAttributes(dir);
                if ((attrs & FileAttributes.System) != 0 || (attrs & FileAttributes.ReparsePoint) != 0)
                    continue;
            }
            catch { continue; }

            foreach (var file in EnumerateFilesWithDepth(dir, patterns, maxDepth - 1))
                yield return file;
        }
    }

    private void PruneCache()
    {
        var cutoff = DateTimeOffset.UtcNow.AddHours(-2);
        foreach (var key in _scannedHashes.Keys)
        {
            if (_scannedHashes.TryGetValue(key, out var record) && record.ScannedAt < cutoff)
                _scannedHashes.TryRemove(key, out _);
        }

        if (_alertedFiles.Count > 10000)
            _alertedFiles.Clear();
    }

    private sealed class ScannedDllRecord
    {
        public bool IsValid { get; init; }
        public DateTimeOffset ScannedAt { get; init; }
    }
}


