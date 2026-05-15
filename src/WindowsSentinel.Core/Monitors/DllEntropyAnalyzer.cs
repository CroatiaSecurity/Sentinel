using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// DLL Entropy Analyzer — Detects packed, encrypted, or obfuscated DLLs by measuring
/// Shannon entropy. High-entropy DLLs are a strong indicator of:
///   - Packed malware (UPX, Themida, VMProtect, custom packers)
///   - Encrypted payloads (shellcode loaders, crypters)
///   - Obfuscated implants (Cobalt Strike, Metasploit, custom C2)
///
/// Ported from Antivirus.ps1's Measure-FileEntropy + Invoke-FileEntropyDetection.
///
/// Scanning strategy:
///   - Scans recently-modified DLLs in high-risk directories every 3 minutes
///   - Scans loaded modules in running processes every 5 minutes
///   - Entropy threshold: 7.2 (normal DLLs are 5.5-6.8; packed/encrypted are 7.5+)
///
/// MITRE ATT&CK:
///   T1027 — Obfuscated Files or Information
///   T1027.002 — Software Packing
/// </summary>
public sealed class DllEntropyAnalyzer : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<DllEntropyAnalyzer> _logger;
    private readonly IoCScanner? _iocScanner;

    private static readonly TimeSpan DiskScanInterval = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan ProcessScanInterval = TimeSpan.FromMinutes(5);
    private const double HighEntropyThreshold = 7.2;
    private const double CriticalEntropyThreshold = 7.6;
    private const int SampleSize = 8192; // Read first 8KB for entropy calculation
    private const int MaxFilesPerScan = 200;

    private readonly ConcurrentDictionary<string, EntropyRecord> _scannedFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _alertedFiles = new();

    private DateTimeOffset _lastDiskScan = DateTimeOffset.MinValue;
    private DateTimeOffset _lastProcessScan = DateTimeOffset.MinValue;

    // High-risk directories to scan for new/modified DLLs
    private static readonly string[] HighRiskPaths;

    // Regex for random hex-named DLLs (common in malware droppers)
    private static readonly System.Text.RegularExpressions.Regex HexNamePattern =
        new(@"^[a-f0-9]{8,}\.dll$", System.Text.RegularExpressions.RegexOptions.IgnoreCase |
                                      System.Text.RegularExpressions.RegexOptions.Compiled);

    static DllEntropyAnalyzer()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = Path.GetTempPath();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        HighRiskPaths = new[]
        {
            appData,
            Path.Combine(localAppData, "Temp"),
            temp,
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Documents"),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
        };
    }

    public DllEntropyAnalyzer(
        IDetectionEngine detectionEngine,
        ILogger<DllEntropyAnalyzer> logger,
        IoCScanner? iocScanner = null)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _iocScanner = iocScanner;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("DllEntropyAnalyzer: Starting (threshold: {Threshold})", HighEntropyThreshold);

        await Task.Delay(TimeSpan.FromSeconds(60), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var now = DateTimeOffset.UtcNow;

                if (now - _lastDiskScan >= DiskScanInterval)
                {
                    await ScanHighRiskDirectoriesAsync(stoppingToken);
                    _lastDiskScan = now;
                }

                if (now - _lastProcessScan >= ProcessScanInterval)
                {
                    await ScanLoadedModulesEntropyAsync(stoppingToken);
                    _lastProcessScan = now;
                }

                PruneCache();
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "DllEntropyAnalyzer: Scan loop error");
                await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);
            }
        }
    }

    /// <summary>
    /// Scans recently-modified DLLs in high-risk directories.
    /// </summary>
    private async Task ScanHighRiskDirectoriesAsync(CancellationToken ct)
    {
        var cutoff = DateTimeOffset.UtcNow.AddHours(-2);
        int scannedCount = 0;

        foreach (var scanPath in HighRiskPaths)
        {
            if (scannedCount >= MaxFilesPerScan) break;
            if (!Directory.Exists(scanPath)) continue;

            ct.ThrowIfCancellationRequested();

            try
            {
                var files = Directory.EnumerateFiles(scanPath, "*.dll", SearchOption.AllDirectories)
                    .Take(MaxFilesPerScan - scannedCount);

                foreach (var filePath in files)
                {
                    ct.ThrowIfCancellationRequested();
                    scannedCount++;

                    try
                    {
                        var fileInfo = new FileInfo(filePath);
                        if (fileInfo.LastWriteTimeUtc < cutoff.UtcDateTime) continue;
                        if (fileInfo.Length == 0 || fileInfo.Length > 50 * 1024 * 1024) continue; // Skip empty or >50MB

                        await AnalyzeFileAsync(filePath, "DiskScan", ct);
                    }
                    catch { continue; }
                }
            }
            catch { continue; }
        }
    }

    /// <summary>
    /// Scans entropy of loaded modules in running processes (non-system DLLs only).
    /// </summary>
    private async Task ScanLoadedModulesEntropyAsync(CancellationToken ct)
    {
        var processes = System.Diagnostics.Process.GetProcesses();
        int scannedCount = 0;

        try
        {
            foreach (var proc in processes)
            {
                if (scannedCount >= MaxFilesPerScan) break;
                ct.ThrowIfCancellationRequested();

                try
                {
                    if (proc.Id <= 4) continue;

                    foreach (System.Diagnostics.ProcessModule module in proc.Modules)
                    {
                        if (scannedCount >= MaxFilesPerScan) break;

                        var path = module.FileName;
                        if (string.IsNullOrEmpty(path)) continue;

                        // Skip system DLLs (they're signed and trusted)
                        var pathLower = path.ToLowerInvariant();
                        if (pathLower.Contains(@"\windows\system32\") ||
                            pathLower.Contains(@"\windows\syswow64\") ||
                            pathLower.Contains(@"\windows\winsxs\") ||
                            pathLower.Contains(@"\program files\") ||
                            pathLower.Contains(@"\program files (x86)\"))
                            continue;

                        scannedCount++;
                        await AnalyzeFileAsync(path, $"LoadedIn:{proc.ProcessName}(PID:{proc.Id})", ct);
                    }
                }
                catch { continue; }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    /// <summary>
    /// Analyzes a single file for entropy and suspicious characteristics.
    /// </summary>
    private async Task AnalyzeFileAsync(string filePath, string context, CancellationToken ct)
    {
        // Check cache
        if (_scannedFiles.TryGetValue(filePath, out var cached))
        {
            var fileInfo = new FileInfo(filePath);
            if (fileInfo.LastWriteTimeUtc == cached.LastModified && cached.Entropy < HighEntropyThreshold)
                return; // Already scanned, not suspicious
        }

        if (!File.Exists(filePath)) return;

        var entropy = CalculateEntropy(filePath);
        if (entropy == null) return;

        var fileName = Path.GetFileName(filePath);
        var lastWrite = new FileInfo(filePath).LastWriteTimeUtc;

        _scannedFiles[filePath] = new EntropyRecord
        {
            Entropy = entropy.Value,
            LastModified = lastWrite,
            ScannedAt = DateTimeOffset.UtcNow
        };

        // Check for random hex-named DLLs (strong malware indicator regardless of entropy)
        bool isHexNamed = HexNamePattern.IsMatch(fileName);

        if (isHexNamed)
        {
            var alertKey = $"hex:{filePath}";
            if (_alertedFiles.TryAdd(alertKey, 0))
            {
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "DLL Analysis: Random Hex-Named DLL",
                    Evidence = $"DLL with random hex name detected: '{fileName}' at '{filePath}'. " +
                              $"Entropy: {entropy.Value:F2}. Context: {context}.",
                    Reasoning = "DLLs with random hexadecimal names (e.g., 'a1b2c3d4e5f6.dll') are " +
                               "extremely common in malware droppers, crypters, and fileless attack stages. " +
                               "Legitimate software uses descriptive names. A hex-named DLL in a user-writable " +
                               "directory is a strong indicator of a dropped payload.",
                    Confidence = 0.87,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "DllEntropyAnalyzer",
                    ProcessId = Environment.ProcessId,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["technique"] = "T1027 - Obfuscated Files",
                        ["file_path"] = filePath,
                        ["file_name"] = fileName,
                        ["entropy"] = entropy.Value.ToString("F4"),
                        ["context"] = context,
                        ["detection_type"] = "HexNamedDll"
                    }
                }, ct);
            }
        }

        // High entropy detection
        if (entropy.Value >= HighEntropyThreshold)
        {
            var alertKey = $"entropy:{filePath}";
            if (!_alertedFiles.TryAdd(alertKey, 0)) return;

            bool isCritical = entropy.Value >= CriticalEntropyThreshold;

            // Check signature
            bool isSigned = IsFileSigned(filePath);

            // If signed by a trusted publisher, reduce severity
            if (isSigned && !isCritical) return;

            // Check IoC
            string? hash = null;
            bool iocMatch = false;
            string iocName = "", iocTech = "";
            try
            {
                hash = IoCScanner.ComputeSha256(filePath);
                if (_iocScanner != null)
                    iocMatch = _iocScanner.IsMaliciousHash(hash, out iocName, out iocTech);
            }
            catch { }

            double confidence = isCritical ? 0.91 : 0.79;
            if (iocMatch) confidence = 0.97;
            if (isHexNamed) confidence = Math.Min(confidence + 0.05, 0.98);

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = iocMatch
                    ? "DLL Analysis: High-Entropy Malicious DLL (IoC Match)"
                    : "DLL Analysis: High-Entropy DLL (Packed/Encrypted)",
                Evidence = $"DLL '{fileName}' has entropy {entropy.Value:F2} " +
                          $"(threshold: {HighEntropyThreshold}). Path: {filePath}. " +
                          $"Signed: {isSigned}. Context: {context}." +
                          (iocMatch ? $" IoC match: {iocName}" : ""),
                Reasoning = "Normal compiled DLLs have entropy between 5.5 and 6.8. " +
                           $"This DLL has entropy {entropy.Value:F2}, indicating it is likely " +
                           (isCritical ? "encrypted (crypter/loader payload). " : "packed (UPX, Themida, VMProtect, or custom packer). ") +
                           "Packed/encrypted DLLs are used to evade signature-based detection. " +
                           "The payload is decrypted at runtime, making static analysis ineffective. " +
                           "This is a common technique in APT tooling, commodity malware, and red team implants.",
                Confidence = confidence,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = "DllEntropyAnalyzer",
                ProcessId = Environment.ProcessId,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["technique"] = iocMatch ? iocTech : "T1027.002 - Software Packing",
                    ["file_path"] = filePath,
                    ["file_name"] = fileName,
                    ["entropy"] = entropy.Value.ToString("F4"),
                    ["is_signed"] = isSigned.ToString(),
                    ["is_hex_named"] = isHexNamed.ToString(),
                    ["context"] = context,
                    ["hash"] = hash ?? "unknown",
                    ["ioc_match"] = iocMatch.ToString()
                }
            }, ct);

            _logger.LogWarning(
                "DllEntropyAnalyzer: HIGH ENTROPY DLL '{File}' (entropy={Entropy:F2}, signed={Signed})",
                fileName, entropy.Value, isSigned);
        }
    }

    /// <summary>
    /// Calculates Shannon entropy of a file (first 8KB sample).
    /// </summary>
    public static double? CalculateEntropy(string filePath)
    {
        try
        {
            if (!File.Exists(filePath)) return null;

            var fileInfo = new FileInfo(filePath);
            var readSize = (int)Math.Min(SampleSize, fileInfo.Length);
            if (readSize == 0) return null;

            var bytes = new byte[readSize];
            using (var fs = File.OpenRead(filePath))
            {
                fs.Read(bytes, 0, readSize);
            }

            // Calculate byte frequency
            var freq = new int[256];
            foreach (var b in bytes)
                freq[b]++;

            // Calculate Shannon entropy
            double entropy = 0;
            double total = bytes.Length;

            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = freq[i] / total;
                entropy -= p * Math.Log2(p);
            }

            return entropy;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsFileSigned(string filePath)
    {
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(filePath);
            return cert != null;
        }
        catch
        {
            return false;
        }
    }

    private void PruneCache()
    {
        // Remove entries older than 1 hour
        var cutoff = DateTimeOffset.UtcNow.AddHours(-1);
        foreach (var key in _scannedFiles.Keys)
        {
            if (_scannedFiles.TryGetValue(key, out var record) && record.ScannedAt < cutoff)
                _scannedFiles.TryRemove(key, out _);
        }

        // Cap alerted files
        if (_alertedFiles.Count > 5000)
            _alertedFiles.Clear();
    }

    private sealed class EntropyRecord
    {
        public double Entropy { get; init; }
        public DateTime LastModified { get; init; }
        public DateTimeOffset ScannedAt { get; init; }
    }
}
