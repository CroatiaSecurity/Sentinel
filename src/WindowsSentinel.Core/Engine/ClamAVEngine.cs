using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// ClamAV integration for signature-based scanning.
/// Shells out to clamscan.exe (must be installed separately).
/// Ported from HydraDragonAntivirus's ClamAV integration.
/// </summary>
public sealed class ClamAVEngine : IAsyncDisposable
{
    private readonly ILogger<ClamAVEngine> _logger;
    private readonly string? _clamScanPath;
    private bool _isInitialized;

    public ClamAVEngine(ILogger<ClamAVEngine> logger, string? clamScanPath = null)
    {
        _logger = logger;
        _clamScanPath = clamScanPath ?? FindClamScan();
    }

    /// <summary>
    /// Initialize the engine and verify ClamAV is available
    /// </summary>
    public async Task<bool> InitializeAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrEmpty(_clamScanPath) || !File.Exists(_clamScanPath))
            {
                _logger.LogWarning("ClamAV: clamscan.exe not found. Install ClamAV to enable scanning.");
                _isInitialized = false;
                return false;
            }

            // Test ClamAV by running version check
            var result = await RunClamScanAsync("--version", cancellationToken);
            if (result.ExitCode == 0)
            {
                _logger.LogInformation("ClamAV initialized: {Version}", result.Output.Trim());
                _isInitialized = true;
                return true;
            }
            else
            {
                _logger.LogWarning("ClamAV: Version check failed");
                _isInitialized = false;
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ClamAV initialization failed");
            _isInitialized = false;
            return false;
        }
    }

    /// <summary>
    /// Scan a single file
    /// </summary>
    public async Task<ClamAVScanResult> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
        if (!_isInitialized)
        {
            return new ClamAVScanResult
            {
                FilePath = filePath,
                IsError = true,
                ErrorMessage = "ClamAV not initialized"
            };
        }

        if (!File.Exists(filePath))
        {
            return new ClamAVScanResult
            {
                FilePath = filePath,
                IsError = true,
                ErrorMessage = "File not found"
            };
        }

        try
        {
            // Use --infected to only show infected files, --no-summary to reduce output
            var args = $"--infected --no-summary --stdout \"{filePath}\"";
            var result = await RunClamScanAsync(args, cancellationToken);

            return ParseScanResult(filePath, result);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ClamAV scan failed for {File}", filePath);
            return new ClamAVScanResult
            {
                FilePath = filePath,
                IsError = true,
                ErrorMessage = ex.Message
            };
        }
    }

    /// <summary>
    /// Scan a directory recursively
    /// </summary>
    public async Task<List<ClamAVScanResult>> ScanDirectoryAsync(string directoryPath, bool recursive = true, CancellationToken cancellationToken = default)
    {
        var results = new List<ClamAVScanResult>();

        if (!_isInitialized)
        {
            _logger.LogWarning("ClamAV not initialized, skipping directory scan");
            return results;
        }

        if (!Directory.Exists(directoryPath))
        {
            _logger.LogWarning("Directory not found: {Path}", directoryPath);
            return results;
        }

        try
        {
            var recursiveFlag = recursive ? "-r" : "";
            var args = $"--infected --no-summary --stdout {recursiveFlag} \"{directoryPath}\"";
            
            var result = await RunClamScanAsync(args, cancellationToken);

            // Parse multi-file results
            var lines = result.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                var scanResult = ParseScanLine(line);
                if (scanResult != null)
                {
                    results.Add(scanResult);
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ClamAV directory scan failed for {Path}", directoryPath);
        }

        return results;
    }

    /// <summary>
    /// Quick scan of suspicious locations (temp, appdata, etc.)
    /// </summary>
    public async Task<List<ClamAVScanResult>> QuickScanAsync(CancellationToken cancellationToken = default)
    {
        var suspiciousPaths = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        };

        var allResults = new List<ClamAVScanResult>();

        foreach (var path in suspiciousPaths.Where(Directory.Exists))
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            _logger.LogDebug("ClamAV: Scanning {Path}", path);
            var results = await ScanDirectoryAsync(path, recursive: false, cancellationToken);
            allResults.AddRange(results);
        }

        return allResults;
    }

    /// <summary>
    /// Update ClamAV virus definitions
    /// </summary>
    public async Task<bool> UpdateDefinitionsAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var freshclamPath = FindFreshClam();
            if (string.IsNullOrEmpty(freshclamPath) || !File.Exists(freshclamPath))
            {
                _logger.LogWarning("freshclam.exe not found, cannot update definitions");
                return false;
            }

            _logger.LogInformation("ClamAV: Updating virus definitions...");

            var psi = new ProcessStartInfo
            {
                FileName = freshclamPath,
                Arguments = "--quiet",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null)
            {
                _logger.LogError("Failed to start freshclam");
                return false;
            }

            await process.WaitForExitAsync(cancellationToken);

            if (process.ExitCode == 0)
            {
                _logger.LogInformation("ClamAV: Definitions updated successfully");
                return true;
            }
            else
            {
                var error = await process.StandardError.ReadToEndAsync(cancellationToken);
                _logger.LogWarning("ClamAV: Update failed: {Error}", error);
                return false;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ClamAV definition update failed");
            return false;
        }
    }

    private async Task<ClamScanResult> RunClamScanAsync(string arguments, CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _clamScanPath!,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi);
        if (process == null)
        {
            return new ClamScanResult { ExitCode = -1, Error = "Failed to start clamscan" };
        }

        // Read output asynchronously with cancellation support
        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);

        await Task.WhenAll(outputTask, errorTask);
        await process.WaitForExitAsync(cancellationToken);

        return new ClamScanResult
        {
            ExitCode = process.ExitCode,
            Output = outputTask.Result,
            Error = errorTask.Result
        };
    }

    private ClamAVScanResult ParseScanResult(string filePath, ClamScanResult result)
    {
        // ClamAV exit codes:
        // 0 = no virus found
        // 1 = virus(es) found
        // 2 = error

        var output = result.Output.Trim();

        if (result.ExitCode == 0)
        {
            return new ClamAVScanResult
            {
                FilePath = filePath,
                IsInfected = false,
                IsError = false
            };
        }
        else if (result.ExitCode == 1)
        {
            // Parse infected result: "filename: Virus.Name FOUND"
            var parts = output.Split(new[] { ": " }, StringSplitOptions.None);
            if (parts.Length >= 2 && parts[1].Contains("FOUND"))
            {
                var virusName = parts[1].Replace(" FOUND", "").Trim();
                return new ClamAVScanResult
                {
                    FilePath = filePath,
                    IsInfected = true,
                    VirusName = virusName,
                    IsError = false
                };
            }

            return new ClamAVScanResult
            {
                FilePath = filePath,
                IsInfected = true,
                IsError = false
            };
        }
        else
        {
            return new ClamAVScanResult
            {
                FilePath = filePath,
                IsError = true,
                ErrorMessage = result.Error.Trim()
            };
        }
    }

    private ClamAVScanResult? ParseScanLine(string line)
    {
        line = line.Trim();
        if (string.IsNullOrWhiteSpace(line)) return null;

        // Format: "path: Virus.Name FOUND" or "path: OK"
        if (line.EndsWith("OK"))
        {
            var filePath = line.Substring(0, line.Length - 3).Trim();
            return new ClamAVScanResult { FilePath = filePath, IsInfected = false };
        }
        else if (line.Contains("FOUND"))
        {
            var parts = line.Split(new[] { ": " }, StringSplitOptions.None);
            if (parts.Length >= 2)
            {
                var filePath = parts[0].Trim();
                var virusPart = parts[1].Replace(" FOUND", "").Trim();
                return new ClamAVScanResult 
                { 
                    FilePath = filePath, 
                    IsInfected = true, 
                    VirusName = virusPart 
                };
            }
        }

        return null;
    }

    private string? FindClamScan()
    {
        // Check common installation paths
        var possiblePaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClamAV", "clamscan.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "ClamAV", "clamscan.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ClamAV", "clamscan.exe"),
            Path.Combine(@"C:\Program Files\ClamAV", "clamscan.exe"),
            Path.Combine(@"C:\Program Files (x86)\ClamAV", "clamscan.exe"),
        };

        foreach (var path in possiblePaths)
        {
            if (File.Exists(path))
                return path;
        }

        // Check PATH
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathEnv.Split(';'))
        {
            var fullPath = Path.Combine(dir, "clamscan.exe");
            if (File.Exists(fullPath))
                return fullPath;
        }

        return null;
    }

    private string? FindFreshClam()
    {
        // Check same locations as clamscan
        var clamscanDir = Path.GetDirectoryName(_clamScanPath);
        if (!string.IsNullOrEmpty(clamscanDir))
        {
            var freshclamPath = Path.Combine(clamscanDir, "freshclam.exe");
            if (File.Exists(freshclamPath))
                return freshclamPath;
        }

        // Check common paths
        var possiblePaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClamAV", "freshclam.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "ClamAV", "freshclam.exe"),
            Path.Combine(@"C:\Program Files\ClamAV", "freshclam.exe"),
            Path.Combine(@"C:\Program Files (x86)\ClamAV", "freshclam.exe"),
        };

        foreach (var path in possiblePaths)
        {
            if (File.Exists(path))
                return path;
        }

        // Check PATH
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathEnv.Split(';'))
        {
            var fullPath = Path.Combine(dir, "freshclam.exe");
            if (File.Exists(fullPath))
                return fullPath;
        }

        return null;
    }

    public ValueTask DisposeAsync()
    {
        _isInitialized = false;
        return ValueTask.CompletedTask;
    }

    private class ClamScanResult
    {
        public int ExitCode { get; set; }
        public string Output { get; set; } = "";
        public string Error { get; set; } = "";
    }
}

/// <summary>
/// Result of a ClamAV scan
/// </summary>
public sealed class ClamAVScanResult
{
    public string FilePath { get; set; } = "";
    public bool IsInfected { get; set; }
    public string? VirusName { get; set; }
    public bool IsError { get; set; }
    public string? ErrorMessage { get; set; }
}


