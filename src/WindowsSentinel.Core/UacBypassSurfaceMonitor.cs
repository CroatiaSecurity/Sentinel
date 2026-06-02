using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace WindowsSentinel.Core;

/// <summary>
/// UAC Bypass Surface Monitor â€” Proactively scans for DLL hijacking vectors that
/// could be exploited for privilege escalation via UAC bypass.
///
/// Ported from Antivirus.ps1's Get-COMAutoElevationVectors, Get-ManifestAutoElevateBinaries,
/// and Test-CopyDropVulnerable.
///
/// Scans for:
///   1. COM objects with Elevation\Enabled=1 whose InprocServer32/LocalServer32 targets
///      are writable or missing â€” attacker can plant a DLL to get auto-elevated execution.
///   2. System32 binaries with autoElevate manifest that lack SetDllDirectory hardening â€”
///      vulnerable to copy-to-temp + DLL sideload UAC bypass.
///   3. Binaries in PATH directories that could be DLL-search-order hijacked.
///
/// Scan frequency: every 15 minutes (these vectors change rarely).
///
/// MITRE ATT&CK:
///   T1548.002 â€” Abuse Elevation Control Mechanism: Bypass UAC
///   T1574.001 â€” Hijack Execution Flow: DLL Search Order Hijacking
/// </summary>
public sealed class UacBypassSurfaceMonitor : BackgroundService
{
    private readonly DetectionEngine _detectionEngine;
    private readonly ILogger<UacBypassSurfaceMonitor> _logger;

    private static readonly TimeSpan ScanInterval = TimeSpan.FromMinutes(15);
    private readonly ConcurrentDictionary<string, byte> _alertedVectors = new();

    // Known-safe auto-elevate binaries (Microsoft ships these intentionally)
    private static readonly HashSet<string> KnownAutoElevateBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "consent.exe", "dism.exe", "pkgmgr.exe", "taskmgr.exe",
        "msconfig.exe", "eventvwr.exe", "mmc.exe", "perfmon.exe",
        "resmon.exe", "sdclt.exe", "slui.exe", "osk.exe",
        "computerdefaults.exe", "changepk.exe", "fodhelper.exe"
    };

    public UacBypassSurfaceMonitor(
        DetectionEngine detectionEngine,
        ILogger<UacBypassSurfaceMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("UacBypassSurfaceMonitor: Starting (scan interval: 15 min)");

        // Initial delay to let system stabilize
        await Task.Delay(TimeSpan.FromSeconds(90), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanComAutoElevationVectorsAsync(stoppingToken);
                await ScanManifestAutoElevateBinariesAsync(stoppingToken);
                await ScanCopyDropVulnerabilitiesAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "UacBypassSurfaceMonitor: Scan error");
            }

            try { await Task.Delay(ScanInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>
    /// Scans HKLM\SOFTWARE\Classes\CLSID for COM objects with Elevation\Enabled=1
    /// whose target DLL/EXE is in a writable location or doesn't exist.
    /// </summary>
    private async Task ScanComAutoElevationVectorsAsync(CancellationToken ct)
    {
        var clsidPaths = new[]
        {
            @"SOFTWARE\Classes\CLSID",
            @"SOFTWARE\WOW6432Node\Classes\CLSID"
        };

        foreach (var basePath in clsidPaths)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                using var baseKey = Registry.LocalMachine.OpenSubKey(basePath);
                if (baseKey == null) continue;

                foreach (var clsidName in baseKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        using var clsidKey = baseKey.OpenSubKey(clsidName);
                        if (clsidKey == null) continue;

                        // Check for Elevation\Enabled=1
                        using var elevationKey = clsidKey.OpenSubKey("Elevation");
                        if (elevationKey == null) continue;

                        var enabled = elevationKey.GetValue("Enabled");
                        if (enabled is not int enabledInt || enabledInt != 1) continue;

                        // Get target path (InprocServer32 or LocalServer32)
                        string? targetPath = null;
                        string targetType = "";

                        using (var inprocKey = clsidKey.OpenSubKey("InprocServer32"))
                        {
                            if (inprocKey != null)
                            {
                                targetPath = inprocKey.GetValue("")?.ToString();
                                targetType = "InprocServer32 (DLL)";
                            }
                        }

                        if (string.IsNullOrEmpty(targetPath))
                        {
                            using var localKey = clsidKey.OpenSubKey("LocalServer32");
                            if (localKey != null)
                            {
                                targetPath = localKey.GetValue("")?.ToString();
                                targetType = "LocalServer32 (EXE)";
                            }
                        }

                        if (string.IsNullOrEmpty(targetPath)) continue;

                        // Expand environment variables
                        targetPath = Environment.ExpandEnvironmentVariables(targetPath);
                        // Strip quotes and arguments
                        targetPath = targetPath.Trim('"').Split(' ')[0];

                        // Check if target is missing or in a writable location
                        bool isMissing = !File.Exists(targetPath);
                        bool isWritable = !isMissing && IsPathUserWritable(targetPath);

                        if (isMissing || isWritable)
                        {
                            var alertKey = $"com:{clsidName}:{targetPath}";
                            if (!_alertedVectors.TryAdd(alertKey, 0)) continue;

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "UAC Bypass Surface: COM AutoElevation Vector",
                                Evidence = $"COM object {clsidName} has Elevation\\Enabled=1 with " +
                                          $"{(isMissing ? "MISSING" : "USER-WRITABLE")} target: {targetPath}",
                                Reasoning = "A COM object configured for auto-elevation points to a target " +
                                           "that is either missing or in a user-writable location. An attacker " +
                                           "can plant a malicious DLL/EXE at this path and trigger the COM object " +
                                           "to achieve code execution at high integrity (UAC bypass). " +
                                           "This is a well-known privilege escalation technique (T1548.002).",
                                Confidence = isMissing ? 0.88 : 0.82,
                                Tier = DetectionTier.Tier1Behavioral,
                                ProcessName = "UacBypassScan",
                                ProcessId = Environment.ProcessId,
                                Timestamp = DateTime.UtcNow,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["technique"] = "T1548.002 - Bypass UAC",
                                    ["clsid"] = clsidName,
                                    ["target_path"] = targetPath,
                                    ["target_type"] = targetType,
                                    ["vulnerability"] = isMissing ? "MissingTarget" : "WritableTarget",
                                    ["registry_path"] = $@"HKLM\{basePath}\{clsidName}"
                                }
                            }, ct);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "UacBypassSurface: Error checking CLSID {Clsid}", clsidName);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "UacBypassSurface: Error scanning {Path}", basePath);
            }
        }
    }

    /// <summary>
    /// Scans System32 for binaries with autoElevate manifest that lack DLL search hardening.
    /// </summary>
    private async Task ScanManifestAutoElevateBinariesAsync(CancellationToken ct)
    {
        var searchPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System)),
            Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "SysWOW64")
        };

        foreach (var searchPath in searchPaths)
        {
            if (!Directory.Exists(searchPath)) continue;

            string[] exeFiles;
            try
            {
                exeFiles = Directory.GetFiles(searchPath, "*.exe", SearchOption.TopDirectoryOnly);
            }
            catch { continue; }

            // Limit to first 300 to avoid excessive I/O
            var filesToCheck = exeFiles.Take(300);

            foreach (var exePath in filesToCheck)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    var fileName = Path.GetFileName(exePath);

                    // Skip known-safe auto-elevate binaries
                    if (KnownAutoElevateBinaries.Contains(fileName)) continue;

                    // Check for autoElevate in embedded manifest
                    if (!HasAutoElevateManifest(exePath)) continue;

                    // Check if binary lacks SetDllDirectory/SetDefaultDllDirectories
                    bool isVulnerable = IsCopyDropVulnerable(exePath);

                    if (isVulnerable)
                    {
                        var alertKey = $"manifest:{exePath}";
                        if (!_alertedVectors.TryAdd(alertKey, 0)) continue;

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "UAC Bypass Surface: Manifest AutoElevate + Copy-Drop Vulnerable",
                            Evidence = $"Binary '{fileName}' has autoElevate manifest and lacks " +
                                      "SetDllDirectory/SetDefaultDllDirectories hardening â€” " +
                                      "vulnerable to copy-to-temp DLL sideload UAC bypass.",
                            Reasoning = "A binary with autoElevate=true in its manifest will run at high " +
                                       "integrity without a UAC prompt. If it also lacks DLL search path " +
                                       "hardening (SetDllDirectory/SetDefaultDllDirectories), an attacker " +
                                       "can copy it to a user-writable directory, place a malicious DLL " +
                                       "alongside it, and execute it to achieve privilege escalation. " +
                                       "This is the 'copy-drop' UAC bypass technique.",
                            Confidence = 0.85,
                            Tier = DetectionTier.Tier2Indicator, // Preventive scan, not active attack
                            ProcessName = "UacBypassScan",
                            ProcessId = Environment.ProcessId,
                            Timestamp = DateTime.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["technique"] = "T1548.002 - Bypass UAC",
                                ["binary_path"] = exePath,
                                ["binary_name"] = fileName,
                                ["vulnerability"] = "CopyDropVulnerable",
                                ["lacks_hardening"] = "SetDllDirectory/SetDefaultDllDirectories"
                            }
                        }, ct);
                    }
                }
                catch { continue; }
            }
        }
    }

    /// <summary>
    /// Scans for recently-created DLLs in directories that are in the system PATH
    /// and could be used for DLL search order hijacking.
    /// </summary>
    private async Task ScanCopyDropVulnerabilitiesAsync(CancellationToken ct)
    {
        // Check user-writable PATH directories for suspicious DLLs
        var pathDirs = (Environment.GetEnvironmentVariable("PATH") ?? "")
            .Split(';', StringSplitOptions.RemoveEmptyEntries);

        foreach (var dir in pathDirs)
        {
            ct.ThrowIfCancellationRequested();

            if (!Directory.Exists(dir)) continue;

            // Skip system directories (they're expected to have DLLs)
            var dirLower = dir.ToLowerInvariant();
            if (dirLower.Contains(@"\windows\system32") ||
                dirLower.Contains(@"\windows\syswow64") ||
                dirLower.Contains(@"\program files"))
                continue;

            // Check if directory is user-writable
            if (!IsPathUserWritable(dir)) continue;

            try
            {
                var recentDlls = Directory.GetFiles(dir, "*.dll", SearchOption.TopDirectoryOnly)
                    .Select(f => new FileInfo(f))
                    .Where(f => (DateTime.UtcNow - f.LastWriteTimeUtc).TotalHours < 24)
                    .Take(20);

                foreach (var dll in recentDlls)
                {
                    var alertKey = $"pathdll:{dll.FullName}";
                    if (!_alertedVectors.TryAdd(alertKey, 0)) continue;

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "UAC Bypass Surface: Suspicious DLL in PATH Directory",
                        Evidence = $"Recently-created DLL '{dll.Name}' found in user-writable PATH " +
                                  $"directory '{dir}' (modified {dll.LastWriteTimeUtc:u}).",
                        Reasoning = "A DLL placed in a user-writable directory that is in the system PATH " +
                                   "can be loaded by any application that searches PATH for DLLs. " +
                                   "If the DLL name matches a commonly-loaded system DLL, this is a " +
                                   "DLL search order hijacking attack that can achieve code execution " +
                                   "in the context of any process that loads it.",
                        Confidence = 0.75,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = "UacBypassScan",
                        ProcessId = Environment.ProcessId,
                        Timestamp = DateTime.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["technique"] = "T1574.001 - DLL Search Order Hijacking",
                            ["dll_path"] = dll.FullName,
                            ["dll_name"] = dll.Name,
                            ["directory"] = dir,
                            ["last_modified"] = dll.LastWriteTimeUtc.ToString("o")
                        }
                    }, ct);
                }
            }
            catch { continue; }
        }
    }

    /// <summary>
    /// Checks if a binary has autoElevate=true in its embedded manifest.
    /// </summary>
    private static bool HasAutoElevateManifest(string exePath)
    {
        try
        {
            // Read first 64KB of the file to find embedded manifest
            var bytes = new byte[65536];
            int bytesRead;
            using (var fs = File.OpenRead(exePath))
            {
                bytesRead = fs.Read(bytes, 0, bytes.Length);
            }

            var content = Encoding.ASCII.GetString(bytes, 0, bytesRead);
            return Regex.IsMatch(content, @"autoElevate[\s>]*true", RegexOptions.IgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Checks if a binary lacks SetDllDirectory/SetDefaultDllDirectories imports
    /// (making it vulnerable to copy-drop DLL sideloading).
    /// </summary>
    private static bool IsCopyDropVulnerable(string exePath)
    {
        try
        {
            var bytes = new byte[65536];
            int bytesRead;
            using (var fs = File.OpenRead(exePath))
            {
                bytesRead = fs.Read(bytes, 0, bytes.Length);
            }

            var content = Encoding.ASCII.GetString(bytes, 0, bytesRead);
            bool hasSetDllDirectory = content.Contains("SetDllDirectory", StringComparison.Ordinal);
            bool hasSetDefaultDllDirectories = content.Contains("SetDefaultDllDirectories", StringComparison.Ordinal);

            return !(hasSetDllDirectory || hasSetDefaultDllDirectories);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Checks if a path is writable by standard (non-elevated) users.
    /// </summary>
    private static bool IsPathUserWritable(string path)
    {
        try
        {
            var dirPath = File.Exists(path) ? Path.GetDirectoryName(path) : path;
            if (string.IsNullOrEmpty(dirPath)) return false;

            var lower = dirPath.ToLowerInvariant();

            // Quick heuristic: user-profile paths are always writable
            if (lower.Contains(@"\users\") || lower.Contains(@"\appdata\") ||
                lower.Contains(@"\temp") || lower.Contains(@"\tmp") ||
                lower.Contains(@"\downloads"))
                return true;

            // System paths are not user-writable (normally)
            if (lower.StartsWith(@"c:\windows\") || lower.StartsWith(@"c:\program files"))
                return false;

            // For other paths, try to create a temp file
            var testFile = Path.Combine(dirPath, $".sentinel_acl_test_{Guid.NewGuid():N}");
            try
            {
                File.WriteAllText(testFile, "");
                File.Delete(testFile);
                return true;
            }
            catch
            {
                return false;
            }
        }
        catch
        {
            return false;
        }
    }
}


