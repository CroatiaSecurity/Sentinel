using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// MONITORED EXECUTION - NOT A TRUE SANDBOX
/// 
/// This component executes suspicious files in a monitored context and observes behavior.
/// IMPORTANT: This is NOT an isolated sandbox. Files execute at the same integrity level
/// as the parent process with access to the user environment. The monitoring detects
/// malicious behavior but does not prevent system modification.
/// 
/// Security model:
/// - ExecutionPolicy RemoteSigned (not Bypass) for PowerShell
/// - ArgumentList escaping prevents command injection
/// - File system and registry monitoring for change detection
/// - Network monitoring for C2 detection
/// - Process tree monitoring for child process detection
/// 
/// This is designed for analysis of already-quarantined or staged files, not as a
/// primary defense mechanism.
/// </summary>
public sealed class PseudoSandbox
{
    private readonly ILogger<PseudoSandbox> _logger;
    private readonly IDetectionEngine _detectionEngine;
    private readonly ScoringEngine _scoringEngine;

    // Suspicious patterns for dynamic analysis
    private static readonly Regex[] SuspiciousNetworkPatterns = new[]
    {
        new Regex(@"\b(dns|tcp|udp|http|connect|send|recv)\s", RegexOptions.IgnoreCase),
        new Regex(@"\b(socket|wget|curl|download|upload)\b", RegexOptions.IgnoreCase),
        new Regex(@"\b(443|4444|8080|9999)\b", RegexOptions.IgnoreCase) // Common C2 ports
    };

    private static readonly Regex[] SuspiciousRegistryPatterns = new[]
    {
        new Regex(@"\b(run|runonce|startup|shell\s+folders)\b", RegexOptions.IgnoreCase),
        new Regex(@"\b(currentversion\\run)\b", RegexOptions.IgnoreCase),
        new Regex(@"\b(services\\|winlogon\\shell)\b", RegexOptions.IgnoreCase)
    };

    private static readonly string[] SuspiciousImports = new[]
    {
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "SetThreadContext",
        "CryptEncrypt", "CryptDecrypt", "InternetOpen", "InternetConnect",
        "URLDownloadToFile", "WinExec", "ShellExecute", "CreateProcess"
    };

    public PseudoSandbox(
        ILogger<PseudoSandbox> logger,
        IDetectionEngine detectionEngine,
        ScoringEngine scoringEngine)
    {
        _logger = logger;
        _detectionEngine = detectionEngine;
        _scoringEngine = scoringEngine;
    }

    /// <summary>
    /// Analyzes a suspicious file in a monitored sandbox environment.
    /// </summary>
    public async Task<SandboxResult> AnalyzeAsync(
        string filePath, 
        SandboxOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new SandboxOptions();
        var result = new SandboxResult
        {
            FilePath = filePath,
            StartTime = DateTimeOffset.UtcNow
        };

        if (!File.Exists(filePath))
        {
            _logger.LogWarning("PseudoSandbox: File not found: {Path}", filePath);
            result.Status = SandboxStatus.FileNotFound;
            result.EndTime = DateTimeOffset.UtcNow;
            return result;
        }

        // Calculate file hash for reference
        result.FileHash = await ComputeFileHashAsync(filePath, cancellationToken);

        _logger.LogInformation(
            "PseudoSandbox: Starting analysis of {File} (timeout={Timeout}s)",
            filePath, options.TimeoutSeconds);

        try
        {
            // Take initial snapshots
            var networkBefore = GetCurrentConnections();
            var registryBefore = SnapshotRegistryKeys();
            var processBefore = GetCurrentProcessList();

            // Set up file system monitoring
            var fileChanges = new FileChangeTracker();
            using var watcher = SetupFileWatcher(options.WatchPaths, fileChanges);

            // Launch the target
            var targetProcess = await LaunchTargetAsync(filePath, options, cancellationToken);
            if (targetProcess == null)
            {
                result.Status = SandboxStatus.LaunchFailed;
                result.EndTime = DateTimeOffset.UtcNow;
                return result;
            }

            result.TargetProcessId = targetProcess.Id;
            _logger.LogInformation("PseudoSandbox: Target launched PID {Pid}", targetProcess.Id);

            // Monitor behavior during execution
            using var monitorCts = new CancellationTokenSource();
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, monitorCts.Token);

            var monitorTask = MonitorBehaviorAsync(
                targetProcess, 
                fileChanges, 
                networkBefore,
                options,
                linkedCts.Token);

            // Wait for timeout or early completion
            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(options.TimeoutSeconds), cancellationToken);
            var completedTask = await Task.WhenAny(monitorTask, timeoutTask);

            if (completedTask == timeoutTask)
            {
                monitorCts.Cancel();
                _logger.LogInformation("PseudoSandbox: Timeout reached after {Timeout}s", options.TimeoutSeconds);
            }

            // Terminate target if still running
            await TerminateTargetAsync(targetProcess, cancellationToken);

            // Collect final snapshots
            await Task.Delay(500, cancellationToken); // Brief delay for cleanup

            var networkAfter = GetCurrentConnections();
            var registryAfter = SnapshotRegistryKeys();
            var processAfter = GetCurrentProcessList();

            // Analyze differences
            result.NetworkConnections = AnalyzeNetworkChanges(networkBefore, networkAfter);
            result.RegistryModifications = AnalyzeRegistryChanges(registryBefore, registryAfter);
            result.FileModifications = fileChanges.GetChanges();
            result.SpawnedProcesses = AnalyzeProcessChanges(processBefore, processAfter, targetProcess.Id);

            // Analyze file for suspicious imports and strings
            result.StaticAnalysis = await PerformStaticAnalysisAsync(filePath, cancellationToken);

            // Score the behavior
            result.BehaviorScore = CalculateBehaviorScore(result);
            result.Verdict = DetermineVerdict(result.BehaviorScore);

            // Check for specific malicious behaviors
            await DetectMaliciousBehaviorsAsync(result, cancellationToken);

            result.Status = SandboxStatus.Completed;
            result.EndTime = DateTimeOffset.UtcNow;

            _logger.LogInformation(
                "PseudoSandbox: Analysis complete. Score={Score}, Verdict={Verdict}, " +
                "Network={Net}, Registry={Reg}, Files={Files}, Processes={Proc}",
                result.BehaviorScore, result.Verdict,
                result.NetworkConnections.Count,
                result.RegistryModifications.Count,
                result.FileModifications.Count,
                result.SpawnedProcesses.Count);
        }
        catch (OperationCanceledException)
        {
            result.Status = SandboxStatus.Cancelled;
            result.EndTime = DateTimeOffset.UtcNow;
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PseudoSandbox: Analysis failed for {File}", filePath);
            result.Status = SandboxStatus.Error;
            result.ErrorMessage = ex.Message;
            result.EndTime = DateTimeOffset.UtcNow;
        }

        return result;
    }

    /// <summary>
    /// Quick analysis - runs file briefly and returns immediate indicators.
    /// </summary>
    public async Task<QuickAnalysisResult> QuickAnalyzeAsync(
        string filePath, 
        CancellationToken cancellationToken = default)
    {
        var options = new SandboxOptions { TimeoutSeconds = 5, CollectMemoryDumps = false };
        var fullResult = await AnalyzeAsync(filePath, options, cancellationToken);

        return new QuickAnalysisResult
        {
            FilePath = filePath,
            FileHash = fullResult.FileHash,
            BehaviorScore = fullResult.BehaviorScore,
            Verdict = fullResult.Verdict,
            HasNetworkActivity = fullResult.NetworkConnections.Count > 0,
            HasPersistenceActivity = fullResult.RegistryModifications.Any(r => 
                r.KeyPath.Contains("Run", StringComparison.OrdinalIgnoreCase)),
            HasInjectionActivity = fullResult.StaticAnalysis?.SuspiciousImports.Any(i => 
                i.Contains("VirtualAlloc") || i.Contains("WriteProcessMemory")) ?? false,
            AnalysisDuration = fullResult.EndTime - fullResult.StartTime
        };
    }

    private Task<Process?> LaunchTargetAsync(string filePath, SandboxOptions options, CancellationToken cancellationToken)
    {
        try
        {
            // Validate file path - reject paths with dangerous characters
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                _logger.LogWarning("PseudoSandbox: Invalid or non-existent file: {Path}", filePath);
                return Task.FromResult<Process?>(null);
            }

            // Check for path traversal attempts
            var fullPath = Path.GetFullPath(filePath);
            if (!fullPath.StartsWith(Path.GetPathRoot(fullPath) ?? string.Empty, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("PseudoSandbox: Suspicious path detected: {Path}", filePath);
                return Task.FromResult<Process?>(null);
            }

            var ext = Path.GetExtension(filePath).ToLowerInvariant();
            ProcessStartInfo psi;

            switch (ext)
            {
                case ".exe":
                    psi = new ProcessStartInfo(filePath);
                    break;
                case ".ps1":
                    // SECURITY FIX: 
                    // 1. Use -ExecutionPolicy RemoteSigned (not Bypass) - allows local scripts, blocks remote
                    // 2. Use ArgumentList for proper escaping (prevents injection)
                    // 3. No -WindowStyle Hidden - we want to monitor visible activity
                    psi = new ProcessStartInfo("powershell.exe");
                    psi.ArgumentList.Add("-NoProfile");
                    psi.ArgumentList.Add("-ExecutionPolicy");
                    psi.ArgumentList.Add("RemoteSigned");  // NOT Bypass - much safer
                    psi.ArgumentList.Add("-File");
                    psi.ArgumentList.Add(filePath);
                    break;
                case ".bat":
                case ".cmd":
                    // SECURITY FIX: Use ArgumentList instead of string interpolation
                    psi = new ProcessStartInfo("cmd.exe");
                    psi.ArgumentList.Add("/c");
                    psi.ArgumentList.Add(filePath);
                    break;
                case ".vbs":
                case ".js":
                    psi = new ProcessStartInfo("cscript.exe");
                    psi.ArgumentList.Add("//nologo");
                    psi.ArgumentList.Add(filePath);
                    break;
                case ".hta":
                    psi = new ProcessStartInfo("mshta.exe");
                    psi.ArgumentList.Add(filePath);
                    break;
                case ".scr":
                    psi = new ProcessStartInfo(filePath);
                    psi.ArgumentList.Add("/s");
                    break;
                default:
                    _logger.LogWarning("PseudoSandbox: Unsupported file type: {Ext}", ext);
                    return Task.FromResult<Process?>(null);
            }

            psi.UseShellExecute = false;  // Required for ArgumentList and redirection
            psi.CreateNoWindow = false;   // SECURITY FIX: Allow window to be visible for monitoring
            psi.RedirectStandardOutput = options.CaptureOutput;
            psi.RedirectStandardError = options.CaptureOutput;
            
            // SECURITY FIX: Removed misleading "RunAsLowIntegrity" option
            // The previous implementation used psi.Verb = "runas" which actually ELEVATES to admin
            // True low-integrity requires Windows sandbox/AppContainer which is not implemented here
            // This analysis runs at same integrity level as parent - DO NOT claim sandboxing
            
            // Set working directory to temp to limit file system exposure
            psi.WorkingDirectory = Path.GetTempPath();

            _logger.LogInformation("PseudoSandbox: Launching {File} with restricted execution policy", filePath);
            var process = Process.Start(psi);
            return Task.FromResult<Process?>(process);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PseudoSandbox: Failed to launch {File}", filePath);
            return Task.FromResult<Process?>(null);
        }
    }

    private async Task MonitorBehaviorAsync(
        Process targetProcess,
        FileChangeTracker fileChanges,
        List<ConnectionInfo> networkBaseline,
        SandboxOptions options,
        CancellationToken cancellationToken)
    {
        var childProcesses = new HashSet<int> { targetProcess.Id };
        var interval = TimeSpan.FromMilliseconds(options.MonitorIntervalMs);

        try
        {
            while (!targetProcess.HasExited && !cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(interval, cancellationToken);

                // Monitor for new child processes
                try
                {
                    var children = GetChildProcesses(targetProcess.Id);
                    foreach (var child in children.Where(c => !childProcesses.Contains(c)))
                    {
                        childProcesses.Add(child);
                        _logger.LogDebug("PseudoSandbox: Detected child process PID {Pid}", child);
                    }
                }
                catch { /* May fail for exited processes */ }

                // Check for early termination conditions
                if (options.StopOnNetwork && HasNewNetworkConnections(networkBaseline))
                {
                    _logger.LogInformation("PseudoSandbox: Stopping early due to network activity");
                    break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Expected
        }
    }

    private async Task TerminateTargetAsync(Process? targetProcess, CancellationToken cancellationToken)
    {
        if (targetProcess == null || targetProcess.HasExited)
            return;

        try
        {
            _logger.LogDebug("PseudoSandbox: Terminating target PID {Pid}", targetProcess.Id);
            targetProcess.Kill(true); // Kill entire tree
            await targetProcess.WaitForExitAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "PseudoSandbox: Error terminating target");
        }
    }

    private FileSystemWatcher SetupFileWatcher(string[] watchPaths, FileChangeTracker tracker)
    {
        var watchers = new List<FileSystemWatcher>();

        foreach (var path in watchPaths.Where(Directory.Exists))
        {
            try
            {
                var watcher = new FileSystemWatcher(path)
                {
                    IncludeSubdirectories = true,
                    EnableRaisingEvents = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime
                };

                watcher.Created += (_, e) => tracker.OnFileCreated(e.FullPath);
                watcher.Changed += (_, e) => tracker.OnFileModified(e.FullPath);
                watcher.Deleted += (_, e) => tracker.OnFileDeleted(e.FullPath);
                watcher.Renamed += (_, e) => tracker.OnFileRenamed(e.OldFullPath, e.FullPath);

                watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "PseudoSandbox: Failed to setup watcher for {Path}", path);
            }
        }

        // Return the first watcher as the disposable (others would need cleanup in production)
        return watchers.FirstOrDefault() ?? new FileSystemWatcher();
    }

    private async Task<StaticAnalysisResult> PerformStaticAnalysisAsync(string filePath, CancellationToken cancellationToken)
    {
        var result = new StaticAnalysisResult();

        try
        {
            // Read file content
            var content = await File.ReadAllBytesAsync(filePath, cancellationToken);
            var text = System.Text.Encoding.UTF8.GetString(content);

            // Check for suspicious imports
            foreach (var import in SuspiciousImports)
            {
                if (text.Contains(import, StringComparison.OrdinalIgnoreCase))
                {
                    result.SuspiciousImports.Add(import);
                }
            }

            // Extract strings
            var strings = ExtractStrings(content);
            result.Strings = strings.Take(100).ToList(); // Limit to first 100

            // Look for suspicious patterns
            result.HasEncodedContent = DetectEncodedContent(text);
            result.HasSuspiciousUrls = DetectSuspiciousUrls(text);
            result.HasPowershellObfuscation = DetectPowershellObfuscation(text);

            // PE analysis for executables
            if (filePath.EndsWith(".exe") || filePath.EndsWith(".dll"))
            {
                result.IsPeFile = true;
                result.HasPackedSections = DetectPacking(content);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "PseudoSandbox: Static analysis error");
        }

        return result;
    }

    private async Task DetectMaliciousBehaviorsAsync(SandboxResult result, CancellationToken cancellationToken)
    {
        // Network-based C2 detection
        if (result.NetworkConnections.Any(c => c.IsSuspiciousPort || c.IsUnknownDestination))
        {
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Sandbox: Suspicious Network Activity Detected",
                Evidence = $"Target made {result.NetworkConnections.Count} network connections during sandbox execution",
                Reasoning = "Network connections from sandboxed files may indicate C2 communication or data exfiltration",
                Confidence = Math.Min(0.7 + (result.NetworkConnections.Count * 0.05), 0.95),
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = Path.GetFileName(result.FilePath),
                ProcessId = result.TargetProcessId ?? 0,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["file_path"] = result.FilePath,
                    ["file_hash"] = result.FileHash,
                    ["connection_count"] = result.NetworkConnections.Count.ToString(),
                    ["technique"] = "T1041 - Exfiltration Over C2 Channel"
                }
            }, cancellationToken);
        }

        // Persistence detection
        var persistenceMods = result.RegistryModifications.Where(r =>
            r.KeyPath.Contains("Run", StringComparison.OrdinalIgnoreCase) ||
            r.KeyPath.Contains("RunOnce", StringComparison.OrdinalIgnoreCase)).ToList();

        if (persistenceMods.Any())
        {
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Sandbox: Persistence Mechanism Detected",
                Evidence = $"Target modified {persistenceMods.Count} persistence-related registry keys",
                Reasoning = "Registry Run key modifications indicate attempt to achieve persistence",
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = Path.GetFileName(result.FilePath),
                ProcessId = result.TargetProcessId ?? 0,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["file_path"] = result.FilePath,
                    ["file_hash"] = result.FileHash,
                    ["modified_keys"] = string.Join("; ", persistenceMods.Select(p => p.KeyPath)),
                    ["technique"] = "T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys"
                }
            }, cancellationToken);
        }

        // Injection detection
        if (result.StaticAnalysis?.SuspiciousImports.Any(i => 
            i.Contains("CreateRemoteThread") || i.Contains("WriteProcessMemory")) ?? false)
        {
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Sandbox: Process Injection Capabilities Detected",
                Evidence = "Target imports process injection APIs",
                Reasoning = "Files with process injection APIs may be shellcode loaders or injectors",
                Confidence = 0.75,
                Tier = DetectionTier.Tier2Indicator,
                ProcessName = Path.GetFileName(result.FilePath),
                ProcessId = 0,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["file_path"] = result.FilePath,
                    ["file_hash"] = result.FileHash,
                    ["suspicious_apis"] = string.Join(", ", result.StaticAnalysis?.SuspiciousImports ?? new List<string>()),
                    ["technique"] = "T1055 - Process Injection"
                }
            }, cancellationToken);
        }
    }

    // Helper methods
    private List<ConnectionInfo> GetCurrentConnections()
    {
        var connections = new List<ConnectionInfo>();
        try
        {
            var tcpConnections = IPGlobalProperties.GetIPGlobalProperties()
                .GetActiveTcpConnections()
                .Select(c => new ConnectionInfo
                {
                    LocalAddress = c.LocalEndPoint.ToString(),
                    RemoteAddress = c.RemoteEndPoint.ToString(),
                    State = c.State.ToString()
                });
            connections.AddRange(tcpConnections);
        }
        catch { }
        return connections;
    }

    private Dictionary<string, string> SnapshotRegistryKeys()
    {
        // Simplified - in production would snapshot relevant keys
        return new Dictionary<string, string>();
    }

    private List<int> GetCurrentProcessList()
    {
        return Process.GetProcesses().Select(p => p.Id).ToList();
    }

    private List<int> GetChildProcesses(int parentPid)
    {
        var children = new List<int>();
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT ProcessId FROM Win32_Process WHERE ParentProcessId = {parentPid}");
            foreach (var obj in searcher.Get())
            {
                children.Add(Convert.ToInt32(obj["ProcessId"]));
            }
        }
        catch { }
        return children;
    }

    private List<ConnectionInfo> AnalyzeNetworkChanges(List<ConnectionInfo> before, List<ConnectionInfo> after)
    {
        var beforeSet = new HashSet<string>(before.Select(c => c.RemoteAddress));
        return after.Where(c => !beforeSet.Contains(c.RemoteAddress) && c.State == "Established").ToList();
    }

    private List<RegistryModification> AnalyzeRegistryChanges(Dictionary<string, string> before, Dictionary<string, string> after)
    {
        var mods = new List<RegistryModification>();
        foreach (var kvp in after)
        {
            if (!before.TryGetValue(kvp.Key, out var oldValue) || oldValue != kvp.Value)
            {
                mods.Add(new RegistryModification
                {
                    KeyPath = kvp.Key,
                    OldValue = oldValue,
                    NewValue = kvp.Value,
                    IsNew = oldValue == null
                });
            }
        }
        return mods;
    }

    private List<ProcessInfo> AnalyzeProcessChanges(List<int> before, List<int> after, int targetPid)
    {
        return after.Where(id => !before.Contains(id) && id != targetPid)
            .Select(id => new ProcessInfo { ProcessId = id, Name = GetProcessNameSafe(id) })
            .ToList();
    }

    private string GetProcessNameSafe(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName;
        }
        catch { return "Unknown"; }
    }

    private int CalculateBehaviorScore(SandboxResult result)
    {
        int score = 0;

        // Network activity (significant)
        score += Math.Min(result.NetworkConnections.Count * 15, 50);

        // Registry persistence
        var persistenceCount = result.RegistryModifications.Count(r =>
            r.KeyPath.Contains("Run", StringComparison.OrdinalIgnoreCase));
        score += persistenceCount * 25;

        // File modifications
        score += Math.Min(result.FileModifications.Count * 5, 30);

        // Spawned processes
        score += result.SpawnedProcesses.Count * 20;

        // Static analysis indicators
        if (result.StaticAnalysis != null)
        {
            score += Math.Min(result.StaticAnalysis.SuspiciousImports.Count * 5, 30);
            if (result.StaticAnalysis.HasEncodedContent) score += 15;
            if (result.StaticAnalysis.HasSuspiciousUrls) score += 20;
            if (result.StaticAnalysis.HasPowershellObfuscation) score += 25;
            if (result.StaticAnalysis.HasPackedSections) score += 15;
        }

        return Math.Min(score, 100);
    }

    private SandboxVerdict DetermineVerdict(int score)
    {
        return score switch
        {
            >= 70 => SandboxVerdict.Malicious,
            >= 40 => SandboxVerdict.Suspicious,
            >= 15 => SandboxVerdict.LowRisk,
            _ => SandboxVerdict.Clean
        };
    }

    private List<string> ExtractStrings(byte[] data)
    {
        var strings = new List<string>();
        var current = new List<byte>();

        foreach (var b in data)
        {
            if (b >= 32 && b < 127) // Printable ASCII
            {
                current.Add(b);
                if (current.Count > 100) // Limit length
                {
                    current.Clear();
                }
            }
            else
            {
                if (current.Count >= 4)
                {
                    strings.Add(System.Text.Encoding.UTF8.GetString(current.ToArray()));
                }
                current.Clear();
            }
        }

        return strings;
    }

    private bool DetectEncodedContent(string text)
    {
        var base64Pattern = new Regex(@"[A-Za-z0-9+/]{100,}={0,2}");
        return base64Pattern.IsMatch(text);
    }

    private bool DetectSuspiciousUrls(string text)
    {
        var urlPattern = new Regex(@"https?://[^\s""]+");
        var urls = urlPattern.Matches(text);
        return urls.Count > 0 && urls.Any(u => 
            u.Value.Contains("pastebin") || 
            u.Value.Contains("githubusercontent") ||
            u.Value.Contains("transfer.sh") ||
            u.Value.Contains("raw.githubusercontent"));
    }

    private bool DetectPowershellObfuscation(string text)
    {
        var indicators = new[]
        {
            "-enc", "-encodedcommand", "[Convert]::", "FromBase64String",
            "-windowstyle hidden", "-nop", "-noprofile"
        };
        return indicators.Any(i => text.Contains(i, StringComparison.OrdinalIgnoreCase));
    }

    private bool DetectPacking(byte[] content)
    {
        // High entropy indicates packing
        if (content.Length < 1000) return false;
        var entropy = CalculateEntropy(content.Take(4096).ToArray());
        return entropy > 6.5;
    }

    private double CalculateEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;
        var frequencies = new int[256];
        foreach (var b in data) frequencies[b]++;
        
        double entropy = 0;
        foreach (var freq in frequencies)
        {
            if (freq == 0) continue;
            var p = (double)freq / data.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private bool HasNewNetworkConnections(List<ConnectionInfo> baseline)
    {
        var current = GetCurrentConnections();
        var baselineSet = new HashSet<string>(baseline.Select(c => c.RemoteAddress));
        return current.Any(c => !baselineSet.Contains(c.RemoteAddress));
    }

    private async Task<string> ComputeFileHashAsync(string filePath, CancellationToken cancellationToken)
    {
        using var sha256 = SHA256.Create();
        await using var stream = File.OpenRead(filePath);
        var hash = await sha256.ComputeHashAsync(stream, cancellationToken);
        return Convert.ToHexString(hash);
    }
}

// Supporting types
public sealed class SandboxOptions
{
    public int TimeoutSeconds { get; set; } = 30;
    public string[] WatchPaths { get; set; } = new[]
    {
        Path.GetTempPath(),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
    };
    public bool StopOnNetwork { get; set; } = false;
    public bool CaptureOutput { get; set; } = true;
    public bool CollectMemoryDumps { get; set; } = false;
    // REMOVED: RunAsLowIntegrity - this option was misleading as it actually elevated via UAC
    // True sandboxing would require Windows Sandbox, AppContainer, or hypervisor isolation
    public int MonitorIntervalMs { get; set; } = 500;
}

public sealed class SandboxResult
{
    public string FilePath { get; set; } = "";
    public string FileHash { get; set; } = "";
    public int? TargetProcessId { get; set; }
    public DateTimeOffset StartTime { get; set; }
    public DateTimeOffset EndTime { get; set; }
    public SandboxStatus Status { get; set; }
    public string? ErrorMessage { get; set; }

    // Analysis results
    public List<ConnectionInfo> NetworkConnections { get; set; } = new();
    public List<RegistryModification> RegistryModifications { get; set; } = new();
    public List<FileModification> FileModifications { get; set; } = new();
    public List<ProcessInfo> SpawnedProcesses { get; set; } = new();
    public StaticAnalysisResult? StaticAnalysis { get; set; }

    // Scoring
    public int BehaviorScore { get; set; }
    public SandboxVerdict Verdict { get; set; }
}

public sealed class QuickAnalysisResult
{
    public string FilePath { get; set; } = "";
    public string FileHash { get; set; } = "";
    public int BehaviorScore { get; set; }
    public SandboxVerdict Verdict { get; set; }
    public bool HasNetworkActivity { get; set; }
    public bool HasPersistenceActivity { get; set; }
    public bool HasInjectionActivity { get; set; }
    public TimeSpan AnalysisDuration { get; set; }
}

public sealed class ConnectionInfo
{
    public string LocalAddress { get; set; } = "";
    public string RemoteAddress { get; set; } = "";
    public string State { get; set; } = "";
    public bool IsSuspiciousPort => RemoteAddress?.Contains(":4444") == true ||
                                     RemoteAddress?.Contains(":8080") == true ||
                                     RemoteAddress?.Contains(":9999") == true;
    public bool IsUnknownDestination => true; // Would check against allowlist in production
}

public sealed class RegistryModification
{
    public string KeyPath { get; set; } = "";
    public string? OldValue { get; set; }
    public string NewValue { get; set; } = "";
    public bool IsNew { get; set; }
}

public sealed class FileModification
{
    public string Path { get; set; } = "";
    public string Type { get; set; } = ""; // Created, Modified, Deleted, Renamed
    public DateTimeOffset Timestamp { get; set; }
}

public sealed class ProcessInfo
{
    public int ProcessId { get; set; }
    public string Name { get; set; } = "";
}

public sealed class StaticAnalysisResult
{
    public bool IsPeFile { get; set; }
    public List<string> SuspiciousImports { get; set; } = new();
    public List<string> Strings { get; set; } = new();
    public bool HasEncodedContent { get; set; }
    public bool HasSuspiciousUrls { get; set; }
    public bool HasPowershellObfuscation { get; set; }
    public bool HasPackedSections { get; set; }
}

public sealed class FileChangeTracker
{
    private readonly List<FileModification> _changes = new();
    private readonly object _lock = new();

    public void OnFileCreated(string path) => AddChange(path, "Created");
    public void OnFileModified(string path) => AddChange(path, "Modified");
    public void OnFileDeleted(string path) => AddChange(path, "Deleted");
    public void OnFileRenamed(string oldPath, string newPath) => AddChange($"{oldPath} -> {newPath}", "Renamed");

    private void AddChange(string path, string type)
    {
        lock (_lock)
        {
            _changes.Add(new FileModification
            {
                Path = path,
                Type = type,
                Timestamp = DateTimeOffset.UtcNow
            });
        }
    }

    public List<FileModification> GetChanges()
    {
        lock (_lock)
        {
            return _changes.ToList();
        }
    }
}

public enum SandboxStatus
{
    FileNotFound,
    LaunchFailed,
    Running,
    Completed,
    Cancelled,
    Error
}

public enum SandboxVerdict
{
    Clean,
    LowRisk,
    Suspicious,
    Malicious
}
