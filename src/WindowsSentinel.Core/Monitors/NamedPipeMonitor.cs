using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Monitors named pipe creation and connection events via ETW
/// (Microsoft-Windows-Kernel-File provider) to detect:
///   - Cobalt Strike SMB beacon lateral movement
///   - PsExec service communication
///   - Impacket named pipe channels
///   - Custom C2 pipe channels
///
/// Named pipes are a critical blind spot for EDRs — many C2 frameworks
/// use them for inter-process communication and lateral movement.
/// </summary>
public sealed class NamedPipeMonitor : IMonitor
{
    public string Name => "Named Pipe Monitor";

    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<NamedPipeMonitor> _logger;
    private readonly ProcessAncestryCache? _ancestryCache;
    private Task? _pollTask;
    private CancellationTokenSource? _cts;

    // Deduplication: track which pipes we've already alerted on
    private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedPipes = new();
    private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromMinutes(5);

    // ── Known malicious pipe name patterns ──────────────────────────────────
    // These patterns cover major C2 frameworks and attack tools.
    private static readonly string[] MaliciousPipePatterns = new[]
    {
        // Cobalt Strike default and common pipes
        "msagent_",
        "MSSE-",
        "postex_",
        "postex_ssh_",
        "status_",
        "mojo.5688.8052.",
        "win_svc.",
        "ntsvcs",
        "scerpc",
        "mypipe-f",
        "mypipe-h",
        "demoagent_",

        // Cobalt Strike SMB beacon (configurable, but common defaults)
        "\\\\pipe\\msagent",
        "\\\\pipe\\MSSE-",

        // PsExec / Impacket
        "psexesvc",
        "remcom_",
        "csexec_",
        "svcctl",

        // Metasploit
        "msf_",
        "meterpreter_",

        // Covenant / Grunt
        "gruntsvc",

        // CrackMapExec
        "cme_",

        // Generic suspicious patterns
        "evil",
        "shell",
        "beacon",
        "implant",
        "c2pipe",
        "cobaltstrike",
    };

    // Known legitimate pipes to exclude (reduce false positives)
    private static readonly HashSet<string> SafePipeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "lsass",
        "ntsvcs",       // Legitimate Windows service
        "scerpc",       // Legitimate Windows service
        "browser",
        "wkssvc",
        "srvsvc",
        "winreg",
        "samr",
        "netlogon",
        "spoolss",
        "epmapper",
        "eventlog",
        "InitShutdown",
        "lsarpc",
        "protected_storage",
        "router",
        "winsock2",
        "tapsrv",
        "atsvc",
        "W32TIME_ALT",
        "MsFteWds",
        "openssh-ssh-agent",
        "docker_engine",
        "crashpad_",
    };

    public NamedPipeMonitor(
        IDetectionEngine detectionEngine,
        ILogger<NamedPipeMonitor> logger,
        ProcessAncestryCache? ancestryCache = null)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _ancestryCache = ancestryCache;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("[{Monitor}] Starting named pipe surveillance.", Name);
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _pollTask = PollLoopAsync(_cts.Token);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("[{Monitor}] Stopping.", Name);
        _cts?.Cancel();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Polls the system for named pipes and checks against known malicious patterns.
    /// Uses the Windows API to enumerate pipes in \\.\pipe\ namespace.
    /// </summary>
    private async Task PollLoopAsync(CancellationToken cancellationToken)
    {
        // Initial delay to let the system settle after boot
        await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken);

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                PruneAlertCache();
                await ScanNamedPipesAsync(cancellationToken);
                await Task.Delay(TimeSpan.FromSeconds(15), cancellationToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[{Monitor}] Scan error.", Name);
                await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
            }
        }
    }

    private async Task ScanNamedPipesAsync(CancellationToken cancellationToken)
    {
        string[] pipes;
        try
        {
            // Enumerate all named pipes on the system
            pipes = Directory.GetFiles(@"\\.\pipe\");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[{Monitor}] Failed to enumerate pipes.", Name);
            return;
        }

        foreach (var pipePath in pipes)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var pipeName = Path.GetFileName(pipePath);
            if (string.IsNullOrEmpty(pipeName)) continue;

            // Skip known safe pipes
            if (IsSafePipe(pipeName)) continue;

            // Check against malicious patterns
            var matchedPattern = GetMatchedPattern(pipeName);
            if (matchedPattern is null) continue;

            // Deduplicate alerts
            var dedupeKey = pipeName.ToLowerInvariant();
            if (_alertedPipes.TryGetValue(dedupeKey, out var lastAlert) &&
                DateTimeOffset.UtcNow - lastAlert < AlertDedupeWindow)
            {
                continue;
            }

            _alertedPipes[dedupeKey] = DateTimeOffset.UtcNow;

            // Try to get the owning process
            int ownerPid = TryGetPipeOwnerPid(pipePath);
            string ownerName = ownerPid > 0
                ? _ancestryCache?.GetProcessName(ownerPid) ?? $"PID:{ownerPid}"
                : "Unknown";

            _logger.LogWarning(
                "[{Monitor}] Suspicious named pipe detected: '{Pipe}' (pattern: {Pattern}, owner: {Owner})",
                Name, pipeName, matchedPattern, ownerName);

            var detection = new DetectionEvent
            {
                RuleName = "NamedPipe: Suspicious C2/Lateral Movement Pipe",
                Evidence = $"Named pipe '{pipeName}' matches known malicious pattern '{matchedPattern}'",
                Reasoning = "Named pipes matching C2 framework patterns (Cobalt Strike, PsExec, Metasploit, " +
                           "Impacket) indicate potential lateral movement or command-and-control communication. " +
                           "Legitimate software rarely uses these pipe naming conventions.",
                Confidence = CalculateConfidence(pipeName, matchedPattern, ownerName),
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = ownerName,
                ProcessId = ownerPid > 0 ? ownerPid : 0,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["pipe_name"] = pipeName,
                    ["matched_pattern"] = matchedPattern,
                    ["owner_pid"] = ownerPid.ToString(),
                    ["owner_name"] = ownerName,
                    ["pipe_path"] = pipePath
                }
            };

            await _detectionEngine.ProcessAsync(detection, cancellationToken);
        }
    }

    private static bool IsSafePipe(string pipeName)
    {
        // Check exact matches
        if (SafePipeNames.Contains(pipeName)) return true;

        // Check prefix matches for known safe patterns
        foreach (var safe in SafePipeNames)
        {
            if (pipeName.StartsWith(safe, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        // Skip Chrome/Edge/Firefox IPC pipes (very common, always benign)
        if (pipeName.StartsWith("chrome.", StringComparison.OrdinalIgnoreCase) ||
            pipeName.StartsWith("chromium.", StringComparison.OrdinalIgnoreCase) ||
            pipeName.StartsWith("mojo.", StringComparison.OrdinalIgnoreCase) ||
            pipeName.StartsWith("gecko-crash", StringComparison.OrdinalIgnoreCase) ||
            pipeName.StartsWith("LOCAL\\", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    private static string? GetMatchedPattern(string pipeName)
    {
        var lowerPipe = pipeName.ToLowerInvariant();

        foreach (var pattern in MaliciousPipePatterns)
        {
            var lowerPattern = pattern.ToLowerInvariant()
                .Replace("\\\\pipe\\", ""); // Normalize pattern

            if (lowerPipe.Contains(lowerPattern))
                return pattern;
        }

        return null;
    }

    private static double CalculateConfidence(string pipeName, string matchedPattern, string ownerName)
    {
        double confidence = 0.70; // Base confidence for pattern match

        // Higher confidence for very specific C2 patterns
        if (matchedPattern.StartsWith("msagent_") ||
            matchedPattern.StartsWith("MSSE-") ||
            matchedPattern.StartsWith("postex_") ||
            matchedPattern.StartsWith("meterpreter_"))
        {
            confidence = 0.90;
        }

        // Higher confidence if owner is suspicious
        if (ownerName.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
            ownerName.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
            ownerName.Contains("rundll32", StringComparison.OrdinalIgnoreCase) ||
            ownerName.Contains("regsvr32", StringComparison.OrdinalIgnoreCase))
        {
            confidence = Math.Min(confidence + 0.10, 0.95);
        }

        return confidence;
    }

    /// <summary>
    /// Attempts to determine the PID that owns a named pipe.
    /// Uses GetNamedPipeServerProcessId when available.
    /// </summary>
    private static int TryGetPipeOwnerPid(string pipePath)
    {
        try
        {
            using var fs = File.Open(pipePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var handle = fs.SafeFileHandle;

            if (GetNamedPipeServerProcessId(handle.DangerousGetHandle(), out uint serverPid))
                return (int)serverPid;
        }
        catch
        {
            // Access denied or pipe closed — expected for many system pipes
        }

        return 0;
    }

    private void PruneAlertCache()
    {
        if (_alertedPipes.Count < 50) return;

        var cutoff = DateTimeOffset.UtcNow - AlertDedupeWindow;
        foreach (var kvp in _alertedPipes)
        {
            if (kvp.Value < cutoff)
                _alertedPipes.TryRemove(kvp.Key, out _);
        }
    }

    public ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        return ValueTask.CompletedTask;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);
}
