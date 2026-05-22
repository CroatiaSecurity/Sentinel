using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// PowerShell Threat Monitor — Detects malicious PowerShell usage by subscribing to
/// the Microsoft-Windows-PowerShell ETW provider for script-block logging events.
///
/// This closes the "living-off-the-land" gap where attackers abuse a user's already-running
/// PowerShell session or spawn new PowerShell instances with malicious commands.
///
/// Detection vectors:
///   1. Encoded commands (-EncodedCommand / -enc) — obfuscation technique
///   2. AMSI bypass attempts (patching AmsiScanBuffer, reflection-based disabling)
///   3. Download cradles (IEX(IWR ...), Net.WebClient, Invoke-WebRequest + IEX)
///   4. Credential access commands (Get-Credential abuse, Mimikatz invocations)
///   5. Reflective loading (Assembly.Load, [Reflection.Assembly]::Load)
///   6. Constrained Language Mode bypass attempts
///   7. Known offensive PowerShell frameworks (PowerSploit, Empire, Covenant, etc.)
///   8. Process injection via PowerShell (Invoke-ReflectivePEInjection, etc.)
///   9. Persistence mechanisms (scheduled tasks, registry run keys via PS)
///  10. Suspicious execution policy bypasses (-ExecutionPolicy Bypass)
///
/// How it works:
///   - Subscribes to Microsoft-Windows-PowerShell ETW provider (Event ID 4104 = ScriptBlock)
///   - Analyzes script content against threat patterns
///   - Falls back to process command-line scanning if ETW is unavailable
///
/// MITRE ATT&amp;CK:
///   T1059.001 — Command and Scripting Interpreter: PowerShell
///   T1562.001 — Impair Defenses: Disable or Modify Tools (AMSI bypass)
///   T1027     — Obfuscated Files or Information (encoded commands)
///   T1105     — Ingress Tool Transfer (download cradles)
/// </summary>
public sealed class PowerShellThreatMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<PowerShellThreatMonitor> _logger;

    private TraceEventSession? _etwSession;
    private static readonly TimeSpan FallbackScanInterval = TimeSpan.FromSeconds(8);

    private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedKeys = new();
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(2);

    // ═══════════════════════════════════════════════════════════════════════════
    // THREAT PATTERNS — Organized by severity
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Critical patterns — immediate kill authorization (AMSI bypass, credential theft).
    /// These indicate active attack in progress.
    /// </summary>
    private static readonly (string Pattern, string Description, double Confidence)[] CriticalPatterns =
    {
        // AMSI bypass techniques
        ("amsiscanbuffer", "AMSI Tampering: AmsiScanBuffer patching", 0.95),
        ("amsiutils", "AMSI Tampering: AmsiUtils reflection", 0.94),
        ("amsiinitfailed", "AMSI Tampering: AmsiInitFailed flag", 0.94),
        ("set-mppreference -disablerealtimemonitoring", "AMSI Tampering: Defender real-time protection disable", 0.93),
        ("set-mppreference -disableioavprotection", "AMSI Tampering: Defender IOAV protection disable", 0.93),
        ("remove-mppreference", "AMSI Tampering: Defender preference removal", 0.88),

        // ETW bypass (blinding EDR)
        ("nttracevent", "ETW Tampering: NtTraceEvent patching", 0.95),
        ("etweventswrite", "ETW Tampering: EtwEventWrite patching", 0.95),

        // Direct credential theft
        ("invoke-mimikatz", "LSASS Credential Dump: Mimikatz via PowerShell", 0.96),
        ("invoke-kerberoast", "Credential Dump: Kerberoasting attack", 0.93),
        ("invoke-rubeus", "Credential Dump: Rubeus Kerberos abuse", 0.93),
        ("sekurlsa::logonpasswords", "LSASS Credential Dump: sekurlsa logonpasswords", 0.96),
        ("invoke-dcsync", "Credential Dump: DCSync attack", 0.95),
        ("get-domainhash", "Credential Dump: Domain hash extraction", 0.92),
    };

    /// <summary>
    /// High-severity patterns — strong indicators of malicious activity.
    /// </summary>
    private static readonly (string Pattern, string Description, double Confidence)[] HighPatterns =
    {
        // Download cradles
        ("iex(iwr", "Download cradle: IEX(IWR ...)", 0.88),
        ("iex(invoke-webrequest", "Download cradle: IEX(Invoke-WebRequest)", 0.88),
        ("iex (new-object net.webclient).downloadstring", "Download cradle: WebClient.DownloadString", 0.90),
        ("invoke-expression (new-object", "Download cradle: Invoke-Expression + New-Object", 0.87),
        (".downloadstring(", "Download cradle: DownloadString method", 0.82),
        (".downloadfile(", "Download cradle: DownloadFile method", 0.80),
        ("start-bitstransfer", "BITS transfer (potential staging)", 0.70),

        // Reflective loading
        ("[reflection.assembly]::load", "Reflective assembly loading", 0.88),
        ("[system.reflection.assembly]::load", "Reflective assembly loading", 0.88),
        ("invoke-reflectivepeinjection", "Reflective PE injection", 0.94),
        ("invoke-shellcode", "Shellcode injection via PowerShell", 0.93),
        ("invoke-dllinjection", "DLL injection via PowerShell", 0.93),

        // Offensive frameworks
        ("invoke-bloodhound", "BloodHound AD enumeration", 0.90),
        ("invoke-sharphound", "SharpHound AD enumeration", 0.90),
        ("invoke-powershellwmi", "WMI lateral movement", 0.85),
        ("invoke-psexec", "PsExec lateral movement", 0.88),
        ("invoke-smbexec", "SMBExec lateral movement", 0.88),
        ("invoke-wmiexec", "WMIExec lateral movement", 0.88),
        ("invoke-atexec", "AtExec lateral movement", 0.85),
        ("invoke-dcomexec", "DCOMExec lateral movement", 0.85),
        ("invoke-internalmonologue", "Internal Monologue NTLMv1 downgrade", 0.92),
        ("invoke-thehash", "Pass-the-Hash via PowerShell", 0.90),

        // Persistence
        ("new-scheduledtaskaction.*-execute.*powershell", "Scheduled task persistence with PowerShell", 0.82),
        ("set-itemproperty.*\\\\run\\\\", "Registry Run key persistence", 0.80),
        ("new-service.*-binarypath", "Service creation for persistence", 0.78),

        // Constrained Language Mode bypass
        ("fulllanguage", "CLM bypass attempt", 0.85),
        ("languagemode.*full", "CLM bypass attempt", 0.85),
    };

    /// <summary>
    /// Medium-severity patterns — suspicious but may have legitimate uses.
    /// Logged as Tier2 indicators for correlation.
    /// </summary>
    private static readonly (string Pattern, string Description, double Confidence)[] MediumPatterns =
    {
        // Encoded commands (very common in attacks, but also used by some legitimate tools)
        ("-encodedcommand", "Encoded command execution", 0.72),
        ("-enc ", "Encoded command execution (short form)", 0.72),
        ("-e ", "Possible encoded command (ambiguous short form)", 0.55),
        ("frombase64string", "Base64 decoding (potential payload)", 0.68),
        ("[convert]::frombase64string", "Base64 decoding", 0.70),

        // Execution policy bypass
        ("-executionpolicy bypass", "Execution policy bypass", 0.65),
        ("-ep bypass", "Execution policy bypass (short)", 0.65),
        ("set-executionpolicy unrestricted", "Execution policy set to unrestricted", 0.70),

        // Reconnaissance
        ("get-aduser", "AD user enumeration", 0.50),
        ("get-adcomputer", "AD computer enumeration", 0.50),
        ("get-adgroup", "AD group enumeration", 0.50),
        ("get-netuser", "PowerView user enumeration", 0.75),
        ("get-netcomputer", "PowerView computer enumeration", 0.75),
        ("get-netgroup", "PowerView group enumeration", 0.75),
        ("get-netdomain", "PowerView domain enumeration", 0.75),
        ("find-localadminaccess", "PowerView local admin discovery", 0.82),

        // Suspicious operations
        ("add-type -typedefinition", "Inline C# compilation (potential payload)", 0.65),
        ("add-type.*dllimport", "P/Invoke definition (potential API abuse)", 0.70),
        ("[runtime.interopservices.marshal]", "Marshal class usage (memory manipulation)", 0.68),
        ("virtualalloc", "VirtualAlloc via PowerShell (shellcode)", 0.80),
        ("virtualprotect", "VirtualProtect via PowerShell (shellcode)", 0.80),
        ("createthread", "CreateThread via PowerShell (shellcode)", 0.82),
    };

    // PowerShell ETW provider
    private static readonly Guid PowerShellProviderGuid =
        new("A0C1853B-5C40-4B15-8766-3CF1C58F985A"); // Microsoft-Windows-PowerShell

    private const int ScriptBlockLoggingEventId = 4104;

    public PowerShellThreatMonitor(
        IDetectionEngine detectionEngine,
        ILogger<PowerShellThreatMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== PowerShell Threat Monitor starting ===");

        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);

        // Try ETW-based monitoring first (requires elevation)
        bool etwAvailable = TryStartEtwSession();

        if (etwAvailable)
        {
            _logger.LogInformation("PowerShellThreatMonitor: ETW script-block logging active");

            // ETW session runs on its own thread; we just wait for cancellation
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
                    PruneAlertCache();
                }
                catch (OperationCanceledException) { break; }
            }
        }
        else
        {
            _logger.LogWarning("PowerShellThreatMonitor: ETW unavailable, falling back to command-line scanning");

            // Fallback: scan running PowerShell processes for suspicious command lines
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await ScanPowerShellProcessesAsync(stoppingToken);
                    PruneAlertCache();
                    await Task.Delay(FallbackScanInterval, stoppingToken);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "PowerShellThreatMonitor: Scan error");
                    await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
                }
            }
        }

        // Cleanup ETW session
        try
        {
            _etwSession?.Stop();
            _etwSession?.Dispose();
        }
        catch { }
    }

    private bool TryStartEtwSession()
    {
        try
        {
            _etwSession = new TraceEventSession("WindowsSentinel-PowerShell");
            _etwSession.EnableProvider(PowerShellProviderGuid, TraceEventLevel.Verbose, ulong.MaxValue);

            // Process events on a background thread
            _etwSession.Source.Dynamic.All += OnEtwEvent;

            Task.Run(() =>
            {
                try { _etwSession.Source.Process(); }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "PowerShellThreatMonitor: ETW session ended");
                }
            });

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "PowerShellThreatMonitor: Failed to start ETW session");
            _etwSession?.Dispose();
            _etwSession = null;
            return false;
        }
    }

    private void OnEtwEvent(TraceEvent eventData)
    {
        try
        {
            // We care about Event ID 4104 (ScriptBlockLogging)
            if ((int)eventData.ID != ScriptBlockLoggingEventId) return;

            // Extract the script block text
            var scriptBlock = eventData.PayloadByName("ScriptBlockText")?.ToString();
            if (string.IsNullOrWhiteSpace(scriptBlock)) return;

            var processId = eventData.ProcessID;
            var processName = "powershell"; // ETW doesn't always give us the name

            try
            {
                using var proc = Process.GetProcessById(processId);
                processName = proc.ProcessName;
            }
            catch { }

            // Analyze the script block
            _ = Task.Run(async () =>
            {
                await AnalyzeScriptBlockAsync(scriptBlock, processName, processId, CancellationToken.None);
            });
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "PowerShellThreatMonitor: Error processing ETW event");
        }
    }

    private async Task AnalyzeScriptBlockAsync(string scriptBlock, string processName, int processId, CancellationToken ct)
    {
        var scriptLower = scriptBlock.ToLowerInvariant();

        // Check critical patterns first
        foreach (var (pattern, description, confidence) in CriticalPatterns)
        {
            if (scriptLower.Contains(pattern))
            {
                var alertKey = $"crit|{processId}|{pattern}";
                if (!ShouldAlert(alertKey)) return;

                _logger.LogCritical(
                    "POWERSHELL THREAT: CRITICAL — {Description} in PID {Pid}",
                    description, processId);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = $"PowerShell Threat: {description}",
                    Evidence = $"Critical PowerShell threat pattern detected in process '{processName}' " +
                              $"(PID {processId}): {description}. " +
                              $"Script fragment: {Truncate(scriptBlock, 500)}",
                    Reasoning = "This PowerShell script block contains patterns associated with active attacks: " +
                               "AMSI/ETW bypass (blinding security tools), credential theft (Mimikatz, Kerberoast), " +
                               "or defense evasion. These are NOT used by legitimate software and indicate " +
                               "an attacker has code execution and is escalating their access.",
                    Confidence = confidence,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = processName,
                    ProcessId = processId,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["pattern"] = pattern,
                        ["description"] = description,
                        ["script_fragment"] = Truncate(scriptBlock, 1000),
                        ["technique"] = "T1059.001 - PowerShell"
                    }
                }, ct);
                return; // One alert per script block
            }
        }

        // Check high-severity patterns
        foreach (var (pattern, description, confidence) in HighPatterns)
        {
            if (scriptLower.Contains(pattern))
            {
                var alertKey = $"high|{processId}|{pattern}";
                if (!ShouldAlert(alertKey)) return;

                _logger.LogWarning(
                    "POWERSHELL THREAT: HIGH — {Description} in PID {Pid}",
                    description, processId);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = $"PowerShell Threat: {description}",
                    Evidence = $"High-severity PowerShell pattern in '{processName}' (PID {processId}): " +
                              $"{description}. Script fragment: {Truncate(scriptBlock, 500)}",
                    Reasoning = "This PowerShell script block contains patterns used in offensive operations: " +
                               "download cradles (staging malware), reflective loading (fileless execution), " +
                               "lateral movement tools, or persistence mechanisms. While some patterns have " +
                               "edge-case legitimate uses, the combination with other signals confirms malice.",
                    Confidence = confidence,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = processName,
                    ProcessId = processId,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["pattern"] = pattern,
                        ["description"] = description,
                        ["script_fragment"] = Truncate(scriptBlock, 1000),
                        ["technique"] = "T1059.001 - PowerShell"
                    }
                }, ct);
                return;
            }
        }

        // Check medium-severity patterns (Tier2 — log only)
        foreach (var (pattern, description, confidence) in MediumPatterns)
        {
            if (scriptLower.Contains(pattern))
            {
                var alertKey = $"med|{processId}|{pattern}";
                if (!ShouldAlert(alertKey)) return;

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = $"PowerShell Suspicious: {description}",
                    Evidence = $"Suspicious PowerShell pattern in '{processName}' (PID {processId}): " +
                              $"{description}. Script fragment: {Truncate(scriptBlock, 300)}",
                    Reasoning = "This PowerShell activity matches patterns commonly seen in attacks but may " +
                               "also have legitimate uses. Logged as a corroborating indicator — if combined " +
                               "with other detections (injection, credential access, network anomalies), " +
                               "confidence increases significantly.",
                    Confidence = confidence,
                    Tier = DetectionTier.Tier2Indicator,
                    ProcessName = processName,
                    ProcessId = processId,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["pattern"] = pattern,
                        ["description"] = description,
                        ["script_fragment"] = Truncate(scriptBlock, 500),
                        ["technique"] = "T1059.001 - PowerShell"
                    }
                }, ct);
                return;
            }
        }
    }

    /// <summary>
    /// Fallback: scans running PowerShell processes' command lines when ETW is unavailable.
    /// Less comprehensive than script-block logging but catches encoded commands and obvious patterns.
    /// </summary>
    private async Task ScanPowerShellProcessesAsync(CancellationToken ct)
    {
        var psProcessNames = new[] { "powershell", "pwsh" };
        var processes = Process.GetProcesses();

        foreach (var process in processes)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                if (!psProcessNames.Contains(process.ProcessName, StringComparer.OrdinalIgnoreCase))
                    continue;

                if (process.Id <= 4 || process.Id == Environment.ProcessId) continue;

                var cmdLine = GetProcessCommandLine(process.Id);
                if (string.IsNullOrWhiteSpace(cmdLine)) continue;

                // Analyze the command line as if it were a script block
                await AnalyzeScriptBlockAsync(cmdLine, process.ProcessName, process.Id, ct);
            }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
            finally
            {
                process.Dispose();
            }
        }
    }

    private bool ShouldAlert(string key)
    {
        if (_alertedKeys.TryGetValue(key, out var last))
        {
            if (DateTimeOffset.UtcNow - last < AlertCooldown)
                return false;
        }
        _alertedKeys[key] = DateTimeOffset.UtcNow;
        return true;
    }

    private void PruneAlertCache()
    {
        var cutoff = DateTimeOffset.UtcNow - AlertCooldown;
        foreach (var kv in _alertedKeys)
        {
            if (kv.Value < cutoff)
                _alertedKeys.TryRemove(kv.Key, out _);
        }
    }

    private static string Truncate(string text, int maxLength)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= maxLength ? text : text[..maxLength] + "...";
    }

    private static string? GetProcessCommandLine(int pid)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            using var results = searcher.Get();
            foreach (var obj in results)
                return obj["CommandLine"]?.ToString();
        }
        catch { }
        return null;
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            _etwSession?.Stop();
            _etwSession?.Dispose();
        }
        catch { }

        await base.StopAsync(cancellationToken);
    }
}
