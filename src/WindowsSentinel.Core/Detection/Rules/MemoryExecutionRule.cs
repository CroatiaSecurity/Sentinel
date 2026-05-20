using System.Diagnostics;
using System.Management;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Detects fileless malware execution and in-memory payload delivery.
/// Ported from GIDR's MemoryExecutionDetection with security hardening.
/// 
/// Catches: reflective DLL injection, process hollowing from memory,
/// .NET in-memory loading, PowerShell download-cradle execution,
/// and "download + execute in memory" techniques.
/// </summary>
public sealed class MemoryExecutionRule : IDetectionRule
{
    public string Name => "Fileless / In-Memory Execution";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    private readonly ILogger<MemoryExecutionRule> _logger;
    private readonly ProcessValidator _processValidator;

    // Track processed PIDs to avoid duplicate detections
    private readonly HashSet<string> _processedPids = new();
    private readonly object _lock = new();

    // Suspicious parents for memory execution (office docs, browsers, scripts)
    private static readonly HashSet<string> SuspiciousParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mshta.exe",
        "wscript.exe", "cscript.exe", "msedge.exe", "chrome.exe", "firefox.exe",
        "iexplore.exe", "acrord32.exe", "acrobat.exe", "explorer.exe"
    };

    // Patterns indicating in-memory execution techniques
    private static readonly string[] SuspiciousCmdPatterns = new[]
    {
        "invoke-expression", "iex", "downloadstring", "downloadfile",
        "frombase64string", "tobase64string", "compressed", "gzipstream",
        "memorystream", "reflection.assembly", "load(", "::load(",
        "virtualalloc", "virtualprotect", "createremotethread",
        "writeprocessmemory", "readprocessmemory", "rtlmovememory",
        "memset", "copy(", "invoke-shellcode", "invoke-mimikatz",
        "invoke-bloodhound", "amsibypass", "etwbypass", "patch-amsi",
        "rc4", "aes", "decrypt", "decodestring", "encodedcommand",
        "enc ", "-enc ", "/enc ", "bypass", "noprofile", "windowstyle hidden",
        "noexit", "executionpolicy bypass", "ep bypass"
    };

    // .NET JIT indicators for in-memory loading
    private static readonly string[] DotNetJitModules = new[]
    {
        "clrjit.dll", "mscorlib.ni.dll", "system.management.automation.ni.dll"
    };

    public MemoryExecutionRule(ILogger<MemoryExecutionRule> logger, ProcessValidator processValidator)
    {
        _logger = logger;
        _processValidator = processValidator;
    }

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;
        if (proc.EventType != "ProcessStart") return null;

        // Skip system processes
        if (proc.ProcessId <= 4) return null;

        // Skip already processed
        string cacheKey = $"{proc.ProcessId}:{proc.ProcessName}:{DateTime.UtcNow:yyyyMMddHH}";
        lock (_lock)
        {
            if (_processedPids.Contains(cacheKey)) return null;
        }

        try
        {
            // SECURITY: Validate PID before WMI query
            if (!_processValidator.IsValidPid(proc.ProcessId))
            {
                _logger.LogDebug("Skipping memory exec check for invalid PID {Pid}", proc.ProcessId);
                return null;
            }

            // Check 1: Fileless execution (no executable path)
            var detection = CheckFilelessExecution(proc);
            if (detection != null)
            {
                lock (_lock) { _processedPids.Add(cacheKey); }
                return detection;
            }

            // Check 2: Download cradle patterns
            detection = CheckDownloadCradle(proc);
            if (detection != null)
            {
                lock (_lock) { _processedPids.Add(cacheKey); }
                return detection;
            }

            // Check 3: .NET in-memory loading
            detection = CheckDotNetMemoryLoad(proc);
            if (detection != null)
            {
                lock (_lock) { _processedPids.Add(cacheKey); }
                return detection;
            }

            // Check 4: Suspicious parent spawning script/encoded command
            detection = CheckSuspiciousParentSpawn(proc);
            if (detection != null)
            {
                lock (_lock) { _processedPids.Add(cacheKey); }
                return detection;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Memory execution detection failed for {Process} PID {Pid}",
                proc.ProcessName, proc.ProcessId);
        }

        return null;
    }

    /// <summary>
    /// Check 1: Process with missing or suspicious executable path
    /// </summary>
    private DetectionEvent? CheckFilelessExecution(ProcessTelemetry proc)
    {
        // Check if ImagePath is missing/empty - potential hollowed/injected process
        string? imagePath = proc.ImagePath;
        if (string.IsNullOrEmpty(imagePath) || imagePath == "N/A")
        {
            // Fallback: try to resolve the path natively before firing a detection
            // to avoid false positives due to delayed ETW image path resolution.
            imagePath = _processValidator.TryGetProcessImagePath(proc.ProcessId);
            
            if (string.IsNullOrEmpty(imagePath))
            {
                return new DetectionEvent
            {
                RuleName = Name,
                Evidence = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) has no executable path - " +
                    "potentially injected or hollowed process executing from memory.",
                Reasoning = "Legitimate processes always have a backing executable file on disk. " +
                    "A missing executable path indicates the process may have been created through " +
                    "process hollowing, injection, or is running purely from memory (fileless execution). " +
                    "This is a common technique used by advanced malware to evade file-based detection.",
                Confidence = 0.88,
                Tier = Tier,
                ProcessName = proc.ProcessName,
                ProcessId = proc.ProcessId,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new()
                {
                    ["DetectionType"] = "FilelessExecution",
                    ["ImagePath"] = proc.ImagePath ?? "null",
                    ["ResolvedImagePath"] = imagePath ?? "null",
                    ["CommandLine"] = proc.CommandLine?.Substring(0, Math.Min(proc.CommandLine?.Length ?? 0, 500)) ?? "",
                }
            };
            }
        }

        return null;
    }

    /// <summary>
    /// Check 2: PowerShell/cmd download cradle patterns
    /// </summary>
    private DetectionEvent? CheckDownloadCradle(ProcessTelemetry proc)
    {
        string cmdLine = (proc.CommandLine ?? "").ToLowerInvariant();
        
        // Check for download cradle patterns
        bool hasDownloadPattern = cmdLine.Contains("downloadstring") || 
                                  cmdLine.Contains("downloadfile") ||
                                  cmdLine.Contains("invoke-webrequest") ||
                                  cmdLine.Contains("wget") ||
                                  cmdLine.Contains("curl");

        bool hasEncodePattern = cmdLine.Contains("frombase64") ||
                                cmdLine.Contains("compressed") ||
                                cmdLine.Contains("gzip") ||
                                cmdLine.Contains("-enc") ||
                                cmdLine.Contains("encodedcommand");

        bool hasExecPattern = cmdLine.Contains("invoke-expression") ||
                              cmdLine.Contains("iex") ||
                              cmdLine.Contains("reflection.assembly") ||
                              cmdLine.Contains("::load(");

        // Download + execute pattern
        if (hasDownloadPattern && (hasEncodePattern || hasExecPattern))
        {
            string evidence = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) detected with " +
                "download cradle pattern: downloads content from remote source and executes it in memory.";

            return new DetectionEvent
            {
                RuleName = Name,
                Evidence = evidence,
                Reasoning = "Download cradles are a common fileless malware technique where a script " +
                    "(PowerShell, cmd, or wscript) downloads a payload from a remote URL, often " +
                    "encoded or compressed, and executes it directly in memory without writing to disk. " +
                    "This evades traditional antivirus file scanning. The combination of download " +
                    "functions with encoding/decoding and execution commands is a high-confidence indicator.",
                Confidence = 0.91,
                Tier = Tier,
                ProcessName = proc.ProcessName,
                ProcessId = proc.ProcessId,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new()
                {
                    ["DetectionType"] = "DownloadCradle",
                    ["HasDownloadPattern"] = hasDownloadPattern.ToString(),
                    ["HasEncodePattern"] = hasEncodePattern.ToString(),
                    ["HasExecPattern"] = hasExecPattern.ToString(),
                    ["CommandLine"] = proc.CommandLine?.Substring(0, Math.Min(proc.CommandLine?.Length ?? 0, 500)) ?? ""
                }
            };
        }

        return null;
    }

    /// <summary>
    /// Check 3: .NET in-memory assembly loading
    /// </summary>
    private DetectionEvent? CheckDotNetMemoryLoad(ProcessTelemetry proc)
    {
        // Check if process has .NET JIT modules loaded
        bool hasJitModule = false;
        try
        {
            using var process = Process.GetProcessById(proc.ProcessId);
            foreach (ProcessModule module in process.Modules)
            {
                string modName = Path.GetFileName(module.FileName ?? "").ToLowerInvariant();
                if (DotNetJitModules.Any(jit => modName.Contains(jit)))
                {
                    hasJitModule = true;
                    break;
                }
            }
        }
        catch { /* Ignore module enumeration errors */ }

        string cmdLine = (proc.CommandLine ?? "").ToLowerInvariant();
        bool hasLoadPattern = cmdLine.Contains("reflection.assembly") ||
                              cmdLine.Contains("::load(") ||
                              cmdLine.Contains("load(") && cmdLine.Contains("byte");

        // .NET loading indicators
        if (hasJitModule && hasLoadPattern)
        {
            return new DetectionEvent
            {
                RuleName = Name,
                Evidence = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) loading .NET assembly in memory " +
                    "via Reflection.Assembly.Load with JIT compiler active.",
                Reasoning = "Loading .NET assemblies directly from byte arrays in memory is a technique " +
                    "used by fileless malware to execute code without writing an assembly to disk. " +
                    "The presence of .NET JIT compilation combined with Assembly.Load patterns indicates " +
                    "potential in-memory execution of a dynamically loaded payload.",
                Confidence = 0.85,
                Tier = Tier,
                ProcessName = proc.ProcessName,
                ProcessId = proc.ProcessId,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new()
                {
                    ["DetectionType"] = "DotNetMemoryLoad",
                    ["HasJitModule"] = hasJitModule.ToString(),
                    ["CommandLine"] = proc.CommandLine?.Substring(0, Math.Min(proc.CommandLine?.Length ?? 0, 500)) ?? ""
                }
            };
        }

        return null;
    }

    /// <summary>
    /// Check 4: Suspicious parent spawning encoded/obfuscated command
    /// </summary>
    private DetectionEvent? CheckSuspiciousParentSpawn(ProcessTelemetry proc)
    {
        // Check if parent is suspicious (office, browser, etc. spawning scripts)
        if (string.IsNullOrEmpty(proc.ParentProcessName))
            return null;

        bool isSuspiciousParent = SuspiciousParents.Contains(proc.ParentProcessName);
        bool isScriptProcess = proc.ProcessName.Contains("powershell") ||
                               proc.ProcessName.Contains("pwsh") ||
                               proc.ProcessName.Contains("cmd") ||
                               proc.ProcessName.Contains("wscript") ||
                               proc.ProcessName.Contains("cscript") ||
                               proc.ProcessName.Contains("mshta");

        if (!isSuspiciousParent || !isScriptProcess)
            return null;

        // Check for encoded/obfuscated command in script
        string cmdLine = (proc.CommandLine ?? "").ToLowerInvariant();
        bool isEncoded = cmdLine.Contains("-enc") ||
                         cmdLine.Contains("encodedcommand") ||
                         cmdLine.Contains("frombase64") ||
                         cmdLine.Contains("bypass") ||
                         cmdLine.Contains("windowstyle hidden");

        if (isEncoded)
        {
            return new DetectionEvent
            {
                RuleName = Name,
                Evidence = $"Suspicious parent '{proc.ParentProcessName}' spawning encoded script " +
                    $"'{proc.ProcessName}' (PID {proc.ProcessId}) with obfuscation indicators.",
                Reasoning = "Office documents, browsers, or other applications spawning encoded or " +
                    "obfuscated PowerShell/cmd commands is a common malware delivery technique. " +
                    "The parent process (often exploited via macro or vulnerability) launches a " +
                    "script child with encoded commands to hide the malicious payload from inspection. " +
                    "This is a high-confidence indicator of exploitation or malicious document activity.",
                Confidence = 0.93,
                Tier = Tier,
                ProcessName = proc.ProcessName,
                ProcessId = proc.ProcessId,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new()
                {
                    ["DetectionType"] = "SuspiciousParentSpawn",
                    ["ParentProcessName"] = proc.ParentProcessName,
                    ["ParentProcessId"] = proc.ParentProcessId.ToString(),
                    ["IsEncoded"] = isEncoded.ToString(),
                    ["CommandLine"] = proc.CommandLine?.Substring(0, Math.Min(proc.CommandLine?.Length ?? 0, 500)) ?? ""
                }
            };
        }

        return null;
    }
}

