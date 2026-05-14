using System.Diagnostics;
using System.Management;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Detects DLL hijacking, side-loading, and module integrity violations.
/// Ported from GIDR's ModuleValidationDetection with security hardening.
/// 
/// Detects when a process loads a DLL from an unexpected location, or when an
/// unsigned DLL is loaded into a signed process (potential side-loading attack).
/// </summary>
public sealed class ModuleValidationRule : IDetectionRule
{
    public string Name => "DLL Hijacking / Module Integrity";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    private readonly ILogger<ModuleValidationRule> _logger;
    private readonly ProcessValidator _processValidator;

    // Rate limiting per process
    private readonly Dictionary<int, DateTime> _lastCheck = new();
    private readonly object _lock = new();

    // Known vulnerable/sideloaded DLLs commonly abused
    private static readonly HashSet<string> CommonlySideloadedDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "d3d11.dll", "d3d12.dll", "dxgi.dll", "version.dll", "winmm.dll",
        "winhttp.dll", "wininet.dll", "ws2_32.dll", "msimg32.dll",
        "gdiplus.dll", "shell32.dll", "shlwapi.dll", "ole32.dll",
        "oleaut32.dll", "comctl32.dll", "comdlg32.dll", "usp10.dll",
        "dbghelp.dll", "dbgcore.dll", "symsrv.dll", "srcsrv.dll"
    };

    // Known legitimate system DLL paths
    private static readonly string[] SystemDllPaths = new[]
    {
        @"C:\Windows\System32",
        @"C:\Windows\SysWOW64",
        @"C:\Windows\WinSxS"
    };

    public ModuleValidationRule(ILogger<ModuleValidationRule> logger, ProcessValidator processValidator)
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

        // Rate limit: check each process max once per 5 minutes
        lock (_lock)
        {
            if (_lastCheck.TryGetValue(proc.ProcessId, out var lastTime))
            {
                if ((DateTime.UtcNow - lastTime).TotalMinutes < 5)
                    return null;
            }
            _lastCheck[proc.ProcessId] = DateTime.UtcNow;
        }

        try
        {
            // SECURITY: Validate PID before module enumeration
            if (!_processValidator.IsValidPid(proc.ProcessId))
            {
                _logger.LogDebug("Skipping module validation for invalid PID {Pid}", proc.ProcessId);
                return null;
            }

            // Validate process is still running
            if (!IsProcessRunningSafe(proc.ProcessId))
                return null;

            // Check for suspicious module loads
            var detection = CheckSuspiciousModuleLoads(proc);
            if (detection != null) return detection;

            // Check for unsigned DLL in signed process
            detection = CheckUnsignedDllInSignedProcess(proc);
            if (detection != null) return detection;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Module validation failed for {Process} PID {Pid}",
                proc.ProcessName, proc.ProcessId);
        }

        return null;
    }

    /// <summary>
    /// Check 1: DLL loaded from suspicious location (not system32 or app directory)
    /// </summary>
    private DetectionEvent? CheckSuspiciousModuleLoads(ProcessTelemetry proc)
    {
        try
        {
            using var process = Process.GetProcessById(proc.ProcessId);
            string processDir = Path.GetDirectoryName(proc.ImagePath ?? "") ?? "";

            foreach (ProcessModule module in process.Modules)
            {
                string modulePath = module.FileName ?? "";
                string moduleName = Path.GetFileName(modulePath);

                // Skip if we can't get path
                if (string.IsNullOrEmpty(modulePath)) continue;

                // Check for commonly sideloaded DLLs in unusual locations
                if (CommonlySideloadedDlls.Contains(moduleName))
                {
                    // Check if loaded from expected system location
                    bool isSystemLocation = SystemDllPaths.Any(sysPath =>
                        modulePath.StartsWith(sysPath, StringComparison.OrdinalIgnoreCase));

                    // Check if loaded from current directory (hijacking indicator)
                    bool isCurrentDir = modulePath.StartsWith(processDir, StringComparison.OrdinalIgnoreCase) &&
                                       !SystemDllPaths.Any(sysPath =>
                                           processDir.StartsWith(sysPath, StringComparison.OrdinalIgnoreCase));

                    if (!isSystemLocation && isCurrentDir)
                    {
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            Evidence = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) loaded " +
                                $"'{moduleName}' from current directory '{processDir}' instead of " +
                                "system location - potential DLL hijacking.",
                            Reasoning = "DLL hijacking (also called DLL side-loading) is an attack where " +
                                "malware places a malicious DLL with the same name as a legitimate system DLL " +
                                "in the application's directory. Windows loads the DLL from the application " +
                                "directory before searching system paths. This is a common technique used " +
                                "by APTs and malware to inject code into legitimate signed processes.",
                            Confidence = 0.89,
                            Tier = Tier,
                            ProcessName = proc.ProcessName,
                            ProcessId = proc.ProcessId,
                            Timestamp = DateTimeOffset.UtcNow,
                            Metadata = new()
                            {
                                ["DetectionType"] = "DllHijacking",
                                ["ModuleName"] = moduleName,
                                ["ModulePath"] = modulePath,
                                ["ProcessDirectory"] = processDir,
                                ["ExpectedLocation"] = @"C:\Windows\System32\" + moduleName
                            }
                        };
                    }
                }

                // Check for DLLs loaded from temp directories (highly suspicious)
                string lowerPath = modulePath.ToLowerInvariant();
                if (lowerPath.Contains("\\temp\\") ||
                    lowerPath.Contains("\\tmp\\") ||
                    lowerPath.Contains(@"\appdata\local\temp") ||
                    lowerPath.Contains(@"\windows\temp"))
                {
                    return new DetectionEvent
                    {
                        RuleName = Name,
                        Evidence = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) loaded " +
                            $"'{moduleName}' from temporary directory '{modulePath}'.",
                        Reasoning = "Legitimate applications do not load DLLs from temporary directories. " +
                            "Loading a DLL from %TEMP% or Windows\\Temp is a strong indicator of malware " +
                            "that extracted and loaded a payload to a temp location. This is commonly " +
                            "used by downloaders, droppers, and fileless malware stages.",
                        Confidence = 0.94,
                        Tier = Tier,
                        ProcessName = proc.ProcessName,
                        ProcessId = proc.ProcessId,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new()
                        {
                            ["DetectionType"] = "DllFromTemp",
                            ["ModuleName"] = moduleName,
                            ["ModulePath"] = modulePath
                        }
                    };
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Module load check failed for PID {Pid}", proc.ProcessId);
        }

        return null;
    }

    /// <summary>
    /// Check 2: Unsigned DLL loaded into a signed process
    /// </summary>
    private DetectionEvent? CheckUnsignedDllInSignedProcess(ProcessTelemetry proc)
    {
        try
        {
            // First check if main process executable is signed
            if (string.IsNullOrEmpty(proc.ImagePath) || !File.Exists(proc.ImagePath))
                return null;

            bool isProcessSigned = IsFileDigitallySigned(proc.ImagePath);
            if (!isProcessSigned)
                return null; // Can't detect side-loading if main process isn't signed

            using var process = Process.GetProcessById(proc.ProcessId);
            int unsignedDllCount = 0;
            string firstUnsignedDll = "";

            foreach (ProcessModule module in process.Modules)
            {
                string modulePath = module.FileName ?? "";
                if (string.IsNullOrEmpty(modulePath) || !File.Exists(modulePath))
                    continue;

                // Skip system DLLs (optimization)
                if (SystemDllPaths.Any(sysPath =>
                    modulePath.StartsWith(sysPath, StringComparison.OrdinalIgnoreCase)))
                    continue;

                // Check if module is signed
                if (!IsFileDigitallySigned(modulePath))
                {
                    unsignedDllCount++;
                    if (string.IsNullOrEmpty(firstUnsignedDll))
                        firstUnsignedDll = Path.GetFileName(modulePath);
                }
            }

            // Flag if multiple unsigned DLLs in signed process
            if (unsignedDllCount >= 2)
            {
                return new DetectionEvent
                {
                    RuleName = Name,
                    Evidence = $"Signed process '{proc.ProcessName}' (PID {proc.ProcessId}) loaded " +
                        $"{unsignedDllCount} unsigned/untrusted DLLs (including '{firstUnsignedDll}').",
                    Reasoning = "A digitally signed process loading multiple unsigned DLLs is a potential " +
                        "DLL side-loading attack. Attackers often use a legitimate signed application " +
                        "(like a Microsoft or vendor tool) to host their malicious unsigned payload DLLs, " +
                        "effectively hiding behind the signed parent process's reputation. This technique " +
                        "bypasses application whitelisting and appears as legitimate signed code in logs.",
                    Confidence = 0.82,
                    Tier = Tier,
                    ProcessName = proc.ProcessName,
                    ProcessId = proc.ProcessId,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new()
                    {
                        ["DetectionType"] = "UnsignedDllInSignedProcess",
                        ["UnsignedDllCount"] = unsignedDllCount.ToString(),
                        ["FirstUnsignedDll"] = firstUnsignedDll,
                        ["ProcessSigned"] = isProcessSigned.ToString()
                    }
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Signature check failed for PID {Pid}", proc.ProcessId);
        }

        return null;
    }

    /// <summary>
    /// SECURITY: Safely check if a file is digitally signed
    /// </summary>
    private bool IsFileDigitallySigned(string filePath)
    {
        try
        {
            // Validate path first
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return false;

            // Check for path traversal
            var fullPath = Path.GetFullPath(filePath);
            if (!fullPath.StartsWith(@"C:\", StringComparison.OrdinalIgnoreCase) &&
                !fullPath.StartsWith(@"D:\", StringComparison.OrdinalIgnoreCase) &&
                !fullPath.StartsWith(@"E:\", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var signer = X509Certificate.CreateFromSignedFile(filePath);
            return signer != null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// SECURITY: Safely check if process is still running
    /// </summary>
    private bool IsProcessRunningSafe(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return !proc.HasExited;
        }
        catch
        {
            return false;
        }
    }
}
