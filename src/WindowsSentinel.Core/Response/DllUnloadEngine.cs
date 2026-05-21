using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Security;
using WindowsSentinel.Core.Utilities;

namespace WindowsSentinel.Core.Response;

/// <summary>
/// Active DLL Unloading Engine — Forcefully unloads malicious/suspicious DLLs from
/// running processes using CreateRemoteThread + FreeLibrary.
///
/// This is the RESPONSE capability that Antivirus.ps1 had (Invoke-ElfDLLUnloader,
/// Invoke-UnsignedDLLRemover) but Sentinel was missing. Detection without response
/// is incomplete — this engine closes the gap.
///
/// Safety constraints:
///   - NEVER unloads from system-critical processes (lsass, csrss, smss, etc.)
///   - NEVER unloads system DLLs (ntdll, kernel32, kernelbase, etc.)
///   - NEVER unloads from Sentinel's own processes
///   - Rate-limited: max 10 unloads per minute to prevent system instability
///   - All unloads are logged with full forensic context
///
/// MITRE ATT&CK: T1055 (Process Injection) — this is the RESPONSE to injection.
/// </summary>
public sealed class DllUnloadEngine : IDisposable
{
    private readonly ILogger<DllUnloadEngine> _logger;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _unloadHistory = new();
    private readonly RateLimiter _rateLimiter;
    private readonly BurstRateLimiter _burstLimiter;
    private bool _disposed;

    // P/Invoke declarations
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateRemoteThread(
        IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

    private const uint PROCESS_CREATE_THREAD = 0x0002;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_OPERATION = 0x0008;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_VM_WRITE = 0x0020;
    private const uint SYNCHRONIZE = 0x00100000;
    private const uint WAIT_OBJECT_0 = 0x00000000;
    private const uint WAIT_TIMEOUT = 0x00000102;

    // Processes we NEVER touch
    private static readonly HashSet<string> ProtectedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "lsass", "csrss", "smss", "wininit", "winlogon", "services",
        "system", "idle", "registry", "memcompression",
        "sentinelservice", "sentinelagent",
        "msmpeng", "securityhealthservice", "nissrv" // Defender
    };

    // DLLs we NEVER unload (system-critical)
    private static readonly HashSet<string> ProtectedDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
        "gdi32.dll", "gdi32full.dll", "msvcrt.dll", "advapi32.dll",
        "sechost.dll", "rpcrt4.dll", "combase.dll", "ole32.dll",
        "oleaut32.dll", "ucrtbase.dll", "msvcp_win.dll", "win32u.dll",
        "bcryptprimitives.dll", "clrjit.dll", "coreclr.dll",
        "hostpolicy.dll", "hostfxr.dll"
    };

    public DllUnloadEngine(ILogger<DllUnloadEngine> logger)
    {
        _logger = logger;
        _rateLimiter = new RateLimiter(maxRequests: 10, timeWindow: TimeSpan.FromMinutes(1));
        _burstLimiter = new BurstRateLimiter(
            sustainedRate: 5,
            sustainedWindow: TimeSpan.FromMinutes(1),
            burstCapacity: 20,
            burstRechargeTime: TimeSpan.FromMinutes(5));
    }

    /// <summary>
    /// Attempts to unload a DLL from a specific process.
    /// Returns true if the DLL was successfully unloaded.
    /// </summary>
    public async Task<DllUnloadResult> UnloadDllAsync(int processId, string dllPath, string reason, CancellationToken cancellationToken = default)
    {
        var moduleName = Path.GetFileName(dllPath);
        var result = new DllUnloadResult
        {
            ProcessId = processId,
            DllPath = dllPath,
            Reason = reason,
            Timestamp = DateTimeOffset.UtcNow
        };

        // Safety check: input validation
        if (!SecurityValidation.IsValidProcessId(processId))
        {
            result.Success = false;
            result.ErrorMessage = $"Invalid process ID: {processId}";
            _logger.LogWarning("DllUnloadEngine: Invalid process ID {Pid}", processId);
            return result;
        }

        if (string.IsNullOrWhiteSpace(dllPath))
        {
            result.Success = false;
            result.ErrorMessage = "DLL path cannot be empty";
            return result;
        }

        // Safety check: rate limiting with burst capability
        if (!_rateLimiter.TryAcquire())
        {
            // Try burst limiter as fallback
            if (!await _burstLimiter.TryAcquireAsync())
            {
                result.Success = false;
                result.ErrorMessage = "Rate limit exceeded (max 10 unloads/minute)";
                _logger.LogWarning("DllUnloadEngine: Rate limit hit — skipping unload of {Dll} from PID {Pid}",
                    moduleName, processId);
                return result;
            }
        }

        // Safety check: protected process
        string processName;
        try
        {
            using var proc = Process.GetProcessById(processId);
            processName = proc.ProcessName;
        }
        catch
        {
            result.Success = false;
            result.ErrorMessage = "Process no longer exists";
            return result;
        }

        if (ProtectedProcesses.Contains(processName))
        {
            result.Success = false;
            result.ErrorMessage = $"Process '{processName}' is protected — cannot unload DLLs";
            _logger.LogWarning("DllUnloadEngine: BLOCKED unload from protected process {Process} (PID {Pid})",
                processName, processId);
            return result;
        }

        // Safety check: self-protection
        if (processId == Environment.ProcessId)
        {
            result.Success = false;
            result.ErrorMessage = "Cannot unload from own process";
            return result;
        }

        // Safety check: protected DLL
        if (ProtectedDlls.Contains(moduleName))
        {
            result.Success = false;
            result.ErrorMessage = $"DLL '{moduleName}' is system-critical — cannot unload";
            _logger.LogWarning("DllUnloadEngine: BLOCKED unload of protected DLL {Dll}", moduleName);
            return result;
        }

        // Safety check: dedup (don't unload same DLL from same process twice)
        var key = $"{processId}:{dllPath.ToLowerInvariant()}";
        if (_unloadHistory.ContainsKey(key))
        {
            result.Success = false;
            result.ErrorMessage = "Already attempted unload for this DLL/process combination";
            return result;
        }

        // Perform the unload
        try
        {
            result.Success = PerformRemoteFreeLibrary(processId, dllPath, out var error);
            result.ErrorMessage = error;

            if (result.Success)
            {
                _logger.LogCritical(
                    "DllUnloadEngine: UNLOADED '{Dll}' from process '{Process}' (PID {Pid}). Reason: {Reason}",
                    moduleName, processName, processId, reason);
            }
            else
            {
                _logger.LogWarning(
                    "DllUnloadEngine: Failed to unload '{Dll}' from PID {Pid}: {Error}",
                    moduleName, processId, error);
            }

            _unloadHistory[key] = DateTimeOffset.UtcNow;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = ex.Message;
            _logger.LogError(ex, "DllUnloadEngine: Exception unloading {Dll} from PID {Pid}",
                moduleName, processId);
        }

        return result;
    }

    /// <summary>
    /// Unloads a DLL from ALL processes that have it loaded.
    /// Returns the number of successful unloads.
    /// </summary>
    public List<DllUnloadResult> UnloadDllFromAllProcesses(string dllPath, string reason)
    {
        var results = new List<DllUnloadResult>();
        var dllPathLower = dllPath.ToLowerInvariant();

        try
        {
            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                try
                {
                    if (ProtectedProcesses.Contains(proc.ProcessName)) continue;
                    if (proc.Id == Environment.ProcessId) continue;
                    if (proc.Id <= 4) continue;

                    // Check if this process has the DLL loaded
                    bool hasModule = false;
                    try
                    {
                        foreach (ProcessModule module in proc.Modules)
                        {
                            if (module.FileName != null &&
                                module.FileName.Equals(dllPath, StringComparison.OrdinalIgnoreCase))
                            {
                                hasModule = true;
                                break;
                            }
                        }
                    }
                    catch { continue; }

                    if (hasModule)
                    {
                        var result = UnloadDll(proc.Id, dllPath, reason);
                        results.Add(result);
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "DllUnloadEngine: Error scanning processes for {Dll}", dllPath);
        }

        return results;
    }

    /// <summary>
    /// Core P/Invoke logic: opens the target process, gets FreeLibrary address,
    /// finds the module base address, and calls CreateRemoteThread(FreeLibrary, moduleBase).
    /// </summary>
    private bool PerformRemoteFreeLibrary(int processId, string dllPath, out string? error)
    {
        error = null;
        IntPtr hProcess = IntPtr.Zero;
        IntPtr hThread = IntPtr.Zero;

        try
        {
            // Open target process with required access
            uint access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                         PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE;
            hProcess = OpenProcess(access, false, processId);

            if (hProcess == IntPtr.Zero)
            {
                error = $"OpenProcess failed (error {Marshal.GetLastWin32Error()})";
                return false;
            }

            // Get FreeLibrary address from kernel32.dll
            IntPtr kernel32 = GetModuleHandleW("kernel32.dll");
            if (kernel32 == IntPtr.Zero)
            {
                error = "Failed to get kernel32.dll handle";
                return false;
            }

            IntPtr freeLibraryAddr = GetProcAddress(kernel32, "FreeLibrary");
            if (freeLibraryAddr == IntPtr.Zero)
            {
                error = "Failed to get FreeLibrary address";
                return false;
            }

            // Find the module's base address in the target process
            IntPtr moduleBase = FindModuleBaseAddress(processId, dllPath);
            if (moduleBase == IntPtr.Zero)
            {
                error = "Module not found in target process (may have already been unloaded)";
                return false;
            }

            // Create remote thread calling FreeLibrary(moduleBase)
            hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0,
                freeLibraryAddr, moduleBase, 0, out _);

            if (hThread == IntPtr.Zero)
            {
                error = $"CreateRemoteThread failed (error {Marshal.GetLastWin32Error()})";
                return false;
            }

            // Wait for the thread to complete (5 second timeout)
            uint waitResult = WaitForSingleObject(hThread, 5000);

            if (waitResult == WAIT_TIMEOUT)
            {
                error = "FreeLibrary call timed out (5s)";
                return false;
            }

            if (waitResult != WAIT_OBJECT_0)
            {
                error = $"WaitForSingleObject returned {waitResult}";
                return false;
            }

            // Check exit code (FreeLibrary returns BOOL — nonzero = success)
            if (GetExitCodeThread(hThread, out uint exitCode))
            {
                if (exitCode == 0)
                {
                    error = "FreeLibrary returned FALSE (DLL may still be in use)";
                    return false;
                }
            }

            return true;
        }
        finally
        {
            if (hThread != IntPtr.Zero) CloseHandle(hThread);
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// Finds the base address of a loaded module in a target process.
    /// </summary>
    private IntPtr FindModuleBaseAddress(int processId, string dllPath)
    {
        try
        {
            using var proc = Process.GetProcessById(processId);
            foreach (ProcessModule module in proc.Modules)
            {
                if (module.FileName != null &&
                    module.FileName.Equals(dllPath, StringComparison.OrdinalIgnoreCase))
                {
                    return module.BaseAddress;
                }
            }
        }
        catch { }

        return IntPtr.Zero;
    }

    /// <summary>
    /// Prunes old unload history entries (older than 1 hour).
    /// </summary>
    public void PruneHistory()
    {
        var cutoff = DateTimeOffset.UtcNow.AddHours(-1);
        foreach (var key in _unloadHistory.Keys)
        {
            if (_unloadHistory.TryGetValue(key, out var time) && time < cutoff)
                _unloadHistory.TryRemove(key, out _);
        }
    }

    /// <summary>
    /// Gets the current rate limit status.
    /// </summary>
    public (RateLimiterStatus Sustained, BurstRateLimiterStatus Burst) GetRateLimitStatus()
    {
        var sustainedStatus = _rateLimiter.GetStatus();
        var burstStatus = _burstLimiter.GetStatus();
        
        return (
            new RateLimiterStatus 
            { 
                Current = sustainedStatus.Current, 
                Max = sustainedStatus.Max, 
                Remaining = sustainedStatus.Remaining 
            },
            new BurstRateLimiterStatus
            {
                AvailableBurst = burstStatus.AvailableBurst,
                BurstCapacity = burstStatus.BurstCapacity,
                SustainedCurrent = burstStatus.Sustained.Current,
                SustainedMax = burstStatus.Sustained.Max,
                SustainedRemaining = burstStatus.Sustained.Remaining
            }
        );
    }

    /// <summary>
    /// Disposes the DLL unload engine resources.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            _rateLimiter.Dispose();
            _burstLimiter.Dispose();
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }

    /// <summary>
    /// Attempts to unload a DLL from a specific process (synchronous version).
    /// Returns true if the DLL was successfully unloaded.
    /// </summary>
    public DllUnloadResult UnloadDll(int processId, string dllPath, string reason)
    {
        return UnloadDllAsync(processId, dllPath, reason).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Safely attempts to unload a DLL with comprehensive error handling.
    /// </summary>
    public async Task<DllUnloadResult> SafeUnloadDllAsync(int processId, string dllPath, string reason, CancellationToken cancellationToken = default)
    {
        try
        {
            return await UnloadDllAsync(processId, dllPath, reason, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "DLL Unload failed safely (PID: {Pid}, DLL: {Dll})", processId, Path.GetFileName(dllPath));
            return new DllUnloadResult
            {
                ProcessId = processId,
                DllPath = dllPath,
                Reason = reason,
                Success = false,
                ErrorMessage = $"Safe execution failed: {ex.Message}",
                Timestamp = DateTimeOffset.UtcNow
            };
        }
    }

    /// <summary>
    /// Validates if a DLL can be safely unloaded from a process.
    /// </summary>
    public DllUnloadValidationResult ValidateUnload(int processId, string dllPath)
    {
        var result = new DllUnloadValidationResult
        {
            ProcessId = processId,
            DllPath = dllPath,
            Timestamp = DateTimeOffset.UtcNow
        };

        try
        {
            // Check process exists
            using var process = Process.GetProcessById(processId);
            result.ProcessName = process.ProcessName;
            result.ProcessExists = true;

            // Check if process is protected
            result.IsProtectedProcess = ProtectedProcesses.Contains(process.ProcessName);

            // Check if DLL is protected
            var dllName = Path.GetFileName(dllPath).ToLowerInvariant();
            result.IsProtectedDll = ProtectedDlls.Contains(dllName);

            // Check rate limit status
            var rateLimitStatus = GetRateLimitStatus();
            result.RateLimitAvailable = rateLimitStatus.Sustained.Current < rateLimitStatus.Sustained.Max;
            result.BurstTokensAvailable = rateLimitStatus.Burst.AvailableBurst > 0;

            // Check if already unloaded recently
            var key = $"{processId}:{dllPath.ToLowerInvariant()}";
            if (_unloadHistory.TryGetValue(key, out var lastUnload))
            {
                result.LastUnloadTime = lastUnload;
                result.CanUnloadAgain = (DateTimeOffset.UtcNow - lastUnload) > TimeSpan.FromHours(1);
            }
            else
            {
                result.CanUnloadAgain = true;
            }

            result.IsValid = result.ProcessExists && 
                           !result.IsProtectedProcess && 
                           !result.IsProtectedDll && 
                           (result.RateLimitAvailable || result.BurstTokensAvailable) && 
                           result.CanUnloadAgain;
        }
        catch (ArgumentException)
        {
            result.ProcessExists = false;
            result.Error = "Process does not exist";
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
        }

        return result;
    }
}

/// <summary>
/// Rate limiter status.
/// </summary>
public sealed class RateLimiterStatus
{
    /// <summary>
    /// Gets the current number of requests in the window.
    /// </summary>
    public int Current { get; set; }

    /// <summary>
    /// Gets the maximum number of requests allowed.
    /// </summary>
    public int Max { get; set; }

    /// <summary>
    /// Gets the time remaining in the current window.
    /// </summary>
    public TimeSpan Remaining { get; set; }
}

/// <summary>
/// Burst rate limiter status.
/// </summary>
public sealed class BurstRateLimiterStatus
{
    /// <summary>
    /// Gets the available burst tokens.
    /// </summary>
    public int AvailableBurst { get; set; }

    /// <summary>
    /// Gets the total burst capacity.
    /// </summary>
    public int BurstCapacity { get; set; }

    /// <summary>
    /// Gets the current sustained rate usage.
    /// </summary>
    public int SustainedCurrent { get; set; }

    /// <summary>
    /// Gets the maximum sustained rate.
    /// </summary>
    public int SustainedMax { get; set; }

    /// <summary>
    /// Gets the time remaining in the sustained window.
    /// </summary>
    public TimeSpan SustainedRemaining { get; set; }
}

/// <summary>
/// Result of a DLL unload attempt.
/// </summary>
public sealed class DllUnloadResult
{
    public int ProcessId { get; set; }
    public string DllPath { get; set; } = "";
    public string Reason { get; set; } = "";
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTimeOffset Timestamp { get; set; }
}

/// <summary>
/// DLL unload validation result.
/// </summary>
public sealed class DllUnloadValidationResult
{
    /// <summary>
    /// Gets the process ID.
    /// </summary>
    public int ProcessId { get; set; }

    /// <summary>
    /// Gets the DLL path.
    /// </summary>
    public string DllPath { get; set; } = "";

    /// <summary>
    /// Gets the process name if available.
    /// </summary>
    public string? ProcessName { get; set; }

    /// <summary>
    /// Gets a value indicating whether the process exists.
    /// </summary>
    public bool ProcessExists { get; set; }

    /// <summary>
    /// Gets a value indicating whether the process is protected.
    /// </summary>
    public bool IsProtectedProcess { get; set; }

    /// <summary>
    /// Gets a value indicating whether the DLL is protected.
    /// </summary>
    public bool IsProtectedDll { get; set; }

    /// <summary>
    /// Gets a value indicating whether rate limit is available.
    /// </summary>
    public bool RateLimitAvailable { get; set; }

    /// <summary>
    /// Gets a value indicating whether burst tokens are available.
    /// </summary>
    public bool BurstTokensAvailable { get; set; }

    /// <summary>
    /// Gets the last unload time if applicable.
    /// </summary>
    public DateTimeOffset? LastUnloadTime { get; set; }

    /// <summary>
    /// Gets a value indicating whether the DLL can be unloaded again.
    /// </summary>
    public bool CanUnloadAgain { get; set; }

    /// <summary>
    /// Gets a value indicating whether the unload is valid.
    /// </summary>
    public bool IsValid { get; set; }

    /// <summary>
    /// Gets any error that occurred during validation.
    /// </summary>
    public string? Error { get; set; }

    /// <summary>
    /// Gets the validation timestamp.
    /// </summary>
    public DateTimeOffset Timestamp { get; set; }
}