using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

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
public sealed class DllUnloadEngine
{
    private readonly ILogger<DllUnloadEngine> _logger;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _unloadHistory = new();
    private int _unloadsThisMinute;
    private DateTimeOffset _minuteStart = DateTimeOffset.UtcNow;
    private const int MaxUnloadsPerMinute = 10;

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
    }

    /// <summary>
    /// Attempts to unload a DLL from a specific process.
    /// Returns true if the DLL was successfully unloaded.
    /// </summary>
    public DllUnloadResult UnloadDll(int processId, string dllPath, string reason)
    {
        var moduleName = Path.GetFileName(dllPath);
        var result = new DllUnloadResult
        {
            ProcessId = processId,
            DllPath = dllPath,
            Reason = reason,
            Timestamp = DateTimeOffset.UtcNow
        };

        // Safety check: rate limiting
        if (!CheckRateLimit())
        {
            result.Success = false;
            result.ErrorMessage = "Rate limit exceeded (max 10 unloads/minute)";
            _logger.LogWarning("DllUnloadEngine: Rate limit hit — skipping unload of {Dll} from PID {Pid}",
                moduleName, processId);
            return result;
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
                Interlocked.Increment(ref _unloadsThisMinute);
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

    private bool CheckRateLimit()
    {
        var now = DateTimeOffset.UtcNow;
        if ((now - _minuteStart).TotalMinutes >= 1)
        {
            _minuteStart = now;
            Interlocked.Exchange(ref _unloadsThisMinute, 0);
        }
        return _unloadsThisMinute < MaxUnloadsPerMinute;
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


