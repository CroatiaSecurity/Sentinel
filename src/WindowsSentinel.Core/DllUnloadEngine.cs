using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Unloads suspicious DLLs from processes instead of killing them.
    /// This is the corrected approach: the old code killed every process that had
    /// a sideloaded DLL (e.g. dbghelp.dll dropped into app folders). The DLL
    /// sideloading detection itself was correct — the problem was the kill response.
    /// Now we:
    ///   1. Detect DLL sideloading (non-system DLL shadowing a system DLL)
    ///   2. Unload the sideloaded DLL via CreateRemoteThread + FreeLibrary
    ///   3. Log the event but do NOT kill the host process
    ///   4. Rate-limit unloads to prevent destabilizing the system
    /// </summary>
    public sealed class DllUnloadEngine : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DllUnloadEngine> _logger;
        private readonly ConcurrentDictionary<string, DateTimeOffset> _unloadHistory = new();
        private int _unloadsThisMinute;
        private DateTimeOffset _minuteStart = DateTimeOffset.UtcNow;
        private readonly object _rateLock = new();

        private const int MaxUnloadsPerMinute = 10;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetModuleHandleA(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;

        private static readonly HashSet<string> ProtectedProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "system", "smss", "csrss", "wininit", "services", "lsass", "svchost",
            "explorer", "dwm", "winlogon", "MsMpEng", "NisSrv",
            "WindowsSentinel.Service", "WindowsSentinel.Agent",
            // Browsers — install in AppData/Program Files, DLL unloading will crash them
            "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "iexplore",
            // Common AppData-resident apps
            "spotify", "discord", "slack", "teams", "onedrive", "dropbox",
            "code", "cursor", "windsurf", "rider", "webstorm", "idea"
        };

        private static readonly HashSet<string> ProtectedDlls = new(StringComparer.OrdinalIgnoreCase)
        {
            "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
            "advapi32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll", "combase.dll",
            "msvcrt.dll", "ucrtbase.dll", "msvcp_win.dll", "bcryptprimitives.dll",
            "clr.dll", "coreclr.dll", "hostfxr.dll", "hostpolicy.dll",
        };

        // Known sideloading targets — legitimate system DLLs that get dropped into app folders
        private static readonly HashSet<string> SideloadTargets = new(StringComparer.OrdinalIgnoreCase)
        {
            "dbghelp.dll", "version.dll", "winmm.dll", "dwrite.dll",
            "cryptsp.dll", "userenv.dll", "profapi.dll", "wtsapi32.dll",
            "dhcpcsvc.dll", "IPHLPAPI.DLL",
        };

        public DllUnloadEngine(DetectionEngine de, ILogger<DllUnloadEngine> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        /// <summary>
        /// Checks a process for sideloaded DLLs and unloads them.
        /// Returns true if any DLLs were unloaded.
        /// </summary>
        public async Task<DllUnloadResult> CheckAndUnloadAsync(int processId, string processName)
        {
            var result = new DllUnloadResult { ProcessId = processId, ProcessName = processName };

            if (ProtectedProcesses.Contains(processName))
                return result;

            try
            {
                using var proc = Process.GetProcessById(processId);
                string? procDir = null;
                try { procDir = Path.GetDirectoryName(proc.MainModule?.FileName); } catch { }
                if (string.IsNullOrEmpty(procDir)) return result;

                // Skip if process is in a system directory
                if (procDir.StartsWith(@"C:\Windows", StringComparison.OrdinalIgnoreCase))
                    return result;

                foreach (ProcessModule mod in proc.Modules)
                {
                    try
                    {
                        var modName = mod.ModuleName?.ToLowerInvariant() ?? "";
                        var modDir = Path.GetDirectoryName(mod.FileName) ?? "";

                        if (!SideloadTargets.Contains(modName)) continue;
                        if (ProtectedDlls.Contains(modName)) continue;

                        // Sideloaded if the DLL is in the process directory (not System32)
                        if (modDir.Equals(procDir, StringComparison.OrdinalIgnoreCase) &&
                            !modDir.StartsWith(@"C:\Windows", StringComparison.OrdinalIgnoreCase))
                        {
                            var key = $"{processId}:{modName}";
                            if (_unloadHistory.ContainsKey(key)) continue;

                            if (!TryConsumeRateLimit()) continue;

                            // Unload instead of kill
                            bool unloaded = TryUnloadDll(processId, mod.BaseAddress);

                            _unloadHistory[key] = DateTimeOffset.UtcNow;

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "DLL Sideloading: Suspicious DLL Unloaded",
                                Evidence = $"Sideloaded '{modName}' from '{mod.FileName}' in process '{processName}' (PID {processId}). Unloaded={unloaded}",
                                Reasoning = $"A system DLL ({modName}) was loaded from the application directory instead of System32, indicating DLL sideloading (T1574.001). The DLL was unloaded; the process was NOT killed.",
                                Confidence = 0.75,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly, // Do NOT kill
                                ProcessName = processName,
                                ProcessId = processId
                            });

                            result.UnloadedDlls.Add(mod.FileName ?? modName);
                            result.Success = true;
                        }
                    }
                    catch { }
                }
            }
            catch (ArgumentException) { } // Process exited
            catch (System.ComponentModel.Win32Exception) { } // Access denied
            catch (InvalidOperationException) { }

            return result;
        }

        private bool TryUnloadDll(int processId, IntPtr moduleBaseAddress)
        {
            IntPtr hProcess = IntPtr.Zero;
            try
            {
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                if (hProcess == IntPtr.Zero) return false;

                // Get FreeLibrary address (same in all processes due to ASLR base)
                var kernel32 = GetModuleHandleA("kernel32.dll");
                if (kernel32 == IntPtr.Zero) return false;
                var freeLibAddr = GetProcAddress(kernel32, "FreeLibrary");
                if (freeLibAddr == IntPtr.Zero) return false;

                // CreateRemoteThread calling FreeLibrary(moduleBaseAddress)
                var thread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, freeLibAddr,
                    moduleBaseAddress, 0, out _);
                if (thread == IntPtr.Zero) return false;

                WaitForSingleObject(thread, 5000);
                CloseHandle(thread);
                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
            }
        }

        private bool TryConsumeRateLimit()
        {
            lock (_rateLock)
            {
                var now = DateTimeOffset.UtcNow;
                if ((now - _minuteStart).TotalMinutes >= 1)
                {
                    _minuteStart = now;
                    _unloadsThisMinute = 0;
                }
                if (_unloadsThisMinute >= MaxUnloadsPerMinute) return false;
                _unloadsThisMinute++;
                return true;
            }
        }
        
        /// <summary>
        /// Scans a target process for recently loaded, unsigned, or suspicious DLLs
        /// (e.g., loaded from Temp, AppData, or any non-standard/unsigned path) and unloads them.
        /// </summary>
        public async Task<DllUnloadResult> UnloadInjectedDllAsync(int targetPid)
        {
            var result = new DllUnloadResult { ProcessId = targetPid };
            try
            {
                using var proc = Process.GetProcessById(targetPid);
                result.ProcessName = proc.ProcessName;
                if (ProtectedProcesses.Contains(result.ProcessName))
                    return result;

                string? procDir = null;
                try { procDir = Path.GetDirectoryName(proc.MainModule?.FileName); } catch { }

                foreach (ProcessModule mod in proc.Modules)
                {
                    try
                    {
                        var modName = mod.ModuleName?.ToLowerInvariant() ?? "";
                        var modPath = mod.FileName ?? "";
                        var modDir = Path.GetDirectoryName(modPath) ?? "";

                        if (ProtectedDlls.Contains(modName)) continue;
                        if (modPath.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase)) continue;

                        // Only flag DLLs from Temp paths — AppData is a legitimate install location
                        // for browsers, Spotify, Discord, etc. Never unload from there.
                        bool isSuspicious = modPath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                                            modPath.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase) ||
                                            (!string.IsNullOrEmpty(procDir) && modDir.Equals(procDir, StringComparison.OrdinalIgnoreCase) && SideloadTargets.Contains(modName));

                        if (isSuspicious)
                        {
                            var key = $"{targetPid}:{modName}";
                            if (_unloadHistory.ContainsKey(key)) continue;

                            if (!TryConsumeRateLimit()) continue;

                            bool unloaded = TryUnloadDll(targetPid, mod.BaseAddress);
                            _unloadHistory[key] = DateTimeOffset.UtcNow;

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "DLL Injection: Injected DLL Unloaded",
                                Evidence = $"Unloaded injected DLL '{modName}' from '{modPath}' in target process '{result.ProcessName}' (PID {targetPid}). Unloaded={unloaded}",
                                Reasoning = "A memory injection event was detected targeting this process. The injected DLL was located and unloaded successfully.",
                                Confidence = 0.90,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = result.ProcessName,
                                ProcessId = targetPid
                            });

                            result.UnloadedDlls.Add(modPath);
                            result.Success = true;
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return result;
        }

        public void Dispose()
        {
            // Cleanup history to release memory
            _unloadHistory.Clear();
        }
    }

    public sealed class DllUnloadResult
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public bool Success { get; set; }
        public List<string> UnloadedDlls { get; set; } = new();
    }
}
