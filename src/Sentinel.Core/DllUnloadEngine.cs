using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Detects and remediates DLL sideloading attacks.
    ///
    /// Attack pattern: attacker drops a malicious DLL (e.g., dbghelp.dll, version.dll)
    /// into the same directory as a legitimate application. When the app starts,
    /// Windows DLL search order loads the local copy instead of the real System32 one.
    ///
    /// Response strategy (no CreateRemoteThread — that looks like malware):
    ///   1. Detect: enumerate loaded modules, find system DLLs loaded from non-system paths
    ///   2. Kill: terminate the compromised process (it already executed attacker code)
    ///   3. Quarantine: move the sideloaded DLL to quarantine (XOR-encrypted, renamed)
    ///   4. Lock: place a zero-byte read-only decoy at the original path to prevent re-drop
    ///
    /// If the attacker keeps re-dropping, FileActivityMonitor catches the write event
    /// and quarantines on arrival. The lock file prevents the race condition where an app
    /// starts between drop and detection.
    /// </summary>
    public sealed class DllUnloadEngine : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly QuarantineManager _quarantineManager;
        private readonly ILogger<DllUnloadEngine> _logger;
        private readonly ConcurrentDictionary<string, DateTimeOffset> _remediationHistory = new();
        private int _remediationsThisMinute;
        private DateTimeOffset _minuteStart = DateTimeOffset.UtcNow;
        private readonly object _rateLock = new();

        private const int MaxRemediationsPerMinute = 10;

        private static readonly HashSet<string> ProtectedProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "system", "smss", "csrss", "wininit", "services", "lsass", "svchost",
            "explorer", "dwm", "winlogon", "MsMpEng", "NisSrv",
            "Sentinel.Service", "Sentinel.Agent",
            // Browsers — install in AppData/Program Files, killing is acceptable but not for sideload FP
            "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "iexplore",
            // Common AppData-resident apps
            "spotify", "discord", "slack", "teams", "onedrive", "dropbox",
            "code", "cursor", "windsurf", "rider", "webstorm", "idea"
        };

        // Known sideloading targets — legitimate system DLLs that attackers drop into app folders
        private static readonly HashSet<string> SideloadTargets = new(StringComparer.OrdinalIgnoreCase)
        {
            "dbghelp.dll", "version.dll", "winmm.dll", "dwrite.dll",
            "cryptsp.dll", "userenv.dll", "profapi.dll", "wtsapi32.dll",
            "dhcpcsvc.dll", "IPHLPAPI.DLL", "msasn1.dll", "netapi32.dll",
            "samcli.dll", "sspicli.dll", "crypt32.dll",
        };

        public DllUnloadEngine(DetectionEngine de, QuarantineManager qm, ILogger<DllUnloadEngine> l)
        {
            _detectionEngine = de;
            _quarantineManager = qm;
            _logger = l;
        }

        /// <summary>
        /// Scans a process for sideloaded DLLs. If found:
        /// - Kills the compromised process
        /// - Quarantines the malicious DLL
        /// - Places a lock file to prevent re-drop
        /// </summary>
        public async Task<DllUnloadResult> CheckAndUnloadAsync(int processId, string processName)
        {
            var result = new DllUnloadResult { ProcessId = processId, ProcessName = processName };

            if (ProtectedProcesses.Contains(processName))
            {
                // Verify path — name alone is spoofable. Only skip if running from legitimate location.
                try
                {
                    using var p = Process.GetProcessById(processId);
                    var path = p.MainModule?.FileName;
                    if (IsProtectedPath(path)) return result;
                }
                catch { return result; } // Can't verify — err on side of caution, don't remediate
            }

            try
            {
                using var proc = Process.GetProcessById(processId);
                string? procDir = null;
                try { procDir = Path.GetDirectoryName(proc.MainModule?.FileName); } catch { }
                if (string.IsNullOrEmpty(procDir)) return result;

                // Skip if process is in the Windows directory — legitimate loads
                var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                var winDirTrailing = winDir.EndsWith('\\') ? winDir : winDir + '\\';
                if (procDir.StartsWith(winDirTrailing, StringComparison.OrdinalIgnoreCase))
                    return result;

                var sideloadedFiles = new List<string>();

                foreach (ProcessModule mod in proc.Modules)
                {
                    try
                    {
                        var modName = mod.ModuleName ?? "";
                        var modDir = Path.GetDirectoryName(mod.FileName) ?? "";

                        if (!SideloadTargets.Contains(modName)) continue;

                        // Sideloaded if the DLL is in the process directory (not a Windows system folder)
                        if (modDir.Equals(procDir, StringComparison.OrdinalIgnoreCase) &&
                            !modDir.StartsWith(winDirTrailing, StringComparison.OrdinalIgnoreCase))
                        {
                            var key = $"{processId}:{modName}";
                            if (_remediationHistory.ContainsKey(key)) continue;
                            if (!TryConsumeRateLimit()) continue;

                            sideloadedFiles.Add(mod.FileName!);
                            _remediationHistory[key] = DateTimeOffset.UtcNow;
                        }
                    }
                    catch { }
                }

                if (sideloadedFiles.Count == 0) return result;

                // Step 1: Attempt in-memory DLL unload via FreeLibrary
                // This removes the malicious code from the process's address space
                // without killing the host process (if possible)
                bool allUnloaded = true;
                foreach (ProcessModule mod in proc.Modules)
                {
                    try
                    {
                        if (sideloadedFiles.Contains(mod.FileName))
                        {
                            bool unloaded = TryUnloadDll(processId, mod.BaseAddress);
                            if (!unloaded) allUnloaded = false;
                        }
                    }
                    catch { allUnloaded = false; }
                }

                // Step 2: If unload failed, kill the process — can't leave malicious code running
                if (!allUnloaded)
                {
                    try { proc.Kill(entireProcessTree: true); }
                    catch { }
                }

                // Step 3: Quarantine each sideloaded DLL from disk + place lock file
                foreach (var dllPath in sideloadedFiles)
                {
                    await RemediateDroppedDll(dllPath, processName, processId);
                    result.UnloadedDlls.Add(dllPath);
                }

                result.Success = true;

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "DLL Sideloading: Malicious DLL Quarantined",
                    Evidence = $"Process '{processName}' (PID {processId}) loaded sideloaded DLLs: {string.Join(", ", sideloadedFiles.Select(Path.GetFileName))}. Process killed, DLLs quarantined.",
                    Reasoning = "System DLLs were loaded from the application directory instead of System32, indicating DLL sideloading (T1574.001). The process was terminated and the malicious DLLs quarantined to prevent re-exploitation.",
                    Confidence = 0.85,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly, // Already handled
                    ProcessName = processName,
                    ProcessId = processId,
                    Metadata = new Dictionary<string, string>
                    {
                        ["SideloadedDlls"] = string.Join(";", sideloadedFiles),
                        ["Action"] = "KILL_AND_QUARANTINE"
                    }
                });
            }
            catch (ArgumentException) { } // Process exited
            catch (System.ComponentModel.Win32Exception) { } // Access denied
            catch (InvalidOperationException) { }

            return result;
        }

        /// <summary>
        /// Called by AdvancedResponseEngine when a DLL injection detection fires.
        /// Scans target process for suspicious DLLs from Temp paths, quarantines them.
        /// </summary>
        public async Task<DllUnloadResult> UnloadInjectedDllAsync(int targetPid)
        {
            var result = new DllUnloadResult { ProcessId = targetPid };
            try
            {
                using var proc = Process.GetProcessById(targetPid);
                result.ProcessName = proc.ProcessName;
                if (ProtectedProcesses.Contains(result.ProcessName))
                {
                    try
                    {
                        var path = proc.MainModule?.FileName;
                        if (IsProtectedPath(path)) return result;
                    }
                    catch { return result; }
                }

                string? procDir = null;
                try { procDir = Path.GetDirectoryName(proc.MainModule?.FileName); } catch { }

                var suspiciousDlls = new List<string>();

                foreach (ProcessModule mod in proc.Modules)
                {
                    try
                    {
                        var modName = mod.ModuleName ?? "";
                        var modPath = mod.FileName ?? "";

                        if (modPath.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase)) continue;

                        // Flag DLLs from Temp paths — clear injection indicator
                        bool isSuspicious = modPath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                                            modPath.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase);

                        // Also flag sideloading from app directory
                        if (!isSuspicious && !string.IsNullOrEmpty(procDir))
                        {
                            var modDir = Path.GetDirectoryName(modPath) ?? "";
                            isSuspicious = modDir.Equals(procDir, StringComparison.OrdinalIgnoreCase) &&
                                           SideloadTargets.Contains(modName);
                        }

                        if (isSuspicious)
                        {
                            var key = $"{targetPid}:{modName}";
                            if (_remediationHistory.ContainsKey(key)) continue;
                            if (!TryConsumeRateLimit()) continue;

                            suspiciousDlls.Add(modPath);
                            _remediationHistory[key] = DateTimeOffset.UtcNow;
                        }
                    }
                    catch { }
                }

                if (suspiciousDlls.Count == 0) return result;

                // Step 1: Attempt in-memory unload via FreeLibrary
                bool allUnloaded = true;
                foreach (ProcessModule mod in proc.Modules)
                {
                    try
                    {
                        if (suspiciousDlls.Contains(mod.FileName))
                        {
                            bool unloaded = TryUnloadDll(targetPid, mod.BaseAddress);
                            if (!unloaded) allUnloaded = false;
                        }
                    }
                    catch { allUnloaded = false; }
                }

                // Step 2: If unload failed, kill the process
                if (!allUnloaded)
                {
                    try { proc.Kill(entireProcessTree: true); }
                    catch { }
                }

                // Step 3: Quarantine each suspicious DLL from disk
                foreach (var dllPath in suspiciousDlls)
                {
                    await RemediateDroppedDll(dllPath, result.ProcessName, targetPid);
                    result.UnloadedDlls.Add(dllPath);
                }

                result.Success = true;
            }
            catch { }
            return result;
        }

        /// <summary>
        /// Unloads a DLL from a target process using QueueUserAPC + FreeLibrary.
        /// QueueUserAPC schedules FreeLibrary(moduleBase) on an alertable thread in the target.
        /// Unlike CreateRemoteThread, QueueUserAPC is not in AV injection signature databases.
        /// Falls back to process kill if no alertable thread responds within 2 seconds.
        /// </summary>
        private static bool TryUnloadDll(int processId, IntPtr moduleBaseAddress)
        {
            IntPtr hProcess = IntPtr.Zero;
            try
            {
                // SECURITY v1.4.4: Reduced from PROCESS_ALL_ACCESS (0x1F0FFF) to minimum required.
                // We only need to enumerate threads (PROCESS_QUERY_INFORMATION) and read module list.
                // Thread handles are opened separately with THREAD_SET_CONTEXT for QueueUserAPC.
                // PROCESS_ALL_ACCESS was overprivileged — provided a window for handle duplication
                // and made this code a powerful injection primitive if processId were attacker-influenced.
                const uint PROCESS_QUERY_INFORMATION = 0x0400;
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, processId);
                if (hProcess == IntPtr.Zero) return false;

                var kernel32 = GetModuleHandleA("kernel32.dll");
                if (kernel32 == IntPtr.Zero) return false;
                var freeLibAddr = GetProcAddress(kernel32, "FreeLibrary");
                if (freeLibAddr == IntPtr.Zero) return false;

                // Queue APC to threads — alertable threads will execute FreeLibrary
                bool queued = false;
                using var proc = System.Diagnostics.Process.GetProcessById(processId);
                foreach (System.Diagnostics.ProcessThread thread in proc.Threads)
                {
                    IntPtr hThread = OpenThread(0x0010, false, (uint)thread.Id); // THREAD_SET_CONTEXT
                    if (hThread == IntPtr.Zero) continue;
                    try
                    {
                        if (QueueUserAPC(freeLibAddr, hThread, moduleBaseAddress) != 0)
                        {
                            queued = true;
                            break;
                        }
                    }
                    finally { CloseHandle(hThread); }
                }

                if (!queued) return false;

                // Poll every 10ms for up to 200ms to see if the module has been successfully unloaded.
                // If the target thread is alertable, this will execute almost instantly.
                for (int i = 0; i < 20; i++)
                {
                    Thread.Sleep(10);
                    if (!IsModuleLoaded(processId, moduleBaseAddress))
                    {
                        return true; // Unloaded successfully!
                    }
                }

                return false; // Timed out, did not unload
            }
            catch { return false; }
            finally
            {
                if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
            }
        }

        private static bool IsModuleLoaded(int processId, IntPtr baseAddress)
        {
            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById(processId);
                foreach (System.Diagnostics.ProcessModule mod in proc.Modules)
                {
                    if (mod.BaseAddress == baseAddress) return true;
                }
            }
            catch { }
            return false;
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        private static extern IntPtr GetModuleHandleA(string lpModuleName);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        /// <summary>
        /// Quarantines a dropped DLL and places a lock file to prevent re-drop.
        /// The lock file is a zero-byte, read-only, hidden, system file at the
        /// same path — Windows won't let anyone overwrite it without first removing
        /// the attributes, which FileActivityMonitor will catch.
        /// </summary>
        private async Task RemediateDroppedDll(string dllPath, string processName, int processId)
        {
            try
            {
                // Small delay — let the killed process release its file handles
                await Task.Delay(200);

                if (!File.Exists(dllPath)) return;

                // Quarantine: XOR-encrypt and move to quarantine directory
                // force: sideloaded payload may be signed; context already proved it is hostile
                await _quarantineManager.QuarantineFileAtomicAsync(dllPath, forceQuarantineSigned: true);

                // Place a lock file: zero-byte decoy with restrictive attributes
                // This prevents the attacker from simply re-dropping the DLL.
                // If they manage to delete/overwrite it, FileActivityMonitor catches that.
                try
                {
                    await File.WriteAllBytesAsync(dllPath, Array.Empty<byte>());
                    File.SetAttributes(dllPath,
                        FileAttributes.ReadOnly |
                        FileAttributes.Hidden |
                        FileAttributes.System);
                }
                catch
                {
                    // Lock file is best-effort — quarantine is the critical path
                }

                _logger.LogInformation(
                    "[DllSideloadRemediator] Quarantined '{DllPath}' from process '{ProcessName}' (PID {Pid}), lock file placed",
                    dllPath, processName, processId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[DllSideloadRemediator] Failed to quarantine '{DllPath}'", dllPath);
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
                    _remediationsThisMinute = 0;
                }
                if (_remediationsThisMinute >= MaxRemediationsPerMinute) return false;
                _remediationsThisMinute++;
                return true;
            }
        }

        public void Dispose()
        {
            _remediationHistory.Clear();
        }

        private static bool IsProtectedPath(string? path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            return path.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase) ||
                   path.StartsWith(@"C:\Program Files", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\AppData\Local\Google\", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\AppData\Local\Microsoft\", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\AppData\Local\BraveSoftware\", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\AppData\Local\Programs\", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\Sentinel", StringComparison.OrdinalIgnoreCase);
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
