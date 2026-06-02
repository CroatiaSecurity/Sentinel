using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace WindowsSentinel.Core
{
    public class LsassDumpCanaryMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly System.Threading.Timer _timer;

        private readonly ConcurrentDictionary<int, DateTime> _alertedPids = new();
        private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromMinutes(5);

        private static readonly HashSet<string> LegitimateDbghelpUsers = new(StringComparer.OrdinalIgnoreCase)
        {
            "devenv.exe", "devenv",
            "windbg.exe", "windbg",
            "windbgx.exe", "windbgx",
            "x64dbg.exe", "x64dbg",
            "x32dbg.exe", "x32dbg",
            "ollydbg.exe", "ollydbg",
            "ida.exe", "ida64.exe",
            "radare2.exe", "r2.exe",
            "cdb.exe",
            "ntsd.exe",
            "drwtsn32.exe",
            "werfault.exe", "werfaultsecure.exe",
            "taskmgr.exe",
            "procmon.exe", "procmon64.exe",
            "procdump.exe", "procdump64.exe",
            "msmpeng.exe",
            "mssense.exe",
            "sentinelservice.exe",
            "sentinelagent.exe",
            "dotnet.exe",
            "crashpad_handler.exe",
            "dumpminitool.exe",
            "steamwebhelper", "steamwebhelper.exe",
            "steam", "steam.exe",
            "GoogleCrashHandler", "GoogleCrashHandler.exe",
            "GoogleCrashHandler64", "GoogleCrashHandler64.exe",
            "Kiro", "Kiro.exe",
            "Code", "Code.exe",
            "code", "code.exe",
            "cursor", "Cursor.exe",
            "electron", "electron.exe",
            "msedge", "msedge.exe",
            "chrome", "chrome.exe",
            "firefox", "firefox.exe",
            "brave", "brave.exe",
            "opera", "opera.exe",
            "discord", "Discord.exe",
            "slack", "Slack.exe",
            "teams", "Teams.exe",
            "svchost", "svchost.exe",
            "rider64", "rider64.exe",
            "idea64", "idea64.exe",
            "pycharm64", "pycharm64.exe",
            "webstorm64", "webstorm64.exe",
            "TmsaInstance64", "TmsaInstance64.exe",
            "PtSessionAgent", "PtSessionAgent.exe",
            "uiSeAgnt", "uiSeAgnt.exe",
            "coreServiceShell", "coreServiceShell.exe",
            "coreFrameworkHost", "coreFrameworkHost.exe",
            "PtSvcHost", "PtSvcHost.exe",
            "AMSPTelemetryService", "AMSPTelemetryService.exe",
            "PtWatchDog", "PtWatchDog.exe",
            "NVDisplay.Container", "NVDisplay.Container.exe",
            "nvcontainer", "nvcontainer.exe",
            "WUDFHost", "WUDFHost.exe",
            "msedgewebview2", "msedgewebview2.exe",
            "mainProcess", "mainProcess.exe",
            "ASCService", "ASCService.exe",
            "fm", "fm.exe"
        };

        private static readonly HashSet<string> GoogleUpdateProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "GoogleUpdate", "GoogleUpdate.exe",
            "GoogleUpdateSetup", "GoogleUpdateSetup.exe",
            "GoogleUpdateOnDemand", "GoogleUpdateOnDemand.exe",
            "GoogleUpdateComRegisterShell64", "GoogleUpdateComRegisterShell64.exe",
            "elevation_service", "elevation_service.exe",
        };

        private static readonly string[] LegitimateGoogleUpdatePaths = new[]
        {
            @"\Program Files (x86)\Google\Update\",
            @"\Program Files\Google\Update\",
            @"\Program Files (x86)\Google\Chrome\Application\",
            @"\Program Files\Google\Chrome\Application\",
            @"\AppData\Local\Temp\GUM",
            @"\Users\",
        };

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
        private static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule,
            uint cb, out uint lpcbNeeded, uint dwFilterFlag);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule,
            [Out] char[] lpFilename, uint nSize);

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint LIST_MODULES_ALL = 0x03;

        public LsassDumpCanaryMonitor(DetectionEngine detectionEngine)
        {
            _detectionEngine = detectionEngine;
            // Scan for dbghelp loads every 15 seconds
            _timer = new System.Threading.Timer(ScanForDbghelpLoad, null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
        }

        private void ScanForDbghelpLoad(object? state)
        {
            try
            {
                PruneAlertCache();

                var selfPid = Environment.ProcessId;
                var processes = Process.GetProcesses();

                foreach (var process in processes)
                {
                    try
                    {
                        var pid = process.Id;
                        if (pid <= 4 || pid == selfPid) continue;
                        if (LegitimateDbghelpUsers.Contains(process.ProcessName)) continue;
                        if (_alertedPids.ContainsKey(pid)) continue;

                        if (IsGoogleUpdateProcessName(process.ProcessName))
                        {
                            var (isLegitimate, reason) = ValidateGoogleUpdateProcess(process);
                            if (isLegitimate)
                            {
                                _alertedPids[pid] = DateTime.UtcNow;
                                continue;
                            }

                            if (HasDbghelpLoaded(pid))
                            {
                                _alertedPids[pid] = DateTime.UtcNow;
                                EmitAlert(pid, process.ProcessName, true, reason);
                            }
                            continue;
                        }

                        if (HasDbghelpLoaded(pid))
                        {
                            _alertedPids[pid] = DateTime.UtcNow;
                            EmitAlert(pid, process.ProcessName, false, null);
                        }
                    }
                    catch (InvalidOperationException) { }
                    catch (System.ComponentModel.Win32Exception) { }
                    finally
                    {
                        process.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"LsassDumpCanaryMonitor error: {ex.Message}");
            }
        }

        private void EmitAlert(int pid, string processName, bool isAptSideload, string? validationReason)
        {
            var alert = new DetectionEvent
            {
                RuleName = "LSASS Credential Dump: dbghelp.dll Loaded",
                ProcessName = processName + ".exe",
                ProcessId = pid,
                Confidence = isAptSideload ? 0.92 : 0.85,
                Tier = DetectionTier.Tier2Indicator,
                Timestamp = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    { "loaded_module", "dbghelp.dll" },
                    { "technique", "T1003.001 - OS Credential Dumping: LSASS Memory" }
                }
            };

            if (isAptSideload)
            {
                alert.Evidence = $"Process '{processName}' (PID {pid}) has dbghelp.dll loaded but is NOT a legitimate Google Update binary: {validationReason}. This matches the PlugX/APT DLL sideloading pattern (T1574.002) where threat actors abuse the GoogleUpdate.exe name to evade detection.";
                alert.Reasoning = "dbghelp.dll loaded by a process impersonating GoogleUpdate.exe from an unexpected path or without a valid Google signature. PlugX (used by APT41, Mustang Panda) and other APT toolkits specifically copy GoogleUpdate.exe to user-writable directories and sideload malicious DLLs alongside it.";
                alert.Metadata.Add("apt_sideload_suspected", "true");
                alert.Metadata.Add("validation_failure", validationReason ?? "unknown");
                alert.Metadata.Add("mitre_sideload", "T1574.002 - DLL Side-Loading");
            }
            else
            {
                alert.Evidence = $"Non-debugger process '{processName}' (PID {pid}) has dbghelp.dll loaded. This DLL is required for MiniDumpWriteDump and is not normally loaded by applications.";
                alert.Reasoning = "dbghelp.dll contains MiniDumpWriteDump — the function used by virtually all credential dumping tools (Mimikatz, NanoDump, HandleKatz, custom tools) to dump LSASS memory. Legitimate applications never load this DLL unless they are debuggers or crash reporters.";
            }

            _ = _detectionEngine.EmitAsync(alert);
        }

        private static bool IsGoogleUpdateProcessName(string processName)
        {
            return GoogleUpdateProcessNames.Contains(processName) ||
                   processName.StartsWith("GoogleUpdate", StringComparison.OrdinalIgnoreCase) ||
                   processName.StartsWith("GoogleCrash", StringComparison.OrdinalIgnoreCase);
        }

        private (bool isLegitimate, string? reason) ValidateGoogleUpdateProcess(Process process)
        {
            try
            {
                string? imagePath = null;
                try { imagePath = process.MainModule?.FileName; }
                catch { }

                if (string.IsNullOrEmpty(imagePath))
                {
                    return (false, "cannot read process image path (access denied or process exited)");
                }

                var pathLower = imagePath.ToLowerInvariant();

                if (IsPlugXStagingPath(pathLower))
                {
                    return (false, $"running from known APT staging path: {imagePath}");
                }

                bool isGoogleSigned = IsSignedByGoogle(imagePath);

                bool isStandardPath = false;
                for (int i = 0; i < 4; i++)
                {
                    if (pathLower.Contains(LegitimateGoogleUpdatePaths[i].ToLowerInvariant()))
                    {
                        isStandardPath = true;
                        break;
                    }
                }

                if (isStandardPath && isGoogleSigned)
                    return (true, null);

                if (isStandardPath && !isGoogleSigned)
                    return (false, $"running from standard path but signature invalid or missing: {imagePath}");

                bool isGumTempPath = pathLower.Contains(@"\appdata\local\temp\gum") ||
                                     Regex.IsMatch(pathLower, @"\\temp\\gum[0-9a-f]+\.tmp\\");
                if (isGumTempPath && isGoogleSigned)
                    return (true, null);

                if (isGumTempPath && !isGoogleSigned)
                    return (false, $"running from GUM temp path but NOT signed by Google — likely PlugX sideload: {imagePath}");

                if (!isGoogleSigned)
                    return (false, $"not signed by Google, running from non-standard path: {imagePath}");

                return (false, $"Google-signed but running from unexpected path: {imagePath}");
            }
            catch (Exception ex)
            {
                return (false, $"validation exception: {ex.Message}");
            }
        }

        private static bool IsPlugXStagingPath(string pathLower)
        {
            if (Regex.IsMatch(pathLower, @"\\programdata\\[a-z0-9]{6,12}\\"))
                return true;

            if (pathLower.Contains(@"\users\public\"))
                return true;

            if (Regex.IsMatch(pathLower, @"\\appdata\\roaming\\[a-z0-9]{6,12}\\"))
                return true;

            if (Regex.IsMatch(pathLower, @"\\windows\\temp\\[a-z0-9]{6,12}\\"))
                return true;

            return false;
        }

        private static bool IsSignedByGoogle(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return false;
                using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
                var subject = cert.Subject;
                return subject.Contains("Google LLC", StringComparison.OrdinalIgnoreCase) ||
                       subject.Contains("Google Inc", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private bool HasDbghelpLoaded(int pid)
        {
            var hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (hProcess == IntPtr.Zero) return false;

            try
            {
                var modules = new IntPtr[1024];
                if (!EnumProcessModulesEx(hProcess, modules, (uint)(modules.Length * IntPtr.Size),
                    out uint needed, LIST_MODULES_ALL))
                    return false;

                int moduleCount = (int)(needed / IntPtr.Size);
                var nameBuffer = new char[260];

                for (int i = 0; i < moduleCount && i < modules.Length; i++)
                {
                    if (modules[i] == IntPtr.Zero) continue;

                    var len = GetModuleFileNameEx(hProcess, modules[i], nameBuffer, (uint)nameBuffer.Length);
                    if (len == 0) continue;

                    var moduleName = new string(nameBuffer, 0, (int)len);
                    var fileName = Path.GetFileName(moduleName);

                    if (string.Equals(fileName, "dbghelp.dll", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(fileName, "dbgcore.dll", StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }

                return false;
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }

        private void PruneAlertCache()
        {
            var cutoff = DateTime.UtcNow - AlertDedupeWindow;
            foreach (var kvp in _alertedPids)
            {
                if (kvp.Value < cutoff)
                {
                    _alertedPids.TryRemove(kvp.Key, out _);
                }
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
