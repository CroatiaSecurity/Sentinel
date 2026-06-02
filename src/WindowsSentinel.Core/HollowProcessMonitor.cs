using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace WindowsSentinel.Core
{
    public class HollowProcessMonitor : IDisposable
    {
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly System.Threading.Timer _timer;

        private readonly ConcurrentDictionary<int, DateTime> _alerted = new();
        private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromMinutes(10);

        private static readonly HashSet<string> AlwaysTrusted = new(StringComparer.OrdinalIgnoreCase)
        {
            "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
            "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
            "fontdrvhost.exe", "dwm.exe", "sihost.exe", "taskhostw.exe",
            "explorer.exe", "RuntimeBroker.exe", "SearchIndexer.exe",
            "MsMpEng.exe", "NisSrv.exe"
        };

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwAccess, bool bInherit, int dwPid);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint GetMappedFileName(
            IntPtr hProcess, IntPtr lpv, [Out] char[] lpFilename, uint nSize);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcessModules(
            IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageName(
            IntPtr hProcess, uint dwFlags, [Out] char[] lpExeName, ref uint lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint QueryDosDevice(
            string lpDeviceName, [Out] char[] lpTargetPath, uint ucchMax);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        private const uint TH32CS_SNAPPROCESS = 0x00000002;
        private static readonly IntPtr INVALID_HANDLE_VALUE = -1;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public int th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public int th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        public HollowProcessMonitor(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine)
        {
            _fusionEngine = fusionEngine;
            _detectionEngine = detectionEngine;
            // Scan for process hollowing every 30 seconds
            _timer = new System.Threading.Timer(ScanProcesses, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(30));
        }

        private void ScanProcesses(object? state)
        {
            try
            {
                PruneAlertCache();

                var processes = GetProcessList();
                var selfPid = Environment.ProcessId;

                foreach (var proc in processes)
                {
                    try
                    {
                        var pid = proc.Pid;
                        if (pid <= 4 || pid == selfPid) continue;
                        if (AlwaysTrusted.Contains(proc.Name)) continue;
                        if (_alerted.ContainsKey(pid)) continue;

                        CheckProcess(pid, proc.Name, proc.Path);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"HollowProcessMonitor error: {ex.Message}");
            }
        }

        private void CheckProcess(int pid, string name, string declaredPath)
        {
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (hProcess == IntPtr.Zero) return;

            try
            {
                string? mappedFile = GetMappedFileName(hProcess, pid);

                if (mappedFile == null)
                {
                    if (!string.IsNullOrEmpty(declaredPath) &&
                        !declaredPath.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase))
                    {
                        FireDetection(pid, name, declaredPath, "UNMAPPED_BASE",
                            $"Process '{name}' (PID {pid}) has no mapped file at its base address. This may indicate shellcode running in a private memory allocation.",
                            0.75);
                    }
                    return;
                }

                string normalizedMapped = NormalizePath(mappedFile);
                string normalizedDeclared = NormalizePath(declaredPath);

                if (string.IsNullOrEmpty(normalizedDeclared)) return;

                if (!normalizedMapped.Equals(normalizedDeclared, StringComparison.OrdinalIgnoreCase))
                {
                    FireDetection(pid, name, declaredPath, "HOLLOWED",
                        $"Process '{name}' (PID {pid}) is HOLLOWED or STOMPED. Declared image: '{declaredPath}' | Actual mapped file: '{mappedFile}'",
                        0.92);
                }
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }

        private void FireDetection(int pid, string name, string declaredPath, string hollowType, string evidence, double confidence)
        {
            _alerted[pid] = DateTime.UtcNow;

            var telemetry = new HollowProcessTelemetry
            {
                Type = "hollow",
                Timestamp = DateTime.UtcNow,
                ProcessId = pid,
                ProcessName = name,
                DeclaredPath = declaredPath,
                HollowType = hollowType,
                Evidence = evidence,
                Confidence = confidence
            };

            var context = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(context);

            var alert = new DetectionEvent
            {
                RuleName = "Process Hollowing: Image Mismatch",
                ProcessName = name,
                ProcessId = pid,
                Confidence = confidence,
                Tier = DetectionTier.Tier1Behavioral,
                Evidence = evidence,
                Reasoning = "The execution file backing the process main module does not match the image path registered in the process table. This is a primary indicator of process hollowing or module stomping, commonly used by advanced implants to masquerade as trusted system utilities.",
                Timestamp = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    { "hollow_type", hollowType },
                    { "declared_path", declaredPath },
                    { "technique", "T1055.012 - Process Injection: Process Hollowing" }
                }
            };

            _ = _detectionEngine.EmitAsync(alert);
        }

        private static string? GetMappedFileName(IntPtr hProcess, int pid)
        {
            IntPtr baseAddress = GetProcessBaseAddress(pid);
            if (baseAddress == IntPtr.Zero) return null;

            var buffer = new char[1024];
            uint result = GetMappedFileName(hProcess, baseAddress, buffer, (uint)buffer.Length);
            if (result == 0) return null;

            var devicePath = new string(buffer, 0, (int)result);
            return DevicePathToDrivePath(devicePath);
        }

        private static IntPtr GetProcessBaseAddress(int pid)
        {
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (hProcess == IntPtr.Zero) return IntPtr.Zero;

            try
            {
                var modules = new IntPtr[1];
                if (!EnumProcessModules(hProcess, modules, (uint)Marshal.SizeOf<IntPtr>(), out _))
                    return IntPtr.Zero;
                return modules[0];
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }

        private static string DevicePathToDrivePath(string devicePath)
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                var driveLetter = drive.Name.TrimEnd('\\');
                var buffer = new char[256];
                if (QueryDosDevice(driveLetter, buffer, (uint)buffer.Length) == 0) continue;

                string deviceName = new string(buffer).Split('\0')[0];
                if (devicePath.StartsWith(deviceName, StringComparison.OrdinalIgnoreCase))
                {
                    return driveLetter + devicePath[deviceName.Length..];
                }
            }
            return devicePath;
        }

        private static string NormalizePath(string path)
        {
            return path.Trim().TrimEnd('\\').ToLowerInvariant();
        }

        private static List<ProcessInfo> GetProcessList()
        {
            var list = new List<ProcessInfo>();
            IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) return list;

            try
            {
                var entry = new PROCESSENTRY32
                {
                    dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>()
                };

                if (!Process32First(hSnapshot, ref entry)) return list;

                do
                {
                    string fullPath = GetFullProcessPath(entry.th32ProcessID);
                    list.Add(new ProcessInfo
                    {
                        Pid = entry.th32ProcessID,
                        Name = entry.szExeFile,
                        Path = fullPath
                    });
                }
                while (Process32Next(hSnapshot, ref entry));
            }
            finally
            {
                CloseHandle(hSnapshot);
            }

            return list;
        }

        private static string GetFullProcessPath(int pid)
        {
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero) return string.Empty;

            try
            {
                var buffer = new char[1024];
                uint size = (uint)buffer.Length;
                if (QueryFullProcessImageName(hProcess, 0, buffer, ref size))
                {
                    return new string(buffer, 0, (int)size);
                }
                return string.Empty;
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }

        private void PruneAlertCache()
        {
            var cutoff = DateTime.UtcNow - AlertDedupeWindow;
            foreach (var kvp in _alerted)
            {
                if (kvp.Value < cutoff)
                {
                    _alerted.TryRemove(kvp.Key, out _);
                }
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
            GC.SuppressFinalize(this);
        }

        private class ProcessInfo
        {
            public int Pid { get; set; }
            public string Name { get; set; } = string.Empty;
            public string Path { get; set; } = string.Empty;
        }
    }
}
