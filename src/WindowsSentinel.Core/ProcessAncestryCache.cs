using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace WindowsSentinel.Core
{
    public class ProcessAncestryCache
    {
        private volatile IReadOnlyDictionary<int, (int parentId, string name)> _cache = new Dictionary<int, (int, string)>();
        private readonly System.Threading.Timer _refreshTimer;

        public ProcessAncestryCache()
        {
            RefreshCache();
            // Refreshed every 5 seconds (as per v4.8.1 optimization)
            _refreshTimer = new System.Threading.Timer(_ => RefreshCache(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        }

        private void RefreshCache()
        {
            var newCache = new Dictionary<int, (int parentId, string name)>();
            try
            {
                var processes = Process.GetProcesses();
                foreach (var proc in processes)
                {
                    try
                    {
                        using (proc)
                        {
                            var parentId = GetParentProcessId(proc);
                            newCache[proc.Id] = (parentId, proc.ProcessName);
                        }
                    }
                    catch
                    {
                        // Ignore access denied on individual processes
                    }
                }
                _cache = newCache;
            }
            catch
            {
                // Fallback / degrade gracefully
            }
        }

        public void RecordProcessStart(int pid, int parentPid, string processName, string imagePath)
        {
            // Inject ETW-sourced process data between periodic refreshes
            var dict = new Dictionary<int, (int, string)>((Dictionary<int, (int, string)>)_cache);
            dict[pid] = (parentPid, processName);
            _cache = dict;
        }

        public (int parentId, string name) GetParent(int pid)
        {
            if (_cache.TryGetValue(pid, out var info))
            {
                return info;
            }
            return (0, "unknown");
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength,
            out int returnLength);

        private static int GetParentProcessId(Process process)
        {
            try
            {
                var pbi = new PROCESS_BASIC_INFORMATION();
                int status = NtQueryInformationProcess(process.Handle, 0, ref pbi, Marshal.SizeOf(pbi), out _);
                if (status == 0)
                {
                    return pbi.InheritedFromUniqueProcessId.ToInt32();
                }
                return 0;
            }
            catch
            {
                return 0;
            }
        }

        public void Stop()
        {
            _refreshTimer.Dispose();
        }
    }
}

