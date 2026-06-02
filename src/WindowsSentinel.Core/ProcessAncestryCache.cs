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

        public (int parentId, string name) GetParent(int pid)
        {
            if (_cache.TryGetValue(pid, out var info))
            {
                return info;
            }
            return (0, "unknown");
        }

        /// <summary>Returns the process name for the given PID, or empty string if not found.</summary>
        public string GetProcessName(int pid)
        {
            if (_cache.TryGetValue(pid, out var info))
                return info.name;
            return string.Empty;
        }

        /// <summary>Returns the parent process name for the given PID, or empty string if not found.</summary>
        public string GetParentName(int pid)
        {
            if (_cache.TryGetValue(pid, out var info) && _cache.TryGetValue(info.parentId, out var parentInfo))
                return parentInfo.name;
            return string.Empty;
        }

        /// <summary>Returns the ancestor chain for the given PID (list of (pid, name) pairs).</summary>
        public IReadOnlyList<(int pid, string name)> GetAncestors(int pid)
        {
            var result = new List<(int, string)>();
            var visited = new HashSet<int>();
            var current = pid;
            while (current != 0 && !visited.Contains(current))
            {
                visited.Add(current);
                if (!_cache.TryGetValue(current, out var info)) break;
                result.Add((current, info.name));
                current = info.parentId;
            }
            return result;
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

