using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

namespace WindowsSentinel.Core
{
    public class ProcessAncestryCache : IDisposable
    {
        private volatile IReadOnlyDictionary<int, (int parentId, string name, string imagePath)> _cache = new Dictionary<int, (int, string, string)>();
        private readonly System.Threading.Timer _refreshTimer;

        // HARDENING: Track PIDs injected by RecordProcessStart (ETW/WMI/fast-poll sourced).
        // These are NEVER overwritten by the periodic refresh — they contain authoritative
        // data captured at process creation time. The refresh only ADDS new PIDs.
        private readonly ConcurrentDictionary<int, (int parentId, string name, string imagePath, DateTimeOffset recordedAt)> _authoritativeEntries = new();

        // HARDENING: Retain dead process entries for 60 seconds after they exit.
        // ChainTracer needs to walk the parent chain AFTER a malicious process is killed.
        // Without retention, the chain trace fails because the PID is already gone.
        private readonly ConcurrentDictionary<int, DateTimeOffset> _deadPidRetention = new();
        private static readonly TimeSpan DeadPidRetentionDuration = TimeSpan.FromSeconds(60);

        public ProcessAncestryCache()
        {
            RefreshCache();
            // Refreshed every 5 seconds (as per v4.8.1 optimization)
            _refreshTimer = new System.Threading.Timer(_ => RefreshCache(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        }

        private void RefreshCache()
        {
            try
            {
                var processes = Process.GetProcesses();
                var currentCache = _cache;
                var livingPids = new HashSet<int>();
                var newCache = new Dictionary<int, (int parentId, string name, string imagePath)>();

                // 1. Always preserve authoritative entries (ETW/WMI/fast-poll sourced)
                foreach (var kvp in _authoritativeEntries)
                {
                    newCache[kvp.Key] = (kvp.Value.parentId, kvp.Value.name, kvp.Value.imagePath);
                }

                // 2. Add currently running processes (only if not already in authoritative set)
                foreach (var proc in processes)
                {
                    var pid = proc.Id;
                    livingPids.Add(pid);

                    if (newCache.ContainsKey(pid))
                    {
                        // Already have authoritative data — don't overwrite
                        proc.Dispose();
                        continue;
                    }

                    if (currentCache.TryGetValue(pid, out var existing))
                    {
                        newCache[pid] = existing;
                        proc.Dispose();
                    }
                    else
                    {
                        try
                        {
                            var parentId = GetParentProcessId(proc);
                            var imagePath = SecurityValidation.GetProcessImagePath(pid) ?? "";
                            newCache[pid] = (parentId, proc.ProcessName, imagePath);
                            proc.Dispose();
                        }
                        catch
                        {
                            proc.Dispose();
                        }
                    }
                }

                // 3. Retain dead PIDs for chain tracing (60s after death)
                var now = DateTimeOffset.UtcNow;

                // Mark newly dead PIDs (were in cache but not in living set)
                foreach (var pid in currentCache.Keys)
                {
                    if (!livingPids.Contains(pid) && pid > 4)
                    {
                        _deadPidRetention.TryAdd(pid, now);
                    }
                }

                // Keep recently-dead PIDs in the cache for chain tracing
                foreach (var kvp in _deadPidRetention)
                {
                    if (now - kvp.Value < DeadPidRetentionDuration)
                    {
                        // Still within retention window — keep in cache if we have data
                        if (!newCache.ContainsKey(kvp.Key) && currentCache.TryGetValue(kvp.Key, out var deadInfo))
                        {
                            newCache[kvp.Key] = deadInfo;
                        }
                    }
                    else
                    {
                        // Expired — remove from retention tracking
                        _deadPidRetention.TryRemove(kvp.Key, out _);
                    }
                }

                // 4. Prune authoritative entries for PIDs dead longer than retention window
                foreach (var pid in _authoritativeEntries.Keys.ToArray())
                {
                    if (!livingPids.Contains(pid) &&
                        _deadPidRetention.TryGetValue(pid, out var deathTime) &&
                        now - deathTime >= DeadPidRetentionDuration)
                    {
                        _authoritativeEntries.TryRemove(pid, out _);
                    }
                    else if (!livingPids.Contains(pid) && !_deadPidRetention.ContainsKey(pid))
                    {
                        // Dead but not tracked yet — start tracking
                        _deadPidRetention.TryAdd(pid, now);
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
            // Record as authoritative — this data came from ETW/WMI/fast-poll at creation time
            // and will NOT be overwritten by the periodic refresh.
            _authoritativeEntries[pid] = (parentPid, processName, imagePath ?? "", DateTimeOffset.UtcNow);

            // Also inject into the live cache immediately for instant availability
            var dict = new Dictionary<int, (int, string, string)>((Dictionary<int, (int, string, string)>)_cache);
            dict[pid] = (parentPid, processName, imagePath ?? "");
            _cache = dict;
        }

        public (int parentId, string name) GetParent(int pid)
        {
            if (_cache.TryGetValue(pid, out var info))
            {
                var parentId = info.parentId;
                string parentName = "unknown";
                if (parentId > 0 && _cache.TryGetValue(parentId, out var parentInfo))
                {
                    parentName = parentInfo.name;
                }
                return (parentId, parentName);
            }
            return (0, "unknown");
        }

        public (int parentId, string name, string imagePath) GetProcessInfo(int pid)
        {
            if (_cache.TryGetValue(pid, out var info))
            {
                return info;
            }
            
            // Fallback to live query
            string? livePath = null;
            try { livePath = SecurityValidation.GetProcessImagePath(pid); } catch {}
            return (0, "unknown", livePath ?? "");
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
            Dispose();
        }

        public void Dispose()
        {
            _refreshTimer.Dispose();
        }
    }
}

