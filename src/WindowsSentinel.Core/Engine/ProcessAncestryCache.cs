using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Maintains a live snapshot of the running process tree using
/// CreateToolhelp32Snapshot (no admin required).
///
/// Refreshes every 2 seconds in the background. Provides:
///   - GetParentName(pid)  — resolves a PID to its parent's process name
///   - GetAncestors(pid)   — full ancestry chain up to the root
///   - GetProcessName(pid) — resolves any PID to its process name
///
/// Used by the correlation engine and detection rules that need parent context.
/// This is what unlocks the SuspiciousParentChild detection map.
/// </summary>
public sealed class ProcessAncestryCache : IAsyncDisposable
{
    private readonly ILogger<ProcessAncestryCache> _logger;

    // pid → (name, parentPid)
    private volatile IReadOnlyDictionary<int, ProcessEntry> _snapshot =
        new Dictionary<int, ProcessEntry>();

    private Task? _refreshTask;
    private CancellationTokenSource? _cts;

    public ProcessAncestryCache(ILogger<ProcessAncestryCache> logger)
    {
        _logger = logger;
    }

    public void Start(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _refreshTask = RefreshLoopAsync(_cts.Token);
    }

    /// <summary>Returns the parent process name for a given PID, or null if unknown.</summary>
    public string? GetParentName(int pid)
    {
        var snap = _snapshot;
        if (!snap.TryGetValue(pid, out var entry)) return null;
        if (!snap.TryGetValue(entry.ParentPid, out var parent)) return null;
        return parent.Name;
    }

    /// <summary>Returns the process name for a given PID, or null if unknown.</summary>
    public string? GetProcessName(int pid)
    {
        _snapshot.TryGetValue(pid, out var entry);
        return entry?.Name;
    }

    /// <summary>
    /// Returns the full ancestry chain for a PID, from immediate parent up to root.
    /// e.g. ["winword.exe", "explorer.exe", "userinit.exe"]
    /// Stops at depth 10 to prevent cycles from PID reuse.
    /// </summary>
    public IReadOnlyList<string> GetAncestors(int pid)
    {
        var snap    = _snapshot;
        var result  = new List<string>();
        var visited = new HashSet<int>();
        int current = pid;

        for (int depth = 0; depth < 10; depth++)
        {
            if (!snap.TryGetValue(current, out var entry)) break;
            if (!visited.Add(entry.ParentPid)) break; // cycle guard

            if (!snap.TryGetValue(entry.ParentPid, out var parent)) break;
            result.Add(parent.Name);
            current = entry.ParentPid;
        }

        return result;
    }

    private async Task RefreshLoopAsync(CancellationToken cancellationToken)
    {
        // Initial snapshot immediately
        TakeSnapshot();

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
                TakeSnapshot();
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ProcessAncestryCache] Snapshot error.");
            }
        }
    }

    private void TakeSnapshot()
    {
        var dict = new Dictionary<int, ProcessEntry>();

        // Primary method: CreateToolhelp32Snapshot (fast, no admin required)
        if (!TryToolhelp32Snapshot(dict))
        {
            // Fallback: WMI/CIM query (works on Server Core/IoT where Toolhelp32 may fail)
            TryWmiSnapshot(dict);
        }

        if (dict.Count > 0)
        {
            // Atomic swap — readers always see a consistent snapshot
            _snapshot = dict;
        }
    }

    private bool TryToolhelp32Snapshot(Dictionary<int, ProcessEntry> dict)
    {
        nint hSnapshot = NativeMethods.CreateToolhelp32Snapshot(
            NativeMethods.TH32CS_SNAPPROCESS, 0);

        if (hSnapshot == NativeMethods.INVALID_HANDLE_VALUE) return false;

        try
        {
            var entry = new NativeMethods.PROCESSENTRY32
            {
                dwSize = (uint)Marshal.SizeOf<NativeMethods.PROCESSENTRY32>()
            };

            if (!NativeMethods.Process32First(hSnapshot, ref entry)) return false;

            do
            {
                dict[entry.th32ProcessID] = new ProcessEntry(
                    entry.th32ProcessID,
                    entry.th32ParentProcessID,
                    entry.szExeFile);
            }
            while (NativeMethods.Process32Next(hSnapshot, ref entry));

            return dict.Count > 0;
        }
        finally
        {
            NativeMethods.CloseHandle(hSnapshot);
        }
    }

    /// <summary>
    /// WMI/CIM fallback for Server Core, IoT, and minimal Windows installations
    /// where CreateToolhelp32Snapshot may return incomplete results.
    /// Uses Win32_Process to get (ProcessId, ParentProcessId, Name).
    /// </summary>
    private void TryWmiSnapshot(Dictionary<int, ProcessEntry> dict)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId, Name FROM Win32_Process");

            using var results = searcher.Get();
            foreach (System.Management.ManagementObject obj in results)
            {
                var pid = Convert.ToInt32(obj["ProcessId"]);
                var ppid = Convert.ToInt32(obj["ParentProcessId"]);
                var name = obj["Name"]?.ToString() ?? string.Empty;

                dict[pid] = new ProcessEntry(pid, ppid, name);
            }

            if (dict.Count > 0)
            {
                _logger.LogDebug(
                    "[ProcessAncestryCache] WMI fallback populated {Count} processes.", dict.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex,
                "[ProcessAncestryCache] WMI fallback failed (CIM may be unavailable).");
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        if (_refreshTask is not null)
        {
            try { await _refreshTask.WaitAsync(TimeSpan.FromSeconds(3)); }
            catch { /* best-effort */ }
        }
        _cts?.Dispose();
    }

    public sealed record ProcessEntry(int Pid, int ParentPid, string Name);

    private static class NativeMethods
    {
        public const uint TH32CS_SNAPPROCESS  = 0x00000002;
        public static readonly nint INVALID_HANDLE_VALUE = -1;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern nint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(nint hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool Process32First(nint hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool Process32Next(nint hSnapshot, ref PROCESSENTRY32 lppe);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PROCESSENTRY32
        {
            public uint   dwSize;
            public uint   cntUsage;
            public int    th32ProcessID;
            public nint   th32DefaultHeapID;
            public uint   th32ModuleID;
            public uint   cntThreads;
            public int    th32ParentProcessID;
            public int    pcPriClassBase;
            public uint   dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }
    }
}


