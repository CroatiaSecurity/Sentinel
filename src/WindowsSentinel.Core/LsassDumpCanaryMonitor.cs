using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Detects LSASS credential dumping by monitoring process handles to lsass.exe.
    /// Behavioral detection — watches for unauthorized processes opening handles
    /// with PROCESS_VM_READ or PROCESS_QUERY_INFORMATION to the LSASS process.
    /// No tool names used; purely runtime handle monitoring.
    /// </summary>
    public sealed class LsassDumpCanaryMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<LsassDumpCanaryMonitor> _logger;
        private readonly System.Threading.Timer _timer;
        private byte? _processTypeIndex;

        // Known legitimate processes that access LSASS (by verified path, not name alone)
        private static readonly HashSet<string> TrustedLsassAccessors = new(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\Windows\System32\lsass.exe",
            @"C:\Windows\System32\csrss.exe",
            @"C:\Windows\System32\services.exe",
            @"C:\Windows\System32\svchost.exe",
            @"C:\Windows\System32\wininit.exe",
            @"C:\ProgramData\Microsoft\Windows Defender\Platform",
        };

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(45);

        public LsassDumpCanaryMonitor(
            DetectionEngine detectionEngine,
            ILogger<LsassDumpCanaryMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _timer = new System.Threading.Timer(CheckLsassHandles, null, ScanInterval, ScanInterval);
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(
            int SystemInformationClass,
            IntPtr SystemInformation,
            int SystemInformationLength,
            ref int ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            uint dwDesiredAccess,
            bool bInheritHandle,
            int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            out IntPtr lpTargetHandle,
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwOptions);

        [DllImport("kernel32.dll")]
        private static extern int GetProcessId(IntPtr handle);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint PROCESS_DUP_HANDLE = 0x0040;
        private const uint DUPLICATE_SAME_ACCESS = 0x00000002;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
        {
            public ushort UniqueProcessId;
            public ushort CreatorBackTraceIndex;
            public byte ObjectTypeIndex;
            public byte HandleAttributes;
            public ushort HandleValue;
            public IntPtr Object;
            public uint GrantedAccess;
        }

        private static byte GetProcessObjectTypeIndex()
        {
            var selfHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, Environment.ProcessId);
            if (selfHandle == IntPtr.Zero) return 0;

            try
            {
                int bufferSize = 1024 * 1024 * 4; // Start with 4MB
                IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
                try
                {
                    int returnLength = 0;
                    int status = NtQuerySystemInformation(16, buffer, bufferSize, ref returnLength);
                    while (status == -1073741820) // STATUS_INFO_LENGTH_MISMATCH
                    {
                        Marshal.FreeHGlobal(buffer);
                        bufferSize = returnLength + 65536;
                        buffer = Marshal.AllocHGlobal(bufferSize);
                        status = NtQuerySystemInformation(16, buffer, bufferSize, ref returnLength);
                    }

                    if (status == 0) // STATUS_SUCCESS
                    {
                        long count = Marshal.ReadIntPtr(buffer).ToInt64();
                        IntPtr entryPtr = buffer + IntPtr.Size;
                        int entrySize = Marshal.SizeOf<SYSTEM_HANDLE_TABLE_ENTRY_INFO>();

                        for (long i = 0; i < count; i++)
                        {
                            var entry = Marshal.PtrToStructure<SYSTEM_HANDLE_TABLE_ENTRY_INFO>(entryPtr);
                            entryPtr += entrySize;

                            if (entry.UniqueProcessId == Environment.ProcessId && entry.HandleValue == (ushort)selfHandle)
                            {
                                return entry.ObjectTypeIndex;
                            }
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch { }
            finally
            {
                CloseHandle(selfHandle);
            }
            return 0;
        }

        private void CheckLsassHandles(object? state)
        {
            try
            {
                // Find LSASS PID
                var lsassProcs = Process.GetProcessesByName("lsass");
                if (lsassProcs.Length == 0) return;

                var lsassPid = lsassProcs[0].Id;
                foreach (var p in lsassProcs) p.Dispose();

                if (_processTypeIndex == null)
                {
                    _processTypeIndex = GetProcessObjectTypeIndex();
                }

                int bufferSize = 1024 * 1024 * 4; // Start with 4MB
                IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
                try
                {
                    int returnLength = 0;
                    int status = NtQuerySystemInformation(16, buffer, bufferSize, ref returnLength);
                    while (status == -1073741820) // STATUS_INFO_LENGTH_MISMATCH
                    {
                        Marshal.FreeHGlobal(buffer);
                        bufferSize = returnLength + 65536;
                        buffer = Marshal.AllocHGlobal(bufferSize);
                        status = NtQuerySystemInformation(16, buffer, bufferSize, ref returnLength);
                    }

                    if (status == 0) // STATUS_SUCCESS
                    {
                        long count = Marshal.ReadIntPtr(buffer).ToInt64();
                        IntPtr entryPtr = buffer + IntPtr.Size;
                        int entrySize = Marshal.SizeOf<SYSTEM_HANDLE_TABLE_ENTRY_INFO>();

                        for (long i = 0; i < count; i++)
                        {
                            var entry = Marshal.PtrToStructure<SYSTEM_HANDLE_TABLE_ENTRY_INFO>(entryPtr);
                            entryPtr += entrySize;

                            if (entry.UniqueProcessId == Environment.ProcessId || entry.UniqueProcessId <= 4)
                                continue;

                            // Filter to process handles using the resolved ObjectTypeIndex
                            if (_processTypeIndex != null && _processTypeIndex != 0 && entry.ObjectTypeIndex != _processTypeIndex)
                                continue;

                            // Check if GrantedAccess contains PROCESS_VM_READ (0x0010)
                            if ((entry.GrantedAccess & 0x0010) == 0)
                                continue;

                            var hSourceProcess = OpenProcess(PROCESS_DUP_HANDLE, false, entry.UniqueProcessId);
                            if (hSourceProcess != IntPtr.Zero)
                            {
                                if (DuplicateHandle(hSourceProcess, (IntPtr)entry.HandleValue, GetCurrentProcess(), out var hTarget, 0, false, DUPLICATE_SAME_ACCESS))
                                {
                                    int targetPid = GetProcessId(hTarget);
                                    CloseHandle(hTarget);

                                    if (targetPid == lsassPid)
                                    {
                                        // Found a process holding a read handle to LSASS!
                                        // Let's resolve its path and verify trust.
                                        string? path = null;
                                        string procName = $"PID_{entry.UniqueProcessId}";
                                        try
                                        {
                                            using var targetProc = Process.GetProcessById(entry.UniqueProcessId);
                                            procName = targetProc.ProcessName;
                                            path = targetProc.MainModule?.FileName;
                                        }
                                        catch { }

                                        bool isTrusted = false;
                                        if (path != null)
                                        {
                                            foreach (var trusted in TrustedLsassAccessors)
                                            {
                                                if (path.StartsWith(trusted, StringComparison.OrdinalIgnoreCase))
                                                {
                                                    isTrusted = true;
                                                    break;
                                                }
                                            }
                                        }

                                        if (!isTrusted)
                                        {
                                            _ = _detectionEngine.EmitAsync(new DetectionEvent
                                            {
                                                RuleName = "Credential Theft: LSASS Handle Opened",
                                                Evidence = $"Process '{procName}' (PID {entry.UniqueProcessId}) opened a handle to LSASS.exe with read permissions (path: '{path ?? "unknown"}')",
                                                Reasoning = "An unauthorized process opened a handle to LSASS with read memory access, indicating potential credential dumping.",
                                                Confidence = 0.90,
                                                Tier = DetectionTier.Tier1Behavioral,
                                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                                ProcessName = procName,
                                                ProcessId = entry.UniqueProcessId
                                            });
                                        }
                                    }
                                }
                                CloseHandle(hSourceProcess);
                            }
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[LsassDumpCanaryMonitor] Check error");
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }
}
