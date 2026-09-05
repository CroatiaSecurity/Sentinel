using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Keeps Sentinel.Service's hot pages in RAM so LatencyMon does not
    /// attribute a stream of hard pagefaults to the service.
    ///
    /// Windows assigns services a low memory priority and trims them first when
    /// a foreground app (game, LatencyMon) runs. Touching those pages later is a
    /// hard fault. Raise priority, prefetch our image, and pin a modest minimum
    /// working set. Best-effort — never fails service start.
    /// </summary>
    public static class WorkingSetGuard
    {
        private const uint MemoryPriorityNormal = 5;
        private const int ProcessMemoryPriority = 0;
        private const int ProcessPowerThrottling = 4;
        private const uint ProcessPowerThrottlingCurrentVersion = 1;
        private const uint ProcessPowerThrottlingExecutionSpeed = 0x1;
        private const uint QuotaLimitsHardWsMinEnable = 0x00000001;
        private const uint QuotaLimitsHardWsMaxDisable = 0x00000008;
        private const long MinWorkingSetBytes = 256L * 1024 * 1024;

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_PRIORITY_INFORMATION
        {
            public uint MemoryPriority;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_POWER_THROTTLING_STATE
        {
            public uint Version;
            public uint ControlMask;
            public uint StateMask;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WIN32_MEMORY_RANGE_ENTRY
        {
            public IntPtr VirtualAddress;
            public IntPtr NumberOfBytes;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetProcessInformation(
            IntPtr hProcess, int processInformationClass, IntPtr processInformation, int processInformationSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetProcessWorkingSetSizeEx(
            IntPtr hProcess, IntPtr minSize, IntPtr maxSize, uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool PrefetchVirtualMemory(
            IntPtr hProcess, UIntPtr numberOfEntries, WIN32_MEMORY_RANGE_ENTRY[] virtualAddresses, uint flags);

        /// <summary>Memory priority + EcoQoS off + image prefetch. Safe at process start.</summary>
        public static void ApplyEarly(ILogger? logger = null)
        {
            try
            {
                var h = GetCurrentProcess();
                SetMemoryPriorityNormal(h);
                DisablePowerThrottling(h);
                PrefetchLoadedImages(h);
            }
            catch (Exception ex)
            {
                logger?.LogDebug(ex, "[WorkingSetGuard] ApplyEarly failed");
            }
        }

        /// <summary>Pin a minimum working set once the process has warmed up.</summary>
        public static void PinMinimumWorkingSet(ILogger? logger = null)
        {
            try
            {
                var h = GetCurrentProcess();
                SetMemoryPriorityNormal(h);
                long min = MinWorkingSetBytes;
                try
                {
                    using var proc = Process.GetCurrentProcess();
                    if (proc.WorkingSet64 > 0 && proc.WorkingSet64 < min)
                        min = Math.Max(proc.WorkingSet64, 32L * 1024 * 1024);
                }
                catch { /* keep default min */ }

                if (!SetProcessWorkingSetSizeEx(
                    h,
                    (IntPtr)min,
                    (IntPtr)(-1),
                    QuotaLimitsHardWsMinEnable | QuotaLimitsHardWsMaxDisable))
                {
                    SetProcessWorkingSetSizeEx(
                        h,
                        (IntPtr)(64L * 1024 * 1024),
                        (IntPtr)(-1),
                        QuotaLimitsHardWsMinEnable | QuotaLimitsHardWsMaxDisable);
                }
            }
            catch (Exception ex)
            {
                logger?.LogDebug(ex, "[WorkingSetGuard] PinMinimumWorkingSet failed");
            }
        }

        /// <summary>Re-assert memory priority. Does not empty or shrink the working set.</summary>
        public static void Refresh(ILogger? logger = null)
        {
            try
            {
                var h = GetCurrentProcess();
                SetMemoryPriorityNormal(h);
            }
            catch (Exception ex)
            {
                logger?.LogDebug(ex, "[WorkingSetGuard] Refresh failed");
            }
        }

        private static void SetMemoryPriorityNormal(IntPtr h)
        {
            var info = new MEMORY_PRIORITY_INFORMATION { MemoryPriority = MemoryPriorityNormal };
            int size = Marshal.SizeOf<MEMORY_PRIORITY_INFORMATION>();
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(info, buf, false);
                SetProcessInformation(h, ProcessMemoryPriority, buf, size);
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        private static void DisablePowerThrottling(IntPtr h)
        {
            var state = new PROCESS_POWER_THROTTLING_STATE
            {
                Version = ProcessPowerThrottlingCurrentVersion,
                ControlMask = ProcessPowerThrottlingExecutionSpeed,
                StateMask = 0
            };
            int size = Marshal.SizeOf<PROCESS_POWER_THROTTLING_STATE>();
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(state, buf, false);
                SetProcessInformation(h, ProcessPowerThrottling, buf, size);
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        private static void PrefetchLoadedImages(IntPtr h)
        {
            WIN32_MEMORY_RANGE_ENTRY[] ranges;
            try
            {
                using var proc = Process.GetCurrentProcess();
                var list = new System.Collections.Generic.List<WIN32_MEMORY_RANGE_ENTRY>(64);
                foreach (ProcessModule mod in proc.Modules)
                {
                    if (mod.BaseAddress == IntPtr.Zero || mod.ModuleMemorySize <= 0)
                        continue;
                    list.Add(new WIN32_MEMORY_RANGE_ENTRY
                    {
                        VirtualAddress = mod.BaseAddress,
                        NumberOfBytes = (IntPtr)mod.ModuleMemorySize
                    });
                }
                ranges = list.ToArray();
            }
            catch
            {
                return;
            }

            if (ranges.Length == 0) return;
            PrefetchVirtualMemory(h, (UIntPtr)ranges.Length, ranges, 0);
        }
    }
}
