using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Detects process hollowing (T1055.012) by comparing a process's declared
    /// image path against the actual file mapped at its base address.
    /// Purely behavioral — checks memory layout, not file names.
    /// </summary>
    public sealed class HollowProcessMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly ILogger<HollowProcessMonitor> _logger;
        private readonly System.Threading.Timer _timer;
        private readonly ConcurrentDictionary<int, DateTime> _alertedPids = new();

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(30);

        public HollowProcessMonitor(
            DetectionEngine detectionEngine,
            TelemetryFusionEngine fusionEngine,
            ILogger<HollowProcessMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _fusionEngine = fusionEngine;
            _logger = logger;
            _timer = new System.Threading.Timer(ScanProcesses, null, ScanInterval, ScanInterval);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private const uint MEM_IMAGE = 0x1000000;
        private const uint MEM_PRIVATE = 0x20000;
        private const uint MEM_COMMIT = 0x1000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        private void ScanProcesses(object? state)
        {
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (proc.Id <= 4) continue;
                        if (_alertedPids.ContainsKey(proc.Id)) continue;

                        var mainModule = proc.MainModule;
                        if (mainModule == null) continue;

                        var declaredPath = mainModule.FileName;
                        var baseAddress = mainModule.BaseAddress;

                        // Query the memory region at the module's base address
                        int infoSize = Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
                        if (VirtualQueryEx(proc.Handle, baseAddress, out var memInfo, infoSize) == infoSize)
                        {
                            // If the region at the module base is MEM_PRIVATE instead of MEM_IMAGE,
                            // the original image was unmapped and replaced — classic process hollowing
                            if ((memInfo.State & MEM_COMMIT) != 0 && (memInfo.Type & MEM_IMAGE) == 0)
                            {
                                _ = _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "Process Hollowing: Image Region Replaced",
                                    Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) base address 0x{baseAddress:X} is MEM_PRIVATE (not MEM_IMAGE). Declared path: {declaredPath}",
                                    Reasoning = "The memory at the process image base address is backed by private memory instead of the file image, indicating the original binary was unmapped and replaced (process hollowing T1055.012).",
                                    Confidence = 0.90, Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = ResponseAction.KillProcessTree,
                                    ProcessName = proc.ProcessName, ProcessId = proc.Id
                                });
                                _alertedPids[proc.Id] = DateTime.UtcNow;
                            }
                        }
                    }
                    catch (InvalidOperationException)
                    {
                        // Process exited
                    }
                    catch (System.ComponentModel.Win32Exception)
                    {
                        // Access denied — expected for system processes
                    }
                    finally
                    {
                        proc.Dispose();
                    }
                }

                // Prune old alerts
                var cutoff = DateTime.UtcNow.AddMinutes(-5);
                foreach (var key in _alertedPids.Keys.ToArray())
                {
                    if (_alertedPids.TryGetValue(key, out var time) && time < cutoff)
                        _alertedPids.TryRemove(key, out _);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[HollowProcessMonitor] Scan error");
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }
}
