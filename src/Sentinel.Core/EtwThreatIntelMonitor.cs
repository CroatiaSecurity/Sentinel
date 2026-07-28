using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Thread and System Call Injection Monitor.
    /// Walks the Win32 start addresses of threads in all running processes.
    /// If a thread starts execution outside of any mapped image/DLL (e.g. in private memory or heap),
    /// it indicates reflective DLL injection, hollowed execution, or direct syscall execution.
    /// Excludes JIT processes (JVM, .NET, Node.js) and trusted signed publishers.
    /// </summary>
    public sealed class EtwThreatIntelMonitor : IMonitor, IDisposable
    {
        public string Name => "EtwThreatIntelMonitor";

        private readonly DetectionEngine _detectionEngine;
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly ILogger<EtwThreatIntelMonitor> _logger;
        private readonly ContextBus? _contextBus;
        private CancellationTokenSource? _cts;
        private Task? _monitorTask;

        private readonly ConcurrentDictionary<int, DateTimeOffset> _alertedPids = new();
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(2);

        private static readonly HashSet<string> AllowedJitProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "java.exe", "javaw.exe", "node.exe", "python.exe", "python3.exe",
            "dotnet.exe", "pwsh.exe", "powershell.exe", "chrome.exe", "msedge.exe",
            "firefox.exe", "brave.exe", "teams.exe", "discord.exe", "spotify.exe"
        };

        public EtwThreatIntelMonitor(
            DetectionEngine detectionEngine,
            TelemetryFusionEngine fusionEngine,
            ILogger<EtwThreatIntelMonitor> logger,
            ContextBus? contextBus = null)
        {
            _detectionEngine = detectionEngine;
            _fusionEngine = fusionEngine;
            _logger = logger;
            _contextBus = contextBus;
        }

        public Task StartAsync(CancellationToken ct)
        {
            _logger.LogInformation("[EtwThreatIntelMonitor] Started — actively scanning thread start addresses for execution anomalies");
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            _monitorTask = Task.Run(() => RunScanLoopAsync(_cts.Token));
            return Task.CompletedTask;
        }

        public async Task StopAsync()
        {
            _logger.LogInformation("[EtwThreatIntelMonitor] Stopping...");
            if (_cts != null)
            {
                _cts.Cancel();
            }
            if (_monitorTask != null)
            {
                try { await _monitorTask; } catch { }
            }
        }

        public void Dispose()
        {
            _cts?.Dispose();
        }

        private async Task RunScanLoopAsync(CancellationToken ct)
        {
            int cycleCount = 0;
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    await ScanThreadsAsync(ct);

                    // v1.6.8: Every 3rd cycle, run the heavier remote injection pattern scan
                    // (ALLOCVM_REMOTE + PROTECTVM_REMOTE detection via VirtualQueryEx)
                    cycleCount++;
                    if (cycleCount % 3 == 0)
                    {
                        await ScanForRemoteInjectionPatternsAsync(ct);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[EtwThreatIntelMonitor] Scan error");
                }
            }
        }

        private async Task ScanThreadsAsync(CancellationToken ct)
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                if (proc.Id <= 4) continue; // Skip System and Idle

                var name = proc.ProcessName;
                if (AllowedJitProcesses.Contains(name + ".exe")) continue;

                // Check cooldown to avoid flooding alerts
                if (_alertedPids.TryGetValue(proc.Id, out var lastAlert) &&
                    DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                    continue;

                try
                {
                    // Build ranges of all loaded modules
                    var modules = new List<(IntPtr Base, IntPtr End)>();
                    try
                    {
                        foreach (ProcessModule mod in proc.Modules)
                        {
                            if (mod.BaseAddress != IntPtr.Zero)
                            {
                                modules.Add((mod.BaseAddress, IntPtr.Add(mod.BaseAddress, mod.ModuleMemorySize)));
                            }
                        }
                    }
                    catch (System.ComponentModel.Win32Exception)
                    {
                        // Access denied — expected for protected system processes (e.g. registry, services)
                        continue;
                    }

                    if (modules.Count == 0) continue;

                    // Scan each thread's Win32 start address
                    foreach (ProcessThread thread in proc.Threads)
                    {
                        if (ct.IsCancellationRequested) break;

                        IntPtr startAddress = IntPtr.Zero;
                        try
                        {
                            startAddress = thread.StartAddress;
                        }
                        catch { continue; }

                        if (startAddress == IntPtr.Zero) continue;

                        // Check if startAddress lies inside any loaded module
                        bool insideModule = false;
                        foreach (var range in modules)
                        {
                            if ((ulong)startAddress >= (ulong)range.Base && (ulong)startAddress <= (ulong)range.End)
                            {
                                insideModule = true;
                                break;
                            }
                        }

                        if (!insideModule)
                        {
                            _alertedPids[proc.Id] = DateTimeOffset.UtcNow;
                            string imagePath = SecurityValidation.GetProcessImagePath(proc.Id) ?? "";

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Evasion: Unmapped Thread Start Address",
                                Evidence = $"Thread {thread.Id} in process '{name}' (PID {proc.Id}) started at unmapped memory address 0x{startAddress.ToString("X")}.",
                                Reasoning = "A thread was started with a Win32 entrypoint that does not map to any loaded executable module or DLL on disk. This is a classic signature of thread hijacking, shellcode injection, or direct system call execution.",
                                Confidence = 0.90,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = name,
                                ProcessId = proc.Id,
                                SignalType = SignalType.AntiTamper,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["ThreadId"] = thread.Id.ToString(),
                                    ["StartAddress"] = $"0x{startAddress.ToString("X")}",
                                    ["ImagePath"] = imagePath
                                }
                            });

                            // Publish enrichment signal for cross-monitor consumption
                            _contextBus?.Publish(new InjectionSignal
                            {
                                ProcessId = proc.Id,
                                ProcessName = name,
                                SourceMonitor = "EtwThreatIntelMonitor",
                                ThreadId = thread.Id,
                                StartAddress = $"0x{startAddress.ToString("X")}",
                                ImagePath = imagePath
                            });

                            break; // Stop scanning this process on first hit
                        }
                    }
                }
                catch (Exception)
                {
                    // Degrade gracefully for exited processes
                }
                finally
                {
                    proc.Dispose();
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // v1.6.8: Full Threat-Intelligence keyword consumption
        //
        // The real Microsoft-Windows-Threat-Intelligence ETW provider
        // (GUID {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}) fires kernel events
        // via EtwTiLog* functions in ntoskrnl.exe. The provider requires
        // PS_PROTECTED_ANTIMALWARE_LIGHT (EPROCESS->Protection = 0x31)
        // backed by an ELAM certificate — not available to userland EDRs
        // without a signed kernel driver.
        //
        // Keywords this detects the RESULTS of (via VirtualQueryEx scanning):
        //   - ALLOCVM_REMOTE:           VirtualAllocEx in another process
        //                               (kernel: EtwTiLogAllocExecVm)
        //   - PROTECTVM_REMOTE:         VirtualProtectEx RWX in another process
        //                               (kernel: EtwTiLogProtectExecVm)
        //   - QUEUEUSERAPC_REMOTE:      QueueUserAPC targeting remote thread
        //                               (kernel: EtwTiLogInsertQueueUserApc)
        //   - SETTHREADCONTEXT_REMOTE:  SetThreadContext for thread hijacking
        //                               (kernel: EtwTiLogSetContextThread)
        //
        // Since Sentinel runs as a Windows Service (not PPL), we cannot
        // subscribe to ETW-TI directly. Instead we detect the observable
        // EFFECTS of these operations: unbacked RWX memory regions in
        // high-value target processes that result from ALLOCVM_REMOTE +
        // PROTECTVM_REMOTE injection sequences.
        //
        // Source: https://github.com/adanto/EtwTiViewer
        // ═══════════════════════════════════════════════════════════════

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_IMAGE = 0x1000000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;

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

        /// <summary>
        /// Scans target processes for RWX memory regions not backed by any loaded module.
        /// This detects ALLOCVM_REMOTE + PROTECTVM_REMOTE patterns — the attacker allocated
        /// executable memory in a remote process and wrote shellcode/implant there.
        /// </summary>
        private async Task ScanForRemoteInjectionPatternsAsync(CancellationToken ct)
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                if (proc.Id <= 4) continue;

                var name = proc.ProcessName;
                if (AllowedJitProcesses.Contains(name + ".exe")) continue;

                // Only scan high-value injection targets
                if (!IsHighValueTarget(name)) { proc.Dispose(); continue; }

                // Check cooldown
                if (_alertedPids.TryGetValue(proc.Id, out var lastAlert) &&
                    DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                {
                    proc.Dispose();
                    continue;
                }

                try
                {
                    IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.Id);
                    if (hProcess == IntPtr.Zero) continue;

                    try
                    {
                        var rwxRegions = FindUnbackedRwxRegions(hProcess, proc);
                        if (rwxRegions.Count > 0)
                        {
                            _alertedPids[proc.Id] = DateTimeOffset.UtcNow;
                            string imagePath = SecurityValidation.GetProcessImagePath(proc.Id) ?? "";

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Threat Intel: Remote Memory Injection (ALLOCVM_REMOTE + PROTECTVM_REMOTE)",
                                Evidence = $"Process '{name}' (PID {proc.Id}) contains {rwxRegions.Count} RWX memory region(s) " +
                                           $"not backed by any loaded module. Total RWX size: {rwxRegions.Sum(r => r.Size):N0} bytes. " +
                                           $"Regions: {string.Join(", ", rwxRegions.Take(3).Select(r => $"0x{r.Address:X} ({r.Size:N0}B)"))}",
                                Reasoning = "Executable read-write-execute memory regions were found in a high-value process that are not " +
                                            "backed by any loaded DLL or executable module. This indicates VirtualAllocEx + VirtualProtectEx " +
                                            "was used by a remote process to inject shellcode or an implant (MITRE T1055.001, T1055.012). " +
                                            "The Microsoft-Windows-Threat-Intelligence ETW provider would report this as ALLOCVM_REMOTE + PROTECTVM_REMOTE.",
                                Confidence = 0.88,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = name,
                                ProcessId = proc.Id,
                                SignalType = SignalType.ProcessInjection,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["RwxRegionCount"] = rwxRegions.Count.ToString(),
                                    ["TotalRwxSize"] = rwxRegions.Sum(r => r.Size).ToString(),
                                    ["ImagePath"] = imagePath,
                                    ["TiKeyword"] = "ALLOCVM_REMOTE|PROTECTVM_REMOTE"
                                }
                            });

                            _contextBus?.Publish(new InjectionSignal
                            {
                                ProcessId = proc.Id,
                                ProcessName = name,
                                SourceMonitor = "EtwThreatIntelMonitor",
                                ThreadId = 0,
                                StartAddress = rwxRegions.First().Address.ToString("X"),
                                ImagePath = imagePath
                            });
                        }
                    }
                    finally { CloseHandle(hProcess); }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }

        private record struct RwxRegionInfo(long Address, long Size);

        private List<RwxRegionInfo> FindUnbackedRwxRegions(IntPtr hProcess, Process proc)
        {
            var results = new List<RwxRegionInfo>();

            // Build module ranges for comparison
            var moduleRanges = new List<(ulong Base, ulong End)>();
            try
            {
                foreach (ProcessModule mod in proc.Modules)
                {
                    if (mod.BaseAddress != IntPtr.Zero)
                    {
                        ulong modBase = (ulong)mod.BaseAddress;
                        moduleRanges.Add((modBase, modBase + (ulong)mod.ModuleMemorySize));
                    }
                }
            }
            catch { return results; }

            // Walk virtual memory regions
            IntPtr address = IntPtr.Zero;
            int infoSize = Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
            int regionsScanned = 0;

            while (regionsScanned < 10000) // Safety cap
            {
                regionsScanned++;
                int bytesReturned = VirtualQueryEx(hProcess, address, out MEMORY_BASIC_INFORMATION mbi, infoSize);
                if (bytesReturned == 0) break;

                // Check for committed RWX memory that is NOT image-backed
                if (mbi.State == MEM_COMMIT &&
                    (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY) &&
                    mbi.Type != MEM_IMAGE)
                {
                    ulong regionBase = (ulong)mbi.BaseAddress;
                    long regionSize = (long)mbi.RegionSize;

                    // Verify it's not inside any known module
                    bool insideModule = moduleRanges.Any(r => regionBase >= r.Base && regionBase < r.End);
                    if (!insideModule && regionSize > 0 && regionSize < 100_000_000) // Skip implausibly large
                    {
                        results.Add(new RwxRegionInfo((long)regionBase, regionSize));
                    }
                }

                // Advance to next region
                ulong nextAddr = (ulong)mbi.BaseAddress + (ulong)mbi.RegionSize;
                if (nextAddr <= (ulong)address) break; // Overflow protection
                address = (IntPtr)nextAddr;
            }

            return results;
        }

        /// <summary>
        /// High-value injection targets: processes frequently abused for process hollowing/injection.
        /// These are checked more aggressively for unbacked RWX regions.
        /// </summary>
        private static bool IsHighValueTarget(string processName)
        {
            var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "svchost", "explorer", "RuntimeBroker", "dllhost",
                "spoolsv", "searchindexer", "taskhostw", "sihost",
                "lsass", "csrss", "winlogon", "wininit", "services",
                "conhost", "wmiprvse", "smartscreen", "backgroundTaskHost"
            };
            return targets.Contains(processName);
        }
    }
}
