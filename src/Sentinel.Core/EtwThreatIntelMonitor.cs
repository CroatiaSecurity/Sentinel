using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Thread-start and unbacked RWX injection scanner.
    /// Uses <see cref="NativeProcessMemory"/> (dynamic APIs). Skips game/anti-cheat paths only.
    ///
    /// KNOWN LIMITATION (v2.0.4 LOW-4): Process hollowing where an attacker overwrites the
    /// .text section of a legitimate signed binary without changing memory type (remains MEM_IMAGE)
    /// will NOT be detected by unbacked-RWX scanning. The Authenticode check on-disk will pass
    /// since the file is genuine. Detection relies on behavioral signals from other monitors
    /// (credential access, C2 beaconing, etc.) that feed into the correlation engine.
    /// Partial mitigation: memory-mapped section hash comparison (future work).
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
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(5);

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
            _logger.LogInformation(
                "[EtwThreatIntelMonitor] Started — thread/RWX injection scan (game paths skipped, APIs dynamic)");
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            _monitorTask = Task.Run(() => RunScanLoopAsync(_cts.Token));
            return Task.CompletedTask;
        }

        public async Task StopAsync()
        {
            _logger.LogInformation("[EtwThreatIntelMonitor] Stopping...");
            _cts?.Cancel();
            if (_monitorTask != null)
            {
                try { await _monitorTask; } catch { /* cancelled */ }
            }
        }

        public void Dispose() => _cts?.Dispose();

        private async Task RunScanLoopAsync(CancellationToken ct)
        {
            int cycle = 0;
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    await ScanThreadsAsync(ct);
                    cycle++;
                    if (cycle % 3 == 0)
                        await ScanForRemoteInjectionPatternsAsync(ct);
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
                if (proc.Id <= 4) { proc.Dispose(); continue; }

                try
                {
                    var name = proc.ProcessName;
                    if (AllowedJitProcesses.Contains(name + ".exe")) { proc.Dispose(); continue; }

                    var imagePath = SecurityValidation.GetProcessImagePath(proc.Id);
                    if (!NativeProcessMemory.CanInspect(proc.Id, imagePath))
                    {
                        proc.Dispose();
                        continue;
                    }

                    if (_alertedPids.TryGetValue(proc.Id, out var last) &&
                        DateTimeOffset.UtcNow - last < AlertCooldown)
                    {
                        proc.Dispose();
                        continue;
                    }

                    var modules = NativeProcessMemory.EnumModules(proc.Id);
                    if (modules.Count == 0) { proc.Dispose(); continue; }

                    var ranges = modules
                        .Where(m => m.Base != IntPtr.Zero)
                        .Select(m => (Base: (ulong)m.Base, End: (ulong)m.Base + (ulong)Math.Max(m.Size, 1)))
                        .ToList();

                    foreach (ProcessThread thread in proc.Threads)
                    {
                        if (ct.IsCancellationRequested) break;
                        IntPtr start;
                        try { start = thread.StartAddress; }
                        catch { continue; }
                        if (start == IntPtr.Zero) continue;

                        ulong sa = (ulong)start;
                        bool inside = ranges.Any(r => sa >= r.Base && sa < r.End);
                        if (inside) continue;

                        _alertedPids[proc.Id] = DateTimeOffset.UtcNow;
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Evasion: Unmapped Thread Start Address",
                            Evidence = $"Thread {thread.Id} in '{name}' (PID {proc.Id}) started at unmapped 0x{start:X}.",
                            Reasoning = "Thread entrypoint outside any loaded module indicates shellcode injection / thread hijacking.",
                            Confidence = 0.90,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            ProcessName = name,
                            ProcessId = proc.Id,
                            SignalType = SignalType.AntiTamper,
                            Metadata = new Dictionary<string, string>
                            {
                                ["ThreadId"] = thread.Id.ToString(),
                                ["StartAddress"] = $"0x{start:X}",
                                ["ImagePath"] = imagePath ?? ""
                            }
                        });

                        _contextBus?.Publish(new InjectionSignal
                        {
                            ProcessId = proc.Id,
                            ProcessName = name,
                            SourceMonitor = "EtwThreatIntelMonitor",
                            ThreadId = thread.Id,
                            StartAddress = $"0x{start:X}",
                            ImagePath = imagePath ?? ""
                        });
                        break;
                    }
                }
                catch { }
                finally
                {
                    try { proc.Dispose(); } catch { }
                }
            }
        }

        private async Task ScanForRemoteInjectionPatternsAsync(CancellationToken ct)
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                if (proc.Id <= 4) { proc.Dispose(); continue; }

                try
                {
                    var name = proc.ProcessName;
                    if (AllowedJitProcesses.Contains(name + ".exe")) { proc.Dispose(); continue; }
                    if (!IsHighValueTarget(name)) { proc.Dispose(); continue; }

                    var imagePath = SecurityValidation.GetProcessImagePath(proc.Id);
                    if (!NativeProcessMemory.CanInspect(proc.Id, imagePath))
                    {
                        proc.Dispose();
                        continue;
                    }

                    if (_alertedPids.TryGetValue(proc.Id, out var last) &&
                        DateTimeOffset.UtcNow - last < AlertCooldown)
                    {
                        proc.Dispose();
                        continue;
                    }

                    uint access = NativeProcessMemory.PROCESS_QUERY_INFORMATION | NativeProcessMemory.PROCESS_VM_READ;
                    IntPtr h = NativeProcessMemory.OpenRemoteHandle(access, proc.Id);
                    if (h == IntPtr.Zero) { proc.Dispose(); continue; }

                    try
                    {
                        var rwx = FindUnbackedRwx(h, proc.Id);
                        if (rwx.Count == 0) continue;

                        _alertedPids[proc.Id] = DateTimeOffset.UtcNow;
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Threat Intel: Remote Memory Injection (ALLOCVM_REMOTE + PROTECTVM_REMOTE)",
                            Evidence = $"Process '{name}' (PID {proc.Id}) has {rwx.Count} unbacked RWX region(s), " +
                                       $"total {rwx.Sum(r => r.Size):N0} bytes.",
                            Reasoning = "Unbacked RWX memory in a high-value process indicates remote injection (T1055).",
                            Confidence = 0.88,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            ProcessName = name,
                            ProcessId = proc.Id,
                            SignalType = SignalType.ProcessInjection,
                            Metadata = new Dictionary<string, string>
                            {
                                ["RwxRegionCount"] = rwx.Count.ToString(),
                                ["TotalRwxSize"] = rwx.Sum(r => r.Size).ToString(),
                                ["ImagePath"] = imagePath ?? ""
                            }
                        });
                    }
                    finally
                    {
                        NativeProcessMemory.CloseHandle(h);
                    }
                }
                catch { }
                finally
                {
                    try { proc.Dispose(); } catch { }
                }
            }
        }

        private static List<(long Address, long Size)> FindUnbackedRwx(IntPtr hProcess, int pid)
        {
            var results = new List<(long, long)>();
            var modules = NativeProcessMemory.EnumModules(pid);
            var ranges = modules
                .Where(m => m.Base != IntPtr.Zero)
                .Select(m => (Base: (ulong)m.Base, End: (ulong)m.Base + (ulong)Math.Max(m.Size, 1)))
                .ToList();

            IntPtr address = IntPtr.Zero;
            int scanned = 0;
            while (scanned < 10000)
            {
                scanned++;
                if (NativeProcessMemory.QueryRemoteRegion(hProcess, address, out var mbi) == 0) break;

                if (mbi.State == NativeProcessMemory.MEM_COMMIT &&
                    mbi.Type != NativeProcessMemory.MEM_IMAGE &&
                    (mbi.Protect == NativeProcessMemory.PAGE_EXECUTE_READWRITE ||
                     mbi.Protect == NativeProcessMemory.PAGE_EXECUTE_WRITECOPY))
                {
                    ulong baseAddr = (ulong)mbi.BaseAddress;
                    long size = (long)mbi.RegionSize;
                    bool inside = ranges.Any(r => baseAddr >= r.Base && baseAddr < r.End);
                    if (!inside && size > 0 && size < 100_000_000)
                        results.Add(((long)baseAddr, size));
                }

                ulong next = (ulong)mbi.BaseAddress + (ulong)mbi.RegionSize;
                if (next <= (ulong)address) break;
                address = (IntPtr)next;
            }

            return results;
        }

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
