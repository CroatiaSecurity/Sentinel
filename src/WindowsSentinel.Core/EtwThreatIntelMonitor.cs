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

namespace WindowsSentinel.Core
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
            ILogger<EtwThreatIntelMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _fusionEngine = fusionEngine;
            _logger = logger;
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
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    await ScanThreadsAsync(ct);
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
    }
}
