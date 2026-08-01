using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// System-wide process integrity (observe-first):
    /// 1. DLL sideload scan via <see cref="DllUnloadEngine"/> — remediate only on proven load.
    /// 2. Module-count growth → Tier2 LogOnly (needs composites for kill).
    /// 3. Missing image path → Tier2 LogOnly.
    /// Games skipped for handle safety only. Defenses stay armed; no identity-based kills.
    /// </summary>
    public sealed class MemoryBehaviorAnalyzer : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly DllUnloadEngine _dllUnloadEngine;
        private readonly SignerTrustService _signerTrust;
        private readonly ILogger<MemoryBehaviorAnalyzer> _logger;
        private readonly System.Threading.Timer _timer;

        private readonly ConcurrentDictionary<int, DateTime> _scannedPids = new();
        private readonly ConcurrentDictionary<int, int> _previousModuleCounts = new();
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(45);
        private const int ModuleGrowthThreshold = 3;

        private static readonly HashSet<string> JitProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "java.exe", "javaw.exe", "node.exe", "python.exe", "dotnet.exe",
            "pwsh.exe", "powershell.exe", "chrome.exe", "msedge.exe", "firefox.exe",
            "brave.exe", "discord.exe", "slack.exe", "teams.exe", "spotify.exe",
            "code.exe", "cursor.exe", "steamwebhelper.exe",
            "svchost.exe", "explorer.exe", "dllhost.exe",
        };

        public MemoryBehaviorAnalyzer(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            SignerTrustService signerTrust,
            DllUnloadEngine dllUnloadEngine,
            ILogger<MemoryBehaviorAnalyzer> logger)
        {
            _ = fusionEngine;
            _detectionEngine = detectionEngine;
            _signerTrust = signerTrust;
            _dllUnloadEngine = dllUnloadEngine;
            _logger = logger;
            _timer = new System.Threading.Timer(ScanMemory, null, ScanInterval, ScanInterval);
        }

        private void ScanMemory(object? state)
        {
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (proc.Id <= 4) continue;

                        var name = proc.ProcessName;
                        var path = SecurityValidation.GetProcessImagePath(proc.Id);

                        // Workaround only: never open memory of game/anti-cheat processes
                        if (SecurityValidation.IsGameOrAntiCheatPath(path))
                            continue;

                        // System-wide + per-process DLL unload (disk + FreeLibrary APC)
                        var unloadResult = _dllUnloadEngine
                            .CheckAndUnloadAsync(proc.Id, name)
                            .GetAwaiter().GetResult();
                        if (unloadResult.Success)
                            continue;

                        if (!NativeProcessMemory.CanInspect(proc.Id, path))
                            continue;

                        // Module count growth → DLL injection
                        int currentModuleCount = -1;
                        try
                        {
                            var mods = NativeProcessMemory.EnumModules(proc.Id);
                            currentModuleCount = mods.Count;
                        }
                        catch { currentModuleCount = -1; }

                        if (currentModuleCount > 0 &&
                            _previousModuleCounts.TryGetValue(proc.Id, out int prevCount))
                        {
                            int growth = currentModuleCount - prevCount;
                            if (growth >= ModuleGrowthThreshold)
                            {
                                bool suspiciousPath = !string.IsNullOrEmpty(path) &&
                                    (path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                                     path.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase));

                                // Single-signal growth: observe. Temp/Downloads path growth is stronger
                                // but still LogOnly until response engine / composites prove malice chain.
                                _ = _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "Memory Injection: Module Count Growth Detected",
                                    Evidence = $"Process '{name}' (PID {proc.Id}) module count grew from {prevCount} to {currentModuleCount} (+{growth})",
                                    Reasoning = "Module growth can indicate DLL injection. Observe-first: LogOnly until " +
                                                "corroborated by injection/network/file composites or a President's Law rule.",
                                    Confidence = suspiciousPath ? 0.75 : 0.65,
                                    Tier = DetectionTier.Tier2Indicator,
                                    AuthorizedResponse = ResponseAction.LogOnly,
                                    ProcessName = name,
                                    ProcessId = proc.Id
                                });
                            }
                        }
                        if (currentModuleCount > 0)
                            _previousModuleCounts[proc.Id] = currentModuleCount;

                        if (_signerTrust.IsSignedProcess(proc.Id))
                            continue;

                        if (JitProcesses.Contains(name + ".exe"))
                            continue;

                        if (_scannedPids.ContainsKey(proc.Id))
                            continue;
                        _scannedPids[proc.Id] = DateTime.UtcNow;

                        // Missing image alone is weak — observe only (not kill on identity/path absence)
                        if (!string.IsNullOrEmpty(path) &&
                            !path.StartsWith(@"\\", StringComparison.Ordinal) &&
                            path.Length > 3 &&
                            !File.Exists(path))
                        {
                            _ = _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Process Hollowing: Image File Missing",
                                Evidence = $"Process '{name}' (PID {proc.Id}) image path '{path}' does not exist on disk",
                                Reasoning = "Possible hollowing indicator (T1055.012). Observe-first LogOnly until " +
                                            "corroborating behavioral signals prove malice.",
                                Confidence = 0.75,
                                Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = name,
                                ProcessId = proc.Id
                            });
                        }
                    }
                    catch (System.ComponentModel.Win32Exception) { }
                    catch (InvalidOperationException) { }
                    catch { }
                    finally
                    {
                        proc.Dispose();
                    }
                }

                var cutoff = DateTime.UtcNow.AddMinutes(-5);
                foreach (var key in _scannedPids.Keys)
                {
                    if (_scannedPids.TryGetValue(key, out var time) && time < cutoff)
                        _scannedPids.TryRemove(key, out _);
                }
                foreach (var key in _previousModuleCounts.Keys.ToArray())
                {
                    try { Process.GetProcessById(key).Dispose(); }
                    catch { _previousModuleCounts.TryRemove(key, out _); }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[MemoryBehaviorAnalyzer] Scan error");
            }
        }

        public void Dispose() => _timer.Dispose();
    }
}
