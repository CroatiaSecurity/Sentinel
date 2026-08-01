using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// System-wide process integrity loop:
    /// 1. Disk-based DLL sideload unload via <see cref="DllUnloadEngine"/> (every process).
    /// 2. Lightweight hollowing signal via QUERY_LIMITED image path existence.
    ///
    /// Never opens Process.Modules / PROCESS_VM_READ (anti-cheat + AV safe).
    /// </summary>
    public sealed class MemoryBehaviorAnalyzer : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly DllUnloadEngine _dllUnloadEngine;
        private readonly ILogger<MemoryBehaviorAnalyzer> _logger;
        private readonly System.Threading.Timer _timer;

        private readonly ConcurrentDictionary<int, DateTime> _scannedPids = new();
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(45);

        public MemoryBehaviorAnalyzer(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            SignerTrustService signerTrust,
            DllUnloadEngine dllUnloadEngine,
            ILogger<MemoryBehaviorAnalyzer> logger)
        {
            _ = fusionEngine;
            _ = signerTrust;
            _detectionEngine = detectionEngine;
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

                        // Skip game / anti-cheat trees entirely
                        if (SecurityValidation.IsGameOrAntiCheatPath(path))
                            continue;

                        // === System-wide per-process DLL sideload unload (disk-based) ===
                        var unloadResult = _dllUnloadEngine
                            .CheckAndUnloadAsync(proc.Id, name)
                            .GetAwaiter().GetResult();
                        if (unloadResult.Success)
                            continue;

                        if (string.IsNullOrEmpty(path))
                            continue;

                        if (_scannedPids.ContainsKey(proc.Id))
                            continue;
                        _scannedPids[proc.Id] = DateTime.UtcNow;

                        // Hollowed process often leaves a dead image path
                        try
                        {
                            if (!File.Exists(path) &&
                                !path.StartsWith(@"\\", StringComparison.Ordinal) &&
                                path.Length > 3)
                            {
                                _ = _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "Process Hollowing: Image File Missing",
                                    Evidence = $"Process '{name}' (PID {proc.Id}) image path '{path}' does not exist on disk",
                                    Reasoning = "QUERY_LIMITED image path no longer exists — possible hollowing (T1055.012). " +
                                                "Log-only until corroboration (observe-first).",
                                    Confidence = 0.75,
                                    Tier = DetectionTier.Tier2Indicator,
                                    AuthorizedResponse = ResponseAction.LogOnly,
                                    ProcessName = name,
                                    ProcessId = proc.Id
                                });
                            }
                        }
                        catch { /* path race */ }
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
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[MemoryBehaviorAnalyzer] Scan error");
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }
}
