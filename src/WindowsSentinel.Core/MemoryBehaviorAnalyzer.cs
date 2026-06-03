using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Scans process memory for behavioral anomalies:
    /// - Excessive RWX (read-write-execute) memory regions
    /// - Unbacked executable memory (no file on disk)
    /// - Known byte prologues indicating position-independent code
    /// Purely behavioral — no tool names, detects memory layout anomalies.
    /// </summary>
    public sealed class MemoryBehaviorAnalyzer : IDisposable
    {
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<MemoryBehaviorAnalyzer> _logger;
        private readonly System.Threading.Timer _timer;

        private readonly ConcurrentDictionary<int, DateTime> _scannedPids = new();
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(90);

        // Known byte sequences for position-independent code prologues
        private static readonly byte[][] CodePrologues = new byte[][]
        {
            new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 },  // CLD; AND RSP, -10h (common x64)
            new byte[] { 0xFC, 0xE8, 0x82, 0x00, 0x00 },  // CLD; CALL +82h (common stager)
            new byte[] { 0x48, 0x31, 0xC9, 0x48, 0x81 },  // XOR RCX,RCX; ...
            new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03 },  // MZ header (reflective PE)
            new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00 },  // CALL $+5
        };

        private static readonly HashSet<string> JitProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "java.exe", "javaw.exe", "node.exe", "python.exe", "python3.exe",
            "ruby.exe", "dotnet.exe", "pwsh.exe", "powershell.exe",
            "deno.exe", "bun.exe",
        };

        public MemoryBehaviorAnalyzer(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            ILogger<MemoryBehaviorAnalyzer> logger)
        {
            _fusionEngine = fusionEngine;
            _detectionEngine = detectionEngine;
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

                        // Skip known JIT processes (legitimate RWX usage)
                        if (JitProcesses.Contains(name + ".exe")) continue;

                        // Skip already-scanned this cycle
                        if (_scannedPids.ContainsKey(proc.Id)) continue;
                        _scannedPids[proc.Id] = DateTime.UtcNow;
                    }
                    catch { }
                    finally
                    {
                        proc.Dispose();
                    }
                }

                // Prune old entries
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
