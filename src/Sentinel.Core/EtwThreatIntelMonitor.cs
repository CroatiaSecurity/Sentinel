using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Threat-intel style injection monitor (userland).
    ///
    /// Observe-first policy: opportunistic Process.Modules / PROCESS_VM_READ scanning
    /// is disabled — those APIs self-terminate Denuvo and other anti-cheat games.
    /// Memory inspection may be re-enabled only via
    /// <see cref="SecurityValidation.MayInspectProcessMemory"/> after independent evidence.
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
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(2);

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
                "[EtwThreatIntelMonitor] Started — invasive process-memory scans disabled (observe-first / anti-cheat safe)");
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
                try { await _monitorTask; } catch { /* cancelled */ }
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
                    // Intentionally no PROCESS_VM_READ / Modules enumeration.
                    // ETW process/network/file monitors remain the primary sensors.
                    _ = _detectionEngine;
                    _ = _fusionEngine;
                    _ = _contextBus;
                    _ = _alertedPids;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[EtwThreatIntelMonitor] Scan error");
                }
            }
        }
    }
}
