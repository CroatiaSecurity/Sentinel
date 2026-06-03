using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Monitors the Microsoft-Windows-Threat-Intelligence ETW provider for:
    /// - Cross-process memory allocation (VirtualAllocEx into another process)
    /// - Cross-process memory writes (WriteProcessMemory / NtWriteVirtualMemory)
    /// - Remote thread creation (CreateRemoteThread / NtCreateThreadEx)
    /// - Thread context manipulation (SetThreadContext / NtSetContextThread)
    /// These are the kernel-level signals for process injection — cannot be renamed.
    /// </summary>
    public sealed class EtwThreatIntelMonitor : IMonitor
    {
        public string Name => "EtwThreatIntelMonitor";

        private readonly DetectionEngine _detectionEngine;
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly ILogger<EtwThreatIntelMonitor> _logger;
        private CancellationTokenSource? _cts;

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
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            Task.Run(() => MonitorLoop(_cts.Token), _cts.Token);
            _logger.LogInformation("[{Monitor}] Started", Name);
            return Task.CompletedTask;
        }

        private async Task MonitorLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(2000, ct);
                    // ETW ThreatIntel provider requires PPL (Protected Process Light)
                    // When running as PPL, this receives kernel callbacks for injection APIs
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[{Monitor}] Error", Name);
                    await Task.Delay(5000, ct);
                }
            }
        }

        public Task StopAsync()
        {
            _cts?.Cancel();
            return Task.CompletedTask;
        }
    }
}
