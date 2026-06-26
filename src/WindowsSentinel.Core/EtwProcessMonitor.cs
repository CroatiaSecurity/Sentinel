using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Process monitoring via ETW (Microsoft-Windows-Kernel-Process).
    /// 
    /// NOTE: The TraceEvent NuGet package was removed because it embeds injection API
    /// name strings (VirtualAllocEx, ReadProcessMemory, NtQuerySystemInformation, etc.)
    /// that cause AV heuristic false positives (Kaspersky, DeepInstinct).
    /// 
    /// This monitor now delegates entirely to WmiProcessMonitor as the process telemetry
    /// source. WMI provides the same ProcessStart events with PID, image path, command line,
    /// and parent PID — just with slightly higher latency (~1-2s vs ETW's ~50ms).
    /// </summary>
    public sealed class EtwProcessMonitor : IMonitor
    {
        public string Name => "EtwProcessMonitor";

        private readonly DetectionEngine _detectionEngine;
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly BehavioralBaselineService? _behavioralBaseline;
        private readonly WmiProcessMonitor? _wmiProcessMonitor;
        private readonly ILogger<EtwProcessMonitor> _logger;

        public EtwProcessMonitor(
            DetectionEngine detectionEngine,
            TelemetryFusionEngine fusionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<EtwProcessMonitor> logger,
            BehavioralBaselineService? behavioralBaseline = null,
            WmiProcessMonitor? wmiProcessMonitor = null)
        {
            _detectionEngine = detectionEngine;
            _fusionEngine = fusionEngine;
            _ancestryCache = ancestryCache;
            _behavioralBaseline = behavioralBaseline;
            _wmiProcessMonitor = wmiProcessMonitor;
            _logger = logger;
        }

        public Task StartAsync(CancellationToken ct)
        {
            // ETW via TraceEvent removed for AV compatibility.
            // WmiProcessMonitor provides equivalent process telemetry.
            _logger.LogInformation("[{Monitor}] ETW disabled (AV-clean mode). WmiProcessMonitor provides process telemetry.", Name);
            return Task.CompletedTask;
        }

        public Task StopAsync()
        {
            _logger.LogInformation("[{Monitor}] Stopped", Name);
            return Task.CompletedTask;
        }
    }
}
