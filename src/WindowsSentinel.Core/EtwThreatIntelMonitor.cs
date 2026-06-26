using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Monitors the Microsoft-Windows-Threat-Intelligence ETW provider for kernel-level
    /// injection signals (cross-process memory allocation, remote thread creation, etc.).
    /// 
    /// NOTE: The TraceEvent NuGet package was removed because it embeds injection API
    /// name strings that cause AV heuristic false positives. This monitor is now a stub
    /// that logs its unavailability. Injection detection is still provided by:
    /// - MemoryBehaviorAnalyzer (module count growth tracking)
    /// - DllUnloadEngine (sideload detection + FreeLibrary unload)
    /// - Rules.cs ThreatIntelInjectionRule (behavioral pattern matching on process events)
    /// 
    /// The ThreatIntel ETW provider also requires PPL (Protected Process Light) to receive
    /// events, which most Sentinel installations don't have — so this was largely non-functional.
    /// </summary>
    public sealed class EtwThreatIntelMonitor : IMonitor
    {
        public string Name => "EtwThreatIntelMonitor";

        private readonly DetectionEngine _detectionEngine;
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly ILogger<EtwThreatIntelMonitor> _logger;

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
            _logger.LogInformation("[{Monitor}] ETW ThreatIntel disabled (AV-clean mode). Injection detection via MemoryBehaviorAnalyzer + DllUnloadEngine.", Name);
            return Task.CompletedTask;
        }

        public Task StopAsync()
        {
            _logger.LogInformation("[{Monitor}] Stopped", Name);
            return Task.CompletedTask;
        }
    }
}
