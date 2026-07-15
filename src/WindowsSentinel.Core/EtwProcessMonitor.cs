using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Process monitoring via ETW — now delegates to the UnifiedEtwSession.
    /// 
    /// ARCHITECTURE (v1.4.5):
    /// This monitor no longer manages its own ETW session. Instead, UnifiedEtwSession
    /// provides a single trace session subscribing to 9 providers simultaneously.
    /// EtwEventDispatcher handles event routing and telemetry conversion.
    /// 
    /// This monitor's role is now limited to:
    ///   1. Checking if UnifiedEtwSession is active
    ///   2. If active: disabling WmiProcessMonitor (prevent duplicate events)
    ///   3. If inactive: ensuring WmiProcessMonitor provides fallback coverage
    /// 
    /// LATENCY: ~50ms via ETW (when active) vs ~1-2s via WMI fallback.
    /// </summary>
    public sealed class EtwProcessMonitor : IMonitor
    {
        public string Name => "EtwProcessMonitor";

        private readonly UnifiedEtwSession _unifiedSession;
        private readonly WmiProcessMonitor? _wmiProcessMonitor;
        private readonly ILogger<EtwProcessMonitor> _logger;

        public EtwProcessMonitor(
            UnifiedEtwSession unifiedSession,
            ILogger<EtwProcessMonitor> logger,
            WmiProcessMonitor? wmiProcessMonitor = null)
        {
            _unifiedSession = unifiedSession;
            _wmiProcessMonitor = wmiProcessMonitor;
            _logger = logger;
        }

        public Task StartAsync(CancellationToken ct)
        {
            if (_unifiedSession.IsActive)
            {
                // ETW session is providing events — disable WMI to prevent duplication
                _wmiProcessMonitor?.Disable();
                _logger.LogInformation(
                    "[{Monitor}] UnifiedEtwSession is active. WMI fallback disabled. " +
                    "Process events at ~50ms latency via Kernel-Process ETW provider.", Name);
            }
            else
            {
                _logger.LogWarning(
                    "[{Monitor}] UnifiedEtwSession is NOT active. " +
                    "WmiProcessMonitor provides fallback process telemetry (~1-2s latency).", Name);
            }

            return Task.CompletedTask;
        }

        public Task StopAsync()
        {
            _logger.LogInformation("[{Monitor}] Stopped", Name);
            return Task.CompletedTask;
        }
    }
}
