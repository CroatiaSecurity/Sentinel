using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Monitors for unauthorized local TCP/UDP listeners:
    /// - Unexpected services binding to ports
    /// - Reverse shell listeners
    /// - Unauthorized web servers or proxy services
    /// Behavioral — detects new listening sockets that weren't present at baseline.
    /// </summary>
    public sealed class LocalServerMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<LocalServerMonitor> _logger;
        private readonly System.Threading.Timer _timer;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(20);

        public LocalServerMonitor(
            DetectionEngine detectionEngine,
            ILogger<LocalServerMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _timer = new System.Threading.Timer(ScanListeners, null, ScanInterval, ScanInterval);
        }

        private readonly HashSet<string> _baselineListeners = new();
        private bool _baselined;

        private void ScanListeners(object? state)
        {
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var listeners = properties.GetActiveTcpListeners();
                var current = new HashSet<string>();

                foreach (var ep in listeners)
                {
                    current.Add($"{ep.Address}:{ep.Port}");
                }

                if (!_baselined)
                {
                    foreach (var l in current) _baselineListeners.Add(l);
                    _baselined = true;
                    return;
                }

                foreach (var listener in current)
                {
                    if (_baselineListeners.Contains(listener)) continue;

                    // New listener appeared
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Network: New Local TCP Listener",
                        Evidence = $"New TCP listener detected: {listener}",
                        Reasoning = "A new TCP listener appeared that was not present at service startup. This could indicate a reverse shell listener, unauthorized web server, or C2 agent.",
                        Confidence = 0.65, Tier = DetectionTier.Tier2Indicator,
                        ProcessName = "SYSTEM", ProcessId = 0
                    });
                    _baselineListeners.Add(listener);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[LocalServerMonitor] Scan error");
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }
}
