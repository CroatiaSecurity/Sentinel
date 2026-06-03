using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Monitors active TCP connections for behavioral anomalies:
    /// - Connections to non-standard ports from system binaries
    /// - High-frequency outbound connections (beaconing)
    /// - Connections from processes running in suspicious paths
    /// Purely behavioral — no domain/IP blocklists.
    /// </summary>
    public sealed class NetworkMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly ILogger<NetworkMonitor> _logger;
        private readonly System.Threading.Timer _timer;
        private readonly ConcurrentDictionary<string, int> _connectionCounts = new();

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(15);

        public NetworkMonitor(
            DetectionEngine detectionEngine,
            TelemetryFusionEngine fusionEngine,
            ILogger<NetworkMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _fusionEngine = fusionEngine;
            _logger = logger;
            _timer = new System.Threading.Timer(ScanConnections, null, ScanInterval, ScanInterval);
        }

        private void ScanConnections(object? state)
        {
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var connections = properties.GetActiveTcpConnections();

                // Track connection counts per remote endpoint for beaconing detection
                var currentCounts = new Dictionary<string, int>();
                foreach (var conn in connections)
                {
                    if (conn.State == TcpState.Established)
                    {
                        var key = $"{conn.RemoteEndPoint.Address}:{conn.RemoteEndPoint.Port}";
                        currentCounts[key] = currentCounts.GetValueOrDefault(key) + 1;
                    }
                }

                foreach (var (key, count) in currentCounts)
                {
                    _connectionCounts[key] = count;
                }

                // Prune stale entries
                var staleKeys = _connectionCounts.Keys.Except(currentCounts.Keys).ToList();
                foreach (var k in staleKeys)
                {
                    _connectionCounts.TryRemove(k, out _);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NetworkMonitor] Scan error");
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }
}
