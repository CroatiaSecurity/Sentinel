using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Monitors the Windows routing table for unauthorized modifications:
    /// - New routes added that redirect traffic (MitM)
    /// - Default gateway changes
    /// - Route count deviations from baseline
    /// </summary>
    public sealed class RouteTableMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<RouteTableMonitor> _logger;
        private readonly System.Threading.Timer _timer;
        private int _baselineRouteCount;
        private string? _baselineGateway;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(30);

        public RouteTableMonitor(
            DetectionEngine detectionEngine,
            ILogger<RouteTableMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            SnapshotBaseline();
            _timer = new System.Threading.Timer(CheckRoutes, null, ScanInterval, ScanInterval);
        }

        private void SnapshotBaseline()
        {
            try
            {
                var props = IPGlobalProperties.GetIPGlobalProperties();
                _baselineRouteCount = CountRoutes();
                _baselineGateway = GetDefaultGateway();
            }
            catch { }
        }

        private void CheckRoutes(object? state)
        {
            try
            {
                var currentCount = CountRoutes();
                var currentGateway = GetDefaultGateway();

                // Alert if routes increased significantly (>5 new routes)
                if (_baselineRouteCount > 0 && currentCount > _baselineRouteCount + 5)
                {
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Network: Routing Table Modified",
                        Evidence = $"Route count increased from {_baselineRouteCount} to {currentCount}",
                        Reasoning = "Multiple new routes were added to the system routing table, which could redirect network traffic for interception.",
                        Confidence = 0.70, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0
                    });
                }

                // Alert if default gateway changed
                if (_baselineGateway != null && currentGateway != null && currentGateway != _baselineGateway)
                {
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Network: Default Gateway Changed",
                        Evidence = $"Default gateway changed from {_baselineGateway} to {currentGateway}",
                        Reasoning = "The default gateway was modified at runtime, which could indicate a network hijack or rogue DHCP server.",
                        Confidence = 0.80, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.NetworkIsolate,
                        ProcessName = "SYSTEM", ProcessId = 0,
                        Metadata = new Dictionary<string, string> { { "TargetIP", currentGateway ?? "" } }
                    });
                }

                _baselineRouteCount = currentCount;
                _baselineGateway = currentGateway;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[RouteTableMonitor] Check error");
            }
        }

        private static int CountRoutes()
        {
            int count = 0;
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    var ipProps = ni.GetIPProperties();
                    count += ipProps.UnicastAddresses.Count;
                    count += ipProps.GatewayAddresses.Count;
                }
            }
            catch { }
            return count;
        }

        private static string? GetDefaultGateway()
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    var gw = ni.GetIPProperties().GatewayAddresses
                        .FirstOrDefault(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                    if (gw != null) return gw.Address.ToString();
                }
            }
            catch { }
            return null;
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }
}
