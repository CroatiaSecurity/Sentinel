using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace WindowsSentinel.Core
{
    public class AppNetworkPolicyMonitor : IDisposable
    {
        private readonly DateTime _startTime = DateTime.UtcNow;
        private readonly ConcurrentDictionary<string, HashSet<string>> _processSubnets = new();
        private readonly DetectionEngine _detectionEngine;
        private readonly System.Threading.Timer _timer;

        private const int LearningPhaseDurationMinutes = 30;
        private const int MaxSubnetsPerProcess = 1000;
        private const int MaxProcesses = 5000;

        private static readonly HashSet<string> NetworkAllowlist = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "msedgewebview2",
            "svchost", "lsass", "sihost", "taskhostw", "RuntimeBroker", "SystemSettings"
        };

        public AppNetworkPolicyMonitor(DetectionEngine detectionEngine)
        {
            _detectionEngine = detectionEngine;
            // Scan TCP connections every 30 seconds
            _timer = new System.Threading.Timer(ScanNetworkConnections, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
        }

        private void ScanNetworkConnections(object? state)
        {
            // In a real system, we P/Invoke GetExtendedTcpTable.
            // Under this stub/implementation, we feed mock network connections or queries.
        }

        public void RegisterConnection(int pid, string processName, string remoteAddress)
        {
            if (string.IsNullOrWhiteSpace(remoteAddress)) return;

            var stem = processName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase);
            if (NetworkAllowlist.Contains(stem)) return;

            // Determine /24 subnet
            var parts = remoteAddress.Split('.');
            if (parts.Length != 4) return; // IPv4 only for simple learning
            var subnet = $"{parts[0]}.{parts[1]}.{parts[2]}.0";

            if (_processSubnets.Count >= MaxProcesses && !_processSubnets.ContainsKey(processName))
            {
                // Prune or reject new processes to prevent memory exhaustion
                return;
            }

            var subnets = _processSubnets.GetOrAdd(processName, _ => new HashSet<string>());

            lock (subnets)
            {
                if (DateTime.UtcNow - _startTime < TimeSpan.FromMinutes(LearningPhaseDurationMinutes))
                {
                    // Learning phase: record subnet
                    if (subnets.Count < MaxSubnetsPerProcess)
                    {
                        subnets.Add(subnet);
                    }
                }
                else
                {
                    // Enforcement phase: alert on new subnet
                    if (!subnets.Contains(subnet))
                    {
                        EmitPolicyAlert(pid, processName, remoteAddress, subnet);
                        
                        // Add it to prevent alert flood
                        if (subnets.Count < MaxSubnetsPerProcess)
                        {
                            subnets.Add(subnet);
                        }
                    }
                }
            }
        }

        private void EmitPolicyAlert(int pid, string processName, string ipAddress, string subnet)
        {
            var alert = new DetectionEvent
            {
                RuleName = "Network Policy: Unusual Destination",
                ProcessName = processName,
                ProcessId = pid,
                Confidence = 0.55,
                Tier = DetectionTier.Tier2Indicator,
                Evidence = $"Process '{processName}' connected to unfamiliar /24 subnet: {subnet} (IP: {ipAddress})",
                Reasoning = "Outbound network connection to a subnet not baselined during the initial 30-minute learning phase.",
                Metadata = new Dictionary<string, string>
                {
                    { "RemoteIp", ipAddress },
                    { "Subnet", subnet }
                }
            };

            _ = _detectionEngine.EmitAsync(alert);
        }

        public void Dispose()
        {
            _timer.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
