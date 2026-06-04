using System;
using System.Collections.Concurrent;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Detects data exfiltration by monitoring:
    /// - Unusually large outbound transfers from the system
    /// - Sudden spikes in bytes-sent that deviate from baseline
    /// Purely behavioral — based on transfer volume, not destinations.
    /// </summary>
    public sealed class DataExfiltrationMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DataExfiltrationMonitor> _logger;
        private long _lastBytesSent;
        private long _baselineRate; // bytes per interval
        private int _samples;

        private static readonly TimeSpan Interval = TimeSpan.FromSeconds(15);
        private const long SpikeMultiplier = 10;
        private const long MinBaselineBytes = 100_000; // 100KB baseline minimum
        private const int WarmupSamples = 10;

        public DataExfiltrationMonitor(DetectionEngine de, ILogger<DataExfiltrationMonitor> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DataExfiltrationMonitor] Started");
            _lastBytesSent = GetTotalBytesSent();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(Interval, ct);
                    var current = GetTotalBytesSent();
                    var delta = current - _lastBytesSent;
                    _lastBytesSent = current;

                    if (delta < 0) continue; // Counter wrapped

                    if (_samples < WarmupSamples)
                    {
                        // Build baseline
                        _baselineRate = (_baselineRate * _samples + delta) / (_samples + 1);
                        _samples++;
                        continue;
                    }

                    // Update rolling baseline
                    _baselineRate = (_baselineRate * 9 + delta) / 10;

                    // Check for spike
                    var threshold = Math.Max(MinBaselineBytes, _baselineRate * SpikeMultiplier);
                    if (delta > threshold)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Data Exfiltration: Outbound Volume Spike",
                            Evidence = $"Outbound data spike: {delta / 1024}KB in {Interval.TotalSeconds}s (baseline: {_baselineRate / 1024}KB)",
                            Reasoning = "A sudden spike in outbound network transfer volume was detected, significantly exceeding the established baseline. This pattern is consistent with data exfiltration.",
                            Confidence = 0.75, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.NetworkIsolate,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DataExfiltrationMonitor] Error"); }
            }
        }

        private static long GetTotalBytesSent()
        {
            long total = 0;
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    var stats = ni.GetIPv4Statistics();
                    total += stats.BytesSent;
                }
            }
            catch { }
            return total;
        }
    }
}

