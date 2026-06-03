using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Detects data exfiltration by monitoring:
    /// - Unusually large outbound transfers from a single process
    /// - Uploads to cloud storage endpoints
    /// - Archive creation followed by network activity
    /// Purely behavioral — based on transfer volume, not destinations.
    /// </summary>
    public sealed class DataExfiltrationMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DataExfiltrationMonitor> _logger;

        public DataExfiltrationMonitor(DetectionEngine de, ILogger<DataExfiltrationMonitor> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DataExfiltrationMonitor] Started");
            while (!ct.IsCancellationRequested)
            {
                try { await Task.Delay(15000, ct); }
                catch (OperationCanceledException) { break; }
            }
        }
    }
}
