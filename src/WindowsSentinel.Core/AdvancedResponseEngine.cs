using System.Diagnostics;
using System.Threading.Tasks;

namespace WindowsSentinel.Core
{
    public class AdvancedResponseEngine
    {
        private readonly SentinelConfig _config;
        private readonly SentinelMetrics _metrics;
        private readonly JsonlEventLogger _eventLogger;

        public AdvancedResponseEngine(
            SentinelConfig config,
            SentinelMetrics metrics,
            JsonlEventLogger eventLogger)
        {
            _config = config;
            _metrics = metrics;
            _eventLogger = eventLogger;
        }

        public async Task HandleAsync(DetectionEvent detection)
        {
            var stopwatch = Stopwatch.StartNew();

            bool shouldKill = false;
            string reason = "LogOnly";

            if (detection.KillAuthorized && detection.Tier == DetectionTier.Tier1Behavioral)
            {
                if (_config.ActiveResponse)
                {
                    shouldKill = true;
                    reason = $"Killed (AuthorizedResponse={detection.AuthorizedResponse})";
                }
                else
                {
                    reason = "LogOnly (ActiveResponse disabled)";
                }
            }
            else if (detection.Tier == DetectionTier.Tier1Behavioral)
            {
                reason = "LogOnly (Tier1 without kill authorization)";
            }
            else
            {
                reason = "LogOnly (Tier2 Indicator)";
            }

            if (shouldKill && detection.ProcessId > 4)
            {
                HardeningModule.SafeKillProcessTree(detection.ProcessId);

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "KILL",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
            }
            else
            {
                stopwatch.Stop();
                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "LOG",
                    Reason = reason,
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
            }
        }
    }
}
