using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace WindowsSentinel.Core
{
    public interface IDetectionRule
    {
        string Name { get; }
        DetectionEvent? Evaluate(FusedTelemetryContext context);
    }

    public class DetectionEngine
    {
        private readonly List<IDetectionRule> _rules = new();
        private readonly Channel<FusedTelemetryContext> _telemetryChannel = Channel.CreateUnbounded<FusedTelemetryContext>();
        private readonly ConcurrentDictionary<(string, int), DateTime> _dedupCache = new();
        private readonly SentinelMetrics _metrics;
        private readonly JsonlEventLogger _eventLogger;
        private readonly AdvancedResponseEngine _responseEngine;
        private readonly CancellationTokenSource _cts = new();

        public DetectionEngine(
            IEnumerable<IDetectionRule> rules,
            SentinelMetrics metrics,
            JsonlEventLogger eventLogger,
            AdvancedResponseEngine responseEngine)
        {
            _rules.AddRange(rules);
            _metrics = metrics;
            _eventLogger = eventLogger;
            _responseEngine = responseEngine;

            // Start background processing
            Task.Run(ProcessTelemetryQueueAsync);
        }

        public void SubmitTelemetry(FusedTelemetryContext context)
        {
            _telemetryChannel.Writer.TryWrite(context);
        }

        public async Task EmitAsync(DetectionEvent detectionEvent)
        {
            // Direct emission bypassing rules (for composite detections)
            await HandleDetectionEventAsync(detectionEvent);
        }

        private async Task ProcessTelemetryQueueAsync()
        {
            var reader = _telemetryChannel.Reader;
            while (await reader.WaitToReadAsync(_cts.Token))
            {
                while (reader.TryRead(out var context))
                {
                    foreach (var rule in _rules)
                    {
                        try
                        {
                            var startTime = DateTime.UtcNow;
                            var detection = rule.Evaluate(context);
                            var duration = (DateTime.UtcNow - startTime).TotalMilliseconds;
                            _metrics.RecordDetection(duration);

                            if (detection != null)
                            {
                                await ProcessDetectionAsync(detection);
                            }
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine($"Error running rule {rule.Name}: {ex.Message}");
                        }
                    }
                }
            }
        }

        private async Task ProcessDetectionAsync(DetectionEvent detection)
        {
            var key = (detection.RuleName, detection.ProcessId);
            var now = DateTime.UtcNow;

            // 60-second deduplication
            if (_dedupCache.TryGetValue(key, out var lastTime))
            {
                if (now - lastTime < TimeSpan.FromSeconds(60))
                {
                    return; // Suppress
                }
            }

            _dedupCache[key] = now;

            await HandleDetectionEventAsync(detection);
        }

        private async Task HandleDetectionEventAsync(DetectionEvent detection)
        {
            // Log the event
            await _eventLogger.LogEventAsync("detection", detection);

            // Forward to response engine
            await _responseEngine.HandleAsync(detection);
        }

        public void Stop()
        {
            _cts.Cancel();
        }
    }
}
