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
        public int RuleCount => _rules.Count;
        private readonly Channel<FusedTelemetryContext> _telemetryChannel = Channel.CreateUnbounded<FusedTelemetryContext>();
        private readonly ConcurrentDictionary<(string, int), DateTime> _dedupCache = new();
        private readonly SentinelMetrics _metrics;
        private readonly JsonlEventLogger _eventLogger;
        private readonly AdvancedResponseEngine _responseEngine;
        private readonly IoCScanner _iocScanner;
        private readonly HashReputationService _reputationService;
        private readonly BehavioralCorrelationEngine _correlationEngine;
        private readonly ScoringEngine _scoringEngine;
        private readonly CancellationTokenSource _cts = new();

        public DetectionEngine(
            IEnumerable<IDetectionRule> rules,
            SentinelMetrics metrics,
            JsonlEventLogger eventLogger,
            AdvancedResponseEngine responseEngine,
            IoCScanner iocScanner,
            HashReputationService reputationService,
            BehavioralCorrelationEngine correlationEngine,
            ScoringEngine scoringEngine)
        {
            _rules.AddRange(rules);
            _metrics = metrics;
            _eventLogger = eventLogger;
            _responseEngine = responseEngine;
            _iocScanner = iocScanner;
            _reputationService = reputationService;
            _correlationEngine = correlationEngine;
            _scoringEngine = scoringEngine;

            // Wire up the correlation engine callback
            _correlationEngine.Initialize(this.EmitAsync);

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
                    // If it is a process start, calculate process image hash and check reputations/IoCs asynchronously
                    if (context.TriggeringEvent is ProcessTelemetry pt)
                    {
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                var imagePath = pt.ImagePath;
                                if (!string.IsNullOrEmpty(imagePath) && System.IO.File.Exists(imagePath))
                                {
                                    string hash = string.Empty;
                                    using (var sha = System.Security.Cryptography.SHA256.Create())
                                    await using (var fs = System.IO.File.OpenRead(imagePath))
                                    {
                                        var hashBytes = await sha.ComputeHashAsync(fs);
                                        hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
                                    }

                                    if (!string.IsNullOrEmpty(hash))
                                    {
                                        bool isIoC = _iocScanner.IsKnownBadHash(hash);
                                        var apiVerdict = await _reputationService.GetVerdictAsync(hash);

                                        if (isIoC || apiVerdict == HashVerdict.Unsafe)
                                        {
                                            var reputationEvent = new DetectionEvent
                                            {
                                                RuleName = "IoC Scanner: Known Malicious File Hash",
                                                Evidence = $"Process '{pt.ProcessName}' (PID {pt.ProcessId}) image file hash matches known malicious reputation signature: {hash}",
                                                Reasoning = "The executed process's file hash matches a known malicious signature in the local threat intelligence IoC cache or the online reputation lookup service.",
                                                Confidence = 0.95,
                                                Tier = DetectionTier.Tier2Indicator,
                                                ProcessName = pt.ProcessName,
                                                ProcessId = pt.ProcessId,
                                                Metadata = new Dictionary<string, string> { { "SHA256", hash } }
                                            };
                                            await ProcessDetectionAsync(reputationEvent);
                                        }
                                    }
                                }
                            }
                            catch { }
                        });
                    }

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

            // Apply threat scoring
            var scoreProfile = _scoringEngine.Score(detection);
            detection.Metadata["ThreatScore"] = scoreProfile.Score.ToString();
            detection.Metadata["ThreatVerdict"] = scoreProfile.Verdict.ToString();
            
            // Adjust tier if verdict is Critical
            if (scoreProfile.Verdict == Verdict.Critical)
            {
                detection.Tier = DetectionTier.Tier1Behavioral;
                if (detection.AuthorizedResponse < ResponseAction.KillProcessTree)
                {
                    detection.AuthorizedResponse = ResponseAction.KillProcessTree;
                }
            }

            await HandleDetectionEventAsync(detection);

            // Feed to correlation engine for composite evaluations
            if (detection.Tier == DetectionTier.Tier2Indicator)
            {
                await _correlationEngine.RegisterSignalAsync(detection);
            }
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
