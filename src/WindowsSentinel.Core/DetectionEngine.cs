using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

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
        private readonly FileReputationEngine _fileReputationEngine;
        private readonly BehavioralCorrelationEngine _correlationEngine;
        private readonly ScoringEngine _scoringEngine;
        private readonly ILogger<DetectionEngine> _logger;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _processingTask;

        public DetectionEngine(
            IEnumerable<IDetectionRule> rules,
            SentinelMetrics metrics,
            JsonlEventLogger eventLogger,
            AdvancedResponseEngine responseEngine,
            IoCScanner iocScanner,
            HashReputationService reputationService,
            FileReputationEngine fileReputationEngine,
            BehavioralCorrelationEngine correlationEngine,
            ScoringEngine scoringEngine,
            ILogger<DetectionEngine> logger)
        {
            _rules.AddRange(rules);
            _metrics = metrics;
            _eventLogger = eventLogger;
            _responseEngine = responseEngine;
            _iocScanner = iocScanner;
            _reputationService = reputationService;
            _fileReputationEngine = fileReputationEngine;
            _correlationEngine = correlationEngine;
            _scoringEngine = scoringEngine;
            _logger = logger;

            // Wire up the correlation engine callback
            _correlationEngine.Initialize(this.EmitAsync);

            // Start background processing
            _processingTask = Task.Run(ProcessTelemetryQueueAsync);
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

        public async Task SubmitConsultantSignalAsync(DetectionEvent detectionEvent)
        {
            if (detectionEvent == null) return;
            detectionEvent.Tier = DetectionTier.Tier2Indicator;
            if (detectionEvent.Metadata == null)
            {
                detectionEvent.Metadata = new Dictionary<string, string>();
            }
            await ProcessDetectionAsync(detectionEvent);
        }

        private async Task ProcessTelemetryQueueAsync()
        {
            try
            {
                var reader = _telemetryChannel.Reader;
                while (await reader.WaitToReadAsync(_cts.Token))
                {
                    while (reader.TryRead(out var context))
                    {
                        try
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
                                            // v1.3.1: Use multi-signal FileReputationEngine for on-execute verdicts
                                            var repoResult = await _fileReputationEngine.EvaluateFileAsync(imagePath, _cts.Token);

                                            // Also check local IoC cache for immediate known-bad
                                            string hash = repoResult.Sha256;
                                            bool isIoC = !string.IsNullOrEmpty(hash) && _iocScanner.IsKnownBadHash(hash);

                                            if (isIoC || repoResult.Verdict == FileVerdict.Malicious)
                                            {
                                                var reputationEvent = new DetectionEvent
                                                {
                                                    RuleName = "File Reputation: Malicious Binary Executed",
                                                    Evidence = $"Process '{pt.ProcessName}' (PID {pt.ProcessId}) binary scored {repoResult.CompositeScore}/100 " +
                                                               $"(Verdict: {repoResult.Verdict}, SHA256: {hash})",
                                                    Reasoning = "The executed binary's composite reputation score exceeds the malicious threshold. " +
                                                                "Score is derived from hash reputation (CIRCL + MalwareBazaar + VirusTotal), " +
                                                                "static PE analysis (entropy, imports, packing), signer trust, and contextual risk.",
                                                    Confidence = 0.95,
                                                    Tier = DetectionTier.Tier1Behavioral,
                                                    AuthorizedResponse = ResponseAction.KillProcessTree,
                                                    ProcessName = pt.ProcessName,
                                                    ProcessId = pt.ProcessId,
                                                    SignalType = SignalType.SuspiciousProcess,
                                                    Metadata = new Dictionary<string, string>
                                                    {
                                                        { "SHA256", hash },
                                                        { "CompositeScore", repoResult.CompositeScore.ToString() },
                                                        { "FileVerdict", repoResult.Verdict.ToString() },
                                                        { "Signed", repoResult.IsSigned.ToString() },
                                                        { "Entropy", repoResult.StaticAnalysis.Entropy.ToString("F2") }
                                                    }
                                                };
                                                await ProcessDetectionAsync(reputationEvent);
                                            }
                                            else if (repoResult.Verdict == FileVerdict.HighRisk)
                                            {
                                                var reputationEvent = new DetectionEvent
                                                {
                                                    RuleName = "File Reputation: High-Risk Binary Executed",
                                                    Evidence = $"Process '{pt.ProcessName}' (PID {pt.ProcessId}) binary scored {repoResult.CompositeScore}/100 " +
                                                               $"(Verdict: {repoResult.Verdict}, Signed: {repoResult.IsSigned})",
                                                    Reasoning = "The binary's reputation score indicates high risk based on multi-signal analysis. " +
                                                                "Flagged by one or more threat intelligence sources or exhibits suspicious static properties.",
                                                    Confidence = 0.80,
                                                    Tier = DetectionTier.Tier1Behavioral,
                                                    AuthorizedResponse = ResponseAction.KillProcess,
                                                    ProcessName = pt.ProcessName,
                                                    ProcessId = pt.ProcessId,
                                                    SignalType = SignalType.SuspiciousProcess,
                                                    Metadata = new Dictionary<string, string>
                                                    {
                                                        { "SHA256", hash },
                                                        { "CompositeScore", repoResult.CompositeScore.ToString() },
                                                        { "FileVerdict", repoResult.Verdict.ToString() }
                                                    }
                                                };
                                                await ProcessDetectionAsync(reputationEvent);
                                            }
                                            else if (repoResult.Verdict == FileVerdict.Suspicious)
                                            {
                                                var reputationEvent = new DetectionEvent
                                                {
                                                    RuleName = "File Reputation: Suspicious Binary Executed",
                                                    Evidence = $"Process '{pt.ProcessName}' (PID {pt.ProcessId}) binary scored {repoResult.CompositeScore}/100 " +
                                                               $"(Unknown to reputation DBs, Entropy: {repoResult.StaticAnalysis.Entropy:F2})",
                                                    Reasoning = "The binary is unknown to all reputation sources and exhibits some suspicious characteristics. " +
                                                                "Logged as a Tier2 indicator to feed the correlation engine.",
                                                    Confidence = 0.55,
                                                    Tier = DetectionTier.Tier2Indicator,
                                                    AuthorizedResponse = ResponseAction.LogOnly,
                                                    ProcessName = pt.ProcessName,
                                                    ProcessId = pt.ProcessId,
                                                    SignalType = SignalType.SuspiciousProcess,
                                                    Metadata = new Dictionary<string, string>
                                                    {
                                                        { "SHA256", hash },
                                                        { "CompositeScore", repoResult.CompositeScore.ToString() },
                                                        { "FileVerdict", repoResult.Verdict.ToString() }
                                                    }
                                                };
                                                await ProcessDetectionAsync(reputationEvent);
                                            }
                                        }
                                    }
                                    catch (OperationCanceledException) { }
                                    catch (Exception ex)
                                    {
                                        _logger.LogError(ex, "[DetectionEngine] Error checking process reputation for {ProcessName} (PID {ProcessId})", pt.ProcessName, pt.ProcessId);
                                    }
                                }, _cts.Token);
                            }

                            foreach (var rule in _rules)
                            {
                                try
                                {
                                    var startTime = DateTime.UtcNow;
                                    var detection = rule.Evaluate(context);

                                    if (detection != null)
                                    {
                                        var duration = (DateTime.UtcNow - startTime).TotalMilliseconds;
                                        _metrics.RecordDetection(duration);
                                        await ProcessDetectionAsync(detection);
                                    }
                                }
                                catch (Exception ex)
                                {
                                    _logger.LogError(ex, "[DetectionEngine] Error running rule {RuleName}", rule.Name);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "[DetectionEngine] Error processing telemetry context item");
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "[DetectionEngine] Critical error in telemetry queue processing loop");
            }
        }

        private async Task ProcessDetectionAsync(DetectionEvent detection)
        {
            var key = (detection.RuleName, detection.ProcessId);
            var now = DateTime.UtcNow;

            // HARDENING v1.3.0: Reduced dedup window from 60s to 10s for Tier1 detections.
            // Previously, an attacker could trigger one alert and then operate freely for 60s
            // knowing the same rule wouldn't fire again. Tier2 indicators keep 30s dedup
            // to reduce noise, but Tier1 behavioral detections need rapid re-alerting.
            var dedupWindow = detection.Tier == DetectionTier.Tier1Behavioral
                ? TimeSpan.FromSeconds(10)
                : TimeSpan.FromSeconds(30);

            var lastTime = _dedupCache.AddOrUpdate(key, now, (k, oldTime) =>
                now - oldTime < dedupWindow ? oldTime : now);

            if (lastTime != now)
            {
                return; // Suppressed by existing recent entry
            }

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
            try
            {
                _processingTask?.Wait(2000);
            }
            catch { }
        }
    }
}
