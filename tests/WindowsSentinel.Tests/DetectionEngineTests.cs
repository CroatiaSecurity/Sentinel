using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using WindowsSentinel.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace WindowsSentinel.Tests
{
    public class DetectionEngineTests
    {
        [Fact]
        public void DetectionEngine_Rewiring_InitializesCorrectly()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_det_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                var metrics = new SentinelMetrics();
                var logPath = Path.Combine(tempDir, "events.jsonl");
                var logger = new JsonlEventLogger(logPath);
                var config = new SentinelConfig { ActiveResponse = false };
                var allowlist = new AllowlistService(cache, NullLogger<AllowlistService>.Instance);
                var responseEngine = new AdvancedResponseEngine(config, metrics, logger, new QuarantineManager(tempDir));
                var iocScanner = new IoCScanner(cache);
                var reputationService = new HashReputationService(cache, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance);
                var correlationEngine = new BehavioralCorrelationEngine();
                var scoringEngine = new ScoringEngine(allowlist, new SafeProcessExemptionRegistry(), NullLogger<ScoringEngine>.Instance);

                var rules = new List<IDetectionRule> { new LsassAccessRule() };
                var engine = new DetectionEngine(
                    rules,
                    metrics,
                    logger,
                    responseEngine,
                    iocScanner,
                    reputationService,
                    correlationEngine,
                    scoringEngine
                );

                Assert.Equal(1, engine.RuleCount);
                engine.Stop();
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }
    }
}
