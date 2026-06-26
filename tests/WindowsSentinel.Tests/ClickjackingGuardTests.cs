using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using WindowsSentinel.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace WindowsSentinel.Tests
{
    public class ClickjackingGuardTests
    {
        private (DetectionEngine engine, JsonlEventLogger logger, string tempDir) CreateTestEngine()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_cj_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);

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

            var rules = new List<IDetectionRule>();
            var engine = new DetectionEngine(
                rules, metrics, logger, responseEngine,
                iocScanner, reputationService, correlationEngine, scoringEngine
            );

            return (engine, logger, tempDir);
        }

        [Fact]
        public async Task ClickjackingGuard_StartsAndStopsCleanly()
        {
            var (engine, logger, tempDir) = CreateTestEngine();
            try
            {
                var guard = new ClickjackingGuard(engine, NullLogger<ClickjackingGuard>.Instance);

                await guard.StartAsync(CancellationToken.None);
                await Task.Delay(100);
                await guard.StopAsync(CancellationToken.None);

                engine.Stop();
                await logger.DisposeAsync();
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task ClickjackingGuard_CancellationStopsCleanly()
        {
            var (engine, logger, tempDir) = CreateTestEngine();
            try
            {
                var guard = new ClickjackingGuard(engine, NullLogger<ClickjackingGuard>.Instance);
                var cts = new CancellationTokenSource();

                await guard.StartAsync(cts.Token);
                await Task.Delay(50);
                cts.Cancel();
                await guard.StopAsync(CancellationToken.None);

                engine.Stop();
                await logger.DisposeAsync();
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public void ClipboardSanitizer_SanitizeText_DetectsRtlOverride()
        {
            var input = "invoice\u202Eexe.doc";
            var result = ClipboardSanitizer.SanitizeText(input, out bool modified);
            Assert.True(modified);
            // RTL override character should be stripped
            Assert.Equal("invoiceexe.doc", result);
        }

        [Fact]
        public void ClipboardSanitizer_SanitizeText_DetectsZeroWidth()
        {
            var input = "normal\u200Btext\u200C";
            var result = ClipboardSanitizer.SanitizeText(input, out bool modified);
            Assert.True(modified);
            Assert.Equal("normaltext", result);
        }
    }
}
