using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Tests
{
    public class HostsFileGuardTests
    {
        private static string? FindCoreSourceFile(string fileName)
        {
            // tests/Sentinel.Tests/bin/{Config}/net*/ → five levels up to repo root
            var candidates = new[]
            {
                Path.GetFullPath(Path.Combine(
                    AppContext.BaseDirectory, "..", "..", "..", "..", "..",
                    "src", "Sentinel.Core", "Monitors", fileName)),
                Path.GetFullPath(Path.Combine(
                    AppContext.BaseDirectory, "..", "..", "..", "..", "..",
                    "src", "Sentinel.Core", fileName)),
            };
            foreach (var c in candidates)
                if (File.Exists(c)) return c;
            return null;
        }

        [Fact]
        public void TrustedHostsContent_DoesNotBlockForumHr()
        {
            // v1.7.6: forum.hr hosts block removed as opinionated — ForumHrWatchMonitor watches instead.
            var sourceFile = FindCoreSourceFile("SystemIntegrityMonitors.cs");
            if (sourceFile == null) return; // CI without source tree

            var content = File.ReadAllText(sourceFile);

            // Must not contain active hosts block lines for forum.hr
            Assert.DoesNotContain("0.0.0.0 forum.hr", content);
            Assert.DoesNotContain("0.0.0.0 www.forum.hr", content);
            Assert.DoesNotContain("0.0.0.0 m.forum.hr", content);
            Assert.DoesNotContain("0.0.0.0 cdn.forum.hr", content);
            Assert.DoesNotContain("0.0.0.0 static.forum.hr", content);
            Assert.DoesNotContain("0.0.0.0 api.forum.hr", content);
            Assert.DoesNotContain("0.0.0.0 img.forum.hr", content);
            Assert.DoesNotContain("0.0.0.0 mail.forum.hr", content);
            Assert.DoesNotContain("0.0.0.0 ads.forum.hr", content);
            Assert.DoesNotContain("0.0.0.0 tracker.forum.hr", content);
        }

        [Fact]
        public void TrustedHostsContent_StillBlocksAdTrackers()
        {
            var sourceFile = FindCoreSourceFile("SystemIntegrityMonitors.cs");
            if (sourceFile == null) return;

            var content = File.ReadAllText(sourceFile);
            Assert.Contains("0.0.0.0 doubleclick.net", content);
            Assert.Contains("0.0.0.0 google-analytics.com", content);
        }

        [Fact]
        public async Task HostsFileGuard_StartsAndStopsCleanly()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_hosts_test_" + Guid.NewGuid().ToString("N")[..8]);
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
                var signerTrust = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
                var fileReputationEngine = new FileReputationEngine(reputationService, signerTrust, cache, NullLogger<FileReputationEngine>.Instance);

                var rules = new List<IDetectionRule>();
                var engine = new DetectionEngine(
                    rules, metrics, logger, responseEngine,
                    iocScanner, reputationService, fileReputationEngine, correlationEngine, scoringEngine,
                    NullLogger<DetectionEngine>.Instance
                );

                var guard = new HostsFileGuard(engine, NullLogger<HostsFileGuard>.Instance);

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
    }
}
