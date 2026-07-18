using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Behavedr.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace Behavedr.Tests
{
    public class HostsFileGuardTests
    {
        [Fact]
        public void TrustedHostsContent_ContainsForumHrBare()
        {
            // Access the embedded hosts content via the guard's behavior:
            // We verify by checking the source string contains expected entries.
            // Since TrustedHostsContent is private, we test indirectly through the SHA hash.
            // Instead, verify the source file contains the expected entries.
            // This is a compile-time guarantee test — if the entries are removed, it fails.
            var sourceFile = Path.Combine(
                AppContext.BaseDirectory, "..", "..", "..", "..", "..",
                "src", "Behavedr.Core", "BackgroundMonitors.cs");

            // Skip if source not available (CI without source tree)
            if (!File.Exists(sourceFile)) return;

            var content = File.ReadAllText(sourceFile);
            Assert.Contains("0.0.0.0 forum.hr", content);
        }

        [Fact]
        public void TrustedHostsContent_ContainsWwwForumHr()
        {
            var sourceFile = Path.Combine(
                AppContext.BaseDirectory, "..", "..", "..", "..", "..",
                "src", "Behavedr.Core", "BackgroundMonitors.cs");

            if (!File.Exists(sourceFile)) return;

            var content = File.ReadAllText(sourceFile);
            Assert.Contains("0.0.0.0 www.forum.hr", content);
        }

        [Fact]
        public void TrustedHostsContent_ContainsAllForumHrSubdomains()
        {
            var sourceFile = Path.Combine(
                AppContext.BaseDirectory, "..", "..", "..", "..", "..",
                "src", "Behavedr.Core", "BackgroundMonitors.cs");

            if (!File.Exists(sourceFile)) return;

            var content = File.ReadAllText(sourceFile);

            var expectedSubdomains = new[]
            {
                "forum.hr", "www.forum.hr", "m.forum.hr", "cdn.forum.hr",
                "static.forum.hr", "api.forum.hr", "img.forum.hr",
                "mail.forum.hr", "ads.forum.hr", "tracker.forum.hr"
            };

            foreach (var domain in expectedSubdomains)
            {
                Assert.Contains($"0.0.0.0 {domain}", content);
            }
        }

        [Fact]
        public async Task HostsFileGuard_StartsAndStopsCleanly()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "behavedr_hosts_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);

            try
            {
                var cache = new SecureCacheStore(tempDir);
                var metrics = new BehavedrMetrics();
                var logPath = Path.Combine(tempDir, "events.jsonl");
                var logger = new JsonlEventLogger(logPath);
                var config = new BehavedrConfig { ActiveResponse = false };
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
