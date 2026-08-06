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
        public void BlockFcmPushChannel_DefaultsOff()
        {
            // v1.8.3: do not break Chrome push for normal users until opted in post-incident
            Assert.False(new SentinelConfig().BlockFcmPushChannel);
        }

        [Fact]
        public void TrustedCastDevices_EmptyMeansObserveNotKill()
        {
            // v1.8.3 docs in Models: empty allowlist is observe-only
            // (unless MitmDefense.Enabled — then rogue Cast IOCs are blocked)
            var cfg = new SentinelConfig();
            Assert.Empty(cfg.TrustedCastDevices);
            Assert.False(cfg.MitmDefense.Enabled);
        }

        [Fact]
        public void MitmDefense_DefaultOff_ButSuiteFieldsPresent()
        {
            var cfg = new SentinelConfig();
            Assert.False(cfg.MitmDefense.Enabled);
            Assert.True(cfg.MitmDefense.RemovePlantedCerts);
            Assert.True(cfg.MitmDefense.BlockFcmPushChannel);
            Assert.True(cfg.MitmDefense.AutoBlockRogueCast);
            Assert.Contains("B0-B3-69", cfg.MitmDefense.RogueCastMacPrefixes);
        }

        [Fact]
        public void MitmDefense_WhenEnabled_AllowsMutationsAndClassifiesActions()
        {
            var cfg = new SentinelConfig
            {
                ActiveResponse = true,
                ObserveUntilChain = true,
                MitmDefense = new MitmDefenseConfig { Enabled = true }
            };
            Assert.True(ProductPosture.AllowsMitmDefenseMutations(cfg));
            Assert.True(ResponsePolicy.MayPerformInlineHostMutation(cfg));

            var castEvt = new DetectionEvent
            {
                RuleName = "Cast Device Guard: Fake Chromecast / Rogue Cast Blocked",
                AuthorizedResponse = ResponseAction.NetworkIsolate,
                Metadata = new Dictionary<string, string> { ["MitmDefense"] = "true" }
            };
            Assert.True(ResponsePolicy.IsMitmDefenseAction(castEvt, cfg));

            var ghostEvt = new DetectionEvent
            {
                RuleName = "Ghost Process: Invisible Process → Fake Chromecast / Rogue Cast (MitM chain)",
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Metadata = new Dictionary<string, string> { ["MitmDefense"] = "true" }
            };
            Assert.True(ResponsePolicy.IsMitmDefenseAction(ghostEvt, cfg));

            var certEvt = new DetectionEvent
            {
                RuleName = "TLS: MitM Planted Root Certificate — Removing",
                AuthorizedResponse = ResponseAction.RemoveCert
            };
            Assert.True(ResponsePolicy.IsMitmDefenseAction(certEvt, cfg));
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

                var guard = new HostsFileGuard(engine, config, NullLogger<HostsFileGuard>.Instance);

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
