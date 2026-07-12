using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using WindowsSentinel.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace WindowsSentinel.Tests.Monitors
{
    public class ConsultantSignalIngestorTests
    {
        [Fact]
        public async Task Ingestor_TailsJsonlFile_SubmitsToDetectionEngine()
        {
            // Setup temp directories
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_consultant_test_" + Guid.NewGuid().ToString("N")[..8]);
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
                    rules,
                    metrics,
                    logger,
                    responseEngine,
                    iocScanner,
                    reputationService,
                    fileReputationEngine,
                    correlationEngine,
                    scoringEngine,
                    NullLogger<DetectionEngine>.Instance
                );

                var ingestor = new ConsultantSignalIngestor(engine, NullLogger<ConsultantSignalIngestor>.Instance, tempDir);

                using var cts = new CancellationTokenSource();
                await ingestor.StartAsync(cts.Token);

                // Write a sample detection event to a JSONL file in tempDir
                var consultantFile = Path.Combine(tempDir, "DragonBreathHunter.jsonl");
                var sampleEvent = new DetectionEvent
                {
                    RuleName = "DragonBreathHunter",
                    Evidence = "Gh0st RAT C2 connection detected",
                    Reasoning = "Outbound connection to known C2 server",
                    Confidence = 0.85,
                    ProcessName = "rustdesk.exe",
                    ProcessId = 1234
                };

                var jsonLine = JsonSerializer.Serialize(sampleEvent);
                await File.WriteAllTextAsync(consultantFile, jsonLine + Environment.NewLine);

                // Wait a moment for file watcher to pick it up and process it
                int waitRetries = 30;
                bool found = false;
                while (waitRetries > 0)
                {
                    await Task.Delay(100);
                    if (File.Exists(logPath))
                    {
                        try
                        {
                            using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            var content = await sr.ReadToEndAsync();
                            if (content.Contains("DragonBreathHunter"))
                            {
                                found = true;
                                break;
                            }
                        }
                        catch
                        {
                            // Ignore lock attempt failures in poll loop
                        }
                    }
                    waitRetries--;
                }

                Assert.True(found, "The consultant signal was not processed and written to the log.");

                // Stop the services
                cts.Cancel();
                await ingestor.StopAsync(CancellationToken.None);
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
