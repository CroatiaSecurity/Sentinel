using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using WindowsSentinel.Core;

namespace WindowsSentinel.Tests
{
    public class AdvancedResponseEngineTests
    {
        [Fact]
        public async Task HandleAsync_Tier2CertificateDetection_DoesNotTriggerAction()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_are_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            try
            {
                var config = new SentinelConfig { ActiveResponse = true };
                var metrics = new SentinelMetrics();
                var logPath = Path.Combine(tempDir, "events.jsonl");
                var logger = new JsonlEventLogger(logPath);
                var quarantine = new QuarantineManager(tempDir);
                var engine = new AdvancedResponseEngine(config, metrics, logger, quarantine);

                // Emitted event with Tier2 and RemoveCertAndKillAdder response
                var detection = new DetectionEvent
                {
                    RuleName = "TLS: Suspicious Root Certificate Detected",
                    Evidence = "Suspicious certificate added",
                    Reasoning = "Testing tier 2 block",
                    Confidence = 0.90,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.RemoveCertAndKillAdder,
                    ProcessName = "powershell.exe",
                    ProcessId = 1234,
                    Metadata = new Dictionary<string, string>
                    {
                        { "CertThumbprint", "1234567890ABCDEF1234567890ABCDEF12345678" },
                        { "AdderProcessId", "1234" }
                    }
                };

                await engine.HandleAsync(detection);
                await logger.DisposeAsync();

                // Read logged response event
                var logLines = await File.ReadAllLinesAsync(logPath);
                bool foundAction = false;
                bool foundLogOnly = false;

                foreach (var line in logLines)
                {
                    if (line.Contains("\"ActionTaken\":\"REMOVE_CERT_AND_KILL_ADDER\""))
                    {
                        foundAction = true;
                    }
                    if (line.Contains("\"ActionTaken\":\"LOG\""))
                    {
                        foundLogOnly = true;
                    }
                }

                Assert.False(foundAction, "Active response action was taken on Tier2 Indicator, which violates the security contract.");
                Assert.True(foundLogOnly, "Expected LOG action for Tier2 Indicator.");
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task HandleAsync_Tier1CertificateDetection_TriggersAction()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_are_test2_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            try
            {
                var config = new SentinelConfig { ActiveResponse = true };
                var metrics = new SentinelMetrics();
                var logPath = Path.Combine(tempDir, "events.jsonl");
                var logger = new JsonlEventLogger(logPath);
                var quarantine = new QuarantineManager(tempDir);
                var engine = new AdvancedResponseEngine(config, metrics, logger, quarantine);

                // Emitted event with Tier1 and RemoveCert response (note: President's law rule hit)
                var detection = new DetectionEvent
                {
                    RuleName = "TLS: Fake President's Law Rule", // Rule name must trigger IsPresidentsLawRule to remain Tier1
                    Evidence = "Suspicious certificate added",
                    Reasoning = "Testing tier 1 execution",
                    Confidence = 0.90,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.RemoveCert,
                    ProcessName = "powershell.exe",
                    ProcessId = 1234,
                    Metadata = new Dictionary<string, string>
                    {
                        { "CertThumbprint", "1234567890ABCDEF1234567890ABCDEF12345678" }
                    }
                };

                await engine.HandleAsync(detection);
                await logger.DisposeAsync();

                // Read logged response event
                var logLines = await File.ReadAllLinesAsync(logPath);
                bool foundRemoveCertAction = false;

                foreach (var line in logLines)
                {
                    if (line.Contains("\"ActionTaken\":\"REMOVE_CERT\""))
                    {
                        foundRemoveCertAction = true;
                    }
                }

                Assert.True(foundRemoveCertAction, "Active response REMOVE_CERT action was not taken on Tier1 Behavioral detection.");
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }
    }
}
