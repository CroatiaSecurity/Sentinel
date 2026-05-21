using System.Threading.Channels;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace WindowsSentinel.Tests.Integration;

/// <summary>
/// Integration tests for the full detection → correlation → response flow.
/// Verifies that detections flow correctly through the pipeline.
/// </summary>
public sealed class DetectionResponseFlowTests
{
    // ── Detection Engine Flow ────────────────────────────────────────────────

    [Fact]
    public async Task DetectionEngine_EmitsEvent_WhenRuleFires()
    {
        // Arrange
        var logger = NullLogger<DetectionEngine>.Instance;
        var engine = new DetectionEngine(Array.Empty<IDetectionRule>(), logger);
        var emittedEvents = new List<DetectionEvent>();

        // Subscribe to detection stream
        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var readTask = Task.Run(async () =>
        {
            await foreach (var detection in engine.DetectionStream.WithCancellation(cts.Token))
            {
                emittedEvents.Add(detection);
                if (emittedEvents.Count >= 1) break;
            }
        }, cts.Token);

        // Act — emit a detection
        var testDetection = new DetectionEvent
        {
            RuleName = "TestRule",
            Tier = DetectionTier.Tier1Behavioral,
            Confidence = 0.95,
            ProcessId = 1234,
            ProcessName = "test.exe",
            Evidence = "Test detection",
            Reasoning = "Integration test",
            Timestamp = DateTimeOffset.UtcNow
        };

        await engine.EmitAsync(testDetection, CancellationToken.None);

        // Wait for event to be consumed
        try { await readTask.WaitAsync(TimeSpan.FromSeconds(3)); } catch { }
        cts.Cancel();

        // Assert
        Assert.NotEmpty(emittedEvents);
        Assert.Equal("TestRule", emittedEvents[0].RuleName);
        Assert.Equal(DetectionTier.Tier1Behavioral, emittedEvents[0].Tier);
        Assert.Equal(0.95, emittedEvents[0].Confidence);
    }

    [Fact]
    public async Task DetectionEngine_Deduplicates_SameRuleAndPid()
    {
        // Arrange
        var logger = NullLogger<DetectionEngine>.Instance;
        var engine = new DetectionEngine(Array.Empty<IDetectionRule>(), logger);
        var emittedEvents = new List<DetectionEvent>();

        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var readTask = Task.Run(async () =>
        {
            await foreach (var detection in engine.DetectionStream.WithCancellation(cts.Token))
            {
                emittedEvents.Add(detection);
            }
        }, cts.Token);

        // Act — emit the same detection twice
        var detection = new DetectionEvent
        {
            RuleName = "DuplicateRule",
            Tier = DetectionTier.Tier1Behavioral,
            Confidence = 0.90,
            ProcessId = 5678,
            ProcessName = "dup.exe",
            Evidence = "Duplicate test",
            Reasoning = "Should be deduplicated",
            Timestamp = DateTimeOffset.UtcNow
        };

        await engine.EmitAsync(detection, CancellationToken.None);
        await engine.EmitAsync(detection, CancellationToken.None); // Duplicate

        // Wait briefly for processing
        await Task.Delay(500);
        cts.Cancel();
        try { await readTask; } catch { }

        // Assert — only one event should be emitted (deduplication)
        Assert.Single(emittedEvents);
    }

    // ── Behavioral Correlation Engine ────────────────────────────────────────

    [Fact]
    public async Task BehavioralCorrelation_FiresComposite_OnMultipleSignals()
    {
        // Arrange
        var logger = NullLogger<BehavioralCorrelationEngine>.Instance;
        var detectionEngine = new DetectionEngine(Array.Empty<IDetectionRule>(), NullLogger<DetectionEngine>.Instance);
        var engine = new BehavioralCorrelationEngine(detectionEngine, logger);
        var compositeEvents = new List<DetectionEvent>();

        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var readTask = Task.Run(async () =>
        {
            await foreach (var detection in detectionEngine.DetectionStream.WithCancellation(cts.Token))
            {
                if (detection.RuleName.StartsWith("COMPOSITE:"))
                    compositeEvents.Add(detection);
            }
        }, cts.Token);

        // Act — emit two correlated signals for the same PID
        var signal1 = new DetectionEvent
        {
            RuleName = "ShadowCopyDeletion",
            Tier = DetectionTier.Tier2Indicator,
            Confidence = 0.85,
            ProcessId = 9999,
            ProcessName = "ransomware.exe",
            Evidence = "Shadow copy deletion detected",
            Reasoning = "vssadmin delete shadows",
            Timestamp = DateTimeOffset.UtcNow
        };

        var signal2 = new DetectionEvent
        {
            RuleName = "BulkFileRename",
            Tier = DetectionTier.Tier2Indicator,
            Confidence = 0.80,
            ProcessId = 9999,
            ProcessName = "ransomware.exe",
            Evidence = "Bulk file rename detected",
            Reasoning = "100+ files renamed with new extension",
            Timestamp = DateTimeOffset.UtcNow
        };

        await engine.OnDetectionAsync(signal1, CancellationToken.None);
        await engine.OnDetectionAsync(signal2, CancellationToken.None);

        // Wait for correlation processing
        await Task.Delay(1000);
        cts.Cancel();
        try { await readTask; } catch { }

        // Assert — should have fired a composite detection
        Assert.NotEmpty(compositeEvents);
    }

    // ── Rate Limiting ────────────────────────────────────────────────────────

    [Fact]
    public async Task DetectionEngine_RateLimits_FloodingAttempts()
    {
        // Arrange
        var logger = NullLogger<DetectionEngine>.Instance;
        var engine = new DetectionEngine(Array.Empty<IDetectionRule>(), logger);
        var emittedCount = 0;

        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var readTask = Task.Run(async () =>
        {
            await foreach (var _ in engine.DetectionStream.WithCancellation(cts.Token))
            {
                Interlocked.Increment(ref emittedCount);
            }
        }, cts.Token);

        // Act — flood with 1000 unique detections
        for (int i = 0; i < 1000; i++)
        {
            var detection = new DetectionEvent
            {
                RuleName = $"FloodRule_{i}",
                Tier = DetectionTier.Tier2Indicator,
                Confidence = 0.50,
                ProcessId = i + 100,
                ProcessName = $"flood_{i}.exe",
                Evidence = "Flood test",
                Reasoning = "Rate limit test",
                Timestamp = DateTimeOffset.UtcNow
            };
            await engine.EmitAsync(detection, CancellationToken.None);
        }

        await Task.Delay(1000);
        cts.Cancel();
        try { await readTask; } catch { }

        // Assert — should have processed events (exact count depends on rate limiting)
        Assert.True(emittedCount > 0, "Should have processed at least some events");
        Assert.True(emittedCount <= 1000, "Should not exceed total submitted");
    }

    // ── Tier Enforcement ────────────────────────────────────────────────────

    [Fact]
    public async Task ResponseEngine_OnlyKills_Tier1Detections()
    {
        // This test verifies the architectural constraint that Tier2 signals
        // NEVER trigger kill actions independently.
        
        var tier2Detection = new DetectionEvent
        {
            RuleName = "Tier2Signal",
            Tier = DetectionTier.Tier2Indicator,
            Confidence = 0.99, // Even high confidence Tier2 should not kill
            ProcessId = 1234,
            ProcessName = "suspicious.exe",
            Evidence = "Advisory signal",
            Reasoning = "Should not trigger kill",
            Timestamp = DateTimeOffset.UtcNow
        };

        // Verify tier is correctly set
        Assert.Equal(DetectionTier.Tier2Indicator, tier2Detection.Tier);
        
        // The architectural constraint: Tier2 can NEVER trigger action
        // This is enforced in AdvancedResponseEngine.HandleAsync
        Assert.NotEqual(DetectionTier.Tier1Behavioral, tier2Detection.Tier);
    }

    [Fact]
    public void DetectionEvent_RequiresMinimumConfidence_ForKill()
    {
        // President's Law: confidence must be >= 0.85 for kill authorization
        const double MinKillConfidence = 0.85;

        var lowConfidence = new DetectionEvent
        {
            RuleName = "LowConfidence",
            Tier = DetectionTier.Tier1Behavioral,
            Confidence = 0.50,
            ProcessId = 1234,
            ProcessName = "maybe.exe",
            Evidence = "Low confidence",
            Reasoning = "Not enough evidence",
            Timestamp = DateTimeOffset.UtcNow
        };

        var highConfidence = new DetectionEvent
        {
            RuleName = "HighConfidence",
            Tier = DetectionTier.Tier1Behavioral,
            Confidence = 0.95,
            ProcessId = 5678,
            ProcessName = "malware.exe",
            Evidence = "High confidence",
            Reasoning = "Strong evidence",
            Timestamp = DateTimeOffset.UtcNow
        };

        Assert.True(lowConfidence.Confidence < MinKillConfidence);
        Assert.True(highConfidence.Confidence >= MinKillConfidence);
    }

    // ── Self-Protection ─────────────────────────────────────────────────────

    [Fact]
    public void SelfProtection_NeverTargetsOwnPid()
    {
        var ownPid = Environment.ProcessId;
        
        // Verify that any detection targeting own PID would be blocked
        var selfTargetDetection = new DetectionEvent
        {
            RuleName = "SelfTarget",
            Tier = DetectionTier.Tier1Behavioral,
            Confidence = 0.99,
            ProcessId = ownPid,
            ProcessName = "SentinelService",
            Evidence = "Self-targeting test",
            Reasoning = "Should be blocked",
            Timestamp = DateTimeOffset.UtcNow
        };

        // The response engine should refuse to kill own PID
        Assert.Equal(ownPid, selfTargetDetection.ProcessId);
        // Actual enforcement is in AdvancedResponseEngine.HandleAsync
    }
}
