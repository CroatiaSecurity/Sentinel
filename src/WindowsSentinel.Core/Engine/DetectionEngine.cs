using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Health;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Runs all registered detection rules against incoming telemetry and
/// streams DetectionEvents to consumers.
///
/// Deduplication: identical (RuleName, ProcessId) pairs are suppressed within
/// a 60-second sliding window to prevent log flooding from repeated events
/// (e.g. network monitor polling the same C2 connection every 5 seconds).
/// </summary>
public sealed class DetectionEngine : IDetectionEngine, IAsyncDisposable
{
    private readonly IReadOnlyList<IDetectionRule> _rules;
    private readonly ILogger<DetectionEngine> _logger;
    private readonly SentinelMetrics? _metrics;
    private readonly Channel<DetectionEvent> _channel;

    // Deduplication: key = "RuleName|ProcessId", value = last-seen time
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentDetections = new();
    private static readonly TimeSpan DedupeWindow = TimeSpan.FromSeconds(60);

    public DetectionEngine(
        IEnumerable<IDetectionRule> rules,
        ILogger<DetectionEngine> logger,
        SentinelMetrics? metrics = null)
    {
        _rules   = rules.ToList().AsReadOnly();
        _logger  = logger;
        _metrics = metrics;
        _channel = Channel.CreateUnbounded<DetectionEvent>(
            new UnboundedChannelOptions { SingleReader = false, SingleWriter = false });
    }

    public IAsyncEnumerable<DetectionEvent> DetectionStream =>
        _channel.Reader.ReadAllAsync();

    public async Task ProcessAsync(object telemetry, CancellationToken cancellationToken)
    {
        // Prune stale dedupe entries periodically (cheap — runs inline)
        PruneDedupeCache();

        foreach (var rule in _rules)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var detection = rule.Evaluate(telemetry);
                if (detection is not null)
                {
                    if (await TryEmitDeduped(detection, cancellationToken))
                        continue;
                }

                // If the rule also supports async evaluation, call it
                if (rule is IAsyncDetectionRule asyncRule)
                {
                    var asyncDetection = await asyncRule.EvaluateAsync(telemetry, cancellationToken);
                    if (asyncDetection is not null)
                    {
                        await TryEmitDeduped(asyncDetection, cancellationToken);
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Rule '{Rule}' threw an exception during evaluation", rule.Name);
            }
        }
    }

    private async Task<bool> TryEmitDeduped(DetectionEvent detection, CancellationToken cancellationToken)
    {
        // Deduplicate: suppress repeated (rule, pid) within the window.
        // ProcessId == 0 means file-system events — dedupe by rule + path instead.
        var dedupeKey = detection.ProcessId == 0
            ? $"{detection.RuleName}|{detection.Metadata.GetValueOrDefault("NewPath", detection.Evidence)}"
            : $"{detection.RuleName}|{detection.ProcessId}";

        if (_recentDetections.TryGetValue(dedupeKey, out var lastSeen) &&
            DateTimeOffset.UtcNow - lastSeen < DedupeWindow)
        {
            _logger.LogDebug(
                "Rule '{Rule}' suppressed (duplicate within {Window}s window).",
                detection.RuleName, DedupeWindow.TotalSeconds);
            return false;
        }

        _recentDetections[dedupeKey] = DateTimeOffset.UtcNow;

        _logger.LogDebug("Rule '{Rule}' fired (Tier {Tier}, confidence {Confidence:P0})",
            detection.RuleName, detection.Tier, detection.Confidence);

        // Record detection in metrics
        _metrics?.RecordDetection(detection.RuleName, detection.Tier.ToString(), detection.Confidence);

        await _channel.Writer.WriteAsync(detection, cancellationToken);
        return true;
    }

    private void PruneDedupeCache()
    {
        // Only prune when the cache grows large enough to be worth it
        if (_recentDetections.Count < 200) return;

        var cutoff = DateTimeOffset.UtcNow - DedupeWindow;
        foreach (var kvp in _recentDetections)
        {
            if (kvp.Value < cutoff)
                _recentDetections.TryRemove(kvp.Key, out _);
        }
    }

    public async Task EmitAsync(DetectionEvent detection, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Composite detection emitted: '{Rule}' (confidence {Confidence:P0})",
            detection.RuleName, detection.Confidence);

        // Record composite detection in metrics
        _metrics?.RecordDetection(detection.RuleName, detection.Tier.ToString(), detection.Confidence);

        await _channel.Writer.WriteAsync(detection, cancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        _channel.Writer.TryComplete();
        return ValueTask.CompletedTask;
    }
}


