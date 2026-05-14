using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Interfaces;

/// <summary>
/// A detection rule evaluates raw telemetry and produces zero or more DetectionEvents.
/// </summary>
public interface IDetectionRule
{
    string Name { get; }
    DetectionTier Tier { get; }

    /// <summary>
    /// Evaluate a raw telemetry object. Returns null if no detection.
    /// </summary>
    DetectionEvent? Evaluate(object telemetry);
}

/// <summary>
/// Optional interface for detection rules that require async evaluation (e.g., network lookups).
/// The detection engine will call EvaluateAsync in addition to Evaluate when this interface is implemented.
/// </summary>
public interface IAsyncDetectionRule : IDetectionRule
{
    /// <summary>
    /// Async evaluation for rules that need I/O (reputation APIs, etc.).
    /// Called by the detection engine after synchronous Evaluate.
    /// </summary>
    Task<DetectionEvent?> EvaluateAsync(object telemetry, CancellationToken cancellationToken);
}
