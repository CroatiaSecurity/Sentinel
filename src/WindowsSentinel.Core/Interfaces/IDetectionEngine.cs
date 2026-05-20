using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Interfaces;

/// <summary>
/// Receives raw telemetry, runs all registered rules, and emits DetectionEvents.
/// </summary>
public interface IDetectionEngine
{
    IAsyncEnumerable<DetectionEvent> DetectionStream { get; }

    /// <summary>
    /// Processes raw telemetry through all registered detection rules.
    /// </summary>
    Task ProcessAsync(object telemetry, CancellationToken cancellationToken);

    /// <summary>
    /// Emits a pre-formed DetectionEvent directly to the stream, bypassing
    /// the rule pipeline. Used by the correlation engine for composite detections.
    /// </summary>
    Task EmitAsync(DetectionEvent detection, CancellationToken cancellationToken);
}


