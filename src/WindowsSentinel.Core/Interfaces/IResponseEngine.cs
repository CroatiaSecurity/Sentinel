using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Interfaces;

/// <summary>
/// The ONLY component permitted to take action on a detection.
/// Tier2 events must never result in an action beyond logging.
/// </summary>
public interface IResponseEngine
{
    Task HandleAsync(DetectionEvent detection, CancellationToken cancellationToken);
}
