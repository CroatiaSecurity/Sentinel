using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Interfaces;

/// <summary>
/// Writes detection events and response actions to persistent JSONL storage.
/// </summary>
public interface IEventLogger : IAsyncDisposable
{
    Task LogDetectionAsync(DetectionEvent detection, CancellationToken cancellationToken);
    Task LogResponseAsync(ResponseAction action, CancellationToken cancellationToken);
}
