namespace WindowsSentinel.Core;

/// <summary>
/// Extended monitor interface for monitors that manage their own lifecycle
/// (ETW session-based monitors, pipe monitors, etc.) rather than using BackgroundService.
/// </summary>
public interface IMonitor : IAsyncDisposable
{
    string Name { get; }
    Task StartAsync(CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
}
