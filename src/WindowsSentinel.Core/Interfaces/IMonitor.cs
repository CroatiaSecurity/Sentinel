namespace WindowsSentinel.Core.Interfaces;

/// <summary>
/// A monitor observes a specific aspect of the system and emits raw events
/// to the detection pipeline via the provided channel writer.
/// </summary>
public interface IMonitor : IAsyncDisposable
{
    string Name { get; }
    Task StartAsync(CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
}

