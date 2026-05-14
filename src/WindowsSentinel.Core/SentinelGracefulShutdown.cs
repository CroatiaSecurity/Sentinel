using System.Collections.Concurrent;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core;

/// <summary>
/// Graceful Shutdown Manager - Handles clean application shutdown.
/// </summary>
public sealed class SentinelGracefulShutdown : IHostedService
{
    private readonly ILogger<SentinelGracefulShutdown> _logger;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ConcurrentDictionary<string, ShutdownTask> _shutdownTasks;

    public SentinelGracefulShutdown(
        ILogger<SentinelGracefulShutdown> logger,
        IHostApplicationLifetime lifetime)
    {
        _logger = logger;
        _lifetime = lifetime;
        _shutdownTasks = new ConcurrentDictionary<string, ShutdownTask>();
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("GracefulShutdown: Registering shutdown handlers");

        // Register shutdown handlers
        _lifetime.ApplicationStopping.Register(OnApplicationStopping);
        _lifetime.ApplicationStopped.Register(OnApplicationStopped);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        // This is called during graceful shutdown
        return Task.CompletedTask;
    }

    /// <summary>
    /// Registers a shutdown task to be executed during graceful shutdown.
    /// </summary>
    public void RegisterShutdownTask(string name, Func<CancellationToken, Task> task, int priority = 100)
    {
        _shutdownTasks[name] = new ShutdownTask
        {
            Name = name,
            Task = task,
            Priority = priority
        };
        
        _logger.LogDebug("GracefulShutdown: Registered task '{Name}' (priority {Priority})", name, priority);
    }

    private void OnApplicationStopping()
    {
        _logger.LogCritical(@"
╔═══════════════════════════════════════════════════════════════╗
║  SENTINEL SHUTDOWN INITIATED                                    ║
╚═══════════════════════════════════════════════════════════════╝");

        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        
        // Execute shutdown tasks in priority order
        var orderedTasks = _shutdownTasks.Values.OrderBy(t => t.Priority).ToList();
        
        foreach (var task in orderedTasks)
        {
            try
            {
                _logger.LogInformation("GracefulShutdown: Executing '{Name}'...", task.Name);
                task.Task(cts.Token).Wait(cts.Token);
                _logger.LogDebug("GracefulShutdown: '{Name}' completed", task.Name);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("GracefulShutdown: '{Name}' was cancelled", task.Name);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GracefulShutdown: '{Name}' failed", task.Name);
            }
        }

        _logger.LogInformation("GracefulShutdown: All shutdown tasks completed");
    }

    private void OnApplicationStopped()
    {
        _logger.LogInformation(@"
╔═══════════════════════════════════════════════════════════════╗
║  SENTINEL SHUTDOWN COMPLETE                                     ║
╚═══════════════════════════════════════════════════════════════╝");
    }
}

/// <summary>
/// A task to be executed during shutdown.
/// </summary>
public sealed class ShutdownTask
{
    public string Name { get; set; } = "";
    public Func<CancellationToken, Task> Task { get; set; } = _ => System.Threading.Tasks.Task.CompletedTask;
    public int Priority { get; set; } = 100;
}
