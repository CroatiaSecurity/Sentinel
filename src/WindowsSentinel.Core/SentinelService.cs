using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core;

/// <summary>
/// Hosted service that orchestrates all monitors, the detection engine,
/// the response engine, and the advanced analysis components.
/// </summary>
public sealed class SentinelService : BackgroundService
{
    private readonly IEnumerable<IMonitor> _monitors;
    private readonly IDetectionEngine _detectionEngine;
    private readonly IResponseEngine _responseEngine;
    private readonly IEventLogger _eventLogger;
    private readonly ProcessAncestryCache _ancestryCache;
    private readonly BehavioralCorrelationEngine _correlationEngine;
    private readonly BeaconingDetector _beaconingDetector;
    private readonly ILogger<SentinelService> _logger;

    public SentinelService(
        IEnumerable<IMonitor> monitors,
        IDetectionEngine detectionEngine,
        IResponseEngine responseEngine,
        IEventLogger eventLogger,
        ProcessAncestryCache ancestryCache,
        BehavioralCorrelationEngine correlationEngine,
        BeaconingDetector beaconingDetector,
        ILogger<SentinelService> logger)
    {
        _monitors           = monitors;
        _detectionEngine    = detectionEngine;
        _responseEngine     = responseEngine;
        _eventLogger        = eventLogger;
        _ancestryCache      = ancestryCache;
        _correlationEngine  = correlationEngine;
        _beaconingDetector  = beaconingDetector;
        _logger             = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Windows Sentinel starting ===");
        _logger.LogInformation("Author: Gorstak | github.com/tandrlemandrle/Sentinel");

        // Start advanced analysis components
        _ancestryCache.Start(stoppingToken);
        _correlationEngine.Start(stoppingToken);
        _beaconingDetector.Start(stoppingToken);

        // Start all monitors
        foreach (var monitor in _monitors)
        {
            try
            {
                await monitor.StartAsync(stoppingToken);
                _logger.LogInformation("Monitor '{Name}' started.", monitor.Name);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start monitor '{Name}'.", monitor.Name);
            }
        }

        _logger.LogInformation("All monitors active. Listening for events...");

        // Consume detection stream, route to response engine AND correlation engine
        try
        {
            await foreach (var detection in _detectionEngine.DetectionStream
                               .WithCancellation(stoppingToken))
            {
                try
                {
                    // Feed into behavioral correlation engine (async, non-blocking)
                    _ = _correlationEngine.OnDetectionAsync(detection, stoppingToken)
                        .ContinueWith(t =>
                        {
                            if (t.IsFaulted)
                                _logger.LogDebug(t.Exception,
                                    "CorrelationEngine error for '{Rule}'.", detection.RuleName);
                        }, TaskScheduler.Default);

                    // Route to response engine
                    await _responseEngine.HandleAsync(detection, stoppingToken);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogError(ex,
                        "ResponseEngine failed handling detection '{Rule}'.", detection.RuleName);
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Detection stream cancelled — shutting down.");
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("=== Windows Sentinel stopping ===");

        foreach (var monitor in _monitors)
        {
            try
            {
                await monitor.StopAsync(cancellationToken);
                _logger.LogInformation("Monitor '{Name}' stopped.", monitor.Name);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error stopping monitor '{Name}'.", monitor.Name);
            }
        }

        await base.StopAsync(cancellationToken);

        await _ancestryCache.DisposeAsync();
        await _correlationEngine.DisposeAsync();
        await _beaconingDetector.DisposeAsync();
        await _eventLogger.DisposeAsync();

        _logger.LogInformation("=== Windows Sentinel stopped ===");
    }
}
