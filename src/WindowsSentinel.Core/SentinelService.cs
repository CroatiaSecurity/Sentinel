using System.Net;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
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
    private readonly IOptionsMonitor<HealthCheckOptions>? _healthOptions;
    private readonly Health.StartupSelfTest? _selfTest;
    private System.Net.HttpListener? _healthListener;
    private CancellationTokenSource? _healthCts;

    public SentinelService(
        IEnumerable<IMonitor> monitors,
        IDetectionEngine detectionEngine,
        IResponseEngine responseEngine,
        IEventLogger eventLogger,
        ProcessAncestryCache ancestryCache,
        BehavioralCorrelationEngine correlationEngine,
        BeaconingDetector beaconingDetector,
        ILogger<SentinelService> logger,
        Health.StartupSelfTest? selfTest = null,
        IOptionsMonitor<HealthCheckOptions> healthOptions = null!)
    {
        _monitors           = monitors;
        _detectionEngine    = detectionEngine;
        _responseEngine     = responseEngine;
        _eventLogger        = eventLogger;
        _ancestryCache      = ancestryCache;
        _correlationEngine  = correlationEngine;
        _beaconingDetector  = beaconingDetector;
        _logger             = logger;
        _selfTest           = selfTest;
        _healthOptions      = healthOptions;
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        // Start health check endpoint if enabled (before main loop)
        if (_healthOptions?.CurrentValue?.Enabled == true)
        {
            await StartHealthEndpointAsync(cancellationToken);
        }

        // Let BackgroundService call ExecuteAsync on a background thread
        await base.StartAsync(cancellationToken);
    }

    private Task StartHealthEndpointAsync(CancellationToken ct)
    {
        _healthCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var port = _healthOptions?.CurrentValue?.Port ?? 5000;
        var prefix = $"http://localhost:{port}/";

        try
        {
            _healthListener = new System.Net.HttpListener();
            _healthListener.Prefixes.Add(prefix);
            _healthListener.Start();

            _logger.LogInformation("Health check endpoint listening on {Prefix}", prefix);

            _ = Task.Run(async () =>
            {
                while (!_healthCts.IsCancellationRequested)
                {
                    try
                    {
                        var context = await _healthListener.GetContextAsync();
                        _ = Task.Run(() => HandleHealthRequest(context), ct);
                    }
                    catch (HttpListenerException) when (ct.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        _logger.LogDebug(ex, "Health endpoint error");
                    }
                }
            }, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to start health endpoint on port {Port}", port);
        }

        return Task.CompletedTask;
    }

    private void HandleHealthRequest(System.Net.HttpListenerContext context)
    {
        var response = context.Response;
        response.ContentType = "application/json";
        response.StatusCode = 200;

        var health = new
        {
            status = "healthy",
            version = SentinelVersion.Version,
            timestamp = DateTime.UtcNow.ToString("o"),
            uptime = Environment.TickCount64 / 1000
        };

        var json = System.Text.Json.JsonSerializer.Serialize(health);
        var buffer = System.Text.Encoding.UTF8.GetBytes(json);
        response.ContentLength64 = buffer.Length;
        response.OutputStream.Write(buffer, 0, buffer.Length);
        response.OutputStream.Close();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Windows Sentinel v{Version} starting ===", SentinelVersion.Version);
        _logger.LogInformation("Author: Gorstak | gorstak.eu | github.com/CroatiaSecurity/Sentinel");

        // ── Startup Self-Test ────────────────────────────────────────────────
        _selfTest?.RunAll();

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

        // Stop health endpoint
        _healthCts?.Cancel();
        _healthListener?.Stop();
        _healthListener?.Close();

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

/// <summary>
/// Health check endpoint configuration options
/// </summary>
public class HealthCheckOptions
{
    /// <summary>
    /// Enable/disable the health check endpoint (default: false)
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// Port for the health check endpoint (default: 5000)
    /// </summary>
    public int Port { get; set; } = 5000;
}


