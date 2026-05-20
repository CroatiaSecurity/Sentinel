using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Agent;

/// <summary>
/// Reads DetectionEvents from the DetectionEngine channel and routes them
/// to the AgentResponseEngine for action (kill or log).
/// </summary>
internal sealed class AgentDetectionPipeline : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly IResponseEngine _responseEngine;
    private readonly ILogger<AgentDetectionPipeline> _logger;

    public AgentDetectionPipeline(
        IDetectionEngine detectionEngine,
        IResponseEngine responseEngine,
        ILogger<AgentDetectionPipeline> logger)
    {
        _detectionEngine = detectionEngine;
        _responseEngine = responseEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Agent Detection Pipeline: starting");

        await foreach (var detection in _detectionEngine.DetectionStream.WithCancellation(stoppingToken))
        {
            try
            {
                await _responseEngine.HandleAsync(detection, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Agent Detection Pipeline: error handling {Rule}", detection.RuleName);
            }
        }
    }
}

