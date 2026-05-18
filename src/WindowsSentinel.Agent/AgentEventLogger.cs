using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Agent;

/// <summary>
/// Event logger for the Agent — writes to the same shared events.jsonl
/// used by the service, with file locking to prevent corruption.
/// </summary>
internal sealed class AgentEventLogger : IEventLogger
{
    private readonly ILogger<AgentEventLogger> _logger;
    private readonly string _eventsPath;
    private readonly object _writeLock = new();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public AgentEventLogger(ILogger<AgentEventLogger> logger)
    {
        _logger = logger;
        _eventsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "WindowsSentinel", "events.jsonl");
    }

    public Task LogDetectionAsync(DetectionEvent detection, CancellationToken cancellationToken)
    {
        var entry = new { type = "detection", timestamp = detection.Timestamp, data = detection };
        WriteJsonLine(entry);
        return Task.CompletedTask;
    }

    public Task LogResponseAsync(ResponseAction response, CancellationToken cancellationToken)
    {
        var entry = new { type = "response", timestamp = response.Timestamp, data = response };
        WriteJsonLine(entry);
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    private void WriteJsonLine(object entry)
    {
        try
        {
            var json = JsonSerializer.Serialize(entry, JsonOptions);
            lock (_writeLock)
            {
                File.AppendAllText(_eventsPath, json + "\n");
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "AgentEventLogger: failed to write event");
        }
    }
}
