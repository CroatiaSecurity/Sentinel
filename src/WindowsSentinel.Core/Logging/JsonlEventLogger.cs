using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Logging;

/// <summary>
/// Writes detection events and response actions to a JSONL (newline-delimited JSON) file.
///
/// Features:
///   - Thread-safe via SemaphoreSlim.
///   - No string-built JSON — uses System.Text.Json exclusively.
///   - Size-based log rotation: when the active log exceeds MaxFileSizeBytes,
///     it is renamed to events.jsonl.1 (shifting older files up to .5) and a
///     new events.jsonl is opened. Up to MaxRotatedFiles rotated files are kept.
/// </summary>
public sealed class JsonlEventLogger : IEventLogger
{
    private readonly string _logPath;
    private readonly ILogger<JsonlEventLogger> _logger;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly JsonSerializerOptions _jsonOptions;
    private StreamWriter? _writer;
    private bool _disposed;

    // Rotate at 50 MB, keep 5 rotated files (250 MB total max).
    private const long MaxFileSizeBytes  = 50 * 1024 * 1024;
    private const int  MaxRotatedFiles   = 5;

    // SECURITY FIX: Rate limiting to prevent log flooding attacks
    // Max 100 entries per second, burst of 200
    private readonly SemaphoreSlim _rateLimiter = new(1, 1);
    private DateTime _rateLimitWindowStart = DateTime.UtcNow;
    private int _entriesInCurrentWindow = 0;
    private const int MaxEntriesPerSecond = 100;
    private const int MaxBurstEntries = 200;
    private int _droppedEntries = 0;

    public JsonlEventLogger(string logPath, ILogger<JsonlEventLogger> logger)
    {
        _logPath = logPath;
        _logger  = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            WriteIndented          = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Converters             = { new JsonStringEnumConverter() }
        };

        var dir = Path.GetDirectoryName(logPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        _writer = OpenWriter();
        _logger.LogInformation("[EventLogger] Writing events to '{Path}'", logPath);
    }

    public async Task LogDetectionAsync(DetectionEvent detection, CancellationToken cancellationToken)
    {
        var entry = new LogEntry
        {
            Type      = "detection",
            Timestamp = detection.Timestamp,
            Data      = detection
        };
        await WriteLineAsync(entry, cancellationToken);
    }

    public async Task LogResponseAsync(ResponseAction action, CancellationToken cancellationToken)
    {
        var entry = new LogEntry
        {
            Type      = "response",
            Timestamp = action.Timestamp,
            Data      = action
        };
        await WriteLineAsync(entry, cancellationToken);
    }

    private async Task WriteLineAsync(object entry, CancellationToken cancellationToken)
    {
        if (_disposed) return;

        // SECURITY FIX: Rate limiting to prevent log flooding attacks
        if (!await CheckRateLimitAsync())
        {
            // Rate limit exceeded - drop this entry but log it occasionally
            _droppedEntries++;
            if (_droppedEntries % 100 == 1)
            {
                _logger.LogWarning("[EventLogger] Rate limit exceeded. Dropped {Count} entries in current window.", _droppedEntries);
            }
            return;
        }

        await _writeLock.WaitAsync(cancellationToken);
        try
        {
            if (_writer is null || _disposed) return;

            // Check if rotation is needed before writing
            await RotateIfNeededAsync();

            string json = JsonSerializer.Serialize(entry, _jsonOptions);
            await _writer.WriteLineAsync(json.AsMemory(), cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "[EventLogger] Failed to write log entry.");
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>
    /// Checks rate limiting. Returns true if entry should be written, false if it should be dropped.
    /// </summary>
    private async Task<bool> CheckRateLimitAsync()
    {
        await _rateLimiter.WaitAsync();
        try
        {
            var now = DateTime.UtcNow;
            var windowElapsed = now - _rateLimitWindowStart;

            // Reset window if 1 second has passed
            if (windowElapsed >= TimeSpan.FromSeconds(1))
            {
                if (_droppedEntries > 0)
                {
                    _logger.LogWarning("[EventLogger] Rate limit window reset. Total dropped in last window: {Count}", _droppedEntries);
                    _droppedEntries = 0;
                }
                _rateLimitWindowStart = now;
                _entriesInCurrentWindow = 0;
            }

            // Check if we're within burst limit
            if (_entriesInCurrentWindow >= MaxBurstEntries)
            {
                return false; // Hard limit reached
            }

            // Check if we're within sustained rate limit
            if (_entriesInCurrentWindow >= MaxEntriesPerSecond && windowElapsed < TimeSpan.FromSeconds(1))
            {
                return false; // Rate limit reached for this second
            }

            _entriesInCurrentWindow++;
            return true;
        }
        finally
        {
            _rateLimiter.Release();
        }
    }

    /// <summary>
    /// Rotates the log file if it exceeds MaxFileSizeBytes.
    /// Must be called while holding _writeLock.
    /// </summary>
    private async Task RotateIfNeededAsync()
    {
        try
        {
            var fi = new FileInfo(_logPath);
            if (!fi.Exists || fi.Length < MaxFileSizeBytes) return;

            // Flush and close current writer
            if (_writer is not null)
            {
                await _writer.FlushAsync();
                await _writer.DisposeAsync();
                _writer = null;
            }

            // Shift existing rotated files: .5 is deleted, .4→.5, .3→.4, ..., .1→.2
            for (int i = MaxRotatedFiles; i >= 1; i--)
            {
                var older = $"{_logPath}.{i}";
                var newer = $"{_logPath}.{i + 1}";
                if (File.Exists(older))
                {
                    if (i == MaxRotatedFiles)
                        File.Delete(older);
                    else
                        File.Move(older, newer, overwrite: true);
                }
            }

            // Rename current log to .1
            File.Move(_logPath, $"{_logPath}.1", overwrite: true);

            _writer = OpenWriter();
            _logger.LogInformation("[EventLogger] Log rotated. New file: '{Path}'", _logPath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[EventLogger] Log rotation failed — continuing with current file.");
            // Re-open writer if it was closed before the error
            _writer ??= OpenWriter();
        }
    }

    private StreamWriter OpenWriter() =>
        new StreamWriter(_logPath, append: true, encoding: System.Text.Encoding.UTF8)
        {
            AutoFlush = true
        };

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        await _writeLock.WaitAsync();
        try
        {
            if (_writer is not null)
            {
                await _writer.FlushAsync();
                await _writer.DisposeAsync();
                _writer = null;
            }
        }
        finally
        {
            _writeLock.Release();
            _writeLock.Dispose();
        }
    }

    private sealed class LogEntry
    {
        [JsonPropertyName("type")]
        public required string Type { get; init; }

        [JsonPropertyName("timestamp")]
        public required DateTimeOffset Timestamp { get; init; }

        [JsonPropertyName("data")]
        public required object Data { get; init; }
    }
}
