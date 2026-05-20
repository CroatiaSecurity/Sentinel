using System.Management;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// WMI-based process creation monitor using Win32_ProcessStartTrace.
/// Works without elevation. Used as the fallback when ETW is unavailable.
/// </summary>
public sealed class WmiProcessMonitor : IAsyncDisposable
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger _logger;
    private ManagementEventWatcher? _watcher;
    private Task? _watchTask;
    private CancellationTokenSource? _cts;

    public WmiProcessMonitor(IDetectionEngine detectionEngine, ILogger logger)
    {
        _detectionEngine = detectionEngine;
        _logger          = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = _cts.Token;

        _watchTask = Task.Run(() => RunWatcherLoop(token), token);
        return Task.CompletedTask;
    }

    private void RunWatcherLoop(CancellationToken cancellationToken)
    {
        try
        {
            var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
            _watcher = new ManagementEventWatcher(query);

            _watcher.EventArrived += async (_, e) =>
            {
                if (cancellationToken.IsCancellationRequested) return;
                try { await HandleEventAsync(e.NewEvent, cancellationToken); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogError(ex, "[WMI Process Monitor] Error handling event.");
                }
            };

            _watcher.Start();
            _logger.LogInformation("[WMI Process Monitor] Watching Win32_ProcessStartTrace.");
            cancellationToken.WaitHandle.WaitOne();
        }
        catch (ManagementException ex)
        {
            // WMI is disabled or the provider is unavailable — log and exit gracefully.
            _logger.LogWarning(
                "[WMI Process Monitor] WMI unavailable (code {Code}): {Message}. " +
                "Process-based detection is disabled.",
                ex.ErrorCode, ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "[WMI Process Monitor] Failed to start — process-based detection is disabled.");
        }
        finally
        {
            try { _watcher?.Stop(); } catch { /* best-effort */ }
        }
    }

    private async Task HandleEventAsync(ManagementBaseObject wmiEvent, CancellationToken cancellationToken)
    {
        int    pid        = Convert.ToInt32(wmiEvent["ProcessID"]  ?? 0);
        int    parentPid  = Convert.ToInt32(wmiEvent["ParentProcessID"] ?? 0);
        string name       = wmiEvent["ProcessName"]?.ToString() ?? string.Empty;

        // Win32_ProcessStartTrace doesn't give us CommandLine or ImagePath directly.
        // We do a best-effort lookup via WMI Win32_Process — it may miss very short-lived processes.
        string imagePath   = string.Empty;
        string commandLine = string.Empty;

        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT ExecutablePath, CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                imagePath   = obj["ExecutablePath"]?.ToString() ?? string.Empty;
                commandLine = obj["CommandLine"]?.ToString()    ?? string.Empty;
                break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[WMI Process Monitor] Could not query Win32_Process for PID {Pid}.", pid);
        }

        var telemetry = new ProcessTelemetry
        {
            EventType       = "ProcessStart",
            ProcessId       = pid,
            ProcessName     = name,
            ImagePath       = imagePath,
            CommandLine     = commandLine,
            ParentProcessId = parentPid,
            Timestamp       = DateTimeOffset.UtcNow
        };

        await _detectionEngine.ProcessAsync(telemetry, cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        _watcher?.Dispose();

        if (_watchTask is not null)
        {
            try { await _watchTask.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch { /* best-effort */ }
        }

        _cts?.Dispose();
    }
}


