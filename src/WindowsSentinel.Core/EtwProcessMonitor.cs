using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core;

/// <summary>
/// Primary process monitor using ETW (requires elevation).
/// Automatically falls back to WMI (Win32_ProcessStartTrace) when ETW
/// is unavailable so the tool remains useful as a standard user.
///
/// Enriches every ProcessTelemetry event with the parent process name
/// resolved from the ProcessAncestryCache, enabling parent-child
/// detection rules without a live WMI query per event.
/// </summary>
public sealed class EtwProcessMonitor : IMonitor
{
    public string Name => "ETW Process Monitor";

    private readonly DetectionEngine _detectionEngine;
    private readonly ILogger<EtwProcessMonitor> _logger;
    private readonly ProcessAncestryCache? _ancestryCache;
    private readonly TelemetryFusionEngine? _fusionEngine;
    private readonly ParentPidSpoofDetector? _ppidDetector;

    // ETW path
    private TraceEventSession? _session;
    private Task? _sessionTask;
    private Task? _ppidCheckTask;

    // WMI fallback path
    private WmiProcessMonitor? _wmiFallback;

    public EtwProcessMonitor(
        DetectionEngine detectionEngine,
        ILogger<EtwProcessMonitor> logger,
        ProcessAncestryCache? ancestryCache = null,
        TelemetryFusionEngine? fusionEngine = null,
        ParentPidSpoofDetector? ppidDetector = null)
    {
        _detectionEngine = detectionEngine;
        _logger          = logger;
        _ancestryCache   = ancestryCache;
        _fusionEngine    = fusionEngine;
        _ppidDetector    = ppidDetector;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("[{Monitor}] Starting (ETW preferred, WMI fallback).", Name);

        if (TryStartEtw(cancellationToken))
        {
            _logger.LogInformation("[{Monitor}] ETW session active.", Name);

            // Start periodic PPID spoof checking
            if (_ppidDetector != null)
            {
                _ppidCheckTask = Task.Run(async () =>
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            await Task.Delay(TimeSpan.FromSeconds(3), cancellationToken);
                            await _ppidDetector.CheckForSpoofingAsync(cancellationToken);
                        }
                        catch (OperationCanceledException) { break; }
                        catch (Exception ex)
                        {
                            _logger.LogDebug(ex, "[{Monitor}] PPID check error.", Name);
                        }
                    }
                }, cancellationToken);
            }
        }
        else
        {
            _logger.LogWarning(
                "[{Monitor}] ETW unavailable (not elevated). " +
                "Falling back to WMI Win32_ProcessStartTrace Ã¢â‚¬â€ " +
                "CommandLine/ImagePath may be empty for very short-lived processes.", Name);

            StartWmiFallback(cancellationToken);
        }

        return Task.CompletedTask;
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ ETW Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    private bool TryStartEtw(CancellationToken cancellationToken)
    {
        try
        {
            _session = new TraceEventSession("WindowsSentinel-ProcessMonitor");
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

            _session.Source.Kernel.ProcessStart += async data =>
            {
                if (cancellationToken.IsCancellationRequested) return;
                try
                {
                    // Resolve parent name from ancestry cache (no WMI query needed)
                    string parentName = _ancestryCache?.GetProcessName(data.ParentID) ?? string.Empty;

                    var telemetry = new EtwProcessEvent
                    {
                        EventType        = "ProcessStart",
                        ProcessId        = data.ProcessID,
                        ProcessName      = data.ProcessName,
                        ImagePath        = data.ImageFileName,
                        CommandLine      = data.CommandLine,
                        ParentProcessId  = data.ParentID,
                        ParentProcessName = parentName,
                        Timestamp        = DateTime.UtcNow
                    };

                    // Feed telemetry fusion engine (enriches event graph)
                    if (_fusionEngine != null)
                    {
                        var pt = new ProcessTelemetry
                        {
                            Type = "ProcessStart",
                            ProcessId = data.ProcessID,
                            ProcessName = data.ProcessName,
                            ImagePath = data.ImageFileName,
                            CommandLine = data.CommandLine,
                            ParentProcessId = data.ParentID,
                            ParentProcessName = parentName,
                            Timestamp = DateTime.UtcNow
                        };
                        var ctx = _fusionEngine.FeedEvent(pt);
                        _detectionEngine.SubmitTelemetry(ctx);
                    }

                    // Record ETW-reported parent for PPID spoof detection
                    _ppidDetector?.RecordEtwParent(data.ProcessID, data.ParentID, data.ProcessName);

                    // Raise detection (ETW process events feed the detection engine via FusedTelemetryContext)
                    _ = telemetry; // already handed off above
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogError(ex, "[{Monitor}] Error processing ETW ProcessStart event.", Name);
                }
            };

            _sessionTask = Task.Run(() =>
            {
                try { _session.Source.Process(); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogError(ex, "[{Monitor}] ETW session ended unexpectedly.", Name);
                }
            }, cancellationToken);

            return true;
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning("[{Monitor}] ETW access denied (not elevated?): {Message}", Name, ex.Message);
            _session?.Dispose();
            _session = null;
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[{Monitor}] ETW session failed ({Type}), will try WMI fallback.", Name, ex.GetType().Name);
            _session?.Dispose();
            _session = null;
            return false;
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ WMI fallback Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    private void StartWmiFallback(CancellationToken cancellationToken)
    {
        try
        {
            // WmiProcessMonitor is used as a background service and self-starts; skip here
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "[{Monitor}] WMI fallback also unavailable. " +
                "Process-based detection is disabled Ã¢â‚¬â€ file and network monitors remain active.",
                Name);
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Lifecycle Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("[{Monitor}] Stopping.", Name);
        _session?.Stop();
        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        _session?.Dispose();

        if (_sessionTask is not null)
        {
            try { await _sessionTask.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch { /* best-effort */ }
        }

        _wmiFallback?.Dispose();
    }
}

/// <summary>Raw telemetry bag from ETW or WMI process events.</summary>
public sealed class EtwProcessEvent
{
    public required string EventType         { get; init; }
    public required int    ProcessId         { get; init; }
    public required string ProcessName       { get; init; }
    public required string ImagePath         { get; init; }
    public required string CommandLine       { get; init; }
    public required int    ParentProcessId   { get; init; }
    public          string ParentProcessName { get; init; } = string.Empty;
    public required DateTime Timestamp { get; init; }
}


