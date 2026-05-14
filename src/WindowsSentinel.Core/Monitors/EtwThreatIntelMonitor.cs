using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Subscribes to the Microsoft-Windows-Threat-Intelligence ETW provider.
///
/// This is the same provider used by Windows Defender and commercial EDRs.
/// It fires on actual kernel-level API calls — not command-line string matching —
/// giving real injection visibility:
///
///   KERNEL_THREATINT_TASK_ALLOCVM      — VirtualAllocEx (cross-process memory allocation)
///   KERNEL_THREATINT_TASK_PROTECTVM    — VirtualProtect to RWX (shellcode activation)
///   KERNEL_THREATINT_TASK_MAPVIEW      — NtMapViewOfSection (hollowing / module stomping)
///   KERNEL_THREATINT_TASK_QUEUEUSERAPC — QueueUserAPC injection
///   KERNEL_THREATINT_TASK_SETTHREADCONTEXT — SetThreadContext (classic hollowing step)
///
/// Requires elevation (admin). Degrades gracefully if unavailable.
///
/// Why this matters: ProcessInjectionRule detects injection tools by name/args.
/// This monitor detects the actual injection API calls regardless of what the
/// tool is called or how it was launched — including in-memory-only attacks.
/// </summary>
public sealed class EtwThreatIntelMonitor : IMonitor
{
    public string Name => "ETW Threat Intelligence Monitor";

    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<EtwThreatIntelMonitor> _logger;
    private readonly TelemetryFusionEngine? _fusionEngine;

    private TraceEventSession? _session;
    private Task? _sessionTask;

    // Microsoft-Windows-Threat-Intelligence provider GUID
    private static readonly Guid ThreatIntelProviderGuid =
        new("F4E1897C-BB5D-5668-F1D8-040F4D8DD344");

    // Task IDs from the provider manifest
    private const int TASK_ALLOCVM_REMOTE      = 1;  // VirtualAllocEx cross-process
    private const int TASK_PROTECTVM_REMOTE     = 3;  // VirtualProtect cross-process
    private const int TASK_MAPVIEW_REMOTE        = 5;  // NtMapViewOfSection cross-process
    private const int TASK_QUEUEUSERAPC_REMOTE   = 7;  // QueueUserAPC cross-process
    private const int TASK_SETTHREADCONTEXT_REMOTE = 9; // SetThreadContext cross-process

    // Protect flags that indicate shellcode activation
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_READ      = 0x20;
    private const uint PAGE_EXECUTE           = 0x10;

    public EtwThreatIntelMonitor(
        IDetectionEngine detectionEngine,
        ILogger<EtwThreatIntelMonitor> logger,
        TelemetryFusionEngine? fusionEngine = null)
    {
        _detectionEngine = detectionEngine;
        _logger          = logger;
        _fusionEngine    = fusionEngine;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("[{Monitor}] Starting (requires elevation).", Name);

        try
        {
            _session = new TraceEventSession("WindowsSentinel-ThreatIntel");

            // Enable the Threat Intelligence provider with all keywords
            _session.EnableProvider(ThreatIntelProviderGuid,
                TraceEventLevel.Verbose,
                ulong.MaxValue);

            _session.Source.Dynamic.All += data =>
            {
                if (cancellationToken.IsCancellationRequested) return;
                try { HandleEventAsync(data, cancellationToken).GetAwaiter().GetResult(); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogDebug(ex, "[{Monitor}] Error handling ThreatIntel event.", Name);
                }
            };

            _sessionTask = Task.Run(() =>
            {
                try { _session.Source.Process(); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "[{Monitor}] ETW ThreatIntel session ended.", Name);
                }
            }, cancellationToken);

            _logger.LogInformation("[{Monitor}] Threat Intelligence ETW provider active.", Name);
        }
        catch (UnauthorizedAccessException)
        {
            _logger.LogWarning(
                "[{Monitor}] Access denied — elevation required for Threat Intelligence provider. " +
                "Process injection detection falls back to command-line heuristics only.", Name);
            _session?.Dispose();
            _session = null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "[{Monitor}] Failed to start Threat Intelligence ETW provider. " +
                "Process injection detection falls back to command-line heuristics only.", Name);
            _session?.Dispose();
            _session = null;
        }

        return Task.CompletedTask;
    }

    private async Task HandleEventAsync(TraceEvent data, CancellationToken cancellationToken)
    {
        int taskId = (int)data.Task;

        switch (taskId)
        {
            case TASK_ALLOCVM_REMOTE:
                await HandleAllocVmAsync(data, cancellationToken);
                break;

            case TASK_PROTECTVM_REMOTE:
                await HandleProtectVmAsync(data, cancellationToken);
                break;

            case TASK_MAPVIEW_REMOTE:
                await HandleMapViewAsync(data, cancellationToken);
                break;

            case TASK_QUEUEUSERAPC_REMOTE:
                await HandleQueueApcAsync(data, cancellationToken);
                break;

            case TASK_SETTHREADCONTEXT_REMOTE:
                await HandleSetThreadContextAsync(data, cancellationToken);
                break;
        }
    }

    private async Task HandleAllocVmAsync(TraceEvent data, CancellationToken ct)
    {
        int callerPid = TryGetInt(data, "CallingProcessId");
        int targetPid = TryGetInt(data, "TargetProcessId");

        // Self-allocation is normal; cross-process is injection
        if (callerPid == targetPid || targetPid == 0) return;

        // Skip known-safe system processes allocating into children
        if (IsSystemPid(callerPid)) return;

        // Feed telemetry fusion engine
        _fusionEngine?.IngestInjection(callerPid, targetPid,
            ThreatIntelEventKind.CrossProcessAllocVm, DateTimeOffset.UtcNow);

        var telemetry = new ThreatIntelTelemetry
        {
            EventKind       = ThreatIntelEventKind.CrossProcessAllocVm,
            CallerProcessId = callerPid,
            TargetProcessId = targetPid,
            Evidence        = $"VirtualAllocEx: PID {callerPid} allocated memory in PID {targetPid}",
            Confidence      = 0.82,
            Timestamp       = DateTimeOffset.UtcNow,
            RawData         = BuildRawData(data)
        };

        await _detectionEngine.ProcessAsync(telemetry, ct);
    }

    private async Task HandleProtectVmAsync(TraceEvent data, CancellationToken ct)
    {
        int callerPid  = TryGetInt(data, "CallingProcessId");
        int targetPid  = TryGetInt(data, "TargetProcessId");
        uint newProtect = TryGetUInt(data, "NewAccessProtection");

        bool isExecutable = (newProtect & PAGE_EXECUTE_READWRITE) != 0 ||
                            (newProtect & PAGE_EXECUTE_READ)       != 0 ||
                            (newProtect & PAGE_EXECUTE)            != 0;

        if (!isExecutable) return;

        // Cross-process RWX → injection; same-process RWX → shellcode staging
        double confidence = callerPid != targetPid ? 0.90 : 0.72;

        var telemetry = new ThreatIntelTelemetry
        {
            EventKind       = ThreatIntelEventKind.ExecutableMemoryProtection,
            CallerProcessId = callerPid,
            TargetProcessId = targetPid,
            Evidence        = callerPid != targetPid
                ? $"VirtualProtect RWX: PID {callerPid} set executable memory in PID {targetPid} (protect=0x{newProtect:X})"
                : $"VirtualProtect RWX: PID {callerPid} marked own memory executable (protect=0x{newProtect:X}) — shellcode staging",
            Confidence      = confidence,
            Timestamp       = DateTimeOffset.UtcNow,
            RawData         = BuildRawData(data)
        };

        await _detectionEngine.ProcessAsync(telemetry, ct);
    }

    private async Task HandleMapViewAsync(TraceEvent data, CancellationToken ct)
    {
        int callerPid = TryGetInt(data, "CallingProcessId");
        int targetPid = TryGetInt(data, "TargetProcessId");

        if (callerPid == targetPid || targetPid == 0) return;
        if (IsSystemPid(callerPid)) return;

        // Feed telemetry fusion engine
        _fusionEngine?.IngestInjection(callerPid, targetPid,
            ThreatIntelEventKind.CrossProcessMapView, DateTimeOffset.UtcNow);

        var telemetry = new ThreatIntelTelemetry
        {
            EventKind       = ThreatIntelEventKind.CrossProcessMapView,
            CallerProcessId = callerPid,
            TargetProcessId = targetPid,
            Evidence        = $"NtMapViewOfSection: PID {callerPid} mapped section into PID {targetPid} — possible hollowing or module stomping",
            Confidence      = 0.85,
            Timestamp       = DateTimeOffset.UtcNow,
            RawData         = BuildRawData(data)
        };

        await _detectionEngine.ProcessAsync(telemetry, ct);
    }

    private async Task HandleQueueApcAsync(TraceEvent data, CancellationToken ct)
    {
        int callerPid = TryGetInt(data, "CallingProcessId");
        int targetPid = TryGetInt(data, "TargetProcessId");

        if (callerPid == targetPid || targetPid == 0) return;
        if (IsSystemPid(callerPid)) return;

        // Feed telemetry fusion engine
        _fusionEngine?.IngestInjection(callerPid, targetPid,
            ThreatIntelEventKind.CrossProcessQueueApc, DateTimeOffset.UtcNow);

        var telemetry = new ThreatIntelTelemetry
        {
            EventKind       = ThreatIntelEventKind.CrossProcessQueueApc,
            CallerProcessId = callerPid,
            TargetProcessId = targetPid,
            Evidence        = $"QueueUserAPC: PID {callerPid} queued APC in PID {targetPid} — APC injection",
            Confidence      = 0.88,
            Timestamp       = DateTimeOffset.UtcNow,
            RawData         = BuildRawData(data)
        };

        await _detectionEngine.ProcessAsync(telemetry, ct);
    }

    private async Task HandleSetThreadContextAsync(TraceEvent data, CancellationToken ct)
    {
        int callerPid = TryGetInt(data, "CallingProcessId");
        int targetPid = TryGetInt(data, "TargetProcessId");

        if (callerPid == targetPid || targetPid == 0) return;
        if (IsSystemPid(callerPid)) return;

        // Feed telemetry fusion engine
        _fusionEngine?.IngestInjection(callerPid, targetPid,
            ThreatIntelEventKind.CrossProcessSetThreadContext, DateTimeOffset.UtcNow);

        var telemetry = new ThreatIntelTelemetry
        {
            EventKind       = ThreatIntelEventKind.CrossProcessSetThreadContext,
            CallerProcessId = callerPid,
            TargetProcessId = targetPid,
            Evidence        = $"SetThreadContext: PID {callerPid} modified thread context in PID {targetPid} — classic process hollowing step",
            Confidence      = 0.93,
            Timestamp       = DateTimeOffset.UtcNow,
            RawData         = BuildRawData(data)
        };

        await _detectionEngine.ProcessAsync(telemetry, ct);
    }

    // PIDs 0 and 4 are System/Idle — they legitimately touch other processes
    private static bool IsSystemPid(int pid) => pid is 0 or 4;

    private static int TryGetInt(TraceEvent data, string field)
    {
        try { return (int)(data.PayloadByName(field) ?? 0); }
        catch { return 0; }
    }

    private static uint TryGetUInt(TraceEvent data, string field)
    {
        try { return (uint)(data.PayloadByName(field) ?? 0u); }
        catch { return 0; }
    }

    private static Dictionary<string, string> BuildRawData(TraceEvent data)
    {
        var dict = new Dictionary<string, string>
        {
            ["ProviderName"] = data.ProviderName,
            ["EventName"]    = data.EventName,
            ["TaskId"]       = ((int)data.Task).ToString()
        };

        try
        {
            foreach (var name in data.PayloadNames)
            {
                var val = data.PayloadByName(name);
                if (val is not null)
                    dict[name] = val.ToString() ?? string.Empty;
            }
        }
        catch { /* best-effort */ }

        return dict;
    }

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
    }
}

// ── Telemetry type for ThreatIntel events ────────────────────────────────────

public enum ThreatIntelEventKind
{
    CrossProcessAllocVm,
    ExecutableMemoryProtection,
    CrossProcessMapView,
    CrossProcessQueueApc,
    CrossProcessSetThreadContext
}

public sealed class ThreatIntelTelemetry
{
    public required ThreatIntelEventKind EventKind       { get; init; }
    public required int                  CallerProcessId { get; init; }
    public required int                  TargetProcessId { get; init; }
    public required string               Evidence        { get; init; }
    public required double               Confidence      { get; init; }
    public required DateTimeOffset       Timestamp       { get; init; }
    public required Dictionary<string, string> RawData   { get; init; }
}
