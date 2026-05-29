using System.Collections.Concurrent;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Telemetry Fusion Engine — Correlates raw telemetry events across all sources
/// (ETW process, file I/O, network, ThreatIntel, AMSI/PowerShell) into unified
/// event chains BEFORE they reach detection rules.
///
/// This is the 1.0.0 architectural upgrade: instead of each monitor independently
/// feeding the DetectionEngine, all raw telemetry flows through the fusion layer
/// first. The fusion layer:
///
///   1. Enriches events with cross-source context (e.g., "this network connection
///      was made by a process that just wrote to a suspicious path")
///   2. Builds temporal event chains per-process (ordered sequence of actions)
///   3. Detects multi-source behavioral patterns that no single rule can see
///   4. Feeds the EventGraph for causal/temporal queries
///
/// Design principle: fusion is PASSIVE enrichment. It never blocks, never kills,
/// never modifies the original telemetry. It adds context that detection rules
/// and the correlation engine can use for higher-confidence decisions.
/// </summary>
public sealed class TelemetryFusionEngine : BackgroundService
{
    private readonly ILogger<TelemetryFusionEngine> _logger;
    private readonly EventGraph _eventGraph;
    private readonly ProcessAncestryCache _ancestryCache;

    // Per-process event chains: ordered sequence of all telemetry events
    private readonly ConcurrentDictionary<int, ProcessEventChain> _chains = new();

    // Cross-process relationships (caller → target for injection, network relay, etc.)
    private readonly ConcurrentDictionary<string, CrossProcessRelation> _relations = new();

    // Temporal window for chain analysis
    private static readonly TimeSpan ChainWindow = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromSeconds(30);

    // Statistics
    private long _totalEventsProcessed;
    private long _fusedCorrelations;

    public TelemetryFusionEngine(
        ILogger<TelemetryFusionEngine> logger,
        EventGraph eventGraph,
        ProcessAncestryCache ancestryCache)
    {
        _logger = logger;
        _eventGraph = eventGraph;
        _ancestryCache = ancestryCache;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Telemetry Fusion Engine starting (v1.0.0) ===");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(CleanupInterval, stoppingToken);
                PruneStaleChains();
                PruneStaleRelations();
                // v4.2.0: Prune the EventGraph to prevent unbounded memory growth
                _eventGraph.Prune();
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "TelemetryFusion: Cleanup error");
            }
        }
    }

    /// <summary>
    /// Ingests a process telemetry event and returns enriched context.
    /// Called by EtwProcessMonitor / WmiProcessMonitor before forwarding to DetectionEngine.
    /// </summary>
    public FusedTelemetryContext IngestProcess(ProcessTelemetry telemetry)
    {
        Interlocked.Increment(ref _totalEventsProcessed);

        var chain = GetOrCreateChain(telemetry.ProcessId, telemetry.ProcessName);

        chain.AddEvent(new ChainEvent
        {
            Kind = TelemetryKind.ProcessStart,
            Timestamp = telemetry.Timestamp,
            Summary = $"Process start: {telemetry.ProcessName} (parent: {telemetry.ParentProcessName})",
            Metadata = new Dictionary<string, string>
            {
                ["image_path"] = telemetry.ImagePath,
                ["command_line"] = telemetry.CommandLine,
                ["parent_pid"] = telemetry.ParentProcessId.ToString(),
                ["parent_name"] = telemetry.ParentProcessName
            }
        });

        // Update event graph
        _eventGraph.AddProcessNode(telemetry.ProcessId, telemetry.ProcessName,
            telemetry.ImagePath, telemetry.ParentProcessId, telemetry.Timestamp);

        // Build fused context
        return BuildContext(telemetry.ProcessId, chain);
    }

    /// <summary>
    /// Ingests a network telemetry event and returns enriched context.
    /// </summary>
    public FusedTelemetryContext IngestNetwork(int processId, string processName,
        string remoteAddress, int remotePort, DateTimeOffset timestamp)
    {
        Interlocked.Increment(ref _totalEventsProcessed);

        var chain = GetOrCreateChain(processId, processName);

        chain.AddEvent(new ChainEvent
        {
            Kind = TelemetryKind.NetworkConnection,
            Timestamp = timestamp,
            Summary = $"Network: {remoteAddress}:{remotePort}",
            Metadata = new Dictionary<string, string>
            {
                ["remote_address"] = remoteAddress,
                ["remote_port"] = remotePort.ToString()
            }
        });

        // Update event graph
        _eventGraph.AddNetworkEdge(processId, remoteAddress, remotePort, timestamp);

        return BuildContext(processId, chain);
    }

    /// <summary>
    /// Ingests a file activity telemetry event and returns enriched context.
    /// </summary>
    public FusedTelemetryContext IngestFileActivity(int processId, string processName,
        string filePath, FileActivityKind activityKind, DateTimeOffset timestamp)
    {
        Interlocked.Increment(ref _totalEventsProcessed);

        var chain = GetOrCreateChain(processId, processName);

        chain.AddEvent(new ChainEvent
        {
            Kind = activityKind switch
            {
                FileActivityKind.Write => TelemetryKind.FileWrite,
                FileActivityKind.Rename => TelemetryKind.FileRename,
                FileActivityKind.Delete => TelemetryKind.FileDelete,
                _ => TelemetryKind.FileRead
            },
            Timestamp = timestamp,
            Summary = $"File {activityKind}: {Path.GetFileName(filePath)}",
            Metadata = new Dictionary<string, string>
            {
                ["file_path"] = filePath,
                ["activity"] = activityKind.ToString()
            }
        });

        // Update event graph
        _eventGraph.AddFileEdge(processId, filePath, activityKind, timestamp);

        return BuildContext(processId, chain);
    }

    /// <summary>
    /// Ingests a ThreatIntel (kernel injection) event and returns enriched context.
    /// </summary>
    public FusedTelemetryContext IngestInjection(int callerPid, int targetPid,
        ThreatIntelEventKind kind, DateTimeOffset timestamp)
    {
        Interlocked.Increment(ref _totalEventsProcessed);

        var callerName = _ancestryCache.GetProcessName(callerPid) ?? "Unknown";
        var targetName = _ancestryCache.GetProcessName(targetPid) ?? "Unknown";

        var chain = GetOrCreateChain(callerPid, callerName);

        chain.AddEvent(new ChainEvent
        {
            Kind = TelemetryKind.Injection,
            Timestamp = timestamp,
            Summary = $"Injection ({kind}): PID {callerPid} → PID {targetPid}",
            Metadata = new Dictionary<string, string>
            {
                ["caller_pid"] = callerPid.ToString(),
                ["target_pid"] = targetPid.ToString(),
                ["target_name"] = targetName,
                ["injection_kind"] = kind.ToString()
            }
        });

        // Record cross-process relationship
        var relationKey = $"{callerPid}→{targetPid}";
        _relations[relationKey] = new CrossProcessRelation
        {
            CallerPid = callerPid,
            TargetPid = targetPid,
            Kind = CrossProcessRelationKind.Injection,
            Timestamp = timestamp
        };

        // Update event graph
        _eventGraph.AddInjectionEdge(callerPid, targetPid, kind, timestamp);

        Interlocked.Increment(ref _fusedCorrelations);
        return BuildContext(callerPid, chain);
    }

    /// <summary>
    /// Ingests a memory behavior event (RWX allocation, shellcode pattern, etc.)
    /// </summary>
    public FusedTelemetryContext IngestMemoryBehavior(int processId, string processName,
        MemoryBehaviorKind kind, string details, DateTimeOffset timestamp)
    {
        Interlocked.Increment(ref _totalEventsProcessed);

        var chain = GetOrCreateChain(processId, processName);

        chain.AddEvent(new ChainEvent
        {
            Kind = TelemetryKind.MemoryBehavior,
            Timestamp = timestamp,
            Summary = $"Memory: {kind} — {details}",
            Metadata = new Dictionary<string, string>
            {
                ["memory_kind"] = kind.ToString(),
                ["details"] = details
            }
        });

        _eventGraph.AddMemoryEvent(processId, kind, timestamp);

        return BuildContext(processId, chain);
    }

    /// <summary>
    /// Gets the full event chain for a process (for forensic analysis).
    /// </summary>
    public ProcessEventChain? GetChain(int processId)
    {
        _chains.TryGetValue(processId, out var chain);
        return chain;
    }

    /// <summary>
    /// Gets fusion statistics.
    /// </summary>
    public TelemetryFusionStats GetStats() => new()
    {
        TotalEventsProcessed = Interlocked.Read(ref _totalEventsProcessed),
        FusedCorrelations = Interlocked.Read(ref _fusedCorrelations),
        ActiveChains = _chains.Count,
        ActiveRelations = _relations.Count
    };

    // ── Private helpers ──────────────────────────────────────────────────────

    private ProcessEventChain GetOrCreateChain(int processId, string processName)
    {
        return _chains.GetOrAdd(processId, _ => new ProcessEventChain
        {
            ProcessId = processId,
            ProcessName = processName,
            CreatedAt = DateTimeOffset.UtcNow
        });
    }

    private FusedTelemetryContext BuildContext(int processId, ProcessEventChain chain)
    {
        var recentEvents = chain.GetRecent(TimeSpan.FromSeconds(60));

        // Compute behavioral indicators from the chain
        var hasNetwork = recentEvents.Any(e => e.Kind == TelemetryKind.NetworkConnection);
        var hasFileWrite = recentEvents.Any(e => e.Kind == TelemetryKind.FileWrite);
        var hasInjection = recentEvents.Any(e => e.Kind == TelemetryKind.Injection);
        var hasMemory = recentEvents.Any(e => e.Kind == TelemetryKind.MemoryBehavior);
        var fileWriteCount = recentEvents.Count(e => e.Kind is TelemetryKind.FileWrite or TelemetryKind.FileRename);
        var networkCount = recentEvents.Count(e => e.Kind == TelemetryKind.NetworkConnection);

        // Check for cross-process relationships involving this PID
        var isInjectionSource = _relations.Values.Any(r => r.CallerPid == processId);
        var isInjectionTarget = _relations.Values.Any(r => r.TargetPid == processId);

        // Compute behavioral velocity (events per second in last 30s)
        var last30s = recentEvents.Where(e =>
            (DateTimeOffset.UtcNow - e.Timestamp).TotalSeconds <= 30).ToList();
        var velocity = last30s.Count > 0 ? last30s.Count / 30.0 : 0;

        // Compute event diversity (unique kinds in last 60s)
        var diversity = recentEvents.Select(e => e.Kind).Distinct().Count();

        return new FusedTelemetryContext
        {
            ProcessId = processId,
            ProcessName = chain.ProcessName,
            ChainLength = chain.TotalEvents,
            RecentEventCount = recentEvents.Count,
            HasNetworkActivity = hasNetwork,
            HasFileWriteActivity = hasFileWrite,
            HasInjectionActivity = hasInjection,
            HasMemoryAnomaly = hasMemory,
            FileWriteCount = fileWriteCount,
            NetworkConnectionCount = networkCount,
            IsInjectionSource = isInjectionSource,
            IsInjectionTarget = isInjectionTarget,
            BehavioralVelocity = velocity,
            EventDiversity = diversity,
            // Multi-vector flag: process is doing file + network + memory/injection
            IsMultiVector = (hasFileWrite && hasNetwork && (hasInjection || hasMemory)),
            // Ancestors from cache
            Ancestors = _ancestryCache.GetAncestors(processId)
        };
    }

    private void PruneStaleChains()
    {
        var cutoff = DateTimeOffset.UtcNow - ChainWindow;
        var staleKeys = _chains
            .Where(kv => kv.Value.LastActivity < cutoff)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var key in staleKeys)
            _chains.TryRemove(key, out _);

        if (staleKeys.Count > 0)
            _logger.LogDebug("TelemetryFusion: Pruned {Count} stale chains", staleKeys.Count);
    }

    private void PruneStaleRelations()
    {
        var cutoff = DateTimeOffset.UtcNow - ChainWindow;
        var staleKeys = _relations
            .Where(kv => kv.Value.Timestamp < cutoff)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var key in staleKeys)
            _relations.TryRemove(key, out _);
    }
}

// ── Supporting types ─────────────────────────────────────────────────────────

public enum TelemetryKind
{
    ProcessStart,
    ProcessStop,
    NetworkConnection,
    NetworkListen,
    FileRead,
    FileWrite,
    FileRename,
    FileDelete,
    RegistryRead,
    RegistryWrite,
    Injection,
    MemoryBehavior,
    AmsiScan,
    PowerShellScript
}

public enum FileActivityKind
{
    Read,
    Write,
    Rename,
    Delete,
    Create
}

public enum MemoryBehaviorKind
{
    RwxAllocation,
    ShellcodePattern,
    UnbackedExecutable,
    SuspiciousUnmap,
    HollowedImage,
    ReflectiveLoad,
    ThreadHijack
}

public enum CrossProcessRelationKind
{
    Injection,
    RemoteThread,
    SharedMemory,
    NamedPipe,
    ParentChild
}

/// <summary>
/// A single event in a process's telemetry chain.
/// </summary>
public sealed class ChainEvent
{
    public required TelemetryKind Kind { get; init; }
    public required DateTimeOffset Timestamp { get; init; }
    public required string Summary { get; init; }
    public Dictionary<string, string> Metadata { get; init; } = new();
}

/// <summary>
/// Ordered sequence of all telemetry events for a single process.
/// Thread-safe via lock.
/// </summary>
public sealed class ProcessEventChain
{
    public required int ProcessId { get; init; }
    public required string ProcessName { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }

    private readonly List<ChainEvent> _events = new();
    private readonly object _lock = new();

    public DateTimeOffset LastActivity { get; private set; }
    public int TotalEvents => _events.Count;

    public void AddEvent(ChainEvent evt)
    {
        lock (_lock)
        {
            _events.Add(evt);
            LastActivity = evt.Timestamp;

            // Cap at 500 events per chain to prevent unbounded growth
            if (_events.Count > 500)
                _events.RemoveRange(0, _events.Count - 500);
        }
    }

    public IReadOnlyList<ChainEvent> GetRecent(TimeSpan window)
    {
        var cutoff = DateTimeOffset.UtcNow - window;
        lock (_lock)
        {
            return _events.Where(e => e.Timestamp >= cutoff).ToList();
        }
    }

    public IReadOnlyList<ChainEvent> GetAll()
    {
        lock (_lock) { return _events.ToList(); }
    }
}

/// <summary>
/// Cross-process relationship record.
/// </summary>
public sealed class CrossProcessRelation
{
    public int CallerPid { get; init; }
    public int TargetPid { get; init; }
    public CrossProcessRelationKind Kind { get; init; }
    public DateTimeOffset Timestamp { get; init; }
}

/// <summary>
/// Enriched context produced by the fusion engine for each telemetry event.
/// Detection rules can use this for higher-confidence decisions.
/// </summary>
public sealed class FusedTelemetryContext
{
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = "";
    public int ChainLength { get; init; }
    public int RecentEventCount { get; init; }

    // Behavioral flags
    public bool HasNetworkActivity { get; init; }
    public bool HasFileWriteActivity { get; init; }
    public bool HasInjectionActivity { get; init; }
    public bool HasMemoryAnomaly { get; init; }
    public int FileWriteCount { get; init; }
    public int NetworkConnectionCount { get; init; }

    // Cross-process context
    public bool IsInjectionSource { get; init; }
    public bool IsInjectionTarget { get; init; }

    // Velocity and diversity metrics
    public double BehavioralVelocity { get; init; }
    public int EventDiversity { get; init; }

    // Multi-vector indicator
    public bool IsMultiVector { get; init; }

    // Process ancestry
    public IReadOnlyList<string> Ancestors { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Fusion engine statistics.
/// </summary>
public sealed class TelemetryFusionStats
{
    public long TotalEventsProcessed { get; init; }
    public long FusedCorrelations { get; init; }
    public int ActiveChains { get; init; }
    public int ActiveRelations { get; init; }
}


