using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// In-memory event graph that maintains temporal and causal relationships
/// between processes, files, network endpoints, and memory events.
///
/// This is NOT a traditional graph database — it's a lightweight, lock-free
/// structure optimized for real-time EDR queries:
///
///   - "What did this process do in the last 60 seconds?"
///   - "Which processes touched this file?"
///   - "What's the full attack tree from this root PID?"
///   - "Which processes connected to this IP?"
///   - "Show me the temporal sequence of events for this incident"
///
/// Nodes: Processes, Files, Network Endpoints, Memory Regions
/// Edges: Created, Wrote, Read, Connected, Injected, Spawned
///
/// The graph auto-prunes nodes older than 10 minutes to prevent unbounded growth.
/// For forensic retention, the ChainTracer and JsonlEventLogger persist full evidence.
/// </summary>
public sealed class EventGraph
{
    private readonly ILogger<EventGraph> _logger;

    // Process nodes: PID → ProcessGraphNode
    private readonly ConcurrentDictionary<int, ProcessGraphNode> _processes = new();

    // File nodes: normalized path → FileGraphNode
    private readonly ConcurrentDictionary<string, FileGraphNode> _files = new();

    // Network endpoint nodes: "ip:port" → NetworkGraphNode
    private readonly ConcurrentDictionary<string, NetworkGraphNode> _endpoints = new();

    // Edges (all types stored in a single concurrent bag per source PID for fast traversal)
    private readonly ConcurrentDictionary<int, ConcurrentBag<GraphEdge>> _edges = new();

    // Retention window
    private static readonly TimeSpan RetentionWindow = TimeSpan.FromMinutes(10);

    public EventGraph(ILogger<EventGraph> logger)
    {
        _logger = logger;
    }

    // ── Node creation ────────────────────────────────────────────────────────

    /// <summary>
    /// Adds or updates a process node in the graph.
    /// </summary>
    public void AddProcessNode(int pid, string name, string imagePath,
        int parentPid, DateTimeOffset timestamp)
    {
        var node = _processes.GetOrAdd(pid, _ => new ProcessGraphNode
        {
            ProcessId = pid,
            ProcessName = name,
            ImagePath = imagePath,
            ParentPid = parentPid,
            FirstSeen = timestamp
        });

        node.LastSeen = timestamp;

        // Create parent→child edge
        if (parentPid > 0)
        {
            AddEdge(parentPid, new GraphEdge
            {
                Kind = EdgeKind.Spawned,
                SourcePid = parentPid,
                TargetPid = pid,
                TargetPath = null,
                Timestamp = timestamp,
                Details = $"Spawned {name}"
            });
        }
    }

    /// <summary>
    /// Adds a file interaction edge (process → file).
    /// </summary>
    public void AddFileEdge(int pid, string filePath, FileActivityKind activity,
        DateTimeOffset timestamp)
    {
        var normalizedPath = NormalizePath(filePath);

        // Ensure file node exists
        var fileNode = _files.GetOrAdd(normalizedPath, _ => new FileGraphNode
        {
            Path = normalizedPath,
            FirstSeen = timestamp
        });
        fileNode.LastSeen = timestamp;
        fileNode.AccessCount++;

        // Add edge
        var edgeKind = activity switch
        {
            FileActivityKind.Write => EdgeKind.Wrote,
            FileActivityKind.Create => EdgeKind.Created,
            FileActivityKind.Delete => EdgeKind.Deleted,
            FileActivityKind.Rename => EdgeKind.Renamed,
            _ => EdgeKind.Read
        };

        AddEdge(pid, new GraphEdge
        {
            Kind = edgeKind,
            SourcePid = pid,
            TargetPid = 0,
            TargetPath = normalizedPath,
            Timestamp = timestamp,
            Details = $"{activity}: {Path.GetFileName(filePath)}"
        });
    }

    /// <summary>
    /// Adds a network connection edge (process → endpoint).
    /// </summary>
    public void AddNetworkEdge(int pid, string remoteAddress, int remotePort,
        DateTimeOffset timestamp)
    {
        var endpointKey = $"{remoteAddress}:{remotePort}";

        var endpointNode = _endpoints.GetOrAdd(endpointKey, _ => new NetworkGraphNode
        {
            Address = remoteAddress,
            Port = remotePort,
            FirstSeen = timestamp
        });
        endpointNode.LastSeen = timestamp;
        endpointNode.ConnectionCount++;

        AddEdge(pid, new GraphEdge
        {
            Kind = EdgeKind.Connected,
            SourcePid = pid,
            TargetPid = 0,
            TargetPath = endpointKey,
            Timestamp = timestamp,
            Details = $"Connected to {endpointKey}"
        });
    }

    /// <summary>
    /// Adds an injection edge (caller → target process).
    /// </summary>
    public void AddInjectionEdge(int callerPid, int targetPid,
        ThreatIntelEventKind kind, DateTimeOffset timestamp)
    {
        AddEdge(callerPid, new GraphEdge
        {
            Kind = EdgeKind.Injected,
            SourcePid = callerPid,
            TargetPid = targetPid,
            TargetPath = null,
            Timestamp = timestamp,
            Details = $"Injection ({kind}): PID {callerPid} → PID {targetPid}"
        });
    }

    /// <summary>
    /// Adds a memory behavior event to the graph.
    /// </summary>
    public void AddMemoryEvent(int pid, MemoryBehaviorKind kind, DateTimeOffset timestamp)
    {
        AddEdge(pid, new GraphEdge
        {
            Kind = EdgeKind.MemoryOperation,
            SourcePid = pid,
            TargetPid = 0,
            TargetPath = null,
            Timestamp = timestamp,
            Details = $"Memory: {kind}"
        });
    }

    // ── Queries ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Gets all edges originating from a process within a time window.
    /// </summary>
    public IReadOnlyList<GraphEdge> GetProcessActivity(int pid, TimeSpan? window = null)
    {
        var cutoff = DateTimeOffset.UtcNow - (window ?? RetentionWindow);

        if (!_edges.TryGetValue(pid, out var edges))
            return Array.Empty<GraphEdge>();

        return edges.Where(e => e.Timestamp >= cutoff)
                   .OrderBy(e => e.Timestamp)
                   .ToList();
    }

    /// <summary>
    /// Gets the full process tree (descendants) from a root PID.
    /// </summary>
    public IReadOnlyList<ProcessGraphNode> GetProcessTree(int rootPid)
    {
        var result = new List<ProcessGraphNode>();
        var visited = new HashSet<int>();
        var queue = new Queue<int>();
        queue.Enqueue(rootPid);

        while (queue.Count > 0 && result.Count < 100) // Safety cap
        {
            var pid = queue.Dequeue();
            if (!visited.Add(pid)) continue;

            if (_processes.TryGetValue(pid, out var node))
            {
                result.Add(node);

                // Find children (processes whose parent is this PID)
                var children = _processes.Values
                    .Where(p => p.ParentPid == pid && !visited.Contains(p.ProcessId));

                foreach (var child in children)
                    queue.Enqueue(child.ProcessId);
            }
        }

        return result;
    }

    /// <summary>
    /// Gets all processes that accessed a specific file.
    /// </summary>
    public IReadOnlyList<int> GetFileAccessors(string filePath)
    {
        var normalizedPath = NormalizePath(filePath);
        var accessors = new HashSet<int>();

        foreach (var (pid, edges) in _edges)
        {
            if (edges.Any(e => e.TargetPath == normalizedPath &&
                e.Kind is EdgeKind.Read or EdgeKind.Wrote or EdgeKind.Created))
            {
                accessors.Add(pid);
            }
        }

        return accessors.ToList();
    }

    /// <summary>
    /// Gets all processes that connected to a specific endpoint.
    /// </summary>
    public IReadOnlyList<int> GetEndpointConnectors(string address, int port)
    {
        var endpointKey = $"{address}:{port}";
        var connectors = new HashSet<int>();

        foreach (var (pid, edges) in _edges)
        {
            if (edges.Any(e => e.TargetPath == endpointKey && e.Kind == EdgeKind.Connected))
            {
                connectors.Add(pid);
            }
        }

        return connectors.ToList();
    }

    /// <summary>
    /// Gets the temporal event sequence for an incident (all events across
    /// related processes within a time window, ordered chronologically).
    /// </summary>
    public IReadOnlyList<GraphEdge> GetIncidentTimeline(int rootPid, TimeSpan window)
    {
        // Get all related PIDs (tree + injection targets)
        var relatedPids = new HashSet<int>();
        var tree = GetProcessTree(rootPid);
        foreach (var node in tree)
            relatedPids.Add(node.ProcessId);

        // Also include injection targets
        foreach (var pid in relatedPids.ToList())
        {
            if (_edges.TryGetValue(pid, out var edges))
            {
                foreach (var edge in edges.Where(e => e.Kind == EdgeKind.Injected))
                {
                    relatedPids.Add(edge.TargetPid);
                }
            }
        }

        // Collect all events from related PIDs
        var cutoff = DateTimeOffset.UtcNow - window;
        var timeline = new List<GraphEdge>();

        foreach (var pid in relatedPids)
        {
            if (_edges.TryGetValue(pid, out var edges))
            {
                timeline.AddRange(edges.Where(e => e.Timestamp >= cutoff));
            }
        }

        return timeline.OrderBy(e => e.Timestamp).ToList();
    }

    /// <summary>
    /// Gets graph statistics.
    /// </summary>
    public EventGraphStats GetStats() => new()
    {
        ProcessNodes = _processes.Count,
        FileNodes = _files.Count,
        NetworkNodes = _endpoints.Count,
        TotalEdges = _edges.Values.Sum(bag => bag.Count)
    };

    /// <summary>
    /// Prunes nodes and edges older than the retention window.
    /// Called periodically by TelemetryFusionEngine.
    /// </summary>
    public void Prune()
    {
        var cutoff = DateTimeOffset.UtcNow - RetentionWindow;

        // Prune old process nodes
        var oldProcesses = _processes
            .Where(kv => kv.Value.LastSeen < cutoff)
            .Select(kv => kv.Key)
            .ToList();
        foreach (var pid in oldProcesses)
        {
            _processes.TryRemove(pid, out _);
            _edges.TryRemove(pid, out _);
        }

        // Prune old file nodes
        var oldFiles = _files
            .Where(kv => kv.Value.LastSeen < cutoff)
            .Select(kv => kv.Key)
            .ToList();
        foreach (var path in oldFiles)
            _files.TryRemove(path, out _);

        // Prune old network nodes
        var oldEndpoints = _endpoints
            .Where(kv => kv.Value.LastSeen < cutoff)
            .Select(kv => kv.Key)
            .ToList();
        foreach (var ep in oldEndpoints)
            _endpoints.TryRemove(ep, out _);
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private void AddEdge(int sourcePid, GraphEdge edge)
    {
        var bag = _edges.GetOrAdd(sourcePid, _ => new ConcurrentBag<GraphEdge>());
        bag.Add(edge);
    }

    private static string NormalizePath(string path)
    {
        return path.ToLowerInvariant().Replace('/', '\\').TrimEnd('\\');
    }
}

// ── Graph node types ─────────────────────────────────────────────────────────

public sealed class ProcessGraphNode
{
    public required int ProcessId { get; init; }
    public required string ProcessName { get; init; }
    public required string ImagePath { get; init; }
    public required int ParentPid { get; init; }
    public required DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen { get; set; }
}

public sealed class FileGraphNode
{
    public required string Path { get; init; }
    public required DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen { get; set; }
    public int AccessCount { get; set; }
}

public sealed class NetworkGraphNode
{
    public required string Address { get; init; }
    public required int Port { get; init; }
    public required DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen { get; set; }
    public int ConnectionCount { get; set; }
}

// ── Edge types ───────────────────────────────────────────────────────────────

public enum EdgeKind
{
    Spawned,        // Process → Process (parent created child)
    Injected,       // Process → Process (injection)
    Read,           // Process → File
    Wrote,          // Process → File
    Created,        // Process → File
    Deleted,        // Process → File
    Renamed,        // Process → File
    Connected,      // Process → Network endpoint
    Listened,       // Process → Network port
    MemoryOperation // Process → self (memory behavior)
}

public sealed class GraphEdge
{
    public required EdgeKind Kind { get; init; }
    public required int SourcePid { get; init; }
    public required int TargetPid { get; init; }
    public required string? TargetPath { get; init; }
    public required DateTimeOffset Timestamp { get; init; }
    public required string Details { get; init; }
}

/// <summary>
/// Graph statistics.
/// </summary>
public sealed class EventGraphStats
{
    public int ProcessNodes { get; init; }
    public int FileNodes { get; init; }
    public int NetworkNodes { get; init; }
    public int TotalEdges { get; init; }
}

