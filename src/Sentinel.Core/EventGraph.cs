using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace Sentinel.Core
{
    public class GraphNode
    {
        public string Key { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty; // PROCESS, FILE, ENDPOINT
        public DateTime LastSeen { get; set; } = DateTime.UtcNow;
        public Dictionary<string, string> Properties { get; set; } = new();
    }

    public class GraphEdge
    {
        public string SourceKey { get; set; } = string.Empty;
        public string TargetKey { get; set; } = string.Empty;
        public string Relation { get; set; } = string.Empty; // WROTE, CONNECTED, SPAWNED
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    public class EventGraph
    {
        private readonly ConcurrentDictionary<string, GraphNode> _nodes = new();
        private readonly ConcurrentDictionary<string, List<GraphEdge>> _processEdges = new();
        private readonly object _pruneLock = new();

        private const int MaxEdgesPerProcess = 300;
        private const int TrimEdgesTarget = 150;

        private const int HardCapProcesses = 5000;
        private const int HardCapFiles = 10000;
        private const int HardCapEndpoints = 3000;

        public void AddNode(string key, string type, Dictionary<string, string>? properties = null)
        {
            var node = _nodes.GetOrAdd(key, k => new GraphNode { Key = k, Type = type });
            node.LastSeen = DateTime.UtcNow;
            if (properties != null)
            {
                foreach (var (pKey, pVal) in properties)
                {
                    node.Properties[pKey] = pVal;
                }
            }
        }

        public void AddEdge(string sourceKey, string targetKey, string relation)
        {
            var edge = new GraphEdge
            {
                SourceKey = sourceKey,
                TargetKey = targetKey,
                Relation = relation,
                Timestamp = DateTime.UtcNow
            };

            // Ensure source and target nodes exist
            AddNode(sourceKey, "PROCESS");
            AddNode(targetKey, relation == "WROTE" ? "FILE" : relation == "CONNECTED" ? "ENDPOINT" : "PROCESS");

            var edges = _processEdges.GetOrAdd(sourceKey, _ => new List<GraphEdge>());
            lock (edges)
            {
                edges.Add(edge);
                if (edges.Count > MaxEdgesPerProcess)
                {
                    // Trim to most recent 150
                    edges.RemoveRange(0, edges.Count - TrimEdgesTarget);
                }
            }
        }

        public List<GraphEdge> GetProcessEdges(string processKey)
        {
            if (_processEdges.TryGetValue(processKey, out var edges))
            {
                lock (edges)
                {
                    return new List<GraphEdge>(edges);
                }
            }
            return new List<GraphEdge>();
        }

        public void Prune(TimeSpan retentionWindow)
        {
            lock (_pruneLock)
            {
                var cutoff = DateTime.UtcNow - retentionWindow;

                // 1. Identify stale nodes
                var staleKeys = _nodes.Where(n => n.Value.LastSeen < cutoff).Select(n => n.Key).ToList();
                foreach (var key in staleKeys)
                {
                    _nodes.TryRemove(key, out _);
                    _processEdges.TryRemove(key, out _);
                }

                // 2. Enforce hard caps
                EnforceHardCaps("PROCESS", HardCapProcesses);
                EnforceHardCaps("FILE", HardCapFiles);
                EnforceHardCaps("ENDPOINT", HardCapEndpoints);
            }
        }

        private void EnforceHardCaps(string type, int capLimit)
        {
            var typeNodes = _nodes.Where(n => n.Value.Type == type).ToList();
            if (typeNodes.Count > capLimit)
            {
                var keysToRemove = typeNodes
                    .OrderBy(n => n.Value.LastSeen)
                    .Take(typeNodes.Count - capLimit)
                    .Select(n => n.Key)
                    .ToList();

                foreach (var key in keysToRemove)
                {
                    _nodes.TryRemove(key, out _);
                    _processEdges.TryRemove(key, out _);
                }
            }
        }
    }
}
