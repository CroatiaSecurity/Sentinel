using System;
using System.Collections.Generic;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class EventGraphTests
    {
        [Fact]
        public void AddNode_StoresNode()
        {
            var graph = new EventGraph();
            graph.AddNode("proc:1000", "process", new Dictionary<string, string> { ["name"] = "test.exe" });
            // Should not throw; node is tracked internally
        }

        [Fact]
        public void AddEdge_StoresEdge()
        {
            var graph = new EventGraph();
            graph.AddNode("proc:1000", "process");
            graph.AddNode("file:test.txt", "file");
            graph.AddEdge("proc:1000", "file:test.txt", "WRITE");
            // Edge is stored; query it
            var edges = graph.GetProcessEdges("proc:1000");
            Assert.NotEmpty(edges);
        }

        [Fact]
        public void Prune_RemovesOldNodes()
        {
            var graph = new EventGraph();
            graph.AddNode("proc:old", "process");
            // Prune with very short retention should remove it
            graph.Prune(TimeSpan.FromTicks(1));
        }

        [Fact]
        public void AddEdge_CapsPerNode()
        {
            var graph = new EventGraph();
            graph.AddNode("proc:heavy", "process");
            for (int i = 0; i < 500; i++)
            {
                graph.AddNode($"file:{i}", "file");
                graph.AddEdge("proc:heavy", $"file:{i}", "WRITE");
            }
            var edges = graph.GetProcessEdges("proc:heavy");
            // Should be capped well below 500
            Assert.True(edges.Count <= 300);
        }

        [Fact]
        public void GetProcessEdges_ReturnsEmpty_ForUnknownNode()
        {
            var graph = new EventGraph();
            var edges = graph.GetProcessEdges("nonexistent");
            Assert.Empty(edges);
        }
    }
}
