using Microsoft.Extensions.Logging.Abstractions;
using WindowsSentinel.Core.Engine;
using Xunit;

namespace WindowsSentinel.Tests.Monitors;

/// <summary>
/// Tests for EventGraph memory management — edge caps and pruning.
/// </summary>
public sealed class EventGraphTests
{
    private EventGraph CreateGraph() => new(NullLogger<EventGraph>.Instance);

    [Fact]
    public void AddEdge_CapsAt300PerProcess()
    {
        var graph = CreateGraph();

        // Add a process node first
        graph.AddProcessNode(1000, "test.exe", @"C:\test.exe", 4, DateTimeOffset.UtcNow);

        // Add 400 file edges to the same PID
        for (int i = 0; i < 400; i++)
        {
            graph.AddFileEdge(1000, $@"C:\file{i}.txt", FileActivityKind.Write, DateTimeOffset.UtcNow);
        }

        // After cap + trim, should be well under 400
        var stats = graph.GetStats();
        Assert.True(stats.TotalEdges <= 300, $"Expected <= 300 edges, got {stats.TotalEdges}");
    }

    [Fact]
    public void Prune_RemovesOldProcessNodes()
    {
        var graph = CreateGraph();

        // Add a process with old timestamp (15 minutes ago — beyond 10-min retention)
        var oldTime = DateTimeOffset.UtcNow.AddMinutes(-15);
        graph.AddProcessNode(2000, "old.exe", @"C:\old.exe", 4, oldTime);

        // Add a recent process
        graph.AddProcessNode(3000, "new.exe", @"C:\new.exe", 4, DateTimeOffset.UtcNow);

        graph.Prune();

        var stats = graph.GetStats();
        // Old process should be pruned, new one should remain
        Assert.Equal(1, stats.ProcessNodes);
    }

    [Fact]
    public void Prune_TrimsEdgeBagsOver150()
    {
        var graph = CreateGraph();

        // Add a process with recent timestamp so it doesn't get pruned
        graph.AddProcessNode(4000, "active.exe", @"C:\active.exe", 4, DateTimeOffset.UtcNow);

        // Add 200 edges (under the AddEdge cap of 300 but over the Prune threshold of 150)
        for (int i = 0; i < 200; i++)
        {
            graph.AddFileEdge(4000, $@"C:\file{i}.txt", FileActivityKind.Write, DateTimeOffset.UtcNow);
        }

        graph.Prune();

        var stats = graph.GetStats();
        Assert.True(stats.TotalEdges <= 155, $"Expected <= 155 edges after prune, got {stats.TotalEdges}");
    }

    [Fact]
    public void Prune_EnforcesHardCapOnProcessNodes()
    {
        var graph = CreateGraph();

        // Add 6000 process nodes (exceeds 5000 hard cap)
        for (int i = 0; i < 6000; i++)
        {
            graph.AddProcessNode(i + 10000, $"proc{i}.exe", $@"C:\proc{i}.exe", 4, DateTimeOffset.UtcNow);
        }

        graph.Prune();

        var stats = graph.GetStats();
        // Should be trimmed to ~2500 (hard cap triggers at 5000, trims to 2500)
        Assert.True(stats.ProcessNodes <= 5000, $"Expected <= 5000 process nodes, got {stats.ProcessNodes}");
    }

    [Fact]
    public void AddNetworkEdge_StoresCorrectly()
    {
        var graph = CreateGraph();

        graph.AddProcessNode(5000, "browser.exe", @"C:\browser.exe", 4, DateTimeOffset.UtcNow);
        graph.AddNetworkEdge(5000, "8.8.8.8", 443, DateTimeOffset.UtcNow);

        var stats = graph.GetStats();
        Assert.Equal(1, stats.NetworkNodes);
        Assert.True(stats.TotalEdges >= 1);
    }
}
