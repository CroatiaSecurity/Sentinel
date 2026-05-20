using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Behavioral Baseline Service - Learns normal system behavior to reduce false positives.
/// Tracks known processes, paths, parent-child relationships, and network patterns.
///
/// SECURITY HARDENING (v0.4.0): persistence routed through <see cref="SecureCacheStore"/>
/// (DPAPI machine-scope + HMAC, ACL'd to SYSTEM/Admins). Pre-0.4 the JSON file under
/// %LOCALAPPDATA% could be hand-edited to mark an attacker's process as "established",
/// which IsEstablishedProcess()/IsKnownExecutablePath() would then trust.
/// </summary>
public sealed class BehavioralBaselineService : BackgroundService
{
    private readonly ILogger<BehavioralBaselineService> _logger;
    private readonly SecureCacheStore _store;

    // Baseline data structures
    private readonly ConcurrentDictionary<string, ProcessBehaviorProfile> _knownProcesses;
    private readonly ConcurrentDictionary<string, PathReputation> _knownExecutablePaths;
    private readonly ConcurrentDictionary<string, ParentChildRelationship> _knownParentChild;
    private readonly ConcurrentDictionary<string, NetworkDestination> _knownNetworkDestinations;

    // Learning configuration
    private readonly TimeSpan _saveInterval = TimeSpan.FromMinutes(5);
    private readonly int _minOccurrencesForTrust = 5;
    private readonly int _minDaysForTrust = 3;
    private DateTimeOffset _lastSave = DateTimeOffset.MinValue;

    public BehavioralBaselineService(ILogger<BehavioralBaselineService> logger)
    {
        _logger = logger;
        _store = new SecureCacheStore(logger, "behavioral_baseline");

        _knownProcesses = new ConcurrentDictionary<string, ProcessBehaviorProfile>();
        _knownExecutablePaths = new ConcurrentDictionary<string, PathReputation>();
        _knownParentChild = new ConcurrentDictionary<string, ParentChildRelationship>();
        _knownNetworkDestinations = new ConcurrentDictionary<string, NetworkDestination>();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Behavioral Baseline Service starting ===");

        // Load existing baseline
        await LoadBaselineAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
                
                // Periodically save baseline
                if (DateTimeOffset.UtcNow - _lastSave > _saveInterval)
                {
                    await SaveBaselineAsync(stoppingToken);
                }

                // Cleanup old entries
                CleanupOldEntries();
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "BehavioralBaseline: Error in main loop");
            }
        }

        // Final save
        await SaveBaselineAsync(stoppingToken);
    }

    /// <summary>
    /// Records process execution for baseline learning.
    /// </summary>
    public void RecordProcessExecution(string processName, string? executablePath, string? commandLine)
    {
        if (string.IsNullOrEmpty(processName)) return;

        var key = processName.ToLowerInvariant();
        
        _knownProcesses.AddOrUpdate(key,
            _ => new ProcessBehaviorProfile
            {
                ProcessName = processName,
                FirstSeen = DateTimeOffset.UtcNow,
                LastSeen = DateTimeOffset.UtcNow,
                ExecutionCount = 1,
                TypicalPaths = executablePath != null 
                    ? new HashSet<string> { executablePath } 
                    : new HashSet<string>(),
                TypicalCommandLines = commandLine != null 
                    ? new HashSet<string> { commandLine.Substring(0, Math.Min(200, commandLine.Length)) } 
                    : new HashSet<string>()
            },
            (_, existing) =>
            {
                existing.LastSeen = DateTimeOffset.UtcNow;
                existing.ExecutionCount++;
                
                if (executablePath != null)
                    existing.TypicalPaths.Add(executablePath);
                
                if (commandLine != null && existing.TypicalCommandLines.Count < 10)
                    existing.TypicalCommandLines.Add(commandLine.Substring(0, Math.Min(200, commandLine.Length)));
                
                return existing;
            });

        // Also record path reputation
        if (!string.IsNullOrEmpty(executablePath))
        {
            RecordExecutablePath(executablePath);
        }
    }

    /// <summary>
    /// Records parent-child process relationship.
    /// </summary>
    public void RecordParentChildRelationship(string parentName, string childName)
    {
        if (string.IsNullOrEmpty(parentName) || string.IsNullOrEmpty(childName)) return;

        var key = $"{parentName.ToLowerInvariant()}->{childName.ToLowerInvariant()}";
        
        _knownParentChild.AddOrUpdate(key,
            _ => new ParentChildRelationship
            {
                ParentName = parentName,
                ChildName = childName,
                FirstSeen = DateTimeOffset.UtcNow,
                LastSeen = DateTimeOffset.UtcNow,
                OccurrenceCount = 1
            },
            (_, existing) =>
            {
                existing.LastSeen = DateTimeOffset.UtcNow;
                existing.OccurrenceCount++;
                return existing;
            });
    }

    /// <summary>
    /// Records network destination for a process.
    /// </summary>
    public void RecordNetworkDestination(string processName, string remoteAddress, int remotePort)
    {
        if (string.IsNullOrEmpty(processName)) return;

        var key = $"{processName.ToLowerInvariant()}:{remoteAddress}:{remotePort}";
        
        _knownNetworkDestinations.AddOrUpdate(key,
            _ => new NetworkDestination
            {
                ProcessName = processName,
                RemoteAddress = remoteAddress,
                RemotePort = remotePort,
                FirstSeen = DateTimeOffset.UtcNow,
                LastSeen = DateTimeOffset.UtcNow,
                ConnectionCount = 1
            },
            (_, existing) =>
            {
                existing.LastSeen = DateTimeOffset.UtcNow;
                existing.ConnectionCount++;
                return existing;
            });
    }

    /// <summary>
    /// Checks if a process is known/established.
    /// </summary>
    public bool IsKnownProcess(string processName)
    {
        if (string.IsNullOrEmpty(processName)) return false;
        return _knownProcesses.ContainsKey(processName.ToLowerInvariant());
    }

    /// <summary>
    /// Checks if a process is established (trusted based on frequency and age).
    /// </summary>
    public bool IsEstablishedProcess(string processName)
    {
        if (string.IsNullOrEmpty(processName)) return false;
        
        if (_knownProcesses.TryGetValue(processName.ToLowerInvariant(), out var profile))
        {
            var daysSinceFirstSeen = (DateTimeOffset.UtcNow - profile.FirstSeen).TotalDays;
            return profile.ExecutionCount >= _minOccurrencesForTrust && daysSinceFirstSeen >= _minDaysForTrust;
        }
        
        return false;
    }

    /// <summary>
    /// Checks if an executable path is known.
    /// </summary>
    public bool IsKnownExecutablePath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        return _knownExecutablePaths.ContainsKey(path.ToLowerInvariant());
    }

    /// <summary>
    /// Checks if a parent-child relationship is known.
    /// </summary>
    public bool IsKnownParentChild(string parentName, string childName)
    {
        if (string.IsNullOrEmpty(parentName) || string.IsNullOrEmpty(childName)) return false;
        
        var key = $"{parentName.ToLowerInvariant()}->{childName.ToLowerInvariant()}";
        return _knownParentChild.ContainsKey(key);
    }

    /// <summary>
    /// Checks if a network destination is known for a process.
    /// </summary>
    public bool IsKnownNetworkDestination(string processName, string remoteAddress, int remotePort)
    {
        if (string.IsNullOrEmpty(processName)) return false;
        
        var key = $"{processName.ToLowerInvariant()}:{remoteAddress}:{remotePort}";
        return _knownNetworkDestinations.ContainsKey(key);
    }

    /// <summary>
    /// Gets trust score for a process (0-100).
    /// </summary>
    public int GetProcessTrustScore(string processName, string? executablePath = null)
    {
        if (string.IsNullOrEmpty(processName)) return 50; // Neutral
        
        int score = 50;
        
        // Known process boost
        if (IsKnownProcess(processName))
        {
            score += 10;
            
            // Established process boost
            if (IsEstablishedProcess(processName))
            {
                score += 20;
            }
        }
        
        // Known path boost
        if (!string.IsNullOrEmpty(executablePath) && IsKnownExecutablePath(executablePath))
        {
            score += 15;
        }
        
        return Math.Min(100, score);
    }

    /// <summary>
    /// Gets baseline statistics.
    /// </summary>
    public BaselineStatistics GetStatistics()
    {
        return new BaselineStatistics
        {
            KnownProcesses = _knownProcesses.Count,
            KnownPaths = _knownExecutablePaths.Count,
            KnownParentChild = _knownParentChild.Count,
            KnownNetworkDestinations = _knownNetworkDestinations.Count,
            EstablishedProcesses = _knownProcesses.Count(p => IsEstablishedProcess(p.Key)),
            LastUpdated = _lastSave
        };
    }

    /// <summary>
    /// Exports baseline to JSON.
    /// </summary>
    public string ExportToJson()
    {
        var data = new BaselineData
        {
            Processes = _knownProcesses.Values.ToList(),
            Paths = _knownExecutablePaths.Values.ToList(),
            ParentChild = _knownParentChild.Values.ToList(),
            NetworkDestinations = _knownNetworkDestinations.Values.ToList(),
            ExportedAt = DateTimeOffset.UtcNow
        };
        
        return JsonSerializer.Serialize(data, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
    }

    private void RecordExecutablePath(string path)
    {
        if (string.IsNullOrEmpty(path)) return;
        
        var key = path.ToLowerInvariant();
        
        _knownExecutablePaths.AddOrUpdate(key,
            _ => new PathReputation
            {
                Path = path,
                FirstSeen = DateTimeOffset.UtcNow,
                LastSeen = DateTimeOffset.UtcNow,
                ExecutionCount = 1
            },
            (_, existing) =>
            {
                existing.LastSeen = DateTimeOffset.UtcNow;
                existing.ExecutionCount++;
                return existing;
            });
    }

    private Task LoadBaselineAsync(CancellationToken cancellationToken)
    {
        var data = _store.TryLoad<BaselineData>();
        if (data is null)
        {
            _logger.LogInformation("BehavioralBaseline: No trusted baseline loaded — starting fresh");
            return Task.CompletedTask;
        }

        foreach (var proc in data.Processes)
            _knownProcesses[proc.ProcessName.ToLowerInvariant()] = proc;
        foreach (var path in data.Paths)
            _knownExecutablePaths[path.Path.ToLowerInvariant()] = path;
        foreach (var pc in data.ParentChild)
        {
            var key = $"{pc.ParentName.ToLowerInvariant()}->{pc.ChildName.ToLowerInvariant()}";
            _knownParentChild[key] = pc;
        }
        foreach (var net in data.NetworkDestinations)
        {
            var key = $"{net.ProcessName.ToLowerInvariant()}:{net.RemoteAddress}:{net.RemotePort}";
            _knownNetworkDestinations[key] = net;
        }

        _logger.LogInformation(
            "BehavioralBaseline: Loaded {Processes} processes, {Paths} paths, {PC} parent-child, {Net} network destinations",
            _knownProcesses.Count, _knownExecutablePaths.Count,
            _knownParentChild.Count, _knownNetworkDestinations.Count);
        return Task.CompletedTask;
    }

    private Task SaveBaselineAsync(CancellationToken cancellationToken)
    {
        var data = new BaselineData
        {
            Processes = _knownProcesses.Values.ToList(),
            Paths = _knownExecutablePaths.Values.ToList(),
            ParentChild = _knownParentChild.Values.ToList(),
            NetworkDestinations = _knownNetworkDestinations.Values.Take(1000).ToList(),
            ExportedAt = DateTimeOffset.UtcNow
        };
        if (_store.TrySave(data))
        {
            _lastSave = DateTimeOffset.UtcNow;
            _logger.LogDebug("BehavioralBaseline: Saved baseline ({Processes} processes)", _knownProcesses.Count);
        }
        else
        {
            _logger.LogWarning("BehavioralBaseline: Save failed");
        }
        return Task.CompletedTask;
    }

    private void CleanupOldEntries()
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-30);
        
        // Remove old process entries
        var oldProcesses = _knownProcesses.Where(p => p.Value.LastSeen < cutoff).Select(p => p.Key).ToList();
        foreach (var key in oldProcesses)
        {
            _knownProcesses.TryRemove(key, out _);
        }

        // Remove old path entries
        var oldPaths = _knownExecutablePaths.Where(p => p.Value.LastSeen < cutoff).Select(p => p.Key).ToList();
        foreach (var key in oldPaths)
        {
            _knownExecutablePaths.TryRemove(key, out _);
        }

        // Remove old parent-child
        var oldPC = _knownParentChild.Where(p => p.Value.LastSeen < cutoff).Select(p => p.Key).ToList();
        foreach (var key in oldPC)
        {
            _knownParentChild.TryRemove(key, out _);
        }

        // Remove old network destinations
        var oldNet = _knownNetworkDestinations.Where(p => p.Value.LastSeen < cutoff).Select(p => p.Key).ToList();
        foreach (var key in oldNet)
        {
            _knownNetworkDestinations.TryRemove(key, out _);
        }

        if (oldProcesses.Count > 0 || oldPaths.Count > 0)
        {
            _logger.LogDebug(
                "BehavioralBaseline: Cleaned up {Proc} processes, {Path} paths, {PC} parent-child, {Net} network",
                oldProcesses.Count, oldPaths.Count, oldPC.Count, oldNet.Count);
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("BehavioralBaseline: Saving baseline before shutdown...");
        await SaveBaselineAsync(cancellationToken);
        await base.StopAsync(cancellationToken);
    }
}

// Data models

public sealed class ProcessBehaviorProfile
{
    public string ProcessName { get; set; } = "";
    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    public int ExecutionCount { get; set; }
    public HashSet<string> TypicalPaths { get; set; } = new();
    public HashSet<string> TypicalCommandLines { get; set; } = new();
}

public sealed class PathReputation
{
    public string Path { get; set; } = "";
    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    public int ExecutionCount { get; set; }
}

public sealed class ParentChildRelationship
{
    public string ParentName { get; set; } = "";
    public string ChildName { get; set; } = "";
    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    public int OccurrenceCount { get; set; }
}

public sealed class NetworkDestination
{
    public string ProcessName { get; set; } = "";
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    public int ConnectionCount { get; set; }
}

public sealed class BaselineData
{
    public List<ProcessBehaviorProfile> Processes { get; set; } = new();
    public List<PathReputation> Paths { get; set; } = new();
    public List<ParentChildRelationship> ParentChild { get; set; } = new();
    public List<NetworkDestination> NetworkDestinations { get; set; } = new();
    public DateTimeOffset ExportedAt { get; set; }
}

public sealed class BaselineStatistics
{
    public int KnownProcesses { get; set; }
    public int KnownPaths { get; set; }
    public int KnownParentChild { get; set; }
    public int KnownNetworkDestinations { get; set; }
    public int EstablishedProcesses { get; set; }
    public DateTimeOffset LastUpdated { get; set; }

    public double EstablishedRatio => KnownProcesses > 0 ? (double)EstablishedProcesses / KnownProcesses : 0;
}


