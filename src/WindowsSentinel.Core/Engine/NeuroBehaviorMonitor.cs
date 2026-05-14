using System.Collections.Concurrent;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// NeuroBehavior Monitor - Advanced behavioral pattern analysis.
/// Detects anomalies by analyzing process behavior patterns over time.
/// </summary>
public sealed class NeuroBehaviorMonitor : BackgroundService
{
    private readonly ILogger<NeuroBehaviorMonitor> _logger;
    private IDetectionEngine? _detectionEngine;
    
    private readonly ConcurrentDictionary<int, NeuroProcessProfile> _processProfiles;
    private readonly ConcurrentDictionary<string, BehaviorPattern> _learnedPatterns;
    
    private readonly TimeSpan _analysisInterval = TimeSpan.FromSeconds(15);
    private readonly int _anomalyThreshold = 70; // 0-100

    public NeuroBehaviorMonitor(ILogger<NeuroBehaviorMonitor> logger)
    {
        _logger = logger;
        _processProfiles = new ConcurrentDictionary<int, NeuroProcessProfile>();
        _learnedPatterns = new ConcurrentDictionary<string, BehaviorPattern>();
    }

    /// <summary>
    /// Sets the detection engine reference. Called after DI construction to avoid circular deps.
    /// </summary>
    public void SetDetectionEngine(IDetectionEngine engine) => _detectionEngine = engine;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== NeuroBehavior Monitor starting ===");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_analysisInterval, stoppingToken);
                
                // Analyze current process behaviors
                AnalyzeProcessBehaviors();
                
                // Detect anomalies
                DetectAnomalies();
                
                // Update learned patterns
                UpdateLearnedPatterns();
                
                // Cleanup old profiles
                CleanupOldProfiles();
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "NeuroBehavior: Error in main loop");
            }
        }
    }

    /// <summary>
    /// Records a behavior event for a process.
    /// </summary>
    public void RecordBehavior(int processId, string processName, BehaviorType type, string? details = null)
    {
        var profile = _processProfiles.GetOrAdd(processId, _ => new NeuroProcessProfile
        {
            ProcessId = processId,
            ProcessName = processName,
            StartTime = DateTimeOffset.UtcNow
        });

        profile.Events.Enqueue(new BehaviorEvent
        {
            Timestamp = DateTimeOffset.UtcNow,
            Type = type,
            Details = details ?? ""
        });

        // Keep only last 100 events
        while (profile.Events.Count > 100)
        {
            profile.Events.TryDequeue(out _);
        }

        profile.LastActivity = DateTimeOffset.UtcNow;
        profile.EventCounts[type] = profile.EventCounts.GetValueOrDefault(type) + 1;
    }

    private void AnalyzeProcessBehaviors()
    {
        foreach (var profile in _processProfiles.Values)
        {
            try
            {
                using var process = System.Diagnostics.Process.GetProcessById(profile.ProcessId);
                
                // Collect metrics
                profile.CPUUsage = (long)process.TotalProcessorTime.TotalMilliseconds;
                profile.MemoryUsageMB = process.WorkingSet64 / (1024 * 1024);
                profile.ThreadCount = process.Threads.Count;
                profile.HandleCount = process.HandleCount;

                // Calculate behavior entropy
                profile.BehaviorEntropy = CalculateBehaviorEntropy(profile);
                
                // Detect pattern
                profile.DetectedPattern = DetectBehaviorPattern(profile);
            }
            catch (System.ArgumentException)
            {
                // Process exited
                profile.IsActive = false;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "NeuroBehavior: Error analyzing PID {Pid}", profile.ProcessId);
            }
        }
    }

    private void DetectAnomalies()
    {
        foreach (var profile in _processProfiles.Values.Where(p => p.IsActive))
        {
            var anomalyScore = CalculateAnomalyScore(profile);
            
            if (anomalyScore > _anomalyThreshold)
            {
                _logger.LogWarning(
                    "NeuroBehavior: ANOMALY DETECTED - {Process} (PID {Pid}) - Score: {Score}/100 - Pattern: {Pattern}",
                    profile.ProcessName,
                    profile.ProcessId,
                    anomalyScore,
                    profile.DetectedPattern);

                // Emit detection event into the pipeline
                if (_detectionEngine != null)
                {
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "NeuroBehavior Anomaly",
                    Evidence = $"Process '{profile.ProcessName}' (PID {profile.ProcessId}) " +
                              $"anomaly score {anomalyScore}/100. Pattern: {profile.DetectedPattern}. " +
                              $"Memory: {profile.MemoryUsageMB}MB, Threads: {profile.ThreadCount}, " +
                              $"Handles: {profile.HandleCount}, Entropy: {profile.BehaviorEntropy:F2}",
                    Reasoning = "NeuroBehavior Monitor detected anomalous process behavior based on " +
                               "event diversity, activity rate, multi-vector operations, and resource usage. " +
                               "High anomaly scores indicate behavior inconsistent with normal applications.",
                    Confidence = Math.Min(anomalyScore / 100.0, 0.95),
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = profile.ProcessName,
                    ProcessId = profile.ProcessId,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["anomaly_score"] = anomalyScore.ToString(),
                        ["pattern"] = profile.DetectedPattern,
                        ["memory_mb"] = profile.MemoryUsageMB.ToString(),
                        ["thread_count"] = profile.ThreadCount.ToString(),
                        ["handle_count"] = profile.HandleCount.ToString(),
                        ["behavior_entropy"] = profile.BehaviorEntropy.ToString("F2")
                    }
                }, CancellationToken.None);
                }
            }
        }
    }

    private int CalculateAnomalyScore(NeuroProcessProfile profile)
    {
        int score = 0;
        var events = profile.Events.ToList();
        
        if (events.Count < 5) return 0; // Need more data

        // Check for rapid event sequences
        var recentEvents = events.Where(e => (DateTimeOffset.UtcNow - e.Timestamp).TotalSeconds < 30).ToList();
        if (recentEvents.Count > 20)
        {
            score += 15; // High activity
        }

        // Check for diverse behavior types (suspicious)
        var uniqueTypes = recentEvents.Select(e => e.Type).Distinct().Count();
        if (uniqueTypes > 5)
        {
            score += 20; // Many different behaviors
        }

        // Check for file/network/registry combination (common in malware)
        if (recentEvents.Any(e => e.Type == BehaviorType.FileAccess) &&
            recentEvents.Any(e => e.Type == BehaviorType.NetworkConnection) &&
            recentEvents.Any(e => e.Type == BehaviorType.RegistryModification))
        {
            score += 25; // Multi-vector activity
        }

        // Memory anomaly
        if (profile.MemoryUsageMB > 500)
        {
            score += 10;
        }

        // Handle leak indicator
        if (profile.HandleCount > 1000)
        {
            score += 15;
        }

        // High entropy behavior
        if (profile.BehaviorEntropy > 4.0)
        {
            score += 15;
        }

        return Math.Min(100, score);
    }

    private double CalculateBehaviorEntropy(NeuroProcessProfile profile)
    {
        var events = profile.Events.ToList();
        if (events.Count == 0) return 0;

        var typeCounts = events.GroupBy(e => e.Type)
                             .ToDictionary(g => g.Key, g => g.Count());
        
        double entropy = 0;
        var total = events.Count;
        
        foreach (var count in typeCounts.Values)
        {
            var p = (double)count / total;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private string DetectBehaviorPattern(NeuroProcessProfile profile)
    {
        var events = profile.Events.ToList();
        
        if (events.Count < 10) return "InsufficientData";

        // Check for specific patterns
        var recent = events.TakeLast(20).ToList();
        
        // Ransomware pattern: File read + file write + many file operations
        if (recent.Count(e => e.Type == BehaviorType.FileAccess) > 10 &&
            recent.Any(e => e.Type == BehaviorType.RegistryModification))
        {
            return "PossibleRansomware";
        }

        // Infostealer pattern: Registry access + file access + network
        if (recent.Any(e => e.Type == BehaviorType.RegistryRead) &&
            recent.Any(e => e.Type == BehaviorType.FileRead) &&
            recent.Any(e => e.Type == BehaviorType.NetworkConnection))
        {
            return "PossibleInfoStealer";
        }

        // Keylogger pattern: Input monitoring + network
        if (recent.Any(e => e.Type == BehaviorType.InputMonitoring) &&
            recent.Any(e => e.Type == BehaviorType.NetworkConnection))
        {
            return "PossibleKeylogger";
        }

        // Normal pattern: Consistent activity
        if (recent.All(e => e.Type == BehaviorType.Normal))
        {
            return "NormalActivity";
        }

        return "MixedActivity";
    }

    private void UpdateLearnedPatterns()
    {
        // Aggregate profiles by process name
        var byName = _processProfiles.Values
            .GroupBy(p => p.ProcessName.ToLowerInvariant())
            .ToList();

        foreach (var group in byName)
        {
            var key = group.Key;
            var profiles = group.ToList();
            
            if (profiles.Count < 3) continue; // Need multiple samples

            _learnedPatterns[key] = new BehaviorPattern
            {
                ProcessName = key,
                SampleCount = profiles.Count,
                AverageMemoryMB = (int)profiles.Average(p => p.MemoryUsageMB),
                AverageThreadCount = (int)profiles.Average(p => p.ThreadCount),
                TypicalEventTypes = profiles.SelectMany(p => p.EventCounts.Keys).Distinct().ToList(),
                LearnedAt = DateTimeOffset.UtcNow
            };
        }
    }

    private void CleanupOldProfiles()
    {
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-30);
        
        var oldProfiles = _processProfiles
            .Where(kv => !kv.Value.IsActive && kv.Value.LastActivity < cutoff)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var pid in oldProfiles)
        {
            _processProfiles.TryRemove(pid, out _);
        }
    }

    /// <summary>
    /// Gets current monitoring statistics.
    /// </summary>
    public NeuroBehaviorStats GetStatistics()
    {
        var activeProfiles = _processProfiles.Values.Where(p => p.IsActive).ToList();
        
        return new NeuroBehaviorStats
        {
            MonitoredProcesses = activeProfiles.Count,
            TotalProfiles = _processProfiles.Count,
            LearnedPatterns = _learnedPatterns.Count,
            HighAnomalyProcesses = activeProfiles.Count(p => CalculateAnomalyScore(p) > _anomalyThreshold),
            AverageEntropy = activeProfiles.Any() ? activeProfiles.Average(p => p.BehaviorEntropy) : 0
        };
    }
}

/// <summary>
/// Types of behavior events.
/// </summary>
public enum BehaviorType
{
    Normal,
    FileAccess,
    FileRead,
    FileWrite,
    FileDelete,
    RegistryRead,
    RegistryModification,
    NetworkConnection,
    NetworkListen,
    ProcessCreate,
    ProcessTerminate,
    MemoryAllocation,
    InputMonitoring,
    PrivilegeEscalation,
    CodeInjection
}

/// <summary>
/// A single behavior event.
/// </summary>
public sealed class BehaviorEvent
{
    public DateTimeOffset Timestamp { get; set; }
    public BehaviorType Type { get; set; }
    public string Details { get; set; } = "";
}

/// <summary>
/// Profile for a single process.
/// </summary>
public sealed class NeuroProcessProfile
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public DateTimeOffset StartTime { get; set; }
    public DateTimeOffset LastActivity { get; set; }
    public bool IsActive { get; set; } = true;
    
    public ConcurrentQueue<BehaviorEvent> Events { get; set; } = new();
    public Dictionary<BehaviorType, int> EventCounts { get; set; } = new();
    
    public long CPUUsage { get; set; }
    public long MemoryUsageMB { get; set; }
    public int ThreadCount { get; set; }
    public int HandleCount { get; set; }
    public double BehaviorEntropy { get; set; }
    public string DetectedPattern { get; set; } = "Unknown";
}

/// <summary>
/// Learned behavior pattern for a process type.
/// </summary>
public sealed class BehaviorPattern
{
    public string ProcessName { get; set; } = "";
    public int SampleCount { get; set; }
    public int AverageMemoryMB { get; set; }
    public int AverageThreadCount { get; set; }
    public List<BehaviorType> TypicalEventTypes { get; set; } = new();
    public DateTimeOffset LearnedAt { get; set; }
}

/// <summary>
/// Statistics for the monitor.
/// </summary>
public sealed class NeuroBehaviorStats
{
    public int MonitoredProcesses { get; set; }
    public int TotalProfiles { get; set; }
    public int LearnedPatterns { get; set; }
    public int HighAnomalyProcesses { get; set; }
    public double AverageEntropy { get; set; }
}
