using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Weighted multi-factor threat scoring engine.
/// Combines multiple detection signals into a unified threat score.
/// </summary>
public sealed class ScoringEngine
{
    private readonly ILogger<ScoringEngine> _logger;
    
    // Detection source weights (multipliers)
    private static readonly Dictionary<DetectionSource, double> SourceWeights = new()
    {
        [DetectionSource.BehaviorEngine] = 1.5,
        [DetectionSource.MemoryScanner] = 1.5,
        [DetectionSource.ProcessChain] = 1.4,
        [DetectionSource.YaraRules] = 1.3,
        [DetectionSource.Network] = 1.2,
        [DetectionSource.StaticAnalysis] = 1.0,
        [DetectionSource.HashReputation] = 1.0,
        [DetectionSource.MitreMapping] = 0.8
    };

    // Base scores for detection categories
    private static readonly Dictionary<string, double> CategoryBaseScores = new()
    {
        ["credential_dump"] = 85,
        ["reverse_shell"] = 90,
        ["process_injection"] = 80,
        ["ransomware"] = 95,
        ["security_evasion"] = 75,
        ["c2_beaconing"] = 85,
        ["persistence"] = 60,
        ["privilege_escalation"] = 70,
        ["attack_tools"] = 65,
        ["unsigned_binary"] = 40,
        ["high_entropy"] = 35,
        ["suspicious_imports"] = 45,
        ["yara_match"] = 50
    };

    // Process tracking for corroboration
    private readonly ConcurrentDictionary<int, ProcessScoreState> _processStates = new();
    private readonly TimeSpan _stateRetention = TimeSpan.FromMinutes(10);

    public ScoringEngine(ILogger<ScoringEngine> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Calculates a weighted threat score for a detection event.
    /// </summary>
    public ThreatScore CalculateScore(
        DetectionEvent detection, 
        DetectionSource source,
        bool isSigned = false,
        bool isSystemProcess = false,
        int corroboratingSources = 0)
    {
        var category = CategorizeDetection(detection);
        var baseScore = CategoryBaseScores.GetValueOrDefault(category, 50);
        var weight = SourceWeights.GetValueOrDefault(source, 1.0);

        // Apply source weight
        var weightedScore = baseScore * weight;

        // Apply adjustments
        var adjustments = new List<ScoreAdjustment>();

        if (isSigned)
        {
            // Signed binary discount
            var signedDiscount = isSystemProcess ? 50 : 20;
            weightedScore -= signedDiscount;
            adjustments.Add(new ScoreAdjustment("Signed Binary", -signedDiscount, 
                isSystemProcess ? "Trusted publisher + system binary" : "Valid signature present"));
        }

        if (isSystemProcess && !isSigned)
        {
            // System process from System32
            weightedScore -= 15;
            adjustments.Add(new ScoreAdjustment("System Process", -15, "Process from C:\\Windows\\System32"));
        }

        // Corroboration bonus (multiple sources agree)
        if (corroboratingSources >= 4)
        {
            weightedScore += 35;
            adjustments.Add(new ScoreAdjustment("Strong Corroboration", +35, "4+ independent detection sources"));
        }
        else if (corroboratingSources >= 3)
        {
            weightedScore += 25;
            adjustments.Add(new ScoreAdjustment("Corroboration", +25, "3 independent detection sources"));
        }
        else if (corroboratingSources >= 2)
        {
            weightedScore += 15;
            adjustments.Add(new ScoreAdjustment("Weak Corroboration", +15, "2 independent detection sources"));
        }

        // Ensure score is within bounds
        weightedScore = Math.Clamp(weightedScore, 0, 200);

        // Determine verdict
        var verdict = DetermineVerdict(weightedScore);

        // Update process state for future corroboration checks
        UpdateProcessState(detection.ProcessId, source, category, detection.Confidence);

        _logger.LogDebug(
            "ScoringEngine: {Rule} -> Category={Category}, Source={Source}, Weight={Weight}, " +
            "Base={Base}, Adjustments={Adjustments}, Final={Final}, Verdict={Verdict}",
            detection.RuleName, category, source, weight, baseScore, 
            adjustments.Count, weightedScore, verdict);

        return new ThreatScore
        {
            Score = (int)weightedScore,
            Verdict = verdict,
            Category = category,
            Source = source,
            OriginalConfidence = detection.Confidence,
            Adjustments = adjustments,
            CorroboratingSources = corroboratingSources
        };
    }

    /// <summary>
    /// Checks for corroborating sources for a given process.
    /// </summary>
    public int GetCorroboratingSourceCount(int processId, DetectionSource currentSource)
    {
        if (_processStates.TryGetValue(processId, out var state))
        {
            // Count unique sources excluding current
            return state.DetectedSources.Count(s => s != currentSource);
        }
        return 0;
    }

    /// <summary>
    /// Gets the complete threat profile for a process.
    /// </summary>
    public ProcessThreatProfile? GetProcessProfile(int processId)
    {
        if (_processStates.TryGetValue(processId, out var state))
        {
            return new ProcessThreatProfile
            {
                ProcessId = processId,
                DetectedCategories = state.DetectedCategories.ToList(),
                DetectedSources = state.DetectedSources.ToList(),
                MaxConfidence = state.MaxConfidence,
                FirstSeen = state.FirstSeen,
                LastSeen = state.LastSeen,
                DetectionCount = state.DetectionCount
            };
        }
        return null;
    }

    /// <summary>
    /// Categorizes a detection event into a threat category.
    /// </summary>
    private string CategorizeDetection(DetectionEvent detection)
    {
        var ruleName = detection.RuleName.ToLowerInvariant();

        if (ruleName.Contains("lsass") || ruleName.Contains("credential") || ruleName.Contains("mimikatz"))
            return "credential_dump";

        if (ruleName.Contains("reverse shell") || ruleName.Contains("c2") || ruleName.Contains("callback"))
            return "reverse_shell";

        if (ruleName.Contains("injection") || ruleName.Contains("hollowing") || ruleName.Contains("hollow"))
            return "process_injection";

        if (ruleName.Contains("ransomware") || ruleName.Contains("shadow copy") || ruleName.Contains("encryption"))
            return "ransomware";

        if (ruleName.Contains("evasion") || ruleName.Contains("tampering") || ruleName.Contains("amsi") || ruleName.Contains("etw"))
            return "security_evasion";

        if (ruleName.Contains("beacon") || ruleName.Contains("beaconing"))
            return "c2_beaconing";

        if (ruleName.Contains("persistence") || ruleName.Contains("run key") || ruleName.Contains("scheduled task"))
            return "persistence";

        if (ruleName.Contains("privilege") || ruleName.Contains("escalation") || ruleName.Contains("uac bypass"))
            return "privilege_escalation";

        if (ruleName.Contains("attack tool") || ruleName.Contains("cobalt strike") || ruleName.Contains("metasploit"))
            return "attack_tools";

        if (ruleName.Contains("unsigned"))
            return "unsigned_binary";

        if (ruleName.Contains("entropy"))
            return "high_entropy";

        if (ruleName.Contains("suspicious import"))
            return "suspicious_imports";

        if (ruleName.Contains("yara"))
            return "yara_match";

        return "unknown";
    }

    private Verdict DetermineVerdict(double score)
    {
        // RESTORED original thresholds — previous (160/120) was too strict and
        // let Reverse Shell, AMSI/ETW Tampering, Cobalt Strike, and live C2
        // beacons fall through to "Suspicious / log only". A single behavioral
        // hit on a known-bad category MUST be killable.
        return score switch
        {
            >= 120 => Verdict.Critical,
            >= 80  => Verdict.Malicious,
            >= 50  => Verdict.Suspicious,
            >= 25  => Verdict.Low,
            _      => Verdict.Clean
        };
    }

    private void UpdateProcessState(int processId, DetectionSource source, string category, double confidence)
    {
        _processStates.AddOrUpdate(processId,
            _ => new ProcessScoreState
            {
                ProcessId = processId,
                DetectedSources = new HashSet<DetectionSource> { source },
                DetectedCategories = new HashSet<string> { category },
                MaxConfidence = confidence,
                FirstSeen = DateTimeOffset.UtcNow,
                LastSeen = DateTimeOffset.UtcNow,
                DetectionCount = 1
            },
            (_, existing) =>
            {
                existing.DetectedSources.Add(source);
                existing.DetectedCategories.Add(category);
                existing.MaxConfidence = Math.Max(existing.MaxConfidence, confidence);
                existing.LastSeen = DateTimeOffset.UtcNow;
                existing.DetectionCount++;
                return existing;
            });

        // Cleanup old states
        CleanupOldStates();
    }

    private void CleanupOldStates()
    {
        var cutoff = DateTimeOffset.UtcNow - _stateRetention;
        var oldKeys = _processStates
            .Where(kv => kv.Value.LastSeen < cutoff)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var key in oldKeys)
        {
            _processStates.TryRemove(key, out _);
        }
    }

    /// <summary>
    /// Periodically cleans up old process states. Should be called on a timer.
    /// </summary>
    public void Cleanup()
    {
        CleanupOldStates();
    }
}

/// <summary>
/// Represents the source of a detection.
/// </summary>
public enum DetectionSource
{
    BehaviorEngine,
    MemoryScanner,
    ProcessChain,
    YaraRules,
    Network,
    StaticAnalysis,
    HashReputation,
    MitreMapping
}

/// <summary>
/// Threat score classification.
/// </summary>
public enum Verdict
{
    Clean,      // 0-24
    Low,        // 25-49
    Suspicious, // 50-79
    Malicious,  // 80-119
    Critical    // 120+
}

/// <summary>
/// Represents a calculated threat score.
/// </summary>
public sealed class ThreatScore
{
    public int Score { get; set; }
    public Verdict Verdict { get; set; }
    public string Category { get; set; } = "unknown";
    public DetectionSource Source { get; set; }
    public double OriginalConfidence { get; set; }
    public List<ScoreAdjustment> Adjustments { get; set; } = new();
    public int CorroboratingSources { get; set; }

    public string VerdictLabel => Verdict.ToString();

    public bool RequiresAction => Verdict is Verdict.Malicious or Verdict.Critical;

    public override string ToString()
    {
        var action = RequiresAction ? "[ACTION REQUIRED]" : "[LOG ONLY]";
        return $"{VerdictLabel} ({Score}) {action} - {Category}";
    }
}

/// <summary>
/// Represents a score adjustment.
/// </summary>
public sealed class ScoreAdjustment
{
    public string Reason { get; }
    public int Value { get; }
    public string Description { get; }

    public ScoreAdjustment(string reason, int value, string description)
    {
        Reason = reason;
        Value = value;
        Description = description;
    }

    public override string ToString() => $"{Reason}: {Value:+#;-#;0} ({Description})";
}

/// <summary>
/// Internal state tracking for process scoring.
/// </summary>
public sealed class ProcessScoreState
{
    public int ProcessId { get; set; }
    public HashSet<DetectionSource> DetectedSources { get; set; } = new();
    public HashSet<string> DetectedCategories { get; set; } = new();
    public double MaxConfidence { get; set; }
    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    public int DetectionCount { get; set; }
}

/// <summary>
/// Represents the complete threat profile for a process.
/// </summary>
public sealed class ProcessThreatProfile
{
    public int ProcessId { get; set; }
    public List<string> DetectedCategories { get; set; } = new();
    public List<DetectionSource> DetectedSources { get; set; } = new();
    public double MaxConfidence { get; set; }
    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    public int DetectionCount { get; set; }

    public int UniqueCategories => DetectedCategories.Count;
    public int UniqueSources => DetectedSources.Count;

    public bool IsMultiCategoryAttack => UniqueCategories >= 3;
    public bool IsCorroborated => UniqueSources >= 3;
}

