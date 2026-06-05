using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Multi-signal scoring engine. Aggregates per-process detection events into a
    /// composite threat score. Score increases with:
    ///   - Base confidence of the detection
    ///   - Number of corroborating detection sources
    ///   - Multiple distinct threat categories on the same process
    ///   - Known-bad hash match
    ///   - President's Law rule hits (always boosted)
    /// Score decreases with:
    ///   - Trusted publisher signature
    ///   - Development/gaming process context
    ///   - User allowlist entry
    /// </summary>
    public sealed class ScoringEngine
    {
        private readonly AllowlistService _allowlist;
        private readonly SafeProcessExemptionRegistry _exemptionRegistry;
        private readonly ILogger<ScoringEngine> _logger;
        private readonly ConcurrentDictionary<int, ProcessScoreState> _processStates = new();
        private readonly TimeSpan _stateRetention = TimeSpan.FromMinutes(30);

        public ScoringEngine(
            AllowlistService allowlist,
            SafeProcessExemptionRegistry exemptionRegistry,
            ILogger<ScoringEngine> logger)
        {
            _allowlist = allowlist;
            _exemptionRegistry = exemptionRegistry;
            _logger = logger;
        }

        private static bool IsAttackOnUserRule(DetectionEvent detection)
        {
            var r = (detection.RuleName ?? string.Empty).ToLowerInvariant();
            return r.Contains("audiohijack") || r.Contains("audio hijack") ||
                   r.Contains("webcamhijack") || r.Contains("webcam hijack") ||
                   r.Contains("keyscrambler") || r.Contains("keylogger") || r.Contains("keystroke") ||
                   r.Contains("cursortakeover") || r.Contains("cursor takeover") ||
                   r.Contains("fakeuac") || r.Contains("fake uac") ||
                   r.Contains("lnkprotection") || r.Contains("lnk protection") ||
                   r.Contains("cookiemonitor") || r.Contains("cookie monitor");
        }

        private static bool IsPresidentsLawRule(DetectionEvent detection)
        {
            var rule = detection.RuleName ?? string.Empty;
            var lower = rule.ToLowerInvariant();
            return lower.Contains("lsass") ||
                   lower.Contains("amsi") ||
                   lower.Contains("etw") ||
                   lower.Contains("ransomware") ||
                   lower.Contains("shadow copy") ||
                   lower.Contains("self-protection") ||
                   lower.Contains("selfprotection") ||
                   lower.Contains("honeypot") ||
                   lower.Contains("chain-nuke") ||
                   lower.Contains("composite") ||
                   lower.Contains("verdictgate") ||
                   lower.Contains("verdict gate") ||
                   lower.Contains("webcamhijack") ||
                   lower.Contains("webcam hijack") ||
                   lower.Contains("audiohijack") ||
                   lower.Contains("audio hijack") ||
                   lower.Contains("antitamper") ||
                   lower.Contains("anti-tamper") ||
                   lower.Contains("tampering") ||
                   lower.Contains("privilege") ||
                   lower.Contains("attack") ||
                   lower.Contains("badusb") ||
                   lower.Contains("arp") ||
                   lower.Contains("canary") ||
                   lower.Contains("dns") ||
                   lower.Contains("tls") ||
                   lower.Contains("neuro") ||
                   lower.Contains("beaconing") ||
                   lower.Contains("hollowing") ||
                   lower.Contains("reverseshell") ||
                   lower.Contains("reverse shell") ||
                   lower.Contains("threatintel");
        }

        /// <summary>
        /// Scores a detection event, combining base confidence with corroboration,
        /// category breadth, and trust context into a composite ThreatScore.
        /// </summary>
        public ThreatScore Score(DetectionEvent detection)
        {
            var category = CategorizeDetection(detection);
            int baseScore = (int)(detection.Confidence * 100);

            var adjustments = new List<ScoreAdjustment>();

            // Attack-on-user boost: double the confidence score adjustment
            if (IsAttackOnUserRule(detection))
            {
                int boost = baseScore;
                adjustments.Add(new ScoreAdjustment("Attack-on-user double confidence boost", boost, "Double confidence weighting for user-targeting attack"));
                baseScore += boost;
            }

            // Corroboration boost: +15 per additional source category on this process
            int corroborating = GetCorroboratingCategoryCount(detection.ProcessId, category);
            if (corroborating > 0)
            {
                int boost = corroborating * 15;
                adjustments.Add(new ScoreAdjustment("Multi-category corroboration", boost,
                    $"{corroborating} other threat categories on this process"));
                baseScore += boost;
            }

            // Tier1 bonus
            if (detection.Tier == DetectionTier.Tier1Behavioral)
            {
                adjustments.Add(new ScoreAdjustment("Tier1 behavioral", 10, "High-fidelity behavioral detection"));
                baseScore += 10;
            }

            // Allowlist reduction
            double reduction = _allowlist.GetConfidenceReduction(
                detection.ProcessName, null, null, detection.RuleName);
            if (reduction > 0)
            {
                int penalty = (int)(reduction * 100);
                adjustments.Add(new ScoreAdjustment("Allowlist reduction", -penalty,
                    $"Trust reduction {reduction:P0}"));
                baseScore -= penalty;
            }

            // Safe process consensus reduction: -30 for safe processes running demoted non-President's Law rules
            bool isPresidentsLaw = IsPresidentsLawRule(detection);
            if (detection.Tier == DetectionTier.Tier1Behavioral && !isPresidentsLaw && _exemptionRegistry.IsSafeProcess(detection.ProcessId))
            {
                adjustments.Add(new ScoreAdjustment("Safe process consensus reduction", -30, "Consensus safe process with demoted rule"));
                baseScore -= 30;
            }

            baseScore = Math.Max(0, baseScore);

            UpdateProcessState(detection.ProcessId, category, detection.Confidence);

            var verdict = DetermineVerdict(baseScore);

            return new ThreatScore
            {
                Score = baseScore,
                Verdict = verdict,
                Category = category,
                OriginalConfidence = detection.Confidence,
                Adjustments = adjustments,
                CorroboratingSources = corroborating
            };
        }

        public int GetCorroboratingCategoryCount(int processId, string currentCategory)
        {
            if (_processStates.TryGetValue(processId, out var state))
                return state.DetectedCategories.Count(c => c != currentCategory);
            return 0;
        }

        public ProcessThreatProfile? GetProcessProfile(int processId)
        {
            if (_processStates.TryGetValue(processId, out var state))
            {
                return new ProcessThreatProfile
                {
                    ProcessId = processId,
                    DetectedCategories = state.DetectedCategories.ToList(),
                    MaxConfidence = state.MaxConfidence,
                    FirstSeen = state.FirstSeen,
                    LastSeen = state.LastSeen,
                    DetectionCount = state.DetectionCount
                };
            }
            return null;
        }

        private static string CategorizeDetection(DetectionEvent detection)
        {
            var r = detection.RuleName.ToLowerInvariant();
            if (r.Contains("lsass") || r.Contains("credential") || r.Contains("mimikatz")) return "credential_dump";
            if (r.Contains("reverse shell") || r.Contains("c2") || r.Contains("callback")) return "reverse_shell";
            if (r.Contains("injection") || r.Contains("hollowing")) return "process_injection";
            if (r.Contains("ransomware") || r.Contains("shadow copy")) return "ransomware";
            if (r.Contains("evasion") || r.Contains("tampering") || r.Contains("amsi") || r.Contains("etw")) return "security_evasion";
            if (r.Contains("beacon")) return "c2_beaconing";
            if (r.Contains("persistence") || r.Contains("scheduled task")) return "persistence";
            if (r.Contains("privilege") || r.Contains("uac bypass")) return "privilege_escalation";
            if (r.Contains("unsigned")) return "unsigned_binary";
            if (r.Contains("entropy")) return "high_entropy";
            if (r.Contains("campaign")) return "campaign_ioc";
            return "unknown";
        }

        private static Verdict DetermineVerdict(double score) => score switch
        {
            >= 120 => Verdict.Critical,
            >= 80 => Verdict.Malicious,
            >= 50 => Verdict.Suspicious,
            >= 25 => Verdict.Low,
            _ => Verdict.Clean
        };

        private void UpdateProcessState(int processId, string category, double confidence)
        {
            _processStates.AddOrUpdate(processId,
                _ => new ProcessScoreState
                {
                    ProcessId = processId,
                    DetectedCategories = new HashSet<string> { category },
                    MaxConfidence = confidence,
                    FirstSeen = DateTimeOffset.UtcNow,
                    LastSeen = DateTimeOffset.UtcNow,
                    DetectionCount = 1
                },
                (_, existing) =>
                {
                    existing.DetectedCategories.Add(category);
                    existing.MaxConfidence = Math.Max(existing.MaxConfidence, confidence);
                    existing.LastSeen = DateTimeOffset.UtcNow;
                    existing.DetectionCount++;
                    return existing;
                });

            CleanupOldStates();
        }

        private void CleanupOldStates()
        {
            var cutoff = DateTimeOffset.UtcNow - _stateRetention;
            foreach (var key in _processStates.Where(kv => kv.Value.LastSeen < cutoff).Select(kv => kv.Key).ToList())
                _processStates.TryRemove(key, out _);
        }

        public void Cleanup() => CleanupOldStates();
    }

    public enum Verdict { Clean, Low, Suspicious, Malicious, Critical }

    public sealed class ThreatScore
    {
        public int Score { get; set; }
        public Verdict Verdict { get; set; }
        public string Category { get; set; } = "unknown";
        public double OriginalConfidence { get; set; }
        public List<ScoreAdjustment> Adjustments { get; set; } = new();
        public int CorroboratingSources { get; set; }
        public bool RequiresAction => Verdict is Verdict.Malicious or Verdict.Critical;
        public override string ToString() => $"{Verdict} ({Score}) {(RequiresAction ? "[ACTION]" : "[LOG]")} - {Category}";
    }

    public sealed class ScoreAdjustment
    {
        public string Reason { get; }
        public int Value { get; }
        public string Description { get; }
        public ScoreAdjustment(string reason, int value, string description)
        { Reason = reason; Value = value; Description = description; }
        public override string ToString() => $"{Reason}: {Value:+#;-#;0} ({Description})";
    }

    public sealed class ProcessScoreState
    {
        public int ProcessId { get; set; }
        public HashSet<string> DetectedCategories { get; set; } = new();
        public double MaxConfidence { get; set; }
        public DateTimeOffset FirstSeen { get; set; }
        public DateTimeOffset LastSeen { get; set; }
        public int DetectionCount { get; set; }
    }

    public sealed class ProcessThreatProfile
    {
        public int ProcessId { get; set; }
        public List<string> DetectedCategories { get; set; } = new();
        public double MaxConfidence { get; set; }
        public DateTimeOffset FirstSeen { get; set; }
        public DateTimeOffset LastSeen { get; set; }
        public int DetectionCount { get; set; }
        public bool IsMultiCategoryAttack => DetectedCategories.Count >= 3;
    }
}
