using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace WindowsSentinel.Core
{
    public class AdvancedResponseEngine
    {
        private readonly SentinelConfig _config;
        private readonly SentinelMetrics _metrics;
        private readonly JsonlEventLogger _eventLogger;

        // President's Law fragments
        private static readonly string[] PresidentsLawFragments = new[]
        {
            "credentialdump", "lsass", "sam", "known dumper", "credential dump",
            "ransomware", "mass-write", "shadow copy delete",
            "reverse shell", "c2 callback", "c2 beacon",
            "process injection", "process hollowing", "hollow process",
            "fileless", "in-memory", "memory execution",
            "audio routed to mic", "audio hijack",
            "webcam hijack",
            "etw", "amsi", "tampering",
            "autonomous malware", "phoning home", "exfiltration",
            "dll hijacking", "module integrity",
            "dll injection",
            "lateral movement",
            "honeypot decoy", "verdictgate", "verdict gate",
            "selfprotection", "self protection",
            "browser credential theft", "covert rat", "covert c2",
            "confirmed c2 beacon", "dga + c2 beaconing",
            "dropped payload phoning home", "staged payload",
            "c2 communication detected", "credential dump confirmed"
        };

        public AdvancedResponseEngine(
            SentinelConfig config,
            SentinelMetrics metrics,
            JsonlEventLogger eventLogger)
        {
            _config = config;
            _metrics = metrics;
            _eventLogger = eventLogger;
        }

        public async Task HandleAsync(DetectionEvent detection)
        {
            var stopwatch = Stopwatch.StartNew();

            bool shouldKill = false;
            string reason = "LogOnly";

            if (detection.Tier == DetectionTier.Tier1Behavioral)
            {
                if (_config.ActiveResponse)
                {
                    // Check if RuleName or Reasoning matches any President's Law fragment
                    bool matchesLaw = MatchesPresidentsLaw(detection.RuleName) || MatchesPresidentsLaw(detection.Reasoning);
                    if (matchesLaw)
                    {
                        shouldKill = true;
                        reason = "Killed (President's Law)";
                    }
                    else
                    {
                        reason = "LogOnly (Rule not in President's Law)";
                    }
                }
                else
                {
                    reason = "LogOnly (ActiveResponse disabled)";
                }
            }
            else
            {
                reason = "LogOnly (Tier2 Indicator)";
            }

            if (shouldKill && detection.ProcessId > 4)
            {
                // Terminate Process Tree
                HardeningModule.SafeKillProcessTree(detection.ProcessId);

                // Record response metric
                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                // Log response action
                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "KILL",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
            }
            else
            {
                stopwatch.Stop();
                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "LOG",
                    Reason = reason,
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
            }
        }

        private static bool MatchesPresidentsLaw(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return false;
            return PresidentsLawFragments.Any(f => text.Contains(f, StringComparison.OrdinalIgnoreCase));
        }
    }
}
