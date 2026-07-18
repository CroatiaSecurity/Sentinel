using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public class DynamicCondition
    {
        public string Field { get; set; } = string.Empty;
        public string Operator { get; set; } = "Equals"; // Equals, Contains, StartsWith, EndsWith, NotEquals, NotContains
        public string Value { get; set; } = string.Empty;

        public bool Evaluate(object target)
        {
            if (target == null) return false;

            var prop = target.GetType().GetProperty(Field, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
            if (prop == null) return false;

            var rawValue = prop.GetValue(target);
            string strValue = rawValue?.ToString() ?? string.Empty;

            switch (Operator.ToLowerInvariant())
            {
                case "equals":
                    return strValue.Equals(Value, StringComparison.OrdinalIgnoreCase);
                case "notequals":
                    return !strValue.Equals(Value, StringComparison.OrdinalIgnoreCase);
                case "contains":
                    return strValue.Contains(Value, StringComparison.OrdinalIgnoreCase);
                case "notcontains":
                    return !strValue.Contains(Value, StringComparison.OrdinalIgnoreCase);
                case "startswith":
                    return strValue.StartsWith(Value, StringComparison.OrdinalIgnoreCase);
                case "endswith":
                    return strValue.EndsWith(Value, StringComparison.OrdinalIgnoreCase);
                default:
                    return false;
            }
        }
    }

    public class DynamicRuleDefinition
    {
        public string Name { get; set; } = string.Empty;
        public string EventType { get; set; } = string.Empty; // e.g. "ProcessTelemetry", "NetworkTelemetry", "FileActivityTelemetry"
        public List<DynamicCondition> Conditions { get; set; } = new();
        public double Confidence { get; set; } = 0.80;
        public string Tier { get; set; } = "Tier1Behavioral"; // Tier1Behavioral, Tier2Indicator
        public string ResponseAction { get; set; } = "LogOnly"; // LogOnly, KillProcessTree, QuarantineAndKill
        public string Evidence { get; set; } = string.Empty;
        public string Reasoning { get; set; } = string.Empty;
        public string SignalType { get; set; } = "SuspiciousProcess"; // LsassAccess, Ransomware, ReverseShell, ProcessInjection, SecurityEvasion, SuspiciousProcess, NetworkC2

        public DetectionEvent CreateEvent(object triggeringEvent, int processId, string processName)
        {
            var tierParsed = Enum.TryParse<DetectionTier>(Tier, true, out var t) ? t : DetectionTier.Tier1Behavioral;
            var responseParsed = Enum.TryParse<Core.ResponseAction>(ResponseAction, true, out var r) ? r : Core.ResponseAction.LogOnly;
            var signalParsed = Enum.TryParse<SignalType>(SignalType, true, out var s) ? s : Core.SignalType.SuspiciousProcess;

            // Simple token replacements in the description fields
            string finalEvidence = ReplaceTokens(Evidence, triggeringEvent);
            string finalReasoning = ReplaceTokens(Reasoning, triggeringEvent);

            return new DetectionEvent
            {
                RuleName = $"DynamicRule:{Name}",
                ProcessId = processId,
                ProcessName = processName,
                Confidence = Confidence,
                Tier = tierParsed,
                AuthorizedResponse = responseParsed,
                SignalType = signalParsed,
                Evidence = finalEvidence,
                Reasoning = finalReasoning,
                Metadata = new Dictionary<string, string> { { "DynamicRuleSource", Name } }
            };
        }

        private string ReplaceTokens(string template, object source)
        {
            if (string.IsNullOrEmpty(template) || source == null) return template;

            var result = template;
            foreach (var prop in source.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                var val = prop.GetValue(source)?.ToString() ?? string.Empty;
                result = result.Replace("{" + prop.Name + "}", val, StringComparison.OrdinalIgnoreCase);
            }
            return result;
        }
    }

    public class DynamicRulesEvaluator : IDetectionRule, IDisposable
    {
        public string Name => "DynamicRulesEvaluator";

        private readonly string _rulesDirectory;
        private readonly List<DynamicRuleDefinition> _rules = new();
        private readonly object _lock = new();
        private readonly FileSystemWatcher? _watcher;
        private readonly ILogger<DynamicRulesEvaluator> _logger;

        public DynamicRulesEvaluator(ILogger<DynamicRulesEvaluator> logger)
        {
            _logger = logger;
            _rulesDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules");

            try
            {
                if (!Directory.Exists(_rulesDirectory))
                {
                    Directory.CreateDirectory(_rulesDirectory);
                }

                LoadRules();

                // Watch directory for changes
                _watcher = new FileSystemWatcher(_rulesDirectory, "*.json")
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
                };
                _watcher.Changed += OnRulesChanged;
                _watcher.Created += OnRulesChanged;
                _watcher.Deleted += OnRulesChanged;
                _watcher.Renamed += OnRulesChanged;
                _watcher.EnableRaisingEvents = true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[DynamicRulesEvaluator] Initialization failed");
            }
        }

        // For unit testing overrides
        public DynamicRulesEvaluator(string testRulesPath, ILogger<DynamicRulesEvaluator> logger)
        {
            _logger = logger;
            _rulesDirectory = testRulesPath;
            if (!Directory.Exists(_rulesDirectory))
            {
                Directory.CreateDirectory(_rulesDirectory);
            }
            LoadRules();
        }

        private void OnRulesChanged(object sender, FileSystemEventArgs e)
        {
            // Simple debounce to let file writes complete
            System.Threading.Thread.Sleep(100);
            LoadRules();
        }

        private void LoadRules()
        {
            lock (_lock)
            {
                _rules.Clear();
                _logger.LogInformation($"[DynamicRulesEvaluator] Loading rules from {_rulesDirectory}");

                if (!Directory.Exists(_rulesDirectory)) return;

                foreach (var file in Directory.GetFiles(_rulesDirectory, "*.json"))
                {
                    try
                    {
                        var content = File.ReadAllText(file);
                        var rule = JsonSerializer.Deserialize<DynamicRuleDefinition>(content, new JsonSerializerOptions
                        {
                            PropertyNameCaseInsensitive = true,
                            Converters = { new JsonStringEnumConverter() }
                        });

                        if (rule != null && !string.IsNullOrEmpty(rule.Name))
                        {
                            _rules.Add(rule);
                            _logger.LogInformation($"[DynamicRulesEvaluator] Successfully loaded dynamic rule: {rule.Name}");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"[DynamicRulesEvaluator] Failed to load rule file {Path.GetFileName(file)}");
                    }
                }
            }
        }

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context?.TriggeringEvent == null) return null;

            var triggeringEvent = context.TriggeringEvent;
            var eventTypeName = triggeringEvent.GetType().Name;

            lock (_lock)
            {
                foreach (var rule in _rules)
                {
                    if (!rule.EventType.Equals(eventTypeName, StringComparison.OrdinalIgnoreCase))
                        continue;

                    bool matchesAll = true;
                    foreach (var condition in rule.Conditions)
                    {
                        if (!condition.Evaluate(triggeringEvent))
                        {
                            matchesAll = false;
                            break;
                        }
                    }

                    if (matchesAll)
                    {
                        int processId = 0;
                        string processName = "Unknown";

                        // Attempt to extract ProcessId and ProcessName via reflection from triggering event
                        var pidProp = triggeringEvent.GetType().GetProperty("ProcessId", BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                        if (pidProp != null)
                        {
                            processId = (int)(pidProp.GetValue(triggeringEvent) ?? 0);
                        }

                        var nameProp = triggeringEvent.GetType().GetProperty("ProcessName", BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                        if (nameProp != null)
                        {
                            processName = nameProp.GetValue(triggeringEvent)?.ToString() ?? "Unknown";
                        }

                        _logger.LogWarning($"[DynamicRulesEvaluator] Dynamic rule match triggered: {rule.Name} on PID {processId} ({processName})");
                        return rule.CreateEvent(triggeringEvent, processId, processName);
                    }
                }
            }

            return null;
        }

        public void Dispose()
        {
            if (_watcher != null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Dispose();
            }
            GC.SuppressFinalize(this);
        }
    }
}
