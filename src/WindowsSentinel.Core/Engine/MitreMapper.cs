using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// MITRE ATT&CK Mapper - Maps detection events to MITRE ATT&CK techniques.
/// Provides technique identification, confidence scoring, and multi-tactic analysis.
/// </summary>
public sealed class MitreMapper
{
    private readonly ILogger<MitreMapper> _logger;

    // MITRE ATT&CK technique database
    private static readonly Dictionary<string, MitreTechnique> TechniqueDatabase = new()
    {
        // Initial Access
        ["T1078"] = new MitreTechnique("T1078", "Valid Accounts", "Initial Access", "Using legitimate credentials"),
        ["T1190"] = new MitreTechnique("T1190", "Exploit Public-Facing Application", "Initial Access", "Exploiting web applications"),
        ["T1566"] = new MitreTechnique("T1566", "Phishing", "Initial Access", "Malicious email-based attacks"),

        // Execution
        ["T1059"] = new MitreTechnique("T1059", "Command and Scripting Interpreter", "Execution", "Using command-line interpreters"),
        ["T1059.001"] = new MitreTechnique("T1059.001", "PowerShell", "Execution", "PowerShell script execution"),
        ["T1059.003"] = new MitreTechnique("T1059.003", "Windows Command Shell", "Execution", "CMD.exe execution"),
        ["T1204"] = new MitreTechnique("T1204", "User Execution", "Execution", "User executes malicious code"),
        ["T1047"] = new MitreTechnique("T1047", "Windows Management Instrumentation", "Execution", "WMI for execution"),

        // Persistence
        ["T1547"] = new MitreTechnique("T1547", "Boot or Logon Autostart Execution", "Persistence", "Auto-starting malware"),
        ["T1547.001"] = new MitreTechnique("T1547.001", "Registry Run Keys", "Persistence", "Run key persistence"),
        ["T1053"] = new MitreTechnique("T1053", "Scheduled Task/Job", "Persistence", "Scheduled task persistence"),
        ["T1546"] = new MitreTechnique("T1546", "Event Triggered Execution", "Persistence", "Event-based triggers"),
        ["T1546.003"] = new MitreTechnique("T1546.003", "WMI Event Subscription", "Persistence", "WMI event persistence"),
        ["T1543"] = new MitreTechnique("T1543", "Create or Modify System Process", "Persistence", "Service-based persistence"),

        // Privilege Escalation
        ["T1068"] = new MitreTechnique("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", "Exploiting vulnerabilities"),
        ["T1078"] = new MitreTechnique("T1078", "Valid Accounts", "Privilege Escalation", "Using privileged accounts"),
        ["T1055"] = new MitreTechnique("T1055", "Process Injection", "Privilege Escalation", "Injecting into processes"),
        ["T1134"] = new MitreTechnique("T1134", "Access Token Manipulation", "Privilege Escalation", "Token theft/manipulation"),

        // Defense Evasion
        ["T1027"] = new MitreTechnique("T1027", "Obfuscated Files or Information", "Defense Evasion", "Hiding malicious content"),
        ["T1562"] = new MitreTechnique("T1562", "Impair Defenses", "Defense Evasion", "Disabling security tools"),
        ["T1562.001"] = new MitreTechnique("T1562.001", "Disable or Modify Tools", "Defense Evasion", "Disabling security tools"),
        ["T1070"] = new MitreTechnique("T1070", "Indicator Removal", "Defense Evasion", "Clearing logs/artifacts"),
        ["T1070.001"] = new MitreTechnique("T1070.001", "Clear Windows Event Logs", "Defense Evasion", "Clearing event logs"),
        ["T1036"] = new MitreTechnique("T1036", "Masquerading", "Defense Evasion", "Disguising malware"),
        ["T1055"] = new MitreTechnique("T1055", "Process Injection", "Defense Evasion", "Hiding in legitimate processes"),

        // Credential Access
        ["T1003"] = new MitreTechnique("T1003", "OS Credential Dumping", "Credential Access", "Stealing credentials"),
        ["T1003.001"] = new MitreTechnique("T1003.001", "LSASS Memory", "Credential Access", "Dumping LSASS"),
        ["T1558"] = new MitreTechnique("T1558", "Steal or Forge Kerberos Tickets", "Credential Access", "Kerberos attacks"),
        ["T1552"] = new MitreTechnique("T1552", "Unsecured Credentials", "Credential Access", "Finding credentials"),

        // Discovery
        ["T1083"] = new MitreTechnique("T1083", "File and Directory Discovery", "Discovery", "Enumerating files"),
        ["T1057"] = new MitreTechnique("T1057", "Process Discovery", "Discovery", "Enumerating processes"),
        ["T1012"] = new MitreTechnique("T1012", "Query Registry", "Discovery", "Reading registry"),
        ["T1082"] = new MitreTechnique("T1082", "System Information Discovery", "Discovery", "Gathering system info"),
        ["T1016"] = new MitreTechnique("T1016", "System Network Configuration Discovery", "Discovery", "Network recon"),
        ["T1049"] = new MitreTechnique("T1049", "System Network Connections Discovery", "Discovery", "Connection enumeration"),
        ["T1033"] = new MitreTechnique("T1033", "System Owner/User Discovery", "Discovery", "User enumeration"),

        // Lateral Movement
        ["T1021"] = new MitreTechnique("T1021", "Remote Services", "Lateral Movement", "Moving between systems"),
        ["T1021.002"] = new MitreTechnique("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement", "SMB lateral movement"),
        ["T1021.006"] = new MitreTechnique("T1021.006", "Windows Remote Management", "Lateral Movement", "WinRM lateral movement"),
        ["T1550"] = new MitreTechnique("T1550", "Use Alternate Authentication Material", "Lateral Movement", "Pass-the-hash/ticket"),

        // Collection
        ["T1115"] = new MitreTechnique("T1115", "Clipboard Data", "Collection", "Clipboard harvesting"),
        ["T1113"] = new MitreTechnique("T1113", "Screen Capture", "Collection", "Screenshots"),
        ["T1005"] = new MitreTechnique("T1005", "Data from Local System", "Collection", "File collection"),
        ["T1056"] = new MitreTechnique("T1056", "Input Capture", "Collection", "Keylogging"),
        ["T1056.001"] = new MitreTechnique("T1056.001", "Keylogging", "Collection", "Keyboard capture"),

        // Command and Control
        ["T1071"] = new MitreTechnique("T1071", "Application Layer Protocol", "Command and Control", "C2 communication"),
        ["T1071.001"] = new MitreTechnique("T1071.001", "Web Protocols", "Command and Control", "HTTP/HTTPS C2"),
        ["T1071.004"] = new MitreTechnique("T1071.004", "DNS", "Command and Control", "DNS tunneling"),
        ["T1573"] = new MitreTechnique("T1573", "Encrypted Channel", "Command and Control", "Encrypted C2"),
        ["T1001"] = new MitreTechnique("T1001", "Data Obfuscation", "Command and Control", "Hiding C2 traffic"),
        ["T1090"] = new MitreTechnique("T1090", "Proxy", "Command and Control", "Proxy communication"),

        // Exfiltration
        ["T1041"] = new MitreTechnique("T1041", "Exfiltration Over C2 Channel", "Exfiltration", "Data exfiltration via C2"),
        ["T1048"] = new MitreTechnique("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "Non-standard exfiltration"),
        ["T1567"] = new MitreTechnique("T1567", "Exfiltration Over Web Service", "Exfiltration", "Cloud exfiltration"),

        // Impact
        ["T1486"] = new MitreTechnique("T1486", "Data Encrypted for Impact", "Impact", "Ransomware encryption"),
        ["T1490"] = new MitreTechnique("T1490", "Inhibit System Recovery", "Impact", "Deleting backups"),
        ["T1491"] = new MitreTechnique("T1491", "Defacement", "Impact", "Defacing resources"),
        ["T1489"] = new MitreTechnique("T1489", "Service Stop", "Impact", "Stopping services"),
        ["T1529"] = new MitreTechnique("T1529", "System Shutdown/Reboot", "Impact", "System shutdown"),
    };

    // Rule to technique mapping
    private static readonly Dictionary<string, List<MitreMapping>> RuleToTechniqueMappings = new(StringComparer.OrdinalIgnoreCase)
    {
        ["lsass"] = new List<MitreMapping>
        {
            new("T1003.001", 0.95, "Direct LSASS access detected"),
            new("T1003", 0.90, "Credential dumping activity"),
        },
        ["credential"] = new List<MitreMapping>
        {
            new("T1003", 0.90, "Credential access activity"),
            new("T1552", 0.70, "Unsecured credentials"),
        },
        ["mimikatz"] = new List<MitreMapping>
        {
            new("T1003.001", 0.98, "Mimikatz detected"),
            new("T1003", 0.95, "Credential dumping tool"),
        },
        ["reverse shell"] = new List<MitreMapping>
        {
            new("T1059", 0.85, "Command execution via reverse shell"),
            new("T1071", 0.80, "C2 channel established"),
        },
        ["c2"] = new List<MitreMapping>
        {
            new("T1071", 0.90, "Command and Control activity"),
            new("T1573", 0.75, "Potential encrypted channel"),
        },
        ["beacon"] = new List<MitreMapping>
        {
            new("T1071", 0.92, "Beaconing to C2"),
            new("T1001", 0.70, "Potential data obfuscation"),
        },
        ["injection"] = new List<MitreMapping>
        {
            new("T1055", 0.90, "Process injection detected"),
            new("T1055.012", 0.85, "Process hollowing possible"),
        },
        ["hollowing"] = new List<MitreMapping>
        {
            new("T1055.012", 0.95, "Process hollowing confirmed"),
            new("T1055", 0.90, "Process manipulation"),
        },
        ["ransomware"] = new List<MitreMapping>
        {
            new("T1486", 0.95, "Ransomware activity"),
            new("T1490", 0.80, "Backup deletion likely"),
        },
        ["shadow copy"] = new List<MitreMapping>
        {
            new("T1490", 0.95, "Inhibiting system recovery"),
            new("T1486", 0.80, "Ransomware preparation"),
        },
        ["amsi bypass"] = new List<MitreMapping>
        {
            new("T1562.001", 0.95, "Disabling security tools"),
            new("T1562", 0.90, "Defense evasion"),
        },
        ["etw"] = new List<MitreMapping>
        {
            new("T1562.001", 0.92, "Tampering with ETW"),
            new("T1562", 0.85, "Impairing defenses"),
        },
        ["persistence"] = new List<MitreMapping>
        {
            new("T1547", 0.85, "Persistence mechanism"),
            new("T1547.001", 0.80, "Run key persistence possible"),
        },
        ["run key"] = new List<MitreMapping>
        {
            new("T1547.001", 0.95, "Registry run key persistence"),
            new("T1547", 0.90, "Boot execution"),
        },
        ["scheduled task"] = new List<MitreMapping>
        {
            new("T1053", 0.95, "Scheduled task/job"),
            new("T1547", 0.80, "Persistence via scheduling"),
        },
        ["wmi"] = new List<MitreMapping>
        {
            new("T1546.003", 0.90, "WMI event subscription"),
            new("T1047", 0.75, "WMI for execution"),
        },
        ["privilege escalation"] = new List<MitreMapping>
        {
            new("T1068", 0.70, "Possible privilege escalation"),
            new("T1078", 0.65, "Valid account abuse"),
        },
        ["uac bypass"] = new List<MitreMapping>
        {
            new("T1548", 0.90, "Bypassing UAC"),
            new("T1078", 0.70, "Elevated execution"),
        },
        ["token manipulation"] = new List<MitreMapping>
        {
            new("T1134", 0.90, "Access token manipulation"),
            new("T1078", 0.70, "Token theft"),
        },
        ["cobalt strike"] = new List<MitreMapping>
        {
            new("T1071", 0.95, "Cobalt Strike C2"),
            new("T1055", 0.80, "Beacon injection possible"),
        },
        ["metasploit"] = new List<MitreMapping>
        {
            new("T1059", 0.90, "Metasploit execution"),
            new("T1071", 0.85, "Metasploit C2"),
        },
        ["lateral movement"] = new List<MitreMapping>
        {
            new("T1021", 0.85, "Lateral movement activity"),
            new("T1021.002", 0.80, "SMB/Admin shares"),
        },
        ["psexec"] = new List<MitreMapping>
        {
            new("T1021.002", 0.92, "PsExec lateral movement"),
            new("T1021", 0.85, "Remote service execution"),
        },
        ["dns exfiltration"] = new List<MitreMapping>
        {
            new("T1071.004", 0.90, "DNS tunneling"),
            new("T1048", 0.80, "Alternative protocol exfiltration"),
        },
        ["fileless"] = new List<MitreMapping>
        {
            new("T1059", 0.85, "Fileless execution"),
            new("T1027", 0.80, "Malicious code in memory"),
        },
        ["keylog"] = new List<MitreMapping>
        {
            new("T1056.001", 0.95, "Keylogging detected"),
            new("T1056", 0.90, "Input capture"),
        },
        ["clipboard"] = new List<MitreMapping>
        {
            new("T1115", 0.85, "Clipboard data collection"),
            new("T1005", 0.70, "Data collection"),
        },
        ["screenshot"] = new List<MitreMapping>
        {
            new("T1113", 0.90, "Screen capture"),
            new("T1005", 0.70, "Data collection"),
        },
        ["rootkit"] = new List<MitreMapping>
        {
            new("T1014", 0.90, "Rootkit detected"),
            new("T1562", 0.80, "Defense evasion"),
        },
        ["byovd"] = new List<MitreMapping>
        {
            new("T1068", 0.95, "BYOVD exploitation"),
            new("T1055", 0.70, "Driver-based injection"),
        },
        ["dll hijack"] = new List<MitreMapping>
        {
            new("T1574.001", 0.90, "DLL search order hijacking"),
            new("T1574", 0.85, "Hijack execution flow"),
        },
        ["self-protection"] = new List<MitreMapping>
        {
            new("T1562", 0.80, "Attempted defense disable"),
            new("T1562.001", 0.75, "Security tool tampering"),
        },
        ["network isolation"] = new List<MitreMapping>
        {
            new("T1490", 0.70, "Inhibit system recovery"),
            new("T1489", 0.65, "Service stop"),
        },
    };

    // Track multi-tactic attacks
    private readonly ConcurrentDictionary<int, AttackTactics> _processTactics = new();

    public MitreMapper(ILogger<MitreMapper> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Maps a detection event to MITRE ATT&CK techniques.
    /// </summary>
    public MitreMappingResult MapDetection(DetectionEvent detection)
    {
        var ruleName = detection.RuleName.ToLowerInvariant();
        var matchedTechniques = new List<MappedTechnique>();

        // Find matching techniques
        foreach (var mapping in RuleToTechniqueMappings)
        {
            if (ruleName.Contains(mapping.Key))
            {
                foreach (var tech in mapping.Value)
                {
                    if (TechniqueDatabase.TryGetValue(tech.TechniqueId, out var technique))
                    {
                        // Adjust confidence based on detection confidence
                        var adjustedConfidence = Math.Min(
                            tech.BaseConfidence * detection.Confidence,
                            0.99);

                        matchedTechniques.Add(new MappedTechnique
                        {
                            Technique = technique,
                            MatchConfidence = adjustedConfidence,
                            MatchReason = tech.MatchReason,
                            Evidence = detection.Evidence
                        });
                    }
                }
            }
        }

        // Check for technique in metadata
        if (detection.Metadata.TryGetValue("technique", out var metadataTechnique))
        {
            var techId = metadataTechnique.Split(' ')[0];
            if (TechniqueDatabase.TryGetValue(techId, out var technique) &&
                !matchedTechniques.Any(m => m.Technique.TechniqueId == techId))
            {
                matchedTechniques.Add(new MappedTechnique
                {
                    Technique = technique,
                    MatchConfidence = detection.Confidence,
                    MatchReason = "Direct metadata attribution",
                    Evidence = detection.Evidence
                });
            }
        }

        // If no specific match, provide generic mapping
        if (matchedTechniques.Count == 0)
        {
            matchedTechniques.Add(new MappedTechnique
            {
                Technique = new MitreTechnique("T1059", "Command and Scripting Interpreter", "Execution", "Unknown activity"),
                MatchConfidence = detection.Confidence * 0.5,
                MatchReason = "Generic execution mapping",
                Evidence = detection.Evidence
            });
        }

        // Update process tactic tracking for multi-tactic analysis
        UpdateTacticTracking(detection.ProcessId, matchedTechniques);

        // Calculate multi-tactic bonus
        var tacticCount = matchedTechniques.Select(m => m.Technique.Tactic).Distinct().Count();
        var multiTacticBonus = tacticCount >= 3 ? 0.05 : 0;

        // Create result
        var result = new MitreMappingResult
        {
            Detection = detection,
            MatchedTechniques = matchedTechniques.OrderByDescending(m => m.MatchConfidence).ToList(),
            PrimaryTechnique = matchedTechniques.OrderByDescending(m => m.MatchConfidence).First(),
            TacticsObserved = matchedTechniques.Select(m => m.Technique.Tactic).Distinct().ToList(),
            MultiTacticScore = tacticCount,
            MultiTacticBonus = multiTacticBonus
        };

        _logger.LogDebug(
            "MitreMapper: {Rule} mapped to {Count} techniques, {Tactics} tactics, bonus {Bonus:P0}",
            detection.RuleName,
            result.MatchedTechniques.Count,
            result.TacticsObserved.Count,
            multiTacticBonus);

        return result;
    }

    /// <summary>
    /// Gets the complete attack chain analysis for a process.
    /// </summary>
    public AttackChainAnalysis GetAttackChainAnalysis(int processId)
    {
        if (!_processTactics.TryGetValue(processId, out var tactics))
        {
            return new AttackChainAnalysis { ProcessId = processId };
        }

        var allTactics = tactics.TacticsSeen.ToList();
        var allTechniques = tactics.TechniquesSeen.ToList();

        // Determine attack phase
        var phase = DetermineAttackPhase(allTactics);

        // Calculate progression
        var progression = AnalyzeProgression(allTactics, allTechniques);

        return new AttackChainAnalysis
        {
            ProcessId = processId,
            AllTactics = allTactics,
            AllTechniques = allTechniques,
            DetectedAt = tactics.FirstSeen,
            LastActivity = tactics.LastSeen,
            ActivityCount = tactics.ActivityCount,
            CurrentPhase = phase,
            Progression = progression,
            EstimatedCompleteness = CalculateCompleteness(allTactics)
        };
    }

    /// <summary>
    /// Gets a summary report of all observed ATT&CK activity.
    /// </summary>
    public MitreSummaryReport GenerateSummaryReport()
    {
        var allTechniques = new Dictionary<string, int>();
        var allTactics = new Dictionary<string, int>();

        foreach (var process in _processTactics)
        {
            foreach (var technique in process.Value.TechniquesSeen)
            {
                allTechniques[technique] = allTechniques.GetValueOrDefault(technique) + 1;
            }

            foreach (var tactic in process.Value.TacticsSeen)
            {
                allTactics[tactic] = allTactics.GetValueOrDefault(tactic) + 1;
            }
        }

        return new MitreSummaryReport
        {
            TotalProcessesObserved = _processTactics.Count,
            UniqueTechniquesObserved = allTechniques.Count,
            UniqueTacticsObserved = allTactics.Count,
            TopTechniques = allTechniques.OrderByDescending(kv => kv.Value).Take(10).ToList(),
            TopTactics = allTactics.OrderByDescending(kv => kv.Value).Take(5).ToList(),
            GeneratedAt = DateTimeOffset.UtcNow
        };
    }

    /// <summary>
    /// Clears tactic tracking data.
    /// </summary>
    public void ClearTracking()
    {
        _processTactics.Clear();
        _logger.LogInformation("MitreMapper: Tactic tracking cleared");
    }

    private void UpdateTacticTracking(int processId, List<MappedTechnique> techniques)
    {
        _processTactics.AddOrUpdate(processId,
            _ => new AttackTactics
            {
                TacticsSeen = new HashSet<string>(techniques.Select(t => t.Technique.Tactic)),
                TechniquesSeen = new HashSet<string>(techniques.Select(t => t.Technique.TechniqueId)),
                FirstSeen = DateTimeOffset.UtcNow,
                LastSeen = DateTimeOffset.UtcNow,
                ActivityCount = 1
            },
            (_, existing) =>
            {
                foreach (var tech in techniques)
                {
                    existing.TacticsSeen.Add(tech.Technique.Tactic);
                    existing.TechniquesSeen.Add(tech.Technique.TechniqueId);
                }
                existing.LastSeen = DateTimeOffset.UtcNow;
                existing.ActivityCount++;
                return existing;
            });
    }

    private string DetermineAttackPhase(List<string> tactics)
    {
        // Define tactic progression
        var phases = new[]
        {
            ("Initial Access", 1),
            ("Execution", 2),
            ("Persistence", 3),
            ("Privilege Escalation", 4),
            ("Defense Evasion", 5),
            ("Credential Access", 6),
            ("Discovery", 7),
            ("Lateral Movement", 8),
            ("Collection", 9),
            ("Command and Control", 10),
            ("Exfiltration", 11),
            ("Impact", 12)
        };

        var maxPhase = tactics
            .Select(t => phases.FirstOrDefault(p => p.Item1 == t).Item2)
            .Where(p => p > 0)
            .DefaultIfEmpty(0)
            .Max();

        return phases.FirstOrDefault(p => p.Item2 == maxPhase).Item1 ?? "Unknown";
    }

    private List<string> AnalyzeProgression(List<string> tactics, List<string> techniques)
    {
        var progression = new List<string>();

        // Check for common kill chain progressions
        if (tactics.Contains("Initial Access") && tactics.Contains("Execution"))
            progression.Add("Initial compromise completed");

        if (tactics.Contains("Credential Access") && tactics.Contains("Lateral Movement"))
            progression.Add("Post-exploitation: spreading to additional systems");

        if (tactics.Contains("Collection") && tactics.Contains("Exfiltration"))
            progression.Add("Data collection and exfiltration in progress");

        if (tactics.Contains("Defense Evasion") && tactics.Contains("Impact"))
            progression.Add("Active defense evasion with impact intent");

        return progression;
    }

    private double CalculateCompleteness(List<string> tactics)
    {
        // Estimate how complete the kill chain is
        var keyPhases = new[] { "Initial Access", "Execution", "Persistence", "Impact" };
        var phasesPresent = keyPhases.Count(tactics.Contains);
        return (double)phasesPresent / keyPhases.Length;
    }
}

/// <summary>
/// Represents a MITRE ATT&CK technique.
/// </summary>
public sealed class MitreTechnique
{
    public string TechniqueId { get; }
    public string Name { get; }
    public string Tactic { get; }
    public string Description { get; }

    public MitreTechnique(string id, string name, string tactic, string description)
    {
        TechniqueId = id;
        Name = name;
        Tactic = tactic;
        Description = description;
    }

    public override string ToString() => $"{TechniqueId} - {Name} ({Tactic})";
}

/// <summary>
/// Maps a rule to MITRE techniques.
/// </summary>
public sealed class MitreMapping
{
    public string TechniqueId { get; }
    public double BaseConfidence { get; }
    public string MatchReason { get; }

    public MitreMapping(string techniqueId, double baseConfidence, string matchReason)
    {
        TechniqueId = techniqueId;
        BaseConfidence = baseConfidence;
        MatchReason = matchReason;
    }
}

/// <summary>
/// Represents a mapped technique with confidence.
/// </summary>
public sealed class MappedTechnique
{
    public MitreTechnique Technique { get; set; } = null!;
    public double MatchConfidence { get; set; }
    public string MatchReason { get; set; } = "";
    public string Evidence { get; set; } = "";

    public override string ToString() =>
        $"{Technique.TechniqueId} ({MatchConfidence:P0} confidence): {MatchReason}";
}

/// <summary>
/// Result of MITRE mapping for a detection.
/// </summary>
public sealed class MitreMappingResult
{
    public DetectionEvent Detection { get; set; } = null!;
    public List<MappedTechnique> MatchedTechniques { get; set; } = new();
    public MappedTechnique PrimaryTechnique { get; set; } = null!;
    public List<string> TacticsObserved { get; set; } = new();
    public int MultiTacticScore { get; set; }
    public double MultiTacticBonus { get; set; }

    public bool IsMultiTactic => MultiTacticScore >= 3;

    public override string ToString() =>
        $"{Detection.RuleName} -> {PrimaryTechnique} (+{MatchedTechniques.Count - 1} more, {MultiTacticScore} tactics)";
}

/// <summary>
/// Tracks attack tactics for a process.
/// </summary>
public sealed class AttackTactics
{
    public HashSet<string> TacticsSeen { get; set; } = new();
    public HashSet<string> TechniquesSeen { get; set; } = new();
    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    public int ActivityCount { get; set; }
}

/// <summary>
/// Complete attack chain analysis for a process.
/// </summary>
public sealed class AttackChainAnalysis
{
    public int ProcessId { get; set; }
    public List<string> AllTactics { get; set; } = new();
    public List<string> AllTechniques { get; set; } = new();
    public DateTimeOffset DetectedAt { get; set; }
    public DateTimeOffset LastActivity { get; set; }
    public int ActivityCount { get; set; }
    public string CurrentPhase { get; set; } = "";
    public List<string> Progression { get; set; } = new();
    public double EstimatedCompleteness { get; set; }

    public TimeSpan Duration => LastActivity - DetectedAt;

    public bool IsKillChainComplete => EstimatedCompleteness >= 0.75;
}

/// <summary>
/// Summary report of MITRE ATT&CK coverage.
/// </summary>
public sealed class MitreSummaryReport
{
    public int TotalProcessesObserved { get; set; }
    public int UniqueTechniquesObserved { get; set; }
    public int UniqueTacticsObserved { get; set; }
    public List<KeyValuePair<string, int>> TopTechniques { get; set; } = new();
    public List<KeyValuePair<string, int>> TopTactics { get; set; } = new();
    public DateTimeOffset GeneratedAt { get; set; }
}

