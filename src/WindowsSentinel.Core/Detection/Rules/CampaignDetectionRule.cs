using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// DragonBreathHunter - Campaign IOC detection for known APT groups and attack campaigns.
/// Detects RONINGLOADER, Gh0st RAT, and other known campaign indicators.
/// </summary>
public sealed class CampaignDetectionRule : IDetectionRule
{
    private readonly ILogger<CampaignDetectionRule> _logger;
    
    // Campaign IOCs
    private static readonly Dictionary<string, CampaignIndicators> CampaignDatabase = new(StringComparer.OrdinalIgnoreCase)
    {
        ["RONINGLOADER"] = new CampaignIndicators
        {
            Name = "RONINGLOADER",
            Description = "Malicious loader used by threat actor groups",
            FileNames = new[] { "ronin.exe", "ronin64.exe", "roning.exe", "rloader.exe" },
            ProcessPatterns = new[] { "ronin", "roning", "rloader" },
            CommandLinePatterns = new[] { @"-s\s+\d+", @"--stage\s+\d+", @"-c\s+[a-f0-9]{32}" },
            NetworkIndicators = new[] { "185.220.101.182", "194.32.107.58", "roninloader.com" },
            RegistryKeys = new[] { @"Software\Ronin", @"Software\Roning" },
            MitreTechniques = new[] { "T1055", "T1059", "T1071", "T1547" }
        },
        
        ["Gh0stRAT"] = new CampaignIndicators
        {
            Name = "Gh0st RAT",
            Description = "Gh0st Remote Access Trojan family",
            FileNames = new[] { "svch0st.exe", "taskmgre.exe", "csrsss.exe", "servicese.exe" },
            ProcessPatterns = new[] { "svch0st", "taskmgre", "csrsss", "servicese" },
            CommandLinePatterns = new[] { @"gh0st", @"127.0.0.1:\d{4,5}", @"0.0.0.0:\d{4,5}" },
            NetworkIndicators = new[] { "huazhongxitong.com", "xinhuazhou.com" },
            MutexPatterns = new[] { @"Global\Gh0st", @"Global\[0-9A-F]{8}" },
            MitreTechniques = new[] { "T1001", "T1005", "T1014", "T1059", "T1071" }
        },
        
        ["PlugX"] = new CampaignIndicators
        {
            Name = "PlugX",
            Description = "PlugX RAT commonly used by Chinese APT groups",
            FileNames = new[] { "bin.exe", "boot.exe", "temp.exe", "update.exe" },
            ProcessPatterns = new[] { "bin.exe", "boot.exe" },
            CommandLinePatterns = new[] { @"-s", @"-d", @"-p\s+\d+" },
            NetworkIndicators = new[] { "verify-jre.com", "adobe-update.org" },
            FilePathPatterns = new[] { @"\\ProgramData\\[a-z0-9]{8}\\", @"\\Public\\[a-z0-9]{8}\\" },
            MitreTechniques = new[] { "T1055", "T1071", "T1547", "T1567" }
        },
        
        ["CobaltStrikeBeacon"] = new CampaignIndicators
        {
            Name = "Cobalt Strike Beacon",
            Description = "Cobalt Strike Malleable C2 Beacon",
            FileNames = new[] { "beacon.exe", "rundll32.exe", "dllhost.exe" },
            ProcessPatterns = Array.Empty<string>(),
            CommandLinePatterns = new[] { @"rundll32.*[a-f0-9]{8}", @"powershell.*-enc.*AAAAAAAAAA" },
            NetworkIndicators = Array.Empty<string>(), // C2 is highly variable in CS
            NamedPipePatterns = new[] { @"\\\\.\\pipe\\[ms]{1}[a-z]{4,8}[0-9]{1,4}" },
            MitreTechniques = new[] { "T1071", "T1055", "T1059", "T1021" }
        },
        
        ["QBot"] = new CampaignIndicators
        {
            Name = "QBot/QakBot",
            Description = "QBot banking trojan",
            FileNames = new[] { "chkdsks.exe", "disk.exe", "taskhost.exe", "regsvr32.exe" },
            ProcessPatterns = new[] { "chkdsks", "disk.exe" },
            CommandLinePatterns = new[] { @"regsvr32.*-s.*[a-z0-9]{8}\.dat" },
            RegistryKeys = new[] { @"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\[a-z]{8}" },
            ScheduledTaskPatterns = new[] { @"[a-z]{8}_[0-9]{6}" },
            MitreTechniques = new[] { "T1053", "T1055", "T1059", "T1547" }
        },
        
        ["Emotet"] = new CampaignIndicators
        {
            Name = "Emotet",
            Description = "Emotet malware",
            FileNames = new[] { "sys.exe", "win.exe", "update.exe", "syswow.exe" },
            ProcessPatterns = new[] { "sys.exe", "syswow" },
            CommandLinePatterns = new[] { @"-E\d+" },
            NetworkIndicators = Array.Empty<string>(), // C2 varies
            ServicePatterns = new[] { @"RemoteRegistry[0-9a-f]{4}" },
            MitreTechniques = new[] { "T1055", "T1059", "T1543", "T1547" }
        },
        
        ["TrickBot"] = new CampaignIndicators
        {
            Name = "TrickBot",
            Description = "TrickBot banking trojan",
            FileNames = new[] { "tab.exe", "client.exe", "services.exe", "inject.exe" },
            ProcessPatterns = new[] { "tab.exe", "inject.exe" },
            CommandLinePatterns = new[] { @"tab.exe.*-s", @"tab.exe.*-i" },
            NetworkIndicators = Array.Empty<string>(),
            ModulePatterns = new[] { @"[a-z]{8}64.dll", @"[a-z]{8}32.dll" },
            MitreTechniques = new[] { "T1003", "T1055", "T1056", "T1071" }
        }
    };

    public CampaignDetectionRule(ILogger<CampaignDetectionRule> logger)
    {
        _logger = logger;
    }

    public string Name => "Campaign IOC Detection";

    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;
        
        foreach (var campaign in CampaignDatabase)
        {
            var indicators = campaign.Value;
            var confidence = 0.0;
            var matches = new List<string>();

            // Check file name
            if (indicators.FileNames.Any(f => 
                proc.ProcessName.Equals(f, StringComparison.OrdinalIgnoreCase) ||
                proc.ImagePath?.EndsWith(f, StringComparison.OrdinalIgnoreCase) == true))
            {
                confidence += 0.4;
                matches.Add($"File name matches {campaign.Key}");
            }

            // Check process name pattern
            if (indicators.ProcessPatterns.Any(p => 
                proc.ProcessName.Contains(p, StringComparison.OrdinalIgnoreCase)))
            {
                confidence += 0.3;
                matches.Add($"Process name pattern matches {campaign.Key}");
            }

            // Check command line patterns
            if (!string.IsNullOrEmpty(proc.CommandLine))
            {
                foreach (var pattern in indicators.CommandLinePatterns)
                {
                    if (System.Text.RegularExpressions.Regex.IsMatch(proc.CommandLine, pattern))
                    {
                        confidence += 0.3;
                        matches.Add($"Command line matches {campaign.Key}");
                        break;
                    }
                }
            }

            // Check file path patterns
            if (!string.IsNullOrEmpty(proc.ImagePath))
            {
                foreach (var pattern in indicators.FilePathPatterns)
                {
                    if (System.Text.RegularExpressions.Regex.IsMatch(proc.ImagePath, pattern))
                    {
                        confidence += 0.3;
                        matches.Add($"Path pattern matches {campaign.Key}");
                        break;
                    }
                }
            }

            // If we have strong confidence, return detection
            if (confidence >= 0.5)
            {
                var evidence = $"Campaign IOC match: {campaign.Key}. {indicators.Description}. " +
                              $"Indicators: {string.Join("; ", matches)}. " +
                              $"MITRE ATT&CK: {string.Join(", ", indicators.MitreTechniques)}";

                _logger.LogCritical(
                    "CampaignDetection: {Campaign} indicators detected for {Process} (PID {Pid})",
                    campaign.Key, proc.ProcessName, proc.ProcessId);

                return new DetectionEvent
                {
                    RuleName = $"Campaign: {indicators.Name}",
                    Evidence = evidence,
                    Reasoning = $"Detected indicators associated with the {campaign.Key} campaign/malware family",
                    Confidence = Math.Min(0.95, confidence),
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = proc.ProcessName,
                    ProcessId = proc.ProcessId,
                    Timestamp = proc.Timestamp,
                    Metadata = new Dictionary<string, string>
                    {
                        ["campaign"] = campaign.Key,
                        ["campaign_description"] = indicators.Description,
                        ["mitre_techniques"] = string.Join(",", indicators.MitreTechniques),
                        ["indicators_matched"] = string.Join(";", matches)
                    }
                };
            }
        }
        
        return null;
    }

    private sealed class CampaignIndicators
    {
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string[] FileNames { get; set; } = Array.Empty<string>();
        public string[] ProcessPatterns { get; set; } = Array.Empty<string>();
        public string[] CommandLinePatterns { get; set; } = Array.Empty<string>();
        public string[] NetworkIndicators { get; set; } = Array.Empty<string>();
        public string[] RegistryKeys { get; set; } = Array.Empty<string>();
        public string[] MutexPatterns { get; set; } = Array.Empty<string>();
        public string[] FilePathPatterns { get; set; } = Array.Empty<string>();
        public string[] NamedPipePatterns { get; set; } = Array.Empty<string>();
        public string[] ScheduledTaskPatterns { get; set; } = Array.Empty<string>();
        public string[] ServicePatterns { get; set; } = Array.Empty<string>();
        public string[] ModulePatterns { get; set; } = Array.Empty<string>();
        public string[] MitreTechniques { get; set; } = Array.Empty<string>();
    }
}

