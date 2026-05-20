using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Akinator Engine - Contextual heuristic scoring inspired by the "20 questions" approach.
/// Analyzes multiple signals to determine likelihood of malicious intent.
/// </summary>
public sealed class AkinatorEngine
{
    private readonly ILogger<AkinatorEngine> _logger;
    private readonly ScoringEngine _scoringEngine;

    // Suspicious path patterns
    private static readonly Regex[] SuspiciousPathPatterns = new[]
    {
        new Regex(@"\\temp\\", RegexOptions.IgnoreCase),
        new Regex(@"\\tmp\\", RegexOptions.IgnoreCase),
        new Regex(@"\\appdata\\local\\temp", RegexOptions.IgnoreCase),
        new Regex(@"\\downloads\\", RegexOptions.IgnoreCase),
        new Regex(@"\\desktop\\", RegexOptions.IgnoreCase),
        new Regex(@"\\public\\", RegexOptions.IgnoreCase),
        new Regex(@"\\programdata\\", RegexOptions.IgnoreCase),
        new Regex(@"\\start menu\\programs\\startup", RegexOptions.IgnoreCase),
        new Regex(@"\\startup\\", RegexOptions.IgnoreCase),
        new Regex(@"recycle\.bin", RegexOptions.IgnoreCase),
        new Regex(@"\\windows\\(debug|tasks|temp|tracing)", RegexOptions.IgnoreCase)
    };

    // Suspicious command line patterns
    private static readonly Dictionary<string, int> CommandLineRiskScores = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Invoke-Expression"] = 3,
        ["IEX "] = 4,
        ["IEX\t"] = 4,
        ["-w hidden"] = 2,
        ["-windowstyle hidden"] = 2,
        ["-windowstyle h"] = 2,
        ["-enc "] = 3,
        ["-encodedcommand"] = 3,
        ["FromBase64String"] = 2,
        ["Convert.ToBase64String"] = 2,
        ["certutil"] = 3,
        ["bitsadmin"] = 3,
        ["mshta.exe"] = 3,
        ["regsvr32"] = 3,
        ["rundll32"] = 2,
        ["comsvcs.dll"] = 5,
        ["MiniDump"] = 5,
        ["DownloadFile"] = 2,
        ["WebClient"] = 2,
        ["Invoke-WebRequest"] = 2,
        ["iwr "] = 2,
        ["wget "] = 2,
        ["curl "] = 2,
        ["-noprofile"] = 1,
        ["-nop "] = 1,
        ["vbscript:"] = 3,
        ["javascript:"] = 3,
        ["jscript:"] = 3,
        ["wscript.shell"] = 3,
        ["scripting.filesystemobject"] = 3,
        ["shell.application"] = 3,
        ["downloadstring"] = 3,
        ["downloaddata"] = 3,
        ["start-process"] = 1,
        ["saps "] = 1,
        ["sal "] = 1,
        ["new-object"] = 1,
        ["net.webclient"] = 2,
        ["reflection.assembly"] = 2,
        ["::load"] = 2,
        ["virtualalloc"] = 4,
        ["virtualprotect"] = 4,
        ["createremotethread"] = 5,
        ["writeprocessmemory"] = 5,
        ["readprocessmemory"] = 4,
        ["openprocess"] = 2,
        ["ntdll"] = 2,
        ["kernel32"] = 1,
        ["LoadLibrary"] = 2,
        ["GetProcAddress"] = 2,
        ["AmsiScanBuffer"] = 5,
        ["EtwEventWrite"] = 4,
        ["etw"]= 3
    };

    // LOLBins (Living Off The Land Binaries)
    private static readonly HashSet<string> LOLBins = new(StringComparer.OrdinalIgnoreCase)
    {
        "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
        "wscript.exe", "cscript.exe", "powershell.exe", "pwsh.exe", "cmd.exe",
        "cmstp.exe", "infdefaultinstall.exe", "installutil.exe", "msbuild.exe",
        "netsh.exe", "regasm.exe", "regsvcs.exe", "schtasks.exe", "wmic.exe",
        "curl.exe", "wget.exe", "tar.exe", "expand.exe", "makecab.exe",
        "extexport.exe", "diskshadow.exe", "esentutl.exe", "odbcconf.exe",
        "rcsi.exe", "winword.exe", "excel.exe", "powerpnt.exe", "msaccess.exe"
    };

    // Combo multiplier threshold
    private const int ComboMultiplierThreshold = 3;
    private const double ComboMultiplier = 1.5;

    public AkinatorEngine(ILogger<AkinatorEngine> logger, ScoringEngine scoringEngine)
    {
        _logger = logger;
        _scoringEngine = scoringEngine;
    }

    /// <summary>
    /// Calculates the Akinator heuristic score for a detection.
    /// Returns a score from 0-100 indicating likelihood of malicious intent.
    /// </summary>
    public AkinatorScore CalculateScore(
        DetectionEvent detection,
        string? filePath = null,
        string? commandLine = null,
        string? parentProcess = null,
        bool isSigned = false,
        bool isMicrosoftSigned = false,
        string? signerName = null)
    {
        int score = 0;
        var signals = new List<AkinatorSignal>();

        // 1. Path Analysis
        if (!string.IsNullOrEmpty(filePath))
        {
            var pathScore = AnalyzePath(filePath);
            if (pathScore > 0)
            {
                score += pathScore;
                signals.Add(new AkinatorSignal("SuspiciousPath", pathScore, $"File in suspicious location: {filePath}"));
            }
        }

        // 2. Command Line Analysis
        if (!string.IsNullOrEmpty(commandLine))
        {
            var cmdScore = AnalyzeCommandLine(commandLine);
            if (cmdScore > 0)
            {
                score += cmdScore;
                signals.Add(new AkinatorSignal("SuspiciousCommandLine", cmdScore, "Command contains suspicious patterns"));
            }

            // Command line length anomaly
            if (commandLine.Length > 1000)
            {
                score += 3;
                signals.Add(new AkinatorSignal("LongCommandLine", 3, $"Unusually long command: {commandLine.Length} chars"));
            }

            if (commandLine.Length > 500 && (commandLine.Contains("-enc") || commandLine.Contains("-encodedcommand")))
            {
                score += 5;
                signals.Add(new AkinatorSignal("EncodedLongCommand", 5, "Long encoded command - likely obfuscated"));
            }
        }

        // 3. Process Name Analysis
        if (!string.IsNullOrEmpty(detection.ProcessName))
        {
            var nameScore = AnalyzeProcessName(detection.ProcessName);
            if (nameScore > 0)
            {
                score += nameScore;
                signals.Add(new AkinatorSignal("SuspiciousProcessName", nameScore, "Process name indicates potential impersonation"));
            }

            // LOLBin detection
            if (LOLBins.Contains(detection.ProcessName + ".exe"))
            {
                score += 2;
                signals.Add(new AkinatorSignal("LOLBinaUsage", 2, $"{detection.ProcessName} is a LOLBin"));
            }
        }

        // 4. Signature Analysis
        if (!isSigned)
        {
            score += 5;
            signals.Add(new AkinatorSignal("Unsigned", 5, "File is not signed"));
        }
        else if (!isMicrosoftSigned)
        {
            score += 2;
            signals.Add(new AkinatorSignal("NonMicrosoftSigned", 2, $"Signed by: {signerName}"));
        }

        // 5. Parent-Child Relationship
        if (!string.IsNullOrEmpty(parentProcess))
        {
            var parentScore = AnalyzeParentChild(parentProcess, detection.ProcessName);
            if (parentScore > 0)
            {
                score += parentScore;
                signals.Add(new AkinatorSignal("SuspiciousParentChild", parentScore, $"{parentProcess} -> {detection.ProcessName}"));
            }
        }

        // 6. Rule-based boosts
        if (detection.RuleName.Contains("ransomware", StringComparison.OrdinalIgnoreCase))
        {
            score += 10;
            signals.Add(new AkinatorSignal("RansomwareRule", 10, "Ransomware-specific detection"));
        }
        else if (detection.RuleName.Contains("credential", StringComparison.OrdinalIgnoreCase))
        {
            score += 10;
            signals.Add(new AkinatorSignal("CredentialRule", 10, "Credential access detection"));
        }
        else if (detection.RuleName.Contains("c2", StringComparison.OrdinalIgnoreCase) ||
                 detection.RuleName.Contains("beacon", StringComparison.OrdinalIgnoreCase))
        {
            score += 8;
            signals.Add(new AkinatorSignal("C2Rule", 8, "C2 communication detection"));
        }

        // Apply combo multiplier if multiple high-risk signals
        var highRiskSignals = signals.Count(s => s.Score >= 3);
        double multiplier = 1.0;
        if (highRiskSignals >= ComboMultiplierThreshold)
        {
            multiplier = ComboMultiplier;
            signals.Add(new AkinatorSignal("ComboMultiplier", 0, $"{highRiskSignals} high-risk signals - applying 1.5x multiplier"));
        }

        // Calculate final score
        var finalScore = (int)Math.Min(100, score * multiplier);

        // Determine verdict
        var verdict = finalScore switch
        {
            >= 80 => AkinatorVerdict.Critical,
            >= 65 => AkinatorVerdict.HighRisk,
            >= 45 => AkinatorVerdict.MediumRisk,
            >= 25 => AkinatorVerdict.LowRisk,
            _ => AkinatorVerdict.Clean
        };

        _logger.LogDebug(
            "Akinator: {Process} scored {Score} ({Verdict}) with {Signals} signals",
            detection.ProcessName, finalScore, verdict, signals.Count);

        return new AkinatorScore
        {
            Score = finalScore,
            Verdict = verdict,
            Signals = signals,
            Multiplier = multiplier,
            HighRiskSignalCount = highRiskSignals
        };
    }

    private int AnalyzePath(string path)
    {
        int score = 0;
        var lowerPath = path.ToLowerInvariant();

        // Check suspicious patterns
        foreach (var pattern in SuspiciousPathPatterns)
        {
            if (pattern.IsMatch(path))
            {
                score += 3;
            }
        }

        // Double extension check
        if (Regex.IsMatch(path, @"\.[a-z]{3}\.[a-z]{3}$", RegexOptions.IgnoreCase))
        {
            score += 2;
        }

        // Random-looking filename
        var fileName = Path.GetFileNameWithoutExtension(path);
        if (IsRandomLooking(fileName))
        {
            score += 4;
        }

        // GUID-like filename
        if (Regex.IsMatch(fileName, @"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.IgnoreCase))
        {
            // Actually probably legitimate (MSI installer, etc)
            score -= 2;
        }

        return score;
    }

    private int AnalyzeCommandLine(string commandLine)
    {
        int score = 0;
        var lowerCmd = commandLine.ToLowerInvariant();

        foreach (var pattern in CommandLineRiskScores)
        {
            if (lowerCmd.Contains(pattern.Key.ToLowerInvariant()))
            {
                score += pattern.Value;
            }
        }

        // Base64 detection
        var base64Pattern = new Regex(@"[A-Za-z0-9+/]{50,}={0,2}");
        var base64Matches = base64Pattern.Matches(commandLine);
        if (base64Matches.Count > 0)
        {
            score += Math.Min(base64Matches.Count * 2, 10);
        }

        // URL in command line
        if (Regex.IsMatch(commandLine, @"https?://[^\s""]+"))
        {
            score += 2;
        }

        return score;
    }

    private int AnalyzeProcessName(string processName)
    {
        int score = 0;
        var lowerName = processName.ToLowerInvariant();

        // System binary impersonation
        var systemProcesses = new[] { "svchost", "lsass", "csrss", "services", "smss", "wininit", "winlogon", "dwm" };
        foreach (var sysProc in systemProcesses)
        {
            if (lowerName.Contains(sysProc) && !lowerName.Equals(sysProc, StringComparison.OrdinalIgnoreCase))
            {
                score += 10; // High score for impersonation
            }
        }

        // Random-looking name
        if (IsRandomLooking(processName))
        {
            score += 5;
        }

        return score;
    }

    private int AnalyzeParentChild(string parent, string child)
    {
        int score = 0;

        // Office apps spawning shells
        var officeApps = new[] { "winword", "excel", "powerpnt", "outlook", "msaccess" };
        var shells = new[] { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe" };

        if (officeApps.Any(o => parent.Contains(o, StringComparison.OrdinalIgnoreCase)) &&
            shells.Any(s => child.Contains(s, StringComparison.OrdinalIgnoreCase)))
        {
            score += 8;
        }

        // Browser spawning shell
        var browsers = new[] { "chrome", "firefox", "msedge", "brave", "opera", "iexplore" };
        if (browsers.Any(b => parent.Contains(b, StringComparison.OrdinalIgnoreCase)) &&
            shells.Any(s => child.Contains(s, StringComparison.OrdinalIgnoreCase)))
        {
            score += 7;
        }

        // Script host spawning other processes
        var scriptHosts = new[] { "wscript.exe", "cscript.exe", "mshta.exe" };
        if (scriptHosts.Any(s => parent.Contains(s, StringComparison.OrdinalIgnoreCase)))
        {
            score += 5;
        }

        return score;
    }

    private bool IsRandomLooking(string name)
    {
        if (string.IsNullOrEmpty(name) || name.Length < 6) return false;

        // Check for random-looking strings (high entropy, no vowels, etc)
        var vowels = "aeiouAEIOU";
        var vowelCount = name.Count(c => vowels.Contains(c));
        var vowelRatio = (double)vowelCount / name.Length;

        // Normal words have ~40% vowels
        if (vowelRatio < 0.2) return true;

        // Check for alternating consonant patterns
        var alternatingPattern = Regex.IsMatch(name, @"(^[^aeiou]{2,}[aeiou]{1,2}[^aeiou]{2,})|([aeiou]{1,2}[^aeiou]{2,}[aeiou]{1,2})");
        if (alternatingPattern && name.Length > 8) return true;

        return false;
    }
}

/// <summary>
/// Represents an Akinator scoring result.
/// </summary>
public sealed class AkinatorScore
{
    public int Score { get; set; }
    public AkinatorVerdict Verdict { get; set; }
    public List<AkinatorSignal> Signals { get; set; } = new();
    public double Multiplier { get; set; }
    public int HighRiskSignalCount { get; set; }

    public bool IsMalicious => Score >= 65;
    public bool IsSuspicious => Score >= 45;

    public string Summary => $"Score: {Score}/100 ({Verdict}) - {Signals.Count} signals, {HighRiskSignalCount} high-risk";
}

/// <summary>
/// Individual signal that contributed to the score.
/// </summary>
public sealed class AkinatorSignal
{
    public string Name { get; }
    public int Score { get; }
    public string Description { get; }

    public AkinatorSignal(string name, int score, string description)
    {
        Name = name;
        Score = score;
        Description = description;
    }

    public override string ToString() => $"[{Name}] +{Score}: {Description}";
}

public enum AkinatorVerdict
{
    Clean,      // 0-24
    LowRisk,    // 25-44
    MediumRisk, // 45-64
    HighRisk,   // 65-79
    Critical    // 80-100
}

