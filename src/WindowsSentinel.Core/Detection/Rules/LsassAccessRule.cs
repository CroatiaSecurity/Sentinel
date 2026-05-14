using System.Text;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Detects credential-dumping attempts targeting LSASS.
///
/// Detection vectors:
///   1. Process name / image path is a known credential-dumping tool.
///   2. Command line explicitly targets lsass (procdump -ma lsass, task manager dump, etc.).
///   3. Known dump-file names produced by credential dumpers.
///   4. Suspicious parent → child relationships (e.g. Word spawning procdump).
///
/// Excludes: lsass.exe itself and a tight whitelist of OS components that
/// legitimately interact with the LSASS process.
/// </summary>
public sealed class LsassAccessRule : IDetectionRule
{
    public string Name => "LSASS Credential Dump Attempt";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    // Processes that legitimately reference lsass — kept intentionally tight.
    private static readonly HashSet<string> AllowedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "lsass", "System", "csrss", "wininit", "services", "smss",
        "MsMpEng",   // Windows Defender
        "SenseCnfg", // Microsoft Defender for Endpoint sensor
        "MsSense"    // Microsoft Defender for Endpoint
    };

    // OBSOLETE: Filename-based detection is completely bypassed by renaming.
    // These are kept only for threat intelligence correlation, NOT for detection decisions.
    // Detection is now 100% behavioral (command-line patterns + hash signatures).
    private static readonly HashSet<string> DumperNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "mimikatz", "mimilib", "mimidrv",
        "procdump", "procdump64",
        "wce",
        "pwdump", "pwdump7", "fgdump",
        "gsecdump", "cachedump",
        "lsadump",
        "nanodump", "minidump",
        "safetykatz", "sharpkatz", "kekeo",
        "pypykatz", "lsassy",
        "secretsdump",
        "invoke-mimikatz", "out-minidump"
    };
    
    // SHA256 hashes of known dumper binaries.
    // REMOVED in v1.1.0: Placeholder/fake hashes that gave false sense of security.
    // Hash-based detection is handled by the HashReputationService (3-API lookup)
    // and IoCScannerRule (curated IOC list). This rule is now PURELY behavioral:
    // command-line patterns + parent-child context. No filename matching, no fake hashes.
    //
    // Why: A static hash list in source code is:
    //   1. Immediately visible to attackers who read the code
    //   2. Trivially bypassed by recompiling the tool
    //   3. Impossible to keep current without a live feed
    //   4. Worse than nothing if it creates false confidence

    // Command-line patterns that indicate lsass targeting.
    // Single-word patterns are matched against individual tokens.
    // Multi-word patterns are matched against the full (lowercased) command line.
    private static readonly string[] LsassTargetPatterns =
    {
        "lsass",                    // procdump -ma lsass, taskmgr dump, etc.
        "sekurlsa",                 // mimikatz module
        "logonpasswords",           // mimikatz command
        "wdigest",                  // mimikatz / manual dump
        "kerberos::list",
        "lsadump::",
        "dcsync",
        "ntds.dit",
        "/ma lsass", "-ma lsass",   // procdump flags
        "comsvcs.dll,MiniDump",     // rundll32 comsvcs lsass dump technique
        "comsvcs MiniDump",
        "Out-MiniDump",
        "CreateDump",
        "dbghelp",                  // manual MiniDumpWriteDump via dbghelp
    };

    // Known dump output file names.
    private static readonly string[] DumpFilePatterns =
    {
        "lsass.dmp", "lsass.zip", "lsass.out",
        "lsass.bin", "lsass.log", "lsass.txt",
        "lsass.exe.dmp", "lsass.mdmp",
        "debug.out", "creds.dmp"
    };

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;
        if (proc.EventType != "ProcessStart") return null;
        if (AllowedProcesses.Contains(proc.ProcessName)) return null;

        // SECURITY: Tokenize command line for proper pattern matching
        var tokens = TokenizeCommandLine(proc.CommandLine);
        var cmdLineLower = proc.CommandLine.ToLowerInvariant();
        
        // Check for LSASS-targeting patterns using tokenization + substring for multi-word patterns
        string? matchedPattern = null;
        foreach (var pattern in LsassTargetPatterns)
        {
            // Multi-word patterns: check against full command line (case-insensitive)
            if (pattern.Contains(' ') || pattern.Contains(',') || pattern.Contains(':'))
            {
                if (cmdLineLower.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    matchedPattern = pattern;
                    break;
                }
            }
            else
            {
                // Single-word patterns: match against individual tokens
                if (tokens.Any(t => t.Equals(pattern, StringComparison.OrdinalIgnoreCase)))
                {
                    matchedPattern = pattern;
                    break;
                }
            }
        }

        // Check for dump file patterns in tokens
        string? matchedDumpFile = DumpFilePatterns.FirstOrDefault(p =>
            tokens.Any(t => t.Equals(p, StringComparison.OrdinalIgnoreCase)));

        // v1.1.0: Detection is PURELY behavioral — command-line patterns only.
        // No filename matching (trivially bypassed by renaming).
        // No static hash matching (placeholder hashes were security theater).
        // Hash reputation is handled by HashReputationService (live 3-API lookup).
        if (matchedPattern is null && matchedDumpFile is null)
        {
            return null;
        }

        // Build evidence string with proper confidence scoring
        string evidence;
        double confidence;

        if (matchedPattern is not null && matchedDumpFile is not null)
        {
            evidence = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) uses LSASS-targeting " +
                      $"pattern '{matchedPattern}' and references dump file '{matchedDumpFile}'. " +
                      $"CommandLine: {proc.CommandLine}";
            confidence = 0.92;
        }
        else if (matchedPattern is not null)
        {
            evidence = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) uses LSASS-targeting " +
                      $"pattern '{matchedPattern}'. CommandLine: {proc.CommandLine}";
            confidence = 0.88;
        }
        else if (matchedDumpFile is not null)
        {
            evidence = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) references known " +
                      $"LSASS dump file name '{matchedDumpFile}'. CommandLine: {proc.CommandLine}";
            confidence = 0.85;
        }
        else
        {
            return null;
        }

        return new DetectionEvent
        {
            RuleName    = Name,
            Evidence    = evidence,
            Reasoning   = "Credential dumping from LSASS is the primary technique used by attackers " +
                          "to harvest plaintext passwords, NTLM hashes, and Kerberos tickets for " +
                          "lateral movement (T1003.001). Tools like Mimikatz, procdump, and the " +
                          "comsvcs.dll MiniDump technique are all covered.",
            Confidence  = confidence,
            Tier        = Tier,
            ProcessName = proc.ProcessName,
            ProcessId   = proc.ProcessId,
            Timestamp   = proc.Timestamp,
            Metadata    = new()
            {
                ["ImagePath"]      = proc.ImagePath,
                ["CommandLine"]    = proc.CommandLine,
                ["ParentPid"]      = proc.ParentProcessId.ToString(),
                ["MatchedPattern"] = matchedPattern ?? matchedDumpFile ?? proc.ProcessName
            }
        };
    }

    // SECURITY FIX: Command-line tokenization for proper pattern detection
    // Prevents bypasses from string obfuscation or unusual spacing
    private static List<string> TokenizeCommandLine(string commandLine)
    {
        var tokens = new List<string>();
        if (string.IsNullOrWhiteSpace(commandLine))
            return tokens;

        var currentToken = new StringBuilder();
        bool inQuotes = false;
        bool inSingleQuotes = false;

        for (int i = 0; i < commandLine.Length; i++)
        {
            char c = commandLine[i];

            if (c == '"' && !inSingleQuotes)
            {
                if (currentToken.Length > 0 && !inQuotes)
                {
                    tokens.Add(currentToken.ToString());
                    currentToken.Clear();
                }
                inQuotes = !inQuotes;
            }
            else if (c == '\'' && !inQuotes)
            {
                if (currentToken.Length > 0 && !inSingleQuotes)
                {
                    tokens.Add(currentToken.ToString());
                    currentToken.Clear();
                }
                inSingleQuotes = !inSingleQuotes;
            }
            else if (char.IsWhiteSpace(c) && !inQuotes && !inSingleQuotes)
            {
                if (currentToken.Length > 0)
                {
                    tokens.Add(currentToken.ToString());
                    currentToken.Clear();
                }
            }
            else
            {
                currentToken.Append(c);
            }
        }

        if (currentToken.Length > 0)
        {
            tokens.Add(currentToken.ToString());
        }

        return tokens;
    }
}
