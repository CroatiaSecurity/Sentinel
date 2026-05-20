using System.Text;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Detects reverse shell and C2 callback behavior.
///
/// Detection vectors:
///   1. Network connection to a known C2/reverse-shell port.
///   2. Shell/interpreter process launched with network-piping arguments.
///   3. Encoded PowerShell payloads (-EncodedCommand / -enc).
///   4. Living-off-the-land binaries (LOLBins) used for download-and-execute.
///   5. Common C2 framework indicators (Cobalt Strike, Metasploit, Sliver, Havoc, etc.).
/// </summary>
public sealed class ReverseShellRule : IDetectionRule
{
    public string Name => "Reverse Shell / C2 Callback";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    // Ports commonly used by reverse-shell frameworks and C2 beacons.
    // Metasploit defaults, netcat defaults, common Cobalt Strike malleable profiles, etc.
    private static readonly HashSet<int> SuspiciousPorts = new()
    {
        // Classic reverse shell / netcat
        4444, 4445, 4446, 4447, 4448,
        1337, 31337,
        // Metasploit common
        5555, 6666, 7777, 8888, 9001, 9002, 9003,
        // Cobalt Strike default team-server
        50050,
        // Havoc C2
        40056,
        // Sliver C2
        31337, 8888,
        // Empire / Starkiller
        1234,
        // Common attacker-chosen high ports
        65535, 65000, 60000
    };

    // Shell / interpreter processes that should not be making raw TCP connections.
    private static readonly HashSet<string> ShellProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe",
        "bash.exe", "sh.exe", "zsh.exe",
        "wscript.exe", "cscript.exe",
        "mshta.exe"
    };

    // Command-line patterns indicating network-piped shell execution.
    private static readonly string[] NetworkShellPatterns =
    {
        // PowerShell TCP socket patterns
        "New-Object Net.Sockets.TCPClient",
        "New-Object System.Net.Sockets.TCPClient",
        "TCPClient",
        "StreamReader", "StreamWriter",
        // Bash / sh piped to nc
        "-e cmd", "-e /bin/sh", "-e /bin/bash", "-e cmd.exe",
        // Netcat variants
        "nc.exe", "ncat", "netcat", "ncat.exe",
        // Python reverse shells
        "socket.connect", "socket.AF_INET",
        "import socket", "os.dup2",
        // Perl reverse shell
        "use Socket",
        // Ruby reverse shell
        "TCPSocket.new",
    };

    // Encoded PowerShell — base64 payload delivery.
    // SECURITY FIX: Uses proper tokenization to detect flag variations
    // that simple string matching would miss (e.g., -en combined with following c)
    private static readonly string[] EncodedPsPatterns =
    {
        "FromBase64String",  // runtime decode + execute
        "[Convert]::FromBase64",
        "IEX(New-Object",    // IEX + download — classic stager
        "IEX (New-Object",
        "iex(new-object",
        "Invoke-Expression (New-Object",
        // Network socket + IEX combination
        "TCPClient",
    };

    // PowerShell encoded command flags (can be combined: -enc, -en c, -encodedcommand, etc.)
    // These are detected via tokenization, not substring matching
    private static readonly string[] PowerShellEncodedFlags = { "-enc", "-ec", "-en", "-encodedcommand" };

    // LOLBin download-and-execute patterns.
    private static readonly (string Process, string Pattern)[] LolbinPatterns =
    {
        ("certutil.exe",   "-decode"),
        ("certutil.exe",   "-urlcache"),
        ("certutil.exe",   "http"),
        ("bitsadmin.exe",  "/transfer"),
        ("bitsadmin.exe",  "http"),
        ("mshta.exe",      "http"),
        ("mshta.exe",      "vbscript"),
        ("mshta.exe",      "javascript"),
        ("regsvr32.exe",   "/s /n /u /i:http"),
        ("regsvr32.exe",   "scrobj.dll"),
        ("rundll32.exe",   "javascript:"),
        ("rundll32.exe",   "http"),
        ("wmic.exe",       "process call create"),
        ("wmic.exe",       "http"),
        ("msiexec.exe",    "/q /i http"),
        ("msiexec.exe",    "http"),
        ("installutil.exe","http"),
        ("cmstp.exe",      "http"),
        ("cmstp.exe",      "/s /ns"),
        ("xwizard.exe",    "http"),
        ("pcalua.exe",     "-a"),
        ("forfiles.exe",   "/c"),
        ("scriptrunner.exe","http"),
        ("ie4uinit.exe",   "-BaseSettings"),
    };

    // Known C2 framework artifact strings in command lines.
    private static readonly string[] C2Indicators =
    {
        // Cobalt Strike
        "beacon", "cobaltstrike", "cs_beacon",
        // Metasploit
        "meterpreter", "msf", "metasploit",
        // Sliver
        "sliver-client", "sliver-server",
        // Havoc
        "havoc", "teamserver",
        // Empire
        "empire", "starkiller",
        // Brute Ratel
        "bruteratel", "badger",
        // Nighthawk
        "nighthawk",
        // Generic staging
        "stager", "stage2", "payload.exe", "beacon.exe",
    };

    public DetectionEvent? Evaluate(object telemetry)
    {
        // ── Network-based detection ──────────────────────────────────────────
        if (telemetry is NetworkTelemetry net)
        {
            if (!SuspiciousPorts.Contains(net.Connection.RemotePort)) return null;

            return new DetectionEvent
            {
                RuleName    = Name,
                Evidence    = $"Outbound TCP connection to {net.Connection.RemoteAddress}:{net.Connection.RemotePort} " +
                              $"from PID {net.Connection.ProcessId} (state: {net.Connection.State})",
                Reasoning   = $"Port {net.Connection.RemotePort} is associated with reverse shell frameworks " +
                              "(Metasploit, netcat, Cobalt Strike, Sliver, Havoc, Empire). " +
                              "Outbound connections to these ports from non-browser processes are high-confidence C2 indicators.",
                Confidence  = 0.80,
                Tier        = Tier,
                ProcessName = net.Connection.ProcessId.ToString(),
                ProcessId   = net.Connection.ProcessId,
                Timestamp   = net.Timestamp,
                Metadata    = new()
                {
                    ["RemoteAddress"] = net.Connection.RemoteAddress,
                    ["RemotePort"]    = net.Connection.RemotePort.ToString(),
                    ["LocalPort"]     = net.Connection.LocalPort.ToString(),
                    ["State"]         = net.Connection.State
                }
            };
        }

        // ── Process-based detection ──────────────────────────────────────────
        if (telemetry is not ProcessTelemetry proc) return null;

        var cmdLower  = proc.CommandLine.ToLowerInvariant();
        var nameLower = proc.ProcessName.ToLowerInvariant();
        var imgLower  = proc.ImagePath.ToLowerInvariant();

        // 1. Encoded PowerShell - using proper tokenization
        if (ShellProcesses.Contains(proc.ProcessName) ||
            imgLower.EndsWith("powershell.exe") || imgLower.EndsWith("pwsh.exe"))
        {
            // SECURITY FIX: Tokenize command line instead of using substring matching
            // This prevents bypasses like splitting flags: -en c (with space) instead of -enc
            var tokens = TokenizeCommandLine(proc.CommandLine);
            
            // Check for encoded command flag patterns using tokenization
            string? matchedFlag = null;
            for (int i = 0; i < tokens.Count; i++)
            {
                var token = tokens[i].ToLowerInvariant();
                
                // Check direct flag matches
                if (PowerShellEncodedFlags.Contains(token))
                {
                    matchedFlag = tokens[i];
                    break;
                }
                
                // Check split flag patterns: -en followed by c (or similar)
                // PowerShell allows: -en c where "c" is the value for the flag
                if ((token == "-en" || token == "-ec") && i + 1 < tokens.Count)
                {
                    var nextToken = tokens[i + 1].ToLowerInvariant();
                    // If next token starts with valid flag continuation or is base64-ish
                    if (nextToken.StartsWith("c") || IsBase64Like(nextToken))
                    {
                        matchedFlag = $"{tokens[i]} {tokens[i + 1]} (split flag)";
                        break;
                    }
                }
            }
            
            // Also check patterns that indicate obfuscation
            var encMatch = EncodedPsPatterns.FirstOrDefault(p =>
                proc.CommandLine.Contains(p, StringComparison.OrdinalIgnoreCase));
                
            if (matchedFlag is not null || encMatch is not null)
            {
                var evidence = matchedFlag is not null 
                    ? $"Encoded PowerShell flag '{matchedFlag}' detected in '{proc.ProcessName}' (PID {proc.ProcessId})"
                    : $"Encoded/obfuscated PowerShell in '{proc.ProcessName}' (PID {proc.ProcessId}): pattern '{encMatch}'";
                    
                return new DetectionEvent
                {
                    RuleName    = Name,
                    Evidence    = evidence + $". CommandLine: {proc.CommandLine}",
                    Reasoning   = "Encoded PowerShell (-EncodedCommand in any form, IEX, FromBase64String) is the most " +
                                  "common delivery mechanism for fileless malware, C2 stagers, and post-exploitation " +
                                  "frameworks. Tokenization detects flag splitting bypass attempts.",
                    Confidence  = matchedFlag is not null ? 0.95 : 0.92,
                    Tier        = Tier,
                    ProcessName = proc.ProcessName,
                    ProcessId   = proc.ProcessId,
                    Timestamp   = proc.Timestamp,
                    Metadata    = new()
                    {
                        ["CommandLine"]    = proc.CommandLine,
                        ["MatchedPattern"] = matchedFlag ?? encMatch ?? "unknown",
                        ["Tokens"] = string.Join("|", tokens.Take(20))  // Log first 20 tokens for analysis
                    }
                };
            }
        }

        // 2. LOLBin download-and-execute
        foreach (var (lolProcess, lolPattern) in LolbinPatterns)
        {
            if ((nameLower == lolProcess.ToLowerInvariant() ||
                 imgLower.EndsWith(lolProcess.ToLowerInvariant())) &&
                cmdLower.Contains(lolPattern.ToLowerInvariant()))
            {
                return new DetectionEvent
                {
                    RuleName    = Name,
                    Evidence    = $"LOLBin '{proc.ProcessName}' (PID {proc.ProcessId}) used with " +
                                  $"download/execute pattern '{lolPattern}'. CommandLine: {proc.CommandLine}",
                    Reasoning   = $"{proc.ProcessName} is a signed Windows binary (LOLBin) that can be " +
                                  "abused to download and execute arbitrary code, bypassing application " +
                                  "whitelisting and AV. This pattern is heavily used by APTs and commodity malware.",
                    Confidence  = 0.90,
                    Tier        = Tier,
                    ProcessName = proc.ProcessName,
                    ProcessId   = proc.ProcessId,
                    Timestamp   = proc.Timestamp,
                    Metadata    = new()
                    {
                        ["CommandLine"]    = proc.CommandLine,
                        ["LolBin"]         = lolProcess,
                        ["MatchedPattern"] = lolPattern
                    }
                };
            }
        }

        // 3. Shell process with network-piping arguments
        if (ShellProcesses.Contains(proc.ProcessName))
        {
            var netMatch = NetworkShellPatterns.FirstOrDefault(p =>
                proc.CommandLine.Contains(p, StringComparison.OrdinalIgnoreCase));
            if (netMatch is not null)
            {
                return new DetectionEvent
                {
                    RuleName    = Name,
                    Evidence    = $"Shell '{proc.ProcessName}' (PID {proc.ProcessId}) with network-pipe " +
                                  $"pattern '{netMatch}'. CommandLine: {proc.CommandLine}",
                    Reasoning   = "Shell processes with network socket arguments are a strong indicator of " +
                                  "reverse shell execution. This pattern is used by PowerShell, bash, and " +
                                  "scripting-language reverse shells.",
                    Confidence  = 0.93,
                    Tier        = Tier,
                    ProcessName = proc.ProcessName,
                    ProcessId   = proc.ProcessId,
                    Timestamp   = proc.Timestamp,
                    Metadata    = new()
                    {
                        ["CommandLine"]    = proc.CommandLine,
                        ["MatchedPattern"] = netMatch
                    }
                };
            }
        }

        // 4. Known C2 framework indicators
        var c2Match = C2Indicators.FirstOrDefault(i =>
            cmdLower.Contains(i) || nameLower.Contains(i) || imgLower.Contains(i));
        if (c2Match is not null)
        {
            return new DetectionEvent
            {
                RuleName    = Name,
                Evidence    = $"C2 framework indicator '{c2Match}' in process '{proc.ProcessName}' " +
                              $"(PID {proc.ProcessId}). CommandLine: {proc.CommandLine}",
                Reasoning   = "Known C2 framework artifact detected. These strings appear in Cobalt Strike " +
                              "beacons, Metasploit stagers, Sliver, Havoc, and Empire implants.",
                Confidence  = 0.88,
                Tier        = Tier,
                ProcessName = proc.ProcessName,
                ProcessId   = proc.ProcessId,
                Timestamp   = proc.Timestamp,
                Metadata    = new()
                {
                    ["CommandLine"] = proc.CommandLine,
                    ["C2Indicator"] = c2Match
                }
            };
        }

        return null;
    }

    // SECURITY FIX: Command-line tokenization for proper flag detection
    // PowerShell allows various flag forms: -enc, -en c (split), -encodedcommand, etc.
    // Simple string matching can be bypassed by: -en c instead of -enc
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

    // Check if a string looks like base64 encoded data
    // Base64 typically: A-Z, a-z, 0-9, +, /, = padding
    // Length usually divisible by 4, minimum 20 chars for encoded commands
    private static bool IsBase64Like(string value)
    {
        if (value.Length < 8 || value.Length > 10000)
            return false;

        // Check for base64 character set
        int base64Chars = 0;
        int totalChars = 0;

        foreach (char c in value)
        {
            if (char.IsWhiteSpace(c))
                continue;

            totalChars++;
            if (char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=')
            {
                base64Chars++;
            }
        }

        // If 90%+ of characters are in base64 alphabet, likely base64
        return totalChars > 0 && (double)base64Chars / totalChars > 0.9;
    }
}

