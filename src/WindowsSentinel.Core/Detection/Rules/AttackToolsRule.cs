using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Detects known attack tools and frameworks by name and artifact patterns.
///
/// Detection vectors:
///   1. Known offensive security tool names (Cobalt Strike, Metasploit, etc.).
///   2. C2 framework artifact patterns in command lines.
///   3. Red team tooling and post-exploitation frameworks.
///   4. Credential theft and password cracking tools.
///   5. Network attack tools (responder, crackmapexec, etc.).
///
/// This rule complements behavioral rules by catching tools by name
/// even when their behavior hasn't triggered yet.
/// </summary>
public sealed class AttackToolsRule : IDetectionRule
{
    public string Name => "Known Attack Tool Detected";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    // Post-exploitation frameworks and C2 clients
    private static readonly HashSet<string> C2Frameworks = new(StringComparer.OrdinalIgnoreCase)
    {
        // Cobalt Strike
        "beacon", "cobaltstrike", "cs_beacon", "artifact", "beacon.exe", "cobaltstrike.exe",
        "stager", "payload.exe", "shellcode",
        // Metasploit
        "meterpreter", "metasploit", "msfvenom", "msf", "meterpreter.exe",
        "msfconsole", "msflistener",
        // Sliver
        "sliver", "sliver-client", "sliver-server", "sliver.exe", "implant",
        // Havoc
        "havoc", "havoc-client", "havoc-server", "demon",
        // Empire
        "empire", "starkiller", "empire.exe", "launcher",
        // Brute Ratel
        "bruteratel", "badger", "brute-ratel",
        // Nighthawk
        "nighthawk", "nh-installer",
        // Covenant
        "covenant", "grunt", "grunt.exe",
        // PoshC2
        "poshc2", "posh",
        // Mythic
        "mythic", "apollo", "ares", "athena",
    };

    // Credential theft and password tools
    private static readonly HashSet<string> CredentialTools = new(StringComparer.OrdinalIgnoreCase)
    {
        // LSASS dumpers (also in LsassAccessRule, but catch by name here too)
        "mimikatz", "mimidrv", "mimilib",
        "procdump", "procdump64",
        "wce", "pwdump", "pwdump7", "fgdump",
        "gsecdump", "cachedump", "lsadump",
        "nanodump", "minidump",
        "safetykatz", "sharpkatz", "kekeo", "kekeo.exe",
        "pypykatz", "lsassy", "secretsdump",
        // Password cracking
        "john", "john.exe", "hashcat", "hashcat64",
        "ophcrack", "l0phtcrack",
        "cain", "cain.exe", "abel",
        // Browser credential theft
        "webbrowserpassview", "browserpass", "chromepass",
        "hackbrowserdata", "sharpweb",
        // Other credential tools
        "lazagne", "la-zagne", "mimipenguin",
        "mccmd", "credential-dump",
    };

    // Network attack tools
    private static readonly HashSet<string> NetworkAttackTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "responder", "responder.exe",
        "crackmapexec", "cme", "crackmapexec.exe",
        "impacket", "smbexec", "wmiexec", "atexec", "dcomexec",
        "pth-toolkit", "pth-net", "pth-winexe",
        "nxc", "netexec",
        "evil-winrm", "evilwinrm",
        "kerbrute", "rubeus", "rubeus.exe",
        "bloodhound", "bloodhound.exe", "sharphound", "sharphound.exe",
        "adexplorer", "adexplorer.exe",
        "powersploit", "powerview", "powerview.ps1",
        "nmap", "masscan", "zmap",
        "ncat", "ncat.exe", "netcat", "nc.exe", "nc64",
    };

    // Active Directory attack tools
    private static readonly HashSet<string> AdAttackTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "adfind", "adfind.exe",
        "admod", "admod.exe",
        "dsquery", "ldapdomaindump",
        "aclpwn", "powerview",
        "invoke-dcsync", "invoke-kerberoast",
        "certipy", "certi", "certutil-attack",
        "laps", "laps-toolkit",
        "zeroexchange", "petitpotam", "dfscoerce",
        "sam-the-admin", "no-pac",
    };

    // Living-off-the-land binaries commonly used in attacks (LOLBins)
    // Note: These are also detected behaviorally in ReverseShellRule.
    // This catches the tool names when used in suspicious combinations.
    private static readonly Dictionary<string, string[]> LolbinAbusePatterns = new()
    {
        ["certutil.exe"] = new[] { "-decode", "-urlcache", "-split", "http://", "https://" },
        ["bitsadmin.exe"] = new[] { "/transfer", "/create", "/addfile", "http://", "https://" },
        ["mshta.exe"] = new[] { "http://", "https://", "vbscript:", "javascript:" },
        ["regsvr32.exe"] = new[] { "/s /n /u /i:http", "/s /n /u /i:https", "scrobj.dll" },
        ["rundll32.exe"] = new[] { "javascript:", "http://", "https://", "\\windows\\system32\\comsvcs.dll" },
        ["wmic.exe"] = new[] { "process call create", "http://", "https://" },
        ["msiexec.exe"] = new[] { "/i http", "/i https", "/q /i" },
        ["installutil.exe"] = new[] { "http://", "https://", "-u" },
        ["cmstp.exe"] = new[] { "/s", "/ns", "http://", "https://" },
        ["pcalua.exe"] = new[] { "-a", "-c" },
        ["forfiles.exe"] = new[] { "/c", "/p", "cmd" },
        ["xwizard.exe"] = new[] { "http://", "https://" },
    };

    // Legitimate security research tools (may cause false positives in enterprise)
    // These get lower confidence unless combined with other indicators
    private static readonly HashSet<string> DualUseTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "burpsuite", "zap", "wireshark", "fiddler",
        "nmap", "sqlmap", "nikto", "dirb", "gobuster",
        "metasploit-framework", "armitage",
    };

    // Command-line patterns indicating attack tool usage
    private static readonly string[] AttackToolPatterns =
    {
        "Invoke-Mimikatz", "Invoke-PsUaCme", "Invoke-WmiCommand",
        "Invoke-DllInjection", "Invoke-ReflectivePEInjection", "Invoke-Shellcode",
        "Invoke-Portscan", "Invoke-kerberoast", "Invoke-DCSync",
        "Get-ComputerInfo", "Get-ADUser", "Get-DomainUser", "Get-DomainController",
        "bloodhound", "sharphound", "Invoke-Bloodhound",
        "Invoke-DCOM", "Invoke-SMBExec", "Invoke-WMIExec",
        "metasploit", "meterpreter", "beacon",
        "runas /user:", "runas /netonly",
    };

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;
        if (proc.EventType != "ProcessStart") return null;

        var cmdLower = proc.CommandLine.ToLowerInvariant();
        var nameLower = proc.ProcessName.ToLowerInvariant();
        var imgLower = proc.ImagePath.ToLowerInvariant();
        var nameStem = Path.GetFileNameWithoutExtension(proc.ProcessName);

        // 1. C2 Framework detection
        foreach (var framework in C2Frameworks)
        {
            if (nameStem.Contains(framework, StringComparison.OrdinalIgnoreCase) ||
                cmdLower.Contains(framework, StringComparison.OrdinalIgnoreCase) ||
                imgLower.Contains(framework, StringComparison.OrdinalIgnoreCase))
            {
                return new DetectionEvent
                {
                    RuleName    = Name,
                    Evidence    = $"Known C2/post-exploitation framework '{framework}' detected. " +
                                  $"Process '{proc.ProcessName}' (PID {proc.ProcessId}). " +
                                  $"CommandLine: {proc.CommandLine}",
                    Reasoning   = "C2 frameworks (Cobalt Strike, Metasploit, Sliver, Havoc, Empire) are used by " +
                                  "attackers to maintain persistent access, execute commands, and exfiltrate data. " +
                                  "Detection of these tools is a high-confidence indicator of compromise (T1071).",
                    Confidence  = 0.95,
                    Tier        = Tier,
                    ProcessName = proc.ProcessName,
                    ProcessId   = proc.ProcessId,
                    Timestamp   = proc.Timestamp,
                    Metadata    = new()
                    {
                        ["ToolCategory"] = "C2Framework",
                        ["ToolName"]     = framework,
                        ["CommandLine"]  = proc.CommandLine,
                        ["ImagePath"]    = proc.ImagePath
                    }
                };
            }
        }

        // 2. Credential theft tools
        foreach (var credTool in CredentialTools)
        {
            if (nameStem.Contains(credTool, StringComparison.OrdinalIgnoreCase) ||
                imgLower.Contains(credTool, StringComparison.OrdinalIgnoreCase))
            {
                return new DetectionEvent
                {
                    RuleName    = Name,
                    Evidence    = $"Known credential theft tool '{credTool}' detected. " +
                                  $"Process '{proc.ProcessName}' (PID {proc.ProcessId}). " +
                                  $"CommandLine: {proc.CommandLine}",
                    Reasoning   = "Credential theft tools (Mimikatz, Procdump, etc.) extract passwords, hashes, " +
                                  "and tickets from memory. These tools are essential to post-exploitation and " +
                                  "lateral movement (T1003). Legitimate use is extremely rare.",
                    Confidence  = 0.97,
                    Tier        = Tier,
                    ProcessName = proc.ProcessName,
                    ProcessId   = proc.ProcessId,
                    Timestamp   = proc.Timestamp,
                    Metadata    = new()
                    {
                        ["ToolCategory"] = "CredentialTheft",
                        ["ToolName"]     = credTool,
                        ["CommandLine"]  = proc.CommandLine,
                        ["ImagePath"]    = proc.ImagePath
                    }
                };
            }
        }

        // 3. Network attack tools
        foreach (var netTool in NetworkAttackTools)
        {
            if (nameStem.Contains(netTool, StringComparison.OrdinalIgnoreCase) ||
                imgLower.Contains(netTool, StringComparison.OrdinalIgnoreCase))
            {
                var isDualUse = DualUseTools.Contains(netTool);
                var confidence = isDualUse ? 0.60 : 0.92;

                // Dual-use tools (nmap, wireshark, ncat, etc.) are Tier2 — log only.
                // They're common in pentesting and sysadmin work and should not auto-kill.
                var tier = isDualUse ? DetectionTier.Tier2Indicator : DetectionTier.Tier1Behavioral;

                return new DetectionEvent
                {
                    RuleName    = Name,
                    Evidence    = $"Known network attack tool '{netTool}' detected. " +
                                  $"Process '{proc.ProcessName}' (PID {proc.ProcessId}). " +
                                  $"CommandLine: {proc.CommandLine}",
                    Reasoning   = isDualUse
                        ? $"'{netTool}' is a dual-use tool common in legitimate pentesting and sysadmin work. " +
                          "Logged as an indicator — investigate in context of other detections."
                        : "Network attack tools (Responder, CrackMapExec, Impacket, BloodHound) are used " +
                          "for lateral movement, credential relay, and Active Directory reconnaissance " +
                          "(T1021, T1119). These tools indicate an active compromise or red team exercise.",
                    Confidence  = confidence,
                    Tier        = tier,
                    ProcessName = proc.ProcessName,
                    ProcessId   = proc.ProcessId,
                    Timestamp   = proc.Timestamp,
                    Metadata    = new()
                    {
                        ["ToolCategory"] = "NetworkAttack",
                        ["ToolName"]     = netTool,
                        ["IsDualUse"]    = isDualUse.ToString(),
                        ["CommandLine"]  = proc.CommandLine,
                        ["ImagePath"]    = proc.ImagePath
                    }
                };
            }
        }

        // 4. AD attack tools
        foreach (var adTool in AdAttackTools)
        {
            if (nameStem.Contains(adTool, StringComparison.OrdinalIgnoreCase) ||
                cmdLower.Contains(adTool, StringComparison.OrdinalIgnoreCase) ||
                imgLower.Contains(adTool, StringComparison.OrdinalIgnoreCase))
            {
                return new DetectionEvent
                {
                    RuleName    = Name,
                    Evidence    = $"Known Active Directory attack tool '{adTool}' detected. " +
                                  $"Process '{proc.ProcessName}' (PID {proc.ProcessId}). " +
                                  $"CommandLine: {proc.CommandLine}",
                    Reasoning   = "AD attack tools (BloodHound, AdFind, Rubeus) are used to enumerate domain " +
                                  "trusts, attack Kerberos, and identify lateral movement paths (T1087, T1558). " +
                                  "These tools are key components of domain compromise campaigns.",
                    Confidence  = 0.90,
                    Tier        = Tier,
                    ProcessName = proc.ProcessName,
                    ProcessId   = proc.ProcessId,
                    Timestamp   = proc.Timestamp,
                    Metadata    = new()
                    {
                        ["ToolCategory"] = "ADAttack",
                        ["ToolName"]     = adTool,
                        ["CommandLine"]  = proc.CommandLine,
                        ["ImagePath"]    = proc.ImagePath
                    }
                };
            }
        }

        // 5. LOLBin abuse patterns
        foreach (var (lolbin, patterns) in LolbinAbusePatterns)
        {
            if (nameLower == lolbin.ToLowerInvariant() ||
                imgLower.EndsWith(lolbin.ToLowerInvariant()))
            {
                foreach (var pattern in patterns)
                {
                    if (cmdLower.Contains(pattern.ToLowerInvariant()))
                    {
                        return new DetectionEvent
                        {
                            RuleName    = Name,
                            Evidence    = $"LOLBin abuse detected: '{lolbin}' with pattern '{pattern}'. " +
                                          $"Process '{proc.ProcessName}' (PID {proc.ProcessId}). " +
                                          $"CommandLine: {proc.CommandLine}",
                            Reasoning   = $"Signed Windows binaries can be abused to download and execute " +
                                          "arbitrary code, bypassing AV and application whitelisting (T1218). " +
                                          "This pattern is heavily used by APTs and commodity malware.",
                            Confidence  = 0.88,
                            Tier        = Tier,
                            ProcessName = proc.ProcessName,
                            ProcessId   = proc.ProcessId,
                            Timestamp   = proc.Timestamp,
                            Metadata    = new()
                            {
                                ["ToolCategory"] = "LOLBin",
                                ["LOLBin"]       = lolbin,
                                ["AbusePattern"] = pattern,
                                ["CommandLine"]  = proc.CommandLine
                            }
                        };
                    }
                }
            }
        }

        // 6. Attack tool command-line patterns
        foreach (var attackPattern in AttackToolPatterns)
        {
            if (cmdLower.Contains(attackPattern.ToLowerInvariant()))
            {
                // Skip if it's just a documentation/help context
                if (cmdLower.Contains("get-help") || cmdLower.Contains("-?") || cmdLower.Contains("/?"))
                {
                    continue;
                }

                return new DetectionEvent
                {
                    RuleName    = Name,
                    Evidence    = $"Attack tool pattern '{attackPattern}' detected in command line. " +
                                  $"Process '{proc.ProcessName}' (PID {proc.ProcessId}). " +
                                  $"CommandLine: {proc.CommandLine}",
                    Reasoning   = "PowerShell scripts and command-line tools with these names are known " +
                                  "attack tools used for credential theft, lateral movement, and persistence " +
                                  "(T1059.001). Detection of these patterns indicates active exploitation.",
                    Confidence  = 0.85,
                    Tier        = Tier,
                    ProcessName = proc.ProcessName,
                    ProcessId   = proc.ProcessId,
                    Timestamp   = proc.Timestamp,
                    Metadata    = new()
                    {
                        ["ToolCategory"] = "CommandLinePattern",
                        ["AttackPattern"] = attackPattern,
                        ["CommandLine"]  = proc.CommandLine
                    }
                };
            }
        }

        return null;
    }
}

