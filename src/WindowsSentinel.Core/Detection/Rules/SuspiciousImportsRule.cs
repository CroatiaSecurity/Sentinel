using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier2 — Detects processes referencing suspicious Win32 API names in their
/// command-line arguments.
///
/// Note: This rule catches explicit tool invocations that pass API names as
/// arguments (e.g. custom loaders, pentest frameworks, script-based injectors).
/// It is intentionally Tier2 because legitimate debugging tools also use these APIs.
/// Pair with UnsignedBinaryRule and HighEntropyRule for higher-confidence correlation.
///
/// Extended to also detect:
///   - Reconnaissance commands (whoami, net user, ipconfig, systeminfo, etc.)
///   - Lateral movement preparation (net use, wmic /node, psexec, etc.)
///   - Persistence mechanism patterns (reg add Run, schtasks /create, etc.)
/// </summary>
public sealed class SuspiciousImportsRule : IDetectionRule
{
    public string Name => "Suspicious API / Recon Pattern";
    public DetectionTier Tier => DetectionTier.Tier2Indicator;

    private static readonly string[] SuspiciousApis =
    {
        // Memory manipulation
        "VirtualAlloc", "VirtualProtect", "VirtualAllocEx",
        "WriteProcessMemory", "ReadProcessMemory",
        // Code execution
        "LoadLibrary", "GetProcAddress",
        "CreateThread", "CreateRemoteThread",
        "NtCreateThreadEx", "RtlCreateUserThread",
        // Process access
        "OpenProcess", "NtOpenProcess",
        // Anti-analysis
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "ZwQueryInformationProcess",
        // Persistence
        "RegOpenKey", "RegSetValue", "CreateService", "StartService",
    };

    // Reconnaissance patterns — commonly run in sequence after initial access.
    private static readonly (string Process, string Pattern, string Description)[] ReconPatterns =
    {
        ("whoami.exe",      "/all",         "Full user/group/privilege enumeration"),
        ("whoami.exe",      "/priv",        "Privilege enumeration"),
        ("net.exe",         "user /domain", "Domain user enumeration"),
        ("net.exe",         "group /domain","Domain group enumeration"),
        ("net.exe",         "localgroup",   "Local group enumeration"),
        ("net1.exe",        "user /domain", "Domain user enumeration"),
        ("ipconfig.exe",    "/all",         "Full network configuration dump"),
        ("systeminfo.exe",  "",             "System information dump"),
        ("nltest.exe",      "/domain_trusts","Domain trust enumeration"),
        ("nltest.exe",      "/dclist",      "Domain controller enumeration"),
        ("arp.exe",         "-a",           "ARP table dump (network discovery)"),
        ("route.exe",       "print",        "Routing table dump"),
        ("netstat.exe",     "-ano",         "Active connection enumeration"),
        ("tasklist.exe",    "/svc",         "Service-to-process mapping"),
        ("reg.exe",         "query",        "Registry enumeration"),
        ("wmic.exe",        "process",      "Process enumeration via WMI"),
        ("wmic.exe",        "product",      "Installed software enumeration"),
        ("wmic.exe",        "useraccount",  "User account enumeration"),
        ("wmic.exe",        "group",        "Group enumeration"),
        ("wmic.exe",        "logicaldisk",  "Disk enumeration"),
        ("cmdkey.exe",      "/list",        "Stored credential enumeration"),
        ("qwinsta.exe",     "",             "RDP session enumeration"),
        ("quser.exe",       "",             "Logged-on user enumeration"),
    };

    // Persistence mechanism patterns.
    private static readonly (string Process, string Pattern)[] PersistencePatterns =
    {
        ("reg.exe",       @"add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("reg.exe",       @"add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("reg.exe",       @"add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        ("schtasks.exe",  "/create"),
        ("sc.exe",        "create"),
        ("sc.exe",        "config"),
        ("powershell.exe","New-ScheduledTask"),
        ("powershell.exe","Register-ScheduledTask"),
        ("powershell.exe","New-Service"),
        ("wmic.exe",      "process call create"),
    };

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;

        var cmdLower  = proc.CommandLine.ToLowerInvariant();
        var nameLower = proc.ProcessName.ToLowerInvariant();

        // 1. Suspicious API names in command line
        var apiMatches = SuspiciousApis
            .Where(api => proc.CommandLine.Contains(api, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (apiMatches.Count > 0)
        {
            return new DetectionEvent
            {
                RuleName    = Name,
                Evidence    = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) references " +
                              $"suspicious APIs: {string.Join(", ", apiMatches)}",
                Reasoning   = "These Win32 APIs are frequently used in shellcode loaders, injectors, and " +
                              "anti-analysis techniques. Their presence in command-line arguments is unusual " +
                              "for legitimate software.",
                Confidence  = Math.Min(0.30 + apiMatches.Count * 0.08, 0.65),
                Tier        = Tier,
                ProcessName = proc.ProcessName,
                ProcessId   = proc.ProcessId,
                Timestamp   = proc.Timestamp,
                Metadata    = new()
                {
                    ["MatchedApis"] = string.Join(", ", apiMatches),
                    ["CommandLine"] = proc.CommandLine
                }
            };
        }

        // 2. Reconnaissance patterns
        foreach (var (reconProcess, reconPattern, reconDesc) in ReconPatterns)
        {
            if ((nameLower == reconProcess.ToLowerInvariant() ||
                 proc.ImagePath.EndsWith(reconProcess, StringComparison.OrdinalIgnoreCase)) &&
                (reconPattern.Length == 0 || cmdLower.Contains(reconPattern.ToLowerInvariant())))
            {
                return new DetectionEvent
                {
                    RuleName    = Name,
                    Evidence    = $"Reconnaissance: '{proc.ProcessName}' (PID {proc.ProcessId}) — {reconDesc}. " +
                                  $"CommandLine: {proc.CommandLine}",
                    Reasoning   = "This command is commonly run during the discovery phase of an attack " +
                                  "(MITRE ATT&CK T1082, T1016, T1033, T1069, T1087). A single instance may " +
                                  "be legitimate; multiple in sequence is a strong indicator of post-exploitation.",
                    Confidence  = 0.40,
                    Tier        = Tier,
                    ProcessName = proc.ProcessName,
                    ProcessId   = proc.ProcessId,
                    Timestamp   = proc.Timestamp,
                    Metadata    = new()
                    {
                        ["CommandLine"] = proc.CommandLine,
                        ["ReconType"]   = reconDesc
                    }
                };
            }
        }

        // 3. Persistence patterns
        foreach (var (persProcess, persPattern) in PersistencePatterns)
        {
            if ((nameLower == persProcess.ToLowerInvariant() ||
                 proc.ImagePath.EndsWith(persProcess, StringComparison.OrdinalIgnoreCase)) &&
                cmdLower.Contains(persPattern.ToLowerInvariant()))
            {
                return new DetectionEvent
                {
                    RuleName    = Name,
                    Evidence    = $"Persistence mechanism: '{proc.ProcessName}' (PID {proc.ProcessId}) " +
                                  $"with pattern '{persPattern}'. CommandLine: {proc.CommandLine}",
                    Reasoning   = "Registry Run keys, scheduled tasks, and services are the most common " +
                                  "persistence mechanisms used by malware (MITRE ATT&CK T1053, T1543, T1547). " +
                                  "This is an indicator — investigate the parent process and payload.",
                    Confidence  = 0.55,
                    Tier        = Tier,
                    ProcessName = proc.ProcessName,
                    ProcessId   = proc.ProcessId,
                    Timestamp   = proc.Timestamp,
                    Metadata    = new()
                    {
                        ["CommandLine"]    = proc.CommandLine,
                        ["MatchedPattern"] = persPattern
                    }
                };
            }
        }

        return null;
    }
}
