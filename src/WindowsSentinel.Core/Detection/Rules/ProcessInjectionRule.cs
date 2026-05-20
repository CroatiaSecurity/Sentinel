using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Detects process injection and process hollowing techniques.
///
/// v1.1.0: Tightened to behavioral-only detection. Tool-name matching removed
/// because it's trivially bypassed by renaming the binary. Detection now relies on:
///
///   1. Injection API names in command-line arguments (behavioral intent signal).
///   2. Suspicious parent-child relationships (Office/browser spawning shells).
///   3. Kernel-observed injection (via EtwThreatIntelMonitor — separate, strongest signal).
///
/// The EtwThreatIntelMonitor provides the REAL injection detection (kernel-level API
/// observation). This rule catches the command-line-visible tooling that precedes or
/// accompanies injection. Together they provide layered coverage.
/// </summary>
public sealed class ProcessInjectionRule : IDetectionRule
{
    public string Name => "Process Injection / Hollowing";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    // v1.1.0: KnownInjectionTools list retained ONLY for threat intel correlation metadata.
    // It is NOT used for detection decisions — renaming bypasses it trivially.
    // Detection is purely behavioral (API patterns in cmdline + parent-child context).
    private static readonly HashSet<string> KnownInjectionTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "mavinject", "mavinject32", "mavinject64",
        "process_herpaderping", "herpaderping",
        "process_ghosting", "ghosting",
        "pe_inject", "pe-inject",
        "injector", "inject",
        "hollowshunter", "hollow",
        "reflective_loader", "reflectiveloader",
        "donut",
        "sRDI",
        "threadinjection",
        "sharpinject", "sharpinjection",
        "invoke-dllinjection",
        "invoke-reflectivepeinjection",
        "invoke-shellcode",
    };

    // API / technique names that appear in command lines of injection tooling.
    private static readonly string[] InjectionApiPatterns =
    {
        // Classic injection APIs
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "RtlCreateUserThread",
        "QueueUserAPC", "NtQueueApcThread",
        // Hollowing APIs
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        "NtCreateSection", "NtMapViewOfSection",
        // Reflective / module stomping
        "reflective", "ReflectiveDLL",
        "module stomp", "module_stomp",
        // Shellcode delivery
        "shellcode", "shellc0de",
        // Process doppelgänging
        "doppelganging", "doppelganger",
        // Atom bombing
        "GlobalAddAtom", "NtSetContextThread",
        // Extra-window memory injection
        "SetWindowLong", "SendMessage",
    };

    // Suspicious parent → child relationships — kept as reference data for future
    // live-process-table enrichment. Currently logged as metadata for SIEM correlation.
    // Key = parent process name, Value = child processes that should never be spawned by it.
    internal static readonly Dictionary<string, HashSet<string>> SuspiciousParentChild =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["winword.exe"]    = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe" },
            ["excel.exe"]      = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe" },
            ["powerpnt.exe"]   = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe" },
            ["outlook.exe"]    = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe" },
            ["onenote.exe"]    = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe" },
            ["acrord32.exe"]   = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe" },
            ["acrobat.exe"]    = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe" },
            ["msedge.exe"]     = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe" },
            ["iexplore.exe"]   = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe" },
            ["chrome.exe"]     = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe" },
            ["firefox.exe"]    = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe" },
            ["wmiprvse.exe"]   = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe" },
            ["msiexec.exe"]    = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe" },
            ["svchost.exe"]    = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe" },
        };

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;

        var nameStem  = Path.GetFileNameWithoutExtension(proc.ProcessName);

        // v1.1.0: Tool-name matching is metadata enrichment only, NOT a detection trigger.
        // Reason: Any attacker who reads this source code can rename their binary.
        bool isKnownToolName = KnownInjectionTools.Contains(nameStem) ||
                               KnownInjectionTools.Contains(proc.ProcessName);

        // 1. Injection API in command line (behavioral signal — can't be hidden if tool uses cmdline args)
        var apiMatch = InjectionApiPatterns.FirstOrDefault(p =>
            proc.CommandLine.Contains(p, StringComparison.OrdinalIgnoreCase));
        if (apiMatch is not null)
        {
            return new DetectionEvent
            {
                RuleName    = Name,
                Evidence    = $"Injection API '{apiMatch}' in command line of '{proc.ProcessName}' " +
                              $"(PID {proc.ProcessId}). CommandLine: {proc.CommandLine}",
                Reasoning   = "Process injection APIs in command-line arguments indicate a tool that " +
                              "explicitly targets another process's memory space for code execution, " +
                              "privilege escalation, or AV evasion.",
                Confidence  = isKnownToolName ? 0.92 : 0.78, // Boost if name also matches
                Tier        = Tier,
                ProcessName = proc.ProcessName,
                ProcessId   = proc.ProcessId,
                Timestamp   = proc.Timestamp,
                Metadata    = new()
                {
                    ["CommandLine"]  = proc.CommandLine,
                    ["MatchedApi"]   = apiMatch,
                    ["KnownTool"]    = isKnownToolName.ToString()
                }
            };
        }

        // 2. Suspicious parent → child relationship (corroborating signal — Tier2)
        if (!string.IsNullOrEmpty(proc.ParentProcessName))
        {
            if (SuspiciousParentChild.TryGetValue(proc.ParentProcessName, out var suspiciousChildren) &&
                suspiciousChildren.Contains(proc.ProcessName))
            {
                return new DetectionEvent
                {
                    RuleName    = Name,
                    Evidence    = $"Suspicious parent-child: '{proc.ParentProcessName}' (PID {proc.ParentProcessId}) " +
                                  $"spawned '{proc.ProcessName}' (PID {proc.ProcessId}). " +
                                  $"CommandLine: {proc.CommandLine}",
                    Reasoning   = $"'{proc.ParentProcessName}' should rarely spawn '{proc.ProcessName}'. " +
                                  "This pattern can indicate macro-based malware or LOLBin abuse, but also " +
                                  "fires on legitimate Windows Update, WMI jobs, and software installers. " +
                                  "Treat as a corroborating signal — investigate alongside other detections.",
                    Confidence  = 0.65,
                    Tier        = DetectionTier.Tier2Indicator, // Log-only; needs corroboration to act
                    ProcessName = proc.ProcessName,
                    ProcessId   = proc.ProcessId,
                    Timestamp   = proc.Timestamp,
                    Metadata    = new()
                    {
                        ["ParentProcess"]  = proc.ParentProcessName,
                        ["ParentPid"]      = proc.ParentProcessId.ToString(),
                        ["CommandLine"]    = proc.CommandLine
                    }
                };
            }
        }

        return null;
    }
}


