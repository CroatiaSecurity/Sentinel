using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Detects ETW tampering and security tool evasion attempts.
///
/// Detection vectors:
///   1. Known ETW-patching tool names.
///   2. ETW provider disable / patch patterns in command lines.
///   3. AMSI bypass patterns (AMSI is the primary AV integration point for scripts).
///   4. Event log clearing / tampering (wevtutil cl, Clear-EventLog).
///   5. Security tool termination (taskkill targeting AV/EDR processes).
///   6. Windows Defender disable commands.
/// </summary>
public sealed class EtwTamperingRule : IDetectionRule
{
    public string Name => "Security Evasion / ETW-AMSI Tampering";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    // Known ETW-patching / evasion tool names.
    private static readonly HashSet<string> EvasionToolNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "SilkETW", "ETWHash", "ETWpatcher",
        "AMSITrigger", "AmsiBypass",
        "Invoke-AmsiBypass", "Invoke-Obfuscation",
        "Invoke-CradleCrafter",
        "SharpBlock",       // blocks ETW / AMSI in .NET
        "Ghostpack",
        "ConfuserEx",       // .NET obfuscator used to evade AMSI
        "phollow",
        "unhook",
        "amsi.fail"
    };

    // ETW patching / disabling patterns.
    private static readonly string[] EtwPatterns =
    {
        "EtwEventWrite",
        "EtwpCreateEtwThread",
        "NtTraceControl",
        "patch etw", "disable etw", "etw bypass", "etw patch",
        "ProviderGuid",
        "EtwRegister",
        "EtwUnregister",
        // Disabling ETW via registry
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger"
    };

    // AMSI bypass patterns — used to disable script scanning before running malicious PS.
    private static readonly string[] AmsiPatterns =
    {
        "amsiInitFailed",
        "AmsiScanBuffer",
        "amsi.dll",
        "[Ref].Assembly.GetType",
        "System.Management.Automation.AmsiUtils",
        "amsiContext",
        "amsiSession",
        "Bypass-AMSI",
        "Disable-Amsi",
        "Invoke-AmsiBypass",
        "Set-MpPreference -DisableRealtimeMonitoring",
        "Set-MpPreference -DisableIOAVProtection",
        "Set-MpPreference -DisableScriptScanning",
        "Add-MpPreference -ExclusionPath",
    };

    // Event log clearing — attackers clear logs to destroy forensic evidence.
    private static readonly (string Process, string Pattern)[] LogClearPatterns =
    {
        ("wevtutil.exe",    "cl "),
        ("wevtutil.exe",    "clear-log"),
        ("powershell.exe",  "Clear-EventLog"),
        ("powershell.exe",  "Remove-EventLog"),
        ("powershell.exe",  "wevtutil"),
        ("cmd.exe",         "wevtutil cl"),
    };

    // Security tool termination — taskkill targeting AV/EDR processes.
    private static readonly string[] SecurityProcessNames =
    {
        // Windows Defender
        "MsMpEng", "MpCmdRun", "NisSrv",
        // Common AV/EDR vendors
        "bdagent", "bdredline",         // Bitdefender
        "ekrn", "egui",                 // ESET
        "avp", "avpui",                 // Kaspersky
        "mbam", "mbamservice",          // Malwarebytes
        "SentinelAgent", "SentinelOne",
        "CrowdStrike", "CSFalcon",
        "CylanceSvc",
        "cb.exe", "cbdefense",          // Carbon Black
        "xagt",                         // FireEye/Trellix
        "cyserver", "cyoptics",         // Cybereason
        "elastic-agent",
        "wdfilter",
        "MsSense", "senseir",           // Microsoft Defender for Endpoint
        "sysmon",                       // Sysinternals Sysmon
        "splunkd", "splunk-optimize"    // Splunk
    };

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;

        var cmdLower  = proc.CommandLine.ToLowerInvariant();
        var nameLower = proc.ProcessName.ToLowerInvariant();
        var nameStem  = Path.GetFileNameWithoutExtension(proc.ProcessName);

        // 1. Known evasion tool by name
        if (EvasionToolNames.Contains(nameStem) || EvasionToolNames.Contains(proc.ProcessName))
        {
            return MakeEvent(proc,
                $"Known evasion tool '{proc.ProcessName}' (PID {proc.ProcessId}) executed. " +
                $"CommandLine: {proc.CommandLine}",
                "This binary is a known ETW/AMSI evasion or obfuscation tool.",
                0.95, proc.ProcessName);
        }

        // 2. ETW patching patterns
        var etwMatch = EtwPatterns.FirstOrDefault(p =>
            proc.CommandLine.Contains(p, StringComparison.OrdinalIgnoreCase) ||
            proc.ImagePath.Contains(p, StringComparison.OrdinalIgnoreCase));
        if (etwMatch is not null)
        {
            return MakeEvent(proc,
                $"ETW tampering pattern '{etwMatch}' in '{proc.ProcessName}' (PID {proc.ProcessId}). " +
                $"CommandLine: {proc.CommandLine}",
                "Patching EtwEventWrite or disabling ETW providers blinds security monitoring tools. " +
                "This is a standard pre-exploitation step in advanced attacks.",
                0.90, etwMatch);
        }

        // 3. AMSI bypass patterns
        var amsiMatch = AmsiPatterns.FirstOrDefault(p =>
            proc.CommandLine.Contains(p, StringComparison.OrdinalIgnoreCase));
        if (amsiMatch is not null)
        {
            return MakeEvent(proc,
                $"AMSI bypass pattern '{amsiMatch}' in '{proc.ProcessName}' (PID {proc.ProcessId}). " +
                $"CommandLine: {proc.CommandLine}",
                "AMSI (Antimalware Scan Interface) bypass is used to disable script-level AV scanning " +
                "before executing malicious PowerShell, VBScript, or JScript payloads. " +
                "This is a near-universal step in modern fileless attacks.",
                0.93, amsiMatch);
        }

        // 4. Event log clearing
        foreach (var (logProcess, logPattern) in LogClearPatterns)
        {
            if ((nameLower == logProcess.ToLowerInvariant() ||
                 proc.ImagePath.EndsWith(logProcess, StringComparison.OrdinalIgnoreCase)) &&
                cmdLower.Contains(logPattern.ToLowerInvariant()))
            {
                return MakeEvent(proc,
                    $"Event log cleared by '{proc.ProcessName}' (PID {proc.ProcessId}) " +
                    $"with pattern '{logPattern}'. CommandLine: {proc.CommandLine}",
                    "Clearing Windows event logs destroys forensic evidence and is a standard " +
                    "post-exploitation step. Legitimate administrators rarely clear all logs.",
                    0.85, logPattern);
            }
        }

        // 5. Security tool termination
        var secKill = SecurityProcessNames.FirstOrDefault(s =>
            cmdLower.Contains(s.ToLowerInvariant()) &&
            (nameLower == "taskkill.exe" || nameLower == "net.exe" || nameLower == "net1.exe" ||
             nameLower == "sc.exe" || nameLower == "powershell.exe" || nameLower == "pwsh.exe"));
        if (secKill is not null)
        {
            return MakeEvent(proc,
                $"Security tool termination: '{proc.ProcessName}' (PID {proc.ProcessId}) " +
                $"targeting '{secKill}'. CommandLine: {proc.CommandLine}",
                "Killing or disabling AV/EDR processes is a standard pre-ransomware and APT step. " +
                "Legitimate software does not terminate security products.",
                0.92, secKill);
        }

        return null;
    }

    private static DetectionEvent MakeEvent(
        ProcessTelemetry proc, string evidence, string reasoning,
        double confidence, string matchedToken)
    {
        return new DetectionEvent
        {
            RuleName    = "Security Evasion / ETW-AMSI Tampering",
            Evidence    = evidence,
            Reasoning   = reasoning,
            Confidence  = confidence,
            Tier        = DetectionTier.Tier1Behavioral,
            ProcessName = proc.ProcessName,
            ProcessId   = proc.ProcessId,
            Timestamp   = proc.Timestamp,
            Metadata    = new()
            {
                ["CommandLine"]  = proc.CommandLine,
                ["ImagePath"]    = proc.ImagePath,
                ["MatchedToken"] = matchedToken,
                ["ParentPid"]    = proc.ParentProcessId.ToString()
            }
        };
    }
}

