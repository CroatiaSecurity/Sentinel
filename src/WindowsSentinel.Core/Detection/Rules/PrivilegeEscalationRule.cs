using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Detects privilege escalation techniques.
///
/// Detection vectors:
///   1. UAC bypass via COM auto-elevation hijacking.
///   2. DLL hijacking in privileged directories.
///   3. Token manipulation / impersonation patterns.
///   4. Named pipe impersonation (printspoofer-style).
///   5. Potato-family exploitation patterns.
/// </summary>
public sealed class PrivilegeEscalationRule : IDetectionRule
{
    public string Name => "Privilege Escalation Attempt";
    public DetectionTier Tier => DetectionTier.Tier2Indicator; // Demoted: UAC/token patterns fire on many legitimate admin tools; use as corroborating signal

    // UAC bypass indicators
    private static readonly string[] UacBypassPatterns =
    {
        // ICMLuaUtil COM object abuse
        "ICMLuaUtil", "E43B3E72-E709-4BB3-8AD0-25FCD3C984F6",
        // CMSTP bypass
        "cmstp.exe /s", "cmstp /s /ns",
        // DiskCleanup hijack
        "DiskCleanup",
        // SilentCleanup task abuse
        "SilentCleanup",
        // System32 binary hijacking from non-standard locations
        "fodhelper", "eventvwr", "sdclt",
        // Registry key manipulation for UAC bypass
        "HKCU\\Software\\Classes\\mscfile",
        "HKCU\\Software\\Classes\\Folder",
        "HKCU\\Software\\Classes\\Drive",
        "CurrentVersion\\App Paths",
    };

    // Token manipulation / impersonation patterns
    private static readonly string[] TokenManipulationPatterns =
    {
        "ImpersonateLoggedOnUser",
        "SetThreadToken",
        "AdjustTokenPrivileges",
        "SeDebugPrivilege", "SeAssignPrimaryTokenPrivilege",
        "SeImpersonatePrivilege", "SeTcbPrivilege",
        "LookupPrivilegeValue",
        "CreateProcessWithToken",
        "CreateProcessWithLogon",
        "RunAs",
        "invoke-runascredentialsoption",
    };

    // Named pipe impersonation (PrintSpoofer, BadPotato, etc.)
    private static readonly string[] NamedPipeImpersonationPatterns =
    {
        "\\\\.\\pipe\\",
        "CreateNamedPipe",
        "ConnectNamedPipe",
        "ImpersonateNamedPipeClient",
        "printspoofer", "badpotato", "godpotato", "sweetpotato",
        "juicypotato", "roguepotato", "efspotato",
        "SeImpersonatePrivilege",
    };

    // DLL hijacking indicators
    private static readonly string[] DllHijackingPatterns =
    {
        "version.dll", "propsys.dll", "ntlanman.dll",
        "twain_32.dll", "spoolss.dll", "cryptsp.dll",
        "userenv.dll", "wlanapi.dll", "samlib.dll",
        "wlbsctrl.dll", "wow64log.dll", "userinit.dll",
        // Known DLL search order hijacking targets
        "\\Program Files\\Windows Defender\\MpCmdRun",
        "\\System32\\",
        "\\SysWOW64\\",
    };

    // Potato-family tool names
    private static readonly HashSet<string> PotatoTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "juicypotato", "juicypotatoexe", "roguepotato",
        "godpotato", "badpotato", "sweetpotato", "efspotato",
        "printspoofer", "potato",
    };

    // Legitimate privilege escalation paths
    private static readonly HashSet<string> LegitimateElevationPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "\\windows\\system32\\",
        "\\windows\\syswow64\\",
        "\\program files\\",
        "\\program files (x86)\\",
    };

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;
        if (proc.EventType != "ProcessStart") return null;

        var cmdLower = proc.CommandLine.ToLowerInvariant();
        var nameLower = proc.ProcessName.ToLowerInvariant();
        var imgLower = proc.ImagePath.ToLowerInvariant();
        var nameStem = Path.GetFileNameWithoutExtension(proc.ProcessName);

        // Check for potato-family tools by name
        if (PotatoTools.Contains(nameStem) || PotatoTools.Contains(proc.ProcessName))
        {
            return new DetectionEvent
            {
                RuleName    = Name,
                Evidence    = $"Known privilege escalation tool '{proc.ProcessName}' (PID {proc.ProcessId}) executed. " +
                              $"CommandLine: {proc.CommandLine}",
                Reasoning   = "Potato-family tools (JuicyPotato, RoguePotato, GodPotato, PrintSpoofer) exploit " +
                              "SeImpersonatePrivilege to escalate from SERVICE to SYSTEM. These are standard " +
                              "post-exploitation tools for local privilege escalation (T1134.001).",
                Confidence  = 0.95,
                Tier        = Tier,
                ProcessName = proc.ProcessName,
                ProcessId   = proc.ProcessId,
                Timestamp   = proc.Timestamp,
                Metadata    = new()
                {
                    ["EscalationType"] = "PotatoExploit",
                    ["CommandLine"]    = proc.CommandLine
                }
            };
        }

        // 1. UAC bypass patterns
        foreach (var bypassPattern in UacBypassPatterns)
        {
            if (cmdLower.Contains(bypassPattern.ToLowerInvariant()))
            {
                // Check if running from legitimate path
                var isLegitPath = LegitimateElevationPaths.Any(p => imgLower.Contains(p.ToLowerInvariant()));

                if (!isLegitPath || cmdLower.Contains("HKCU"))
                {
                    return new DetectionEvent
                    {
                        RuleName    = Name,
                        Evidence    = $"UAC bypass pattern '{bypassPattern}' detected in " +
                                      $"process '{proc.ProcessName}' (PID {proc.ProcessId}). " +
                                      $"CommandLine: {proc.CommandLine}",
                        Reasoning   = "UAC bypass techniques allow attackers to execute code with elevated " +
                                      "privileges without prompting the user. Common methods include COM object " +
                                      "hijacking, registry manipulation, and trusted binary abuse (T1548.002). " +
                                      "These patterns indicate an attempt to bypass security controls.",
                        Confidence  = 0.88,
                        Tier        = Tier,
                        ProcessName = proc.ProcessName,
                        ProcessId   = proc.ProcessId,
                        Timestamp   = proc.Timestamp,
                        Metadata    = new()
                        {
                            ["EscalationType"] = "UACBypass",
                            ["BypassPattern"]  = bypassPattern,
                            ["CommandLine"]    = proc.CommandLine
                        }
                    };
                }
            }
        }

        // 2. Token manipulation patterns
        foreach (var tokenPattern in TokenManipulationPatterns)
        {
            if (cmdLower.Contains(tokenPattern.ToLowerInvariant()))
            {
                // Skip legitimate tools
                if (imgLower.Contains("\\windows\\system32\\") ||
                    imgLower.Contains("\\windows\\syswow64\\"))
                {
                    continue;
                }

                return new DetectionEvent
                {
                    RuleName    = Name,
                    Evidence    = $"Token manipulation pattern '{tokenPattern}' detected in " +
                                  $"process '{proc.ProcessName}' (PID {proc.ProcessId}). " +
                                  $"CommandLine: {proc.CommandLine}",
                    Reasoning   = "Token manipulation allows attackers to impersonate other users or escalate " +
                                  "privileges by manipulating Windows access tokens (T1134). " +
                                  "SeDebugPrivilege, SeImpersonatePrivilege, and SeTcbPrivilege are high-value " +
                                  "privileges that enable SYSTEM-level access.",
                    Confidence  = 0.82,
                    Tier        = Tier,
                    ProcessName = proc.ProcessName,
                    ProcessId   = proc.ProcessId,
                    Timestamp   = proc.Timestamp,
                    Metadata    = new()
                    {
                        ["EscalationType"] = "TokenManipulation",
                        ["TokenPattern"]   = tokenPattern,
                        ["CommandLine"]    = proc.CommandLine
                    }
                };
            }
        }

        // 3. Named pipe impersonation
        foreach (var pipePattern in NamedPipeImpersonationPatterns)
        {
            if (cmdLower.Contains(pipePattern.ToLowerInvariant()))
            {
                // Legitimate pipe usage from Windows directory
                if (pipePattern == "\\\\.\\pipe\\" &&
                    (imgLower.Contains("\\windows\\") || nameLower == "powershell" || nameLower == "pwsh"))
                {
                    continue; // PowerShell legitimately uses named pipes for remoting
                }

                return new DetectionEvent
                {
                    RuleName    = Name,
                    Evidence    = $"Named pipe impersonation pattern '{pipePattern}' detected in " +
                                  $"process '{proc.ProcessName}' (PID {proc.ProcessId}). " +
                                  $"CommandLine: {proc.CommandLine}",
                    Reasoning   = "Named pipe impersonation is a privilege escalation technique where an attacker " +
                                  "creates a named pipe and tricks a privileged process into connecting to it, " +
                                  "then impersonates that client's security context (T1055.003). " +
                                  "PrintSpoofer and Potato tools use this to gain SYSTEM privileges.",
                    Confidence  = 0.85,
                    Tier        = Tier,
                    ProcessName = proc.ProcessName,
                    ProcessId   = proc.ProcessId,
                    Timestamp   = proc.Timestamp,
                    Metadata    = new()
                    {
                        ["EscalationType"] = "NamedPipeImpersonation",
                        ["PipePattern"]    = pipePattern,
                        ["CommandLine"]    = proc.CommandLine
                    }
                };
            }
        }

        // 4. DLL hijacking indicators
        var isSuspiciousPath = imgLower.Contains("\\temp\\") ||
                               imgLower.Contains("\\appdata\\") ||
                               imgLower.Contains("\\downloads\\") ||
                               imgLower.Contains("\\public\\");

        if (isSuspiciousPath)
        {
            foreach (var dllPattern in DllHijackingPatterns)
            {
                if (cmdLower.Contains(dllPattern.ToLowerInvariant()))
                {
                    return new DetectionEvent
                    {
                        RuleName    = Name,
                        Evidence    = $"Potential DLL hijacking: process '{proc.ProcessName}' (PID {proc.ProcessId}) " +
                                      $"running from suspicious path '{proc.ImagePath}' " +
                                      $"with DLL reference '{dllPattern}'. " +
                                      $"CommandLine: {proc.CommandLine}",
                        Reasoning   = "DLL hijacking occurs when an attacker places a malicious DLL in a location " +
                                      "where it will be loaded before the legitimate one (T1574.001). " +
                                      "Executables in user-writable directories referencing common hijacking targets " +
                                      "are strong indicators of this technique.",
                        Confidence  = 0.80,
                        Tier        = Tier,
                        ProcessName = proc.ProcessName,
                        ProcessId   = proc.ProcessId,
                        Timestamp   = proc.Timestamp,
                        Metadata    = new()
                        {
                            ["EscalationType"] = "DllHijacking",
                            ["TargetDll"]      = dllPattern,
                            ["ImagePath"]      = proc.ImagePath,
                            ["CommandLine"]    = proc.CommandLine
                        }
                    };
                }
            }
        }

        return null;
    }
}
