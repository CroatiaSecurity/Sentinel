using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Security tool evasion and tampering detection.
/// Detects AMSI bypass, ETW patching, event log clearing, and AV/EDR process termination.
/// </summary>
public sealed class EtwTamperingRule : IDetectionRule
{
    public string Name => "AMSI/ETW Tampering Detected";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;
        if (proc.EventType != "ProcessStart") return null;

        string cmd = proc.CommandLine ?? "";

        // 1. ETW Patching Indicators
        if (cmd.Contains("etw bypass", StringComparison.OrdinalIgnoreCase) ||
            cmd.Contains("EtwEventWrite", StringComparison.OrdinalIgnoreCase) ||
            cmd.Contains("NtTraceEvent", StringComparison.OrdinalIgnoreCase))
        {
            return new DetectionEvent
            {
                RuleName = "ETW Tampering Detected",
                Evidence = $"ETW patching indicator found in command line: '{cmd}'",
                Reasoning = "The process attempted to patch or bypass Event Tracing for Windows (ETW), which is a common defense evasion technique used to blind endpoint security tools.",
                Confidence = 0.95,
                Tier = Tier,
                ProcessName = proc.ProcessName,
                ProcessId = proc.ProcessId,
                Timestamp = proc.Timestamp,
                Metadata = new()
                {
                    ["CommandLine"] = cmd,
                    ["technique"] = "T1562.001 - Disable or Modify Tools"
                }
            };
        }

        // 2. AMSI Bypass Patterns
        if (cmd.Contains("AmsiUtils", StringComparison.OrdinalIgnoreCase) ||
            cmd.Contains("AmsiScanBuffer", StringComparison.OrdinalIgnoreCase) ||
            cmd.Contains("amsiInitFailed", StringComparison.OrdinalIgnoreCase))
        {
            return new DetectionEvent
            {
                RuleName = "AMSI Tampering Detected",
                Evidence = $"AMSI bypass pattern found in command line: '{cmd}'",
                Reasoning = "The process attempted to bypass the Antimalware Scan Interface (AMSI) to prevent script analysis and detection of memory-loaded payloads.",
                Confidence = 0.95,
                Tier = Tier,
                ProcessName = proc.ProcessName,
                ProcessId = proc.ProcessId,
                Timestamp = proc.Timestamp,
                Metadata = new()
                {
                    ["CommandLine"] = cmd,
                    ["technique"] = "T1562.001 - Disable or Modify Tools"
                }
            };
        }

        // 3. Defender / AV Disabling Attempts
        if (cmd.Contains("Set-MpPreference", StringComparison.OrdinalIgnoreCase) &&
            (cmd.Contains("-DisableRealtimeMonitoring", StringComparison.OrdinalIgnoreCase) ||
             cmd.Contains("-DisableIOAVProtection", StringComparison.OrdinalIgnoreCase)))
        {
            return new DetectionEvent
            {
                RuleName = "Security Tool Tampering Detected",
                Evidence = $"Windows Defender disable command found in command line: '{cmd}'",
                Reasoning = "The process attempted to disable Windows Defender real-time monitoring or I/O protection, indicating an active attempt to bypass security controls.",
                Confidence = 0.93,
                Tier = Tier,
                ProcessName = proc.ProcessName,
                ProcessId = proc.ProcessId,
                Timestamp = proc.Timestamp,
                Metadata = new()
                {
                    ["CommandLine"] = cmd,
                    ["technique"] = "T1562.001 - Disable or Modify Tools"
                }
            };
        }

        // 4. Event Log Clearing
        if (proc.ProcessName.Equals("wevtutil.exe", StringComparison.OrdinalIgnoreCase) &&
            cmd.Contains(" cl ", StringComparison.OrdinalIgnoreCase))
        {
            return new DetectionEvent
            {
                RuleName = "Event Log Cleared",
                Evidence = $"wevtutil command to clear log: '{cmd}'",
                Reasoning = "The wevtutil tool was used to clear event logs, which is a common anti-forensics technique used by attackers to hide their activity.",
                Confidence = 0.90,
                Tier = Tier,
                ProcessName = proc.ProcessName,
                ProcessId = proc.ProcessId,
                Timestamp = proc.Timestamp,
                Metadata = new()
                {
                    ["CommandLine"] = cmd,
                    ["technique"] = "T1070.001 - Indicator Removal on Host: Clear Windows Event Logs"
                }
            };
        }

        // 5. Security Tool Process Termination
        if (proc.ProcessName.Equals("taskkill.exe", StringComparison.OrdinalIgnoreCase) &&
            cmd.Contains("MsMpEng", StringComparison.OrdinalIgnoreCase))
        {
            return new DetectionEvent
            {
                RuleName = "Security Tool Tampering Detected",
                Evidence = $"Attempt to terminate Windows Defender service using taskkill: '{cmd}'",
                Reasoning = "The process attempted to kill the Windows Defender anti-malware service (MsMpEng.exe), indicating a direct attempt to disable endpoint protection.",
                Confidence = 0.95,
                Tier = Tier,
                ProcessName = proc.ProcessName,
                ProcessId = proc.ProcessId,
                Timestamp = proc.Timestamp,
                Metadata = new()
                {
                    ["CommandLine"] = cmd,
                    ["technique"] = "T1562.001 - Disable or Modify Tools"
                }
            };
        }

        return null;
    }
}
