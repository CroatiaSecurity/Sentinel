using System;
using System.Linq;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Detects command-line execution of popular exfiltration tools like rclone and azcopy.
/// Resilient to executable renaming by focusing on specific argument combinations.
/// </summary>
public sealed class DataExfiltrationRule : IDetectionRule
{
    public string Name => "Known Data Exfiltration Tool Execution";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;

        string cmd = (proc.CommandLine ?? "").ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(cmd)) return null;

        // Pattern 1: Rclone
        // Attackers use rclone to sync data to Mega, Dropbox, or custom WebDAV.
        // e.g. rclone copy C:\Users\ remote:backup --transfers 10
        bool isRclone = cmd.Contains("copy") && cmd.Contains("--transfers") && (cmd.Contains("remote:") || cmd.Contains("mega:") || proc.ProcessName.Contains("rclone"));

        // Pattern 2: AzCopy
        // e.g. azcopy copy "C:\Data" "https://..." --recursive
        bool isAzCopy = cmd.Contains("copy") && cmd.Contains("--recursive") && (cmd.Contains("http") || proc.ProcessName.Contains("azcopy"));

        if (isRclone || isAzCopy)
        {
            return new DetectionEvent
            {
                RuleName = Name,
                Evidence = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) executed known exfiltration tool signature: {cmd}",
                Reasoning = "Command-line arguments indicate the use of a data synchronization/exfiltration tool " +
                            "(like rclone or azcopy) configured for bulk transfer. This is commonly used by threat actors " +
                            "prior to ransomware deployment to steal data for double-extortion.",
                Confidence = 0.90,
                Tier = Tier,
                ProcessName = proc.ProcessName,
                ProcessId = proc.ProcessId,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new()
                {
                    ["technique"] = "T1567 - Exfiltration Over Web Service",
                    ["command_line"] = cmd
                }
            };
        }

        return null;
    }
}

