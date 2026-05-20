using System;
using System.Linq;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Detects local account creation and modification indicative of persistence or lateral movement.
/// Resilient to executable renaming by focusing on specific argument combinations.
/// </summary>
public sealed class AccountManipulationRule : IDetectionRule
{
    public string Name => "Local Account Manipulation";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;

        string cmd = (proc.CommandLine ?? "").ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(cmd)) return null;

        // Pattern 1: net user /add
        // Covers: net user backdoor Password123! /add
        bool isNetUserAdd = cmd.Contains("user") && cmd.Contains("/add");

        // Pattern 2: net localgroup administrators /add
        // Covers: net localgroup administrators backdoor /add
        bool isLocalGroupAdd = cmd.Contains("localgroup") && cmd.Contains("/add");

        // Pattern 3: PowerShell New-LocalUser
        bool isPsLocalUser = cmd.Contains("new-localuser") || cmd.Contains("add-localgroupmember");

        if (isNetUserAdd || isLocalGroupAdd || isPsLocalUser)
        {
            return new DetectionEvent
            {
                RuleName = Name,
                Evidence = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) manipulated local accounts: {cmd}",
                Reasoning = "Command-line arguments indicate the creation of a local user or modification of a local group. " +
                            "Attackers use this to establish persistence or escalate privileges on compromised hosts.",
                Confidence = 0.85,
                Tier = Tier,
                ProcessName = proc.ProcessName,
                ProcessId = proc.ProcessId,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new()
                {
                    ["technique"] = "T1136.001 - Create Account: Local Account",
                    ["command_line"] = cmd
                }
            };
        }

        return null;
    }
}

