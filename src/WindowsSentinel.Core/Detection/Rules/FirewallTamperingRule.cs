using System;
using System.Linq;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Detects attempts to tamper with the Windows Firewall or network routing.
/// Resilient to executable renaming by focusing on specific, unique argument signatures.
/// </summary>
public sealed class FirewallTamperingRule : IDetectionRule
{
    public string Name => "Firewall & Network Tampering";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;

        string cmd = (proc.CommandLine ?? "").ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(cmd)) return null;

        // Pattern 1: Disable Windows Firewall globally
        // netsh advfirewall set allprofiles state off
        bool isAdvFirewallDisable = cmd.Contains("advfirewall") && cmd.Contains("set") && cmd.Contains("allprofiles") && cmd.Contains("state") && cmd.Contains("off");
        
        // Pattern 2: Disable via netsh firewall (legacy)
        // netsh firewall set opmode disable
        bool isLegacyFirewallDisable = cmd.Contains("firewall") && cmd.Contains("set") && cmd.Contains("opmode") && cmd.Contains("disable");

        // Pattern 3: Disable via PowerShell
        // Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
        bool isPsFirewallDisable = cmd.Contains("set-netfirewallprofile") && cmd.Contains("enabled") && (cmd.Contains("false") || cmd.Contains("0"));

        // Pattern 4: Adding suspicious routes
        // route add 0.0.0.0 mask 0.0.0.0 (could be legitimate, but paired with specific processes it's anomalous)
        // Attackers often use `route add` to pivot. We'll flag it if we see `route` and `add` and `mask`.
        bool isRouteAdd = cmd.Contains("route") && cmd.Contains("add") && cmd.Contains("mask");

        if (isAdvFirewallDisable || isLegacyFirewallDisable || isPsFirewallDisable || isRouteAdd)
        {
            string technique = isRouteAdd ? "T1016 - System Network Configuration Discovery/Tampering" : "T1562.004 - Impair Defenses: Disable or Modify System Firewall";
            string logic = isRouteAdd ? "adding manual routes" : "disabling the host firewall";
            
            return new DetectionEvent
            {
                RuleName = Name,
                Evidence = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) executed network tampering command: {cmd}",
                Reasoning = $"Command-line arguments strongly indicate an attempt to {logic}. " +
                            "Attackers often disable firewalls to allow lateral movement, C2 communication, or exfiltration.",
                Confidence = 0.95,
                Tier = Tier,
                ProcessName = proc.ProcessName,
                ProcessId = proc.ProcessId,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new()
                {
                    ["technique"] = technique,
                    ["command_line"] = cmd
                }
            };
        }

        return null;
    }
}

