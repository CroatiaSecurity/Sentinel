using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Converts HollowProcessTelemetry into a DetectionEvent.
///
/// Fires when HollowProcessMonitor detects a mismatch between a process's
/// declared image path and the actual file mapped at its base address,
/// or when a process has no mapped file at its base address (shellcode).
///
/// Process hollowing (T1055.012) is used by:
///   - Cobalt Strike (default and custom profiles)
///   - Metasploit meterpreter
///   - Dridex, TrickBot, Emotet loaders
///   - Most sophisticated APT implants
/// </summary>
public sealed class HollowProcessRule : IDetectionRule
{
    public string Name => "Process Hollowing / Memory Mismatch";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not HollowProcessTelemetry hollow) return null;

        string reasoning = hollow.HollowType switch
        {
            "HOLLOWED" =>
                "The process's declared image path does not match the file actually mapped at its " +
                "base address in memory. This is the definitive indicator of process hollowing " +
                "(T1055.012): a legitimate process was started suspended, its memory was unmapped, " +
                "and malicious code was written in its place. Used by Cobalt Strike, Metasploit, " +
                "Dridex, TrickBot, and most sophisticated implants.",

            "UNMAPPED_BASE" =>
                "The process has no file-backed mapping at its base address — its main executable " +
                "region is a private (anonymous) allocation. This indicates shellcode or a " +
                "reflectively-loaded PE running entirely in memory, with no on-disk image. " +
                "Used by fileless malware and in-memory loaders.",

            _ =>
                "Memory layout anomaly detected in process image mapping."
        };

        return new DetectionEvent
        {
            RuleName    = Name,
            Evidence    = hollow.Evidence,
            Reasoning   = reasoning,
            Confidence  = hollow.Confidence,
            Tier        = Tier,
            ProcessName = hollow.ProcessName,
            ProcessId   = hollow.ProcessId,
            Timestamp   = hollow.Timestamp,
            Metadata    = new()
            {
                ["DeclaredPath"] = hollow.DeclaredPath,
                ["HollowType"]   = hollow.HollowType
            }
        };
    }
}
