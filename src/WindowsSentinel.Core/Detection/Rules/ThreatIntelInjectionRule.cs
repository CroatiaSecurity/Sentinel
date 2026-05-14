using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Converts ThreatIntelTelemetry (from EtwThreatIntelMonitor) into
/// DetectionEvents.
///
/// This rule fires on actual kernel API calls observed via the
/// Microsoft-Windows-Threat-Intelligence ETW provider — not heuristics.
/// It covers:
///   - Cross-process VirtualAllocEx (shellcode staging in another process)
///   - VirtualProtect to RWX (shellcode activation, same or cross-process)
///   - NtMapViewOfSection cross-process (hollowing, module stomping)
///   - QueueUserAPC cross-process (APC injection)
///   - SetThreadContext cross-process (classic hollowing)
///
/// When this fires, it is not a guess. The kernel observed the call.
/// </summary>
public sealed class ThreatIntelInjectionRule : IDetectionRule
{
    public string Name => "Kernel-Observed Process Injection (ThreatIntel ETW)";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ThreatIntelTelemetry ti) return null;

        string reasoning = ti.EventKind switch
        {
            ThreatIntelEventKind.CrossProcessAllocVm =>
                "VirtualAllocEx allocates memory in a remote process — the first step of classic " +
                "shellcode injection (T1055.001). The kernel observed this call directly.",

            ThreatIntelEventKind.ExecutableMemoryProtection =>
                "VirtualProtect with PAGE_EXECUTE_READWRITE marks memory as executable. " +
                "This is how shellcode is activated after being written to memory (T1055). " +
                "Cross-process RWX is near-certain injection; same-process RWX is shellcode staging.",

            ThreatIntelEventKind.CrossProcessMapView =>
                "NtMapViewOfSection maps a section object into a remote process. " +
                "This is the core mechanism of process hollowing (T1055.012) and " +
                "module stomping — the kernel observed this call directly.",

            ThreatIntelEventKind.CrossProcessQueueApc =>
                "QueueUserAPC queued an APC routine in a remote thread. " +
                "APC injection (T1055.004) executes shellcode when the target thread " +
                "enters an alertable wait state. The kernel observed this call directly.",

            ThreatIntelEventKind.CrossProcessSetThreadContext =>
                "SetThreadContext modified a thread's register state in a remote process. " +
                "This is the final step of process hollowing (T1055.012) — redirecting " +
                "execution to injected shellcode. The kernel observed this call directly.",

            _ => "Kernel-level process injection API observed via Threat Intelligence ETW provider."
        };

        return new DetectionEvent
        {
            RuleName    = Name,
            Evidence    = ti.Evidence,
            Reasoning   = reasoning,
            Confidence  = ti.Confidence,
            Tier        = Tier,
            ProcessName = ti.CallerProcessId.ToString(),
            ProcessId   = ti.CallerProcessId,
            Timestamp   = ti.Timestamp,
            Metadata    = new(ti.RawData)
            {
                ["TargetProcessId"] = ti.TargetProcessId.ToString(),
                ["EventKind"]       = ti.EventKind.ToString()
            }
        };
    }
}
