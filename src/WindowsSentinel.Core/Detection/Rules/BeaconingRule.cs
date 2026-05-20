using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Converts BeaconingTelemetry into a DetectionEvent.
///
/// Fires when the BeaconingDetector's statistical analysis determines that
/// a process is connecting to a remote endpoint at regular intervals
/// (low coefficient of variation) consistent with C2 beacon behavior.
///
/// This is not a signature — it's a statistical property of the traffic.
/// It catches custom C2 frameworks, modified Cobalt Strike profiles, and
/// any beacon that doesn't use a known port, as long as it beacons regularly.
/// </summary>
public sealed class BeaconingRule : IDetectionRule
{
    public string Name => "C2 Beaconing Behavior (Statistical)";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not BeaconingTelemetry beacon) return null;

        // Confidence scales with regularity (lower CV = more regular = more suspicious)
        // and observation count (more data = more certain)
        double cvFactor    = Math.Max(0, 1.0 - beacon.CoefficientOfVariation / 0.40);
        double countFactor = Math.Min(1.0, beacon.ObservationCount / 20.0);
        double confidence  = 0.70 + cvFactor * 0.20 + countFactor * 0.08;
        confidence = Math.Min(confidence, 0.95);

        string intervalDesc = beacon.MeanIntervalSec < 60
            ? $"{beacon.MeanIntervalSec:F1}s"
            : $"{beacon.MeanIntervalSec / 60:F1}min";

        return new DetectionEvent
        {
            RuleName    = Name,
            Evidence    = $"Process '{beacon.ProcessName}' (PID {beacon.ProcessId}) is beaconing to " +
                          $"{beacon.RemoteAddress}:{beacon.RemotePort} every ~{intervalDesc} " +
                          $"(CV={beacon.CoefficientOfVariation:F3}, n={beacon.ObservationCount})",
            Reasoning   = $"Statistical analysis of {beacon.ObservationCount} connection intervals shows " +
                          $"mean={intervalDesc}, stddev={beacon.StdDevSec:F1}s, " +
                          $"CV={beacon.CoefficientOfVariation:F3}. " +
                          "A coefficient of variation below 0.40 indicates highly regular timing " +
                          "consistent with C2 beacon behavior. Legitimate software connects " +
                          "irregularly (CV > 1.0). This detection is signature-independent — " +
                          "it catches custom C2 frameworks and modified beacon profiles.",
            Confidence  = confidence,
            Tier        = Tier,
            ProcessName = beacon.ProcessName,
            ProcessId   = beacon.ProcessId,
            Timestamp   = beacon.Timestamp,
            Metadata    = new()
            {
                ["RemoteAddress"]          = beacon.RemoteAddress,
                ["RemotePort"]             = beacon.RemotePort.ToString(),
                ["MeanIntervalSec"]        = beacon.MeanIntervalSec.ToString("F2"),
                ["StdDevSec"]              = beacon.StdDevSec.ToString("F2"),
                ["CoefficientOfVariation"] = beacon.CoefficientOfVariation.ToString("F4"),
                ["ObservationCount"]       = beacon.ObservationCount.ToString()
            }
        };
    }
}


