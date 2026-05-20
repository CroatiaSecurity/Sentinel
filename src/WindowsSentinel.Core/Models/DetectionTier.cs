namespace WindowsSentinel.Core.Models;

/// <summary>
/// Detection tier controls whether a response action is permitted.
/// Tier1 = behavioral, auto-response allowed.
/// Tier2 = indicators, log only — NEVER triggers action.
/// </summary>
public enum DetectionTier
{
    Tier1Behavioral = 1,
    Tier2Indicator  = 2
}


