namespace WindowsSentinel.Core.Models;

/// <summary>
/// Represents a single detection event produced by a monitor or detection rule.
/// Every field is required for explainability compliance.
/// </summary>
public sealed record DetectionEvent
{
    public required string RuleName       { get; init; }
    public required string Evidence       { get; init; }
    public required string Reasoning      { get; init; }
    public required double Confidence     { get; init; }   // 0.0 – 1.0
    public required DetectionTier Tier    { get; init; }
    public required string ProcessName    { get; init; }
    public required int    ProcessId      { get; init; }
    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>Optional extra context (e.g. network endpoint, file path).</summary>
    public Dictionary<string, string> Metadata { get; init; } = new();
}

