namespace WindowsSentinel.Core.Models;

public enum ResponseActionKind
{
    LogOnly,
    KillProcess,
    SuspendProcess,
    AlertUser
}

/// <summary>
/// Describes an action taken (or not taken) in response to a detection event.
/// </summary>
public sealed record ResponseAction
{
    public required ResponseActionKind Kind        { get; init; }
    public required DetectionEvent     TriggerEvent { get; init; }
    public required DateTimeOffset     Timestamp   { get; init; }
    public string? Notes { get; init; }
}


