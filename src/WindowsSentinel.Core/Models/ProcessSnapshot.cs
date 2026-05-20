namespace WindowsSentinel.Core.Models;

public sealed record ProcessSnapshot
{
    public required int    ProcessId   { get; init; }
    public required string ProcessName { get; init; }
    public required string ImagePath   { get; init; }
    public required string CommandLine { get; init; }
    public required int    ParentProcessId { get; init; }
    public required bool   IsSigned    { get; init; }
    public required DateTimeOffset StartTime { get; init; }
}


