namespace WindowsSentinel.Core.Models;

public sealed record NetworkConnection
{
    public required string Protocol     { get; init; }   // TCP, TCP6, UDP, UDP6
    public required int    LocalPort    { get; init; }
    public required string LocalAddress { get; init; }
    public required int    RemotePort   { get; init; }
    public required string RemoteAddress { get; init; }
    public required int    ProcessId    { get; init; }
    public required string State        { get; init; }
}


