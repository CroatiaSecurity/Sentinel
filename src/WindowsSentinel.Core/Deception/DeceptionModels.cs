namespace WindowsSentinel.Core.Deception;

/// <summary>
/// Context passed to the deception engine describing what kind of attack was detected
/// and what deception tactics are applicable.
/// </summary>
public sealed record DeceptionContext
{
    /// <summary>Target process ID to deceive before killing.</summary>
    public required int ProcessId { get; init; }

    /// <summary>Target process name.</summary>
    public required string ProcessName { get; init; }

    /// <summary>Detected attack category for tactic selection.</summary>
    public required AttackCategory Category { get; init; }

    /// <summary>Remote C2 address if known (for beacon flooding).</summary>
    public string? RemoteAddress { get; init; }

    /// <summary>Remote C2 port if known.</summary>
    public int? RemotePort { get; init; }

    /// <summary>File paths being staged for exfiltration if known.</summary>
    public IReadOnlyList<string> StagedFiles { get; init; } = Array.Empty<string>();

    /// <summary>Identified C2 framework signature (cobalt_strike, sliver, etc.).</summary>
    public string? C2Framework { get; init; }

    /// <summary>Process image path on disk.</summary>
    public string? ImagePath { get; init; }
}

/// <summary>
/// Categories of detected attacks that determine which deception tactics apply.
/// </summary>
[Flags]
public enum AttackCategory
{
    None = 0,
    Exfiltration = 1 << 0,
    C2Beaconing = 1 << 1,
    CredentialTheft = 1 << 2,
    Ransomware = 1 << 3,
    ProcessInjection = 1 << 4,
    Reconnaissance = 1 << 5,
    DataStaging = 1 << 6,
    ClipboardTheft = 1 << 7,
    ScreenCapture = 1 << 8,
    DnsTunneling = 1 << 9
}

/// <summary>
/// Result of deception engine execution — logged for forensic purposes.
/// </summary>
public sealed record DeceptionResult
{
    /// <summary>Whether any deception tactics were executed.</summary>
    public bool Executed { get; init; }

    /// <summary>Individual tactic results.</summary>
    public IReadOnlyList<DeceptionTacticResult> Tactics { get; init; } = Array.Empty<DeceptionTacticResult>();

    /// <summary>Total time spent on deception before kill.</summary>
    public TimeSpan Duration { get; init; }

    /// <summary>Reason if deception was skipped.</summary>
    public string? SkipReason { get; init; }
}

/// <summary>
/// Result of a single deception tactic execution.
/// </summary>
public sealed record DeceptionTacticResult
{
    /// <summary>Name of the tactic executed.</summary>
    public required string TacticName { get; init; }

    /// <summary>Whether the tactic succeeded.</summary>
    public bool Success { get; init; }

    /// <summary>Human-readable description of what was done.</summary>
    public string? Description { get; init; }

    /// <summary>Error message if the tactic failed.</summary>
    public string? Error { get; init; }

    /// <summary>Time spent on this tactic.</summary>
    public TimeSpan Duration { get; init; }
}


