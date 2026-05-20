namespace WindowsSentinel.Core.Deception;

/// <summary>
/// Interface for individual deception tactics that can be executed pre-kill.
/// Each tactic is a self-contained hostile action against the attacker's process or data.
/// </summary>
public interface IDeceptionTactic
{
    /// <summary>
    /// Execute this deception tactic against the target process.
    /// Must be fast (sub-second) and failure-tolerant.
    /// </summary>
    Task<DeceptionTacticResult> ExecuteAsync(DeceptionContext context, CancellationToken cancellationToken);
}

