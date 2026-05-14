namespace WindowsSentinel.Core.Deception;

using WindowsSentinel.Core.Models;

/// <summary>
/// Interface for the pre-kill deception engine.
/// Executes attacker-hostile actions BEFORE process termination to poison exfiltrated data,
/// waste attacker resources, and destabilize implants.
/// </summary>
public interface IDeceptionEngine
{
    /// <summary>
    /// Executes all applicable deception tactics against the target process before it is killed.
    /// Returns a summary of actions taken for forensic logging.
    /// </summary>
    Task<DeceptionResult> ExecutePreKillDeceptionAsync(
        DetectionEvent detection,
        DeceptionContext context,
        CancellationToken cancellationToken);
}
