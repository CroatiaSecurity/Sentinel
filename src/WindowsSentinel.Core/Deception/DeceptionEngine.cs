using System.Diagnostics;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Deception;

/// <summary>
/// Aggressive Deception Engine (v1.7.0) — Executes attacker-hostile tactics before process kill.
/// 
/// Philosophy: Don't just stop the attacker — make them pay. Every exfiltration attempt should
/// cost the attacker time, pollute their data, destabilize their tooling, and expose their
/// infrastructure. All tactics operate on OUR OWN SYSTEM against an intruder already present.
/// 
/// Tactic selection is based on detected attack category:
///   - Exfiltration → File replacement (zip bombs, sparse bombs), clipboard poisoning
///   - C2 Beaconing → Memory flooding, beacon flooding, environment poisoning
///   - Credential Theft → Weaponized honeypot deployment
///   - Process Injection → DLL stomping, handle pollution, stack corruption
///   - Data Staging → Symlink loops, sparse file traps
///   - Clipboard Theft → Clipboard poisoning with tracking data
///   - Screen Capture → Memory flooding (pollute captured frames)
///   - DNS Tunneling → Response pollution
/// 
/// SAFETY:
///   - Maximum 2 seconds total deception time before kill proceeds
///   - Never targets own PID or system-critical processes
///   - All actions logged before execution
///   - Deception failure never prevents the kill from proceeding
/// </summary>
public sealed class DeceptionEngine : IDeceptionEngine
{
    private readonly ILogger<DeceptionEngine> _logger;
    private readonly MemoryFloodingTactic _memoryFlooding;
    private readonly FileTrapTactic _fileTraps;
    private readonly ClipboardPoisonTactic _clipboardPoison;
    private readonly ImplantDestabilizer _implantDestabilizer;
    private readonly BeaconFlooder _beaconFlooder;
    private readonly EnvironmentPoisoner _environmentPoisoner;
    private readonly HoneypotWeaponizer _honeypotWeaponizer;
    private readonly NetworkHoneypotDeployer _networkHoneypot;

    /// <summary>Maximum time allowed for all deception tactics before kill proceeds.</summary>
    private static readonly TimeSpan MaxDeceptionTime = TimeSpan.FromSeconds(2);

    public DeceptionEngine(
        ILogger<DeceptionEngine> logger,
        MemoryFloodingTactic memoryFlooding,
        FileTrapTactic fileTraps,
        ClipboardPoisonTactic clipboardPoison,
        ImplantDestabilizer implantDestabilizer,
        BeaconFlooder beaconFlooder,
        EnvironmentPoisoner environmentPoisoner,
        HoneypotWeaponizer honeypotWeaponizer,
        NetworkHoneypotDeployer networkHoneypot)
    {
        _logger = logger;
        _memoryFlooding = memoryFlooding;
        _fileTraps = fileTraps;
        _clipboardPoison = clipboardPoison;
        _implantDestabilizer = implantDestabilizer;
        _beaconFlooder = beaconFlooder;
        _environmentPoisoner = environmentPoisoner;
        _honeypotWeaponizer = honeypotWeaponizer;
        _networkHoneypot = networkHoneypot;
    }

    public async Task<DeceptionResult> ExecutePreKillDeceptionAsync(
        DetectionEvent detection,
        DeceptionContext context,
        CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();

        // SAFETY: Never deceive our own process
        if (context.ProcessId == Environment.ProcessId)
        {
            return new DeceptionResult
            {
                Executed = false,
                SkipReason = "Target is own process — deception skipped"
            };
        }

        // SAFETY: Never deceive PID 0 or 4 (System)
        if (context.ProcessId <= 4)
        {
            return new DeceptionResult
            {
                Executed = false,
                SkipReason = $"Target PID {context.ProcessId} is system-critical — deception skipped"
            };
        }

        _logger.LogWarning(
            "[DECEPTION] Engaging pre-kill deception against PID {Pid} ({Process}) — Category: {Category}",
            context.ProcessId, context.ProcessName, context.Category);

        var tactics = SelectTactics(context);
        var results = new List<DeceptionTacticResult>();

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(MaxDeceptionTime);

        foreach (var tactic in tactics)
        {
            if (timeoutCts.Token.IsCancellationRequested)
            {
                _logger.LogWarning("[DECEPTION] Time budget exhausted — proceeding to kill");
                break;
            }

            // Run network-based and lateral movement deception tactics asynchronously 
            // in the background without blocking the pre-kill execution path or budget.
            if (tactic is BeaconFlooder || tactic is NetworkHoneypotDeployer)
            {
                _logger.LogWarning("[DECEPTION] Spawning asynchronous background deception tactic: {Tactic}", tactic.GetType().Name);
                
                // Fire and forget using Task.Run
                _ = Task.Run(async () =>
                {
                    // Create a 10-second timeout for the background task to prevent thread exhaustion
                    using var bgCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    bgCts.CancelAfter(TimeSpan.FromSeconds(10));

                    try
                    {
                        var tacticSw = Stopwatch.StartNew();
                        var result = await tactic.ExecuteAsync(context, bgCts.Token);
                        tacticSw.Stop();
                        
                        if (result.Success)
                        {
                            _logger.LogWarning(
                                "[DECEPTION] [ASYNC] ✓ {Tactic}: {Description} (Duration: {Duration}ms)",
                                result.TacticName, result.Description, tacticSw.ElapsedMilliseconds);
                        }
                        else
                        {
                            _logger.LogDebug(
                                "[DECEPTION] [ASYNC] ✗ {Tactic}: {Error}",
                                result.TacticName, result.Error);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        _logger.LogWarning("[DECEPTION] [ASYNC] Tactic {Tactic} timed out after 10 seconds", tactic.GetType().Name);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[DECEPTION] [ASYNC] Tactic {Tactic} failed", tactic.GetType().Name);
                    }
                }, cancellationToken);

                results.Add(new DeceptionTacticResult
                {
                    TacticName = tactic.GetType().Name,
                    Success = true,
                    Description = "Delegated to background execution"
                });
                continue;
            }

            try
            {
                var tacticSw = Stopwatch.StartNew();
                var result = await tactic.ExecuteAsync(context, timeoutCts.Token);
                tacticSw.Stop();

                results.Add(result with { Duration = tacticSw.Elapsed });

                if (result.Success)
                {
                    _logger.LogWarning(
                        "[DECEPTION] ✓ {Tactic}: {Description}",
                        result.TacticName, result.Description);
                }
                else
                {
                    _logger.LogDebug(
                        "[DECEPTION] ✗ {Tactic}: {Error}",
                        result.TacticName, result.Error);
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("[DECEPTION] Tactic cancelled due to time budget");
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DECEPTION] Tactic failed (non-fatal)");
                results.Add(new DeceptionTacticResult
                {
                    TacticName = tactic.GetType().Name,
                    Success = false,
                    Error = ex.Message
                });
            }
        }

        sw.Stop();

        _logger.LogWarning(
            "[DECEPTION] Complete: {Succeeded}/{Total} tactics in {Duration}ms — proceeding to kill",
            results.Count(r => r.Success), results.Count, sw.ElapsedMilliseconds);

        return new DeceptionResult
        {
            Executed = results.Any(r => r.Success),
            Tactics = results,
            Duration = sw.Elapsed
        };
    }

    /// <summary>
    /// Selects applicable deception tactics based on the detected attack category.
    /// Tactics are ordered by impact and speed — fastest first to maximize execution within time budget.
    /// </summary>
    private IReadOnlyList<IDeceptionTactic> SelectTactics(DeceptionContext context)
    {
        var tactics = new List<IDeceptionTactic>();

        // Memory flooding — always applicable, fast, high impact on attacker forensics
        tactics.Add(_memoryFlooding);

        // Implant destabilization — always applicable when we have a malicious process
        tactics.Add(_implantDestabilizer);

        // Environment poisoning — fast, breaks implant reconnection
        if (context.Category.HasFlag(AttackCategory.C2Beaconing) ||
            context.Category.HasFlag(AttackCategory.ProcessInjection))
        {
            tactics.Add(_environmentPoisoner);
        }

        // Clipboard poisoning — when clipboard theft detected
        if (context.Category.HasFlag(AttackCategory.ClipboardTheft) ||
            context.Category.HasFlag(AttackCategory.Exfiltration))
        {
            tactics.Add(_clipboardPoison);
        }

        // File traps — when data staging or exfiltration detected
        if (context.Category.HasFlag(AttackCategory.DataStaging) ||
            context.Category.HasFlag(AttackCategory.Exfiltration))
        {
            tactics.Add(_fileTraps);
        }

        // Beacon flooding — when C2 channel identified
        if (context.Category.HasFlag(AttackCategory.C2Beaconing) &&
            context.RemoteAddress != null)
        {
            tactics.Add(_beaconFlooder);
        }

        // Honeypot weaponization — when credential theft detected
        if (context.Category.HasFlag(AttackCategory.CredentialTheft))
        {
            tactics.Add(_honeypotWeaponizer);
        }

        // Network honeypot deployment (Nuclear Option) — deploy fake lateral movement targets
        // This runs on ANY confirmed kill to waste attacker time if they have persistence
        tactics.Add(_networkHoneypot);

        return tactics;
    }
}

