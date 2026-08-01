// Critical Monitor Group — self-protection monitors that restart indefinitely

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// On-disk ntdll integrity only. Remote process memory APIs (ReadProcessMemory /
    /// VirtualQueryEx) were removed — they land in the PE import table and trigger
    /// Sophos Mal/MSIL-AZ and similar AV heuristics, and break anti-cheat games.
    /// </summary>
    public sealed class SyscallStubMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<SyscallStubMonitor> _logger;
        private byte[]? _baselineNtdllHash;

        public SyscallStubMonitor(DetectionEngine de, ILogger<SyscallStubMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[SyscallStubMonitor] Started (on-disk ntdll integrity only)");
            var ntdllPath = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
            if (File.Exists(ntdllPath))
            {
                try
                {
                    using var fs = new FileStream(ntdllPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    _baselineNtdllHash = SHA256.HashData(fs);
                }
                catch { /* access race */ }
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);

                    if (_baselineNtdllHash != null && File.Exists(ntdllPath))
                    {
                        byte[] currentHash;
                        using (var fs = new FileStream(ntdllPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        {
                            currentHash = SHA256.HashData(fs);
                        }
                        if (!currentHash.SequenceEqual(_baselineNtdllHash))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "ETW Tampering: ntdll.dll On-Disk Hash Changed",
                                Evidence = $"ntdll.dll hash changed from {Convert.ToHexString(_baselineNtdllHash)} to {Convert.ToHexString(currentHash)}",
                                Reasoning = "The on-disk ntdll.dll hash changed, which should never happen during normal operation.",
                                Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                            _baselineNtdllHash = currentHash;
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[SyscallStubMonitor] Error"); }
            }
        }
    }

    public sealed class IPSecIntegrityGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<IPSecIntegrityGuard> _logger;
        private int _consecutiveFailures;
        private bool _cleanedObserveMode;

        public IPSecIntegrityGuard(DetectionEngine de, SentinelConfig config, ILogger<IPSecIntegrityGuard> l)
        {
            _detectionEngine = de;
            _config = config;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            HardeningModule.RestrictivePortHardeningEnabled = _config.RestrictivePortHardening;

            _logger.LogInformation(
                "[IPSecIntegrityGuard] Started — IPSec profile={Mode} (self-heal every 30s)",
                _config.RestrictivePortHardening
                    ? "restrictive (attack + SSH/RDP/SMB/DB lockdown)"
                    : "attack-only (malware/legacy ports; user services free)");

            // Once after upgrade: rebuild so old full-block policies drop SSH/RDP/etc.
            if (!_cleanedObserveMode)
            {
                HardeningModule.ReapplyIPSecPolicy();
                _cleanedObserveMode = true;
            }

            await Task.Delay(15000, ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    HardeningModule.RestrictivePortHardeningEnabled = _config.RestrictivePortHardening;

                    if (!HardeningModule.IsIPSecPolicyActive())
                    {
                        _consecutiveFailures++;
                        _logger.LogWarning(
                            "[IPSecIntegrityGuard] IPSec policy GSecurity is MISSING or UNASSIGNED — re-applying (failure #{Count})",
                            _consecutiveFailures);

                        HardeningModule.ReapplyIPSecPolicy();

                        await Task.Delay(2000, ct);
                        bool reapplied = HardeningModule.IsIPSecPolicyActive();

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: IPSec Policy Deleted and Re-Applied",
                            Evidence = $"GSecurity IPSec policy was found missing/unassigned. " +
                                       $"Re-application {(reapplied ? "SUCCEEDED" : "FAILED")}. " +
                                       $"Consecutive failures: {_consecutiveFailures}. " +
                                       $"Profile: {(_config.RestrictivePortHardening ? "restrictive" : "attack-only")}",
                            Reasoning = "The IPSec policy that blocks attack-only (or restrictive) ports was removed. " +
                                        "Sentinel re-applied the current profile. Default profile does not block SSH/RDP/SMB.",
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.AntiTamper,
                            Metadata = new Dictionary<string, string>
                            {
                                ["Reapplied"] = reapplied.ToString(),
                                ["ConsecutiveFailures"] = _consecutiveFailures.ToString(),
                                ["Restrictive"] = _config.RestrictivePortHardening.ToString()
                            }
                        });

                        if (reapplied)
                            _consecutiveFailures = 0;
                    }
                    else
                    {
                        _consecutiveFailures = 0;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[IPSecIntegrityGuard] Error"); }

                await Task.Delay(30000, ct);
            }
        }
    }

    /// <summary>
    /// Self-heals Microsoft Defender ASR policy rules (Block mode) every 60s.
    /// Ported from GEDR_ASR_Rules.ps1 install-once behavior into continuous integrity.
    /// </summary>
    public sealed class AsrPolicyGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<AsrPolicyGuard> _logger;
        private int _consecutiveFailures;

        public AsrPolicyGuard(DetectionEngine de, ILogger<AsrPolicyGuard> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[AsrPolicyGuard] Started — verifying Defender ASR Block rules every 60s");

            // Allow HardeningModule to apply first
            try { await Task.Delay(20000, ct); } catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    if (!HardeningModule.IsAsrPolicyIntact())
                    {
                        _consecutiveFailures++;
                        _logger.LogWarning(
                            "[AsrPolicyGuard] ASR policy incomplete or demoted — re-applying (failure #{Count})",
                            _consecutiveFailures);

                        HardeningModule.ReapplyAsrRules();
                        await Task.Delay(1500, ct);
                        bool ok = HardeningModule.IsAsrPolicyIntact();

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: ASR Policy Drift Re-Applied",
                            Evidence = $"One or more Defender ASR Block rules were missing or not set to Block. " +
                                       $"Re-application {(ok ? "SUCCEEDED" : "FAILED")}. " +
                                       $"Consecutive failures: {_consecutiveFailures}",
                            Reasoning = "Attack Surface Reduction rules block Office child processes, " +
                                        "LSASS credential theft, USB execution, WMI persistence, and related " +
                                        "attack surfaces. An attacker or misconfiguration demoted these rules; " +
                                        "Sentinel restored them.",
                            Confidence = 0.90,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.AntiTamper,
                            Metadata = new Dictionary<string, string>
                            {
                                ["Reapplied"] = ok.ToString(),
                                ["ConsecutiveFailures"] = _consecutiveFailures.ToString(),
                                ["RuleCount"] = HardeningModule.AsrRules.Length.ToString()
                            }
                        });

                        if (ok) _consecutiveFailures = 0;
                    }
                    else
                    {
                        _consecutiveFailures = 0;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[AsrPolicyGuard] Error"); }

                try { await Task.Delay(60000, ct); }
                catch (OperationCanceledException) { break; }
            }
        }
    }
}
