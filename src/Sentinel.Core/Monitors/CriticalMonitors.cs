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
    public sealed class SyscallStubMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<SyscallStubMonitor> _logger;
        private byte[]? _baselineNtdllHash;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        public SyscallStubMonitor(DetectionEngine de, ILogger<SyscallStubMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[SyscallStubMonitor] Started");
            var ntdllPath = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
            if (File.Exists(ntdllPath))
            {
                try
                {
                    using var fs = new FileStream(ntdllPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    _baselineNtdllHash = SHA256.HashData(fs);
                }
                catch { }
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    if (_baselineNtdllHash == null || !File.Exists(ntdllPath)) continue;
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
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[SyscallStubMonitor] Error"); }
            }
        }
    }

    public sealed class IPSecIntegrityGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<IPSecIntegrityGuard> _logger;
        private int _consecutiveFailures;

        public IPSecIntegrityGuard(DetectionEngine de, ILogger<IPSecIntegrityGuard> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[IPSecIntegrityGuard] Started — verifying GSecurity IPSec policy every 30s");

            // Initial delay to allow HardeningModule to apply first
            await Task.Delay(15000, ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    if (!HardeningModule.IsIPSecPolicyActive())
                    {
                        _consecutiveFailures++;
                        _logger.LogWarning(
                            "[IPSecIntegrityGuard] IPSec policy GSecurity is MISSING or UNASSIGNED — re-applying (failure #{Count})",
                            _consecutiveFailures);

                        HardeningModule.ReapplyIPSecPolicy();

                        // Verify it actually applied
                        await Task.Delay(2000, ct);
                        bool reapplied = HardeningModule.IsIPSecPolicyActive();

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: IPSec Policy Deleted and Re-Applied",
                            Evidence = $"GSecurity IPSec policy was found missing/unassigned. " +
                                       $"Re-application {(reapplied ? "SUCCEEDED" : "FAILED")}. " +
                                       $"Consecutive failures: {_consecutiveFailures}",
                            Reasoning = "The IPSec policy that blocks dangerous ports (FTP, SSH, RDP, SMB, etc.) " +
                                        "was removed or unassigned. This is a critical security tampering event — " +
                                        "an attacker with admin privileges likely ran 'netsh ipsec static delete policy' " +
                                        "to re-enable blocked network protocols for lateral movement or data exfiltration. " +
                                        "Sentinel has re-applied the policy.",
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.AntiTamper,
                            Metadata = new Dictionary<string, string>
                            {
                                ["Reapplied"] = reapplied.ToString(),
                                ["ConsecutiveFailures"] = _consecutiveFailures.ToString()
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
}
