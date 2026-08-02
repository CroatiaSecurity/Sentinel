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
    /// On-disk ntdll integrity + remote Hell's Gate / indirect-syscall scan.
    /// Memory APIs resolved via <see cref="NativeProcessMemory"/> (not PE imports).
    /// Skips game/anti-cheat paths only — defenses stay armed for everything else.
    /// </summary>
    public sealed class SyscallStubMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<SyscallStubMonitor> _logger;
        private byte[]? _baselineNtdllHash;
        private readonly System.Collections.Concurrent.ConcurrentDictionary<int, DateTimeOffset> _syscallAlertedPids = new();
        private static readonly TimeSpan SyscallAlertCooldown = TimeSpan.FromMinutes(5);

        public SyscallStubMonitor(DetectionEngine de, ILogger<SyscallStubMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[SyscallStubMonitor] Started — ntdll integrity + Hell's Gate scan (game paths skipped)");
            var ntdllPath = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
            if (File.Exists(ntdllPath))
            {
                try
                {
                    using var fs = new FileStream(ntdllPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    _baselineNtdllHash = System.Security.Cryptography.Sha256Net48.HashData(fs);
                }
                catch { /* access race */ }
            }

            int cycleCount = 0;
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
                            currentHash = System.Security.Cryptography.Sha256Net48.HashData(fs);
                        }
                        if (!currentHash.SequenceEqual(_baselineNtdllHash))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "ETW Tampering: ntdll.dll On-Disk Hash Changed",
                                Evidence = $"ntdll.dll hash changed from {ConvertHex.ToHexString(_baselineNtdllHash)} to {ConvertHex.ToHexString(currentHash)}",
                                Reasoning = "The on-disk ntdll.dll hash changed, which should never happen during normal operation.",
                                Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                            _baselineNtdllHash = currentHash;
                        }
                    }

                    cycleCount++;
                    if (cycleCount % 2 == 0)
                        await ScanForIndirectSyscallPatternsAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[SyscallStubMonitor] Error"); }
            }
        }

        private async Task ScanForIndirectSyscallPatternsAsync(CancellationToken ct)
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                if (proc.Id <= 4) { proc.Dispose(); continue; }

                try
                {
                    var name = proc.ProcessName;
                    if (IsJitProcess(name)) { proc.Dispose(); continue; }

                    var imagePath = SecurityValidation.GetProcessImagePath(proc.Id);
                    if (!NativeProcessMemory.CanInspect(proc.Id, imagePath))
                    {
                        proc.Dispose();
                        continue;
                    }

                    if (_syscallAlertedPids.TryGetValue(proc.Id, out var lastAlert) &&
                        DateTimeOffset.UtcNow - lastAlert < SyscallAlertCooldown)
                    {
                        proc.Dispose();
                        continue;
                    }

                    uint access = NativeProcessMemory.PROCESS_QUERY_INFORMATION | NativeProcessMemory.PROCESS_VM_READ;
                    IntPtr hProcess = NativeProcessMemory.OpenRemoteHandle(access, proc.Id);
                    if (hProcess == IntPtr.Zero) { proc.Dispose(); continue; }

                    try
                    {
                        int stubCount = ScanProcessForSyscallStubs(hProcess);
                        if (stubCount >= 3)
                        {
                            _syscallAlertedPids[proc.Id] = DateTimeOffset.UtcNow;
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Evasion: Indirect Syscall / Hell's Gate Pattern Detected",
                                Evidence = $"Process '{name}' (PID {proc.Id}) contains {stubCount} syscall stub(s) " +
                                           $"in non-image (private) executable memory. Pattern: mov r10,rcx; mov eax,SSN; syscall.",
                                Reasoning = "Multiple syscall sequences in private executable memory indicate Hell's Gate / " +
                                            "SysWhispers-style EDR bypass (MITRE T1106, T1562.001).",
                                Confidence = 0.92,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = name,
                                ProcessId = proc.Id,
                                SignalType = SignalType.SecurityEvasion,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["SyscallStubCount"] = stubCount.ToString(),
                                    ["ImagePath"] = imagePath ?? "",
                                    ["Technique"] = "IndirectSyscall/HellsGate"
                                }
                            });
                        }
                    }
                    finally
                    {
                        NativeProcessMemory.CloseHandle(hProcess);
                        proc.Dispose();
                    }
                }
                catch
                {
                    try { proc.Dispose(); } catch { }
                }
            }
        }

        private static int ScanProcessForSyscallStubs(IntPtr hProcess)
        {
            int stubCount = 0;
            IntPtr address = IntPtr.Zero;
            int regionsScanned = 0;

            while (regionsScanned < 5000)
            {
                regionsScanned++;
                int bytesReturned = NativeProcessMemory.QueryRemoteRegion(hProcess, address, out var mbi);
                if (bytesReturned == 0) break;

                long regionSize = (long)mbi.RegionSize;
                if (mbi.State == NativeProcessMemory.MEM_COMMIT &&
                    mbi.Type != NativeProcessMemory.MEM_IMAGE &&
                    NativeProcessMemory.IsExecutableProtection(mbi.Protect) &&
                    regionSize > 0 && regionSize <= 4 * 1024 * 1024)
                {
                    int readSize = (int)Math.Min(regionSize, 4096);
                    byte[] buffer = new byte[readSize];
                    if (NativeProcessMemory.CopyRemote(hProcess, mbi.BaseAddress, buffer, out int bytesRead) &&
                        bytesRead > 16)
                    {
                        stubCount += CountSyscallStubs(buffer, bytesRead);
                        if (stubCount >= 3) return stubCount;
                    }
                }

                ulong nextAddr = (ulong)mbi.BaseAddress + (ulong)mbi.RegionSize;
                if (nextAddr <= (ulong)address) break;
                address = (IntPtr)nextAddr;
            }

            return stubCount;
        }

        private static int CountSyscallStubs(byte[] buffer, int length)
        {
            int count = 0;
            for (int i = 0; i <= length - 12; i++)
            {
                if (buffer[i] == 0x4C && buffer[i + 1] == 0x8B && buffer[i + 2] == 0xD1 && buffer[i + 3] == 0xB8)
                {
                    if (buffer[i + 6] == 0x00 && buffer[i + 7] == 0x00)
                    {
                        int searchEnd = Math.Min(i + 28, length - 1);
                        for (int j = i + 8; j < searchEnd; j++)
                        {
                            if (buffer[j] == 0x0F && buffer[j + 1] == 0x05)
                            {
                                count++;
                                i = j + 1;
                                break;
                            }
                        }
                    }
                }
            }
            return count;
        }

        private static bool IsJitProcess(string name)
        {
            var jit = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "java", "javaw", "node", "python", "python3", "dotnet", "pwsh",
                "powershell", "chrome", "msedge", "firefox", "brave", "teams",
                "discord", "spotify", "code", "cursor", "kiro", "electron",
                "msedgewebview2", "slack", "steamwebhelper"
            };
            return jit.Contains(name);
        }
    }

    public sealed class IPSecIntegrityGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<IPSecIntegrityGuard> _logger;
        private int _consecutiveFailures;
        private bool _cleanedObserveMode;
        private DateTimeOffset _nextAttemptUtc = DateTimeOffset.MinValue;
        private DateTimeOffset _lastEmitUtc = DateTimeOffset.MinValue;

        // After repeated re-apply failures, back off aggressively so we do not
        // burn CPU/disk and flood events.jsonl (was every 30s forever).
        private const int SoftFailThreshold = 3;
        private const int HardFailThreshold = 8;
        private static readonly TimeSpan MinEmitInterval = TimeSpan.FromMinutes(15);

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
                "[IPSecIntegrityGuard] Started — IPSec profile={Mode} (self-heal with backoff)",
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

                    if (HardeningModule.IsIPSecPolicyActive())
                    {
                        if (_consecutiveFailures > 0)
                            _logger.LogInformation(
                                "[IPSecIntegrityGuard] IPSec policy GSecurity active again after {Count} failure(s)",
                                _consecutiveFailures);
                        _consecutiveFailures = 0;
                        _nextAttemptUtc = DateTimeOffset.MinValue;
                    }
                    else if (DateTimeOffset.UtcNow >= _nextAttemptUtc)
                    {
                        _consecutiveFailures++;
                        _logger.LogWarning(
                            "[IPSecIntegrityGuard] IPSec policy GSecurity is MISSING or UNASSIGNED — re-applying (failure #{Count})",
                            _consecutiveFailures);

                        // Stop hammering netsh after hard threshold; only re-check periodically.
                        bool skipReapply = _consecutiveFailures > HardFailThreshold;
                        bool reapplied = false;
                        if (!skipReapply)
                        {
                            HardeningModule.ReapplyIPSecPolicy();
                            await Task.Delay(2000, ct);
                            reapplied = HardeningModule.IsIPSecPolicyActive();
                        }
                        else
                        {
                            reapplied = HardeningModule.IsIPSecPolicyActive();
                        }

                        // Emit on first failure, state change to success, or every MinEmitInterval
                        // while still failing — not on every poll.
                        bool shouldEmit = !reapplied
                            ? (_consecutiveFailures == 1
                               || DateTimeOffset.UtcNow - _lastEmitUtc >= MinEmitInterval)
                            : true;

                        if (shouldEmit)
                        {
                            _lastEmitUtc = DateTimeOffset.UtcNow;
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Anti-Tamper: IPSec Policy Deleted and Re-Applied",
                                Evidence = $"GSecurity IPSec policy was found missing/unassigned. " +
                                           $"Re-application {(skipReapply ? "SKIPPED (backoff)" : reapplied ? "SUCCEEDED" : "FAILED")}. " +
                                           $"Consecutive failures: {_consecutiveFailures}. " +
                                           $"Profile: {(_config.RestrictivePortHardening ? "restrictive" : "attack-only")}",
                                Reasoning = "The IPSec policy that blocks attack-only (or restrictive) ports was removed. " +
                                            "Sentinel re-applied the current profile. Default profile does not block SSH/RDP/SMB. " +
                                            "Repeated failures indicate netsh/IPSec stack issues or policy API unavailable — " +
                                            "backoff is applied to avoid resource exhaustion.",
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
                                    ["Restrictive"] = _config.RestrictivePortHardening.ToString(),
                                    ["BackedOff"] = skipReapply.ToString()
                                }
                            });
                        }

                        if (reapplied)
                        {
                            _consecutiveFailures = 0;
                            _nextAttemptUtc = DateTimeOffset.MinValue;
                        }
                        else
                        {
                            _nextAttemptUtc = DateTimeOffset.UtcNow + ComputeBackoff(_consecutiveFailures);
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[IPSecIntegrityGuard] Error"); }

                await Task.Delay(30000, ct);
            }
        }

        /// <summary>
        /// Exponential-ish backoff: 30s → 2m → 5m → 15m → 1h (capped).
        /// </summary>
        private static TimeSpan ComputeBackoff(int consecutiveFailures)
        {
            if (consecutiveFailures <= SoftFailThreshold)
                return TimeSpan.FromSeconds(30);
            if (consecutiveFailures <= 5)
                return TimeSpan.FromMinutes(2);
            if (consecutiveFailures <= HardFailThreshold)
                return TimeSpan.FromMinutes(5);
            if (consecutiveFailures <= 15)
                return TimeSpan.FromMinutes(15);
            return TimeSpan.FromHours(1);
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
