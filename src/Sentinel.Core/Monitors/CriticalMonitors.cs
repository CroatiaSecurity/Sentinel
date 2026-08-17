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
    /// Hell's Gate requires a well-formed stub table (compact syscall+ret or a copied
    /// ntdll prologue) with 3+ distinct SSNs. Loose <c>0F 05</c> bytes in V8/Chromium
    /// JIT regions are not a hit — process-name skips are not used as a trust grant.
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
                    using var fs = new FileStream(ntdllPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
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
                        var scan = ScanProcessForSyscallStubs(hProcess);
                        if (scan.IsHit)
                        {
                            _syscallAlertedPids[proc.Id] = DateTimeOffset.UtcNow;
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Evasion: Indirect Syscall / Hell's Gate Pattern Detected",
                                Evidence = $"Process '{name}' (PID {proc.Id}) contains {scan.WellFormedStubs} well-formed " +
                                           $"syscall stub(s) ({scan.DistinctSsns} distinct SSNs) in non-image executable memory. " +
                                           "Pattern: mov r10,rcx; mov eax,SSN; syscall; ret.",
                                Reasoning = "A table of compact, ret-terminated syscall stubs with multiple SSNs in private " +
                                            "executable memory indicates Hell's Gate / SysWhispers-style EDR bypass " +
                                            "(MITRE T1106, T1562.001). Sparse 0F 05 bytes in JIT code are ignored.",
                                Confidence = 0.92,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = name,
                                ProcessId = proc.Id,
                                SignalType = SignalType.SecurityEvasion,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["SyscallStubCount"] = scan.WellFormedStubs.ToString(),
                                    ["DistinctSsnCount"] = scan.DistinctSsns.ToString(),
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

        private static HellsGateScanResult ScanProcessForSyscallStubs(IntPtr hProcess)
        {
            int stubCount = 0;
            var ssns = new HashSet<int>();
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
                        foreach (var hit in FindSyscallStubs(buffer, bytesRead))
                        {
                            stubCount++;
                            ssns.Add(hit.Ssn);
                            if (stubCount >= 3 && ssns.Count >= 3)
                                return new HellsGateScanResult(stubCount, ssns.Count);
                        }
                    }
                }

                ulong nextAddr = (ulong)mbi.BaseAddress + (ulong)mbi.RegionSize;
                if (nextAddr <= (ulong)address) break;
                address = (IntPtr)nextAddr;
            }

            return new HellsGateScanResult(stubCount, ssns.Count);
        }

        /// <summary>
        /// Compact Hell's Gate / SysWhispers stub, or a copied ntdll prologue.
        /// Does not count a lone <c>syscall</c> floating near <c>mov r10,rcx; mov eax,imm</c>
        /// — that is the V8 / Chromium JIT false positive.
        /// </summary>
        internal static List<SyscallStubHit> FindSyscallStubs(byte[] buffer, int length)
        {
            var hits = new List<SyscallStubHit>();
            if (buffer == null || length < 11) return hits;
            int lim = Math.Min(length, buffer.Length);

            for (int i = 0; i <= lim - 11; i++)
            {
                if (buffer[i] != 0x4C || buffer[i + 1] != 0x8B ||
                    buffer[i + 2] != 0xD1 || buffer[i + 3] != 0xB8)
                    continue;
                if (buffer[i + 6] != 0x00 || buffer[i + 7] != 0x00)
                    continue;

                int ssn = buffer[i + 4] | (buffer[i + 5] << 8);

                // mov r10,rcx; mov eax,SSN; syscall; ret
                if (i + 10 < lim &&
                    buffer[i + 8] == 0x0F && buffer[i + 9] == 0x05 && buffer[i + 10] == 0xC3)
                {
                    hits.Add(new SyscallStubHit(i, ssn));
                    i += 10;
                    continue;
                }

                // Copied ntdll: test byte ptr [SharedUserData+0x308],1 / jne +3 / syscall / ret
                if (i + 20 < lim &&
                    buffer[i + 8] == 0xF6 && buffer[i + 9] == 0x04 && buffer[i + 10] == 0x25 &&
                    buffer[i + 11] == 0x08 && buffer[i + 12] == 0x03 && buffer[i + 13] == 0xFE &&
                    buffer[i + 14] == 0x7F && buffer[i + 15] == 0x01 &&
                    buffer[i + 16] == 0x75 && buffer[i + 17] == 0x03 &&
                    buffer[i + 18] == 0x0F && buffer[i + 19] == 0x05 &&
                    buffer[i + 20] == 0xC3)
                {
                    hits.Add(new SyscallStubHit(i, ssn));
                    i += 20;
                }
            }

            return hits;
        }

        internal static int CountSyscallStubs(byte[] buffer, int length) =>
            FindSyscallStubs(buffer, length).Count;

        internal static bool IsHellsGateEvidence(IReadOnlyList<SyscallStubHit> hits)
        {
            if (hits == null || hits.Count < 3) return false;
            var ssns = new HashSet<int>();
            foreach (var hit in hits)
                ssns.Add(hit.Ssn);
            return ssns.Count >= 3;
        }

        internal readonly struct SyscallStubHit
        {
            public readonly int Offset;
            public readonly int Ssn;
            public SyscallStubHit(int offset, int ssn) { Offset = offset; Ssn = ssn; }
        }

        internal readonly struct HellsGateScanResult
        {
            public readonly int WellFormedStubs;
            public readonly int DistinctSsns;
            public bool IsHit => WellFormedStubs >= 3 && DistinctSsns >= 3;
            public HellsGateScanResult(int stubs, int ssns)
            {
                WellFormedStubs = stubs;
                DistinctSsns = ssns;
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
                "[IPSecIntegrityGuard] Started — IPSec profile={Mode}",
                _config.RestrictivePortHardening
                    ? "restrictive lockdown (self-heal)"
                    : "work-first (no GSecurity IPSec; remove leftovers)");

            // Once after upgrade: either remove GSecurity (default) or rebuild restrictive set.
            if (!_cleanedObserveMode)
            {
                if (_config.RestrictivePortHardening)
                    HardeningModule.ReapplyIPSecPolicy();
                else
                    HardeningModule.ReleaseUserWorkSurface();
                _cleanedObserveMode = true;
            }

            await Task.Delay(15000, ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    HardeningModule.RestrictivePortHardeningEnabled = _config.RestrictivePortHardening;

                    // Default: never re-arm IPSec. If someone re-creates GSecurity, tear it down.
                    if (!_config.RestrictivePortHardening)
                    {
                        if (HardeningModule.IsIPSecPolicyActive())
                        {
                            _logger.LogInformation(
                                "[IPSecIntegrityGuard] GSecurity present in work-first mode — removing");
                            HardeningModule.RemoveIPSecPolicyIfPresent();
                        }
                        _consecutiveFailures = 0;
                    }
                    else if (HardeningModule.IsIPSecPolicyActive())
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
                            "[IPSecIntegrityGuard] Restrictive IPSec GSecurity missing — re-applying (failure #{Count})",
                            _consecutiveFailures);

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
                                Evidence = $"Restrictive GSecurity IPSec was missing/unassigned. " +
                                           $"Re-application {(skipReapply ? "SKIPPED (backoff)" : reapplied ? "SUCCEEDED" : "FAILED")}. " +
                                           $"Consecutive failures: {_consecutiveFailures}.",
                                Reasoning = "RestrictivePortHardening is on: Sentinel maintains the lockdown IPSec profile. " +
                                            "Default work-first installs do not use GSecurity at all.",
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
                                    ["Restrictive"] = "true",
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
    /// Restrictive/kiosk only: self-heals Defender ASR Block rules every 60s.
    /// Default work-first: releases ASR Block policy leftovers and does not re-arm them.
    /// </summary>
    public sealed class AsrPolicyGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<AsrPolicyGuard> _logger;
        private int _consecutiveFailures;
        private bool _releasedWorkFirst;

        public AsrPolicyGuard(DetectionEngine de, SentinelConfig config, ILogger<AsrPolicyGuard> l)
        {
            _detectionEngine = de;
            _config = config;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation(
                "[AsrPolicyGuard] Started — mode={Mode}",
                _config.RestrictivePortHardening ? "restrictive (ASR Block self-heal)" : "work-first (no ASR re-arm)");

            try { await Task.Delay(20000, ct); } catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    HardeningModule.RestrictivePortHardeningEnabled = _config.RestrictivePortHardening;

                    if (!_config.RestrictivePortHardening)
                    {
                        if (!_releasedWorkFirst)
                        {
                            HardeningModule.ReleaseAsrBlockPolicy();
                            HardeningModule.ApplyAsrOnlyExclusions();
                            _releasedWorkFirst = true;
                            _logger.LogInformation(
                                "[AsrPolicyGuard] Work-first: released Sentinel ASR Block policy leftovers");
                        }
                        _consecutiveFailures = 0;
                    }
                    else if (!HardeningModule.IsAsrPolicyIntact())
                    {
                        _consecutiveFailures++;
                        _logger.LogWarning(
                            "[AsrPolicyGuard] Restrictive ASR incomplete — re-applying (failure #{Count})",
                            _consecutiveFailures);

                        HardeningModule.ReapplyAsrRules();
                        await Task.Delay(1500, ct);
                        bool ok = HardeningModule.IsAsrPolicyIntact();

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: ASR Policy Drift Re-Applied",
                            Evidence = $"Restrictive ASR Block rules missing/demoted. " +
                                       $"Re-application {(ok ? "SUCCEEDED" : "FAILED")}. " +
                                       $"Consecutive failures: {_consecutiveFailures}",
                            Reasoning = "RestrictivePortHardening is on: Sentinel maintains ASR Block policy. " +
                                        "Default work-first installs do not force ASR Block rules.",
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
                                ["RuleCount"] = HardeningModule.AsrRules.Length.ToString(),
                                ["Restrictive"] = "true"
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
