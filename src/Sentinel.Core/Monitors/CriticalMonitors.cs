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

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION_SYSCALL lpBuffer, int dwLength);

        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_IMAGE = 0x1000000;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        private const uint PAGE_EXECUTE = 0x10;

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION_SYSCALL
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        // Cooldown per PID for indirect syscall detections
        private readonly System.Collections.Concurrent.ConcurrentDictionary<int, DateTimeOffset> _syscallAlertedPids = new();
        private static readonly TimeSpan SyscallAlertCooldown = TimeSpan.FromMinutes(5);

        // Hell's Gate / Halo's Gate signature patterns (x64):
        // mov r10, rcx     → 4C 8B D1
        // mov eax, SSN     → B8 xx xx 00 00
        // syscall          → 0F 05
        // ret              → C3
        private static readonly byte[] HellsGatePrefix = new byte[] { 0x4C, 0x8B, 0xD1, 0xB8 };
        private static readonly byte[] SyscallInstruction = new byte[] { 0x0F, 0x05 };

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

            int cycleCount = 0;
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);

                    // Original check: on-disk ntdll hash integrity
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

                    // v1.6.8: Every 2nd cycle, scan for indirect syscall / Hell's Gate patterns
                    // in target processes (non-image executable memory containing syscall stubs)
                    cycleCount++;
                    if (cycleCount % 2 == 0)
                    {
                        await ScanForIndirectSyscallPatternsAsync(ct);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[SyscallStubMonitor] Error"); }
            }
        }

        /// <summary>
        /// v1.6.8: Scans target processes for Hell's Gate / indirect syscall patterns.
        ///
        /// Indirect syscalls bypass EDR userland hooks by:
        /// 1. Reading the System Service Number (SSN) from ntdll.dll stubs
        /// 2. Manually constructing a syscall stub in private memory:
        ///    mov r10, rcx  (4C 8B D1)
        ///    mov eax, SSN  (B8 xx xx 00 00)
        ///    syscall       (0F 05)
        ///    ret           (C3)
        /// 3. Calling the stub directly, bypassing any hooks on ntdll exports
        ///
        /// Detection: scan non-image executable memory regions for this pattern.
        /// Legitimate code (JIT, trampolines) does NOT contain syscall instructions
        /// in private (non-image) memory — only in ntdll.dll itself.
        /// </summary>
        private async Task ScanForIndirectSyscallPatternsAsync(CancellationToken ct)
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                if (proc.Id <= 4) { proc.Dispose(); continue; }

                var name = proc.ProcessName;

                // Skip known JIT engines that may have syscall-like byte sequences
                if (IsJitProcess(name)) { proc.Dispose(); continue; }

                // Cooldown check
                if (_syscallAlertedPids.TryGetValue(proc.Id, out var lastAlert) &&
                    DateTimeOffset.UtcNow - lastAlert < SyscallAlertCooldown)
                {
                    proc.Dispose();
                    continue;
                }

                try
                {
                    IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.Id);
                    if (hProcess == IntPtr.Zero) continue;

                    try
                    {
                        int syscallStubCount = ScanProcessForSyscallStubs(hProcess, proc);
                        if (syscallStubCount >= 3) // Require 3+ distinct syscall stubs (one could be incidental)
                        {
                            _syscallAlertedPids[proc.Id] = DateTimeOffset.UtcNow;
                            string imagePath = SecurityValidation.GetProcessImagePath(proc.Id) ?? "";

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Evasion: Indirect Syscall / Hell's Gate Pattern Detected",
                                Evidence = $"Process '{name}' (PID {proc.Id}) contains {syscallStubCount} syscall stub(s) " +
                                           $"in non-image (private) executable memory. Pattern: mov r10,rcx; mov eax,SSN; syscall.",
                                Reasoning = "Multiple syscall instruction sequences were found in private (non-image-backed) executable memory. " +
                                            "This is the signature of Hell's Gate, Halo's Gate, or SysWhispers-style indirect syscall execution. " +
                                            "Legitimate processes never construct raw syscall stubs outside ntdll.dll — this technique is used exclusively " +
                                            "to bypass EDR userland hooks on ntdll exports (MITRE T1106, T1562.001).",
                                Confidence = 0.92,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = name,
                                ProcessId = proc.Id,
                                SignalType = SignalType.SecurityEvasion,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["SyscallStubCount"] = syscallStubCount.ToString(),
                                    ["ImagePath"] = imagePath,
                                    ["Technique"] = "IndirectSyscall/HellsGate"
                                }
                            });
                        }
                    }
                    finally { CloseHandle(hProcess); }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }

        private int ScanProcessForSyscallStubs(IntPtr hProcess, Process proc)
        {
            int stubCount = 0;

            // Build module ranges to identify image-backed regions
            var moduleRanges = new List<(ulong Base, ulong End)>();
            try
            {
                foreach (ProcessModule mod in proc.Modules)
                {
                    if (mod.BaseAddress != IntPtr.Zero)
                    {
                        ulong modBase = (ulong)mod.BaseAddress;
                        moduleRanges.Add((modBase, modBase + (ulong)mod.ModuleMemorySize));
                    }
                }
            }
            catch { return 0; }

            // Walk memory regions looking for non-image executable pages
            IntPtr address = IntPtr.Zero;
            int infoSize = Marshal.SizeOf<MEMORY_BASIC_INFORMATION_SYSCALL>();
            int regionsScanned = 0;

            while (regionsScanned < 5000)
            {
                regionsScanned++;
                int bytesReturned = VirtualQueryEx(hProcess, address, out MEMORY_BASIC_INFORMATION_SYSCALL mbi, infoSize);
                if (bytesReturned == 0) break;

                long regionSize = (long)mbi.RegionSize;

                // Only scan committed, executable, non-image regions (private memory)
                if (mbi.State == MEM_COMMIT &&
                    mbi.Type != MEM_IMAGE &&
                    IsExecutableProtection(mbi.Protect) &&
                    regionSize > 0 && regionSize <= 4 * 1024 * 1024) // Cap at 4MB per region
                {
                    ulong regionBase = (ulong)mbi.BaseAddress;
                    bool insideModule = moduleRanges.Any(r => regionBase >= r.Base && regionBase < r.End);

                    if (!insideModule)
                    {
                        // Read up to 4KB of the region to scan for syscall stubs
                        int readSize = (int)Math.Min(regionSize, 4096);
                        byte[] buffer = new byte[readSize];

                        if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, readSize, out int bytesRead) && bytesRead > 16)
                        {
                            stubCount += CountSyscallStubs(buffer, bytesRead);
                            if (stubCount >= 3) return stubCount; // Early exit once threshold met
                        }
                    }
                }

                // Advance
                ulong nextAddr = (ulong)mbi.BaseAddress + (ulong)mbi.RegionSize;
                if (nextAddr <= (ulong)address) break;
                address = (IntPtr)nextAddr;
            }

            return stubCount;
        }

        /// <summary>
        /// Counts occurrences of the Hell's Gate syscall stub pattern in a memory buffer:
        /// 4C 8B D1       mov r10, rcx
        /// B8 xx xx 00 00 mov eax, SSN (SSN < 0x1000 for valid syscalls)
        /// ... (optional intermediate bytes)
        /// 0F 05          syscall
        /// </summary>
        private static int CountSyscallStubs(byte[] buffer, int length)
        {
            int count = 0;
            for (int i = 0; i <= length - 12; i++)
            {
                // Check for Hell's Gate prefix: 4C 8B D1 B8
                if (buffer[i] == 0x4C && buffer[i + 1] == 0x8B && buffer[i + 2] == 0xD1 && buffer[i + 3] == 0xB8)
                {
                    // Verify SSN is reasonable (bytes 4-5 are the SSN, bytes 6-7 should be 0x00)
                    if (buffer[i + 6] == 0x00 && buffer[i + 7] == 0x00)
                    {
                        // Look for syscall instruction (0F 05) within the next 20 bytes
                        int searchEnd = Math.Min(i + 28, length - 1);
                        for (int j = i + 8; j < searchEnd; j++)
                        {
                            if (buffer[j] == 0x0F && buffer[j + 1] == 0x05)
                            {
                                count++;
                                i = j + 1; // Skip past this stub
                                break;
                            }
                        }
                    }
                }
            }
            return count;
        }

        private static bool IsExecutableProtection(uint protect)
        {
            return protect == PAGE_EXECUTE ||
                   protect == PAGE_EXECUTE_READ ||
                   protect == PAGE_EXECUTE_READWRITE ||
                   protect == PAGE_EXECUTE_WRITECOPY;
        }

        private static bool IsJitProcess(string name)
        {
            var jitProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "java", "javaw", "node", "python", "python3", "dotnet", "pwsh",
                "powershell", "chrome", "msedge", "firefox", "brave", "teams",
                "discord", "spotify", "code", "Code - Insiders", "cursor",
                "kiro", "windsurf", "positron", "Devin", "Antigravity IDE",
                "rider64", "idea64", "phpstorm64", "webstorm64", "goland64",
                "pycharm64", "clion64", "electron", "msedgewebview2",
                "slack", "steamwebhelper"
            };
            return jitProcesses.Contains(name);
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
