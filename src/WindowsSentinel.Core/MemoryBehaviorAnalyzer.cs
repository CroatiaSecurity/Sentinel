using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Scans process memory for behavioral anomalies:
    /// - Excessive RWX (read-write-execute) memory regions
    /// - Unbacked executable memory (no file on disk)
    /// - Known byte prologues indicating position-independent code
    /// Purely behavioral — no tool names, detects memory layout anomalies.
    /// </summary>
    public sealed class MemoryBehaviorAnalyzer : IDisposable
    {
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<MemoryBehaviorAnalyzer> _logger;
        private readonly System.Threading.Timer _timer;

        private readonly ConcurrentDictionary<int, DateTime> _scannedPids = new();
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(90);

        // Known byte sequences for position-independent code prologues
        private static readonly byte[][] CodePrologues = new byte[][]
        {
            new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 },  // CLD; AND RSP, -10h (common x64)
            new byte[] { 0xFC, 0xE8, 0x82, 0x00, 0x00 },  // CLD; CALL +82h (common stager)
            new byte[] { 0x48, 0x31, 0xC9, 0x48, 0x81 },  // XOR RCX,RCX; ...
            new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03 },  // MZ header (reflective PE)
            new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00 },  // CALL $+5
        };

        private static readonly HashSet<string> JitProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "java.exe", "javaw.exe", "node.exe", "python.exe", "python3.exe",
            "ruby.exe", "dotnet.exe", "pwsh.exe", "powershell.exe",
            "deno.exe", "bun.exe",
            // Chromium/Electron apps use V8 JIT → RWX is normal
            "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe",
            "msedgewebview2.exe", "Devin.exe", "code.exe", "cursor.exe", "Kiro.exe",
            "Antigravity IDE.exe",
            "electron.exe", "slack.exe", "discord.exe", "teams.exe", "spotify.exe",
            "steamwebhelper.exe", "cefsharp.browsersubprocess.exe",
        };

        public MemoryBehaviorAnalyzer(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            ILogger<MemoryBehaviorAnalyzer> logger)
        {
            _fusionEngine = fusionEngine;
            _detectionEngine = detectionEngine;
            _logger = logger;
            _timer = new System.Threading.Timer(ScanMemory, null, ScanInterval, ScanInterval);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_PRIVATE = 0x20000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        private const int RwxThreshold = 3;

        private void ScanMemory(object? state)
        {
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (proc.Id <= 4) continue;
                        var name = proc.ProcessName;

                        if (JitProcesses.Contains(name + ".exe")) continue;
                        if (_scannedPids.ContainsKey(proc.Id)) continue;
                        _scannedPids[proc.Id] = DateTime.UtcNow;

                        // Walk the virtual address space looking for RWX private regions
                        int rwxCount = 0;
                        bool hasPrologue = false;
                        IntPtr address = IntPtr.Zero;
                        int infoSize = Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

                        while (true)
                        {
                            if (VirtualQueryEx(proc.Handle, address, out var mbi, infoSize) != infoSize)
                                break;

                            if ((mbi.State & MEM_COMMIT) != 0 &&
                                (mbi.Type & MEM_PRIVATE) != 0 &&
                                (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY))
                            {
                                rwxCount++;

                                // Sample first 16 bytes for code prologues
                                if (!hasPrologue && (long)mbi.RegionSize >= 16)
                                {
                                    var sample = new byte[16];
                                    if (ReadProcessMemory(proc.Handle, mbi.BaseAddress, sample, sample.Length, out _))
                                    {
                                        foreach (var prologue in CodePrologues)
                                        {
                                            if (sample.AsSpan(0, prologue.Length).SequenceEqual(prologue))
                                            {
                                                hasPrologue = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }

                            var nextAddr = (long)mbi.BaseAddress + (long)mbi.RegionSize;
                            if (nextAddr <= (long)address) break; // Overflow protection
                            address = (IntPtr)nextAddr;
                        }

                        if (rwxCount >= RwxThreshold)
                        {
                            var confidence = hasPrologue ? 0.85 : 0.65;
                            var tier = hasPrologue ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator;
                            _ = _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = hasPrologue
                                    ? "Memory Injection: RWX Region with Shellcode Prologue"
                                    : "Memory Injection: Excessive RWX Private Regions",
                                Evidence = $"Process '{name}' (PID {proc.Id}) has {rwxCount} RWX private memory regions{(hasPrologue ? " with known shellcode prologue" : "")}",
                                Reasoning = hasPrologue
                                    ? "A process has private RWX memory containing known position-independent code prologues, strongly indicating injected shellcode."
                                    : "A process has an abnormally high number of private RWX memory regions, which is unusual for legitimate software and suggests code injection.",
                                Confidence = confidence, Tier = tier,
                                AuthorizedResponse = hasPrologue ? ResponseAction.KillProcessTree : ResponseAction.LogOnly,
                                ProcessName = name, ProcessId = proc.Id
                            });
                        }
                    }
                    catch (System.ComponentModel.Win32Exception) { }
                    catch (InvalidOperationException) { }
                    catch { }
                    finally
                    {
                        proc.Dispose();
                    }
                }

                // Prune old entries
                var cutoff = DateTime.UtcNow.AddMinutes(-5);
                foreach (var key in _scannedPids.Keys)
                {
                    if (_scannedPids.TryGetValue(key, out var time) && time < cutoff)
                        _scannedPids.TryRemove(key, out _);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[MemoryBehaviorAnalyzer] Scan error");
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }
}
