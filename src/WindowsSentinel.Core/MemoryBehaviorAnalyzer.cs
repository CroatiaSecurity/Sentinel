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
    /// Scans process memory layout for behavioral anomalies:
    /// - Excessive RWX (read-write-execute) private memory regions
    /// - Unbacked executable memory (no file on disk)
    ///
    /// Detection method: VirtualQueryEx to enumerate memory region types/protection.
    /// Does NOT read process memory (no ReadProcessMemory) — only queries metadata.
    /// This avoids AV heuristic triggers while still detecting injected code regions.
    ///
    /// Rationale: Legitimate apps (browsers, .NET, JIT engines) have some RWX regions.
    /// But 3+ private RWX regions in a non-JIT process is anomalous. Combined with
    /// other signals (process from Temp path, unsigned, suspicious parent), this
    /// contributes to composite detection via the correlation engine.
    /// </summary>
    public sealed class MemoryBehaviorAnalyzer : IDisposable
    {
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<MemoryBehaviorAnalyzer> _logger;
        private readonly System.Threading.Timer _timer;

        private readonly ConcurrentDictionary<int, DateTime> _scannedPids = new();
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(90);

        private static readonly HashSet<string> JitProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "java.exe", "javaw.exe", "node.exe", "python.exe", "python3.exe",
            "ruby.exe", "dotnet.exe", "pwsh.exe", "powershell.exe",
            "deno.exe", "bun.exe",
            // Chromium/Electron apps use V8 JIT — RWX is normal
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
        private const uint MEM_IMAGE = 0x1000000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        private const int RwxThreshold = 5; // Raised from 3 to reduce FP on .NET processes

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

                        IntPtr baseAddress = IntPtr.Zero;
                        try { baseAddress = proc.MainModule?.BaseAddress ?? IntPtr.Zero; } catch { }

                        // === Check 1: Process Hollowing (T1055.012) ===
                        // If base address region is MEM_PRIVATE instead of MEM_IMAGE,
                        // the original image was unmapped and replaced.
                        if (baseAddress != IntPtr.Zero)
                        {
                            int infoSize = Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
                            if (VirtualQueryEx(proc.Handle, baseAddress, out var baseMbi, infoSize) == infoSize)
                            {
                                if ((baseMbi.State & MEM_COMMIT) != 0 && (baseMbi.Type & MEM_IMAGE) == 0)
                                {
                                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                                    {
                                        RuleName = "Process Hollowing: Image Region Replaced",
                                        Evidence = $"Process '{name}' (PID {proc.Id}) base address 0x{baseAddress:X} is MEM_PRIVATE (not MEM_IMAGE)",
                                        Reasoning = "The memory at the process image base address is backed by private memory instead of the file image, indicating the original binary was unmapped and replaced (process hollowing T1055.012).",
                                        Confidence = 0.90, Tier = DetectionTier.Tier1Behavioral,
                                        AuthorizedResponse = ResponseAction.KillProcessTree,
                                        ProcessName = name, ProcessId = proc.Id
                                    });
                                    continue; // Already detected as hollowed — skip RWX check
                                }
                            }
                        }

                        // === Check 2: Excessive RWX Private Regions ===
                        int rwxCount = 0;
                        long totalRwxSize = 0;
                        IntPtr address = IntPtr.Zero;
                        int mbiSize = Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

                        while (true)
                        {
                            if (VirtualQueryEx(proc.Handle, address, out var mbi, mbiSize) != mbiSize)
                                break;

                            if ((mbi.State & MEM_COMMIT) != 0 &&
                                (mbi.Type & MEM_PRIVATE) != 0 &&
                                (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY))
                            {
                                rwxCount++;
                                totalRwxSize += (long)mbi.RegionSize;
                            }

                            var nextAddr = (long)mbi.BaseAddress + (long)mbi.RegionSize;
                            if (nextAddr <= (long)address) break;
                            address = (IntPtr)nextAddr;
                        }

                        if (rwxCount >= RwxThreshold)
                        {
                            bool isFromSuspiciousPath = false;
                            try
                            {
                                var imagePath = proc.MainModule?.FileName ?? "";
                                isFromSuspiciousPath =
                                    imagePath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                                    imagePath.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase) ||
                                    imagePath.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase);
                            }
                            catch { }

                            var confidence = isFromSuspiciousPath ? 0.80 : 0.60;
                            var tier = isFromSuspiciousPath
                                ? DetectionTier.Tier1Behavioral
                                : DetectionTier.Tier2Indicator;

                            _ = _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Memory Injection: Excessive RWX Private Regions",
                                Evidence = $"Process '{name}' (PID {proc.Id}) has {rwxCount} RWX private memory regions ({totalRwxSize / 1024}KB total)",
                                Reasoning = "A non-JIT process has an abnormally high number of private RWX memory regions, which is unusual for legitimate software and suggests code injection or unpacked payload execution.",
                                Confidence = confidence, Tier = tier,
                                AuthorizedResponse = isFromSuspiciousPath
                                    ? ResponseAction.KillProcessTree
                                    : ResponseAction.LogOnly,
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
