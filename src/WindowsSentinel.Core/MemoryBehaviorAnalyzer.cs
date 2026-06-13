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
        private readonly AllowlistService? _allowlist;
        private readonly ILogger<MemoryBehaviorAnalyzer> _logger;
        private readonly System.Threading.Timer _timer;

        private readonly ConcurrentDictionary<int, DateTime> _scannedPids = new();
        private readonly ConcurrentDictionary<int, int> _previousRwxCounts = new();
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
            // Games with JIT/scripting engines
            "fm.exe", "Football Manager 2024.exe", "Football Manager 2025.exe",
        };

        public MemoryBehaviorAnalyzer(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            ILogger<MemoryBehaviorAnalyzer> logger,
            AllowlistService? allowlist = null)
        {
            _fusionEngine = fusionEngine;
            _detectionEngine = detectionEngine;
            _allowlist = allowlist;
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

                        if (JitProcesses.Contains(name + ".exe"))
                        {
                            // JIT name match — but verify path to prevent rename bypass
                            string? jitPath = null;
                            try { jitPath = proc.MainModule?.FileName; } catch { }
                            if (IsLegitimateJitPath(jitPath))
                                continue;
                        }
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
                            // Check if this is a GROWING count (injection) vs STABLE count (JIT engine)
                            // JIT engines allocate RWX at startup and stay stable.
                            // Injection adds new RWX regions over time.
                            bool isGrowing = false;
                            if (_previousRwxCounts.TryGetValue(proc.Id, out int prevCount))
                            {
                                // If RWX count grew by 3+ since last scan, it's actively being injected
                                isGrowing = rwxCount > prevCount + 2;
                            }
                            _previousRwxCounts[proc.Id] = rwxCount;

                            // First time seeing this PID with high RWX: record baseline, don't alert yet
                            if (!isGrowing && prevCount == 0) continue;

                            // Stable high count across scans = JIT engine, not injection
                            if (!isGrowing) continue;

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

                            var confidence = isFromSuspiciousPath ? 0.80 : 0.70;
                            var tier = isFromSuspiciousPath
                                ? DetectionTier.Tier1Behavioral
                                : DetectionTier.Tier2Indicator;

                            _ = _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Memory Injection: RWX Region Growth Detected",
                                Evidence = $"Process '{name}' (PID {proc.Id}) RWX regions grew from {prevCount} to {rwxCount} ({totalRwxSize / 1024}KB total)",
                                Reasoning = "A process's private RWX memory region count increased between scans, indicating new executable code was injected at runtime. Stable JIT engines allocate RWX at startup and don't grow. Growing RWX = active code injection.",
                                Confidence = confidence, Tier = tier,
                                AuthorizedResponse = isFromSuspiciousPath
                                    ? ResponseAction.KillProcessTree
                                    : ResponseAction.LogOnly,
                                ProcessName = name, ProcessId = proc.Id
                            });
                        }
                        else
                        {
                            // Below threshold — record for future comparison
                            _previousRwxCounts[proc.Id] = rwxCount;
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

        /// <summary>
        /// Verifies that a JIT-named process is actually running from a legitimate install path.
        /// Prevents bypass via rename: attacker can't just name malware "node.exe" — it must
        /// also be in Program Files, AppData\Local\Programs, or a known runtime directory.
        /// </summary>
        private static bool IsLegitimateJitPath(string? path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            return path.StartsWith(@"C:\Program Files", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\AppData\Local\Programs\", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\AppData\Local\Google\", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\AppData\Local\Microsoft\", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\AppData\Local\BraveSoftware\", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\AppData\Local\Vivaldi\", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\dotnet\", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\nodejs\", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains(@"\Python", StringComparison.OrdinalIgnoreCase) ||
                   path.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase);
        }
    }
}
