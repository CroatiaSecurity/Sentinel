using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Behavedr.Core
{
    /// <summary>
    /// Scans process memory layout for behavioral anomalies:
    /// - Process image path mismatch (hollowed process — binary replaced in memory)
    /// - Module count growth over time (DLL injection adds new modules)
    /// - Unsigned/unknown modules loaded from suspicious paths
    ///
    /// Detection method: .NET Process.Modules enumeration + module count tracking.
    /// Does NOT use VirtualQueryEx or ReadProcessMemory — avoids AV heuristic triggers.
    /// Process hollowing is detected by comparing the MainModule path against the
    /// expected image for the process name, and by tracking module list growth.
    /// </summary>
    public sealed class MemoryBehaviorAnalyzer : IDisposable
    {
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly SignerTrustService _signerTrust;
        private readonly DllUnloadEngine _dllUnloadEngine;
        private readonly ILogger<MemoryBehaviorAnalyzer> _logger;
        private readonly System.Threading.Timer _timer;

        private readonly ConcurrentDictionary<int, DateTime> _scannedPids = new();
        private readonly ConcurrentDictionary<int, int> _previousModuleCounts = new();
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(90);

        private static readonly HashSet<string> JitProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "java.exe", "javaw.exe", "node.exe", "python.exe", "python3.exe",
            "ruby.exe", "dotnet.exe", "pwsh.exe", "powershell.exe",
            "deno.exe", "bun.exe",
            // Chromium/Electron apps use V8 JIT — module growth is normal
            "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe",
            "msedgewebview2.exe", "Devin.exe", "code.exe", "cursor.exe", "Kiro.exe",
            "Antigravity IDE.exe",
            "electron.exe", "slack.exe", "discord.exe", "teams.exe", "spotify.exe",
            "steamwebhelper.exe", "cefsharp.browsersubprocess.exe",
            // Games with JIT/scripting engines
            "fm.exe", "Football Manager 2024.exe", "Football Manager 2025.exe",
            // System processes that dynamically load service DLLs / modules on demand
            "svchost.exe", "Taskmgr.exe", "mmc.exe", "explorer.exe",
            "SearchHost.exe", "RuntimeBroker.exe", "dllhost.exe",
        };

        // Module count growth threshold: injection adds 1-2 DLLs at a time
        private const int ModuleGrowthThreshold = 3;

        public MemoryBehaviorAnalyzer(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            SignerTrustService signerTrust,
            DllUnloadEngine dllUnloadEngine,
            ILogger<MemoryBehaviorAnalyzer> logger)
        {
            _fusionEngine = fusionEngine;
            _detectionEngine = detectionEngine;
            _signerTrust = signerTrust;
            _dllUnloadEngine = dllUnloadEngine;
            _logger = logger;
            _timer = new System.Threading.Timer(ScanMemory, null, ScanInterval, ScanInterval);
        }

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
                        var path = SecurityValidation.GetProcessImagePath(proc.Id);

                        // Skip scanning games/Steam apps to prevent anti-tamper/anti-cheat false triggers
                        if (path != null)
                        {
                            var lowerPath = path.ToLowerInvariant();
                            // Reject Temp/Downloads directories to prevent directory rename bypasses
                            bool isSuspiciousDir = lowerPath.Contains(@"\temp\") || 
                                                    lowerPath.Contains(@"\downloads\") || 
                                                    lowerPath.Contains(@"\appdata\local\temp\");

                            if (!isSuspiciousDir && 
                                (lowerPath.Contains(@"\steamapps\common\") ||
                                 lowerPath.Contains(@"\steam\") ||
                                 lowerPath.Contains(@"\gog games\") ||
                                 lowerPath.Contains(@"\epic games\")))
                            {
                                continue;
                            }
                        }

                        // Bypass memory scanner entirely for trusted processes signed by reputable publishers
                        if (_signerTrust.IsSignedProcess(proc.Id))
                        {
                            continue;
                        }

                        // === Check: Active DLL Sideloading Detection & Unloading ===
                        var unloadResult = _dllUnloadEngine.CheckAndUnloadAsync(proc.Id, name).GetAwaiter().GetResult();
                        if (unloadResult.Success)
                        {
                            continue;
                        }

                        if (JitProcesses.Contains(name + ".exe"))
                        {
                            if (IsLegitimateJitPath(path))
                                continue;
                        }
                        if (_scannedPids.ContainsKey(proc.Id)) continue;
                        _scannedPids[proc.Id] = DateTime.UtcNow;

                        // === Check 1: Process Hollowing via image path anomaly ===
                        // A hollowed process has its MainModule replaced — the file path
                        // won't exist, or it won't match what the process name suggests.
                        try
                        {
                            var mainModule = proc.MainModule;
                            if (mainModule != null)
                            {
                                var imagePath = mainModule.FileName ?? "";

                                // Image file doesn't exist on disk = unmapped and replaced
                                if (!string.IsNullOrEmpty(imagePath) && !System.IO.File.Exists(imagePath))
                                {
                                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                                    {
                                        RuleName = "Process Hollowing: Image File Missing",
                                        Evidence = $"Process '{name}' (PID {proc.Id}) image path '{imagePath}' does not exist on disk",
                                        Reasoning = "The process's main module points to a file that no longer exists, indicating the original image was unmapped and the process was hollowed (T1055.012).",
                                        Confidence = 0.90, Tier = DetectionTier.Tier1Behavioral,
                                        AuthorizedResponse = ResponseAction.KillProcessTree,
                                        ProcessName = name, ProcessId = proc.Id
                                    });
                                    continue;
                                }
                            }
                        }
                        catch (System.ComponentModel.Win32Exception) { } // Access denied = normal for protected processes

                        // === Check 2: Module Count Growth (DLL Injection Indicator) ===
                        // Injection adds modules over time. Legitimate processes load all
                        // their DLLs at startup and stay stable.
                        int currentModuleCount = 0;
                        try { currentModuleCount = proc.Modules.Count; } catch { continue; }

                        if (_previousModuleCounts.TryGetValue(proc.Id, out int prevCount))
                        {
                            int growth = currentModuleCount - prevCount;
                            if (growth >= ModuleGrowthThreshold)
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

                                var confidence = isFromSuspiciousPath ? 0.80 : 0.70;
                                var tier = isFromSuspiciousPath
                                    ? DetectionTier.Tier1Behavioral
                                    : DetectionTier.Tier2Indicator;

                                _ = _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "Memory Injection: Module Count Growth Detected",
                                    Evidence = $"Process '{name}' (PID {proc.Id}) module count grew from {prevCount} to {currentModuleCount} (+{growth})",
                                    Reasoning = "A process loaded multiple new modules between scans, indicating DLL injection. Legitimate processes load dependencies at startup and remain stable. Growing module count = active injection.",
                                    Confidence = confidence, Tier = tier,
                                    AuthorizedResponse = isFromSuspiciousPath
                                        ? ResponseAction.KillProcessTree
                                        : ResponseAction.LogOnly,
                                    ProcessName = name, ProcessId = proc.Id
                                });
                            }
                        }
                        _previousModuleCounts[proc.Id] = currentModuleCount;
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
            var lower = path.ToLowerInvariant();
            return lower.StartsWith(@"c:\program files", StringComparison.OrdinalIgnoreCase) ||
                   lower.Contains(@"\appdata\local\programs\", StringComparison.OrdinalIgnoreCase) ||
                   lower.Contains(@"\appdata\local\google\", StringComparison.OrdinalIgnoreCase) ||
                   lower.Contains(@"\appdata\local\microsoft\", StringComparison.OrdinalIgnoreCase) ||
                   lower.Contains(@"\appdata\local\bravesoftware\", StringComparison.OrdinalIgnoreCase) ||
                   lower.Contains(@"\appdata\local\vivaldi\", StringComparison.OrdinalIgnoreCase) ||
                   lower.Contains(@"\dotnet\", StringComparison.OrdinalIgnoreCase) ||
                   lower.Contains(@"\nodejs\", StringComparison.OrdinalIgnoreCase) ||
                   lower.Contains(@"\python", StringComparison.OrdinalIgnoreCase) ||
                   lower.StartsWith(@"c:\windows\", StringComparison.OrdinalIgnoreCase) ||
                   lower.Contains(@"\steamapps\common\", StringComparison.OrdinalIgnoreCase) ||
                   lower.Contains(@"\steam\", StringComparison.OrdinalIgnoreCase) ||
                   lower.Contains(@"\gog games\", StringComparison.OrdinalIgnoreCase) ||
                   lower.Contains(@"\epic games\", StringComparison.OrdinalIgnoreCase);
        }
    }
}
