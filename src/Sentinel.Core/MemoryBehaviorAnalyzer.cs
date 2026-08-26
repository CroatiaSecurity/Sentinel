using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// System-wide process integrity (permanent product law — do not disable):
    /// 1. Every mapped module is identity-checked (path + Microsoft signature).
    ///    Foreign modules are unloaded immediately via <see cref="DllUnloadEngine"/>
    ///    (constraint: DLL unloaders may remediate without a chain; Tier1, never demoted).
    /// 2. Missing image path → Tier2 LogOnly.
    /// Games skipped for handle safety only (Denuvo). Module *count* is not a signal.
    /// </summary>
    public sealed class MemoryBehaviorAnalyzer : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly DllUnloadEngine _dllUnloadEngine;
        private readonly SignerTrustService _signerTrust;
        private readonly ILogger<MemoryBehaviorAnalyzer> _logger;
        private readonly System.Threading.Timer _timer;

        private readonly ConcurrentDictionary<int, DateTime> _scannedPids = new();
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(5);

        private static readonly HashSet<string> JitProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "java.exe", "javaw.exe", "node.exe", "python.exe", "dotnet.exe",
            "pwsh.exe", "powershell.exe", "chrome.exe", "msedge.exe", "firefox.exe",
            "brave.exe", "discord.exe", "slack.exe", "teams.exe", "spotify.exe",
            "code.exe", "cursor.exe", "steamwebhelper.exe", "ceprkac.exe",
            "msedgewebview2.exe",
            "svchost.exe", "explorer.exe", "dllhost.exe",
        };

        public MemoryBehaviorAnalyzer(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            SignerTrustService signerTrust,
            DllUnloadEngine dllUnloadEngine,
            ILogger<MemoryBehaviorAnalyzer> logger)
        {
            _ = fusionEngine;
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

                        // Workaround only: never open memory of game/anti-cheat processes
                        // (path + name + fail-closed when path unresolved — Denuvo / FM)
                        if (SecurityValidation.IsGameOrAntiCheatProcess(proc.Id, path) ||
                            !NativeProcessMemory.CanInspect(proc.Id, path))
                            continue;

                        // Identity-check every mapped module; unload foreign ones now.
                        _ = _dllUnloadEngine
                            .CheckAndUnloadAsync(proc.Id, name)
                            .GetAwaiter().GetResult();

                        if (_signerTrust.IsSignedProcess(proc.Id))
                            continue;

                        if (JitProcesses.Contains(name + ".exe"))
                            continue;

                        if (_scannedPids.ContainsKey(proc.Id))
                            continue;
                        _scannedPids[proc.Id] = DateTime.UtcNow;

                        // Missing image alone is weak — observe only (not kill on identity/path absence)
                        if (!string.IsNullOrEmpty(path) &&
                            !path!.StartsWith(@"\\") &&
                            path.Length > 3 &&
                            !File.Exists(path))
                        {
                            _ = _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Process Hollowing: Image File Missing",
                                Evidence = $"Process '{name}' (PID {proc.Id}) image path '{path}' does not exist on disk",
                                Reasoning = "Possible hollowing indicator (T1055.012). Observe-first LogOnly until " +
                                            "corroborating behavioral signals prove malice.",
                                Confidence = 0.75,
                                Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = name,
                                ProcessId = proc.Id,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["WeakObserveSeed"] = "true",
                                    ["ImagePath"] = path ?? ""
                                }
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

        public void Dispose() => _timer.Dispose();
    }
}
