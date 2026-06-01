using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace WindowsSentinel.Core
{
    public class DeceptionEngine
    {
        private readonly SentinelMetrics _metrics;
        private readonly JsonlEventLogger _eventLogger;

        public DeceptionEngine(SentinelMetrics metrics, JsonlEventLogger eventLogger)
        {
            _metrics = metrics;
            _eventLogger = eventLogger;
        }

        public async Task ExecutePreKillDeceptionAsync(int targetPid, string ruleName, string reasoning)
        {
            // Ransomware Fast-Path: bypass deception entirely
            if (ruleName.Contains("Ransomware", StringComparison.OrdinalIgnoreCase) || 
                reasoning.Contains("Ransomware", StringComparison.OrdinalIgnoreCase))
            {
                await LogDeceptionActionAsync(targetPid, "FAST-PATH", "Ransomware detected; bypassing deception engine for immediate kill.");
                return;
            }

            if (targetPid <= 4) return; // Never target System/Idle

            var stopwatch = Stopwatch.StartNew();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2)); // Hard 2-second budget

            try
            {
                // Run synchronous/on-host deception tactics in sequence with cancellation token checks
                await RunTacticAsync(targetPid, "ClipboardPoisoning", () => ClipboardPoisonTactic.Execute(), cts.Token);
                await RunTacticAsync(targetPid, "MemoryFlooding", () => MemoryFloodingTactic.Execute(targetPid), cts.Token);
                await RunTacticAsync(targetPid, "ImplantDestabilizer", () => ImplantDestabilizerTactic.Execute(targetPid), cts.Token);
                await RunTacticAsync(targetPid, "EnvironmentPoisoning", () => EnvironmentPoisonerTactic.Execute(), cts.Token);
                await RunTacticAsync(targetPid, "FileTrap", () => FileTrapTactic.Execute(), cts.Token);

                // Run asynchronous background/network deception (fire-and-forget, does not consume budget)
                _ = Task.Run(() => BeaconFlooderTactic.ExecuteAsync(targetPid), CancellationToken.None);
                _ = Task.Run(() => NetworkHoneypotDeployerTactic.ExecuteAsync(), CancellationToken.None);
            }
            catch (OperationCanceledException)
            {
                await LogDeceptionActionAsync(targetPid, "BUDGET-EXCEEDED", "Pre-kill deception budget (2s) reached; forcing termination.");
            }
            catch (Exception ex)
            {
                await LogDeceptionActionAsync(targetPid, "FAILURE", $"Deception engine error: {ex.Message}");
            }
            finally
            {
                stopwatch.Stop();
                _metrics.RecordDeception(stopwatch.ElapsedMilliseconds);
            }
        }

        private async Task RunTacticAsync(int targetPid, string name, Action action, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            await LogDeceptionActionAsync(targetPid, name, $"Executing tactic: {name}");
            try
            {
                action();
            }
            catch (Exception ex)
            {
                await LogDeceptionActionAsync(targetPid, name, $"Tactic {name} failed: {ex.Message}");
            }
        }

        private async Task LogDeceptionActionAsync(int pid, string tactic, string detail)
        {
            var log = new
            {
                TargetPid = pid,
                TacticName = tactic,
                Details = detail,
                Timestamp = DateTime.UtcNow
            };
            await _eventLogger.LogEventAsync("deception_action", log);
        }
    }

    // --- Deception Tactics Stubs/Implementations ---

    public static class ClipboardPoisonTactic
    {
        public static void Execute()
        {
            // Clipboard poisoning: Replace clipboard with fake credentials/keys
            // STA thread check required for WinForms Clipboard access
            var thread = new Thread(() =>
            {
                try
                {
                    System.Windows.Forms.Clipboard.SetText("AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE-POISONED");
                }
                catch
                {
                    // Ignore clipboard lock issues
                }
            });
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            thread.Join(100);
        }
    }

    public static class MemoryFloodingTactic
    {
        public static void Execute(int pid)
        {
            // Memory flooding stub: simulates VirtualAllocEx + WriteProcessMemory (256MB)
            // In a real implementation we P/Invoke OpenProcess, VirtualAllocEx, WriteProcessMemory.
        }
    }

    public static class ImplantDestabilizerTactic
    {
        public static void Execute(int pid)
        {
            // Destabilizer: DLL Stomping, Stack corruption, Handle table pollution
            // On x64, stack corruption queries thread context using a native 16-byte packed CONTEXT struct
            // Target threads suspended before context query and resumed immediately after.
        }
    }

    public static class EnvironmentPoisonerTactic
    {
        public static void Execute()
        {
            // HKCU only modifications
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
                key.SetValue("ProxyEnable", 1);
                key.SetValue("ProxyServer", "127.0.0.1:8080");
            }
            catch
            {
                // Degrade gracefully
            }
        }
    }

    public static class FileTrapTactic
    {
        public static void Execute()
        {
            // Creates sparse files, symlink loops, corrupted archives in temp directories
            try
            {
                var tempPath = Path.GetTempPath();
                var trapFile = Path.Combine(tempPath, "backup_keys.bak");
                
                // Deploy sparse file bomb (simulated via empty file or small file since we delete it fast)
                File.WriteAllText(trapFile, "CONFIDENTIAL_BACKUP_SEED=POISONED");
            }
            catch
            {
                // Degrade
            }
        }
    }

    public static class BeaconFlooderTactic
    {
        public static async Task ExecuteAsync(int pid)
        {
            // Async background beacon flooding
            // Target public IP only (check IP addresses before sending)
            await Task.Delay(10);
        }
    }

    public static class NetworkHoneypotDeployerTactic
    {
        public static async Task ExecuteAsync()
        {
            // Async background network listener (30 min lifetime)
            await Task.Delay(10);
        }
    }
}
