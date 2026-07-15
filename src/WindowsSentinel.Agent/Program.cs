using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using WindowsSentinel.Core;

namespace WindowsSentinel.Agent
{
    public class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeConsole();

        // ── Self-restart state ────────────────────────────────────────────
        // Tracks how many times this process has already re-launched itself so
        // we can give up after too many rapid failures (crash loop guard).
        private const int MaxSelfRestarts = 5;
        private const string RestartCountEnvVar = "WS_AGENT_RESTART_COUNT";
        // ─────────────────────────────────────────────────────────────────

        [STAThread]
        public static void Main(string[] args)
        {
            // ── Crash handlers (registered first, before any allocations) ──
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                LogCrash("UnhandledException", e.ExceptionObject as Exception);
                // v1.3.9: On terminal crash, schedule a self-relaunch before we exit.
                // This covers exception types that kill the process before the finally
                // block in Run() can fire (e.g., StackOverflowException-adjacent CLR faults).
                if (e.IsTerminating)
                    ScheduleDelayedRelaunch(args);
            };

            System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (s, e) =>
            {
                LogCrash("UnobservedTaskException", e.Exception);
                e.SetObserved();
            };

            System.Windows.Forms.Application.ThreadException += (s, e) =>
            {
                LogCrash("ThreadException", e.Exception);
            };

            // ── Hardening ─────────────────────────────────────────────────
            HardeningModule.ApplyOrFail();

            // Detach from parent console window (installer / Run key launch)
            try { FreeConsole(); } catch { }

            // ── Build & run host ──────────────────────────────────────────
            var host = CreateHostBuilder(args).Build();

            // v1.3.9: Wire the orchestrator into the detection engine so
            // agent-side detections flow through incident grouping and response
            // coordination instead of falling back to the bare response engine.
            var detectionEngine = host.Services.GetRequiredService<DetectionEngine>();
            var orchestrator    = host.Services.GetRequiredService<SentinelOrchestrator>();
            detectionEngine.SetOrchestrator(orchestrator);

            try
            {
                host.Run();
            }
            catch (Exception ex)
            {
                // Host-level crash (e.g., a BackgroundService threw out of ExecuteAsync
                // in a way the generic host didn't swallow)
                LogCrash("HostCrash", ex);
            }
            finally
            {
                // v1.3.9: Self-restart on exit — covers all normal and abnormal exits
                // except the IsTerminating path above (which calls ScheduleDelayedRelaunch).
                // The AgentWatchdog in the Service is the authoritative restarter; this is
                // a belt-and-suspenders fallback for the window before the watchdog notices.
                TryImmediateRestart(args);
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // Self-restart helpers
        // ═══════════════════════════════════════════════════════════════

        /// <summary>
        /// Attempts to re-launch this process immediately.
        /// Called from the finally block after the host exits.
        ///
        /// Guards:
        ///   - Only restarts on unclean exit (non-zero expected lifecycle exits are
        ///     not currently signalled, so we restart on every exit — the watchdog
        ///     dedup window prevents storms).
        ///   - Restart counter in the environment prevents crash-loop amplification
        ///     beyond MaxSelfRestarts.
        /// </summary>
        private static void TryImmediateRestart(string[] args)
        {
            try
            {
                // Read the restart counter from the environment (set on the child process below)
                int restartCount = 0;
                var envVal = Environment.GetEnvironmentVariable(RestartCountEnvVar);
                if (envVal != null) int.TryParse(envVal, out restartCount);

                if (restartCount >= MaxSelfRestarts)
                {
                    // Too many rapid self-restarts — let the AgentWatchdog (Service side) handle it
                    LogCrash("SelfRestartAborted",
                        new InvalidOperationException(
                            $"Self-restart limit ({MaxSelfRestarts}) reached. " +
                            "Waiting for AgentWatchdog to recover the agent."));
                    return;
                }

                var exePath = Environment.ProcessPath
                    ?? Process.GetCurrentProcess().MainModule?.FileName;
                if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                    return;

                // Brief cooldown to avoid tight restart loops on repeated immediate crashes
                Thread.Sleep(2000);

                var psi = new ProcessStartInfo(exePath)
                {
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    // Pass incremented counter so the child knows how many times this has been tried
                    Environment = { [RestartCountEnvVar] = (restartCount + 1).ToString() }
                };

                // Forward original args
                foreach (var a in args)
                    psi.ArgumentList.Add(a);

                Process.Start(psi);
            }
            catch
            {
                // Best-effort — if we can't self-restart, the AgentWatchdog will cover it
            }
        }

        /// <summary>
        /// Called from the UnhandledException handler when IsTerminating=true.
        /// The process is about to die before the finally block can run, so we
        /// spawn a helper cmd.exe to re-launch us after a short sleep.
        /// </summary>
        private static void ScheduleDelayedRelaunch(string[] args)
        {
            try
            {
                var envVal = Environment.GetEnvironmentVariable(RestartCountEnvVar);
                int restartCount = 0;
                if (envVal != null) int.TryParse(envVal, out restartCount);
                if (restartCount >= MaxSelfRestarts) return;

                var exePath = Environment.ProcessPath
                    ?? Process.GetCurrentProcess().MainModule?.FileName;
                if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                    return;

                // cmd /c "ping -n 4 127.0.0.1 >nul & start "" "<exePath>""
                // ping -n 4 gives ~3s delay without needing timeout.exe
                var cmd = $"/c ping -n 4 127.0.0.1 >nul & start \"\" \"{exePath}\"";
                Process.Start(new ProcessStartInfo("cmd.exe", cmd)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    Environment = { [RestartCountEnvVar] = (restartCount + 1).ToString() }
                });
            }
            catch { }
        }

        // ═══════════════════════════════════════════════════════════════
        // Crash logger
        // ═══════════════════════════════════════════════════════════════

        private static void LogCrash(string type, Exception? ex)
        {
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var crashLog = Path.Combine(programData, "WindowsSentinel", "agent_crash.log");
                var msg = $"[{DateTime.UtcNow:o}] [{type}] {ex?.Message}\n{ex?.StackTrace}" +
                          $"\nInnerException: {ex?.InnerException?.Message}\n{ex?.InnerException?.StackTrace}" +
                          $"\n-----------------------------------\n";
                File.AppendAllText(crashLog, msg);
            }
            catch { }
        }

        // ═══════════════════════════════════════════════════════════════
        // Host builder
        // ═══════════════════════════════════════════════════════════════

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((_, config) =>
                {
                    // Resolve appsettings relative to the exe directory, not CWD.
                    // This matters when the process is launched by the AgentWatchdog
                    // or a scheduled task where CWD may be System32.
                    config.SetBasePath(AppContext.BaseDirectory);
                })
                .ConfigureServices((hostContext, services) =>
                {
                    var config = new SentinelConfig();
                    hostContext.Configuration.GetSection("Sentinel").Bind(config);
                    services.AddSingleton(config);

                    var threatReportingConfig = new ThreatReportingConfig();
                    hostContext.Configuration.GetSection("ThreatReporting").Bind(threatReportingConfig);
                    services.AddSingleton(threatReportingConfig);

                    // Infrastructure required by monitors
                    services.AddSingleton<SentinelMetrics>();
                    services.AddSingleton<ThreatReportService>();
                    services.AddSingleton<JsonlEventLogger>(_ => new JsonlEventLogger(config.LogPath));
                    services.AddSingleton<EventGraph>();
                    services.AddSingleton<ProcessAncestryCache>();
                    services.AddSingleton<SecureCacheStore>();
                    services.AddSingleton<HashReputationService>();
                    services.AddSingleton<QuarantineManager>();
                    services.AddSingleton<SafeProcessExemptionRegistry>();
                    services.AddSingleton<FileVerdictAds>();
                    services.AddSingleton<IoCScanner>();
                    services.AddSingleton<AllowlistService>();
                    services.AddSingleton<SignerTrustService>();
                    services.AddSingleton<ScoringEngine>();
                    services.AddSingleton<ChainTracer>();
                    services.AddSingleton<DllUnloadEngine>();
                    services.AddSingleton<FileReputationEngine>();
                    services.AddSingleton<DetectionEngine>();

                    // v1.3.2: Orchestration layer
                    services.AddSingleton<IncidentManager>();
                    services.AddSingleton<MonitorRegistry>();
                    services.AddSingleton<StartupSequencer>();
                    services.AddSingleton<ContextBus>();
                    services.AddSingleton<ResponseCoordinator>();
                    services.AddSingleton<SentinelOrchestrator>();
                    services.AddSingleton<TelemetryFusionEngine>();
                    services.AddSingleton<AdvancedResponseEngine>();
                    services.AddSingleton<BehavioralCorrelationEngine>();

                    // Rules
                    services.AddTransient<IDetectionRule, LsassAccessRule>();
                    services.AddTransient<IDetectionRule, RansomwareDetectionRule>();
                    services.AddTransient<IDetectionRule, ReverseShellRule>();
                    services.AddTransient<IDetectionRule, UnsignedBinaryRule>();
                    services.AddTransient<IDetectionRule, VerdictGateRule>();
                    services.AddTransient<IDetectionRule, ClickFixDetectionRule>();
                    services.AddTransient<IDetectionRule, DllSideloadingDetectionRule>();
                    services.AddTransient<IDetectionRule, ChromeRemoteDebuggingRule>();
                    services.AddSingleton<IDetectionRule, DynamicRulesEvaluator>();

                    // Tray Icon
                    services.AddHostedService<TrayIconService>();

                    // User-session monitors (require user desktop/registry hive)
                    services.AddHostedService<ClipboardSanitizer>();
                    services.AddHostedService<ScreenCaptureMonitor>();
                    services.AddHostedService<WebcamMicMonitor>();
                    services.AddHostedService<AudioHijackMonitor>();
                    services.AddHostedService<MicSessionMonitor>();
                    services.AddHostedService<NeuroBehaviorVisualMonitor>();
                    services.AddHostedService<BrowserExtensionMonitor>();
                    services.AddHostedService<PhantomKeystrokeGuard>();
                    services.AddHostedService<ClickjackingGuard>();
                    services.AddHostedService<WebcamHijackMonitor>();
                    services.AddHostedService<ShellWatchdog>();
                    services.AddSingleton<IsolationResponseEngine>();
                });
    }
}
