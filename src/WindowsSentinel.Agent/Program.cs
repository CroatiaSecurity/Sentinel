using System;
using System.Runtime.InteropServices;
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

        [STAThread]
        public static void Main(string[] args)
        {
            // Apply DLL search path hardening early
            HardeningModule.ApplyOrFail();

            // FreeConsole on startup to detach from parent CLI window
            try
            {
                FreeConsole();
            }
            catch
            {
                // Degrade gracefully if not launched from console
            }

            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureServices((hostContext, services) =>
                {
                    var config = new SentinelConfig();
                    hostContext.Configuration.GetSection("Sentinel").Bind(config);
                    services.AddSingleton(config);

                    // Infrastructure required by monitors
                    services.AddSingleton<SentinelMetrics>();
                    services.AddSingleton<JsonlEventLogger>(_ => new JsonlEventLogger(config.LogPath));
                    services.AddSingleton<EventGraph>();
                    services.AddSingleton<ProcessAncestryCache>();
                    services.AddSingleton<SecureCacheStore>();
                    services.AddSingleton<HashReputationService>();
                    services.AddSingleton<QuarantineManager>();
                    services.AddSingleton<DetectionEngine>();
                    services.AddSingleton<TelemetryFusionEngine>();
                    services.AddSingleton<AdvancedResponseEngine>();
                    services.AddSingleton<BehavioralCorrelationEngine>();

                    // Rules
                    services.AddTransient<IDetectionRule, LsassAccessRule>();
                    services.AddTransient<IDetectionRule, RansomwareDetectionRule>();
                    services.AddTransient<IDetectionRule, ReverseShellRule>();
                    services.AddTransient<IDetectionRule, UnsignedBinaryRule>();

                    // Tray Icon
                    services.AddHostedService<TrayIconService>();

                    // User-session utility services (Clipboard needs STA/user session)
                    services.AddSingleton<ClipboardSanitizer>();

                    // User-session monitors (require user desktop/registry hive)
                    services.AddHostedService<ScreenCaptureMonitor>();
                    services.AddHostedService<WebcamMicMonitor>();
                    services.AddHostedService<AudioHijackMonitor>();
                    services.AddHostedService<MicSessionMonitor>();
                    services.AddHostedService<NeuroBehaviorVisualMonitor>();
                    services.AddHostedService<BrowserExtensionMonitor>();
                    services.AddSingleton<PhantomKeystrokeGuard>();
                });
    }
}
