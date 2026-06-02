using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core;

namespace WindowsSentinel.Service
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseWindowsService()
                .ConfigureServices((hostContext, services) =>
                {
                    // Configuration
                    var config = new SentinelConfig();
                    // Simple CLI flag parse
                    foreach (var arg in args)
                    {
                        if (arg.Equals("--active-response", StringComparison.OrdinalIgnoreCase))
                        {
                            config.ActiveResponse = true;
                        }
                    }
                    services.AddSingleton(config);

                    // Infrastructure & Utilities
                    services.AddSingleton<SentinelMetrics>();
                    services.AddSingleton<JsonlEventLogger>(_ => new JsonlEventLogger(config.LogPath));
                    services.AddSingleton<EventGraph>();
                    services.AddSingleton<ProcessAncestryCache>();
                    services.AddSingleton<SecureCacheStore>();
                    services.AddSingleton<HashReputationService>();
                    services.AddSingleton<QuarantineManager>();
                    
                    // Engines
                    services.AddSingleton<TelemetryFusionEngine>();
                    services.AddSingleton<DeceptionEngine>();
                    services.AddSingleton<AdvancedResponseEngine>();
                    services.AddSingleton<BehavioralCorrelationEngine>();

                    // Rules
                    services.AddTransient<IDetectionRule, LsassAccessRule>();
                    services.AddTransient<IDetectionRule, RansomwareDetectionRule>();
                    services.AddTransient<IDetectionRule, ReverseShellRule>();
                    services.AddTransient<IDetectionRule, UnsignedBinaryRule>();

                    // Detection Engine
                    services.AddSingleton<DetectionEngine>();

                    // Monitors/Background items
                    services.AddSingleton<WmiProcessMonitor>();
                    services.AddSingleton<ClipboardSanitizer>();
                    services.AddSingleton<UsbDeviceFingerprinter>();
                    services.AddSingleton<AppNetworkPolicyMonitor>();
                    services.AddSingleton<DnsBlocklistEngine>();

                    // Service Background Worker
                    services.AddHostedService<SentinelService>();
                });
    }
}
