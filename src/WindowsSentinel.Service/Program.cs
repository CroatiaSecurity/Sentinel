using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
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
                    hostContext.Configuration.GetSection("Sentinel").Bind(config);

                    // CLI flag overrides
                    for (int i = 0; i < args.Length; i++)
                    {
                        if (args[i].Equals("--active-response", StringComparison.OrdinalIgnoreCase))
                        {
                            config.ActiveResponse = true;
                        }
                        else if ((args[i].Equals("--log", StringComparison.OrdinalIgnoreCase) || args[i].Equals("-l", StringComparison.OrdinalIgnoreCase)) && i + 1 < args.Length)
                        {
                            config.LogPath = args[++i];
                        }
                        else if ((args[i].Equals("--watch", StringComparison.OrdinalIgnoreCase) || args[i].Equals("-w", StringComparison.OrdinalIgnoreCase)) && i + 1 < args.Length)
                        {
                            config.WatchPath = args[++i];
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
                    services.AddSingleton<FileActivityMonitor>();
                    services.AddSingleton<ClipboardSanitizer>();
                    services.AddSingleton<UsbDeviceFingerprinter>();
                    services.AddSingleton<AppNetworkPolicyMonitor>();
                    services.AddSingleton<DnsBlocklistEngine>();

                    // Service Background Worker
                    services.AddHostedService<SentinelService>();
                });
    }
}
