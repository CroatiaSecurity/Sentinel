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
            // Apply DLL search path hardening early
            HardeningModule.ApplyOrFail();

            // Secure Sentinel's installation directory permissions
            HardeningModule.SecureInstallationDirectory();

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

                    var threatReportingConfig = new ThreatReportingConfig();
                    hostContext.Configuration.GetSection("ThreatReporting").Bind(threatReportingConfig);

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
                    services.AddSingleton(threatReportingConfig);

                    // Infrastructure & Utilities
                    services.AddSingleton<SentinelMetrics>();
                    services.AddSingleton<JsonlEventLogger>(_ => new JsonlEventLogger(config.LogPath));
                    services.AddSingleton<EventGraph>();
                    services.AddSingleton<ProcessAncestryCache>();
                    services.AddSingleton<SecureCacheStore>();
                    services.AddSingleton<HashReputationService>();
                    services.AddSingleton<QuarantineManager>();
                    services.AddSingleton<SafeProcessExemptionRegistry>();
                    services.AddSingleton<FileVerdictAds>();

                    // Utility services (SYSTEM-session safe only)
                    services.AddSingleton<UsbDeviceFingerprinter>();
                    services.AddSingleton<IoCScanner>();
                    services.AddSingleton<ParentPidSpoofDetector>();
                    services.AddSingleton<ToastService>();

                    // Engines
                    services.AddSingleton<TelemetryFusionEngine>();
                    services.AddSingleton<AdvancedResponseEngine>();
                    services.AddSingleton<BehavioralCorrelationEngine>();
                    services.AddSingleton<AllowlistService>();
                    services.AddSingleton<ScoringEngine>();
                    services.AddSingleton<ChainTracer>();
                    services.AddSingleton<DllUnloadEngine>();
                    services.AddSingleton<IncidentResponseService>();

                    // Rules
                    services.AddTransient<IDetectionRule, LsassAccessRule>();
                    services.AddTransient<IDetectionRule, RansomwareDetectionRule>();
                    services.AddTransient<IDetectionRule, ReverseShellRule>();
                    services.AddTransient<IDetectionRule, ThreatIntelInjectionRule>();
                    services.AddTransient<IDetectionRule, PrivilegeEscalationRule>();
                    services.AddTransient<IDetectionRule, AttackToolsRule>();
                    services.AddTransient<IDetectionRule, CampaignIocRule>();
                    services.AddTransient<IDetectionRule, UnsignedBinaryRule>();
                    services.AddTransient<IDetectionRule, CampaignDetectionRule>();
                    services.AddTransient<IDetectionRule, VerdictGateRule>();

                    // Detection Engine
                    services.AddSingleton<DetectionEngine>();

                    // IMonitor implementations (started by SentinelService)
                    services.AddSingleton<IMonitor, DnsQueryMonitor>();
                    services.AddSingleton<IMonitor, EtwProcessMonitor>();
                    services.AddSingleton<IMonitor, EtwThreatIntelMonitor>();

                    // Monitors injected into SentinelService
                    services.AddSingleton<WmiProcessMonitor>();
                    services.AddSingleton<FileActivityMonitor>();
                    services.AddSingleton<NetworkMonitor>();
                    services.AddSingleton<LsassDumpCanaryMonitor>();
                    services.AddSingleton<RouteTableMonitor>();
                    services.AddSingleton<HollowProcessMonitor>();
                    services.AddSingleton<MemoryBehaviorAnalyzer>();
                    services.AddSingleton<TokenIntegrityMonitor>();
                    services.AddSingleton<CredentialCanaryMonitor>();
                    services.AddSingleton<LocalServerMonitor>();
                    services.AddSingleton<AppNetworkPolicyMonitor>();

                    // Startup & Health
                    services.AddHostedService<StartupSelfTest>();
                    services.AddHostedService<SentinelHealthCheck>();

                    // BackgroundService monitors
                    services.AddHostedService<SentinelService>();
                    services.AddHostedService<AntiTamperGuard>();
                    services.AddHostedService<RansomwareIoMonitor>();
                    services.AddHostedService<ArpSpoofMonitor>();
                    services.AddHostedService<BluetoothMonitor>();
                    services.AddHostedService<CanaryFileMonitor>();
                    services.AddHostedService<ChromeCredentialGuardMonitor>();
                    services.AddHostedService<ChromeSessionGuardMonitor>();
                    services.AddHostedService<DataExfiltrationMonitor>();
                    services.AddHostedService<DeviceInstallMonitor>();
                    services.AddHostedService<DllEntropyAnalyzer>();
                    services.AddHostedService<DllLoadFailureMonitor>();
                    services.AddHostedService<DnsResponseValidationMonitor>();
                    services.AddHostedService<FirefoxCredentialGuardMonitor>();
                    services.AddHostedService<FirewallIntegrityMonitor>();
                    services.AddHostedService<GatewayFingerprintMonitor>();
                    services.AddHostedService<MicrosoftAccountGuardMonitor>();
                    services.AddHostedService<PublicIpMonitor>();
                    services.AddHostedService<RemoteAccessMonitor>();
                    services.AddHostedService<RuntimeModuleIntegrityMonitor>();
                    services.AddHostedService<ScheduledTaskMonitor>();
                    services.AddHostedService<SecureBootIntegrityMonitor>();
                    services.AddHostedService<SyscallStubMonitor>();
                    services.AddHostedService<TlsCertificateMonitor>();
                    services.AddHostedService<UacBypassSurfaceMonitor>();
                    services.AddHostedService<WifiSecurityMonitor>();
                    services.AddHostedService<WindowsUpdateIntegrityMonitor>();
                    services.AddHostedService<WmiPersistenceMonitor>();
                    services.AddHostedService<WorkFoldersExfilMonitor>();
                    services.AddHostedService<AdsDataStagingMonitor>();
                    services.AddSingleton<BeaconingDetector>();
                    services.AddHostedService<BeaconingDetector>(sp => sp.GetRequiredService<BeaconingDetector>());
                    services.AddHostedService<ModuleValidationMonitor>();
                    services.AddHostedService<DiskWideDllScanner>();
                    services.AddSingleton<BehavioralBaselineService>();
                    services.AddHostedService<BehavioralBaselineService>(sp => sp.GetRequiredService<BehavioralBaselineService>());
                    services.AddHostedService<PhantomDeviceMonitor>();
                    services.AddHostedService<FileVerdictScanner>();
                    services.AddHostedService<WebcamHijackMonitor>();
                    services.AddHostedService<ConsultantSignalIngestor>();
                    services.AddHostedService<RegistryMonitor>();
                });
    }
}
