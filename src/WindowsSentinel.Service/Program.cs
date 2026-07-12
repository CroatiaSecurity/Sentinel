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

            var host = CreateHostBuilder(args).Build();

            // Wire up ReinfectionCorrelator -> AdvancedResponseEngine (avoids circular DI)
            var responseEngine = host.Services.GetService<AdvancedResponseEngine>();
            var correlator = host.Services.GetService<ReinfectionCorrelator>();
            if (responseEngine != null && correlator != null)
                responseEngine.SetReinfectionCorrelator(correlator);

            host.Run();
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

                    var appIntegrityConfig = new ApplicationIntegrityConfig();
                    hostContext.Configuration.GetSection("ApplicationIntegrity").Bind(appIntegrityConfig);
                    services.AddSingleton(appIntegrityConfig);

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
                    services.AddSingleton<ThreatReportService>();
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
                    services.AddSingleton<SignerTrustService>();
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
                    services.AddTransient<IDetectionRule, ClickFixDetectionRule>();
                    services.AddTransient<IDetectionRule, DllSideloadingDetectionRule>();
                    services.AddTransient<IDetectionRule, ChromeRemoteDebuggingRule>();
                    services.AddSingleton<IDetectionRule, DynamicRulesEvaluator>();

                    // Detection Engine
                    services.AddSingleton<FileReputationEngine>();
                    services.AddSingleton<DetectionEngine>();

                    // v1.3.2: Orchestration layer
                    services.AddSingleton<IncidentManager>();
                    services.AddSingleton<MonitorRegistry>();
                    services.AddSingleton<StartupSequencer>();
                    // v1.3.3: Context Bus + Response Coordinator
                    services.AddSingleton<ContextBus>();
                    services.AddSingleton<ResponseCoordinator>();
                    services.AddSingleton<SentinelOrchestrator>();

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
                    services.AddHostedService<CveShieldHardener>();
                    services.AddSingleton<RansomwareIoMonitor>();
                    services.AddHostedService<RansomwareIoMonitor>(sp => sp.GetRequiredService<RansomwareIoMonitor>());
                    services.AddHostedService<ArpSpoofMonitor>();
                    services.AddHostedService<BluetoothMonitor>();
                    services.AddHostedService<CanaryFileMonitor>();
                    services.AddHostedService<BrowserCredentialGuard>();
                    services.AddHostedService<DataExfiltrationMonitor>();
                    services.AddHostedService<DllEntropyAnalyzer>();
                    services.AddHostedService<DllLoadFailureMonitor>();
                    services.AddHostedService<DnsResponseValidationMonitor>();
                    services.AddHostedService<FirewallIntegrityMonitor>();
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
                    services.AddHostedService<NetworkInterfaceGuard>();
                    services.AddHostedService<WindowsUpdateIntegrityMonitor>();
                    services.AddHostedService<WmiPersistenceMonitor>();
                    services.AddHostedService<WorkFoldersExfilMonitor>();
                    services.AddHostedService<AdsDataStagingMonitor>();
                    services.AddSingleton<BeaconingDetector>();
                    services.AddHostedService<BeaconingDetector>(sp => sp.GetRequiredService<BeaconingDetector>());
                    services.AddHostedService<ModuleValidationMonitor>();
                    services.AddHostedService<DiskWideDllScanner>();
                    services.AddHostedService<DeviceInstallMonitor>();
                    services.AddHostedService<GatewayFingerprintMonitor>();
                    services.AddSingleton<BehavioralBaselineService>();
                    services.AddHostedService<BehavioralBaselineService>(sp => sp.GetRequiredService<BehavioralBaselineService>());
                    services.AddSingleton<PhantomDeviceMonitor>();
                    services.AddHostedService<PhantomDeviceMonitor>(sp => sp.GetRequiredService<PhantomDeviceMonitor>());
                    services.AddHostedService<FileVerdictScanner>();
                    services.AddHostedService<ConsultantSignalIngestor>();
                    services.AddHostedService<RegistryMonitor>();
                    services.AddHostedService<GhostProcessMonitor>();
                    services.AddHostedService<CriticalServiceGuard>();
                    services.AddHostedService<NullSessionGuard>();
                    services.AddHostedService<HostsFileGuard>();
                    services.AddHostedService<BrowserDnsPolicyGuard>();
                    services.AddHostedService<MtpTransferGuard>();
                    services.AddHostedService<BootIntegrityGuard>();
                    services.AddSingleton<PersistentConnectionMonitor>();
                    services.AddHostedService<PersistentConnectionMonitor>(sp => sp.GetRequiredService<PersistentConnectionMonitor>());
                    services.AddSingleton<ReinfectionCorrelator>();
                    services.AddHostedService<ReinfectionCorrelator>(sp => sp.GetRequiredService<ReinfectionCorrelator>());
                    services.AddHostedService<NetworkReinfectionDetector>();
                    services.AddHostedService<AcousticThreatMonitor>();
                    services.AddSingleton<IsolationResponseEngine>();

                    // v1.0.1: Blind spot monitors
                    services.AddHostedService<VolumeMountMonitor>();
                    services.AddHostedService<WslMonitor>();
                    services.AddHostedService<RawDiskAccessMonitor>();
                    services.AddHostedService<NetworkShareMonitor>();
                    services.AddHostedService<EphemeralProcessMonitor>();
                    services.AddHostedService<PrintSpoolerMonitor>();
                    services.AddHostedService<SandboxEscapeMonitor>();
                    services.AddHostedService<AppDnsExfilMonitor>();

                    // v1.0.2: Cast device guard
                    services.AddHostedService<CastDeviceGuard>();

                    // v1.1.0: Defensive isolation containment
                    services.AddSingleton<PseudoSandbox>();
                    services.AddHostedService<PseudoSandbox>(sp => sp.GetRequiredService<PseudoSandbox>());

                    // v1.2.5: Application Integrity (Cuckoo Egg Detection)
                    services.AddHostedService<ApplicationIntegrityMonitor>();

                    // v1.3.9: Agent watchdog — relaunches WindowsSentinel.Agent.exe in the
                    // user session if it dies, and fires an anti-tamper alert on repeated kills
                    services.AddHostedService<AgentWatchdog>();
                });
    }
}
