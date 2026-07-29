using System;
using System.Threading;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Sentinel.Core;

namespace Sentinel.Service
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            // DIAGNOSTIC: Write immediately on process start, before anything else
            try
            {
                System.IO.File.AppendAllText(
                    System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "Sentinel", "startup_trace.log"),
                    $"[{DateTime.UtcNow:O}] Main() entered. Args: {string.Join(" ", args)}\n");
            }
            catch { }

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

            // DIAGNOSTIC v1.4.8: Log unhandled exceptions that kill the host.
            // The service was dying after ~16 seconds with no crash trace — this
            // catches whatever unobserved Task exception is triggering host shutdown.
            AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            {
                var ex = e.ExceptionObject as Exception;
                try
                {
                    var msg = $"[FATAL] UnhandledException in AppDomain: {ex?.GetType().Name}: {ex?.Message}\n{ex?.StackTrace}";
                    System.IO.File.AppendAllText(
                        System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                            "Sentinel", "fatal_crash.log"),
                        $"[{DateTime.UtcNow:O}] {msg}\n\n");
                }
                catch { }
            };

            TaskScheduler.UnobservedTaskException += (_, e) =>
            {
                try
                {
                    var msg = $"[UNOBSERVED] {e.Exception?.GetType().Name}: {e.Exception?.InnerException?.Message ?? e.Exception?.Message}\n{e.Exception?.InnerException?.StackTrace ?? e.Exception?.StackTrace}";
                    System.IO.File.AppendAllText(
                        System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                            "Sentinel", "fatal_crash.log"),
                        $"[{DateTime.UtcNow:O}] {msg}\n\n");
                }
                catch { }
                e.SetObserved(); // Prevent process crash from unobserved tasks
            };

            // STABILITY v1.4.9: Use host.StartAsync() + manual infinite wait instead of host.Run().
            // host.Run() returns when ANY hosted service task completes, killing the process.
            // We start the host and then block Main forever — only SCM stop signal exits.
            try
            {
                System.IO.File.AppendAllText(
                    System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "Sentinel", "startup_trace.log"),
                    $"[{DateTime.UtcNow:O}] Calling host.StartAsync()...\n");
            }
            catch { }

            await host.StartAsync();

            try
            {
                System.IO.File.AppendAllText(
                    System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "Sentinel", "startup_trace.log"),
                    $"[{DateTime.UtcNow:O}] host.StartAsync() completed. Blocking Main forever (ManualResetEvent)...\n");
            }
            catch { }

            // Block Main() forever. NOTHING can make this return except process termination.
            // This prevents the .NET Host's "BackgroundService completed → shutdown" behavior
            // from propagating to a process exit.
            Thread.Sleep(Timeout.Infinite);
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseWindowsService()
                .ConfigureServices((hostContext, services) =>
                {
                    // STABILITY v1.4.8: Prevent host shutdown when a BackgroundService
                    // completes or throws. Without this, if ANY MonitorGroup's ExecuteAsync
                    // returns (e.g., monitor startup failure), the entire host shuts down.
                    services.Configure<HostOptions>(opts =>
                    {
                        opts.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.Ignore;
                        opts.ServicesStartConcurrently = false;
                        opts.ServicesStopConcurrently = true;
                        opts.ShutdownTimeout = TimeSpan.FromSeconds(10);
                    });

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

                    // Unified ETW Session — single session subscribing to 9 system providers
                    // Provides event-driven telemetry at ~50ms latency for all monitors
                    services.AddSingleton<UnifiedEtwSession>();
                    services.AddSingleton<EtwEventDispatcher>();

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
                    services.AddTransient<IDetectionRule, NpmSupplyChainRule>();
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

                    // Monitors injected into SentinelService (singleton for cross-service access)
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

                    // Startup & Health (always start immediately, outside groups)
                    services.AddHostedService<StartupSelfTest>();
                    services.AddHostedService<SentinelHealthCheck>();

                    // Core SentinelService (manages IMonitor lifecycle + ProcessAncestryCache)
                    services.AddHostedService<SentinelService>();

                    // ─────────────────────────────────────────────────────────────────
                    // v1.4.4: Monitor Groups — replaces flat AddHostedService registrations.
                    // Groups provide staggered startup, independent failure restart, and
                    // priority-based ordering. Critical monitors start first with unlimited
                    // restart; peripheral monitors start last with limited restart.
                    // ─────────────────────────────────────────────────────────────────

                    // Singletons that need to be accessible via DI (referenced by other components)
                    services.AddSingleton<BeaconingDetector>();
                    services.AddSingleton<RansomwareIoMonitor>();
                    services.AddSingleton<BehavioralBaselineService>();
                    services.AddSingleton<PhantomDeviceMonitor>();
                    services.AddSingleton<PersistentConnectionMonitor>();
                    services.AddSingleton<ReinfectionCorrelator>();
                    services.AddSingleton<PseudoSandbox>();
                    services.AddSingleton<IsolationResponseEngine>();

                    // ── Group 1: Critical (Self-Protection) ──────────────────────────
                    // Starts immediately, restarts indefinitely. These monitors protect
                    // Sentinel itself and must never stay down.
                    services.AddSingleton<IHostedService>(sp =>
                    {
                        var monitors = new List<IHostedService>
                        {
                            sp.GetRequiredService<AntiTamperGuard>(),
                            sp.GetRequiredService<IPSecIntegrityGuard>(),
                            sp.GetRequiredService<AsrPolicyGuard>(),
                            sp.GetRequiredService<AgentWatchdog>(),
                            sp.GetRequiredService<SyscallStubMonitor>(),
                            sp.GetRequiredService<ConnectivityCanaryMonitor>(),
                            sp.GetRequiredService<EtwSessionGuard>(),
                            sp.GetRequiredService<EtwProviderTamperMonitor>(),
                        };
                        return new MonitorGroup(
                            new MonitorGroupConfig
                            {
                                Name = "Critical",
                                StartDelay = TimeSpan.Zero,
                                StaggerDelay = TimeSpan.FromMilliseconds(100),
                                RestartIndefinitely = true,
                                RestartCooldown = TimeSpan.FromSeconds(5),
                                HealthCheckInterval = TimeSpan.FromSeconds(15),
                            },
                            monitors,
                            sp.GetRequiredService<ILogger<MonitorGroup>>());
                    });
                    services.AddSingleton<AntiTamperGuard>();
                    services.AddSingleton<IPSecIntegrityGuard>();
                    services.AddSingleton<AsrPolicyGuard>();
                    services.AddSingleton<AgentWatchdog>();
                    services.AddSingleton<SyscallStubMonitor>();
                    services.AddSingleton<ConnectivityCanaryMonitor>();
                    services.AddSingleton<EtwSessionGuard>();
                    services.AddSingleton<EtwProviderTamperMonitor>();
                    services.AddSingleton<WfpIntegrityMonitor>();
                    services.AddSingleton<DriverLoadMonitor>();

                    // ── Group 2: Core Detection ──────────────────────────────────────
                    // Starts after self-test (2s delay). Primary behavioral detection.
                    // Restart up to 5 times before degrading.
                    services.AddSingleton<IHostedService>(sp =>
                    {
                        var monitors = new List<IHostedService>
                        {
                            sp.GetRequiredService<RansomwareIoMonitor>(),
                            sp.GetRequiredService<BeaconingDetector>(),
                            sp.GetRequiredService<BehavioralBaselineService>(),
                            sp.GetRequiredService<FileVerdictScanner>(),
                            sp.GetRequiredService<ConsultantSignalIngestor>(),
                            sp.GetRequiredService<GhostProcessMonitor>(),
                            sp.GetRequiredService<EphemeralProcessMonitor>(),
                            sp.GetRequiredService<ModuleValidationMonitor>(),
                            sp.GetRequiredService<RuntimeModuleIntegrityMonitor>(),
                            sp.GetRequiredService<DllEntropyAnalyzer>(),
                            sp.GetRequiredService<DllLoadFailureMonitor>(),
                            sp.GetRequiredService<DiskWideDllScanner>(),
                            sp.GetRequiredService<PersistentConnectionMonitor>(),
                            sp.GetRequiredService<DataExfiltrationMonitor>(),
                            sp.GetRequiredService<AdsDataStagingMonitor>(),
                            sp.GetRequiredService<ScriptExecutionMonitor>(),
                            sp.GetRequiredService<ScriptHardeningMonitor>(),
                            sp.GetRequiredService<NamedPipeMonitor>(),
                            sp.GetRequiredService<RpcLateralMonitor>(),
                            sp.GetRequiredService<TokenTheftMonitor>(),
                            sp.GetRequiredService<CloudSyncExfilMonitor>(),
                            sp.GetRequiredService<LnkShortcutMonitor>(),
                        };
                        return new MonitorGroup(
                            new MonitorGroupConfig
                            {
                                Name = "CoreDetection",
                                StartDelay = TimeSpan.FromSeconds(2),
                                StaggerDelay = TimeSpan.FromMilliseconds(200),
                                MaxRestartAttempts = 5,
                                RestartCooldown = TimeSpan.FromSeconds(10),
                                HealthCheckInterval = TimeSpan.FromSeconds(30),
                            },
                            monitors,
                            sp.GetRequiredService<ILogger<MonitorGroup>>());
                    });
                    services.AddSingleton<FileVerdictScanner>();
                    services.AddSingleton<ConsultantSignalIngestor>();
                    services.AddSingleton<GhostProcessMonitor>();
                    services.AddSingleton<EphemeralProcessMonitor>();
                    services.AddSingleton<ModuleValidationMonitor>();
                    services.AddSingleton<RuntimeModuleIntegrityMonitor>();
                    services.AddSingleton<DllEntropyAnalyzer>();
                    services.AddSingleton<DllLoadFailureMonitor>();
                    services.AddSingleton<DiskWideDllScanner>();
                    services.AddSingleton<DataExfiltrationMonitor>();
                    services.AddSingleton<AdsDataStagingMonitor>();
                    services.AddSingleton<ScriptExecutionMonitor>();
                    services.AddSingleton<ScriptHardeningMonitor>();
                    services.AddSingleton<NamedPipeMonitor>();
                    services.AddSingleton<RpcLateralMonitor>();
                    services.AddSingleton<TokenTheftMonitor>();
                    services.AddSingleton<CloudSyncExfilMonitor>();
                    services.AddSingleton<LnkShortcutMonitor>();

                    // ── Group 3: Credential Protection ────────────────────────────────
                    // Starts after core detection (4s). Protects credentials and sessions.
                    services.AddSingleton<IHostedService>(sp =>
                    {
                        var monitors = new List<IHostedService>
                        {
                            sp.GetRequiredService<CanaryFileMonitor>(),
                            sp.GetRequiredService<BrowserCredentialGuard>(),
                            sp.GetRequiredService<BrowserC2Guard>(),
                            sp.GetRequiredService<MicrosoftAccountGuardMonitor>(),
                            sp.GetRequiredService<NullSessionGuard>(),
                            sp.GetRequiredService<BuiltinAdminGuard>(),
                            sp.GetRequiredService<PasswordRotationGuard>(),
                            sp.GetRequiredService<RemoteSessionGuard>(),
                        };
                        return new MonitorGroup(
                            new MonitorGroupConfig
                            {
                                Name = "CredentialProtection",
                                StartDelay = TimeSpan.FromSeconds(4),
                                StaggerDelay = TimeSpan.FromMilliseconds(200),
                                MaxRestartAttempts = 3,
                                RestartCooldown = TimeSpan.FromSeconds(10),
                                HealthCheckInterval = TimeSpan.FromSeconds(30),
                            },
                            monitors,
                            sp.GetRequiredService<ILogger<MonitorGroup>>());
                    });
                    services.AddSingleton<CanaryFileMonitor>();
                    services.AddSingleton<BrowserCredentialGuard>();
                    services.AddSingleton<BrowserC2Guard>();
                    services.AddSingleton<MicrosoftAccountGuardMonitor>();
                    services.AddSingleton<NullSessionGuard>();
                    services.AddSingleton<BuiltinAdminGuard>();
                    services.AddSingleton<PasswordRotationGuard>();
                    services.AddSingleton<RemoteSessionGuard>();

                    // ── Group 4: Network Integrity ────────────────────────────────────
                    // Starts after credential group (6s). Monitors network-layer attacks.
                    services.AddSingleton<IHostedService>(sp =>
                    {
                        var monitors = new List<IHostedService>
                        {
                            sp.GetRequiredService<ArpSpoofMonitor>(),
                            sp.GetRequiredService<DnsResponseValidationMonitor>(),
                            sp.GetRequiredService<PublicIpMonitor>(),
                            sp.GetRequiredService<WifiSecurityMonitor>(),
                            sp.GetRequiredService<NetworkInterfaceGuard>(),
                            sp.GetRequiredService<AppDnsExfilMonitor>(),
                            sp.GetRequiredService<NetworkShareMonitor>(),
                            sp.GetRequiredService<NetworkReinfectionDetector>(),
                            sp.GetRequiredService<ReinfectionCorrelator>(),
                            sp.GetRequiredService<DnsCrossValidator>(),
                            sp.GetRequiredService<TrafficVolumeBaseline>(),
                            sp.GetRequiredService<OutboundConnectionWhitelist>(),
                            sp.GetRequiredService<RemoteAccessMonitor>(),
                            sp.GetRequiredService<ThreatIntelFeedBlocker>(),
                            sp.GetRequiredService<ForumHrWatchMonitor>(),
                        };
                        return new MonitorGroup(
                            new MonitorGroupConfig
                            {
                                Name = "NetworkIntegrity",
                                StartDelay = TimeSpan.FromSeconds(6),
                                StaggerDelay = TimeSpan.FromMilliseconds(200),
                                MaxRestartAttempts = 3,
                                RestartCooldown = TimeSpan.FromSeconds(10),
                                HealthCheckInterval = TimeSpan.FromSeconds(30),
                            },
                            monitors,
                            sp.GetRequiredService<ILogger<MonitorGroup>>());
                    });
                    services.AddSingleton<ArpSpoofMonitor>();
                    services.AddSingleton<DnsResponseValidationMonitor>();
                    services.AddSingleton<PublicIpMonitor>();
                    services.AddSingleton<WifiSecurityMonitor>();
                    services.AddSingleton<NetworkInterfaceGuard>();
                    services.AddSingleton<AppDnsExfilMonitor>();
                    services.AddSingleton<NetworkShareMonitor>();
                    services.AddSingleton<NetworkReinfectionDetector>();
                    services.AddSingleton<DnsCrossValidator>();
                    services.AddSingleton<TrafficVolumeBaseline>();
                    services.AddSingleton<OutboundConnectionWhitelist>();
                    services.AddSingleton<RemoteAccessMonitor>();
                    services.AddSingleton<ThreatIntelFeedBlocker>();
                    services.AddSingleton<ForumHrWatchMonitor>();

                    // ── Group 5: System Integrity ─────────────────────────────────────
                    // Starts delayed (10s). Monitors OS-level configuration drift.
                    services.AddSingleton<IHostedService>(sp =>
                    {
                        var monitors = new List<IHostedService>
                        {
                            sp.GetRequiredService<FirewallIntegrityMonitor>(),
                            sp.GetRequiredService<SecureBootIntegrityMonitor>(),
                            sp.GetRequiredService<WindowsUpdateIntegrityMonitor>(),
                            sp.GetRequiredService<ScheduledTaskMonitor>(),
                            sp.GetRequiredService<CriticalServiceGuard>(),
                            sp.GetRequiredService<RegistryMonitor>(),
                            sp.GetRequiredService<WmiPersistenceMonitor>(),
                            sp.GetRequiredService<WorkFoldersExfilMonitor>(),
                            sp.GetRequiredService<TlsCertificateMonitor>(),
                            sp.GetRequiredService<UacBypassSurfaceMonitor>(),
                            sp.GetRequiredService<HostsFileGuard>(),
                            sp.GetRequiredService<BrowserDnsPolicyGuard>(),
                            sp.GetRequiredService<BootIntegrityGuard>(),
                            sp.GetRequiredService<CveShieldHardener>(),
                            sp.GetRequiredService<ApplicationIntegrityMonitor>(),
                            sp.GetRequiredService<PseudoSandbox>(),
                            sp.GetRequiredService<AcousticThreatMonitor>(),
                            sp.GetRequiredService<WfpIntegrityMonitor>(),
                            sp.GetRequiredService<DriverLoadMonitor>(),
                            sp.GetRequiredService<WmiProviderIntegrityMonitor>(),
                        };
                        return new MonitorGroup(
                            new MonitorGroupConfig
                            {
                                Name = "SystemIntegrity",
                                StartDelay = TimeSpan.FromSeconds(10),
                                StaggerDelay = TimeSpan.FromMilliseconds(300),
                                MaxRestartAttempts = 3,
                                RestartCooldown = TimeSpan.FromSeconds(15),
                                HealthCheckInterval = TimeSpan.FromSeconds(60),
                            },
                            monitors,
                            sp.GetRequiredService<ILogger<MonitorGroup>>());
                    });
                    services.AddSingleton<FirewallIntegrityMonitor>();
                    services.AddSingleton<SecureBootIntegrityMonitor>();
                    services.AddSingleton<WindowsUpdateIntegrityMonitor>();
                    services.AddSingleton<ScheduledTaskMonitor>();
                    services.AddSingleton<CriticalServiceGuard>();
                    services.AddSingleton<RegistryMonitor>();
                    services.AddSingleton<WmiPersistenceMonitor>();
                    services.AddSingleton<WorkFoldersExfilMonitor>();
                    services.AddSingleton<TlsCertificateMonitor>();
                    services.AddSingleton<UacBypassSurfaceMonitor>();
                    services.AddSingleton<HostsFileGuard>();
                    services.AddSingleton<BrowserDnsPolicyGuard>();
                    services.AddSingleton<BootIntegrityGuard>();
                    services.AddSingleton<CveShieldHardener>();
                    services.AddSingleton<ApplicationIntegrityMonitor>();
                    services.AddSingleton<AcousticThreatMonitor>();
                    services.AddSingleton<WmiProviderIntegrityMonitor>();

                    // ── Group 6: Peripheral & Environmental ───────────────────────────
                    // Starts late (30s). Monitors hardware peripherals and external media.
                    // Lower priority — log and continue on failure.
                    services.AddSingleton<IHostedService>(sp =>
                    {
                        var monitors = new List<IHostedService>
                        {
                            sp.GetRequiredService<BluetoothMonitor>(),
                            sp.GetRequiredService<PhantomDeviceMonitor>(),
                            sp.GetRequiredService<DeviceInstallMonitor>(),
                            sp.GetRequiredService<MtpTransferGuard>(),
                            sp.GetRequiredService<VolumeMountMonitor>(),
                            sp.GetRequiredService<CastDeviceGuard>(),
                            sp.GetRequiredService<WslMonitor>(),
                            sp.GetRequiredService<RawDiskAccessMonitor>(),
                            sp.GetRequiredService<PrintSpoolerMonitor>(),
                            sp.GetRequiredService<SandboxEscapeMonitor>(),
                            sp.GetRequiredService<HardwareSecurityGuard>(),
                            sp.GetRequiredService<UsbHidWhitelist>(),
                            sp.GetRequiredService<PhysicalAccessMonitor>(),
                        };
                        return new MonitorGroup(
                            new MonitorGroupConfig
                            {
                                Name = "Peripheral",
                                StartDelay = TimeSpan.FromSeconds(30),
                                StaggerDelay = TimeSpan.FromMilliseconds(500),
                                MaxRestartAttempts = 2,
                                RestartCooldown = TimeSpan.FromSeconds(30),
                                HealthCheckInterval = TimeSpan.FromSeconds(60),
                            },
                            monitors,
                            sp.GetRequiredService<ILogger<MonitorGroup>>());
                    });
                    services.AddSingleton<BluetoothMonitor>();
                    services.AddSingleton<DeviceInstallMonitor>();
                    services.AddSingleton<MtpTransferGuard>();
                    services.AddSingleton<VolumeMountMonitor>();
                    services.AddSingleton<CastDeviceGuard>();
                    services.AddSingleton<WslMonitor>();
                    services.AddSingleton<RawDiskAccessMonitor>();
                    services.AddSingleton<PrintSpoolerMonitor>();
                    services.AddSingleton<SandboxEscapeMonitor>();
                    services.AddSingleton<HardwareSecurityGuard>();
                    services.AddSingleton<UsbHidWhitelist>();
                    services.AddSingleton<PhysicalAccessMonitor>();
                });
    }
}
