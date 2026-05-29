using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;
using WindowsSentinel.Core.SelfProtection;

namespace WindowsSentinel.Agent;

/// <summary>
/// Windows Sentinel Agent - Runs in user session for:
///   1. Service watchdog (heartbeat monitoring + restart)
///   2. User-session monitors that require user-context access:
///      - ClipboardMonitor (clipboard ownership is per-session)
///      - ScreenCaptureMonitor (window enumeration is per-session)
///      - WebcamMicMonitor (camera/mic DLL scanning in user processes)
///      - AudioHijackMonitor (audio routing detection)
///      - MicSessionMonitor (WASAPI session enumeration is per-session)
///
/// v2.3.0: Moved user-session monitors from Service to Agent. The SYSTEM service
/// cannot enumerate WASAPI audio sessions, clipboard ownership, or reliably detect
/// foreground/visible windows in the user's desktop session.
/// </summary>
class Program
{
    static async Task<int> Main(string[] args)
    {
        // Apply DLL-search hardening before any non-trivial managed code runs.
        // Agent runs in user session (not SYSTEM), so we don't gate on install-dir ACL.
        ProcessHardening.ApplyOrFail(logger: null, refuseUnsafeInstallDir: false);

        // Single instance check - prevent duplicates
        using var mutex = new Mutex(true, "WindowsSentinelAgent", out bool createdNew);
        if (!createdNew)
        {
            return 0;
        }

        var builder = Host.CreateApplicationBuilder(args);

        // Logging to Event Log
        builder.Logging.ClearProviders();
        builder.Logging.AddEventLog(settings =>
        {
            settings.SourceName = "Windows Sentinel Agent";
            settings.LogName = "Application";
        });
        builder.Logging.SetMinimumLevel(LogLevel.Information);

        // ── Core detection infrastructure (lightweight — no scoring/akinator/chain-tracer) ──
        builder.Services.AddSingleton<IDetectionEngine>(sp =>
            new DetectionEngine(
                Enumerable.Empty<IDetectionRule>(),
                sp.GetRequiredService<ILogger<DetectionEngine>>()));
        builder.Services.AddSingleton<IEventLogger, AgentEventLogger>();
        builder.Services.AddSingleton<TrayIconService>();
        builder.Services.AddSingleton<IResponseEngine>(sp =>
            new AgentResponseEngine(
                sp.GetRequiredService<IEventLogger>(),
                sp.GetRequiredService<ILogger<AgentResponseEngine>>(),
                sp.GetRequiredService<TrayIconService>()));
        // TelemetryFusionEngine is optional for monitors — register as null
        builder.Services.AddSingleton<TelemetryFusionEngine>(_ => null!);

        // ── User-session monitors ────────────────────────────────────────────
        builder.Services.AddHostedService<ClipboardMonitor>();
        builder.Services.AddHostedService<ScreenCaptureMonitor>();
        builder.Services.AddHostedService<WebcamMicMonitor>();
        builder.Services.AddHostedService<AudioHijackMonitor>();
        builder.Services.AddHostedService<MicSessionMonitor>();
        builder.Services.AddHostedService<NeuroBehaviorVisualMonitor>();

        // ── Detection pipeline consumer (reads channel, routes to response engine) ──
        builder.Services.AddHostedService<AgentDetectionPipeline>();

        // ── System tray icon ─────────────────────────────────────────────────
        builder.Services.AddHostedService(sp => sp.GetRequiredService<TrayIconService>());

        // ── Service watchdog ─────────────────────────────────────────────────
        builder.Services.AddHostedService<ServiceWatchdogService>();

        var host = builder.Build();

        var logger = host.Services.GetRequiredService<ILogger<Program>>();
        logger.LogInformation("Windows Sentinel Agent v4.3.0 starting in user session (with user-context monitors)");

        await host.RunAsync();

        return 0;
    }

    /// <summary>
    /// Service Watchdog - Monitors the Sentinel service heartbeat file.
    /// If the heartbeat goes stale (service was killed/crashed/compromised),
    /// attempts to restart the service. This is a cross-process integrity check
    /// that survives in-process injection attacks against the service.
    /// </summary>
    class ServiceWatchdogService : BackgroundService
    {
        private readonly ILogger<ServiceWatchdogService> _logger;
        private readonly string _heartbeatPath;
        private const int StaleThresholdSeconds = 90; // 3 missed heartbeats (30s interval)
        private const int CheckIntervalSeconds = 15;
        private int _restartAttempts = 0;
        private const int MaxRestartAttempts = 3;

        public ServiceWatchdogService(ILogger<ServiceWatchdogService> logger)
        {
            _logger = logger;
            _heartbeatPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "WindowsSentinel", "watchdog.heartbeat");
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Service Watchdog: Starting — monitoring {Path}", _heartbeatPath);

            // Wait for service to start up before monitoring
            await Task.Delay(TimeSpan.FromSeconds(60), stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(CheckIntervalSeconds), stoppingToken);
                    await CheckHeartbeatAsync(stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Service Watchdog: Check error");
                }
            }
        }

        private async Task CheckHeartbeatAsync(CancellationToken ct)
        {
            if (!File.Exists(_heartbeatPath))
            {
                // File doesn't exist — service may not have started yet or was gracefully stopped
                _logger.LogDebug("Service Watchdog: Heartbeat file not found (service may be stopped)");
                return;
            }

            try
            {
                var content = await File.ReadAllTextAsync(_heartbeatPath, ct);

                // Verify HMAC signature (prevents heartbeat forgery)
                if (!WindowsSentinel.Core.Health.HeartbeatService.VerifyHeartbeat(
                    content, out var payload, out var lastHeartbeat))
                {
                    _logger.LogCritical(
                        "Service Watchdog: HEARTBEAT SIGNATURE INVALID. " +
                        "File may have been tampered with by an attacker to prevent restart.");
                    await AttemptServiceRestartAsync(ct);
                    return;
                }

                var age = DateTimeOffset.UtcNow - lastHeartbeat;

                if (age.TotalSeconds > StaleThresholdSeconds)
                {
                    _logger.LogCritical(
                        "Service Watchdog: HEARTBEAT STALE ({Age:F0}s old). " +
                        "Service may have been killed or compromised. Attempting restart.",
                        age.TotalSeconds);

                    await AttemptServiceRestartAsync(ct);
                }
                else
                {
                    // Heartbeat is fresh and authentic — reset restart counter
                    _restartAttempts = 0;
                }
            }
            catch (IOException)
            {
                // File may be locked by service writing to it — normal
            }
        }

        private Task AttemptServiceRestartAsync(CancellationToken ct)
        {
            if (_restartAttempts >= MaxRestartAttempts)
            {
                _logger.LogCritical(
                    "Service Watchdog: Max restart attempts ({Max}) reached. " +
                    "Service may be under active attack. Manual intervention required.",
                    MaxRestartAttempts);
                return Task.CompletedTask;
            }

            _restartAttempts++;
            _logger.LogCritical("Service Watchdog: Restart attempt {Attempt}/{Max}",
                _restartAttempts, MaxRestartAttempts);

            try
            {
                // Use native .NET ServiceController — no sc.exe LOLBin dependency
                using var sc = new System.ServiceProcess.ServiceController("Windows Sentinel");
                if (sc.Status == System.ServiceProcess.ServiceControllerStatus.Stopped)
                {
                    sc.Start();
                    sc.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                    _logger.LogInformation("Service Watchdog: Service restarted successfully");
                }
                else
                {
                    _logger.LogInformation("Service Watchdog: Service is already in state {Status}", sc.Status);
                }
            }
            catch (InvalidOperationException ex)
            {
                // Service not found or SCM unavailable (stripped Windows)
                _logger.LogWarning(ex, "Service Watchdog: ServiceController unavailable — cannot restart automatically");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Service Watchdog: Failed to restart service");
            }

            return Task.CompletedTask;
        }
    }
}


