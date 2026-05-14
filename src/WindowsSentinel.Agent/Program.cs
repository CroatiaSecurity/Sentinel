using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.SelfProtection;

namespace WindowsSentinel.Agent;

/// <summary>
/// Windows Sentinel Agent - Runs in user session for UI interaction and service watchdog.
/// Launched by the SYSTEM service via CreateProcessAsUser.
///
/// v1.0.0 CHANGE: Key Scrambler removed entirely. The fake-keystroke injection approach
/// was security theater — it only confused primitive loggers and broke legitimate apps.
/// Keylogger detection is now handled by the service (HardeningModule) via hook enumeration.
/// The agent's role is now: service watchdog + future UI notifications.
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
            Console.WriteLine("[Agent] Another instance already running. Exiting.");
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

        // Service watchdog — monitors the service heartbeat file and restarts if stale
        builder.Services.AddHostedService<ServiceWatchdogService>();

        var host = builder.Build();

        var logger = host.Services.GetRequiredService<ILogger<Program>>();
        logger.LogInformation("Windows Sentinel Agent v1.0.0 starting in user session");

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
                var parts = content.Split('|');
                if (parts.Length < 1) return;

                if (DateTimeOffset.TryParse(parts[0], out var lastHeartbeat))
                {
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
                        // Heartbeat is fresh — reset restart counter
                        _restartAttempts = 0;
                    }
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
