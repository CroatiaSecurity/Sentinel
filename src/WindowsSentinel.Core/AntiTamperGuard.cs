using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Self-protection against tampering:
    ///
    /// 1. Binary integrity — alerts if Sentinel's own executable is deleted/replaced while running
    /// 2. Anti-suspend detection — monitors execution timing; fires if a gap exceeds threshold
    ///    (indicates NtSuspendProcess was used to freeze Sentinel while attacker operates)
    /// 3. Service reinstall — if Sentinel's service registry key is deleted, re-registers via SCM
    /// 4. Last-gasp logging — on unexpected exit, writes final state to last_gasp.jsonl
    ///
    /// Scan interval: 2 seconds for timing (anti-suspend), 10 seconds for binary/service checks.
    /// </summary>
    public sealed class AntiTamperGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<AntiTamperGuard> _logger;
        private readonly SentinelConfig _config;

        private const string ServiceName = "Windows Sentinel";
        private const int SuspendThresholdMs = 10_000; // 10s gap = suspended
        private readonly int _timingTickMs;
        private readonly int _integrityTickMs;

        private DateTimeOffset _lastTick = DateTimeOffset.UtcNow;
        private readonly string? _ownExePath;
        private readonly string _lastGaspPath;
        private bool _exitHandlerRegistered;
        private bool _serviceAlertSuppressed; // Only alert once about missing service registration
        private bool _systemJustResumed;

        public AntiTamperGuard(
            DetectionEngine detectionEngine,
            JsonlEventLogger eventLogger,
            SentinelConfig config,
            ILogger<AntiTamperGuard> logger)
        {
            _detectionEngine = detectionEngine;
            _eventLogger = eventLogger;
            _config = config;
            _logger = logger;
            _ownExePath = Environment.ProcessPath;
            _lastGaspPath = Path.Combine(
                Path.GetDirectoryName(_eventLogger.LogFilePath) ?? AppContext.BaseDirectory,
                "last_gasp.jsonl");
            
            _timingTickMs = config.AntiTamperTimingTickMs > 0 ? config.AntiTamperTimingTickMs : 2000;
            _integrityTickMs = config.AntiTamperIntegrityTickMs > 0 ? config.AntiTamperIntegrityTickMs : 10000;
        }

        public override Task StartAsync(CancellationToken cancellationToken)
        {
            try
            {
                Microsoft.Win32.SystemEvents.PowerModeChanged += OnPowerModeChanged;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[AntiTamperGuard] Failed to subscribe to PowerModeChanged events");
            }
            return base.StartAsync(cancellationToken);
        }

        public override void Dispose()
        {
            try
            {
                Microsoft.Win32.SystemEvents.PowerModeChanged -= OnPowerModeChanged;
            }
            catch { }
            base.Dispose();
        }

        private void OnPowerModeChanged(object sender, Microsoft.Win32.PowerModeChangedEventArgs e)
        {
            if (e.Mode == Microsoft.Win32.PowerModes.Resume)
            {
                _logger.LogInformation("[AntiTamperGuard] System resume detected; suppressing anti-suspend alarm for next tick");
                _systemJustResumed = true;
            }
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[AntiTamperGuard] Started — monitoring binary integrity, timing, and service registration");

            // Register exit handler for last-gasp logging
            RegisterExitHandler();

            int tickCounter = 0;

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_timingTickMs, stoppingToken);
                    tickCounter++;

                    // === Anti-Suspend Detection ===
                    var now = DateTimeOffset.UtcNow;
                    var elapsed = (now - _lastTick).TotalMilliseconds;
                    _lastTick = now;

                    if (_systemJustResumed)
                    {
                        _systemJustResumed = false;
                        elapsed = 0;
                    }

                    // If elapsed time is significantly more than expected, we were suspended
                    if (elapsed > SuspendThresholdMs)
                    {
                        var gapSeconds = elapsed / 1000.0;
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: Process Suspended",
                            Evidence = $"Execution gap of {gapSeconds:F1}s detected (expected ~{_timingTickMs / 1000.0:F1}s). " +
                                       $"Sentinel was likely suspended via NtSuspendProcess.",
                            Reasoning = "The Sentinel service experienced a timing gap far exceeding its " +
                                        $"expected tick interval ({gapSeconds:F1}s actual). This indicates the process was " +
                                        "suspended by an external actor using NtSuspendProcess/NtSuspendThread. " +
                                        "Attackers suspend EDR processes to operate undetected during the freeze window. " +
                                        "This is a high-confidence indicator of active compromise.",
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly, // Can't kill ourselves; alert is the response
                            ProcessName = "WindowsSentinel.Service",
                            ProcessId = Environment.ProcessId,
                            Metadata = new Dictionary<string, string>
                            {
                                ["GapSeconds"] = gapSeconds.ToString("F1"),
                                ["ExpectedTickMs"] = _timingTickMs.ToString()
                            }
                        });
                    }

                    // === Binary & Service Checks (dynamic check based on integrity / timing ratio) ===
                    int ticksPerCheck = Math.Max(1, _integrityTickMs / _timingTickMs);
                    if (tickCounter % ticksPerCheck == 0)
                    {
                        await CheckBinaryIntegrity();
                        await CheckServiceRegistration();
                        await CheckAndEnforceQosPolicies();
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[AntiTamperGuard] Error");
                    try { await Task.Delay(5000, stoppingToken); } catch { break; }
                }
            }
        }

        /// <summary>
        /// Checks if our own binary still exists on disk.
        /// If it's been deleted while we're running, attacker is trying to
        /// prevent restart after service stop/reboot.
        /// </summary>
        private async Task CheckBinaryIntegrity()
        {
            if (_ownExePath == null) return;

            if (!File.Exists(_ownExePath))
            {
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Anti-Tamper: Sentinel Binary Deleted",
                    Evidence = $"Sentinel executable no longer exists at: {_ownExePath}",
                    Reasoning = "The Sentinel service binary has been deleted from disk while the service " +
                                "is still running. This is a direct tampering attempt — the attacker wants " +
                                "to ensure Sentinel cannot restart after a reboot or service crash.",
                    Confidence = 0.99,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0
                });
            }
        }

        /// <summary>
        /// Checks if the Sentinel Windows service is still registered.
        /// If the service registry key was deleted, re-register it via SCM.
        /// Attackers delete services to prevent auto-restart.
        /// </summary>
        private async Task CheckServiceRegistration()
        {
            if (_serviceAlertSuppressed) return;

            try
            {
                // Check if service exists via ServiceController
                using var sc = new ServiceController(ServiceName);
                _ = sc.Status; // Throws InvalidOperationException if service doesn't exist

                // Enforce start type is Automatic so attackers cannot disable it
                if (sc.StartType != ServiceStartMode.Automatic)
                {
                    try
                    {
                        var psi = new ProcessStartInfo("sc.exe", $"config \"{ServiceName}\" start=auto")
                        { CreateNoWindow = true, UseShellExecute = false };
                        Process.Start(psi)?.WaitForExit(5000);
                        _logger.LogWarning("[AntiTamperGuard] Enforced service '{Service}' StartType back to Automatic.", ServiceName);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "[AntiTamperGuard] Failed to enforce service StartType");
                    }
                }
            }
            catch (InvalidOperationException)
            {
                _serviceAlertSuppressed = true; // Only alert once

                // Service registration is gone — attempt re-register
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Anti-Tamper: Service Registration Deleted",
                    Evidence = $"Windows service '{ServiceName}' is no longer registered in SCM",
                    Reasoning = "The Sentinel service registration was removed from the Service Control Manager " +
                                "while the service is still running. This prevents automatic restart on boot. " +
                                "Attempting to re-register.",
                    Confidence = 0.98,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0
                });

                // Attempt to re-register using sc.exe (standard Windows tool)
                // This is a legitimate self-healing action, not offensive
                if (_ownExePath != null)
                {
                    try
                    {
                        var psi = new ProcessStartInfo("sc.exe",
                            $"create \"{ServiceName}\" binPath=\"{_ownExePath}\" start=auto DisplayName=\"Windows Sentinel\"")
                        { CreateNoWindow = true, UseShellExecute = false };
                        Process.Start(psi)?.WaitForExit(5000);

                        _logger.LogWarning("[AntiTamperGuard] Re-registered service '{Service}'", ServiceName);
                        // Reset the suppression flag so we can detect and fix subsequent deletions
                        _serviceAlertSuppressed = false;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "[AntiTamperGuard] Failed to re-register service");
                    }
                }
            }
            catch { } // Service exists — all good
        }

        /// <summary>
        /// Registers handlers that write a last-gasp log entry on unexpected exit.
        /// This captures final state before crash/kill for forensic analysis.
        /// </summary>
        private void RegisterExitHandler()
        {
            if (_exitHandlerRegistered) return;
            _exitHandlerRegistered = true;

            AppDomain.CurrentDomain.ProcessExit += (_, _) => WriteLastGasp("ProcessExit");
            AppDomain.CurrentDomain.UnhandledException += (_, args) =>
                WriteLastGasp($"UnhandledException: {(args.ExceptionObject as Exception)?.Message ?? "unknown"}");
        }

        private void WriteLastGasp(string reason)
        {
            try
            {
                var entry = System.Text.Json.JsonSerializer.Serialize(new
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    Reason = reason,
                    ProcessId = Environment.ProcessId,
                    Uptime = (DateTimeOffset.UtcNow - Process.GetCurrentProcess().StartTime.ToUniversalTime()).ToString(),
                    LastTick = _lastTick
                });
                File.AppendAllText(_lastGaspPath, entry + Environment.NewLine);
            }
            catch { } // Best-effort — we're dying
        }

        /// <summary>
        /// Scans Policies\Microsoft\Windows\QoS registry subkeys to detect and delete
        /// any bandwidth throttling rules targeting Windows Sentinel binaries.
        /// </summary>
        private async Task CheckAndEnforceQosPolicies()
        {
            try
            {
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\QoS", true);
                if (baseKey == null) return;

                foreach (var subkeyName in baseKey.GetSubKeyNames())
                {
                    using var subKey = baseKey.OpenSubKey(subkeyName);
                    if (subKey == null) continue;

                    var appName = subKey.GetValue("App Name") as string;
                    if (!string.IsNullOrEmpty(appName) &&
                        (appName.Contains("WindowsSentinel", StringComparison.OrdinalIgnoreCase) ||
                         appName.Contains("Sentinel", StringComparison.OrdinalIgnoreCase)))
                    {
                        // Found a policy targeting Sentinel! Delete it.
                        baseKey.DeleteSubKeyTree(subkeyName);
                        
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: Network QoS Throttling Detected",
                            Evidence = $"Rogue QoS policy '{subkeyName}' targeting '{appName}' was found in registry.",
                            Reasoning = "An attacker attempted to throttle or block Sentinel's network traffic " +
                                        "by writing a policy-based QoS rule to HKLM\\Software\\Policies\\Microsoft\\Windows\\QoS. " +
                                        "This is a common EDR evasion technique to prevent alerts from reaching the cloud. " +
                                        "Sentinel has removed the registry key to restore full network bandwidth.",
                            Confidence = 0.99,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly, // Healed in-line
                            ProcessName = "SYSTEM",
                            ProcessId = 0
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[AntiTamperGuard] Error checking QoS policies");
            }
        }
    }
}
