using System;
using System.IO;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Verifies core subsystems on startup before activating monitors:
    /// ETW session, DPAPI encryption, quarantine directory, log file, rule loading.
    /// </summary>
    public sealed class StartupSelfTest : IHostedService
    {
        private readonly ILogger<StartupSelfTest> _logger;
        private readonly JsonlEventLogger _eventLogger;
        private readonly QuarantineManager _quarantine;
        private readonly DetectionEngine _detectionEngine;
        private readonly SecureCacheStore _cacheStore;

        public StartupSelfTest(
            ILogger<StartupSelfTest> logger,
            JsonlEventLogger eventLogger,
            QuarantineManager quarantine,
            DetectionEngine detectionEngine,
            SecureCacheStore cacheStore)
        {
            _logger = logger;
            _eventLogger = eventLogger;
            _quarantine = quarantine;
            _detectionEngine = detectionEngine;
            _cacheStore = cacheStore;
        }

        public Task StartAsync(CancellationToken ct)
        {
            _logger.LogInformation("[StartupSelfTest] Running pre-flight checks...");
            int passed = 0, failed = 0;

            // 0. Ensure critical network services are running (NlaSvc depends on stopped LanmanWorkstation)
            EnsureCriticalNetworkServices();

            // 1. Log file writable
            try
            {
                var logDir = Path.GetDirectoryName(_eventLogger.LogFilePath);
                if (string.IsNullOrEmpty(logDir))
                    logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WindowsSentinel");
                if (Directory.Exists(logDir)) passed++; else { Directory.CreateDirectory(logDir); passed++; }
            }
            catch (Exception ex) { failed++; _logger.LogWarning(ex, "[StartupSelfTest] Log directory check FAILED"); }

            // 2. Quarantine directory accessible
            try
            {
                var logDir = Path.GetDirectoryName(_eventLogger.LogFilePath);
                if (string.IsNullOrEmpty(logDir))
                    logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WindowsSentinel");
                var quarantineDir = Path.Combine(logDir, "Quarantine");
                if (!Directory.Exists(quarantineDir)) Directory.CreateDirectory(quarantineDir);
                passed++;
            }
            catch (Exception ex) { failed++; _logger.LogWarning(ex, "[StartupSelfTest] Quarantine directory check FAILED"); }

            // 3. DPAPI / SecureCacheStore functional
            try
            {
                // SECURITY v1.4.4: Use a random key for the self-test cache entry.
                // Previously used a fixed key "_check" with fixed value "ok" — known plaintext
                // that could theoretically aid cryptanalysis of the HMAC key when observed
                // before/after boot in the DPAPI-encrypted file. Random key eliminates this.
                var testKey = $"_selftest_{Guid.NewGuid():N}";
                var testVal = Guid.NewGuid().ToString("N");
                _cacheStore.Save("selftest", testKey, testVal);
                var val = _cacheStore.Load("selftest", testKey);
                if (val == testVal) passed++; else { failed++; _logger.LogWarning("[StartupSelfTest] DPAPI cache read-back mismatch"); }
            }
            catch (Exception ex) { failed++; _logger.LogWarning(ex, "[StartupSelfTest] DPAPI cache check FAILED"); }

            // 4. Detection rules loaded
            try
            {
                var ruleCount = _detectionEngine.RuleCount;
                if (ruleCount > 0) { passed++; _logger.LogInformation("[StartupSelfTest] {Count} detection rules loaded", ruleCount); }
                else { failed++; _logger.LogWarning("[StartupSelfTest] No detection rules loaded!"); }
            }
            catch (Exception ex) { failed++; _logger.LogWarning(ex, "[StartupSelfTest] Rule count check FAILED"); }

            // 5. Event logger functional
            try
            {
                _ = _eventLogger.LogEventAsync("selftest", new { Status = "OK", Timestamp = DateTime.UtcNow });
                passed++;
            }
            catch (Exception ex) { failed++; _logger.LogWarning(ex, "[StartupSelfTest] Event logger check FAILED"); }

            _logger.LogInformation("[StartupSelfTest] Complete: {Passed} passed, {Failed} failed", passed, failed);

            if (failed > 0)
            {
                _logger.LogWarning("[StartupSelfTest] Some subsystems degraded — Sentinel running in reduced mode");
            }

            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken ct) => Task.CompletedTask;

        /// <summary>
        /// Ensures NlaSvc and its dependencies are running.
        /// NlaSvc (Network Location Awareness) controls the network tray icon.
        /// GSecurity disables LanmanWorkstation which NlaSvc depends on for some functions,
        /// causing NlaSvc to stay stopped and the tray to show "No Internet" even when connected.
        /// </summary>
        private void EnsureCriticalNetworkServices()
        {
            var servicesToStart = new[] { "NlaSvc", "netprofm" };
            foreach (var svcName in servicesToStart)
            {
                try
                {
                    using var sc = new System.ServiceProcess.ServiceController(svcName);
                    if (sc.Status != System.ServiceProcess.ServiceControllerStatus.Running)
                    {
                        _logger.LogWarning("[StartupSelfTest] Service '{Svc}' is {Status} — starting it", svcName, sc.Status);
                        sc.Start();
                        sc.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));
                        _logger.LogInformation("[StartupSelfTest] Service '{Svc}' started successfully", svcName);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[StartupSelfTest] Failed to start service '{Svc}'", svcName);
                }
            }
        }
    }
}
