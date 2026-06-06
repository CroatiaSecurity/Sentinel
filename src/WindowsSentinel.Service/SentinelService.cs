using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core;

namespace WindowsSentinel.Service
{
    public class SentinelService : BackgroundService
    {
        private readonly ILogger<SentinelService> _logger;
        private readonly SentinelConfig _config;
        private readonly JsonlEventLogger _eventLogger;
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly IEnumerable<IMonitor> _monitors;

        // Constructor-injected singletons that self-start
        private readonly UsbDeviceFingerprinter _usbDeviceFingerprinter;
        private readonly AppNetworkPolicyMonitor _networkPolicyMonitor;
        private readonly WmiProcessMonitor _wmiProcessMonitor;
        private readonly FileActivityMonitor _fileActivityMonitor;
        private readonly NetworkMonitor _networkMonitor;
        private readonly LsassDumpCanaryMonitor _lsassDumpCanaryMonitor;
        private readonly RouteTableMonitor _routeTableMonitor;
        private readonly HollowProcessMonitor _hollowProcessMonitor;
        private readonly MemoryBehaviorAnalyzer _memoryBehaviorAnalyzer;
        private readonly TokenIntegrityMonitor _tokenIntegrityMonitor;
        private readonly CredentialCanaryMonitor _credentialCanaryMonitor;
        private readonly LocalServerMonitor _localServerMonitor;
        private readonly ParentPidSpoofDetector _parentPidSpoofDetector;
        private readonly ChainTracer _chainTracer;

        public SentinelService(
            ILogger<SentinelService> logger,
            SentinelConfig config,
            JsonlEventLogger eventLogger,
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            IEnumerable<IMonitor> monitors,
            UsbDeviceFingerprinter usbDeviceFingerprinter,
            AppNetworkPolicyMonitor networkPolicyMonitor,
            WmiProcessMonitor wmiProcessMonitor,
            FileActivityMonitor fileActivityMonitor,
            NetworkMonitor networkMonitor,
            LsassDumpCanaryMonitor lsassDumpCanaryMonitor,
            RouteTableMonitor routeTableMonitor,
            HollowProcessMonitor hollowProcessMonitor,
            MemoryBehaviorAnalyzer memoryBehaviorAnalyzer,
            TokenIntegrityMonitor tokenIntegrityMonitor,
            CredentialCanaryMonitor credentialCanaryMonitor,
            LocalServerMonitor localServerMonitor,
            AdvancedResponseEngine responseEngine,
            IncidentResponseService incidentResponseService,
            DllUnloadEngine dllUnloadEngine,
            ParentPidSpoofDetector parentPidSpoofDetector,
            ChainTracer chainTracer)
        {
            // Wire incident response into response engine (late binding to avoid circular DI)
            responseEngine.SetIncidentResponseService(incidentResponseService);
            responseEngine.SetDllUnloadEngine(dllUnloadEngine);
            responseEngine.SetChainTracer(chainTracer);

            _logger = logger;
            _config = config;
            _eventLogger = eventLogger;
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _monitors = monitors;
            _usbDeviceFingerprinter = usbDeviceFingerprinter;
            _networkPolicyMonitor = networkPolicyMonitor;
            _wmiProcessMonitor = wmiProcessMonitor;
            _fileActivityMonitor = fileActivityMonitor;
            _networkMonitor = networkMonitor;
            _lsassDumpCanaryMonitor = lsassDumpCanaryMonitor;
            _routeTableMonitor = routeTableMonitor;
            _hollowProcessMonitor = hollowProcessMonitor;
            _memoryBehaviorAnalyzer = memoryBehaviorAnalyzer;
            _tokenIntegrityMonitor = tokenIntegrityMonitor;
            _credentialCanaryMonitor = credentialCanaryMonitor;
            _localServerMonitor = localServerMonitor;
            _parentPidSpoofDetector = parentPidSpoofDetector;
            _chainTracer = chainTracer;
        }


        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Windows Sentinel Service starting...");

            // Startup Self-Test
            if (!RunStartupSelfTest())
            {
                _logger.LogCritical("Windows Sentinel startup self-test FAILED. Stopping service.");
                return;
            }

            // Start all IMonitor implementations (ETW sessions, DNS monitor, etc.)
            foreach (var monitor in _monitors)
            {
                try
                {
                    await monitor.StartAsync(stoppingToken);
                    _logger.LogInformation("Started monitor: {Monitor}", monitor.Name);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to start monitor: {Monitor}", monitor.Name);
                }
            }

            _logger.LogInformation("Windows Sentinel Service successfully started.");

            await _eventLogger.LogEventAsync("service_start", new
            {
                Status = "started",
                Version = "6.8.0",
                Timestamp = DateTime.UtcNow
            }, stoppingToken);

            try
            {
                while (!stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(5000, stoppingToken);
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }
            finally
            {
                _logger.LogInformation("Windows Sentinel Service stopping...");

                // Stop IMonitors
                foreach (var monitor in _monitors)
                {
                    try { await monitor.StopAsync(); }
                    catch (Exception ex) { _logger.LogError(ex, "Error stopping monitor: {Monitor}", monitor.Name); }
                }

                _ancestryCache.Stop();
                _detectionEngine.Stop();
            }
        }

        private bool RunStartupSelfTest()
        {
            _logger.LogInformation("Running startup self-test...");

            // 1. Verify log path access
            var logDir = Path.GetDirectoryName(_eventLogger.LogFilePath);
            if (string.IsNullOrEmpty(logDir))
                logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WindowsSentinel");
            if (!Directory.Exists(logDir))
            {
                try
                {
                    Directory.CreateDirectory(logDir);
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Self-test failed to create log directory: {ex.Message}");
                    return false;
                }
            }

            // 2. Verify quarantine access
            var quarantineDir = Path.Combine(logDir, "Quarantine");
            if (!Directory.Exists(quarantineDir))
            {
                try
                {
                    Directory.CreateDirectory(quarantineDir);
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Self-test failed to create quarantine directory: {ex.Message}");
                    return false;
                }
            }

            // 3. Verify process hardening module
            if (!HardeningModule.ApplyOrFail())
            {
                _logger.LogWarning("Self-test: HardeningModule.ApplyOrFail returned false (likely non-fatal, continuing).");
            }

            _logger.LogInformation("Startup self-test PASSED.");
            return true;
        }
    }
}

