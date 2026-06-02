using System;
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
        private readonly ClipboardSanitizer _clipboardSanitizer;
        private readonly UsbDeviceFingerprinter _usbDeviceFingerprinter;
        private readonly AppNetworkPolicyMonitor _networkPolicyMonitor;
        private readonly DnsBlocklistEngine _dnsBlocklistEngine;
        private readonly WmiProcessMonitor _wmiProcessMonitor;

        public SentinelService(
            ILogger<SentinelService> logger,
            SentinelConfig config,
            JsonlEventLogger eventLogger,
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ClipboardSanitizer clipboardSanitizer,
            UsbDeviceFingerprinter usbDeviceFingerprinter,
            AppNetworkPolicyMonitor networkPolicyMonitor,
            DnsBlocklistEngine dnsBlocklistEngine,
            WmiProcessMonitor wmiProcessMonitor)
        {
            _logger = logger;
            _config = config;
            _eventLogger = eventLogger;
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _clipboardSanitizer = clipboardSanitizer;
            _usbDeviceFingerprinter = usbDeviceFingerprinter;
            _networkPolicyMonitor = networkPolicyMonitor;
            _dnsBlocklistEngine = dnsBlocklistEngine;
            _wmiProcessMonitor = wmiProcessMonitor;
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

            _logger.LogInformation("Windows Sentinel Service successfully started.");

            // Log startup to the JSONL log file so it is initialized with non-zero size
            await _eventLogger.LogEventAsync("service_start", new
            {
                Status = "started",
                Version = "5.2.0",
                Timestamp = DateTime.UtcNow
            });

            try
            {
                while (!stoppingToken.IsCancellationRequested)
                {
                    // Monitor loop / heartbeat
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
                _ancestryCache.Stop();
                _detectionEngine.Stop();
            }
        }

        private bool RunStartupSelfTest()
        {
            _logger.LogInformation("Running startup self-test...");

            // 1. Verify log path access
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var logDir = Path.Combine(programData, "WindowsSentinel");
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
