using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Monitors process creation/termination via ETW (Microsoft-Windows-Kernel-Process).
    /// Feeds telemetry into the fusion engine for rule evaluation.
    /// Detects: suspicious parent-child relationships, processes from temp paths,
    /// processes with anomalous command-line lengths, living-off-the-land binaries.
    /// </summary>
    public sealed class EtwProcessMonitor : IMonitor
    {
        public string Name => "EtwProcessMonitor";

        private const string SessionName = "SentinelKernelProcess";
        private const string KernelProcessProvider = "Microsoft-Windows-Kernel-Process";

        private readonly DetectionEngine _detectionEngine;
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly BehavioralBaselineService? _behavioralBaseline;
        private readonly ILogger<EtwProcessMonitor> _logger;
        private CancellationTokenSource? _cts;
        private TraceEventSession? _session;
        private Task? _monitorTask;

        public EtwProcessMonitor(
            DetectionEngine detectionEngine,
            TelemetryFusionEngine fusionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<EtwProcessMonitor> logger,
            BehavioralBaselineService? behavioralBaseline = null)
        {
            _detectionEngine = detectionEngine;
            _fusionEngine = fusionEngine;
            _ancestryCache = ancestryCache;
            _behavioralBaseline = behavioralBaseline;
            _logger = logger;
        }

        public Task StartAsync(CancellationToken ct)
        {
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            _monitorTask = Task.Run(() => MonitorLoop(_cts.Token), _cts.Token);
            _logger.LogInformation("[{Monitor}] Started", Name);
            return Task.CompletedTask;
        }

        private void MonitorLoop(CancellationToken ct)
        {
            try
            {
                // Kill any stale session from previous crash
                TraceEventSession.GetActiveSession(SessionName)?.Stop(noThrow: true);

                _session = new TraceEventSession(SessionName);
                _session.EnableProvider(KernelProcessProvider, TraceEventLevel.Informational, 0x10); // ProcessStart keyword

                ct.Register(() =>
                {
                    _session?.Stop();
                    _session?.Dispose();
                });

                _session.Source.Dynamic.All += data =>
                {
                    if (ct.IsCancellationRequested) return;

                    try
                    {
                        if (data.EventName == "ProcessStart" || data.EventName == "ProcessStart/Start")
                        {
                            var pid = (int)data.PayloadByName("ProcessID");
                            var imagePath = data.PayloadStringByName("ImageName") ?? string.Empty;
                            var cmdLine = data.PayloadStringByName("CommandLine") ?? string.Empty;
                            var parentPid = (int)data.PayloadByName("ParentProcessID");

                            var processName = System.IO.Path.GetFileNameWithoutExtension(imagePath);

                            _ancestryCache.RecordProcessStart(pid, parentPid, processName, imagePath);

                            var (_, parentName) = _ancestryCache.GetParent(parentPid);
                            _behavioralBaseline?.RecordProcess(processName, imagePath, parentPid, parentName);

                            var telemetry = new ProcessTelemetry
                            {
                                Type = "ProcessStart",
                                ProcessId = pid,
                                ProcessName = processName,
                                ImagePath = imagePath,
                                CommandLine = cmdLine,
                                ParentProcessId = parentPid,
                                Timestamp = data.TimeStamp.ToUniversalTime()
                            };

                            var context = _fusionEngine.FeedEvent(telemetry);
                            _detectionEngine.SubmitTelemetry(context);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[{Monitor}] Error processing event {Event}", Name, data.EventName);
                    }
                };

                _logger.LogInformation("[{Monitor}] ETW session '{Session}' processing events", Name, SessionName);
                _session.Source.Process(); // Blocks until session stops
            }
            catch (UnauthorizedAccessException)
            {
                _logger.LogWarning("[{Monitor}] ETW session requires admin/SYSTEM. Process telemetry via WMI fallback only.", Name);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _logger.LogError(ex, "[{Monitor}] ETW session failed", Name);
            }
        }

        public Task StopAsync()
        {
            _cts?.Cancel();
            _session?.Stop(noThrow: true);
            _session?.Dispose();
            _session = null;
            _logger.LogInformation("[{Monitor}] Stopped", Name);
            return Task.CompletedTask;
        }
    }
}
