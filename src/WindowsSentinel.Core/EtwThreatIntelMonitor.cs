using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Monitors the Microsoft-Windows-Threat-Intelligence ETW provider for:
    /// - Cross-process memory allocation (VirtualAllocEx into another process)
    /// - Cross-process memory writes (WriteProcessMemory / NtWriteVirtualMemory)
    /// - Remote thread creation (CreateRemoteThread / NtCreateThreadEx)
    /// - Thread context manipulation (SetThreadContext / NtSetContextThread)
    /// These are the kernel-level signals for process injection — cannot be renamed.
    /// NOTE: This provider requires the service to run as Protected Process Light (PPL).
    /// Without PPL, the session starts but receives no events (silently).
    /// </summary>
    public sealed class EtwThreatIntelMonitor : IMonitor
    {
        public string Name => "EtwThreatIntelMonitor";

        private const string SessionName = "SentinelThreatIntel";
        private static readonly Guid ThreatIntelProviderGuid = Guid.Parse("F4E1897A-BB5D-5668-F1D8-040F4D8DD344");

        private readonly DetectionEngine _detectionEngine;
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly ILogger<EtwThreatIntelMonitor> _logger;
        private CancellationTokenSource? _cts;
        private TraceEventSession? _session;

        public EtwThreatIntelMonitor(
            DetectionEngine detectionEngine,
            TelemetryFusionEngine fusionEngine,
            ILogger<EtwThreatIntelMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _fusionEngine = fusionEngine;
            _logger = logger;
        }

        public Task StartAsync(CancellationToken ct)
        {
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            Task.Run(() => MonitorLoop(_cts.Token), _cts.Token);
            _logger.LogInformation("[{Monitor}] Started", Name);
            return Task.CompletedTask;
        }

        private void MonitorLoop(CancellationToken ct)
        {
            try
            {
                TraceEventSession.GetActiveSession(SessionName)?.Stop(noThrow: true);

                _session = new TraceEventSession(SessionName);
                _session.EnableProvider(ThreatIntelProviderGuid, TraceEventLevel.Verbose);

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
                        var apiName = data.EventName ?? string.Empty;
                        // ThreatIntel events: KERNEL_THREATINT_TASK_ALLOCVM, KERNEL_THREATINT_TASK_PROTECTVM,
                        // KERNEL_THREATINT_TASK_MAPVIEW, KERNEL_THREATINT_TASK_QUEUEUSERAPC,
                        // KERNEL_THREATINT_TASK_SETTHREADCONTEXT, KERNEL_THREATINT_TASK_READVM, KERNEL_THREATINT_TASK_WRITEVM

                        var callerPid = 0;
                        var targetPid = 0;
                        try
                        {
                            callerPid = (int)(data.PayloadByName("CallingProcessId") ?? data.PayloadByName("SourceProcessId") ?? 0);
                            targetPid = (int)(data.PayloadByName("TargetProcessId") ?? 0);
                        }
                        catch { /* Payload field names vary by event */ }

                        if (callerPid <= 4 || targetPid <= 4 || callerPid == targetPid) return;

                        var telemetry = new ThreatIntelTelemetry
                        {
                            Type = "ThreatIntel",
                            ProcessId = callerPid,
                            ProcessName = GetProcessName(callerPid),
                            TargetProcessId = targetPid,
                            ApiName = apiName,
                            Timestamp = data.TimeStamp.ToUniversalTime()
                        };

                        var context = _fusionEngine.FeedEvent(telemetry);
                        _detectionEngine.SubmitTelemetry(context);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[{Monitor}] Error processing ThreatIntel event", Name);
                    }
                };

                _logger.LogInformation("[{Monitor}] ETW session '{Session}' processing (requires PPL for events)", Name, SessionName);
                _session.Source.Process();
            }
            catch (UnauthorizedAccessException)
            {
                _logger.LogWarning("[{Monitor}] ETW ThreatIntel session requires admin/SYSTEM.", Name);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _logger.LogError(ex, "[{Monitor}] ETW ThreatIntel session failed", Name);
            }
        }

        private static string GetProcessName(int pid)
        {
            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById(pid);
                return proc.ProcessName;
            }
            catch { return $"PID_{pid}"; }
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
