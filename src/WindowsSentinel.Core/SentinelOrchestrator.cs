using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Central coordination point for the entire Sentinel EDR pipeline.
    ///
    /// SentinelOrchestrator is the "brain" that ties all components together:
    ///   - Routes detections through IncidentManager before response
    ///   - Supervises monitors via MonitorRegistry
    ///   - Manages startup via StartupSequencer
    ///   - Prevents duplicate/conflicting responses on the same PID
    ///   - Provides unified health status for the entire system
    ///
    /// All detection events flow through here:
    ///   Monitor → TelemetryFusion → DetectionEngine → Orchestrator → ResponseEngine
    ///                                                      ↓
    ///                                              IncidentManager
    ///                                              (group, escalate)
    ///
    /// This replaces the previous fire-and-forget pattern where DetectionEngine
    /// routed directly to ResponseEngine with no coordination.
    /// </summary>
    public sealed class SentinelOrchestrator : IDisposable
    {
        private readonly IncidentManager _incidentManager;
        private readonly MonitorRegistry _monitorRegistry;
        private readonly StartupSequencer _startupSequencer;
        private readonly AdvancedResponseEngine _responseEngine;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<SentinelOrchestrator> _logger;

        // Response lock: prevents duplicate kill attempts on the same PID
        private readonly ConcurrentDictionary<int, DateTimeOffset> _responseInProgress = new();
        private static readonly TimeSpan ResponseLockDuration = TimeSpan.FromSeconds(30);

        private bool _isRunning;
        private DateTimeOffset _startTime;

        public SentinelOrchestrator(
            IncidentManager incidentManager,
            MonitorRegistry monitorRegistry,
            StartupSequencer startupSequencer,
            AdvancedResponseEngine responseEngine,
            JsonlEventLogger eventLogger,
            ILogger<SentinelOrchestrator> logger)
        {
            _incidentManager = incidentManager;
            _monitorRegistry = monitorRegistry;
            _startupSequencer = startupSequencer;
            _responseEngine = responseEngine;
            _eventLogger = eventLogger;
            _logger = logger;
        }

        /// <summary>
        /// The unified detection→incident→response pipeline entry point.
        /// Called by DetectionEngine instead of routing directly to ResponseEngine.
        ///
        /// Flow:
        ///   1. Register detection with IncidentManager (group into incident)
        ///   2. Check if response is already in progress for this PID (prevent duplicates)
        ///   3. If incident severity warrants response, acquire response lock and execute
        ///   4. Mark incident as responded
        /// </summary>
        public async Task ProcessDetectionAsync(DetectionEvent detection)
        {
            // 1. Group into incident
            var incident = _incidentManager.RegisterDetection(detection);

            // 2. Route to response engine (it makes the kill/log decision)
            //    But first check response lock to prevent duplicate kills
            if (detection.KillAuthorized && detection.ProcessId > 0)
            {
                if (!TryAcquireResponseLock(detection.ProcessId))
                {
                    _logger.LogDebug(
                        "[Orchestrator] Response already in progress for PID {Pid} — skipping duplicate",
                        detection.ProcessId);
                    return;
                }
            }

            // 3. Execute response
            await _responseEngine.HandleAsync(detection);

            // 4. If response was a kill action, mark incident as responded
            if (detection.KillAuthorized && detection.Tier == DetectionTier.Tier1Behavioral)
            {
                _incidentManager.MarkRespondedByPid(detection.ProcessId,
                    detection.AuthorizedResponse.ToString());
            }
        }

        /// <summary>
        /// Acquires a per-PID response lock. Returns false if another response is
        /// already in progress (prevents duplicate kills, quarantine races).
        /// </summary>
        private bool TryAcquireResponseLock(int pid)
        {
            var now = DateTimeOffset.UtcNow;

            // Clean stale locks
            foreach (var (lockedPid, lockTime) in _responseInProgress)
            {
                if (now - lockTime > ResponseLockDuration)
                    _responseInProgress.TryRemove(lockedPid, out _);
            }

            return _responseInProgress.TryAdd(pid, now);
        }

        /// <summary>
        /// Releases the response lock for a PID (called after response completes).
        /// </summary>
        public void ReleaseResponseLock(int pid)
        {
            _responseInProgress.TryRemove(pid, out _);
        }

        // ═══════════════════════════════════════════════════════════════
        // System Lifecycle
        // ═══════════════════════════════════════════════════════════════

        /// <summary>
        /// Starts the entire Sentinel system in dependency order.
        /// Called by SentinelService.ExecuteAsync instead of the old foreach loop.
        /// </summary>
        public async Task<StartupReport> StartSystemAsync(CancellationToken ct)
        {
            _startTime = DateTimeOffset.UtcNow;
            _logger.LogInformation("[Orchestrator] Starting Sentinel system...");

            var report = await _startupSequencer.ExecuteAsync(ct);
            _isRunning = true;

            _logger.LogInformation("[Orchestrator] System ONLINE — {Running}/{Total} monitors active",
                _monitorRegistry.GetStats().Running, _monitorRegistry.GetStats().TotalRegistered);

            return report;
        }

        /// <summary>
        /// Graceful shutdown of all components in reverse dependency order.
        /// </summary>
        public async Task StopSystemAsync()
        {
            _isRunning = false;
            _logger.LogInformation("[Orchestrator] Shutting down Sentinel system...");

            // Log final system state
            var stats = GetSystemHealth();
            await _eventLogger.LogEventAsync("system_shutdown", new
            {
                Uptime = (DateTimeOffset.UtcNow - _startTime).ToString(@"d\.hh\:mm\:ss"),
                stats.MonitorStats,
                stats.IncidentStats,
                Timestamp = DateTimeOffset.UtcNow
            });
        }

        // ═══════════════════════════════════════════════════════════════
        // Unified Health
        // ═══════════════════════════════════════════════════════════════

        /// <summary>
        /// Returns the unified health status of the entire Sentinel system.
        /// Used by health check endpoints and tray icon.
        /// </summary>
        public SystemHealthStatus GetSystemHealth()
        {
            var monStats = _monitorRegistry.GetStats();
            var incStats = _incidentManager.GetStats();
            var startupReport = _startupSequencer.GetLastReport();

            var overallHealth = SystemHealth.Healthy;
            if (monStats.Failed > 0 || monStats.Stale > 0)
                overallHealth = SystemHealth.Degraded;
            if (monStats.Failed > monStats.TotalRegistered / 3)
                overallHealth = SystemHealth.Critical;
            if (!_isRunning)
                overallHealth = SystemHealth.Offline;

            return new SystemHealthStatus
            {
                Health = overallHealth,
                IsRunning = _isRunning,
                Uptime = _isRunning ? DateTimeOffset.UtcNow - _startTime : TimeSpan.Zero,
                MonitorStats = monStats,
                IncidentStats = incStats,
                StartupDurationMs = startupReport?.TotalDurationMs ?? 0,
                DegradedMode = startupReport?.DegradedMode ?? false,
                ActiveIncidents = _incidentManager.GetActiveIncidents(),
                UnhealthyMonitors = _monitorRegistry.GetUnhealthyMonitors(),
                ResponseLocksHeld = _responseInProgress.Count
            };
        }

        // ═══════════════════════════════════════════════════════════════
        // Monitor Heartbeat Passthrough
        // ═══════════════════════════════════════════════════════════════

        /// <summary>
        /// Convenience: monitors call this to heartbeat through the orchestrator.
        /// </summary>
        public void Heartbeat(string monitorName) => _monitorRegistry.Heartbeat(monitorName);

        /// <summary>
        /// Convenience: get the incident for a PID (used by response engine for context).
        /// </summary>
        public Incident? GetIncidentForPid(int pid) => _incidentManager.GetIncidentForPid(pid);

        public void Dispose()
        {
            _incidentManager.Dispose();
            _monitorRegistry.Dispose();
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Data Models
    // ═══════════════════════════════════════════════════════════════

    public enum SystemHealth
    {
        Healthy,    // All monitors running, no issues
        Degraded,   // Some monitors failed/stale, operating with reduced coverage
        Critical,   // More than 1/3 monitors down
        Offline     // System not started or shutting down
    }

    public sealed class SystemHealthStatus
    {
        public SystemHealth Health { get; set; }
        public bool IsRunning { get; set; }
        public TimeSpan Uptime { get; set; }
        public MonitorRegistryStats MonitorStats { get; set; } = new();
        public IncidentStats IncidentStats { get; set; } = new();
        public long StartupDurationMs { get; set; }
        public bool DegradedMode { get; set; }
        public IReadOnlyList<Incident> ActiveIncidents { get; set; } = Array.Empty<Incident>();
        public IReadOnlyList<MonitorStatus> UnhealthyMonitors { get; set; } = Array.Empty<MonitorStatus>();
        public int ResponseLocksHeld { get; set; }
    }
}
