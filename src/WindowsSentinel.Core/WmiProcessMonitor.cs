using System;
using System.Collections.Generic;
using System.Management;
using System.Diagnostics;
using System.Threading;

namespace WindowsSentinel.Core
{
    public class WmiProcessMonitor : IDisposable
    {
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly BehavioralBaselineService? _behavioralBaseline;
        private ManagementEventWatcher? _watcher;
        private volatile bool _disabled;

        // Fast-poll gap coverage: catches processes that spawn+exit within WMI's 1-2s latency
        private System.Threading.Timer? _fastPollTimer;
        private HashSet<int> _lastKnownPids = new();
        private readonly object _fastPollLock = new();

        /// <summary>
        /// When true, WMI process monitoring is active (ETW failed or hasn't started).
        /// Set to false by EtwProcessMonitor once ETW session is processing events.
        /// </summary>
        public bool IsActive => !_disabled && _watcher != null;

        public WmiProcessMonitor(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            BehavioralBaselineService? behavioralBaseline = null)
        {
            _fusionEngine = fusionEngine;
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _behavioralBaseline = behavioralBaseline;

            Start();
        }

        /// <summary>
        /// Called by EtwProcessMonitor when ETW session succeeds.
        /// Stops WMI monitoring to prevent duplicate telemetry events.
        /// </summary>
        public void Disable()
        {
            _disabled = true;
            try
            {
                _watcher?.Stop();
                _watcher?.Dispose();
                _watcher = null;
            }
            catch { }
        }

        public void Start()
        {
            try
            {
                var query = new WqlEventQuery("__InstanceCreationEvent", new TimeSpan(0, 0, 1),
                    "TargetInstance ISA 'Win32_Process'");

                _watcher = new ManagementEventWatcher(query);
                _watcher.EventArrived += OnProcessStarted;
                _watcher.Start();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to start WmiProcessMonitor: {ex.Message}");
            }

            // Start fast-poll gap coverage (250ms) to catch ephemeral processes
            // that spawn and exit within WMI's 1-2s event delivery latency
            InitializeFastPoll();
            _fastPollTimer = new System.Threading.Timer(FastPollProcesses, null, 250, 250);
        }

        private void InitializeFastPoll()
        {
            try
            {
                var pids = new HashSet<int>();
                foreach (var proc in Process.GetProcesses())
                {
                    pids.Add(proc.Id);
                    proc.Dispose();
                }
                lock (_fastPollLock)
                {
                    _lastKnownPids = pids;
                }
            }
            catch { }
        }

        /// <summary>
        /// Rapid process snapshot every 250ms. Detects new PIDs that appear between
        /// WMI event deliveries — critical for catching sub-second payloads (credential
        /// dumpers, droppers, stagers) that execute and exit before WMI fires.
        /// </summary>
        private void FastPollProcesses(object? state)
        {
            if (_disabled) return;
            try
            {
                var currentPids = new HashSet<int>();
                var newProcesses = new List<Process>();

                foreach (var proc in Process.GetProcesses())
                {
                    currentPids.Add(proc.Id);
                    bool isNew;
                    lock (_fastPollLock)
                    {
                        isNew = !_lastKnownPids.Contains(proc.Id);
                    }

                    if (isNew && proc.Id > 4)
                    {
                        newProcesses.Add(proc);
                    }
                    else
                    {
                        proc.Dispose();
                    }
                }

                lock (_fastPollLock)
                {
                    _lastKnownPids = currentPids;
                }

                // Process new PIDs — record them into ancestry cache immediately
                foreach (var proc in newProcesses)
                {
                    try
                    {
                        var pid = proc.Id;
                        var name = proc.ProcessName;
                        var imagePath = SecurityValidation.GetProcessImagePath(pid) ?? "";

                        // Record into ancestry cache so ChainTracer/GhostProcessMonitor can resolve it
                        // even if the process exits before the next WMI event
                        _ancestryCache.RecordProcessStart(pid, 0, name, imagePath);

                        _behavioralBaseline?.RecordProcess(name, imagePath, 0, "");
                    }
                    catch { }
                    finally
                    {
                        proc.Dispose();
                    }
                }
            }
            catch { }
        }

        private void OnProcessStarted(object sender, EventArrivedEventArgs e)
        {
            if (_disabled) return;
            try
            {
                var targetInstance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                int pid = Convert.ToInt32(targetInstance["ProcessId"]);
                string name = targetInstance["Name"]?.ToString() ?? "unknown";
                int ppid = Convert.ToInt32(targetInstance["ParentProcessId"]);
                string cmdLine = targetInstance["CommandLine"]?.ToString() ?? string.Empty;
                string imagePath = targetInstance["ExecutablePath"]?.ToString() ?? string.Empty;

                var parent = _ancestryCache.GetParent(pid);
                string parentName = parent.name != "unknown" ? parent.name : "unknown";

                _behavioralBaseline?.RecordProcess(name, imagePath, ppid, parentName);

                var telemetry = new ProcessTelemetry
                {
                    Type = "process",
                    ProcessId = pid,
                    ProcessName = name,
                    ParentProcessId = ppid,
                    ParentProcessName = parentName,
                    CommandLine = cmdLine,
                    ImagePath = imagePath,
                    Timestamp = DateTime.UtcNow
                };

                // Feed telemetry to fusion engine
                var context = _fusionEngine.FeedEvent(telemetry);

                // Submit to detection engine
                _detectionEngine.SubmitTelemetry(context);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error processing WMI process start event: {ex.Message}");
            }
        }

        public void Dispose()
        {
            _fastPollTimer?.Dispose();
            try
            {
                _watcher?.Stop();
                _watcher?.Dispose();
            }
            catch { }
        }
    }
}
