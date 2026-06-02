using System;
using System.Management;
using System.Diagnostics;

namespace WindowsSentinel.Core
{
    public class WmiProcessMonitor : IDisposable
    {
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private ManagementEventWatcher? _watcher;

        public WmiProcessMonitor(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache)
        {
            _fusionEngine = fusionEngine;
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;

            Start();
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
        }

        private void OnProcessStarted(object sender, EventArrivedEventArgs e)
        {
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
            try
            {
                _watcher?.Stop();
                _watcher?.Dispose();
            }
            catch { }
        }
    }
}
