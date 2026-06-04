using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace WindowsSentinel.Core
{
    public class AdvancedResponseEngine
    {
        private readonly SentinelConfig _config;
        private readonly SentinelMetrics _metrics;
        private readonly JsonlEventLogger _eventLogger;
        private readonly QuarantineManager _quarantineManager;
        private IncidentResponseService? _incidentResponse;
        private DllUnloadEngine? _dllUnloadEngine;
        private ChainTracer? _chainTracer;

        public AdvancedResponseEngine(
            SentinelConfig config,
            SentinelMetrics metrics,
            JsonlEventLogger eventLogger,
            QuarantineManager quarantineManager)
        {
            _config = config;
            _metrics = metrics;
            _eventLogger = eventLogger;
            _quarantineManager = quarantineManager;
        }

        public void SetDllUnloadEngine(DllUnloadEngine engine) => _dllUnloadEngine = engine;

        public void SetChainTracer(ChainTracer tracer) => _chainTracer = tracer;

        public void SetIncidentResponseService(IncidentResponseService irs) => _incidentResponse = irs;

        public async Task HandleAsync(DetectionEvent detection)
        {
            var stopwatch = Stopwatch.StartNew();

            bool shouldKill = false;
            bool shouldIsolateNetwork = false;
            bool shouldUnloadDllAndKillOwner = false;
            string reason = "LogOnly";

            if (detection.AuthorizedResponse == ResponseAction.UnloadDllAndKillOwner && detection.Tier == DetectionTier.Tier1Behavioral)
            {
                if (_config.ActiveResponse)
                {
                    shouldUnloadDllAndKillOwner = true;
                    reason = $"UnloadDllAndKillOwner (AuthorizedResponse={detection.AuthorizedResponse})";
                }
                else
                {
                    reason = "LogOnly (ActiveResponse disabled)";
                }
            }
            else if (detection.AuthorizedResponse == ResponseAction.NetworkIsolate && detection.Tier == DetectionTier.Tier1Behavioral)
            {
                if (_config.ActiveResponse)
                {
                    shouldIsolateNetwork = true;
                    reason = $"NetworkIsolate (AuthorizedResponse={detection.AuthorizedResponse})";
                }
                else
                {
                    reason = "LogOnly (ActiveResponse disabled)";
                }
            }
            else if (detection.KillAuthorized && detection.Tier == DetectionTier.Tier1Behavioral)
            {
                if (_config.ActiveResponse)
                {
                    shouldKill = true;
                    reason = $"Killed (AuthorizedResponse={detection.AuthorizedResponse})";
                }
                else
                {
                    reason = "LogOnly (ActiveResponse disabled)";
                }
            }
            else if (detection.Tier == DetectionTier.Tier1Behavioral)
            {
                reason = "LogOnly (Tier1 without kill authorization)";
            }
            else
            {
                reason = "LogOnly (Tier2 Indicator)";
            }

            if (shouldUnloadDllAndKillOwner)
            {
                // Unload DLL from target first
                var targetPidStr = detection.Metadata.GetValueOrDefault("TargetProcessId", "0");
                int.TryParse(targetPidStr, out int targetPid);
                
                string unloadedDllsInfo = "None";
                if (targetPid > 0 && _dllUnloadEngine != null)
                {
                    var unloadResult = await _dllUnloadEngine.UnloadInjectedDllAsync(targetPid);
                    if (unloadResult.Success && unloadResult.UnloadedDlls.Count > 0)
                    {
                        unloadedDllsInfo = string.Join(", ", unloadResult.UnloadedDlls);
                    }
                }

                // Quarantine the owner binary (if possible) before killing it
                try
                {
                    using var proc = Process.GetProcessById(detection.ProcessId);
                    var imagePath = proc.MainModule?.FileName;
                    if (!string.IsNullOrEmpty(imagePath) && File.Exists(imagePath))
                    {
                        await _quarantineManager.QuarantineFileAtomicAsync(imagePath);
                    }
                }
                catch { }

                // Terminate injecting process tree
                if (detection.ProcessId > 4)
                {
                    HardeningModule.SafeKillProcessTree(detection.ProcessId);
                }

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "UNLOAD_DLL_AND_KILL_OWNER",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}. Unloaded={unloadedDllsInfo}. TargetPID={targetPid}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
            }
            else if (shouldIsolateNetwork)
            {
                // Network-level threat: block suspicious IPs extracted from evidence metadata
                var targetIp = detection.Metadata.GetValueOrDefault("TargetIP", "");
                if (!string.IsNullOrEmpty(targetIp))
                {
                    IsolateNetworkTarget(targetIp, detection.RuleName);
                }

                // Also flush DNS cache to clear poisoned entries
                RunHidden("ipconfig", "/flushdns");

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "NETWORK_ISOLATE",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}. Target={targetIp}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
            }
            else if (shouldKill && detection.ProcessId > 4)
            {
                // Collect forensic evidence before killing
                try { if (_incidentResponse != null) _ = _incidentResponse.CollectEvidenceAsync(detection); } catch { }

                if (_chainTracer != null)
                {
                    await _chainTracer.TraceAndRespondAsync(detection);
                }
                else
                {
                    HardeningModule.SafeKillProcessTree(detection.ProcessId);
                }

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "KILL",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
            }
            else
            {
                stopwatch.Stop();
                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "LOG",
                    Reason = reason,
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
            }
        }

        private void IsolateNetworkTarget(string ip, string ruleName)
        {
            var safeName = ip.Replace('.', '_').Replace(':', '_');
            var fwRule = $"Sentinel-Isolate-{safeName}";

            // Block inbound+outbound to the suspicious IP
            RunHidden("netsh", $"advfirewall firewall add rule name=\"{fwRule}-OUT\" dir=out action=block remoteip={ip} enable=yes");
            RunHidden("netsh", $"advfirewall firewall add rule name=\"{fwRule}-IN\" dir=in action=block remoteip={ip} enable=yes");

            // Flush ARP for this IP
            RunHidden("arp", $"-d {ip}");
        }

        private static void RunHidden(string exe, string args)
        {
            try
            {
                Process.Start(new ProcessStartInfo(exe, args)
                { CreateNoWindow = true, UseShellExecute = false })?.WaitForExit(5000);
            }
            catch { }
        }
    }
}
