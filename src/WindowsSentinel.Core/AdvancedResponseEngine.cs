using System;
using System.Diagnostics;
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

        public AdvancedResponseEngine(
            SentinelConfig config,
            SentinelMetrics metrics,
            JsonlEventLogger eventLogger)
        {
            _config = config;
            _metrics = metrics;
            _eventLogger = eventLogger;
        }

        public async Task HandleAsync(DetectionEvent detection)
        {
            var stopwatch = Stopwatch.StartNew();

            bool shouldKill = false;
            bool shouldIsolateNetwork = false;
            string reason = "LogOnly";

            if (detection.AuthorizedResponse == ResponseAction.NetworkIsolate && detection.Tier == DetectionTier.Tier1Behavioral)
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

            if (shouldIsolateNetwork)
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
                HardeningModule.SafeKillProcessTree(detection.ProcessId);

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
