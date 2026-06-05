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

        private bool IsPresidentsLawRule(DetectionEvent detection)
        {
            var rule = detection.RuleName ?? string.Empty;
            var lower = rule.ToLowerInvariant();
            return lower.Contains("lsass") ||
                   lower.Contains("amsi") ||
                   lower.Contains("etw") ||
                   lower.Contains("ransomware") ||
                   lower.Contains("shadow copy") ||
                   lower.Contains("self-protection") ||
                   lower.Contains("selfprotection") ||
                   lower.Contains("honeypot") ||
                   lower.Contains("chain-nuke") ||
                   lower.Contains("composite") ||
                   lower.Contains("verdictgate") ||
                   lower.Contains("verdict gate") ||
                   lower.Contains("webcamhijack") ||
                   lower.Contains("webcam hijack") ||
                   lower.Contains("audiohijack") ||
                   lower.Contains("audio hijack") ||
                   lower.Contains("antitamper") ||
                   lower.Contains("anti-tamper") ||
                   lower.Contains("tampering") ||
                   lower.Contains("privilege") ||
                   lower.Contains("attack") ||
                   lower.Contains("badusb") ||
                   lower.Contains("arp") ||
                   lower.Contains("canary") ||
                   lower.Contains("dns") ||
                   lower.Contains("tls") ||
                   lower.Contains("neuro") ||
                   lower.Contains("beaconing") ||
                   lower.Contains("hollowing") ||
                   lower.Contains("reverseshell") ||
                   lower.Contains("reverse shell") ||
                   lower.Contains("threatintel");
        }

        public async Task HandleAsync(DetectionEvent detection)
        {
            var stopwatch = Stopwatch.StartNew();

            bool shouldKill = false;
            bool shouldIsolateNetwork = false;
            bool shouldUnloadDllAndKillOwner = false;
            bool shouldRemoveCertAndKillAdder = false;
            string reason = "LogOnly";

            var isPresidentsLaw = IsPresidentsLawRule(detection);
            var effectiveTier = detection.Tier;
            var effectiveResponse = detection.AuthorizedResponse;
            var effectiveKillAuthorized = detection.KillAuthorized;

            if (effectiveTier == DetectionTier.Tier1Behavioral && !isPresidentsLaw)
            {
                effectiveTier = DetectionTier.Tier2Indicator;
                effectiveResponse = ResponseAction.LogOnly;
                effectiveKillAuthorized = false;
                reason = "LogOnly (Demoted non-President's-law rule)";
            }

            if (effectiveResponse == ResponseAction.UnloadDllAndKillOwner && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (_config.ActiveResponse)
                {
                    shouldUnloadDllAndKillOwner = true;
                    reason = $"UnloadDllAndKillOwner (AuthorizedResponse={effectiveResponse})";
                }
                else
                {
                    reason = "LogOnly (ActiveResponse disabled)";
                }
            }
            else if (effectiveResponse == ResponseAction.RemoveCertAndKillAdder && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (_config.ActiveResponse)
                {
                    shouldRemoveCertAndKillAdder = true;
                    reason = $"RemoveCertAndKillAdder (AuthorizedResponse={effectiveResponse})";
                }
                else
                {
                    reason = "LogOnly (ActiveResponse disabled)";
                }
            }
            else if (effectiveResponse == ResponseAction.NetworkIsolate && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (_config.ActiveResponse)
                {
                    shouldIsolateNetwork = true;
                    reason = $"NetworkIsolate (AuthorizedResponse={effectiveResponse})";
                }
                else
                {
                    reason = "LogOnly (ActiveResponse disabled)";
                }
            }
            else if (effectiveKillAuthorized && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (_config.ActiveResponse)
                {
                    shouldKill = true;
                    reason = $"Killed (AuthorizedResponse={effectiveResponse})";
                }
                else
                {
                    reason = "LogOnly (ActiveResponse disabled)";
                }
            }
            else if (effectiveTier == DetectionTier.Tier1Behavioral)
            {
                reason = "LogOnly (Tier1 without kill authorization)";
            }
            else
            {
                if (reason == "LogOnly")
                {
                    reason = "LogOnly (Tier2 Indicator)";
                }
            }

            if (shouldRemoveCertAndKillAdder)
            {
                // Cert removal + adder kill is handled directly by TlsCertificateMonitor
                // (uses native X509Store.Remove API + HardeningModule.SafeKillProcessTree).
                // The response engine just logs the action taken.
                var certThumb = detection.Metadata.GetValueOrDefault("CertThumbprint", "Unknown");
                var adderPidStr = detection.Metadata.GetValueOrDefault("AdderProcessId", "0");

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "REMOVE_CERT_AND_KILL_ADDER",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}. CertThumbprint={certThumb}. AdderPID={adderPidStr}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
            }
            else if (shouldUnloadDllAndKillOwner)
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
