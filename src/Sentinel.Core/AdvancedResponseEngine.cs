using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    public class AdvancedResponseEngine
    {
        private readonly SentinelConfig _config;
        private readonly SentinelMetrics _metrics;
        private readonly JsonlEventLogger _eventLogger;
        private readonly QuarantineManager _quarantineManager;
        private readonly AllowlistService? _allowlist;
        private IncidentResponseService? _incidentResponse;
        private DllUnloadEngine? _dllUnloadEngine;
        private ChainTracer? _chainTracer;
        private ReinfectionCorrelator? _reinfectionCorrelator;

        // v1.6.0: Rolling kill budget to prevent response weaponization (FP kill storms)
        private readonly ConcurrentQueue<long> _killTimestampsMs = new();
        private long _lastRateLimitLogMs;
        // v1.6.1: NetworkIsolate budget + Tier1 alert hook
        private readonly ConcurrentQueue<long> _isolateTimestampsMs = new();
        private long _lastIsolateRateLimitLogMs;
        private DetectionEngine? _detectionEngine;

        /// <summary>Set after DI construction to avoid circular dependency.</summary>
        public void SetReinfectionCorrelator(ReinfectionCorrelator correlator) => _reinfectionCorrelator = correlator;

        public AdvancedResponseEngine(
            SentinelConfig config,
            SentinelMetrics metrics,
            JsonlEventLogger eventLogger,
            QuarantineManager quarantineManager,
            AllowlistService? allowlist = null)
        {
            _config = config;
            _metrics = metrics;
            _eventLogger = eventLogger;
            _quarantineManager = quarantineManager;
            _allowlist = allowlist;
        }

        /// <summary>
        /// v1.6.0: Returns false when MaxKillsPerMinute budget is exhausted.
        /// NetworkIsolate is gated separately via TryConsumeIsolateBudget.
        /// </summary>
        private bool TryConsumeKillBudget()
        {
            int limit = _config.MaxKillsPerMinute;
            if (limit <= 0) return true;

            long now = Environment.TickCount64;
            long windowStart = now - 60_000;
            while (_killTimestampsMs.TryPeek(out long ts) && ts < windowStart)
                _killTimestampsMs.TryDequeue(out _);

            if (_killTimestampsMs.Count >= limit)
            {
                // Log at most once per 30s to avoid log floods
                long lastLog = Interlocked.Read(ref _lastRateLimitLogMs);
                if (now - lastLog > 30_000 &&
                    Interlocked.CompareExchange(ref _lastRateLimitLogMs, now, lastLog) == lastLog)
                {
                    _ = _eventLogger.LogEventAsync("response", new ResponseEvent
                    {
                        ProcessId = 0,
                        ProcessName = "SYSTEM",
                        ActionTaken = "RATE_LIMITED",
                        Reason = $"Kill budget exhausted ({limit}/min). Subsequent kills demoted to LogOnly until window slides.",
                        ExecutionTimeMs = 0
                    });
                    // v1.6.1: Loud Tier1 so operators see weaponized FP / ransomware wave
                    EmitBudgetExhaustedAlert("KillBudget", limit);
                }
                return false;
            }

            _killTimestampsMs.Enqueue(now);
            return true;
        }

        /// <summary>
        /// v1.6.1: Cap new NetworkIsolate targets per minute.
        /// </summary>
        private bool TryConsumeIsolateBudget()
        {
            int limit = _config.MaxNetworkIsolatesPerMinute;
            if (limit <= 0) return true;

            long now = Environment.TickCount64;
            long windowStart = now - 60_000;
            while (_isolateTimestampsMs.TryPeek(out long ts) && ts < windowStart)
                _isolateTimestampsMs.TryDequeue(out _);

            if (_isolateTimestampsMs.Count >= limit)
            {
                long lastLog = Interlocked.Read(ref _lastIsolateRateLimitLogMs);
                if (now - lastLog > 30_000 &&
                    Interlocked.CompareExchange(ref _lastIsolateRateLimitLogMs, now, lastLog) == lastLog)
                {
                    _ = _eventLogger.LogEventAsync("response", new ResponseEvent
                    {
                        ProcessId = 0,
                        ProcessName = "SYSTEM",
                        ActionTaken = "ISOLATE_RATE_LIMITED",
                        Reason = $"NetworkIsolate budget exhausted ({limit}/min). Further isolates skipped until window slides.",
                        ExecutionTimeMs = 0
                    });
                    EmitBudgetExhaustedAlert("NetworkIsolateBudget", limit);
                }
                return false;
            }

            _isolateTimestampsMs.Enqueue(now);
            return true;
        }

        private void EmitBudgetExhaustedAlert(string budgetType, int limit)
        {
            var de = _detectionEngine;
            if (de == null) return;
            _ = de.EmitAsync(new DetectionEvent
            {
                RuleName = "Anti-Tamper: Response Budget Exhausted",
                Evidence = $"{budgetType} hit limit of {limit} actions per minute. " +
                           "Further destructive responses are demoted/skipped until the window slides.",
                Reasoning = "Exhausting the automated response budget can indicate either a true mass-infection " +
                            "event (ransomware) or an attacker weaponizing false positives / decoy beacons. " +
                            "Operators must review immediately; detection logging continues.",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                SignalType = SignalType.AntiTamper,
                Metadata = new Dictionary<string, string>
                {
                    ["BudgetType"] = budgetType,
                    ["LimitPerMinute"] = limit.ToString()
                }
            });
        }

        public void SetDllUnloadEngine(DllUnloadEngine engine) => _dllUnloadEngine = engine;

        public void SetChainTracer(ChainTracer tracer) => _chainTracer = tracer;

        public void SetIncidentResponseService(IncidentResponseService irs) => _incidentResponse = irs;

        /// <summary>v1.6.1: Wire DetectionEngine after DI to avoid circular construction.</summary>
        public void SetDetectionEngine(DetectionEngine engine) => _detectionEngine = engine;

        private static readonly HashSet<string> PresidentsLawKeywords = new(StringComparer.OrdinalIgnoreCase)
        {
            "lsass", "amsi", "etw", "ransomware", "shadow copy",
            "self-protection", "selfprotection", "honeypot", "chain-nuke",
            "composite", "verdictgate", "verdict gate",
            "webcamhijack", "webcam hijack", "audiohijack", "audio hijack",
            "antitamper", "anti-tamper", "tampering",
            "hollowing", "reverseshell", "reverse shell",
            "threatintel", "badusb", "canary",
            "tls:", "certificate"
        };

        private bool IsPresidentsLawRule(DetectionEvent detection)
        {
            // Delegate to ScoringEngine's authoritative enum-based categorization
            // to avoid divergence between the two parallel President's Law checks.
            return ScoringEngine.IsPresidentsLawRule(detection.RuleName);
        }

        public async Task HandleAsync(DetectionEvent detection)
        {
            var stopwatch = Stopwatch.StartNew();

            bool shouldKill = false;
            bool shouldIsolateNetwork = false;
            bool shouldQuarantineAndKill = false;
            bool shouldRemoveCertAndKillAdder = false;
            bool shouldRemoveCert = false;
            bool shouldRemoveRegistryEntry = false;
            string reason = "LogOnly";

            // HARDENING v1.3.8: Absolute self-exclusion — never take action against our own processes.
            // The FileReputationEngine flags our unsigned dev builds as "Suspicious" (score ~43-48),
            // and the correlation engine can escalate these to kill responses. Force LogOnly.
            //
            // SECURITY: Path-verified, not name-based. An attacker naming their binary
            // "Sentinel.Agent.exe" in a user-writable directory is NOT excluded.
            // We resolve the actual image path and verify it resides in our installation directory.
            if (detection.ProcessId > 0)
            {
                try
                {
                    var detectedImagePath = SecurityValidation.GetProcessImagePath(detection.ProcessId);
                    // SECURITY v1.4.4: Normalize both paths with Path.GetFullPath() to resolve
                    // symlinks, junctions, and relative segments (../) before comparison.
                    // Also use trailing separator to prevent prefix collision attacks
                    // (e.g., C:\Program Files\Sentinel2\evil.exe matching our dir).
                    var selfDir = Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\') + '\\';
                    if (detectedImagePath != null)
                    {
                        var normalizedTarget = Path.GetFullPath(detectedImagePath);
                        if (normalizedTarget.StartsWith(selfDir, StringComparison.OrdinalIgnoreCase))
                        {
                            reason = "LogOnly (Self-exclusion: verified Sentinel install path)";
                            stopwatch.Stop();
                            _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                            var selfLog = new ResponseEvent
                            {
                                ProcessId = detection.ProcessId,
                                ProcessName = detection.ProcessName,
                                ActionTaken = "LOG",
                                Reason = reason,
                                ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                            };
                            await _eventLogger.LogEventAsync("response", selfLog);
                            return;
                        }
                    }
                }
                catch { /* process may have exited — continue with normal handling */ }
            }

            var isPresidentsLaw = IsPresidentsLawRule(detection);
            var effectiveTier = detection.Tier;
            var effectiveResponse = detection.AuthorizedResponse;
            var effectiveKillAuthorized = detection.KillAuthorized;

            string? imagePath = null;
            try
            {
                if (detection.ProcessId > 0)
                {
                    imagePath = SecurityValidation.GetProcessImagePath(detection.ProcessId);
                }
            }
            catch { }

            if (_allowlist != null && _allowlist.ShouldSuppress(detection.ProcessName, imagePath, detection.RuleName))
            {
                effectiveTier = DetectionTier.Tier2Indicator;
                effectiveResponse = ResponseAction.LogOnly;
                effectiveKillAuthorized = false;
                reason = "LogOnly (Suppressed by allowlist)";
            }
            // HARDENING v1.3.0: Removed blanket demotion of non-President's-Law Tier1 detections.
            // Previously, ANY Tier1 detection that wasn't in the President's Law categories was
            // demoted to LogOnly — meaning C2 Beaconing, Ghost Process, DLL Sideloading, Attack Tools,
            // and System Integrity detections all fired but never killed anything.
            // Now: Tier1 detections execute their AuthorizedResponse as-is. The detection rules
            // themselves are responsible for setting appropriate response levels.

            if (effectiveResponse == ResponseAction.QuarantineAndKill && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (_config.ActiveResponse)
                {
                    shouldQuarantineAndKill = true;
                    reason = $"QuarantineAndKill (AuthorizedResponse={effectiveResponse})";
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
            else if (effectiveResponse == ResponseAction.RemoveRegistryEntry && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (_config.ActiveResponse)
                {
                    shouldRemoveRegistryEntry = true;
                    reason = $"RemoveRegistryEntry (AuthorizedResponse={effectiveResponse})";
                }
                else
                {
                    reason = "LogOnly (ActiveResponse disabled)";
                }
            }
            else if (effectiveResponse == ResponseAction.RemoveCert && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (_config.ActiveResponse)
                {
                    shouldRemoveCert = true;
                    reason = $"RemoveCert (AuthorizedResponse={effectiveResponse}, no process terminated)";
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
                var certThumb = detection.Metadata.GetValueOrDefault("CertThumbprint", "Unknown");
                var adderPidStr = detection.Metadata.GetValueOrDefault("AdderProcessId", "0");

                if (!string.IsNullOrEmpty(certThumb) && certThumb != "Unknown")
                {
                    RemoveCertificateFromStore(certThumb);
                }

                if (int.TryParse(adderPidStr, out int adderPid) && adderPid > 4)
                {
                    if (TryConsumeKillBudget())
                        HardeningModule.SafeKillProcessTree(adderPid);
                    else
                        reason += " [kill rate-limited]";
                }

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
            else if (shouldRemoveCert)
            {
                var certThumb = detection.Metadata.GetValueOrDefault("CertThumbprint", "Unknown");

                if (!string.IsNullOrEmpty(certThumb) && certThumb != "Unknown")
                {
                    RemoveCertificateFromStore(certThumb);
                }

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "REMOVE_CERT",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}. CertThumbprint={certThumb}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
            }
            else if (shouldQuarantineAndKill)
            {
                // v1.6.0: rate-limit destructive responses
                if (!TryConsumeKillBudget())
                {
                    stopwatch.Stop();
                    _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                    await _eventLogger.LogEventAsync("response", new ResponseEvent
                    {
                        ProcessId = detection.ProcessId,
                        ProcessName = detection.ProcessName,
                        ActionTaken = "LOG",
                        Reason = $"Triggered by rule: {detection.RuleName}. QuarantineAndKill rate-limited (MaxKillsPerMinute).",
                        ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                    });
                    return;
                }

                // DLL sideloading/injection: quarantine the malicious DLL, kill the host process
                var targetPidStr = detection.Metadata.GetValueOrDefault("TargetProcessId", "0");
                int.TryParse(targetPidStr, out int targetPid);
                
                string quarantinedInfo = "None";
                if (targetPid > 0 && _dllUnloadEngine != null)
                {
                    var remediateResult = await _dllUnloadEngine.UnloadInjectedDllAsync(targetPid);
                    if (remediateResult.Success && remediateResult.UnloadedDlls.Count > 0)
                    {
                        quarantinedInfo = string.Join(", ", remediateResult.UnloadedDlls);
                    }
                }

                // HARDENING v1.5.9: Verify Authenticode before quarantining the injector binary.
                // Legitimate debugging/profiling tools (e.g., x64dbg, Process Hacker, AV hooking
                // engines) use injection APIs but are validly signed. Quarantining them is an
                // irreversible false positive that destroys the user's tool from disk.
                // Fix: signed injectors are still killed (stop the action) but NOT quarantined.
                // Unsigned/invalid-signature injectors are quarantined as before.
                bool injectorQuarantined = false;
                try
                {
                    using var proc = Process.GetProcessById(detection.ProcessId);
                    var quarantinePath = proc.MainModule?.FileName;
                    if (!string.IsNullOrEmpty(quarantinePath) && File.Exists(quarantinePath))
                    {
                        bool injectorIsSigned = SecurityValidation.VerifyAuthenticodeSignature(quarantinePath);
                        if (!injectorIsSigned)
                        {
                            await _quarantineManager.QuarantineFileAtomicAsync(quarantinePath);
                            injectorQuarantined = true;
                        }
                        // else: signed binary — kill process tree but preserve the file on disk
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
                    ActionTaken = injectorQuarantined ? "QUARANTINE_AND_KILL" : "KILL_ONLY (signed injector preserved)",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}. Quarantined={quarantinedInfo}. InjectorQuarantined={injectorQuarantined}. TargetPID={targetPid}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
                NotifyReinfectionCorrelator(detection);
            }
            else if (shouldIsolateNetwork)
            {
                // v1.6.1: rate-limit isolate storms (decoy C2 / domain-fronting noise)
                if (!TryConsumeIsolateBudget())
                {
                    stopwatch.Stop();
                    _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                    await _eventLogger.LogEventAsync("response", new ResponseEvent
                    {
                        ProcessId = detection.ProcessId,
                        ProcessName = detection.ProcessName,
                        ActionTaken = "LOG",
                        Reason = $"Triggered by rule: {detection.RuleName}. NetworkIsolate rate-limited (MaxNetworkIsolatesPerMinute).",
                        ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                    });
                    return;
                }

                // Network-level threat: block suspicious IPs extracted from evidence metadata
                var targetIp = detection.Metadata.GetValueOrDefault("TargetIP", "");
                if (!string.IsNullOrEmpty(targetIp))
                {
                    // Validate IP before creating firewall rules
                    if (!System.Net.IPAddress.TryParse(targetIp, out var parsedIp) ||
                        System.Net.IPAddress.IsLoopback(parsedIp) ||
                        targetIp == "0.0.0.0" || targetIp == "255.255.255.255" ||
                        IsLikelyCdnOrPublicResolver(parsedIp))
                    {
                        // Skip invalid/loopback/broadcast/major CDN-or-resolver IPs (collateral)
                    }
                    else
                    {
                        IsolateNetworkTarget(targetIp, detection.RuleName);
                    }
                }

                // Also flush DNS cache to clear poisoned entries
                FlushDnsCache();

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
            else if (shouldRemoveRegistryEntry)
            {
                var hive = detection.Metadata.GetValueOrDefault("Hive", "HKLM");
                var keyPath = detection.Metadata.GetValueOrDefault("KeyPath", "");
                var valueName = detection.Metadata.GetValueOrDefault("ValueName", "");
                var subKey = detection.Metadata.GetValueOrDefault("SubKey", "");
                var removed = false;
                var removalLog = "";

                try
                {
                    if (!string.IsNullOrEmpty(valueName) && !string.IsNullOrEmpty(keyPath))
                    {
                        // Remove a specific value from a key
                        var regHive = hive switch
                        {
                            "HKCU" => Microsoft.Win32.Registry.CurrentUser,
                            "HKCR" => Microsoft.Win32.Registry.ClassesRoot,
                            _ => Microsoft.Win32.Registry.LocalMachine
                        };
                        using var key = regHive.OpenSubKey(keyPath, writable: true);
                        if (key != null)
                        {
                            key.DeleteValue(valueName, throwOnMissingValue: false);
                            removed = true;
                            removalLog = $"Removed value '{valueName}' from {hive}\\{keyPath}";
                        }
                    }
                    else if (!string.IsNullOrEmpty(subKey) && keyPath.Contains("Services"))
                    {
                        // Remove a service subkey
                        using var servicesKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath, writable: true);
                        if (servicesKey != null)
                        {
                            servicesKey.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false);
                            removed = true;
                            removalLog = $"Removed service subkey '{subKey}' from {hive}\\{keyPath}";
                        }
                    }
                    else if (!string.IsNullOrEmpty(keyPath) && keyPath.Contains("CLSID"))
                    {
                        // Remove a CLSID subkey tree
                        using var clsidKey = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey(keyPath, writable: true);
                        if (clsidKey != null)
                        {
                            var parent = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey("CLSID", writable: true);
                            if (parent != null)
                            {
                                var clsid = detection.Metadata.GetValueOrDefault("CLSID", "");
                                if (!string.IsNullOrEmpty(clsid))
                                {
                                    parent.DeleteSubKeyTree(clsid, throwOnMissingSubKey: false);
                                    removed = true;
                                    removalLog = $"Removed CLSID '{clsid}' from HKCR\\CLSID";
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    removalLog = $"Failed to remove registry entry: {ex.Message}";
                }

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = removed ? "REMOVE_REGISTRY_ENTRY" : "REMOVE_REGISTRY_ENTRY_FAILED",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}. {removalLog}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
            }
            else if (shouldKill && detection.ProcessId > 4)
            {
                // v1.6.0: rate-limit kill storms
                if (!TryConsumeKillBudget())
                {
                    stopwatch.Stop();
                    _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                    await _eventLogger.LogEventAsync("response", new ResponseEvent
                    {
                        ProcessId = detection.ProcessId,
                        ProcessName = detection.ProcessName,
                        ActionTaken = "LOG",
                        Reason = $"Triggered by rule: {detection.RuleName}. Kill rate-limited (MaxKillsPerMinute).",
                        ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                    });
                    return;
                }

                // Collect forensic evidence before killing
                try { if (_incidentResponse != null) _ = _incidentResponse.CollectEvidenceAsync(detection); } catch { }

                var reasonText = $"Triggered by rule: {detection.RuleName}. {reason}";
                if (_chainTracer != null)
                {
                    var traceResult = await _chainTracer.TraceAndRespondAsync(detection);
                    if (traceResult != null && traceResult.Success)
                    {
                        if (traceResult.AttackRoot != null)
                        {
                            reasonText += $". Root source of attack: {traceResult.AttackRoot.ProcessName} (PID {traceResult.AttackRoot.ProcessId}, Path: '{traceResult.AttackRoot.ImagePath ?? "unknown"}')";
                        }
                        if (traceResult.QuarantinedFiles.Count > 0)
                        {
                            var files = string.Join(", ", traceResult.QuarantinedFiles.Select(f => $"{f.ProcessName} ('{f.OriginalPath}')"));
                            reasonText += $". Quarantined source files: {files}";
                        }
                    }
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
                    Reason = reasonText,
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
                NotifyReinfectionCorrelator(detection);
            }
            else
            {
                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
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

        private void NotifyReinfectionCorrelator(DetectionEvent detection)
        {
            try
            {
                if (_reinfectionCorrelator == null) return;
                var hash = detection.Metadata?.GetValueOrDefault("SHA256", "");
                if (string.IsNullOrEmpty(hash))
                {
                    // Try to compute hash from process image
                    try
                    {
                        using var proc = Process.GetProcessById(detection.ProcessId);
                        var path = proc.MainModule?.FileName;
                        if (!string.IsNullOrEmpty(path) && File.Exists(path))
                        {
                            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                                FileShare.ReadWrite | FileShare.Delete);
                            hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(fs)).ToLowerInvariant();
                        }
                    }
                    catch { }
                }
                if (!string.IsNullOrEmpty(hash))
                {
                    _reinfectionCorrelator.RegisterKilledHash(hash, detection.ProcessName ?? "unknown", detection.ProcessName ?? "unknown");
                }
            }
            catch { }
        }

        private void RemoveCertificateFromStore(string thumbprint)
        {
            var stores = new (System.Security.Cryptography.X509Certificates.StoreName Name, System.Security.Cryptography.X509Certificates.StoreLocation Location)[]
            {
                (System.Security.Cryptography.X509Certificates.StoreName.Root, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine),
                (System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine),
                (System.Security.Cryptography.X509Certificates.StoreName.Root, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser),
                (System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser)
            };

            foreach (var (storeName, storeLocation) in stores)
            {
                try
                {
                    using var store = new System.Security.Cryptography.X509Certificates.X509Store(storeName, storeLocation);
                    store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);

                    var certs = store.Certificates.Find(
                        System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint,
                        thumbprint,
                        validOnly: false);

                    foreach (var cert in certs)
                    {
                        store.Remove(cert);
                        _eventLogger.LogEventAsync("debug", new { Message = $"Successfully removed cert {thumbprint} from {storeName} ({storeLocation})" }).GetAwaiter().GetResult();
                    }
                }
                catch (Exception ex)
                {
                    _eventLogger.LogEventAsync("debug", new { Message = $"Failed to open/remove cert {thumbprint} from {storeName} ({storeLocation}): {ex.Message}" }).GetAwaiter().GetResult();
                }
            }
        }

        private void IsolateNetworkTarget(string ip, string ruleName)
        {
            var safeName = ip.Replace('.', '_').Replace(':', '_');
            var fwRule = $"Sentinel-Isolate-{safeName}";

            try
            {
                // Use Windows Firewall COM API (INetFwPolicy2) instead of shelling out to netsh.
                // This avoids Process.Start patterns that AV engines flag as malware behavior.
                var fwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (fwPolicyType == null) return;
                dynamic? fwPolicy = Activator.CreateInstance(fwPolicyType);
                if (fwPolicy == null) return;

                var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                if (ruleType == null) return;

                // Outbound block
                dynamic? outRule = Activator.CreateInstance(ruleType);
                if (outRule != null)
                {
                    outRule.Name = $"{fwRule}-OUT";
                    outRule.Description = $"Sentinel: Block outbound to {ip} ({ruleName})";
                    outRule.Direction = 2; // NET_FW_RULE_DIR_OUT
                    outRule.Action = 0;    // NET_FW_ACTION_BLOCK
                    outRule.RemoteAddresses = ip;
                    outRule.Enabled = true;
                    outRule.Profiles = 0x7FFFFFFF; // All profiles
                    fwPolicy.Rules.Add(outRule);
                }

                // Inbound block
                dynamic? inRule = Activator.CreateInstance(ruleType);
                if (inRule != null)
                {
                    inRule.Name = $"{fwRule}-IN";
                    inRule.Description = $"Sentinel: Block inbound from {ip} ({ruleName})";
                    inRule.Direction = 1; // NET_FW_RULE_DIR_IN
                    inRule.Action = 0;    // NET_FW_ACTION_BLOCK
                    inRule.RemoteAddresses = ip;
                    inRule.Enabled = true;
                    inRule.Profiles = 0x7FFFFFFF;
                    fwPolicy.Rules.Add(inRule);
                }
            }
            catch (Exception ex)
            {
                // Fallback: if COM fails (e.g., service not running), log and continue
                _eventLogger.LogEventAsync("debug", new { Message = $"Firewall COM failed for {ip}: {ex.Message}" }).GetAwaiter().GetResult();
            }
        }

        private static void FlushDnsCache()
        {
            try
            {
                // DnsFlushResolverCache is a documented public API — not a shell-out
                DnsFlushResolverCache();
            }
            catch { }
        }

        [System.Runtime.InteropServices.DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
        private static extern uint DnsFlushResolverCache();

        /// <summary>
        /// v1.6.1: Avoid firewall-blocking major public resolvers / well-known CDN anycast
        /// prefixes when decoy beaconing tries to force NetworkIsolate collateral damage.
        /// Not exhaustive — best-effort guardrail.
        /// </summary>
        private static bool IsLikelyCdnOrPublicResolver(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && bytes.Length == 4)
            {
                // Cloudflare 1.1.1.0/24, 1.0.0.0/24
                if (bytes[0] == 1 && (bytes[1] == 1 || bytes[1] == 0)) return true;
                // Google DNS 8.8.8.0/24, 8.8.4.0/24
                if (bytes[0] == 8 && bytes[1] == 8) return true;
                // Quad9 9.9.9.0/24
                if (bytes[0] == 9 && bytes[1] == 9 && bytes[2] == 9) return true;
            }
            return false;
        }
    }
}
