using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    public class BehavioralCorrelationEngine
    {
        private readonly ConcurrentDictionary<int, List<DetectionEvent>> _signalBuffers = new();
        private Func<DetectionEvent, Task>? _emitCallback;
        private DateTime _lastPruneTime = DateTime.UtcNow;

        private static readonly HashSet<string> ElectronAndJitApps = new(StringComparer.OrdinalIgnoreCase)
        {
            // Electron / JIT apps with legitimate RWX + network
            "code", "cursor", "Devin", "discord", "slack", "teams", "steamwebhelper",
            "spotify", "brave", "chrome", "msedge", "fm", "kiro",
            // Windows system processes
            // HARDENING v1.5.9: REMOVED "svchost" from this list.
            // svchost.exe is NOT a JIT/Electron app — it's the #1 process injection target
            // for living-off-the-land attacks (LOLBins). Attackers inject into svchost because
            // it's always running, has network access, and runs as SYSTEM. Blanket-exempting it
            // from composite correlation meant that an attacker generating only Tier2 signals
            // (suspicious DNS, unusual network patterns, credential probing) inside svchost
            // would NEVER trigger composite detection. Now svchost participates fully in
            // correlation — legitimate svchost activity won't accumulate multiple distinct
            // threat-category signals, so false positives remain low.
            "sppsvc", "WmiPrvSE", "MsMpEng", "MpDefenderCoreService",
            "NisSrv", "SgrmBroker", "OneDrive",
            "MicrosoftStartFeedProvider", "backgroundTaskHost", "widgets",
            "GameBarPresenceWriter", "sihost", "taskhostw",
            "SearchHost", "StartMenuExperienceHost", "explorer"
        };

        private const int MaxSignalsPerBuffer = 50;
        // v1.5.4: Reduced Tier2 buffer for allowlisted apps to accumulate early evidence
        // without consuming excessive memory. If a Tier1 signal arrives later, this
        // evidence is available for composite evaluation (supply-chain compromise detection).
        private const int MaxAllowlistedTier2Buffer = 5;
        private static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan PruneInterval = TimeSpan.FromSeconds(60);

        public void Initialize(Func<DetectionEvent, Task> emitCallback)
        {
            _emitCallback = emitCallback;
        }

        public async Task RegisterSignalAsync(DetectionEvent signal)
        {
            var pid = signal.ProcessId;
            if (pid <= 0) return;

            // v1.5.4: Periodic pruning of dead PID entries to prevent memory leak
            // on high-churn systems (build servers, containers).
            PruneStaleBuffers();

            // Check if process name is in the Electron/JIT allowlist
            var stem = signal.ProcessName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase);
            if (ElectronAndJitApps.Contains(stem))
            {
                // Verify the process is legitimately signed
                var path = ResolveImagePath(pid);
                if (!string.IsNullOrEmpty(path) && SecurityValidation.VerifyAuthenticodeSignature(path))
                {
                    // HARDENING: Never exclude Tier1 signals from correlation, even for signed
                    // Electron apps. A supply-chain compromise (e.g., malicious update to Discord,
                    // Slack, or VS Code) would run under the signed binary's identity. If the
                    // signal is Tier1 or this PID already has buffered signals, it MUST participate
                    // in composite correlation to detect "Injected C2 Beacon", "Credential Dump",
                    // and similar high-severity chains.
                    if (signal.Tier != DetectionTier.Tier1Behavioral)
                    {
                        var existingBuffer = _signalBuffers.GetValueOrDefault(pid);
                        bool hasExistingSignals = false;
                        if (existingBuffer != null)
                        {
                            lock (existingBuffer)
                            {
                                hasExistingSignals = existingBuffer.Count > 0;
                            }
                        }
                        if (!hasExistingSignals)
                        {
                            // v1.5.4: Instead of dropping Tier2 entirely, accumulate a small
                            // buffer so evidence is available if a Tier1 signal arrives later
                            // (supply-chain compromise detection). Capped at 5 signals.
                            var t2Buffer = _signalBuffers.GetOrAdd(pid, _ => new List<DetectionEvent>());
                            lock (t2Buffer)
                            {
                                if (t2Buffer.Count < MaxAllowlistedTier2Buffer)
                                {
                                    t2Buffer.Add(signal);
                                }
                            }
                            return; // Don't evaluate composites for lone Tier2 on allowlisted apps
                        }
                    }
                    // Tier1 or PID already has signals — allow into correlation
                }
            }

            var buffer = _signalBuffers.GetOrAdd(pid, _ => new List<DetectionEvent>());
            lock (buffer)
            {
                buffer.Add(signal);
                if (buffer.Count > MaxSignalsPerBuffer)
                {
                    buffer.RemoveAt(0);
                }

                // Prune old signals
                var cutoff = DateTime.UtcNow - CorrelationWindow;
                buffer.RemoveAll(s => s.Timestamp < cutoff);
            }

            await EvaluateCompositesAsync(pid, buffer);
        }

        private async Task EvaluateCompositesAsync(int pid, List<DetectionEvent> signals)
        {
            if (_emitCallback == null) return;

            List<DetectionEvent> currentSignals;
            lock (signals)
            {
                currentSignals = new List<DetectionEvent>(signals);
            }

            if (currentSignals.Count < 2) return;

            // Extract signal type sets for efficient multi-check
            var types = new HashSet<SignalType>(currentSignals.Select(s => s.SignalType));
            var distinctRules = currentSignals.Select(s => s.RuleName).Distinct().Count();

            // ═══════════════════════════════════════════════════════════════
            // Highest confidence composites first (return on match)
            // Require signals from DIFFERENT sources (distinct SignalTypes)
            // ═══════════════════════════════════════════════════════════════

            // Active Ransomware Chain (0.99)
            // Multiple distinct ransomware indicators (e.g., shadow copy + mass rename)
            if (currentSignals.Count(s => s.SignalType == SignalType.Ransomware) >= 2 &&
                currentSignals.Where(s => s.SignalType == SignalType.Ransomware).Select(s => s.RuleName).Distinct().Count() >= 2)
            {
                await EmitCompositeAsync(pid, "Active Ransomware Chain", 0.99,
                    "Multiple distinct ransomware indicators from independent sources.",
                    "Shadow copy destruction, backup deletion, or mass file encryption confirmed by cross-signal correlation.");
                return;
            }

            // Injected C2 Beacon (0.98)
            // Process injection (kernel ETW) + outbound C2
            if (types.Contains(SignalType.ProcessInjection) && types.Contains(SignalType.NetworkC2))
            {
                await EmitCompositeAsync(pid, "Injected C2 Beacon", 0.98,
                    "Kernel-observed process injection followed by C2 network activity.",
                    "Code was injected into this process and it subsequently established command-and-control communication.");
                return;
            }

            // Credential Dump + Exfiltration (0.96)
            if ((types.Contains(SignalType.LsassAccess) || types.Contains(SignalType.CredentialTheft)) &&
                types.Contains(SignalType.NetworkC2))
            {
                await EmitCompositeAsync(pid, "Credential Dump + Exfiltration", 0.96,
                    "Credential access combined with outbound network communication.",
                    "Credential material was accessed and network exfiltration was observed on the same process.");
                return;
            }

            // In-Memory Implant + Network (0.96)
            // Memory anomaly (RWX/unbacked) + any network C2 — classic fileless implant
            if (types.Contains(SignalType.ProcessInjection) &&
                (types.Contains(SignalType.NetworkC2) || types.Contains(SignalType.ReverseShell)))
            {
                await EmitCompositeAsync(pid, "In-Memory Implant Active", 0.96,
                    "Memory anomaly (injection/RWX) combined with network callback.",
                    "Process exhibits in-memory code execution anomalies alongside active network communication — consistent with a loaded implant.");
                return;
            }

            // Fileless Attack Chain (0.95)
            // AMSI/ETW evasion or security evasion + shell or C2
            if ((types.Contains(SignalType.AmsiTampering) || types.Contains(SignalType.EtwTampering) || types.Contains(SignalType.SecurityEvasion)) &&
                (types.Contains(SignalType.ReverseShell) || types.Contains(SignalType.NetworkC2)))
            {
                await EmitCompositeAsync(pid, "Fileless Attack Chain", 0.95,
                    "Security evasion (AMSI/ETW tampering) combined with shell or C2 activity.",
                    "Process disabled security telemetry then established external communication — hallmark of staged fileless attack.");
                return;
            }

            // DGA + C2 Beaconing (0.94)
            // Suspicious DNS (high entropy or rapid queries) + network C2 beaconing
            var hasDnsAnomaly = currentSignals.Any(s =>
                s.RuleName.Contains("DNS", StringComparison.OrdinalIgnoreCase) &&
                (s.RuleName.Contains("DGA", StringComparison.OrdinalIgnoreCase) ||
                 s.RuleName.Contains("Rapid", StringComparison.OrdinalIgnoreCase) ||
                 s.RuleName.Contains("Tunnel", StringComparison.OrdinalIgnoreCase)));
            if (hasDnsAnomaly && types.Contains(SignalType.NetworkC2))
            {
                await EmitCompositeAsync(pid, "DGA + C2 Beaconing", 0.94,
                    "Algorithmically-generated DNS queries correlated with periodic C2 callbacks.",
                    "Process resolved high-entropy or high-volume domains and maintains regular beacon timing — DGA-based C2 channel.");
                return;
            }

            // ═══ v1.7.1: Covert RAT — Unsigned + Hidden + Network (0.88–0.92) ═══
            // Unsigned binary from staging path + sustained network + no visible window or recon activity
            var hasUnsignedOrSuspicious = currentSignals.Any(s =>
                s.SignalType == SignalType.SuspiciousProcess ||
                s.RuleName.Contains("Unsigned", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Suspicious Path", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Attack Tool", StringComparison.OrdinalIgnoreCase));
            var hasStagingPath = currentSignals.Any(s =>
                s.RuleName.Contains("Staging", StringComparison.OrdinalIgnoreCase) ||
                s.Evidence?.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase) == true ||
                s.Evidence?.Contains("\\AppData\\", StringComparison.OrdinalIgnoreCase) == true);
            var hasRecon = currentSignals.Any(s =>
                s.RuleName.Contains("Recon", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Enumeration", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Discovery", StringComparison.OrdinalIgnoreCase));
            if (hasUnsignedOrSuspicious && hasStagingPath && types.Contains(SignalType.NetworkC2))
            {
                double covertRatConfidence = hasRecon ? 0.92 : 0.88;
                await EmitCompositeAsync(pid, "Covert RAT: Unsigned + Hidden + Network", covertRatConfidence,
                    "Unsigned binary from staging path with sustained network activity.",
                    "A binary from a staging directory (Temp/AppData) initiated C2 networking — behavioral RAT pattern detected without campaign IOCs.");
                return;
            }

            // ═══ v1.7.1: Confirmed C2 Beacon — Unsigned Process (0.88–0.93) ═══
            // Unsigned binary exhibiting periodic beaconing (statistical CV < threshold)
            var hasBeaconing = currentSignals.Any(s =>
                s.RuleName.Contains("Beaconing", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Beacon", StringComparison.OrdinalIgnoreCase));
            if (hasUnsignedOrSuspicious && hasBeaconing)
            {
                double beaconConfidence = hasStagingPath ? 0.93 : 0.88;
                await EmitCompositeAsync(pid, "Confirmed C2 Beacon: Unsigned Process", beaconConfidence,
                    "Unsigned binary exhibiting periodic beaconing pattern.",
                    "An unsigned process maintains regular-interval callbacks characteristic of C2 beaconing — confirms active command-and-control regardless of framework.");
                return;
            }

            // ═══ v1.7.1: Covert C2 — Unsigned + Sustained Connection (0.90) ═══
            // Unsigned binary maintaining a long-lived outbound connection (60s+)
            var hasSustainedConnection = currentSignals.Any(s =>
                s.RuleName.Contains("Sustained", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Long-lived", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Persistent Connection", StringComparison.OrdinalIgnoreCase) ||
                (s.SignalType == SignalType.NetworkC2 &&
                 s.Evidence?.Contains("60s", StringComparison.OrdinalIgnoreCase) == true));
            if (hasUnsignedOrSuspicious && hasSustainedConnection)
            {
                await EmitCompositeAsync(pid, "Covert C2: Unsigned + Sustained Connection", 0.90,
                    "Unsigned binary maintaining a 60s+ outbound connection.",
                    "An unsigned binary holds a persistent outbound connection — matches PlugX/RAT pattern of fake updater from temp path holding HTTPS to C2.");
                return;
            }

            // Dropped Payload Phoning Home (0.93)
            // Unsigned/suspicious binary + C2 network (catch-all for unsigned + any network C2)
            if (hasUnsignedOrSuspicious && types.Contains(SignalType.NetworkC2))
            {
                await EmitCompositeAsync(pid, "Dropped Payload Active", 0.93,
                    "Unsigned or staged binary established C2 communication.",
                    "A binary from an untrusted path initiated command-and-control networking — consistent with a deployed implant or RAT.");
                return;
            }

            // ═══ v1.6.8: Named Pipe C2 + Network Beaconing (0.95) ═══
            // Named pipe matching C2/lateral-movement pattern + network C2 beaconing on same PID
            var hasNamedPipe = currentSignals.Any(s =>
                s.RuleName.Contains("Named Pipe", StringComparison.OrdinalIgnoreCase));
            if (hasNamedPipe && types.Contains(SignalType.NetworkC2))
            {
                await EmitCompositeAsync(pid, "Named Pipe C2 + Network Beaconing", 0.95,
                    "Suspicious named pipe correlated with C2 network beaconing on the same process.",
                    "A process created a named pipe matching C2/lateral-movement patterns AND maintains periodic network beaconing — confirms active C2 implant using IPC for inter-process staging.");
                return;
            }

            // Spoofed Process + Network (0.92)
            // PPID spoofing detection + any network activity
            var hasPpidSpoof = currentSignals.Any(s =>
                s.RuleName.Contains("Parent", StringComparison.OrdinalIgnoreCase) &&
                s.RuleName.Contains("Spoof", StringComparison.OrdinalIgnoreCase));
            if (hasPpidSpoof && (types.Contains(SignalType.NetworkC2) || types.Contains(SignalType.ReverseShell)))
            {
                await EmitCompositeAsync(pid, "Spoofed Process Phoning Home", 0.92,
                    "Process with spoofed parent established network communication.",
                    "Parent PID spoofing was detected on a process that subsequently made outbound connections — evading parent-chain-based trust.");
                return;
            }

            // Evasion + Persistence (0.91)
            // Security evasion + any registry/persistence signal
            var hasPersistence = currentSignals.Any(s =>
                s.RuleName.Contains("Autorun", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Service", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Scheduled Task", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Registry", StringComparison.OrdinalIgnoreCase));
            if (types.Contains(SignalType.SecurityEvasion) && hasPersistence)
            {
                await EmitCompositeAsync(pid, "Evasion + Persistence Install", 0.91,
                    "Security evasion combined with persistence mechanism installation.",
                    "Process evaded security controls then installed persistence — establishing long-term access.");
                return;
            }

            // ═══ v1.6.8: Token Theft + Lateral Movement (0.93) ═══
            // Token theft/impersonation + RPC/SMB lateral movement or named pipe IPC
            var hasTokenTheft = currentSignals.Any(s =>
                s.RuleName.Contains("Token Theft", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Impersonate", StringComparison.OrdinalIgnoreCase));
            var hasLateralMovement = currentSignals.Any(s =>
                s.RuleName.Contains("Lateral", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("RPC", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Named Pipe", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Network Share", StringComparison.OrdinalIgnoreCase));
            if (hasTokenTheft && hasLateralMovement)
            {
                await EmitCompositeAsync(pid, "Token Theft + Lateral Movement", 0.93,
                    "Token manipulation combined with lateral movement indicators on the same process.",
                    "Process stole/impersonated a privileged token then initiated lateral movement (RPC/SMB/named pipe) — classic post-exploitation pivot pattern (MITRE T1134 + T1021).");
                return;
            }

            // Privilege Escalation + Network (0.90)
            // Privilege escalation + any outbound network
            var hasPrivEsc = currentSignals.Any(s =>
                s.RuleName.Contains("Privilege", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Escalation", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Token", StringComparison.OrdinalIgnoreCase));
            if (hasPrivEsc && (types.Contains(SignalType.NetworkC2) || types.Contains(SignalType.ReverseShell)))
            {
                await EmitCompositeAsync(pid, "Escalation + C2 Channel", 0.90,
                    "Privilege escalation observed alongside outbound C2 communication.",
                    "Process escalated privileges then communicated externally — post-exploitation lateral movement preparation.");
                return;
            }
        }

        private async Task EmitCompositeAsync(int pid, string ruleName, double confidence, string evidence, string reasoning)
        {
            string name = "unknown";
            if (_signalBuffers.TryGetValue(pid, out var buffer))
            {
                lock (buffer)
                {
                    name = buffer.FirstOrDefault()?.ProcessName ?? "unknown";
                }
            }

            var compositeEvent = new DetectionEvent
            {
                RuleName = ruleName,
                ProcessId = pid,
                ProcessName = name,
                Confidence = confidence,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Evidence = $"[COMPOSITE] {evidence} (PID {pid})",
                Reasoning = reasoning,
                Timestamp = DateTime.UtcNow
            };

            await _emitCallback!(compositeEvent);
        }

        private static string? ResolveImagePath(int pid)
        {
            return SecurityValidation.GetProcessImagePath(pid);
        }

        /// <summary>
        /// v1.5.4: Removes signal buffer entries for PIDs whose newest signal is older
        /// than the correlation window. Prevents unbounded ConcurrentDictionary growth
        /// on systems with high process churn (build servers, containers).
        /// Called on each signal registration but rate-limited to once per PruneInterval.
        /// </summary>
        private void PruneStaleBuffers()
        {
            var now = DateTime.UtcNow;
            if (now - _lastPruneTime < PruneInterval)
                return;
            _lastPruneTime = now;

            var cutoff = now - CorrelationWindow;
            var staleKeys = new List<int>();

            foreach (var kvp in _signalBuffers)
            {
                lock (kvp.Value)
                {
                    // Remove expired signals
                    kvp.Value.RemoveAll(s => s.Timestamp < cutoff);
                    // Mark buffer for removal if empty
                    if (kvp.Value.Count == 0)
                    {
                        staleKeys.Add(kvp.Key);
                    }
                }
            }

            // Remove empty buffers
            foreach (var key in staleKeys)
            {
                _signalBuffers.TryRemove(key, out _);
            }
        }
    }
}
