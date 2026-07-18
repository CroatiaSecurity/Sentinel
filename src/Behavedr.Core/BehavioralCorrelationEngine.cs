using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Behavedr.Core
{
    public class BehavioralCorrelationEngine
    {
        private readonly ConcurrentDictionary<int, List<DetectionEvent>> _signalBuffers = new();
        private Func<DetectionEvent, Task>? _emitCallback;

        private static readonly HashSet<string> ElectronAndJitApps = new(StringComparer.OrdinalIgnoreCase)
        {
            // Electron / JIT apps with legitimate RWX + network
            "code", "cursor", "Devin", "discord", "slack", "teams", "steamwebhelper",
            "spotify", "brave", "chrome", "msedge", "fm", "kiro",
            // Windows system processes
            "svchost", "sppsvc", "WmiPrvSE", "MsMpEng", "MpDefenderCoreService",
            "NisSrv", "SgrmBroker", "OneDrive",
            "MicrosoftStartFeedProvider", "backgroundTaskHost", "widgets",
            "GameBarPresenceWriter", "sihost", "taskhostw",
            "SearchHost", "StartMenuExperienceHost", "explorer"
        };

        private const int MaxSignalsPerBuffer = 50;
        private static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(60);

        public void Initialize(Func<DetectionEvent, Task> emitCallback)
        {
            _emitCallback = emitCallback;
        }

        public async Task RegisterSignalAsync(DetectionEvent signal)
        {
            var pid = signal.ProcessId;
            if (pid <= 0) return;

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
                            return; // Exclude Tier2 from correlation if no prior signals
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

            // Dropped Payload Phoning Home (0.93)
            // Unsigned/suspicious binary + C2 network
            var hasUnsignedOrSuspicious = currentSignals.Any(s =>
                s.SignalType == SignalType.SuspiciousProcess ||
                s.RuleName.Contains("Unsigned", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Suspicious Path", StringComparison.OrdinalIgnoreCase) ||
                s.RuleName.Contains("Attack Tool", StringComparison.OrdinalIgnoreCase));
            if (hasUnsignedOrSuspicious && types.Contains(SignalType.NetworkC2))
            {
                await EmitCompositeAsync(pid, "Dropped Payload Active", 0.93,
                    "Unsigned or staged binary established C2 communication.",
                    "A binary from an untrusted path initiated command-and-control networking — consistent with a deployed implant or RAT.");
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
    }
}
