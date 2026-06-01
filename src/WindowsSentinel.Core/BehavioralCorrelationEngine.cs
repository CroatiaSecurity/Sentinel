using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WindowsSentinel.Core
{
    public class BehavioralCorrelationEngine
    {
        private readonly ConcurrentDictionary<int, List<DetectionEvent>> _signalBuffers = new();
        private Func<DetectionEvent, Task>? _emitCallback;

        private static readonly HashSet<string> ElectronAndJitApps = new(StringComparer.OrdinalIgnoreCase)
        {
            "code", "cursor", "discord", "slack", "teams", "steamwebhelper",
            "spotify", "brave", "chrome", "msedge", "fm", "kiro"
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
                return; // Exclude from composite correlation
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

            // Composite 1: Active Ransomware Chain (0.99)
            // 2+ distinct ransomware signals (process + file)
            var rwSignals = currentSignals.Where(s => s.RuleName.Contains("Ransomware", StringComparison.OrdinalIgnoreCase)).ToList();
            if (rwSignals.Select(s => s.RuleName).Distinct().Count() >= 2)
            {
                await EmitCompositeAsync(pid, "Active Ransomware Chain", 0.99,
                    "Multiple distinct ransomware indicators observed on process.",
                    "Process exhibits file manipulation combined with volume shadow deletion or backup destruction.");
                return;
            }

            // Composite 2: Fileless Attack Chain (0.95)
            // AMSI/ETW evasion + encoded PS or C2 network
            var hasEvasion = currentSignals.Any(s => s.RuleName.Contains("EtwTampering", StringComparison.OrdinalIgnoreCase) || s.RuleName.Contains("Amsi", StringComparison.OrdinalIgnoreCase));
            var hasShellOrC2 = currentSignals.Any(s => s.RuleName.Contains("ReverseShell", StringComparison.OrdinalIgnoreCase) || s.RuleName.Contains("Beacon", StringComparison.OrdinalIgnoreCase));
            if (hasEvasion && hasShellOrC2)
            {
                await EmitCompositeAsync(pid, "Fileless Attack Chain", 0.95,
                    "AMSI/ETW evasion followed by shell execution or C2 beaconing.",
                    "Process tampered with system diagnostics and immediately established C2 communication.");
                return;
            }

            // Composite 3: Credential Dump + Exfiltration (0.96)
            var hasCredDump = currentSignals.Any(s => s.RuleName.Contains("Lsass", StringComparison.OrdinalIgnoreCase) || s.RuleName.Contains("Credential", StringComparison.OrdinalIgnoreCase));
            var hasNetwork = currentSignals.Any(s => s.RuleName.Contains("Network", StringComparison.OrdinalIgnoreCase) || s.RuleName.Contains("C2", StringComparison.OrdinalIgnoreCase));
            if (hasCredDump && hasNetwork)
            {
                await EmitCompositeAsync(pid, "Credential Dump + Exfiltration", 0.96,
                    "Credential dumping attempt followed by outbound network traffic.",
                    "LSASS target read detected alongside immediate external exfiltration.");
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
                Evidence = $"[COMPOSITE] {evidence} (PID {pid})",
                Reasoning = reasoning,
                Timestamp = DateTime.UtcNow
            };

            await _emitCallback!(compositeEvent);
        }
    }
}
