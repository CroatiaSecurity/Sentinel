using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace Sentinel.Core
{
    /// <summary>
    /// Global response posture: every monitor is observe-only until a multi-signal chain
    /// points at a real terminal attack. Kill-grade Tier1 is reserved for high-confidence
    /// token theft, credential dump, reverse shell, or C2 beaconing (or multi-signal composites
    /// that prove those). DLL unload remediations are exempt and may act immediately.
    /// </summary>
    public static class ResponsePolicy
    {
        /// <summary>Metadata key set when a detection is authorized for full destructive response.</summary>
        public const string ChainConfirmedKey = "ChainConfirmed";

        /// <summary>Metadata key: which terminal outcome family authorized the nuke.</summary>
        public const string TerminalOutcomeKey = "TerminalOutcome";

        /// <summary>
        /// The only single-signal families that may carry Tier1 (kill-grade) labels.
        /// Everything else is Tier2 observe fuel for correlation / composites.
        /// </summary>
        public static readonly HashSet<string> KillGradeTerminalFamilies = new(StringComparer.OrdinalIgnoreCase)
        {
            "CredentialDump",
            "TokenTheft",
            "ReverseShell",
            "C2Beacon",
        };

        /// <summary>Minimum confidence for a kill-grade family to stay Tier1 (default 0.85).</summary>
        public const double DefaultMinTier1Confidence = 0.85;

        private static readonly ConcurrentDictionary<int, PidSignalBuffer> PidBuffers = new();

        private static readonly string[] DllUnloadRuleFragments =
        {
            "DLL Sideloading",
            "DLL Injection",
            "DllUnload",
            "DLL Unload",
            "FreeLibrary",
            "Sideload",
            "Injected Module",
            "Hostile Module",
            "Proven Load",
        };

        /// <summary>
        /// Terminal attack families that authorize chain-confirmed nuke.
        /// Normal software (Steam DirectX/redist System32 writes, GPU drivers, installers) is NOT here.
        /// </summary>
        private static readonly (string Outcome, string[] Fragments)[] TerminalOutcomes =
        {
            ("BYOVD", new[]
            {
                "BYOVD", "Vulnerable Driver", "kdmapper", "DBUtil",
                "RTCore", "AsIO", "WinRing0", "capcom.sys", "gdrv", "iqvw64e",
                "Vulnerable Kernel", "Bring Your Own",
            }),
            ("CredentialDump", new[]
            {
                "LSASS", "Credential Dump", "Credential Theft", "Mimikatz", "sekurlsa",
                "procdump", "comsvcs", "MiniDump", "DumpCred", "SAM hive", "SECURITY hive",
                "ntds.dit", "DCSync", "secretsdump", "Credential Canary",
            }),
            ("TokenTheft", new[]
            {
                "Token Theft", "Token Stealing", "SYSTEM Token", "Impersonat",
                "SeImpersonate", "DuplicateToken", "MakeToken", "GodPotato", "PrintSpoofer",
                "Potato", "JuicyPotato", "RoguePotato", "SharpEfsPotato",
            }),
            ("ReverseShell", new[]
            {
                "Reverse Shell", "Bind Shell", "Interactive Shell", "pty.spawn",
                "socket.dup", "nc -e", "ncat", "revshell", "meterpreter",
            }),
            ("Exfil", new[]
            {
                "Exfil", "Exfiltration", "Data Staging", "Cloud Sync Exfil",
                "Bulk Upload", "Outbound Transfer", "WorkFolders Exfil",
                "AppDnsExfil", "DNS Tunnel", "DNS Exfil",
            }),
            ("C2Beacon", new[]
            {
                "C2 Beacon", "C2 Beaconing", "Beaconing", "Beacon Detector",
                "Command-and-Control", "Command and Control", "NetworkC2",
                "Injected C2", "Confirmed C2", "Covert C2", "C2 Channel",
                "Periodic Callback", "Statistical Beacon",
            }),
        };

        /// <summary>
        /// System-directory write rules that are almost always installer/redist life
        /// (Steam DirectX, GPU runtimes). Logged as Tier2 observe; never chain-seed.
        /// </summary>
        private static readonly string[] BenignNoiseRuleFragments =
        {
            "Unauthorized Write to System Directory",
            "System Integrity: Unauthorized Write",
            "Write to System Directory",
        };

        /// <summary>
        /// Secondary weak rules that are benign ONLY when the process/path is a known
        /// DirectX / VC++ / installer redistributable (not for arbitrary processes).
        /// </summary>
        private static readonly string[] InstallerContextWeakRuleFragments =
        {
            "Ephemeral Process",
            "Self-Deleting",
            "Parent PID Spoof",
            "PPID Spoof",
            "Unsigned Binary in Temp",
            "High Entropy",
        };

        /// <summary>
        /// Composites that already encode multi-signal proof toward a terminal outcome.
        /// </summary>
        private static readonly string[] NukeCompositeFragments =
        {
            "Credential Dump + Exfiltration",
            "Token Theft + Lateral Movement",
            "Injected C2 Beacon",
            "In-Memory Implant Active",
            "Fileless Attack Chain",
            "Named Pipe C2 + Network Beaconing",
            "Spoofed Process Phoning Home",
            "Escalation + C2 Channel",
            "Active Ransomware Chain",
            "Covert RAT",
            "Confirmed C2 Beacon",
            "Covert C2",
            "Dropped Payload Active",
            "DGA + C2 Beaconing",
            "[COMPOSITE]",
        };

        public static bool IsDllUnloadExempt(DetectionEvent? detection)
        {
            if (detection == null) return false;
            var r = detection.RuleName ?? "";
            foreach (var f in DllUnloadRuleFragments)
            {
                if (r.IndexOf(f) >= 0)
                    return true;
            }

            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue("DllUnloadExempt", out var flag) &&
                string.Equals(flag, "true"))
                return true;

            return false;
        }

        /// <summary>
        /// Standing tier law: Tier1 only when the act is kill-grade and confident enough —
        /// token theft, credential dump, reverse shell, C2 beaconing — or a multi-signal
        /// composite / chain-confirmed detection that proves one of those.
        /// All other signals become Tier2 + LogOnly (still feed correlation).
        /// DLL-unload exempt detections keep their response path but are not auto-promoted.
        /// </summary>
        public static void ApplyTierLaw(DetectionEvent detection, double minConfidence = DefaultMinTier1Confidence)
        {
            if (detection == null) return;

            detection.Metadata ??= new Dictionary<string, string>();

            // Multi-signal composites already encode independent proof → keep Tier1 kill intent.
            if (IsNukeComposite(detection))
            {
                detection.Tier = DetectionTier.Tier1Behavioral;
                if (detection.AuthorizedResponse < ResponseAction.KillProcessTree)
                    detection.AuthorizedResponse = ResponseAction.QuarantineAndKill;
                detection.Metadata["TierLaw"] = "Composite";
                return;
            }

            // Already chain-confirmed (correlation path) → Tier1.
            if (detection.Metadata.TryGetValue(ChainConfirmedKey, out var chain) &&
                string.Equals(chain, "true"))
            {
                detection.Tier = DetectionTier.Tier1Behavioral;
                detection.Metadata["TierLaw"] = "ChainConfirmed";
                return;
            }

            // Benign installer / DirectX / System32 redist noise is never Tier1.
            if (IsBenignInstallerNoise(detection))
            {
                DemoteToObserve(detection, "BenignInstallerNoise");
                return;
            }

            var outcome = ClassifyTerminalOutcome(detection);
            bool killGrade = outcome != null && KillGradeTerminalFamilies.Contains(outcome);
            double conf = detection.Confidence;
            if (conf <= 0 && detection.Metadata.TryGetValue("ThreatScore", out var scoreStr) &&
                double.TryParse(scoreStr, out var score))
            {
                // ScoringEngine uses 0–100; map roughly to 0–1 when Confidence unset.
                conf = score > 1.0 ? score / 100.0 : score;
            }

            if (killGrade && conf >= minConfidence)
            {
                detection.Tier = DetectionTier.Tier1Behavioral;
                detection.Metadata["TierLaw"] = outcome!;
                detection.Metadata[TerminalOutcomeKey] = outcome!;
                // Recommended action may be kill-grade; ObserveUntilChain still gates execution
                // until a second independent signal / composite confirms.
                return;
            }

            // Weak / non-terminal / low-confidence → observe only. Still logs + correlates.
            DemoteToObserve(detection, killGrade ? "LowConfidenceTerminal" : "NonKillGrade");
        }

        private static void DemoteToObserve(DetectionEvent detection, string reason)
        {
            detection.Tier = DetectionTier.Tier2Indicator;
            if (detection.AuthorizedResponse >= ResponseAction.NetworkIsolate)
                detection.AuthorizedResponse = ResponseAction.LogOnly;
            detection.Metadata ??= new Dictionary<string, string>();
            detection.Metadata["TierLaw"] = reason;
            detection.Metadata["ObserveOnly"] = "true";
        }

        public static bool IsKillGradeTerminal(DetectionEvent detection)
        {
            var outcome = ClassifyTerminalOutcome(detection);
            return outcome != null && KillGradeTerminalFamilies.Contains(outcome);
        }

        /// <summary>
        /// Classify terminal outcome family from rule/evidence/signal type, or null if not terminal.
        /// </summary>
        public static string? ClassifyTerminalOutcome(DetectionEvent detection)
        {
            if (detection == null) return null;

            // Installer / DirectX / GPU redistributable noise is never terminal.
            if (IsBenignInstallerNoise(detection))
                return null;

            switch (detection.SignalType)
            {
                case SignalType.LsassAccess:
                case SignalType.CredentialTheft:
                    return "CredentialDump";
                case SignalType.ReverseShell:
                    return "ReverseShell";
                case SignalType.NetworkC2:
                    return "C2Beacon";
            }

            var haystack = string.Join(" ",
                detection.RuleName ?? "",
                detection.Evidence ?? "",
                detection.Reasoning ?? "");

            foreach (var (outcome, fragments) in TerminalOutcomes)
            {
                foreach (var f in fragments)
                {
                    if (haystack.IndexOf(f) >= 0)
                        return outcome;
                }
            }

            return null;
        }

        public static bool IsBenignInstallerNoise(DetectionEvent detection)
        {
            if (detection == null) return false;

            // Explicit metadata from monitors (FileActivityMonitor DirectX path, etc.)
            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue("BenignInstallerNoise", out var flag) &&
                string.Equals(flag, "true"))
                return true;

            string? imagePath = null;
            string? filePath = null;
            if (detection.Metadata != null)
            {
                detection.Metadata.TryGetValue("ImagePath", out imagePath);
                detection.Metadata.TryGetValue("FilePath", out filePath);
            }

            // Any signal from a DirectX/redist process is observe-only noise (never Tier1/composite).
            if (InstallerHeuristics.IsDirectXOrRuntimeRedist(detection.ProcessName, imagePath) ||
                InstallerHeuristics.IsDirectXOrRuntimeRedist(detection.ProcessName, filePath))
                return true;

            var r = detection.RuleName ?? "";
            foreach (var f in BenignNoiseRuleFragments)
            {
                if (r.IndexOf(f) >= 0)
                    return true; // System32 integrity writes are never kill-grade alone
            }

            // Weak secondary rules only when process is installer/redist context.
            bool installerContext =
                InstallerHeuristics.IsInstallerExtractor(detection.ProcessName, imagePath) ||
                InstallerHeuristics.LooksLikeInstallerName(detection.ProcessName, imagePath);
            if (installerContext)
            {
                foreach (var f in InstallerContextWeakRuleFragments)
                {
                    if (r.IndexOf(f) >= 0)
                        return true;
                }
            }

            // System32/SysWOW64 writes of GPU/DirectX/runtime names = Steam/driver redist race.
            var path = filePath ?? (detection.Evidence ?? "");
            if (path.IndexOf(@"\System32\") >= 0 ||
                path.IndexOf(@"\SysWOW64\") >= 0)
            {
                if (InstallerHeuristics.IsDirectXOrRuntimeRedist(detection.ProcessName, path))
                    return true;

                string[] redistHints =
                {
                    "vulkan", "nvcuda", "nvEncode", "nvapi", "d3d", "dxgi", "xinput",
                    "xaudio", "d3dx", "D3DCompiler", "vcomp", "vcruntime", "msvcp",
                    "ucrtbase", "api-ms-win", "openal", "physx", "x3daudio", "xact",
                    "xapofx", "dsetup", "dxsetup",
                };
                foreach (var h in redistHints)
                {
                    if (path.IndexOf(h) >= 0)
                        return true;
                }

                // Unattributed System32 PE write (PID ≤ 4) during redist races — never kill-grade.
                if (detection.ProcessId <= 4 &&
                    (r.IndexOf("System Directory") >= 0 ||
                     r.IndexOf("Unauthorized Write") >= 0))
                    return true;
            }

            // Low-confidence System32 write signals are observe fuel only — not composite legs.
            if (detection.Confidence > 0 && detection.Confidence < 0.70 &&
                (r.IndexOf("Unauthorized Write") >= 0 ||
                 r.IndexOf("System Directory") >= 0))
                return true;

            return false;
        }

        /// <summary>
        /// True when this signal must not count toward multi-signal composites or chain nukes.
        /// DirectX installs may log Tier2 once or twice; they must never satisfy composite legs.
        /// </summary>
        public static bool IsNonCorrelatingObserveNoise(DetectionEvent detection)
            => detection == null || IsBenignInstallerNoise(detection);

        public static bool IsNukeComposite(DetectionEvent detection)
        {
            if (detection == null) return false;
            var r = detection.RuleName ?? "";
            var e = detection.Evidence ?? "";
            if (e.IndexOf("[COMPOSITE]") >= 0)
                return true;
            foreach (var f in NukeCompositeFragments)
            {
                if (r.IndexOf(f) >= 0)
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Record this detection for PID-level multi-signal correlation.
        /// Returns true when enough distinct rules accumulate AND at least one is a terminal outcome
        /// (or a nuke composite already fired).
        /// </summary>
        public static bool RegisterAndEvaluateChain(DetectionEvent detection, SentinelConfig config)
        {
            if (detection == null || config == null) return false;

            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue(ChainConfirmedKey, out var already) &&
                string.Equals(already, "true"))
                return true;

            if (IsBenignInstallerNoise(detection))
                return false;

            if (IsNukeComposite(detection))
            {
                TagChainConfirmed(detection, "Composite");
                return true;
            }

            int pid = detection.ProcessId;
            if (pid <= 4)
            {
                // No reliable process attribution — never authorize host mutation from PID 0 noise
                // (this is exactly how Steam DirectX / dxsetup races look).
                return false;
            }

            int minSignals = Math.Max(2, config.ChainConfirmMinSignals);
            int windowSec = Math.Max(30, config.ChainConfirmWindowSeconds);
            var window = TimeSpan.FromSeconds(windowSec);

            var buffer = PidBuffers.GetOrAdd(pid, _ => new PidSignalBuffer());
            lock (buffer)
            {
                var now = DateTime.UtcNow;
                buffer.Entries.RemoveAll(e => now - e.When > window);
                buffer.Entries.Add(new SignalEntry(detection.RuleName ?? "unknown", ClassifyTerminalOutcome(detection), now));

                var distinctRules = buffer.Entries.Select(e => e.RuleName).Distinct(StringComparer.OrdinalIgnoreCase).Count();
                var terminal = buffer.Entries.Select(e => e.Outcome).FirstOrDefault(o => o != null);

                if (distinctRules >= minSignals && terminal != null)
                {
                    TagChainConfirmed(detection, terminal);
                    return true;
                }

                // Two+ terminal-family signals of different families (e.g. token + reverse shell)
                var terminalFamilies = buffer.Entries
                    .Where(e => e.Outcome != null)
                    .Select(e => e.Outcome!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                if (terminalFamilies.Count >= 2)
                {
                    TagChainConfirmed(detection, string.Join("+", terminalFamilies));
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// When ObserveUntilChain is on: may we take kill/quarantine/isolate/host mutation?
        /// DLL unload path is always allowed (callers still use DllUnloadEngine).
        /// </summary>
        public static bool MayPerformDestructiveResponse(DetectionEvent detection, SentinelConfig config)
        {
            if (config == null || !config.ActiveResponse)
                return false;

            if (!config.ObserveUntilChain)
                return true;

            if (IsDllUnloadExempt(detection))
                return true;

            return RegisterAndEvaluateChain(detection, config);
        }

        /// <summary>
        /// Inline monitor host mutations (hosts rewrite, SUBST kill, USB disable, cuckoo restore)
        /// when ObserveUntilChain is on — never, unless a detection is already chain-confirmed.
        /// Prefer routing through DetectionEngine so chain logic applies.
        /// </summary>
        public static bool MayPerformInlineHostMutation(SentinelConfig config, DetectionEvent? chainContext = null)
        {
            if (config == null || !config.ActiveResponse)
                return false;

            if (!config.ObserveUntilChain)
                return true;

            if (chainContext != null && MayPerformDestructiveResponse(chainContext, config))
                return true;

            return false;
        }

        public static bool ShouldNotifyUser(DetectionEvent detection, SentinelConfig config)
        {
            if (config == null) return false;
            if (!config.SilentObserve)
                return true;
            if (detection?.Metadata == null) return false;
            return detection.Metadata.TryGetValue(ChainConfirmedKey, out var v) &&
                   string.Equals(v, "true");
        }

        public static bool ShouldAutoReportIncident(DetectionEvent detection, SentinelConfig config)
        {
            // Same gate as user notify when silent observe is on.
            if (config == null) return true;
            if (!config.SilentObserve)
                return true;
            return ShouldNotifyUser(detection, config);
        }

        private static void TagChainConfirmed(DetectionEvent detection, string outcome)
        {
            detection.Metadata ??= new Dictionary<string, string>();
            detection.Metadata[ChainConfirmedKey] = "true";
            detection.Metadata[TerminalOutcomeKey] = outcome;
        }

        private sealed class PidSignalBuffer
        {
            public List<SignalEntry> Entries { get; } = new();
        }

        private readonly record struct SignalEntry(string RuleName, string? Outcome, DateTime When);

        /// <summary>Test helper — clear PID buffers between tests.</summary>
        internal static void ResetForTests() => PidBuffers.Clear();
    }
}
