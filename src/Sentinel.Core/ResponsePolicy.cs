using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace Sentinel.Core
{
    /// <summary>
    /// Global response posture: every monitor is observe-only until a multi-signal chain
    /// points at a real terminal attack (BYOVD, exfil, token theft, reverse shell, cred dump).
    /// DLL unload remediations (DllUnloadEngine + proven sideload load) are exempt and may act immediately.
    /// </summary>
    public static class ResponsePolicy
    {
        /// <summary>Metadata key set when a detection is authorized for full destructive response.</summary>
        public const string ChainConfirmedKey = "ChainConfirmed";

        /// <summary>Metadata key: which terminal outcome family authorized the nuke.</summary>
        public const string TerminalOutcomeKey = "TerminalOutcome";

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
        /// Rules that look "interesting" but are normal life — never terminal, never chain-seed alone.
        /// (Steam DirectX, Vulkan/CUDA redists, GPU driver drops into System32, etc.)
        /// </summary>
        private static readonly string[] BenignNoiseRuleFragments =
        {
            "Unauthorized Write to System Directory",
            "System Integrity: Unauthorized Write",
            "Write to System Directory",
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
                if (r.Contains(f, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue("DllUnloadExempt", out var flag) &&
                string.Equals(flag, "true", StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
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

            var haystack = string.Join(' ',
                detection.RuleName ?? "",
                detection.Evidence ?? "",
                detection.Reasoning ?? "");

            foreach (var (outcome, fragments) in TerminalOutcomes)
            {
                foreach (var f in fragments)
                {
                    if (haystack.Contains(f, StringComparison.OrdinalIgnoreCase))
                        return outcome;
                }
            }

            return null;
        }

        public static bool IsBenignInstallerNoise(DetectionEvent detection)
        {
            if (detection == null) return false;
            var r = detection.RuleName ?? "";
            foreach (var f in BenignNoiseRuleFragments)
            {
                if (r.Contains(f, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // System32/SysWOW64 writes of GPU/DirectX/runtime names with no process = Steam/driver redist race.
            var path = detection.Metadata != null && detection.Metadata.TryGetValue("FilePath", out var fp)
                ? fp
                : (detection.Evidence ?? "");
            if (path.Contains(@"\System32\", StringComparison.OrdinalIgnoreCase) ||
                path.Contains(@"\SysWOW64\", StringComparison.OrdinalIgnoreCase))
            {
                string[] redistHints =
                {
                    "vulkan", "nvcuda", "nvEncode", "nvapi", "d3d", "dxgi", "xinput",
                    "xaudio", "d3dx", "D3DCompiler", "vcomp", "vcruntime", "msvcp",
                    "ucrtbase", "api-ms-win", "openal", "physx",
                };
                foreach (var h in redistHints)
                {
                    if (path.Contains(h, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }

            return false;
        }

        public static bool IsNukeComposite(DetectionEvent detection)
        {
            if (detection == null) return false;
            var r = detection.RuleName ?? "";
            var e = detection.Evidence ?? "";
            if (e.Contains("[COMPOSITE]", StringComparison.OrdinalIgnoreCase))
                return true;
            foreach (var f in NukeCompositeFragments)
            {
                if (r.Contains(f, StringComparison.OrdinalIgnoreCase))
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
                string.Equals(already, "true", StringComparison.OrdinalIgnoreCase))
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
                   string.Equals(v, "true", StringComparison.OrdinalIgnoreCase);
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
