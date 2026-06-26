using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Manages allowlisting for detection suppression and confidence reduction.
    /// Includes built-in trusted publishers, development tools, gaming processes,
    /// and a user-managed persistent allowlist stored in SecureCacheStore.
    /// President's Law rules (LSASS, AMSI, ETW, ransomware, self-protection) are
    /// NEVER suppressed regardless of allowlist status.
    /// </summary>
    public sealed class AllowlistService
    {
        private readonly SecureCacheStore _cacheStore;
        private readonly ILogger<AllowlistService> _logger;
        private readonly ConcurrentDictionary<string, AllowlistEntry> _userAllowlist;

        public AllowlistService(SecureCacheStore cacheStore, ILogger<AllowlistService> logger)
        {
            _cacheStore = cacheStore;
            _logger = logger;
            _userAllowlist = new ConcurrentDictionary<string, AllowlistEntry>(StringComparer.OrdinalIgnoreCase);
            LoadUserAllowlist();
        }

        /// <summary>
        /// Checks if a process should be suppressed from detection entirely.
        ///
        /// ONLY the user-managed allowlist can suppress detections.
        /// No built-in name lists, no path guessing, no gaming exemptions.
        ///
        /// If a detection fires on a legitimate app, it means the behavioral
        /// detection is wrong and needs fixing — not that the app needs allowlisting.
        ///
        /// President's Law rules (LSASS, ransomware, injection, etc.) are NEVER
        /// suppressed regardless of allowlist status.
        /// </summary>
        public bool ShouldSuppress(string processName, string? imagePath, string? ruleName)
        {
            // President's Law rules are NEVER fully suppressed — even if user-allowlisted.
            // However, user-allowlisted processes get demoted in the response engine (LogOnly),
            // not suppressed at detection level. This ensures the detection is always logged.
            if (IsPresidentsLawRule(ruleName)) return false;
            if (IsUserAllowlisted(processName, imagePath)) return true;
            return false;
        }

        /// <summary>
        /// Gets a confidence reduction factor (0.0 to 0.3) based on trust signals.
        /// Only reduces confidence — never suppresses. And only for user-allowlisted processes.
        /// </summary>
        public double GetConfidenceReduction(string processName, string? imagePath, string? signerName, string? ruleName)
        {
            if (IsPresidentsLawRule(ruleName)) return 0.0;
            if (IsUserAllowlisted(processName, imagePath)) return 0.3;
            return 0.0;
        }

        /// <summary>
        /// Development process check — used only by ParentPidSpoofDetector to reduce
        /// PPID false positives on tools with complex spawn chains. Requires path verification
        /// at the call site — this method alone does NOT grant any suppression.
        /// </summary>
        public bool IsDevelopmentProcess(string processName)
        {
            return DevelopmentProcesses.Contains(processName);
        }

        private static readonly HashSet<string> DevelopmentProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "devenv", "code", "Windsurf", "cursor",
            "msbuild", "dotnet", "node", "npm", "python", "py",
            "git", "git-remote-https",
            "cargo", "rustc", "go", "java", "javac",
            "cl", "link", "cmake", "ninja",
            "docker", "docker-compose", "kubectl",
            "powershell", "pwsh", "cmd", "wt",
            "rider64", "phpstorm64", "idea64", "webstorm64", "goland64",
        };

        public void AddToUserAllowlist(string processName, string? imagePath, string reason)
        {
            _userAllowlist[processName.ToLowerInvariant()] = new AllowlistEntry
            {
                ProcessName = processName,
                ImagePath = imagePath ?? "",
                Reason = reason,
                AddedAt = DateTimeOffset.UtcNow,
                AddedBy = "User"
            };
            SaveUserAllowlist();
            _logger.LogInformation("Allowlist: Added '{Process}' — {Reason}", processName, reason);
        }

        public void RemoveFromUserAllowlist(string processName)
        {
            if (_userAllowlist.TryRemove(processName.ToLowerInvariant(), out _))
            {
                SaveUserAllowlist();
                _logger.LogInformation("Allowlist: Removed '{Process}'", processName);
            }
        }

        public IReadOnlyList<AllowlistEntry> GetUserAllowlist() => _userAllowlist.Values.ToList();

        private bool IsUserAllowlisted(string processName, string? imagePath)
        {
            if (_userAllowlist.ContainsKey(processName.ToLowerInvariant()))
                return true;

            if (!string.IsNullOrEmpty(imagePath))
                return _userAllowlist.Values.Any(e =>
                    !string.IsNullOrEmpty(e.ImagePath) &&
                    imagePath.Equals(e.ImagePath, StringComparison.OrdinalIgnoreCase));

            return false;
        }

        private static bool IsPresidentsLawRule(string? ruleName)
        {
            if (string.IsNullOrEmpty(ruleName)) return false;
            var lower = ruleName.ToLowerInvariant();
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
                   lower.Contains("hollowing") ||
                   lower.Contains("reverseshell") ||
                   lower.Contains("reverse shell") ||
                   lower.Contains("threatintel");
            // NOTE: "beaconing" removed from President's Law (v0.8.2).
            // Beaconing detections now use multi-factor cryptographic trust verification
            // (Authenticode + path + diversity + baseline) in the BeaconingDetector itself.
            // The detection ALWAYS fires and is logged, but the response is demoted for
            // verified-legitimate software. This can't be exploited because demotion requires
            // a valid Authenticode signature (needs the publisher's private key).
        }

        private void LoadUserAllowlist()
        {
            try
            {
                var json = _cacheStore.Load("allowlist", "user");
                if (string.IsNullOrWhiteSpace(json)) return;
                var entries = JsonSerializer.Deserialize<List<AllowlistEntry>>(json);
                if (entries == null) return;
                foreach (var e in entries)
                    _userAllowlist[e.ProcessName.ToLowerInvariant()] = e;
                _logger.LogInformation("Allowlist: Loaded {Count} user entries", _userAllowlist.Count);
            }
            catch { }
        }

        private void SaveUserAllowlist()
        {
            try
            {
                var json = JsonSerializer.Serialize(_userAllowlist.Values.ToList());
                _cacheStore.Save("allowlist", "user", json);
            }
            catch { }
        }
    }

    public sealed class AllowlistEntry
    {
        public string ProcessName { get; set; } = "";
        public string ImagePath { get; set; } = "";
        public string Reason { get; set; } = "";
        public DateTimeOffset AddedAt { get; set; }
        public string AddedBy { get; set; } = "";
    }
}
