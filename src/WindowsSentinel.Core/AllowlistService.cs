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

        private static readonly HashSet<string> GamingProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "steam", "steamwebhelper", "GameOverlayUI",
            "EpicGamesLauncher", "EpicWebHelper",
            "origin", "EADesktop", "EABackgroundService",
            "battle.net", "GalaxyClient",
            "UbisoftConnect",
            "riotclientservices", "valorant", "leagueclient",
            "overwolf",
            "EasyAntiCheat", "EasyAntiCheat_EOS",
            "BEService", "BEService_x64",
            "vgc", "vgtray",
            "PnkBstrA", "PnkBstrB",
            "FaceItService",
            "UnityCrashHandler64", "CrashReportClient",
            "UnrealCEFSubProcess",
            "GTA5", "RDR2", "eldenring", "cyberpunk2077",
            "FortniteClient-Win64-Shipping",
            "csgo", "cs2", "dota2",
            "Minecraft.Windows", "javaw",
            "ffxiv_dx11",
        };

        private static readonly string[] TrustedPaths = new[]
        {
            @"\Program Files\",
            @"\Program Files (x86)\",
            @"\Windows\System32\",
            @"\Windows\SysWOW64\",
            @"\Windows\WinSxS\",
            @"\Windows\Microsoft.NET\",
        };

        public AllowlistService(SecureCacheStore cacheStore, ILogger<AllowlistService> logger)
        {
            _cacheStore = cacheStore;
            _logger = logger;
            _userAllowlist = new ConcurrentDictionary<string, AllowlistEntry>(StringComparer.OrdinalIgnoreCase);
            LoadUserAllowlist();
        }

        /// <summary>
        /// Checks if a process should be suppressed from detection entirely.
        /// President's Law rules are NEVER suppressed.
        /// </summary>
        public bool ShouldSuppress(string processName, string? imagePath, string? ruleName)
        {
            if (IsPresidentsLawRule(ruleName)) return false;
            if (IsUserAllowlisted(processName, imagePath)) return true;
            if (GamingProcesses.Contains(processName)) return true;
            return false;
        }

        /// <summary>
        /// Gets a confidence reduction factor (0.0 to 0.5) based on trust signals.
        /// </summary>
        public double GetConfidenceReduction(string processName, string? imagePath, string? signerName, string? ruleName)
        {
            if (IsPresidentsLawRule(ruleName)) return 0.0;

            double reduction = 0.0;

            if (DevelopmentProcesses.Contains(processName))
                reduction += 0.2;

            if (!string.IsNullOrEmpty(imagePath))
            {
                var lowerPath = imagePath.ToLowerInvariant();
                if (TrustedPaths.Any(tp => lowerPath.Contains(tp.ToLowerInvariant())))
                    reduction += 0.1;
            }

            if (IsUserAllowlisted(processName, imagePath))
                reduction += 0.4;

            return Math.Min(0.5, reduction);
        }

        public bool IsDevelopmentProcess(string processName) => DevelopmentProcesses.Contains(processName);
        public bool IsGamingProcess(string processName) => GamingProcesses.Contains(processName);

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
                   lower.Contains("beaconing") ||
                   lower.Contains("hollowing") ||
                   lower.Contains("reverseshell") ||
                   lower.Contains("reverse shell") ||
                   lower.Contains("threatintel");
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
