using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Allowlist Service — Proactive false positive prevention.
///
/// Three tiers of trust:
///   1. Signed Vendor Trust: Microsoft-signed and known-good publisher binaries
///      are automatically trusted (never killed, reduced scoring).
///   2. Development Context: Dev tools (VS, Rider, Docker, WSL, npm, dotnet)
///      get reduced scoring when performing expected behaviors.
///   3. User Allowlist: Processes/paths the user explicitly marks as safe.
///      Persisted via SecureCacheStore (DPAPI+HMAC).
///
/// The allowlist NEVER overrides President's Law kills for:
///   - LSASS credential dumping
///   - AMSI/ETW tampering
///   - Ransomware mass-write
///   - Self-protection violations
/// These are always lethal regardless of allowlist status.
/// </summary>
public sealed class AllowlistService
{
    private readonly ILogger<AllowlistService> _logger;
    private readonly SecureCacheStore _store;

    // User-defined allowlist (persisted)
    private readonly ConcurrentDictionary<string, AllowlistEntry> _userAllowlist;

    // Signed vendor trust (built-in, not persisted)
    private static readonly HashSet<string> TrustedPublishers = new(StringComparer.OrdinalIgnoreCase)
    {
        // OS vendors
        "Microsoft Corporation",
        "Microsoft Windows",
        "Microsoft Windows Publisher",
        "Apple Inc.",
        // Browsers
        "Google LLC",
        "Google Inc",
        "Mozilla Corporation",
        "Brave Software, Inc.",
        "Opera Norway AS",
        "Vivaldi Technologies AS",
        // Creative / productivity
        "Adobe Inc.",
        "Adobe Systems Incorporated",
        "Figma, Inc.",
        "Notion Labs, Inc.",
        "Obsidian",
        // Hardware / drivers
        "Intel Corporation",
        "Intel(R) Corporation",
        "NVIDIA Corporation",
        "Advanced Micro Devices, Inc.",
        "Realtek Semiconductor Corp.",
        "Logitech",
        "Corsair Memory, Inc.",
        "SteelSeries ApS",
        "Razer Inc.",
        "HyperX",
        "Samsung Electronics Co., Ltd.",
        "Western Digital Technologies, Inc.",
        "Seagate Technology LLC",
        // Gaming
        "Valve Corp.",
        "Valve",
        "Epic Games, Inc.",
        "Riot Games, Inc.",
        "Electronic Arts, Inc.",
        "Blizzard Entertainment, Inc.",
        "Steam",
        "Ubisoft Entertainment SA",
        "CD PROJEKT S.A.",
        "Rockstar Games, Inc.",
        "Take-Two Interactive Software, Inc.",
        "Bethesda Softworks LLC",
        "BANDAI NAMCO Entertainment Inc.",
        "Square Enix Co., Ltd.",
        "Capcom Co., Ltd.",
        "SEGA Corporation",
        // Dev tools
        "JetBrains s.r.o.",
        "JetBrains",
        "GitHub, Inc.",
        "Docker Inc",
        "Oracle Corporation",
        "Oracle America, Inc.",
        "Red Hat, Inc.",
        "Canonical Ltd.",
        "Node.js Foundation",
        "Python Software Foundation",
        "The Git Development Community",
        "Sublime HQ Pty Ltd",
        "Panic, Inc.",
        // Communication
        "Zoom Video Communications, Inc.",
        "Slack Technologies, Inc.",
        "Spotify AB",
        "Discord Inc.",
        "Telegram FZ-LLC",
        "Signal Messenger, LLC",
        "WhatsApp LLC",
        // Media / streaming
        "OBS Project",
        "VideoLAN",
        "Plex, Inc.",
        "Audacity Team",
        "GIMP",
        // Utilities
        "Notepad++",
        "WireGuard LLC",
        "OpenVPN Inc.",
        "7-Zip",
        "Igor Pavlov",
        "WinRAR GmbH",
        "RARLAB",
        "PeaZip",
        "Bitwarden Inc.",
        "AgileBits Inc.",
        "NordVPN S.A.",
        "ExpressVPN",
        "Mullvad VPN AB",
        "ProtonVPN AG",
        "Proton AG",
        "Malwarebytes Inc.",
        "Malwarebytes Corporation",
        // Security / optimization products
        "Trend Micro Inc.",
        "Trend Micro, Inc.",
        "IObit",
        "IObit Information Technology",
        "Ashampoo GmbH & Co. KG",
        "Piriform Software Ltd",  // CCleaner
        "Gen Digital Inc.",       // Norton/Avast/AVG parent
        "ESET, spol. s r.o.",
        "Kaspersky Lab",
        "Bitdefender SRL",
        "F-Secure Corporation",
        "Sophos Ltd",
        // Cloud / productivity
        "Dropbox, Inc.",
        "Box, Inc.",
        "Atlassian Pty Ltd",
        "Salesforce, Inc.",
    };

    // Development tools — processes that legitimately do "suspicious" things
    private static readonly HashSet<string> DevelopmentProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // IDEs
        "devenv", "rider64", "code", "idea64", "webstorm64", "pycharm64",
        "clion64", "goland64", "rubymine64", "phpstorm64", "datagrip64",
        "android studio", "eclipse", "netbeans", "sublime_text", "notepad++",
        "cursor", "Kiro", "zed", "fleet",
        // Build tools
        "msbuild", "dotnet", "node", "npm", "npx", "yarn", "pnpm",
        "python", "python3", "pip", "pip3", "cargo", "rustc", "rustup",
        "go", "javac", "java", "gradle", "gradlew", "mvn", "maven",
        "cmake", "make", "ninja", "cl", "link", "gcc", "g++", "clang",
        "tsc", "webpack", "vite", "esbuild", "rollup", "turbo", "nx",
        "deno", "bun",
        // Containers & VMs
        "docker", "dockerd", "docker-compose", "podman", "containerd",
        "wsl", "wslhost", "vmware", "vmplayer", "virtualbox", "vboxheadless",
        "hyper-v", "vmms", "vmwp", "qemu-system-x86_64",
        // Version control
        "git", "git-remote-https", "gh", "svn", "hg",
        // Package managers
        "nuget", "choco", "chocolatey", "winget", "scoop", "pip", "conda",
        // Debuggers & profilers
        "windbg", "cdb", "ntsd", "procdump", "procmon", "procexp",
        "perfview", "dotnet-trace", "dotnet-dump", "dotnet-counters",
        "x64dbg", "x32dbg", "ollydbg",
        // Terminals
        "windowsterminal", "wt", "conhost", "mintty", "alacritty",
        "powershell", "pwsh", "cmd", "bash", "wezterm-gui",
        // Database tools
        "ssms", "mysql", "psql", "mongod", "redis-server", "sqlite3",
        // API / network tools
        "postman", "insomnia", "curl", "wget", "httpie",
        "fiddler", "wireshark", "nmap",
    };

    // Gaming processes — never interfere with games
    private static readonly HashSet<string> GamingProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Launchers
        "steam", "steamwebhelper", "steamservice",
        "epicgameslauncher", "easyanticheat", "battleye",
        "origin", "ea app", "eadesktop", "EABackgroundService",
        "battle.net", "agent",
        "gog galaxy", "galaxyclient", "GalaxyClient",
        "ubisoft game launcher", "uplay", "UbisoftConnect",
        "riotclientservices", "valorant", "leagueclient",
        "overwolf",
        "playnite", "Playnite.DesktopApp",
        "heroic", "lutris",
        // Anti-cheat (these do kernel-level stuff that looks suspicious)
        "EasyAntiCheat", "EasyAntiCheat_EOS",
        "BEService", "BEService_x64",
        "vgc", "vgtray",                    // Vanguard (Valorant)
        "PnkBstrA", "PnkBstrB",             // PunkBuster
        "FaceItService", "faceit",
        // Common game engines / runtimes
        "UnityCrashHandler64", "CrashReportClient",
        "UnrealCEFSubProcess",
        // Specific popular games (high-IO, network, memory patterns)
        "GTA5", "RDR2", "eldenring", "cyberpunk2077",
        "Overwatch", "Diablo IV", "WorldOfWarcraft",
        "FortniteClient-Win64-Shipping",
        "csgo", "cs2", "dota2",
        "Minecraft.Windows", "javaw",
        "ffxiv_dx11", "FFXIV",
    };

    // Paths that are always legitimate (never flag files here)
    private static readonly string[] TrustedPaths = new[]
    {
        @"\Program Files\",
        @"\Program Files (x86)\",
        @"\Windows\System32\",
        @"\Windows\SysWOW64\",
        @"\Windows\WinSxS\",
        @"\Windows\Microsoft.NET\",
    };

    public AllowlistService(ILogger<AllowlistService> logger)
    {
        _logger = logger;
        _store = new SecureCacheStore(logger, "user_allowlist");
        _userAllowlist = new ConcurrentDictionary<string, AllowlistEntry>(StringComparer.OrdinalIgnoreCase);
        LoadUserAllowlist();
    }

    /// <summary>
    /// Checks if a process should be suppressed from detection entirely.
    /// Returns true if the process is allowlisted and the rule is NOT a President's Law rule.
    /// President's Law rules ALWAYS fire regardless of allowlist.
    /// </summary>
    public bool ShouldSuppress(string processName, string? imagePath, string? ruleName)
    {
        // President's Law rules are NEVER suppressed
        if (IsPresidentsLawRule(ruleName))
            return false;

        // Check user allowlist (highest priority)
        if (IsUserAllowlisted(processName, imagePath))
            return true;

        // Check gaming context (never interfere with games)
        if (GamingProcesses.Contains(processName))
            return true;

        return false;
    }

    /// <summary>
    /// Gets a confidence reduction factor based on trust level.
    /// Returns 0.0 (no reduction) to 0.5 (halve confidence).
    /// President's Law rules always return 0.0 (no reduction).
    /// </summary>
    public double GetConfidenceReduction(
        string processName,
        string? imagePath,
        string? signerName,
        string? ruleName)
    {
        if (IsPresidentsLawRule(ruleName))
            return 0.0;

        double reduction = 0.0;

        // Trusted publisher signature
        if (!string.IsNullOrEmpty(signerName) && TrustedPublishers.Contains(signerName))
        {
            reduction += 0.3;
        }

        // Development tool context
        if (DevelopmentProcesses.Contains(processName))
        {
            reduction += 0.2;
        }

        // Trusted install path
        if (!string.IsNullOrEmpty(imagePath))
        {
            var lowerPath = imagePath.ToLowerInvariant();
            if (TrustedPaths.Any(tp => lowerPath.Contains(tp.ToLowerInvariant())))
            {
                reduction += 0.1;
            }
        }

        // User allowlist
        if (IsUserAllowlisted(processName, imagePath))
        {
            reduction += 0.4;
        }

        return Math.Min(0.5, reduction); // Never reduce by more than half
    }

    /// <summary>
    /// Checks if a process is a known development tool.
    /// Used by the correlation engine to avoid flagging dev activity as attacks.
    /// </summary>
    public bool IsDevelopmentProcess(string processName)
    {
        return DevelopmentProcesses.Contains(processName);
    }

    /// <summary>
    /// Checks if a process is a known gaming process.
    /// </summary>
    public bool IsGamingProcess(string processName)
    {
        return GamingProcesses.Contains(processName);
    }

    /// <summary>
    /// Checks if a signer is in the trusted publishers list.
    /// </summary>
    public bool IsTrustedPublisher(string? signerName)
    {
        if (string.IsNullOrEmpty(signerName)) return false;
        return TrustedPublishers.Contains(signerName);
    }

    /// <summary>
    /// Adds a process to the user allowlist.
    /// </summary>
    public void AddToUserAllowlist(string processName, string? imagePath, string reason)
    {
        var key = processName.ToLowerInvariant();
        _userAllowlist[key] = new AllowlistEntry
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

    /// <summary>
    /// Removes a process from the user allowlist.
    /// </summary>
    public void RemoveFromUserAllowlist(string processName)
    {
        if (_userAllowlist.TryRemove(processName.ToLowerInvariant(), out _))
        {
            SaveUserAllowlist();
            _logger.LogInformation("Allowlist: Removed '{Process}'", processName);
        }
    }

    /// <summary>
    /// Gets all user allowlist entries.
    /// </summary>
    public IReadOnlyList<AllowlistEntry> GetUserAllowlist()
    {
        return _userAllowlist.Values.ToList();
    }

    private bool IsUserAllowlisted(string processName, string? imagePath)
    {
        if (_userAllowlist.ContainsKey(processName.ToLowerInvariant()))
            return true;

        // Also check by path
        if (!string.IsNullOrEmpty(imagePath))
        {
            return _userAllowlist.Values.Any(e =>
                !string.IsNullOrEmpty(e.ImagePath) &&
                imagePath.Equals(e.ImagePath, StringComparison.OrdinalIgnoreCase));
        }

        return false;
    }

    /// <summary>
    /// President's Law rules that NEVER respect allowlists.
    /// These are existential threats that must always be acted upon.
    /// </summary>
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
               lower.Contains("honeypot") ||
               lower.Contains("chain-nuke") ||
               lower.Contains("composite");
    }

    private void LoadUserAllowlist()
    {
        var data = _store.TryLoad<AllowlistData>();
        if (data == null) return;

        foreach (var entry in data.Entries)
        {
            _userAllowlist[entry.ProcessName.ToLowerInvariant()] = entry;
        }

        _logger.LogInformation("Allowlist: Loaded {Count} user allowlist entries", _userAllowlist.Count);
    }

    private void SaveUserAllowlist()
    {
        var data = new AllowlistData
        {
            Entries = _userAllowlist.Values.ToList(),
            SavedAt = DateTimeOffset.UtcNow
        };
        _store.TrySave(data);
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

public sealed class AllowlistData
{
    public List<AllowlistEntry> Entries { get; set; } = new();
    public DateTimeOffset SavedAt { get; set; }
}


