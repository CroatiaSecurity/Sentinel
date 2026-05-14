using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Contextual Analysis Engine - Analyzes execution context to reduce false positives.
/// Detects installer context, update context, boot context, and user activity.
/// </summary>
public sealed class ContextualAnalysisEngine
{
    private readonly ILogger<ContextualAnalysisEngine> _logger;
    
    // Context tracking
    private readonly ConcurrentDictionary<string, InstallerContextInfo> _activeInstallers;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _activeUpdates;
    private DateTimeOffset _lastUserActivity = DateTimeOffset.UtcNow;
    private DateTimeOffset _systemStartTime = DateTimeOffset.UtcNow;
    
    // Configuration
    private readonly TimeSpan _installerContextWindow = TimeSpan.FromMinutes(10);
    private readonly TimeSpan _updateContextWindow = TimeSpan.FromMinutes(5);
    private readonly TimeSpan _bootContextWindow = TimeSpan.FromMinutes(3);
    private readonly TimeSpan _userActivityWindow = TimeSpan.FromMinutes(5);

    // Known installer processes
    private static readonly HashSet<string> InstallerProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "msiexec.exe", "setup.exe", "install.exe", "installer.exe", "wininst.exe",
        "inno_setup.exe", "nsis.exe", "wise.exe", "installshield.exe",
        "wusa.exe", "dism.exe", "sfc.exe", "pkgmgr.exe", "ocsetup.exe",
        "chrome_installer.exe", "firefox_installer.exe", "vs_setup.exe",
        "teams_installer.exe", "onedrive_setup.exe", "zoom_installer.exe",
        "discord_installer.exe", "steam_installer.exe", "epic_games_launcher.exe"
    };

    // Known update processes
    private static readonly HashSet<string> UpdateProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "wuauclt.exe", "usoclient.exe", "umclient.exe", "windowsupdatebox.exe",
        "update.exe", "updater.exe", "autoupdate.exe", "checkforupdates.exe",
        "googleupdate.exe", "firefox_updater.exe", "chrome_updater.exe",
        "edge_update.exe", "onedrive_update.exe", "teams_update.exe",
        "zoom_update.exe", "discord_update.exe", "steam_client_bootstrapper.exe",
        "origin_client_service.exe", "epic_online_services.exe"
    };

    // Browser processes
    private static readonly HashSet<string> BrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "opera.exe",
        "iexplore.exe", "safari.exe", "vivaldi.exe", "tor.exe"
    };

    // Office processes
    private static readonly HashSet<string> OfficeProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
        "onenote.exe", "onenotem.exe", "mspub.exe", "visio.exe", "teams.exe"
    };

    // Development tools — legitimately do "suspicious" things (compile, inject, debug)
    private static readonly HashSet<string> DevelopmentProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "devenv.exe", "rider64.exe", "code.exe", "idea64.exe", "webstorm64.exe",
        "msbuild.exe", "dotnet.exe", "node.exe", "npm.cmd", "cargo.exe",
        "rustc.exe", "go.exe", "javac.exe", "python.exe", "python3.exe",
        "cmake.exe", "ninja.exe", "cl.exe", "link.exe", "gcc.exe", "g++.exe",
        "docker.exe", "wsl.exe", "git.exe", "nuget.exe",
        "windbg.exe", "cdb.exe", "procdump.exe", "procmon.exe", "procexp.exe",
        "perfview.exe", "testhost.exe", "vstest.console.exe", "xunit.console.exe"
    };

    // Gaming processes — never interfere
    private static readonly HashSet<string> GamingProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "steam.exe", "steamwebhelper.exe", "epicgameslauncher.exe",
        "origin.exe", "eadesktop.exe", "battle.net.exe", "gog galaxy.exe",
        "ubisoft game launcher.exe", "riotclientservices.exe",
        "overwolf.exe", "obs64.exe", "obs.exe", "streamlabs obs.exe"
    };

    public ContextualAnalysisEngine(ILogger<ContextualAnalysisEngine> logger)
    {
        _logger = logger;
        _activeInstallers = new ConcurrentDictionary<string, InstallerContextInfo>();
        _activeUpdates = new ConcurrentDictionary<string, DateTimeOffset>();
        _systemStartTime = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Records that a process is an installer/updater.
    /// </summary>
    public void RecordInstallerStart(string processName, string? commandLine = null)
    {
        if (string.IsNullOrEmpty(processName)) return;

        var key = processName.ToLowerInvariant();
        
        _activeInstallers[key] = new InstallerContextInfo
        {
            ProcessName = processName,
            StartTime = DateTimeOffset.UtcNow,
            CommandLine = commandLine ?? "",
            IsInstaller = IsKnownInstaller(processName)
        };

        _logger.LogDebug("Context: Installer context started for {Process}", processName);
    }

    /// <summary>
    /// Records that an installer/updater has finished.
    /// </summary>
    public void RecordInstallerEnd(string processName)
    {
        if (string.IsNullOrEmpty(processName)) return;
        
        _activeInstallers.TryRemove(processName.ToLowerInvariant(), out _);
    }

    /// <summary>
    /// Records that an update is in progress.
    /// </summary>
    public void RecordUpdateStart(string processName)
    {
        if (string.IsNullOrEmpty(processName)) return;
        
        _activeUpdates[processName.ToLowerInvariant()] = DateTimeOffset.UtcNow;
        _logger.LogDebug("Context: Update context started for {Process}", processName);
    }

    /// <summary>
    /// Records user activity.
    /// </summary>
    public void RecordUserActivity()
    {
        _lastUserActivity = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Analyzes the context for a detection and returns context flags.
    /// </summary>
    public ContextFlags AnalyzeContext(
        string processName,
        string? parentProcessName = null,
        string? commandLine = null)
    {
        var flags = ContextFlags.None;

        // Check installer context
        if (IsInInstallerContext(processName, parentProcessName))
        {
            flags |= ContextFlags.InstallerContext;
        }

        // Check update context
        if (IsInUpdateContext(processName, parentProcessName))
        {
            flags |= ContextFlags.UpdateContext;
        }

        // Check boot context
        if (IsInBootContext())
        {
            flags |= ContextFlags.BootContext;
        }

        // Check user activity
        if (IsRecentUserActivity())
        {
            flags |= ContextFlags.UserActiveContext;
        }

        // Check first run
        if (IsFirstRun(processName))
        {
            flags |= ContextFlags.FirstRunContext;
        }

        // Check if browser
        if (BrowserProcesses.Contains(processName))
        {
            flags |= ContextFlags.BrowserContext;
        }

        // Check if office app
        if (OfficeProcesses.Contains(processName))
        {
            flags |= ContextFlags.OfficeContext;
        }

        // Check if development tool
        if (DevelopmentProcesses.Contains(processName))
        {
            flags |= ContextFlags.DevelopmentContext;
        }

        // Check if gaming
        if (GamingProcesses.Contains(processName))
        {
            flags |= ContextFlags.GameContext;
        }

        // Check for elevated process
        if (IsElevatedProcess(processName, commandLine))
        {
            flags |= ContextFlags.ElevatedContext;
        }

        return flags;
    }

    /// <summary>
    /// Gets a modifier to apply to suspicion score based on context.
    /// Negative = reduce suspicion, Positive = increase suspicion.
    /// </summary>
    public int GetContextModifier(ContextFlags flags)
    {
        int modifier = 0;

        // Legitimate contexts reduce suspicion
        if (flags.HasFlag(ContextFlags.InstallerContext))
        {
            modifier -= 20;
        }

        if (flags.HasFlag(ContextFlags.UpdateContext))
        {
            modifier -= 15;
        }

        if (flags.HasFlag(ContextFlags.BootContext))
        {
            modifier -= 10; // Boot-time processes are often legitimate
        }

        if (flags.HasFlag(ContextFlags.UserActiveContext))
        {
            modifier -= 5; // User is present, likely intentional
        }

        if (flags.HasFlag(ContextFlags.BrowserContext) || flags.HasFlag(ContextFlags.OfficeContext))
        {
            modifier -= 10; // Common legitimate apps
        }

        // Development tools legitimately do "suspicious" things
        if (flags.HasFlag(ContextFlags.DevelopmentContext))
        {
            modifier -= 25; // Strong reduction — devs compile, inject, debug
        }

        // Gaming — never interfere
        if (flags.HasFlag(ContextFlags.GameContext))
        {
            modifier -= 30; // Very strong reduction — games use anti-cheat, hooks, etc.
        }

        // Suspicious contexts increase suspicion
        if (flags.HasFlag(ContextFlags.FirstRunContext) && !flags.HasFlag(ContextFlags.InstallerContext))
        {
            modifier += 5; // First run without installer context is slightly suspicious
        }

        // Combo: First run + No user activity = more suspicious
        if (flags.HasFlag(ContextFlags.FirstRunContext) && !flags.HasFlag(ContextFlags.UserActiveContext))
        {
            modifier += 10;
        }

        // Cap the modifier
        return Math.Max(-50, Math.Min(50, modifier));
    }

    /// <summary>
    /// Gets a human-readable description of the context.
    /// </summary>
    public string GetContextDescription(ContextFlags flags)
    {
        if (flags == ContextFlags.None) return "Normal execution";

        var descriptions = new List<string>();

        if (flags.HasFlag(ContextFlags.InstallerContext))
            descriptions.Add("Software installation in progress");
        
        if (flags.HasFlag(ContextFlags.UpdateContext))
            descriptions.Add("Software update in progress");
        
        if (flags.HasFlag(ContextFlags.BootContext))
            descriptions.Add("System startup phase");
        
        if (flags.HasFlag(ContextFlags.UserActiveContext))
            descriptions.Add("User recently active");
        
        if (flags.HasFlag(ContextFlags.FirstRunContext))
            descriptions.Add("First time execution");
        
        if (flags.HasFlag(ContextFlags.BrowserContext))
            descriptions.Add("Browser process");
        
        if (flags.HasFlag(ContextFlags.OfficeContext))
            descriptions.Add("Office application");
        
        if (flags.HasFlag(ContextFlags.ElevatedContext))
            descriptions.Add("Running with elevated privileges");

        return string.Join("; ", descriptions);
    }

    /// <summary>
    /// Determines if a process is in a legitimate install path.
    /// </summary>
    public bool IsLegitimateInstallPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;

        var lowerPath = path.ToLowerInvariant();

        // Standard legitimate paths
        var legitimatePaths = new[]
        {
            @"\program files\",
            @"\program files (x86)\",
            @"\windows\system32\",
            @"\windows\syswow64\",
            @"\windows\microsoft.net\",
            @"\windows\winsxs\",
            @"\windows\installer\"
        };

        return legitimatePaths.Any(lp => lowerPath.Contains(lp));
    }

    private bool IsInInstallerContext(string processName, string? parentProcessName)
    {
        // Check if this process is a known installer
        if (IsKnownInstaller(processName))
            return true;

        // Check if parent was an installer
        if (!string.IsNullOrEmpty(parentProcessName))
        {
            if (_activeInstallers.ContainsKey(parentProcessName.ToLowerInvariant()))
            {
                var info = _activeInstallers[parentProcessName.ToLowerInvariant()];
                if (DateTimeOffset.UtcNow - info.StartTime < _installerContextWindow)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private bool IsInUpdateContext(string processName, string? parentProcessName)
    {
        // Check if this process is a known updater
        if (IsKnownUpdater(processName))
            return true;

        // Check active updates
        if (_activeUpdates.ContainsKey(processName.ToLowerInvariant()))
        {
            var startTime = _activeUpdates[processName.ToLowerInvariant()];
            if (DateTimeOffset.UtcNow - startTime < _updateContextWindow)
            {
                return true;
            }
        }

        // Check parent
        if (!string.IsNullOrEmpty(parentProcessName))
        {
            if (_activeUpdates.ContainsKey(parentProcessName.ToLowerInvariant()))
            {
                var startTime = _activeUpdates[parentProcessName.ToLowerInvariant()];
                if (DateTimeOffset.UtcNow - startTime < _updateContextWindow)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private bool IsInBootContext()
    {
        return DateTimeOffset.UtcNow - _systemStartTime < _bootContextWindow;
    }

    private bool IsRecentUserActivity()
    {
        return DateTimeOffset.UtcNow - _lastUserActivity < _userActivityWindow;
    }

    private bool IsFirstRun(string processName)
    {
        // In production, this would check against a database of seen processes
        // For now, we use a simple heuristic: process started within last 2 minutes
        return false; // Placeholder - would need process start time tracking
    }

    private bool IsElevatedProcess(string processName, string? commandLine)
    {
        // Check for elevation indicators in command line
        if (!string.IsNullOrEmpty(commandLine))
        {
            var lowerCmd = commandLine.ToLowerInvariant();
            if (lowerCmd.Contains("-verb runas") || 
                lowerCmd.Contains("runas") ||
                lowerCmd.Contains("requestedexecutionlevel=requireadministrator"))
            {
                return true;
            }
        }

        return false;
    }

    private bool IsKnownInstaller(string processName)
    {
        return InstallerProcesses.Contains(processName) ||
               processName.Contains("setup", StringComparison.OrdinalIgnoreCase) ||
               processName.Contains("install", StringComparison.OrdinalIgnoreCase) ||
               processName.Contains("installer", StringComparison.OrdinalIgnoreCase);
    }

    private bool IsKnownUpdater(string processName)
    {
        return UpdateProcesses.Contains(processName) ||
               processName.Contains("update", StringComparison.OrdinalIgnoreCase) ||
               processName.Contains("updater", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Cleanup old entries.
    /// </summary>
    public void Cleanup()
    {
        var now = DateTimeOffset.UtcNow;

        // Clean old installer contexts
        var oldInstallers = _activeInstallers
            .Where(kv => now - kv.Value.StartTime > _installerContextWindow)
            .Select(kv => kv.Key)
            .ToList();
        
        foreach (var key in oldInstallers)
        {
            _activeInstallers.TryRemove(key, out _);
        }

        // Clean old update contexts
        var oldUpdates = _activeUpdates
            .Where(kv => now - kv.Value > _updateContextWindow)
            .Select(kv => kv.Key)
            .ToList();
        
        foreach (var key in oldUpdates)
        {
            _activeUpdates.TryRemove(key, out _);
        }
    }
}

/// <summary>
/// Context flags for execution context.
/// </summary>
[Flags]
public enum ContextFlags
{
    None = 0,
    InstallerContext = 1 << 0,      // Software installation in progress
    UpdateContext = 1 << 1,         // Software update in progress
    BootContext = 1 << 2,           // System startup phase
    UserActiveContext = 1 << 3,     // User recently active
    FirstRunContext = 1 << 4,       // First time execution
    BrowserContext = 1 << 5,        // Browser process
    OfficeContext = 1 << 6,         // Office application
    ElevatedContext = 1 << 7,       // Running elevated
    GameContext = 1 << 8,           // Gaming application
    DevelopmentContext = 1 << 9     // Development tool
}

public sealed class InstallerContextInfo
{
    public string ProcessName { get; set; } = "";
    public DateTimeOffset StartTime { get; set; }
    public string CommandLine { get; set; } = "";
    public bool IsInstaller { get; set; }
}
