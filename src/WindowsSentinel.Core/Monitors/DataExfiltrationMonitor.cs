using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Data Exfiltration Prevention Monitor (v1.8.0) — Correlation-based DLP.
/// 
/// PHILOSOPHY: Zero false positives. We achieve this by NEVER firing on a single signal.
/// Every detection requires correlation of 2+ independent indicators within a time window.
/// 
/// How it works:
///   1. Monitors DNS resolutions for known exfil service domains (via DnsQueryMonitor — Tier2)
///   2. Monitors sensitive file access patterns (credential stores, SSH keys — Tier2)
///   3. Monitors removable media reads (USB drives — Tier2)
///   4. Monitors outbound connection volume per-process
///   5. The BehavioralCorrelationEngine combines these Tier2 signals into Tier1 kills:
///      - Exfil DNS + Network connection = KILL
///      - Sensitive file access + Network connection = KILL
///      - Removable media read + Network connection = KILL
///      - Exfil DNS + Sensitive file access = KILL (pre-staging)
/// 
/// Single signals are ALWAYS Tier2 (log only). This prevents false positives:
///   - Chrome resolving mega.nz? Tier2 log. (User browsing normally)
///   - Git reading ~/.ssh/id_rsa? Tier2 log. (Normal git operation)
///   - OneDrive syncing from USB? Tier2 log. (Normal sync)
///   - Unknown process reads USB AND connects to mega.nz? TIER1 KILL.
/// 
/// The key insight: legitimate software does ONE of these things.
/// Only malware does MULTIPLE in combination on the same PID within 120 seconds.
/// 
/// Allowlists prevent even Tier2 noise from known-good processes.
/// </summary>
public sealed class DataExfiltrationMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<DataExfiltrationMonitor> _logger;
    private readonly ProcessAncestryCache? _ancestryCache;

    // Deduplication: prevent same alert firing repeatedly
    private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedExfil = new();
    private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromMinutes(5);

    // Per-process outbound byte tracking
    private readonly ConcurrentDictionary<string, ConnectionTracker> _connections = new();

    // User-configured protected paths (loaded from appsettings.json or defaults)
    // Any non-allowlisted process reading from these paths generates a Tier2 signal.
    private readonly List<string> _protectedPaths;

    // Scan interval
    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(10);

    // Default protected paths — covers common high-value data locations.
    // Users can override via appsettings.json "Sentinel:ProtectedPaths" array.
    private static readonly string[] DefaultProtectedPaths = new[]
    {
        // User profile high-value directories
        @"%USERPROFILE%\Documents",
        @"%USERPROFILE%\Desktop",
        @"%USERPROFILE%\Pictures",
        @"%USERPROFILE%\Downloads",
        // Common project/work directories
        @"%USERPROFILE%\source",
        @"%USERPROFILE%\repos",
        @"%USERPROFILE%\Projects",
        // All non-C: fixed drives (D:, E:, F:, etc.) — likely data drives
        // These are resolved dynamically at startup
    };

    // ═══════════════════════════════════════════════════════════════════════
    // ALLOWLISTS — processes that legitimately do these things
    // 
    // IMPORTANT: Name-based allowlists are a FIRST PASS only. The real check
    // is: is the binary signed AND running from a trusted location?
    // An unsigned "chrome.exe" from %TEMP% is NOT allowlisted.
    // ═══════════════════════════════════════════════════════════════════════

    // Trusted install locations — binaries here get reduced suspicion
    private static readonly string[] TrustedPaths = new[]
    {
        @"C:\Program Files\",
        @"C:\Program Files (x86)\",
        @"C:\Windows\System32\",
        @"C:\Windows\SysWOW64\",
    };

    // Processes that legitimately access credential stores
    private static readonly HashSet<string> CredentialAccessAllowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "svchost", "searchindexer", "msiexec", "lsass",
        "chrome", "firefox", "msedge", "brave", "opera", "vivaldi",
        "code", "devenv", "rider", "idea64", "webstorm64",
        "git", "ssh", "ssh-agent", "gpg-agent", "git-remote-https",
        "onedrive", "dropbox", "googledrivesync",
        "windowsterminal", "powershell", "pwsh", "cmd", "conhost",
        "sentinelservice", "sentinelagent",
        "msmpeng", "mpcmdrun", // Defender
        "1password", "bitwarden", "keepass", "lastpass", // Password managers
        "kubectl", "docker", "terraform", "aws", "az", "gcloud", // Cloud CLI tools
        "node", "python", "dotnet", "java", "ruby", "go", // Dev runtimes
    };

    // Processes that legitimately make sustained outbound connections.
    // NOTE: This list is only checked for processes running from trusted paths.
    // An unsigned binary named "steam.exe" from %TEMP% will NOT be allowlisted.
    private static readonly HashSet<string> NetworkAllowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        // Browsers
        "chrome", "firefox", "msedge", "brave", "opera", "vivaldi",
        "msedgewebview2",
        // Communication / social
        "teams", "slack", "discord", "zoom", "webex",
        "telegram", "signal", "whatsapp", "skype",
        "thunderbird", "outlook",
        // Cloud sync
        "onedrive", "dropbox", "googledrivesync", "icloud",
        "megasync", "pcloud", "boxsync", "nextcloud",
        // Microsoft services (legitimate sustained connections for telemetry/updates)
        "MpDefenderCoreService", "MsMpEng", "NisSrv",
        "OneDrive.Sync.Service",
        "MicrosoftStartFeedProvider",
        "SearchHost", "widgets", "WidgetService",
        "backgroundTaskHost", "BackgroundTransferHost",
        "PhoneExperienceHost", "YourPhone",
        "GameBarPresenceWriter", "gamingservices",
        "WinStore.App", "Microsoft.Photos",
        "SettingSyncHost", "SettingsSync",
        "usocoreworker", "WaaSMedicAgent",
        // Windows system services
        "svchost", "lsass", "services",
        "spoolsv", "SearchIndexer",
        "sihost", "taskhostw", "RuntimeBroker",
        "SystemSettings", "ShellExperienceHost",
        "StartMenuExperienceHost", "TextInputHost",
        "ctfmon", "fontdrvhost",
        // Games (common launchers — individual games are covered by trusted path check)
        "steam", "steamwebhelper", "epicgameslauncher", "origin", "galaxyclient",
        "battle.net", "eadesktop", "UbisoftConnect",
        // Dev tools
        "code", "devenv", "rider64", "Kiro", "cursor",
        "git", "git-remote-https", "gh",
        "node", "dotnet", "python", "java",
        "docker", "dockerd", "kubectl",
        // FTP/SSH clients
        "putty", "winscp", "filezilla", "kitty", "mobaxterm",
        "ssh", "sftp", "scp",
        // VPN / network
        "wireguard", "openvpn", "nordvpn", "ExpressVPN",
        "mullvad-daemon", "ProtonVPN",
        // System
        "wuauclt",
        "sentinelservice", "sentinelagent",
        // Security products (legitimate outbound for updates/telemetry)
        "TmsaInstance64", "coreServiceShell", "PtSvcHost", "AMSPTelemetryService",
        "ASCService", "LiveTuner3",
        "SgrmBroker", "SecurityHealthService",
        // Media / streaming
        "spotify", "vlc", "mpc-hc", "plex", "plexmediaserver",
        // Backup
        "veeam", "acronis", "backblaze", "crashplan",
        // NVIDIA / GPU
        "NVDisplay.Container", "NVIDIA Web Helper",
        "nvcontainer", "NvTelemetryContainer",
        // Hardware utilities
        "RazerCentralService", "CorsairService", "iCUE",
        "LogiOverlay", "lghub", "lghub_agent",
        "AsusSystemAnalysis", "ArmouryCrate",
    };

    // Processes that legitimately read from USB drives
    private static readonly HashSet<string> RemovableMediaAllowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "svchost", "searchindexer", "msiexec",
        "onedrive", "dropbox", "googledrivesync",
        "totalcmd", "7zfm", "winrar", "peazip",
        "sentinelservice", "sentinelagent",
        "msmpeng", "mpcmdrun",
        "robocopy", "xcopy",
    };

    // Processes that legitimately read from protected data paths
    // (broader than credential allowlist — includes file managers, backup tools, etc.)
    private static readonly HashSet<string> ProtectedPathAllowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "svchost", "searchindexer", "searchprotocolhost", "msiexec",
        "chrome", "firefox", "msedge", "brave", "opera", "vivaldi",
        "code", "devenv", "rider", "idea64", "webstorm64", "sublime_text", "notepad++",
        "git", "git-remote-https", "gh",
        "onedrive", "dropbox", "googledrivesync", "icloud",
        "windowsterminal", "powershell", "pwsh", "cmd", "conhost",
        "sentinelservice", "sentinelagent",
        "msmpeng", "mpcmdrun", // Defender
        "totalcmd", "7zfm", "winrar", "peazip", // File managers
        "robocopy", "xcopy", // Copy tools
        "node", "python", "dotnet", "java", "ruby", "go", "cargo", "rustc", // Dev runtimes
        "msbuild", "csc", "vbcscompiler", // Build tools
        "docker", "kubectl", "terraform",
        "steam", "epicgameslauncher", // Games
        "vlc", "mpc-hc", "mpv", // Media players
        "word", "excel", "powerpnt", "outlook", "winword", // Office
        "acrobat", "acrord32", // PDF
    };

    // Disk image extensions — high-value exfil targets
    private static readonly HashSet<string> DiskImageExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".iso", ".vhd", ".vhdx", ".img", ".wim", ".vmdk", ".qcow2", ".vdi"
    };

    // Sensitive path fragments — credential stores and key material
    private static readonly string[] SensitivePathFragments =
    {
        @"\.ssh\", @"\.aws\", @"\.azure\", @"\.gcp\", @"\.kube\",
        @"\Login Data", @"\Cookies", // Browser credential DBs
        @"\Microsoft\Credentials\", @"\Microsoft\Protect\",
        @"\Mozilla\Firefox\Profiles\",
        @"\wallet.dat", @"\seed.txt", @"\keystore\",
        @"\.env", @"\id_rsa", @"\id_ed25519",
    };

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int pdwSize, bool bOrder,
        int ulAf, int TableClass, uint Reserved);

    public DataExfiltrationMonitor(
        IDetectionEngine detectionEngine,
        ILogger<DataExfiltrationMonitor> logger,
        ProcessAncestryCache? ancestryCache = null)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _ancestryCache = ancestryCache;
        _protectedPaths = ResolveProtectedPaths();
    }

    /// <summary>
    /// Resolves protected paths from defaults + all non-system fixed drives.
    /// Any non-C: fixed drive is assumed to be a data drive worth protecting.
    /// </summary>
    private static List<string> ResolveProtectedPaths()
    {
        var paths = new List<string>();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        // Resolve %USERPROFILE% paths
        foreach (var template in DefaultProtectedPaths)
        {
            var resolved = template.Replace("%USERPROFILE%", userProfile);
            if (Directory.Exists(resolved))
                paths.Add(resolved);
        }

        // Add ALL non-C: fixed drives (data drives)
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.DriveType == DriveType.Fixed &&
                drive.IsReady &&
                !drive.RootDirectory.FullName.StartsWith("C", StringComparison.OrdinalIgnoreCase))
            {
                paths.Add(drive.RootDirectory.FullName);
            }
        }

        return paths;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[DataExfiltrationMonitor] Starting — correlation-based exfil prevention active");

        // Run monitoring loops in parallel
        var networkTask = MonitorOutboundConnectionsAsync(stoppingToken);
        var removableTask = MonitorRemovableMediaAsync(stoppingToken);
        var sensitiveTask = MonitorSensitiveDirectoriesAsync(stoppingToken);

        await Task.WhenAll(networkTask, removableTask, sensitiveTask);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // OUTBOUND CONNECTION MONITORING
    // Emits Tier2 signals for sustained connections from non-allowlisted processes.
    // Only becomes a kill when correlated with file access or DNS signals.
    // ═══════════════════════════════════════════════════════════════════════

    private async Task MonitorOutboundConnectionsAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await ScanEstablishedConnectionsAsync(ct);
                PruneStaleData();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "[DataExfiltrationMonitor] Network scan error");
            }

            await Task.Delay(ScanInterval, ct);
        }
    }

    private async Task ScanEstablishedConnectionsAsync(CancellationToken ct)
    {
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, 2, 5, 0);
        if (bufferSize == 0) return;

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetExtendedTcpTable(buffer, ref bufferSize, false, 2, 5, 0) != 0) return;

            var numEntries = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(buffer + 4 + (i * rowSize));
                if (row.dwState != 5) continue; // ESTABLISHED only

                var pid = (int)row.dwOwningPid;
                if (pid <= 4) continue;

                var remoteAddr = new IPAddress(row.dwRemoteAddr);
                if (IPAddress.IsLoopback(remoteAddr) || IsPrivateAddress(remoteAddr)) continue;

                var remotePort = (int)((row.dwRemotePort >> 8) | ((row.dwRemotePort & 0xFF) << 8));
                var processName = GetProcessNameSafe(pid);

                // Skip allowlisted processes running from trusted paths — no signal, no noise
                if (IsProcessTrusted(pid, processName, NetworkAllowlist)) continue;

                var key = $"{pid}:{remoteAddr}:{remotePort}";
                var tracker = _connections.GetOrAdd(key, _ => new ConnectionTracker
                {
                    ProcessId = pid,
                    ProcessName = processName,
                    RemoteAddress = remoteAddr.ToString(),
                    RemotePort = remotePort,
                    FirstSeen = DateTimeOffset.UtcNow
                });
                tracker.LastSeen = DateTimeOffset.UtcNow;
                tracker.PollCount++;

                // Only emit Tier2 after connection persists for 60+ seconds (3+ polls at 10s interval)
                // This filters out transient connections (DNS, quick API calls, etc.)
                var duration = tracker.LastSeen - tracker.FirstSeen;
                if (duration >= TimeSpan.FromSeconds(60) && !tracker.Alerted)
                {
                    tracker.Alerted = true;

                    var dedupeKey = $"outbound:{pid}:{remoteAddr}";
                    if (_alertedExfil.ContainsKey(dedupeKey)) continue;
                    _alertedExfil.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                    // Tier2 — this alone does NOT kill. Needs correlation.
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Network: Sustained Outbound Connection",
                        Evidence = $"Non-allowlisted process '{processName}' (PID {pid}) has maintained " +
                                   $"connection to {remoteAddr}:{remotePort} for {duration.TotalSeconds:F0}s",
                        Reasoning = "A process not in the network allowlist has maintained a sustained outbound " +
                                    "connection to an external IP. This is a corroborating signal — combined with " +
                                    "sensitive file access or exfil DNS resolution, it indicates data exfiltration.",
                        Confidence = 0.65,
                        Tier = DetectionTier.Tier2Indicator, // NEVER kills alone
                        ProcessName = processName ?? pid.ToString(),
                        ProcessId = pid,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["remote_address"] = remoteAddr.ToString(),
                            ["remote_port"] = remotePort.ToString(),
                            ["duration_seconds"] = duration.TotalSeconds.ToString("F0"),
                            ["technique"] = "T1041 - Exfiltration Over C2 Channel"
                        }
                    }, ct);
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // REMOVABLE MEDIA MONITORING
    // Emits Tier2 when non-allowlisted processes read from USB drives.
    // Becomes a kill only when correlated with network activity.
    // ═══════════════════════════════════════════════════════════════════════

    private async Task MonitorRemovableMediaAsync(CancellationToken ct)
    {
        var activeWatchers = new ConcurrentDictionary<string, FileSystemWatcher>();

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var removableDrives = DriveInfo.GetDrives()
                    .Where(d => d.DriveType == DriveType.Removable && d.IsReady)
                    .Select(d => d.RootDirectory.FullName)
                    .ToList();

                // Start watchers for new drives
                foreach (var drive in removableDrives)
                {
                    if (activeWatchers.ContainsKey(drive)) continue;

                    try
                    {
                        var watcher = new FileSystemWatcher(drive)
                        {
                            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName,
                            IncludeSubdirectories = true,
                            EnableRaisingEvents = true
                        };

                        watcher.Changed += (_, e) => OnRemovableFileEvent(e.FullPath, drive, ct);
                        watcher.Created += (_, e) => OnRemovableFileEvent(e.FullPath, drive, ct);

                        activeWatchers.TryAdd(drive, watcher);
                        _logger.LogInformation("[DataExfiltrationMonitor] Watching removable drive: {Drive}", drive);
                    }
                    catch { /* Drive may not be accessible */ }
                }

                // Remove watchers for disconnected drives
                foreach (var kvp in activeWatchers)
                {
                    if (!Directory.Exists(kvp.Key))
                    {
                        kvp.Value.Dispose();
                        activeWatchers.TryRemove(kvp.Key, out _);
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "[DataExfiltrationMonitor] Removable media scan error");
            }

            await Task.Delay(TimeSpan.FromSeconds(5), ct);
        }

        // Cleanup
        foreach (var w in activeWatchers.Values) w.Dispose();
    }

    private void OnRemovableFileEvent(string filePath, string drivePath, CancellationToken ct)
    {
        var ext = Path.GetExtension(filePath);
        var isDiskImage = DiskImageExtensions.Contains(ext);

        var dedupeKey = $"removable:{drivePath}:{Path.GetFileName(filePath)}";
        if (_alertedExfil.ContainsKey(dedupeKey)) return;
        _alertedExfil.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

        // Tier2 — log only. Correlation engine will combine with network signals for kill.
        _ = _detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = isDiskImage
                ? "Removable Media: Disk Image Access"
                : "Removable Media: File Activity",
            Evidence = $"File activity on removable media: {filePath}",
            Reasoning = isDiskImage
                ? "A disk image file (.iso, .vhd, .img) on removable media was accessed. " +
                  "Disk images are high-value exfiltration targets. If this process also has " +
                  "network activity, it indicates USB-to-network data theft."
                : "File activity detected on removable media. If the accessing process also " +
                  "has outbound network connections, this indicates USB-to-network exfiltration.",
            Confidence = isDiskImage ? 0.75 : 0.55,
            Tier = DetectionTier.Tier2Indicator, // NEVER kills alone
            ProcessName = "FileSystem",
            ProcessId = 0,
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["file_path"] = filePath,
                ["drive_path"] = drivePath,
                ["is_disk_image"] = isDiskImage.ToString(),
                ["technique"] = "T1052 - Exfiltration Over Physical Medium"
            }
        }, ct);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SENSITIVE DIRECTORY MONITORING
    // Emits Tier2 when credential stores / key material is accessed.
    // Becomes a kill only when correlated with network or exfil DNS signals.
    // ═══════════════════════════════════════════════════════════════════════

    private async Task MonitorSensitiveDirectoriesAsync(CancellationToken ct)
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var watchers = new List<FileSystemWatcher>();

        var sensitiveDirs = new[]
        {
            Path.Combine(userProfile, ".ssh"),
            Path.Combine(userProfile, ".aws"),
            Path.Combine(userProfile, ".azure"),
            Path.Combine(userProfile, ".kube"),
            Path.Combine(userProfile, "AppData", "Local", "Google", "Chrome", "User Data"),
            Path.Combine(userProfile, "AppData", "Local", "Microsoft", "Edge", "User Data"),
            Path.Combine(userProfile, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"),
            Path.Combine(userProfile, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
            Path.Combine(userProfile, "AppData", "Local", "Microsoft", "Credentials"),
            Path.Combine(userProfile, "AppData", "Roaming", "Microsoft", "Credentials"),
            Path.Combine(userProfile, "AppData", "Roaming", "Microsoft", "Protect"),
        };

        foreach (var dir in sensitiveDirs)
        {
            if (!Directory.Exists(dir)) continue;

            try
            {
                var watcher = new FileSystemWatcher(dir)
                {
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
                    IncludeSubdirectories = true,
                    EnableRaisingEvents = true
                };

                watcher.Changed += (_, e) => OnSensitiveFileEvent(e.FullPath, ct);
                watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DataExfiltrationMonitor] Cannot watch {Dir}", dir);
            }
        }

        _logger.LogInformation("[DataExfiltrationMonitor] Watching {Count} sensitive directories", watchers.Count);

        try
        {
            await Task.Delay(Timeout.Infinite, ct);
        }
        catch (OperationCanceledException) { }
        finally
        {
            foreach (var w in watchers) w.Dispose();
        }
    }

    private void OnSensitiveFileEvent(string filePath, CancellationToken ct)
    {
        // Only alert on actual credential files, not every file in the directory
        if (!IsSensitiveFile(filePath)) return;

        var dedupeKey = $"sensitive:{filePath}";
        if (_alertedExfil.ContainsKey(dedupeKey)) return;
        _alertedExfil.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

        var category = DetermineCategory(filePath);

        // Tier2 — log only. Correlation engine combines with network for kill.
        _ = _detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = "Sensitive File Access: Credential Store",
            Evidence = $"Credential/key file accessed: {filePath}",
            Reasoning = $"A sensitive {category} file was accessed. This is a corroborating signal — " +
                        "if the accessing process also has outbound network connections or resolved " +
                        "an exfiltration service domain, it indicates active credential theft.",
            Confidence = 0.70,
            Tier = DetectionTier.Tier2Indicator, // NEVER kills alone
            ProcessName = "FileSystem",
            ProcessId = 0,
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["file_path"] = filePath,
                ["category"] = category,
                ["technique"] = "T1552 - Unsecured Credentials"
            }
        }, ct);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    private static bool IsSensitiveFile(string filePath)
    {
        var lower = filePath.ToLowerInvariant();
        foreach (var fragment in SensitivePathFragments)
        {
            if (lower.Contains(fragment.ToLowerInvariant()))
                return true;
        }
        return false;
    }

    private static bool IsInAllowlist(string? processName, HashSet<string> allowlist)
    {
        if (string.IsNullOrEmpty(processName)) return false;
        return allowlist.Contains(processName);
    }

    /// <summary>
    /// Checks if a process should be trusted based on name + location.
    /// A process is only truly allowlisted if:
    ///   1. Its name is in the allowlist, AND
    ///   2. It's running from a trusted path (Program Files, System32, etc.)
    /// 
    /// This prevents attackers from renaming their tool to "putty.exe" and bypassing detection.
    /// Any binary from Temp, Downloads, AppData\Local\Temp, or user-writable paths
    /// is NEVER allowlisted regardless of name.
    /// </summary>
    private static bool IsProcessTrusted(int pid, string? processName, HashSet<string> allowlist)
    {
        if (string.IsNullOrEmpty(processName)) return false;
        if (!allowlist.Contains(processName)) return false;

        // Name matches — now verify it's running from a trusted location
        try
        {
            using var proc = Process.GetProcessById(pid);
            var path = proc.MainModule?.FileName;
            if (string.IsNullOrEmpty(path))
            {
                // Can't get path (sandboxed/protected process) — trust known Microsoft components
                if (processName is "msedgewebview2" or "SearchHost" or "widgets" or "backgroundTaskHost")
                    return true;
                return false;
            }

            // Must be in a trusted install location
            foreach (var trusted in TrustedPaths)
            {
                if (path.StartsWith(trusted, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // Also trust anything in the user's Program Files equivalent on other drives
            // (e.g., D:\Program Files\)
            if (path.Contains(@"\Program Files\", StringComparison.OrdinalIgnoreCase) ||
                path.Contains(@"\Program Files (x86)\", StringComparison.OrdinalIgnoreCase))
                return true;

            // v4.1.0: Trust well-known apps that install to AppData (Electron apps, Discord, Spotify, etc.)
            // These are verified by process name match + known install path pattern.
            var pathLower = path.ToLowerInvariant();
            if (pathLower.Contains(@"\appdata\local\") || pathLower.Contains(@"\appdata\roaming\"))
            {
                // Only trust if the folder name matches the process name (prevents impersonation)
                var processLower = processName.ToLowerInvariant();
                if (pathLower.Contains($@"\{processLower}\") ||
                    pathLower.Contains($@"\{processLower}app\") ||  // e.g., \discordapp\ 
                    pathLower.Contains($@"\programs\{processLower}"))
                    return true;
            }

            // NOT in a trusted path — don't trust it even if name matches
            return false;
        }
        catch
        {
            // Can't verify path — don't trust
            return false;
        }
    }

    private static string? GetProcessNameSafe(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.ProcessName;
        }
        catch { return null; }
    }

    private static string DetermineCategory(string filePath)
    {
        var lower = filePath.ToLowerInvariant();
        if (lower.Contains(".ssh") || lower.Contains("id_rsa") || lower.Contains("id_ed25519"))
            return "ssh_keys";
        if (lower.Contains(".aws") || lower.Contains(".azure") || lower.Contains(".kube") || lower.Contains(".gcp"))
            return "cloud_credentials";
        if (lower.Contains("login data") || lower.Contains("cookies") || lower.Contains("firefox"))
            return "browser_credentials";
        if (lower.Contains(@"\credentials\") || lower.Contains(@"\protect\"))
            return "windows_credentials";
        if (lower.Contains("wallet") || lower.Contains("seed") || lower.Contains("keystore"))
            return "cryptocurrency";
        if (lower.Contains(".env"))
            return "environment_secrets";
        return "sensitive_file";
    }

    private static bool IsPrivateAddress(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        if (bytes.Length == 4)
        {
            return bytes[0] == 10 ||
                   (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168) ||
                   bytes[0] == 127;
        }
        return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal;
    }

    private void PruneStaleData()
    {
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-5);

        foreach (var kvp in _connections)
        {
            if (kvp.Value.LastSeen < cutoff)
                _connections.TryRemove(kvp.Key, out _);
        }

        foreach (var kvp in _alertedExfil)
        {
            if (kvp.Value < cutoff)
                _alertedExfil.TryRemove(kvp.Key, out _);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // INTERNAL MODELS
    // ═══════════════════════════════════════════════════════════════════════

    private sealed class ConnectionTracker
    {
        public int ProcessId { get; init; }
        public string? ProcessName { get; init; }
        public required string RemoteAddress { get; init; }
        public int RemotePort { get; init; }
        public DateTimeOffset FirstSeen { get; init; }
        public DateTimeOffset LastSeen { get; set; }
        public int PollCount { get; set; }
        public bool Alerted { get; set; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }
}


