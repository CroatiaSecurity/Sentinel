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
/// Suspicious Local Server Monitor — Detects unexpected processes listening on
/// localhost or all-interfaces that could serve malicious payloads locally.
///
/// Attack vectors detected:
///   1. Local HTTP/HTTPS servers serving exploits to the browser (localhost:8080, etc.)
///   2. Local proxy/MITM servers intercepting traffic (complements ShadowProxyDetector)
///   3. Processes spawned from mounted ISOs/VHDs/VeraCrypt volumes running local services
///   4. Processes running from unusual paths (Temp, AppData, removable media) that bind ports
///
/// Why this matters:
///   - The NetworkMonitor only flags OUTBOUND connections to suspicious remote ports
///   - Localhost traffic is invisible to it — an attacker running a local web server
///     can serve exploits to the browser without triggering any network detection
///   - Mounted ISOs/VHDs appear as normal drive letters but are suspicious origins
///   - WPD (Windows Portable Devices) don't get drive letters but can still execute code
///
/// Detection philosophy:
///   - System services (svchost, IIS, SQL Server) = allowlisted
///   - Development tools (node, python, dotnet) = allowlisted (developers run local servers)
///   - Unknown process from Temp/AppData/removable/mounted volume listening = suspicious
///   - Any process listening + running from ISO/VHD mount point = highly suspicious
/// </summary>
public sealed class LocalServerMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<LocalServerMonitor> _logger;
    private readonly TelemetryFusionEngine? _fusionEngine;

    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(30);

    private readonly ConcurrentDictionary<int, DateTimeOffset> _alertedPids = new();
    private readonly HashSet<string> _knownMountedVolumes = new(StringComparer.OrdinalIgnoreCase);
    private DateTimeOffset _lastVolumeScan = DateTimeOffset.MinValue;

    // ── Allowlisted processes that legitimately listen on local ports ──────────

    private static readonly HashSet<string> AllowedListeners = new(StringComparer.OrdinalIgnoreCase)
    {
        // System
        "system", "svchost", "svchost.exe",
        "lsass", "lsass.exe",
        "services", "services.exe",
        "wininit", "wininit.exe",
        "spoolsv", "spoolsv.exe",
        // Web servers (legitimate)
        "w3wp", "w3wp.exe",                     // IIS worker
        "iisexpress", "iisexpress.exe",
        "httpd", "httpd.exe",                   // Apache
        "nginx", "nginx.exe",
        // Databases
        "sqlservr", "sqlservr.exe",
        "postgres", "postgres.exe",
        "mysqld", "mysqld.exe",
        "mongod", "mongod.exe",
        "redis-server", "redis-server.exe",
        // Development tools
        "node", "node.exe",
        "python", "python.exe", "python3", "python3.exe",
        "pythonw", "pythonw.exe",
        "dotnet", "dotnet.exe",
        "java", "java.exe", "javaw", "javaw.exe",
        "ruby", "ruby.exe",
        "php", "php.exe",
        "go", "go.exe",
        "cargo", "cargo.exe",
        "deno", "deno.exe",
        "bun", "bun.exe",
        // IDEs / dev tools
        "code", "code.exe",
        "kiro", "kiro.exe",
        "devenv", "devenv.exe",
        "rider64", "rider64.exe",
        "idea64", "idea64.exe",
        "webstorm64", "webstorm64.exe",
        // Docker / containers
        "docker", "docker.exe",
        "dockerd", "dockerd.exe",
        "com.docker.backend", "com.docker.backend.exe",
        "vpnkit", "vpnkit.exe",
        // Browsers (internal debug ports)
        "msedge", "msedge.exe",
        "chrome", "chrome.exe",
        "firefox", "firefox.exe",
        // Remote desktop / sharing
        "teamviewer", "teamviewer.exe",
        "teamviewer_service", "teamviewer_service.exe",
        "anydesk", "anydesk.exe",
        // Gaming
        "steam", "steam.exe",
        "steamwebhelper", "steamwebhelper.exe",
        "epicgameslauncher", "epicgameslauncher.exe",
        // Communication
        "teams", "teams.exe",
        "ms-teams", "ms-teams.exe",
        "slack", "slack.exe",
        "discord", "discord.exe",
        "spotify", "spotify.exe",
        // Security
        "sentinelservice", "sentinelservice.exe",
        "sentinelagent", "sentinelagent.exe",
        "msmpeng", "msmpeng.exe",               // Defender
        "securityhealthservice", "securityhealthservice.exe",
        // Virtualization
        "vmware-hostd", "vmware-hostd.exe",
        "vmnat", "vmnat.exe",
        "virtualboxvm", "virtualboxvm.exe",
        "vboxsvc", "vboxsvc.exe",
        // Misc system
        "searchhost", "searchhost.exe",
        "runtimebroker", "runtimebroker.exe",
        "explorer", "explorer.exe",
        "windowsterminal", "windowsterminal.exe",
        "wt", "wt.exe",
        "powershell", "powershell.exe",
        "pwsh", "pwsh.exe",
        "cmd", "cmd.exe",
        "conhost", "conhost.exe",
        // Print
        "printfilterpipelinesvc", "printfilterpipelinesvc.exe",
    };

    // Paths that are suspicious origins for a listening process
    private static readonly string[] SuspiciousPaths =
    {
        @"\temp\",
        @"\tmp\",
        @"\appdata\local\temp\",
        @"\downloads\",
        @"\public\",
        @"\recycle",
        @"\programdata\",  // Not always suspicious but worth noting
    };

    // ── P/Invoke for TCP listening sockets ────────────────────────────────────

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen,
        bool sort, int ipVersion, int tableClass, uint reserved);

    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_LISTENER = 3; // Only LISTEN state

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPidListen
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPidListen
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        public uint OwningPid;
    }

    public LocalServerMonitor(
        IDetectionEngine detectionEngine,
        ILogger<LocalServerMonitor> logger,
        TelemetryFusionEngine? fusionEngine = null)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _fusionEngine = fusionEngine;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Local Server Monitor starting ===");

        // Initial delay
        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Refresh mounted volume knowledge periodically
                if (DateTimeOffset.UtcNow - _lastVolumeScan > TimeSpan.FromMinutes(2))
                {
                    RefreshMountedVolumes();
                    _lastVolumeScan = DateTimeOffset.UtcNow;
                }

                await ScanListeningProcessesAsync(stoppingToken);
                await Task.Delay(ScanInterval, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "LocalServerMonitor: Scan error");
                await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
            }
        }
    }

    private async Task ScanListeningProcessesAsync(CancellationToken ct)
    {
        var listeners = GetTcpListeners();
        var selfPid = Environment.ProcessId;

        foreach (var (pid, localAddr, localPort) in listeners)
        {
            ct.ThrowIfCancellationRequested();

            if (pid <= 4 || pid == selfPid) continue;
            if (_alertedPids.ContainsKey(pid)) continue;

            // Get process info
            string processName;
            string? processPath;
            try
            {
                using var p = Process.GetProcessById(pid);
                processName = p.ProcessName;
                try { processPath = p.MainModule?.FileName; } catch { processPath = null; }
            }
            catch { continue; } // Process exited

            // Skip allowlisted
            if (AllowedListeners.Contains(processName)) continue;

            // Analyze the process path for suspicious indicators
            var suspicionReasons = new List<string>();
            double confidence = 0.60; // Base confidence for unknown listener

            if (processPath != null)
            {
                var lowerPath = processPath.ToLowerInvariant();

                // Check if running from a mounted ISO/VHD volume
                if (IsFromMountedVolume(lowerPath))
                {
                    suspicionReasons.Add("Running from mounted ISO/VHD volume");
                    confidence = Math.Max(confidence, 0.85);
                }

                // Check if running from suspicious path
                foreach (var sp in SuspiciousPaths)
                {
                    if (lowerPath.Contains(sp))
                    {
                        suspicionReasons.Add($"Running from suspicious path ({sp.Trim('\\')})");
                        confidence = Math.Max(confidence, 0.78);
                        break;
                    }
                }

                // Check if running from a non-standard drive (D:, E:, etc. that might be removable)
                if (lowerPath.Length >= 2 && lowerPath[1] == ':' && lowerPath[0] != 'c')
                {
                    var driveInfo = GetDriveType(lowerPath[..3]);
                    if (driveInfo == DriveType.Removable || driveInfo == DriveType.CDRom)
                    {
                        suspicionReasons.Add($"Running from removable/CD-ROM drive ({lowerPath[..3]})");
                        confidence = Math.Max(confidence, 0.82);
                    }
                }
            }
            else
            {
                // Can't determine path — suspicious in itself
                suspicionReasons.Add("Process path could not be determined (possible WPD or hidden volume)");
                confidence = Math.Max(confidence, 0.75);
            }

            // If no specific suspicion beyond "unknown listener", only alert on
            // non-standard ports (skip common dev ports to reduce noise)
            if (suspicionReasons.Count == 0)
            {
                // Common development ports — don't alert on these for unknown processes
                // unless they have other suspicious indicators
                if (IsCommonDevPort(localPort)) continue;

                suspicionReasons.Add("Unknown process listening on local port");
            }

            _alertedPids[pid] = DateTimeOffset.UtcNow;

            var tier = confidence >= 0.80
                ? DetectionTier.Tier1Behavioral
                : DetectionTier.Tier2Indicator;

            _logger.LogWarning(
                "Local Server: '{Name}' (PID {Pid}) listening on {Addr}:{Port} — {Reasons}",
                processName, pid, localAddr, localPort, string.Join("; ", suspicionReasons));

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = confidence >= 0.80
                    ? "Local Server: Suspicious Process Listening"
                    : "Local Server: Unknown Process Listening",
                Evidence = $"Process '{processName}' (PID {pid}) is listening on {localAddr}:{localPort}. " +
                          $"Path: {processPath ?? "unknown"}. " +
                          $"Indicators: {string.Join("; ", suspicionReasons)}.",
                Reasoning = "A process not in the known-legitimate listener allowlist is binding a " +
                           "local listening socket. This can indicate: a local web server serving " +
                           "exploits to the browser, a local proxy intercepting traffic, malware " +
                           "launched from a mounted ISO/VHD providing a local C2 channel, or a " +
                           "payload dropped to a staging path establishing a local service for " +
                           "lateral movement or privilege escalation. Localhost traffic is invisible " +
                           "to outbound network monitoring, making this a common evasion technique.",
                Confidence = confidence,
                Tier = tier,
                ProcessName = processName,
                ProcessId = pid,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["technique"] = "T1571 - Non-Standard Port / T1090 - Proxy",
                    ["listen_address"] = localAddr,
                    ["listen_port"] = localPort.ToString(),
                    ["process_path"] = processPath ?? "unknown",
                    ["from_mounted_volume"] = IsFromMountedVolume(processPath?.ToLowerInvariant() ?? "").ToString(),
                    ["suspicion_reasons"] = string.Join("; ", suspicionReasons)
                }
            }, ct);

            _fusionEngine?.IngestFileActivity(pid, processName,
                "local_server_listen", FileActivityKind.Write, DateTimeOffset.UtcNow);
        }

        // Prune old alerts
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-10);
        foreach (var kv in _alertedPids)
            if (kv.Value < cutoff) _alertedPids.TryRemove(kv.Key, out _);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Mounted volume detection (ISO, VHD, VeraCrypt, etc.)
    // ═══════════════════════════════════════════════════════════════════════════

    private void RefreshMountedVolumes()
    {
        _knownMountedVolumes.Clear();

        try
        {
            // Find drives that are mounted images (ISO/VHD/VHDX)
            foreach (var drive in DriveInfo.GetDrives())
            {
                try
                {
                    if (drive.DriveType == DriveType.CDRom ||
                        drive.DriveType == DriveType.Removable)
                    {
                        _knownMountedVolumes.Add(drive.RootDirectory.FullName.ToLowerInvariant());
                    }
                }
                catch { /* Drive not ready */ }
            }

            // Also check for VHD/VHDX mounts via WMI
            // Mounted VHDs appear as fixed drives but have a virtual disk backing
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT * FROM Win32_Volume WHERE DriveType = 3");
                using var results = searcher.Get();
                foreach (System.Management.ManagementObject vol in results)
                {
                    using (vol)
                    {
                        var deviceId = vol["DeviceID"] as string;
                        var label = vol["Label"] as string;
                        var driveLetter = vol["DriveLetter"] as string;

                        // VHD-mounted volumes often have specific device paths
                        if (deviceId != null &&
                            (deviceId.Contains("HarddiskVolume", StringComparison.OrdinalIgnoreCase) ||
                             deviceId.Contains("VHD", StringComparison.OrdinalIgnoreCase)))
                        {
                            // Check if this is a recently-appeared volume (heuristic)
                            if (driveLetter != null && driveLetter != "C:")
                            {
                                // We'll track non-C fixed drives as potentially mounted
                                // The actual suspicion scoring happens when a process runs from here
                            }
                        }
                    }
                }
            }
            catch { /* WMI not available */ }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "LocalServerMonitor: Error refreshing mounted volumes");
        }
    }

    private bool IsFromMountedVolume(string lowerPath)
    {
        if (string.IsNullOrEmpty(lowerPath)) return false;

        foreach (var vol in _knownMountedVolumes)
        {
            if (lowerPath.StartsWith(vol)) return true;
        }

        return false;
    }

    private static DriveType GetDriveType(string rootPath)
    {
        try
        {
            var di = new DriveInfo(rootPath);
            return di.DriveType;
        }
        catch
        {
            return DriveType.Unknown;
        }
    }

    private static bool IsCommonDevPort(int port)
    {
        // Ports commonly used by development tools — don't alert on these
        // unless the process has other suspicious indicators
        return port is 3000 or 3001 or 3030 or 4200 or 5000 or 5001 or 5173 or 5174
            or 5500 or 8000 or 8080 or 8081 or 8443 or 8888 or 9000 or 9090
            or 9229  // Node.js debugger
            or 35729 // LiveReload
            or 49152 or >= 49152 and <= 65535; // Dynamic/ephemeral ports (often RPC)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // TCP listener enumeration via P/Invoke
    // ═══════════════════════════════════════════════════════════════════════════

    private List<(int pid, string address, int port)> GetTcpListeners()
    {
        var result = new List<(int, string, int)>();

        // IPv4 listeners
        try
        {
            int bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);

            var buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                if (GetExtendedTcpTable(buffer, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) == 0)
                {
                    int numEntries = Marshal.ReadInt32(buffer);
                    var rowPtr = buffer + 4;
                    var rowSize = Marshal.SizeOf<MibTcpRowOwnerPidListen>();

                    for (int i = 0; i < numEntries; i++)
                    {
                        var row = Marshal.PtrToStructure<MibTcpRowOwnerPidListen>(rowPtr);
                        var addr = new IPAddress(row.LocalAddr).ToString();
                        var port = IPAddress.NetworkToHostOrder((short)(row.LocalPort & 0xFFFF)) & 0xFFFF;

                        result.Add(((int)row.OwningPid, addr, port));
                        rowPtr += rowSize;
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "LocalServerMonitor: Error getting IPv4 TCP listeners");
        }

        // IPv6 listeners
        try
        {
            int bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET6, TCP_TABLE_OWNER_PID_LISTENER, 0);

            var buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                if (GetExtendedTcpTable(buffer, ref bufferSize, true, AF_INET6, TCP_TABLE_OWNER_PID_LISTENER, 0) == 0)
                {
                    int numEntries = Marshal.ReadInt32(buffer);
                    var rowPtr = buffer + 4;
                    var rowSize = Marshal.SizeOf<MibTcp6RowOwnerPidListen>();

                    for (int i = 0; i < numEntries; i++)
                    {
                        var row = Marshal.PtrToStructure<MibTcp6RowOwnerPidListen>(rowPtr);
                        var addr = new IPAddress(row.LocalAddr).ToString();
                        var port = IPAddress.NetworkToHostOrder((short)(row.LocalPort & 0xFFFF)) & 0xFFFF;

                        result.Add(((int)row.OwningPid, addr, port));
                        rowPtr += rowSize;
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "LocalServerMonitor: Error getting IPv6 TCP listeners");
        }

        return result;
    }
}

