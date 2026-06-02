using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Suspicious Local Server Monitor — Detects unexpected processes listening on
    /// localhost or all-interfaces that could serve malicious payloads locally.
    /// </summary>
    public class LocalServerMonitor : IDisposable
    {
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly ILogger<LocalServerMonitor> _logger;
        private readonly System.Threading.Timer _timer;

        private readonly ConcurrentDictionary<int, DateTime> _alertedPids = new();
        private readonly HashSet<string> _knownMountedVolumes = new(StringComparer.OrdinalIgnoreCase);
        private DateTime _lastVolumeScan = DateTime.MinValue;

        // Allowlisted processes that legitimately listen on local ports
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
            @"\programdata\",
        };

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
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<LocalServerMonitor> logger)
        {
            _fusionEngine = fusionEngine;
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _logger = logger;

            // Scan every 30 seconds
            _timer = new System.Threading.Timer(ScanListeningProcesses, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
        }

        private void ScanListeningProcesses(object? state)
        {
            try
            {
                // Refresh mounted volume knowledge periodically
                if (DateTime.UtcNow - _lastVolumeScan > TimeSpan.FromMinutes(2))
                {
                    RefreshMountedVolumes();
                    _lastVolumeScan = DateTime.UtcNow;
                }

                PruneAlertCache();

                var listeners = GetTcpListeners();
                var selfPid = Environment.ProcessId;

                foreach (var (pid, localAddr, localPort) in listeners)
                {
                    if (pid <= 4 || pid == selfPid) continue;
                    if (_alertedPids.ContainsKey(pid)) continue;

                    string processName = "unknown";
                    string? processPath = null;

                    var ancestry = _ancestryCache.GetParent(pid);
                    if (ancestry.name != "unknown")
                    {
                        processName = ancestry.name;
                    }
                    else
                    {
                        try
                        {
                            using var p = Process.GetProcessById(pid);
                            processName = p.ProcessName;
                            try { processPath = p.MainModule?.FileName; } catch { }
                        }
                        catch { continue; } // Process exited
                    }

                    // Skip allowlisted
                    if (AllowedListeners.Contains(processName)) continue;

                    // Analyze process path
                    var suspicionReasons = new List<string>();
                    double confidence = 0.60;

                    if (processPath != null)
                    {
                        var lowerPath = processPath.ToLowerInvariant();

                        // Check mounted volume
                        if (IsFromMountedVolume(lowerPath))
                        {
                            suspicionReasons.Add("Running from mounted ISO/VHD volume");
                            confidence = Math.Max(confidence, 0.85);
                        }

                        // Check suspicious path
                        foreach (var sp in SuspiciousPaths)
                        {
                            if (lowerPath.Contains(sp))
                            {
                                suspicionReasons.Add($"Running from suspicious path ({sp.Trim('\\')})");
                                confidence = Math.Max(confidence, 0.78);
                                break;
                            }
                        }

                        // Check removable drive
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
                        suspicionReasons.Add("Process path could not be determined");
                        confidence = Math.Max(confidence, 0.75);
                    }

                    // If no other indicators, check if this is a standard dev/rpc port
                    if (suspicionReasons.Count == 0)
                    {
                        if (IsCommonDevPort(localPort)) continue;
                        suspicionReasons.Add("Unknown process listening on local port");
                    }

                    _alertedPids[pid] = DateTime.UtcNow;

                    var tier = confidence >= 0.80
                        ? DetectionTier.Tier1Behavioral
                        : DetectionTier.Tier2Indicator;

                    _logger.LogWarning(
                        "Local Server: '{Name}' (PID {Pid}) listening on {Addr}:{Port} — {Reasons}",
                        processName, pid, localAddr, localPort, string.Join("; ", suspicionReasons));

                    var detection = new DetectionEvent
                    {
                        RuleName = confidence >= 0.80
                            ? "Local Server: Suspicious Process Listening"
                            : "Local Server: Unknown Process Listening",
                        Evidence = $"Process '{processName}' (PID {pid}) is listening on {localAddr}:{localPort}. Path: {processPath ?? "unknown"}. Indicators: {string.Join("; ", suspicionReasons)}.",
                        Reasoning = "A process not in the known-legitimate listener allowlist is binding a local listening socket. This can indicate: a local web server serving exploits to the browser, a local proxy intercepting traffic, malware launched from a mounted ISO/VHD providing a local C2 channel, or a payload dropped to a staging path establishing a local service for lateral movement or privilege escalation. Localhost traffic is invisible to outbound network monitoring, making this a common evasion technique.",
                        Confidence = confidence,
                        Tier = tier,
                        ProcessName = processName,
                        ProcessId = pid,
                        Timestamp = DateTime.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["technique"] = "T1571 - Non-Standard Port / T1090 - Proxy",
                            ["listen_address"] = localAddr,
                            ["listen_port"] = localPort.ToString(),
                            ["process_path"] = processPath ?? "unknown",
                            ["from_mounted_volume"] = IsFromMountedVolume(processPath?.ToLowerInvariant() ?? "").ToString(),
                            ["suspicion_reasons"] = string.Join("; ", suspicionReasons)
                        }
                    };

                    _ = _detectionEngine.EmitAsync(detection);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "LocalServerMonitor scan error");
            }
        }

        private void RefreshMountedVolumes()
        {
            _knownMountedVolumes.Clear();
            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    try
                    {
                        if (drive.DriveType == DriveType.CDRom || drive.DriveType == DriveType.Removable)
                        {
                            _knownMountedVolumes.Add(drive.RootDirectory.FullName.ToLowerInvariant());
                        }
                    }
                    catch { }
                }

                try
                {
                    using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Volume WHERE DriveType = 3"))
                    using (var results = searcher.Get())
                    {
                        foreach (ManagementObject vol in results)
                        {
                            using (vol)
                            {
                                var deviceId = vol["DeviceID"] as string;
                                var driveLetter = vol["DriveLetter"] as string;

                                if (deviceId != null &&
                                    (deviceId.Contains("HarddiskVolume", StringComparison.OrdinalIgnoreCase) ||
                                     deviceId.Contains("VHD", StringComparison.OrdinalIgnoreCase)))
                                {
                                    if (driveLetter != null && !driveLetter.StartsWith("C:", StringComparison.OrdinalIgnoreCase))
                                    {
                                        _knownMountedVolumes.Add(driveLetter.ToLowerInvariant() + "\\");
                                    }
                                }
                            }
                        }
                    }
                }
                catch { }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error refreshing mounted volumes");
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
            return port is 3000 or 3001 or 3030 or 4200 or 5000 or 5001 or 5173 or 5174
                or 5500 or 8000 or 8080 or 8081 or 8443 or 8888 or 9000 or 9090
                or 9229 or 35729 or >= 49152 and <= 65535;
        }

        private List<(int pid, string address, int port)> GetTcpListeners()
        {
            var result = new List<(int, string, int)>();

            // IPv4 TCP
            try
            {
                int bufferSize = 0;
                GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);

                if (bufferSize > 0)
                {
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
                                var port = NetworkToHostOrder(row.LocalPort);

                                result.Add(((int)row.OwningPid, addr, port));
                                rowPtr += rowSize;
                            }
                        }
                    }
                    finally { Marshal.FreeHGlobal(buffer); }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error getting IPv4 TCP listeners");
            }

            // IPv6 TCP
            try
            {
                int bufferSize = 0;
                GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET6, TCP_TABLE_OWNER_PID_LISTENER, 0);

                if (bufferSize > 0)
                {
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
                                var port = NetworkToHostOrder(row.LocalPort);

                                result.Add(((int)row.OwningPid, addr, port));
                                rowPtr += rowSize;
                            }
                        }
                    }
                    finally { Marshal.FreeHGlobal(buffer); }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error getting IPv6 TCP listeners");
            }

            return result;
        }

        private static int NetworkToHostOrder(uint networkPort)
        {
            byte[] bytes = BitConverter.GetBytes(networkPort);
            return (bytes[0] << 8) | bytes[1];
        }

        private void PruneAlertCache()
        {
            var cutoff = DateTime.UtcNow - TimeSpan.FromMinutes(10);
            foreach (var kv in _alertedPids)
            {
                if (kv.Value < cutoff)
                {
                    _alertedPids.TryRemove(kv.Key, out _);
                }
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
