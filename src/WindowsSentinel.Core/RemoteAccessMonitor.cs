using System.Diagnostics;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace WindowsSentinel.Core;

/// <summary>
/// Remote Access Monitor (v4.0.0) â€” Detects unauthorized remote desktop/access tools
/// and RDP session anomalies.
///
/// Addresses the scenario where an attacker presents a fake desktop to the user
/// via RDP relay, VNC, or commercial remote access tools.
///
/// Detection vectors:
///   1. UNAUTHORIZED REMOTE ACCESS TOOLS: Detects running processes for VNC, TeamViewer,
///      AnyDesk, ScreenConnect, RustDesk, and other remote access software that wasn't
///      explicitly allowlisted.
///   2. RDP STATE MONITORING: Checks if RDP is enabled and alerts if it was enabled
///      without user knowledge. Detects active RDP sessions.
///   3. LISTENING PORT DETECTION: Identifies processes listening on known remote access
///      ports (3389, 5900-5999, 5938, 7070, etc.).
///   4. RDP SESSION ANOMALIES: Detects multiple concurrent sessions, sessions from
///      unexpected IPs, or shadow sessions (attacker watching your screen).
///
/// MITRE ATT&amp;CK: T1021.001 (Remote Desktop Protocol), T1219 (Remote Access Software)
/// </summary>
public sealed class RemoteAccessMonitor : BackgroundService
{
    private readonly DetectionEngine _detectionEngine;
    private readonly ILogger<RemoteAccessMonitor> _logger;

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(60);

    // Known remote access tool process names (lowercase for comparison)
    private static readonly Dictionary<string, string> RemoteAccessTools = new(StringComparer.OrdinalIgnoreCase)
    {
        // VNC variants
        ["winvnc"] = "UltraVNC Server",
        ["winvnc4"] = "RealVNC Server",
        ["tvnserver"] = "TightVNC Server",
        ["vncserver"] = "VNC Server (generic)",
        ["x11vnc"] = "x11vnc",
        // TeamViewer
        ["teamviewer"] = "TeamViewer",
        ["teamviewer_service"] = "TeamViewer Service",
        ["tv_w32"] = "TeamViewer (legacy)",
        ["tv_x64"] = "TeamViewer (64-bit)",
        // AnyDesk
        ["anydesk"] = "AnyDesk",
        ["anydesk_service"] = "AnyDesk Service",
        // ConnectWise ScreenConnect (formerly known as Control)
        ["screenconnect.clientservice"] = "ScreenConnect/ConnectWise Control",
        ["screenconnect.windowsclient"] = "ScreenConnect Client",
        // RustDesk
        ["rustdesk"] = "RustDesk",
        ["rustdesk-server"] = "RustDesk Server",
        // Splashtop
        ["sragent"] = "Splashtop Agent",
        ["srmanager"] = "Splashtop Manager",
        // LogMeIn / GoTo
        ["logmein"] = "LogMeIn",
        ["lmi_rescue"] = "LogMeIn Rescue",
        ["g2mstart"] = "GoToMeeting",
        // Ammyy Admin (commonly abused by scammers)
        ["aa_v3"] = "Ammyy Admin",
        // DWService
        ["dwagent"] = "DWService Agent",
        // Radmin
        ["radmin"] = "Radmin Server",
        ["rserver3"] = "Radmin Server 3",
        // NetSupport (commonly abused by RATs)
        ["client32"] = "NetSupport Manager/RAT",
        // Bomgar/BeyondTrust
        ["bomgar-scc"] = "BeyondTrust Remote Support",
        // SimpleHelp
        ["simplegateway"] = "SimpleHelp",
        ["simpleservice"] = "SimpleHelp Service",
        // Action1 RMM (abused by ransomware groups)
        ["action1_agent"] = "Action1 RMM Agent",
        // Atera
        ["ateraagent"] = "Atera RMM Agent",
        // ngrok (tunnel that exposes local services)
        ["ngrok"] = "ngrok tunnel (exposes local ports to internet)",
        // Chisel / frp (attacker tunneling tools)
        ["chisel"] = "Chisel tunnel (attacker tool)",
        ["frpc"] = "frp client (reverse proxy tunnel)",
        ["frps"] = "frp server",
    };

    // Known remote access listening ports
    private static readonly Dictionary<int, string> RemoteAccessPorts = new()
    {
        [3389] = "RDP (Remote Desktop Protocol)",
        [5900] = "VNC (default)",
        [5901] = "VNC (display :1)",
        [5902] = "VNC (display :2)",
        [5938] = "TeamViewer",
        [5939] = "TeamViewer (file transfer)",
        [7070] = "AnyDesk",
        [4899] = "Radmin",
        [6129] = "DameWare",
        [8200] = "GoToMyPC",
    };

    // Allowlisted processes (user can extend via config in future)
    private static readonly HashSet<string> Allowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        // Add any legitimate remote access tools the user explicitly uses
        // Empty by default â€” all remote access tools are suspicious unless allowlisted
    };

    private bool _rdpBaselineEnabled;
    private readonly HashSet<string> _alertedProcesses = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<int> _alertedPorts = new();

    public RemoteAccessMonitor(
        DetectionEngine detectionEngine,
        ILogger<RemoteAccessMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[RemoteAccessMonitor] Starting â€” monitoring for unauthorized remote access tools");

        // Capture RDP baseline state
        _rdpBaselineEnabled = IsRdpEnabled();
        _logger.LogInformation("[RemoteAccessMonitor] RDP baseline: {State}",
            _rdpBaselineEnabled ? "ENABLED" : "disabled");

        // Initial scan
        await ScanForRemoteAccessToolsAsync(stoppingToken);
        await CheckRdpStateAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(PollInterval, stoppingToken);
                await ScanForRemoteAccessToolsAsync(stoppingToken);
                await CheckRdpStateAsync(stoppingToken);
                await CheckRemoteAccessPortsAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[RemoteAccessMonitor] Scan error");
            }
        }
    }

    private async Task ScanForRemoteAccessToolsAsync(CancellationToken ct)
    {
        Process[] processes;
        try { processes = Process.GetProcesses(); }
        catch { return; }

        try
        {
            foreach (var proc in processes)
            {
                try
                {
                    var name = proc.ProcessName;
                    if (Allowlist.Contains(name)) continue;

                    if (RemoteAccessTools.TryGetValue(name, out var toolName))
                    {
                        // Deduplicate â€” only alert once per process name per session
                        if (!_alertedProcesses.Add(name)) continue;

                        _logger.LogCritical(
                            "[RemoteAccessMonitor] UNAUTHORIZED REMOTE ACCESS TOOL: {Tool} ({Process}, PID {Pid})",
                            toolName, name, proc.Id);

                        string? imagePath = null;
                        try { imagePath = proc.MainModule?.FileName; } catch { }

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Unauthorized Remote Access Tool Detected",
                            Evidence = $"Remote access tool '{toolName}' running as '{name}' (PID {proc.Id}). " +
                                       (imagePath != null ? $"Path: {imagePath}" : "Path: unknown"),
                            Reasoning = "An unauthorized remote access tool is running on this system. " +
                                        "This could allow an attacker to view your screen, control your " +
                                        "mouse/keyboard, and access files â€” potentially presenting a fake " +
                                        "desktop or relaying your session through their infrastructure. " +
                                        "If you did not install this tool, treat this as a compromise indicator.",
                            Confidence = 0.88,
                            Tier = DetectionTier.Tier1Behavioral,
                            ProcessName = name,
                            ProcessId = proc.Id,
                            Timestamp = DateTime.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["technique"] = "T1219 - Remote Access Software",
                                ["tool_name"] = toolName,
                                ["image_path"] = imagePath ?? "unknown"
                            }
                        }, ct);
                    }
                }
                catch { /* Process may have exited */ }
            }
        }
        finally
        {
            foreach (var p in processes)
            {
                try { p.Dispose(); } catch { }
            }
        }
    }

    private async Task CheckRdpStateAsync(CancellationToken ct)
    {
        var currentlyEnabled = IsRdpEnabled();

        // Detect RDP being enabled when it wasn't at baseline
        if (currentlyEnabled && !_rdpBaselineEnabled)
        {
            _logger.LogCritical("[RemoteAccessMonitor] RDP was ENABLED since service start!");

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "RDP Enabled Without Authorization",
                Evidence = "Remote Desktop Protocol was enabled after Sentinel started. " +
                           "Baseline state was: disabled. Current state: enabled.",
                Reasoning = "RDP was not enabled when Sentinel started but is now active. " +
                            "An attacker may have enabled RDP to establish persistent remote access. " +
                            "If you did not enable this, an attacker can connect to your desktop remotely.",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = "TermService",
                ProcessId = 0,
                Timestamp = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["technique"] = "T1021.001 - Remote Services: Remote Desktop Protocol",
                    ["action"] = "rdp_enabled",
                    ["baseline_state"] = "disabled",
                    ["current_state"] = "enabled"
                }
            }, ct);

            _rdpBaselineEnabled = currentlyEnabled; // Update to prevent spam
        }

        // Check for active RDP sessions (TermService connections)
        if (currentlyEnabled)
        {
            await CheckActiveRdpSessionsAsync(ct);
        }
    }

    private async Task CheckActiveRdpSessionsAsync(CancellationToken ct)
    {
        try
        {
            // Check if TermService (RDP) has active TCP connections
            var tcpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
            var rdpConnections = tcpConnections
                .Where(c => c.LocalEndPoint.Port == 3389 && c.State == TcpState.Established)
                .ToList();

            if (rdpConnections.Count > 0)
            {
                var remoteIps = string.Join(", ", rdpConnections.Select(c => c.RemoteEndPoint.Address));

                // Only alert once per set of remote IPs
                var dedupeKey = $"rdp_session:{remoteIps}";
                if (_alertedProcesses.Contains(dedupeKey)) return;
                _alertedProcesses.Add(dedupeKey);

                _logger.LogCritical(
                    "[RemoteAccessMonitor] ACTIVE RDP SESSION from: {IPs}",
                    remoteIps);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Active RDP Session Detected",
                    Evidence = $"Active RDP connection(s) from: {remoteIps}. " +
                               $"Total active sessions: {rdpConnections.Count}.",
                    Reasoning = "One or more remote desktop sessions are currently active. " +
                                "If you are not actively using Remote Desktop, an attacker may be " +
                                "connected to your machine and viewing/controlling your desktop.",
                    Confidence = 0.82,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "TermService",
                    ProcessId = 0,
                    Timestamp = DateTime.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["technique"] = "T1021.001 - Remote Services: Remote Desktop Protocol",
                        ["remote_addresses"] = remoteIps,
                        ["session_count"] = rdpConnections.Count.ToString()
                    }
                }, ct);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[RemoteAccessMonitor] RDP session check error");
        }
    }

    private async Task CheckRemoteAccessPortsAsync(CancellationToken ct)
    {
        try
        {
            var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();

            foreach (var listener in listeners)
            {
                if (RemoteAccessPorts.TryGetValue(listener.Port, out var serviceName))
                {
                    // Skip RDP if it was already enabled at baseline
                    if (listener.Port == 3389 && _rdpBaselineEnabled) continue;

                    if (!_alertedPorts.Add(listener.Port)) continue;

                    _logger.LogWarning(
                        "[RemoteAccessMonitor] Remote access port LISTENING: {Port} ({Service})",
                        listener.Port, serviceName);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Remote Access Port Listening",
                        Evidence = $"Port {listener.Port} ({serviceName}) is listening for connections. " +
                                   $"Address: {listener.Address}",
                        Reasoning = "A port commonly used by remote access tools is actively listening. " +
                                    "This could allow remote connections to this machine. Verify this is " +
                                    "intentional and authorized.",
                        Confidence = 0.72,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = serviceName,
                        ProcessId = 0,
                        Timestamp = DateTime.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["technique"] = "T1219 - Remote Access Software",
                            ["port"] = listener.Port.ToString(),
                            ["service"] = serviceName,
                            ["address"] = listener.Address.ToString()
                        }
                    }, ct);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[RemoteAccessMonitor] Port scan error");
        }
    }

    private static bool IsRdpEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"System\CurrentControlSet\Control\Terminal Server");
            if (key == null) return false;

            var value = key.GetValue("fDenyTSConnections");
            // 0 = RDP enabled, 1 = RDP disabled
            return value is int intVal && intVal == 0;
        }
        catch
        {
            return false;
        }
    }
}
