using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core;

/// <summary>
/// Screen Capture &amp; Overlay Security Monitor â€” Detects unauthorized screen capture,
/// transparent overlay windows, and DXGI duplication abuse.
///
/// Monitors for:
///   1. Processes using DXGI Desktop Duplication (screen capture API) that aren't
///      known screen recorders, RDP, or accessibility tools
///   2. Transparent overlay windows (WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST)
///      owned by non-allowlisted processes â€” used for credential phishing overlays
///   3. Background processes loading screen-capture DLL combinations (gdi32 + d3d11 + dxgi)
///      without a visible window â€” indicates silent screen grabbing
///   4. Processes using PrintWindow/BitBlt APIs from the background
///
/// This catches:
///   - Screen capture spyware (screenshots sent to C2)
///   - Credential phishing overlays (fake login prompts drawn over real apps)
///   - Banking trojan overlays (fake banking UI overlaid on browser)
///   - Remote access trojans with screen streaming
///   - Game/app overlays used for social engineering
///
/// Detection philosophy:
///   - Known screen recorders (OBS, ShareX, Snipping Tool) = allowlisted
///   - Background process with capture DLLs + no window = suspicious
///   - Transparent topmost overlay from unknown process = highly suspicious
///   - Screen capture + network activity = spyware (composite with correlation engine)
///
/// Feeds into BehavioralCorrelationEngine composites:
///   - ScreenCapture + Network â†’ "Screen Exfiltration" (spyware)
///   - ScreenCapture + Clipboard â†’ "Data Harvesting" (infostealer)
///   - Overlay + Injection â†’ "Credential Phishing via Overlay"
/// </summary>
public sealed class ScreenCaptureMonitor : BackgroundService
{
    private readonly DetectionEngine _detectionEngine;
    private readonly ILogger<ScreenCaptureMonitor> _logger;
    private readonly TelemetryFusionEngine? _fusionEngine;

    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(25);
    private static readonly TimeSpan OverlayScanInterval = TimeSpan.FromSeconds(15);

    // Track alerted PIDs to avoid flooding
    private readonly ConcurrentDictionary<int, DateTime> _alertedCapturePids = new();
    private readonly ConcurrentDictionary<int, DateTime> _alertedOverlayPids = new();
    private readonly ConcurrentDictionary<int, int> _overlayHitCount = new();

    // Overlay must be seen N times before alerting (avoids transient tooltip/splash alerts)
    private const int OverlayConfirmationThreshold = 3;

    // â”€â”€ DLL combinations that indicate screen capture capability â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// <summary>
    /// Primary screen capture indicators â€” processes loading these are likely capturing.
    /// </summary>
    private static readonly string[] ScreenCaptureDlls =
    {
        "dxgi.dll", "d3d11.dll", "d3d12.dll",  // DXGI Desktop Duplication
    };

    /// <summary>
    /// Secondary indicators â€” combined with primary = stronger signal.
    /// </summary>
    private static readonly string[] CaptureHelperDlls =
    {
        "shcore.dll",           // DPI-aware capture
        "windowscodecs.dll",    // Image encoding (saving screenshots)
        "mfplat.dll",           // Media Foundation (video encoding for streaming)
        "mfreadwrite.dll",      // Media Foundation read/write (recording)
        "wmvcore.dll",          // Windows Media (screen recording)
    };

    // â”€â”€ Allowlisted processes (legitimate screen capture) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    private static readonly HashSet<string> AllowedCaptureProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // System
        "dwm", "dwm.exe",
        "csrss", "csrss.exe",
        "explorer", "explorer.exe",
        "shellexperiencehost", "shellexperiencehost.exe",
        "applicationframehost", "applicationframehost.exe",
        "systemsettings", "systemsettings.exe",
        "logonui", "logonui.exe",
        "lockapp", "lockapp.exe",
        // Screen capture tools
        "obs64", "obs64.exe", "obs32", "obs32.exe",
        "obs", "obs.exe",
        "sharex", "sharex.exe",
        "snippingtool", "snippingtool.exe",
        "screenclippinghost", "screenclippinghost.exe",
        "snipingtool", "snipingtool.exe",       // Win11 variant
        "lightshot", "lightshot.exe",
        "greenshot", "greenshot.exe",
        "flameshot", "flameshot.exe",
        "screenpresso", "screenpresso.exe",
        // Remote desktop (legitimate screen sharing)
        "mstsc", "mstsc.exe",
        "rdpclip", "rdpclip.exe",
        "msrdc", "msrdc.exe",
        "teamviewer", "teamviewer.exe",
        "teamviewer_service", "teamviewer_service.exe",
        "anydesk", "anydesk.exe",
        // Video conferencing (screen share)
        "teams", "teams.exe",
        "ms-teams", "ms-teams.exe",
        "zoom", "zoom.exe",
        "cpthost", "cpthost.exe",               // Zoom capture host
        "slack", "slack.exe",
        "discord", "discord.exe",
        "webex", "webex.exe",
        "ciscowebexstart", "ciscowebexstart.exe",
        // Games / GPU (naturally load DXGI)
        "steamwebhelper", "steamwebhelper.exe",
        "steam", "steam.exe",
        "epicgameslauncher", "epicgameslauncher.exe",
        "gameoverlayui", "gameoverlayui.exe",
        // Streaming
        "streamlabs", "streamlabs.exe",
        "xsplit", "xsplit.exe",
        // Accessibility
        "magnify", "magnify.exe",
        "narrator", "narrator.exe",
        // Browsers (use GPU/DXGI for rendering)
        "msedge", "msedge.exe",
        "chrome", "chrome.exe",
        "firefox", "firefox.exe",
        "brave", "brave.exe",
        "opera", "opera.exe",
        "vivaldi", "vivaldi.exe",
        // IDEs / editors (GPU rendering)
        "code", "code.exe",
        "kiro", "kiro.exe",
        "devenv", "devenv.exe",
        "rider64", "rider64.exe",
        "idea64", "idea64.exe",
        // GPU tools
        "nvidia share", "nvidia share.exe",
        "nvcontainer", "nvcontainer.exe",
        "nvspcaps64", "nvspcaps64.exe",
        "geforceexperience", "geforceexperience.exe",
        "aaborern", "aaborern.exe",             // AMD overlay
        "radeonoverlay", "radeonoverlay.exe",
        // Sentinel itself
        "sentinelservice", "sentinelservice.exe",
        "sentinelagent", "sentinelagent.exe",
        // Windows components
        "runtimebroker", "runtimebroker.exe",
        "searchhost", "searchhost.exe",
        "startmenuexperiencehost", "startmenuexperiencehost.exe",
        "textinputhost", "textinputhost.exe",
        "widgetservice", "widgetservice.exe",
        "widgets", "widgets.exe",
        "windowsterminal", "windowsterminal.exe",
        "wt", "wt.exe",
    };

    // â”€â”€ Allowlisted overlay processes (legitimate topmost transparent windows) â”€

    private static readonly HashSet<string> AllowedOverlayProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // System UI
        "dwm", "dwm.exe",
        "explorer", "explorer.exe",
        "shellexperiencehost", "shellexperiencehost.exe",
        "searchhost", "searchhost.exe",
        "startmenuexperiencehost", "startmenuexperiencehost.exe",
        "lockapp", "lockapp.exe",
        "logonui", "logonui.exe",
        "applicationframehost", "applicationframehost.exe",
        "textinputhost", "textinputhost.exe",
        "runtimebroker", "runtimebroker.exe",
        "widgetservice", "widgetservice.exe",
        "widgets", "widgets.exe",
        // Browsers (PiP windows, DevTools, dropdown menus use layered/topmost)
        "msedge", "msedge.exe",
        "chrome", "chrome.exe",
        "firefox", "firefox.exe",
        "brave", "brave.exe",
        "opera", "opera.exe",
        "vivaldi", "vivaldi.exe",
        // IDEs / editors (Electron apps use layered windows for menus, tooltips, overlays)
        "code", "code.exe",
        "kiro", "kiro.exe",
        "devenv", "devenv.exe",
        "rider64", "rider64.exe",
        "idea64", "idea64.exe",
        // Notifications / toasts
        "sentinelagent", "sentinelagent.exe",
        "sentinelservice", "sentinelservice.exe",
        // Game overlays (legitimate)
        "gameoverlayui", "gameoverlayui.exe",
        "nvidia share", "nvidia share.exe",
        "geforceexperience", "geforceexperience.exe",
        "radeonoverlay", "radeonoverlay.exe",
        "discord", "discord.exe",               // Discord overlay
        // Accessibility
        "magnify", "magnify.exe",
        "narrator", "narrator.exe",
        // Clipboard / productivity
        "ditto", "ditto.exe",
        "powertoys", "powertoys.exe",
        "powertoys.fancyzones", "powertoys.fancyzones.exe",
        // Snipping / screenshot
        "snippingtool", "snippingtool.exe",
        "screenclippinghost", "screenclippinghost.exe",
        // Input method
        "ctfmon", "ctfmon.exe",
        // Conferencing (screen share overlays, annotation tools)
        "teams", "teams.exe",
        "ms-teams", "ms-teams.exe",
        "zoom", "zoom.exe",
        "slack", "slack.exe",
        // Streaming (scene overlays)
        "obs64", "obs64.exe",
        "obs", "obs.exe",
        "streamlabs", "streamlabs.exe",
        // Windows Terminal (quake mode uses topmost)
        "windowsterminal", "windowsterminal.exe",
        "wt", "wt.exe",
        // Steam (overlay notifications)
        "steam", "steam.exe",
        "steamwebhelper", "steamwebhelper.exe",
        // Games (legitimate overlay/topmost windows for in-game UI, Steam integration)
        "fm", "fm.exe",                         // Football Manager
        "GameOverlayUI", "GameOverlayUI.exe",   // Steam game overlay (already above but kept for clarity)
    };

    // â”€â”€ P/Invoke declarations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern int GetWindowLongW(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll")]
    private static extern int GetWindowThreadProcessId(IntPtr hWnd, out int processId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern int GetWindowText(IntPtr hWnd, char[] text, int count);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern int GetClassName(IntPtr hWnd, char[] className, int maxCount);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetClientRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMonitorInfoW(IntPtr hMonitor, ref MONITORINFO lpmi);

    private const uint MONITOR_DEFAULTTONEAREST = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct MONITORINFO
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    private const int GWL_EXSTYLE = -20;
    private const int WS_EX_LAYERED = 0x00080000;
    private const int WS_EX_TRANSPARENT = 0x00000020;
    private const int WS_EX_TOPMOST = 0x00000008;
    private const int WS_EX_TOOLWINDOW = 0x00000080;
    private const int WS_EX_NOACTIVATE = 0x08000000;

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left, Top, Right, Bottom;
        public int Width => Right - Left;
        public int Height => Bottom - Top;
        public int Area => Width * Height;
    }

    public ScreenCaptureMonitor(
        DetectionEngine detectionEngine,
        ILogger<ScreenCaptureMonitor> logger,
        TelemetryFusionEngine? fusionEngine = null)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _fusionEngine = fusionEngine;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Screen Capture & Overlay Monitor starting ===");

        // Initial delay to let system stabilize
        await Task.Delay(TimeSpan.FromSeconds(20), stoppingToken);

        var lastOverlayScan = DateTime.MinValue;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Screen capture DLL scan
                await ScanForScreenCaptureProcessesAsync(stoppingToken);

                // Overlay scan (slightly more frequent since overlays are transient)
                var now = DateTime.UtcNow;
                if (now - lastOverlayScan >= OverlayScanInterval)
                {
                    ScanForSuspiciousOverlays(stoppingToken);
                    lastOverlayScan = now;
                }

                await Task.Delay(ScanInterval, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ScreenCaptureMonitor: Scan error");
                await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
            }
        }
    }

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // DETECTION 1: Background processes with screen capture DLL combinations
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    private async Task ScanForScreenCaptureProcessesAsync(CancellationToken ct)
    {
        var selfPid = Environment.ProcessId;
        var procs = Process.GetProcesses();

        try
        {
            foreach (var proc in procs)
            {
                ct.ThrowIfCancellationRequested();
                using var p = proc;

                if (p.Id == selfPid || p.Id <= 4) continue;
                if (AllowedCaptureProcesses.Contains(p.ProcessName)) continue;
                if (_alertedCapturePids.ContainsKey(p.Id)) continue;

                // Skip processes with visible windows (user is likely aware of them)
                // We only care about BACKGROUND screen capture.
                // Note: Process.MainWindowHandle is unreliable â€” some apps (games, multi-window
                // engines) don't have a .NET-recognized "main" window. We also enumerate all
                // top-level windows owned by this PID to catch those cases.
                bool hasVisibleWindow;
                try
                {
                    hasVisibleWindow = p.MainWindowHandle != IntPtr.Zero &&
                                       IsWindowVisible(p.MainWindowHandle);
                }
                catch { continue; }

                if (!hasVisibleWindow)
                {
                    // Fallback: check if the process owns ANY visible top-level window
                    hasVisibleWindow = ProcessOwnsVisibleWindow(p.Id);
                }

                if (hasVisibleWindow) continue;

                // Also skip if this process owns the foreground window (fullscreen games
                // often don't set MainWindowHandle but ARE the active foreground app)
                if (IsProcessForegroundFullscreen(p.Id)) continue;

                // Check loaded modules for screen capture DLL combination
                bool hasPrimaryCapture = false;
                bool hasHelper = false;
                bool hasImageCodec = false;

                try
                {
                    foreach (ProcessModule m in p.Modules)
                    {
                        var name = Path.GetFileName(m.FileName ?? "").ToLowerInvariant();
                        if (string.IsNullOrEmpty(name)) continue;

                        foreach (var dll in ScreenCaptureDlls)
                            if (name == dll) { hasPrimaryCapture = true; break; }

                        foreach (var dll in CaptureHelperDlls)
                            if (name == dll) { hasHelper = true; break; }

                        if (name == "windowscodecs.dll" || name == "wic.dll")
                            hasImageCodec = true;

                        if (hasPrimaryCapture && (hasHelper || hasImageCodec)) break;
                    }
                }
                catch { continue; } // Access denied / process exited

                // Need primary capture DLLs + at least one helper/codec
                // (just having dxgi.dll alone is too common â€” every GPU app loads it)
                if (!hasPrimaryCapture || (!hasHelper && !hasImageCodec)) continue;

                // This is a background process with screen capture + encoding capability
                _alertedCapturePids[p.Id] = DateTime.UtcNow;

                string? processPath = null;
                try { processPath = p.MainModule?.FileName; } catch { }

                _logger.LogWarning(
                    "Screen Capture: Background process '{Name}' (PID {Pid}) has screen capture " +
                    "DLL combination loaded without a visible window â€” possible screen-grabbing malware",
                    p.ProcessName, p.Id);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Screen Capture: Background Process with Capture DLLs",
                    Evidence = $"Background process '{p.ProcessName}' (PID {p.Id}) has loaded " +
                              $"screen capture DLLs (DXGI/D3D11) combined with image encoding " +
                              $"libraries, but has no visible window. " +
                              $"Path: {processPath ?? "unknown"}.",
                    Reasoning = "A process with no visible window that loads both screen capture " +
                               "APIs (DXGI Desktop Duplication / Direct3D) and image encoding " +
                               "libraries (Windows Imaging Component, Media Foundation) is likely " +
                               "performing silent screen capture. Legitimate screen recorders have " +
                               "visible UI. Background capture is the hallmark of spyware, RATs, " +
                               "and infostealers that screenshot the desktop periodically.",
                    Confidence = 0.75,
                    Tier = DetectionTier.Tier2Indicator,
                    ProcessName = p.ProcessName,
                    ProcessId = p.Id,
                    Timestamp = DateTime.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["technique"] = "T1113 - Screen Capture",
                        ["has_visible_window"] = "false",
                        ["has_dxgi"] = hasPrimaryCapture.ToString(),
                        ["has_image_codec"] = hasImageCodec.ToString(),
                        ["has_media_foundation"] = hasHelper.ToString(),
                        ["process_path"] = processPath ?? "unknown"
                    }
                }, ct);

                // Feed telemetry fusion for composite correlation
                _fusionEngine?.IngestFileActivity(p.Id, p.ProcessName,
                    "screen_capture", FileActivityKind.Read, DateTime.UtcNow);
            }
        }
        finally
        {
            // Process objects already disposed via 'using var p = proc' above
        }
    }

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // HELPER: Check if a process owns any visible top-level window
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    /// <summary>
    /// Enumerates all top-level windows and returns true if the given PID owns at least
    /// one that is visible and has a non-trivial size. This catches cases where
    /// Process.MainWindowHandle fails (multi-window apps, games with separate render
    /// windows, launcherâ†’game handoffs, etc.)
    /// </summary>
    private static bool ProcessOwnsVisibleWindow(int pid)
    {
        bool found = false;

        EnumWindows((hWnd, _) =>
        {
            if (!IsWindowVisible(hWnd)) return true;

            GetWindowThreadProcessId(hWnd, out int windowPid);
            if (windowPid != pid) return true;

            // Ignore tiny windows (tray icons, hidden helper windows)
            if (!GetWindowRect(hWnd, out RECT rect)) return true;
            if (rect.Area < 50000) return true; // ~224x224 minimum

            // Skip tool windows (tooltips, floating toolbars) â€” they don't count as "visible app"
            var exStyle = GetWindowLongW(hWnd, GWL_EXSTYLE);
            if ((exStyle & WS_EX_TOOLWINDOW) != 0) return true;

            found = true;
            return false; // Stop enumerating
        }, IntPtr.Zero);

        return found;
    }

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // HELPER: Detect if a process is the foreground fullscreen application
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    /// <summary>
    /// Returns true if the given PID owns the current foreground window AND that window
    /// covers the full monitor (fullscreen exclusive or borderless fullscreen).
    /// This prevents false positives on games and media players that don't report
    /// a MainWindowHandle but are clearly the active user-facing application.
    /// </summary>
    private static bool IsProcessForegroundFullscreen(int pid)
    {
        try
        {
            var fgHwnd = GetForegroundWindow();
            if (fgHwnd == IntPtr.Zero) return false;

            GetWindowThreadProcessId(fgHwnd, out int fgPid);
            if (fgPid != pid) return false;

            // The process owns the foreground window â€” now check if it's fullscreen
            if (!GetWindowRect(fgHwnd, out RECT windowRect)) return false;

            var monitor = MonitorFromWindow(fgHwnd, MONITOR_DEFAULTTONEAREST);
            if (monitor == IntPtr.Zero) return false;

            var monitorInfo = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
            if (!GetMonitorInfoW(monitor, ref monitorInfo)) return false;

            // Window covers the entire monitor = fullscreen (exclusive or borderless)
            var mr = monitorInfo.rcMonitor;
            return windowRect.Left <= mr.Left &&
                   windowRect.Top <= mr.Top &&
                   windowRect.Right >= mr.Right &&
                   windowRect.Bottom >= mr.Bottom;
        }
        catch
        {
            return false;
        }
    }

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // DETECTION 2: Suspicious transparent overlay windows
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    private void ScanForSuspiciousOverlays(CancellationToken ct)
    {
        var suspiciousWindows = new List<(IntPtr hWnd, int pid, string processName, RECT rect)>();

        EnumWindows((hWnd, _) =>
        {
            if (ct.IsCancellationRequested) return false;
            if (!IsWindowVisible(hWnd)) return true;

            var exStyle = GetWindowLongW(hWnd, GWL_EXSTYLE);

            // Look for: LAYERED + TRANSPARENT + TOPMOST (the phishing overlay trifecta)
            bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
            bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;
            bool isTopmost = (exStyle & WS_EX_TOPMOST) != 0;

            // Must be at least layered + one of (transparent, topmost)
            if (!isLayered || (!isTransparent && !isTopmost)) return true;

            // Get owning process
            GetWindowThreadProcessId(hWnd, out int pid);
            if (pid <= 4) return true;

            // Get window size â€” ignore tiny windows (tooltips, notification icons)
            if (!GetWindowRect(hWnd, out RECT rect)) return true;
            if (rect.Area < 50000) return true; // Less than ~224x224 pixels â€” too small to be an overlay attack

            // Get process name
            string processName;
            try
            {
                using var p = Process.GetProcessById(pid);
                processName = p.ProcessName;
            }
            catch { return true; }

            // Skip allowlisted
            if (AllowedOverlayProcesses.Contains(processName)) return true;

            suspiciousWindows.Add((hWnd, pid, processName, rect));
            return true;
        }, IntPtr.Zero);

        // Process suspicious overlays
        foreach (var (hWnd, pid, processName, rect) in suspiciousWindows)
        {
            if (ct.IsCancellationRequested) break;
            if (_alertedOverlayPids.ContainsKey(pid)) continue;

            // Increment hit count â€” only alert after confirmation threshold
            var count = _overlayHitCount.AddOrUpdate(pid, 1, (_, c) => c + 1);
            if (count < OverlayConfirmationThreshold) continue;

            _alertedOverlayPids[pid] = DateTime.UtcNow;

            // Get window title and class for evidence
            var titleBuf = new char[256];
            var titleLen = GetWindowText(hWnd, titleBuf, titleBuf.Length);
            var title = titleLen > 0 ? new string(titleBuf, 0, titleLen) : "(no title)";

            var classBuf = new char[256];
            var classLen = GetClassName(hWnd, classBuf, classBuf.Length);
            var className = classLen > 0 ? new string(classBuf, 0, classLen) : "(unknown)";

            var exStyle = GetWindowLongW(hWnd, GWL_EXSTYLE);
            bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;
            bool isTopmost = (exStyle & WS_EX_TOPMOST) != 0;
            bool isNoActivate = (exStyle & WS_EX_NOACTIVATE) != 0;

            string? processPath = null;
            try
            {
                using var p = Process.GetProcessById(pid);
                processPath = p.MainModule?.FileName;
            }
            catch { }

            _logger.LogWarning(
                "Overlay Detection: '{Name}' (PID {Pid}) has a large transparent topmost window " +
                "({W}x{H}) â€” possible credential phishing or banking trojan overlay",
                processName, pid, rect.Width, rect.Height);

            // Determine confidence based on how many overlay flags are set
            double confidence = 0.70;
            if (isTransparent && isTopmost) confidence = 0.82;
            if (isTransparent && isTopmost && isNoActivate) confidence = 0.88;

            // v4.7.0: Reduce false positives on games and legitimate apps.
            // If the process runs from a trusted install path (Program Files, Steam, Epic, GOG, etc.)
            // OR is Authenticode-signed, downgrade to Tier2 (advisory only, never kills).
            // Real banking trojans run from Temp/AppData/Downloads and are unsigned.
            var tier = DetectionTier.Tier1Behavioral;
            bool isTrustedPath = false;
            bool isSigned = false;

            if (!string.IsNullOrEmpty(processPath))
            {
                var pathLower = processPath.ToLowerInvariant();
                isTrustedPath = pathLower.Contains(@"\program files\") ||
                                pathLower.Contains(@"\program files (x86)\") ||
                                pathLower.Contains(@"\steamapps\") ||
                                pathLower.Contains(@"\steam\") ||
                                pathLower.Contains(@"\epic games\") ||
                                pathLower.Contains(@"\gog galaxy\") ||
                                pathLower.Contains(@"\riot games\") ||
                                pathLower.Contains(@"\battle.net\") ||
                                pathLower.Contains(@"\ubisoft\") ||
                                pathLower.Contains(@"\ea games\") ||
                                pathLower.Contains(@"\origin\") ||
                                pathLower.Contains(@"\windows\");

                if (!isTrustedPath)
                {
                    // Check Authenticode signature as fallback
                    try
                    {
                        using var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                            System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(processPath));
                        isSigned = true;
                    }
                    catch { isSigned = false; }
                }
            }

            if (isTrustedPath || isSigned)
            {
                // Trusted app with overlay â€” log as Tier2 advisory, never kill
                tier = DetectionTier.Tier2Indicator;
                confidence = Math.Min(confidence, 0.60); // Cap confidence below kill threshold
            }

            _ = _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Overlay Attack: Suspicious Transparent Window",
                Evidence = $"Process '{processName}' (PID {pid}) owns a large transparent overlay window " +
                          $"({rect.Width}x{rect.Height} pixels). Window class: '{className}', " +
                          $"Title: '{title}'. Styles: Layered={true}, Transparent={isTransparent}, " +
                          $"Topmost={isTopmost}, NoActivate={isNoActivate}. " +
                          $"Path: {processPath ?? "unknown"}. " +
                          $"TrustedPath: {isTrustedPath}, Signed: {isSigned}. " +
                          $"Seen {count} times (persistent overlay).",
                Reasoning = tier == DetectionTier.Tier2Indicator
                    ? "A large transparent topmost window was detected from a process running from a " +
                      "trusted install location or with a valid Authenticode signature. This is likely " +
                      "a game overlay, media player, or legitimate application UI. Logged as advisory only."
                    : "A large transparent topmost window from a non-system process is the " +
                      "primary technique used by banking trojans and credential phishing malware. " +
                      "The overlay is drawn on top of legitimate applications (browsers, banking apps) " +
                      "to capture credentials entered by the user who believes they're typing into " +
                      "the real application. The WS_EX_TRANSPARENT flag makes it click-through, " +
                      "and WS_EX_TOPMOST keeps it above all other windows.",
                Confidence = confidence,
                Tier = tier,
                ProcessName = processName,
                ProcessId = pid,
                Timestamp = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["technique"] = "T1056.004 - Credential API Hooking / T1113 - Screen Capture",
                    ["window_size"] = $"{rect.Width}x{rect.Height}",
                    ["window_class"] = className,
                    ["window_title"] = title,
                    ["ex_style_transparent"] = isTransparent.ToString(),
                    ["ex_style_topmost"] = isTopmost.ToString(),
                    ["ex_style_noactivate"] = isNoActivate.ToString(),
                    ["persistence_count"] = count.ToString(),
                    ["process_path"] = processPath ?? "unknown"
                }
            }, ct);

            // Feed telemetry fusion
            _fusionEngine?.IngestFileActivity(pid, processName,
                "overlay_window", FileActivityKind.Write, DateTime.UtcNow);
        }

        // Prune old entries
        var cutoff = DateTime.UtcNow.AddMinutes(-5);
        foreach (var kv in _alertedCapturePids)
            if (kv.Value < cutoff) _alertedCapturePids.TryRemove(kv.Key, out _);
        foreach (var kv in _alertedOverlayPids)
            if (kv.Value < cutoff) _alertedOverlayPids.TryRemove(kv.Key, out _);

        // Prune overlay hit counts for processes no longer showing overlays
        foreach (var pid in _overlayHitCount.Keys.ToList())
        {
            if (!suspiciousWindows.Any(w => w.pid == pid))
                _overlayHitCount.TryRemove(pid, out _);
        }
    }
}


