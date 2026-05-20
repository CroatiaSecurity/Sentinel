using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Webcam &amp; Microphone Exfiltration Monitor — Detects unauthorized background
/// access to camera and microphone devices.
///
/// Detection philosophy:
///   - User actively on a video call / streaming site / recording app = ALLOWED
///   - Background process (no visible window) accessing camera/mic = SUSPICIOUS
///   - Background camera/mic access + network activity = EXFILTRATION (composite kill)
///
/// How we avoid false positives on legitimate use:
///   1. Comprehensive allowlist of known conferencing, streaming, recording, and
///      browser processes (Teams, Zoom, Discord, OBS, Chrome, Firefox, Edge, etc.)
///   2. Processes WITH a visible window are given a pass — the user can see them
///   3. Only background (no visible window) or headless processes trigger detection
///   4. Confirmation threshold: must be seen accessing camera/mic DLLs across
///      multiple scan cycles (avoids transient loads during app startup)
///   5. Standalone detection is Tier2 (log only) — only the composite with network
///      activity triggers a kill (via correlation engine)
///
/// This means:
///   - User on Google Meet in Chrome → Chrome is allowlisted → no alert
///   - User streaming on OBS → OBS is allowlisted → no alert
///   - User in Zoom call → Zoom is allowlisted → no alert
///   - Unknown background process loading camera DLLs + sending data → ALERT + KILL
///
/// Feeds into BehavioralCorrelationEngine composites:
///   - WebcamMic + Network → "Camera/Mic Exfiltration" (spyware streaming to C2)
///   - WebcamMic + ScreenCapture → "Full Surveillance Suite" (updated to include camera)
///
/// MITRE ATT&amp;CK: T1125 (Video Capture), T1123 (Audio Capture)
/// </summary>
public sealed class WebcamMicMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<WebcamMicMonitor> _logger;
    private readonly TelemetryFusionEngine? _fusionEngine;

    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(20);

    // Track alerted PIDs to avoid flooding
    private readonly ConcurrentDictionary<int, DateTimeOffset> _alertedPids = new();

    // Confirmation: must see camera/mic access N times before alerting
    private readonly ConcurrentDictionary<int, int> _hitCount = new();
    private const int ConfirmationThreshold = 3;

    // ── DLLs that indicate webcam/camera access ──────────────────────────────

    /// <summary>
    /// DLLs loaded when a process accesses the camera via Media Foundation,
    /// DirectShow, or legacy Video for Windows APIs.
    /// NOTE: mf.dll, mfplat.dll, mfreadwrite.dll are excluded from this list because
    /// they are loaded by any process that plays video (browsers, media players).
    /// We only count DLLs that specifically indicate CAMERA CAPTURE intent.
    /// </summary>
    private static readonly string[] CameraDlls =
    {
        "mfcore.dll",           // Media Foundation core (Win10+) — less common than mfplat
        "mfsensorgroup.dll",    // Camera sensor group (Win10+)
        "frameserver.dll",      // Windows Camera Frame Server
        "framservermonitor.dll",// Frame Server monitor
        "avicap32.dll",         // Video for Windows (legacy capture)
        "qcap.dll",             // DirectShow capture
        "ksproxy.ax",           // Kernel Streaming proxy (camera driver)
        "vidcap.dll",           // Video capture helper
    };

    /// <summary>
    /// DLLs loaded when a process accesses the microphone for recording
    /// (as opposed to playback — we only care about capture/recording).
    /// NOTE: audioses.dll, mmdevapi.dll, mfplat.dll are excluded because they are
    /// loaded by virtually every process that plays audio (browsers, editors, shell).
    /// We only count DLLs that specifically indicate CAPTURE intent.
    /// </summary>
    private static readonly string[] MicRecordingDlls =
    {
        "audioclient.dll",      // Audio client (capture streams — more specific than audioses)
        "mfreadwrite.dll",      // Media Foundation read/write (recording)
        "winmm.dll",            // Windows Multimedia (waveIn API — legacy recording)
        "portaudio.dll",        // PortAudio (cross-platform audio capture)
        "naudio.dll",           // NAudio (.NET audio library)
    };

    /// <summary>
    /// Stronger camera indicators — these DLLs are specifically for camera
    /// frame capture, not general media playback.
    /// </summary>
    private static readonly string[] StrongCameraIndicators =
    {
        "mfsensorgroup.dll",    // Camera sensor group — only loaded for camera access
        "frameserver.dll",      // Frame Server — camera frame delivery
        "avicap32.dll",         // Video for Windows capture
        "qcap.dll",             // DirectShow capture filter
        "ksproxy.ax",           // Kernel streaming (camera driver interface)
    };

    // ── Allowlisted processes (legitimate camera/mic users) ──────────────────

    private static readonly HashSet<string> AllowedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Video conferencing
        "teams", "teams.exe",
        "ms-teams", "ms-teams.exe",
        "zoom", "zoom.exe",
        "cpthost", "cpthost.exe",               // Zoom capture host
        "slack", "slack.exe",
        "discord", "discord.exe",
        "skype", "skype.exe",
        "skypeapp", "skypeapp.exe",
        "webex", "webex.exe",
        "ciscowebexstart", "ciscowebexstart.exe",
        "gotomeeting", "gotomeeting.exe",
        "bluejeans", "bluejeans.exe",
        // Streaming / recording
        "obs64", "obs64.exe", "obs32", "obs32.exe",
        "obs", "obs.exe",
        "streamlabs", "streamlabs.exe",
        "xsplit", "xsplit.exe",
        "xsplit.core", "xsplit.core.exe",
        "nvidia share", "nvidia share.exe",
        "geforceexperience", "geforceexperience.exe",
        // Browsers (user may be on video call site, streaming, etc.)
        "chrome", "chrome.exe",
        "msedge", "msedge.exe",
        "msedgewebview2", "msedgewebview2.exe",  // Edge WebView2 child processes
        "firefox", "firefox.exe",
        "brave", "brave.exe",
        "opera", "opera.exe",
        "vivaldi", "vivaldi.exe",
        // Camera apps
        "windowscamera", "windowscamera.exe",
        "camera", "camera.exe",
        "microsoft.windows.camera", "microsoft.windows.camera.exe",
        // Media / editing
        "audacity", "audacity.exe",
        "adobe premiere pro", "adobe premiere pro.exe",
        "premiere", "premiere.exe",
        "davinci resolve", "resolve.exe",
        "shotcut", "shotcut.exe",
        "handbrake", "handbrake.exe",
        "vlc", "vlc.exe",
        // Voice assistants / accessibility
        "cortana", "cortana.exe",
        "siri", "siri.exe",
        // Security / biometric
        "windows hello", "windows hello.exe",
        "windowsbiometricservice", "windowsbiometricservice.exe",
        // System
        "dwm", "dwm.exe",
        "csrss", "csrss.exe",
        "svchost", "svchost.exe",
        "explorer", "explorer.exe",
        "runtimebroker", "runtimebroker.exe",
        "applicationframehost", "applicationframehost.exe",
        "systemsettings", "systemsettings.exe",
        "sihost", "sihost.exe",
        "searchhost", "searchhost.exe",
        "startmenuexperiencehost", "startmenuexperiencehost.exe",
        "shellexperiencehost", "shellexperiencehost.exe",
        "textinputhost", "textinputhost.exe",
        "widgetservice", "widgetservice.exe",
        "widgets", "widgets.exe",
        // IDEs / editors (Electron apps load audio/media DLLs for notifications)
        "code", "code.exe",
        "kiro", "kiro.exe",
        "devenv", "devenv.exe",
        "rider64", "rider64.exe",
        "idea64", "idea64.exe",
        "windowsterminal", "windowsterminal.exe",
        "wt", "wt.exe",
        // Sentinel itself
        "sentinelservice", "sentinelservice.exe",
        "sentinelagent", "sentinelagent.exe",
        // Voice chat in games
        "steam", "steam.exe",
        "steamwebhelper", "steamwebhelper.exe",
        // Remote desktop
        "mstsc", "mstsc.exe",
        "teamviewer", "teamviewer.exe",
        "anydesk", "anydesk.exe",
    };

    // ── P/Invoke for window visibility check ─────────────────────────────────

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    public WebcamMicMonitor(
        IDetectionEngine detectionEngine,
        ILogger<WebcamMicMonitor> logger,
        TelemetryFusionEngine? fusionEngine = null)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _fusionEngine = fusionEngine;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Webcam & Microphone Monitor starting ===");

        // Initial delay to let system stabilize
        await Task.Delay(TimeSpan.FromSeconds(20), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "WebcamMicMonitor: scan error");
            }

            try { await Task.Delay(ScanInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task ScanAsync(CancellationToken ct)
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
                if (AllowedProcesses.Contains(p.ProcessName)) continue;
                if (_alertedPids.ContainsKey(p.Id)) continue;

                // Skip processes with a visible main window — user can see them
                bool hasVisibleWindow;
                try
                {
                    hasVisibleWindow = p.MainWindowHandle != IntPtr.Zero &&
                                       IsWindowVisible(p.MainWindowHandle);
                }
                catch { continue; }

                if (hasVisibleWindow) continue;

                // Check loaded modules for camera/mic DLLs
                bool hasStrongCamera = false;
                int cameraDllCount = 0;
                int micDllCount = 0;

                try
                {
                    foreach (ProcessModule m in p.Modules)
                    {
                        var name = Path.GetFileName(m.FileName ?? "").ToLowerInvariant();
                        if (string.IsNullOrEmpty(name)) continue;

                        foreach (var dll in CameraDlls)
                        {
                            if (name == dll)
                            {
                                cameraDllCount++;
                                break;
                            }
                        }

                        foreach (var dll in StrongCameraIndicators)
                        {
                            if (name == dll)
                            {
                                hasStrongCamera = true;
                                break;
                            }
                        }

                        foreach (var dll in MicRecordingDlls)
                        {
                            if (name == dll)
                            {
                                micDllCount++;
                                break;
                            }
                        }
                    }
                }
                catch { continue; } // Access denied / process exited

                // Need strong camera indicator OR multiple camera-specific DLLs loaded
                // (these are all camera-specific now, so even 2 is meaningful)
                bool suspiciousCamera = hasStrongCamera || cameraDllCount >= 2;

                // For mic: need 3+ mic-specific DLLs (audioclient alone is common)
                bool suspiciousMic = micDllCount >= 3;

                if (!suspiciousCamera && !suspiciousMic) continue;

                // Confirmation threshold — must be seen across multiple scans
                var count = _hitCount.AddOrUpdate(p.Id, 1, (_, c) => c + 1);
                if (count < ConfirmationThreshold) continue;

                // This is a background process with camera/mic access — emit detection
                _alertedPids[p.Id] = DateTimeOffset.UtcNow;

                string? processPath = null;
                try { processPath = p.MainModule?.FileName; } catch { }

                string deviceType = (suspiciousCamera && suspiciousMic) ? "Camera + Microphone"
                    : suspiciousCamera ? "Camera (Webcam)"
                    : "Microphone";

                double confidence = hasStrongCamera ? 0.80 : 0.70;
                if (suspiciousCamera && suspiciousMic) confidence = 0.82;

                _logger.LogWarning(
                    "WebcamMic: Background process '{Name}' (PID {Pid}) accessing {Device} " +
                    "with no visible window — possible spyware/RAT",
                    p.ProcessName, p.Id, deviceType);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = $"Webcam/Mic Access: Background {deviceType} Capture",
                    Evidence = $"Background process '{p.ProcessName}' (PID {p.Id}) has loaded " +
                              $"{deviceType.ToLowerInvariant()} capture DLLs with no visible window. " +
                              $"Camera DLLs: {cameraDllCount}, Mic DLLs: {micDllCount}, " +
                              $"Strong camera indicator: {hasStrongCamera}. " +
                              $"Path: {processPath ?? "unknown"}. " +
                              $"Confirmed across {count} scan cycles.",
                    Reasoning = "A process with no visible window that loads camera/microphone " +
                               "capture APIs is likely performing unauthorized recording. " +
                               "Legitimate video/audio applications have visible UI (conferencing " +
                               "apps, browsers, camera apps). Background-only camera/mic access " +
                               "is the hallmark of spyware, RATs, and stalkerware that secretly " +
                               "record the user. Browsers and known conferencing apps are allowlisted.",
                    Confidence = confidence,
                    Tier = DetectionTier.Tier2Indicator,
                    ProcessName = p.ProcessName,
                    ProcessId = p.Id,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["technique"] = "T1125 - Video Capture / T1123 - Audio Capture",
                        ["device_type"] = deviceType,
                        ["has_visible_window"] = "false",
                        ["camera_dll_count"] = cameraDllCount.ToString(),
                        ["mic_dll_count"] = micDllCount.ToString(),
                        ["strong_camera_indicator"] = hasStrongCamera.ToString(),
                        ["confirmation_count"] = count.ToString(),
                        ["process_path"] = processPath ?? "unknown"
                    }
                }, ct);

                // Feed telemetry fusion for composite correlation
                _fusionEngine?.IngestFileActivity(p.Id, p.ProcessName,
                    "webcam_mic_capture", FileActivityKind.Read, DateTimeOffset.UtcNow);
            }
        }
        finally
        {
            // Prune old entries
            var cutoff = DateTimeOffset.UtcNow.AddMinutes(-5);
            foreach (var kv in _alertedPids)
                if (kv.Value < cutoff) _alertedPids.TryRemove(kv.Key, out _);

            // Prune hit counts for processes no longer showing camera/mic access
            foreach (var pid in _hitCount.Keys.ToList())
            {
                try
                {
                    Process.GetProcessById(pid);
                }
                catch
                {
                    _hitCount.TryRemove(pid, out _);
                }
            }
        }
    }
}

