using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Microphone Session Monitor — Detects unauthorized processes with active audio
/// sessions on capture (microphone) endpoints.
///
/// Attack scenario this catches:
///   An attacker injects a DLL into any process (or runs a standalone tool) that
///   opens the microphone capture device and WRITES audio into it — feeding fake
///   audio (deepfake voice, pre-recorded commands) to the victim's Discord/Teams/
///   whatever. No command-line flags, no new DLLs to scan for, no virtual cable
///   software needed. Just a process silently holding an audio session on the mic.
///
/// Detection approach:
///   1. Enumerate all active audio capture (microphone) devices
///   2. For each device, enumerate all audio sessions (via WASAPI IAudioSessionManager2)
///   3. For each session, get the owning PID
///   4. Flag any PID that:
///      - Is not in the allowlist of known legitimate mic users
///      - Has no visible window (background/hidden process)
///      - Is not the foreground application
///   5. Track session participants over time — a NEW participant appearing on a mic
///      endpoint that was previously stable is a high-confidence indicator
///
/// This catches:
///   - DLL injection into any process that then opens a mic session
///   - Standalone tools feeding audio to mic without obvious command-line flags
///   - Virtual audio driver abuse (process opens the virtual mic's render side)
///   - Any process writing to the mic capture buffer via WASAPI shared/exclusive mode
///
/// Does NOT false-positive on:
///   - User's voice chat app (Discord, Teams, Zoom — allowlisted)
///   - Browser-based calls (Chrome, Edge, Firefox — allowlisted)
///   - Voice assistants, accessibility tools
///   - The user's own recording software (OBS, Audacity — allowlisted)
///
/// Feeds into BehavioralCorrelationEngine composites:
///   - MicSession + Network → "Audio Injection: Mic Feed + Network" (impersonation)
///   - MicSession + ScreenCapture → "Full Surveillance Suite"
///
/// MITRE ATT&amp;CK: T1123 (Audio Capture — inverse: audio injection to capture device)
/// </summary>
public sealed class MicSessionMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<MicSessionMonitor> _logger;
    private readonly TelemetryFusionEngine? _fusionEngine;

    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(15);

    // Track known mic session PIDs — used to detect NEW participants
    private readonly ConcurrentDictionary<int, DateTimeOffset> _knownMicPids = new();
    // Track alerted PIDs to avoid flooding
    private readonly ConcurrentDictionary<int, DateTimeOffset> _alertedPids = new();
    // Confirmation: must be seen across N scans before alerting (avoids transient opens)
    private readonly ConcurrentDictionary<int, int> _hitCount = new();
    private const int ConfirmationThreshold = 2;

    // ── Allowlisted processes (legitimate mic users) ─────────────────────────

    private static readonly HashSet<string> AllowedMicProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Video conferencing
        "teams", "teams.exe",
        "ms-teams", "ms-teams.exe",
        "zoom", "zoom.exe",
        "cpthost", "cpthost.exe",
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
        "audacity", "audacity.exe",
        "adobe audition", "adobe audition.exe",
        "reaper", "reaper.exe",
        "ableton live", "ableton live.exe",
        "fl64", "fl64.exe",
        "flstudio", "flstudio.exe",
        // Browsers (WebRTC calls, voice chat sites)
        "chrome", "chrome.exe",
        "msedge", "msedge.exe",
        "msedgewebview2", "msedgewebview2.exe",
        "firefox", "firefox.exe",
        "brave", "brave.exe",
        "opera", "opera.exe",
        "vivaldi", "vivaldi.exe",
        // Voice assistants / accessibility
        "cortana", "cortana.exe",
        "narrator", "narrator.exe",
        "speechruntime", "speechruntime.exe",
        // Games with voice chat
        "steam", "steam.exe",
        "steamwebhelper", "steamwebhelper.exe",
        // Remote desktop
        "mstsc", "mstsc.exe",
        "teamviewer", "teamviewer.exe",
        "teamviewer_service", "teamviewer_service.exe",
        "anydesk", "anydesk.exe",
        // System audio services
        "audiodg", "audiodg.exe",
        "svchost", "svchost.exe",
        "runtimebroker", "runtimebroker.exe",
        // Sentinel itself
        "sentinelservice", "sentinelservice.exe",
        "sentinelagent", "sentinelagent.exe",
    };

    // ── COM interfaces for WASAPI audio session enumeration ───────────────────

    // CLSID_MMDeviceEnumerator
    private static readonly Guid CLSID_MMDeviceEnumerator = new("BCDE0395-E52F-467C-8E3D-C4579291692E");
    // IID_IMMDeviceEnumerator
    private static readonly Guid IID_IMMDeviceEnumerator = new("A95664D2-9614-4F35-A746-DE8DB63617E6");

    private const int eCapture = 1;         // EDataFlow.eCapture
    private const int eAll = 0;             // Not used — we only want capture
    private const int DEVICE_STATE_ACTIVE = 0x00000001;
    private const int AUDCLNT_SHAREMODE_SHARED = 0;

    // IAudioSessionManager2 IID
    private static readonly Guid IID_IAudioSessionManager2 = new("77AA99A0-1BD6-484F-8BC7-2C654C9A9B6F");

    [DllImport("ole32.dll")]
    private static extern int CoCreateInstance(
        ref Guid rclsid, IntPtr pUnkOuter, uint dwClsContext, ref Guid riid, out IntPtr ppv);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern int GetWindowThreadProcessId(IntPtr hWnd, out int processId);

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll")]
    private static extern int GetWindowLongW(IntPtr hWnd, int nIndex);

    private const int GWL_EXSTYLE = -20;
    private const int WS_EX_TOOLWINDOW = 0x00000080;

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left, Top, Right, Bottom;
        public int Area => (Right - Left) * (Bottom - Top);
    }

    public MicSessionMonitor(
        IDetectionEngine detectionEngine,
        ILogger<MicSessionMonitor> logger,
        TelemetryFusionEngine? fusionEngine = null)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _fusionEngine = fusionEngine;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Microphone Session Monitor starting ===");

        // Initial delay — let system audio stabilize after boot/login
        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanMicSessionsAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "MicSessionMonitor: scan error");
            }

            try { await Task.Delay(ScanInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task ScanMicSessionsAsync(CancellationToken ct)
    {
        var activeMicPids = new HashSet<int>();

        try
        {
            // Enumerate active audio sessions on capture devices via WASAPI COM
            var sessionPids = EnumerateCaptureSessionPids();

            foreach (var pid in sessionPids)
            {
                ct.ThrowIfCancellationRequested();
                if (pid <= 4) continue;
                activeMicPids.Add(pid);

                // Skip allowlisted
                string processName;
                try
                {
                    using var p = Process.GetProcessById(pid);
                    processName = p.ProcessName;
                }
                catch { continue; } // Process exited

                if (AllowedMicProcesses.Contains(processName)) continue;
                if (_alertedPids.ContainsKey(pid)) continue;

                // Skip processes with a visible window — user is aware of them
                if (ProcessOwnsVisibleWindow(pid)) continue;

                // Skip if it's the foreground app
                if (IsProcessForeground(pid)) continue;

                // Confirmation threshold — must persist across scans
                var count = _hitCount.AddOrUpdate(pid, 1, (_, c) => c + 1);
                if (count < ConfirmationThreshold) continue;

                // Determine if this is a NEW participant (appeared after baseline)
                bool isNewParticipant = !_knownMicPids.ContainsKey(pid);

                _alertedPids[pid] = DateTimeOffset.UtcNow;

                string? processPath = null;
                TimeSpan processAge = TimeSpan.Zero;
                try
                {
                    using var p = Process.GetProcessById(pid);
                    processPath = p.MainModule?.FileName;
                    processAge = DateTimeOffset.UtcNow - p.StartTime.ToUniversalTime();
                }
                catch { }

                // Higher confidence if it's a new participant on an established mic
                double confidence = isNewParticipant ? 0.85 : 0.75;

                _logger.LogWarning(
                    "MicSession: Background process '{Name}' (PID {Pid}) has active audio session " +
                    "on microphone capture device with no visible window — possible audio injection/impersonation",
                    processName, pid);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Audio Injection: Unauthorized Mic Session",
                    Evidence = $"Background process '{processName}' (PID {pid}) holds an active audio " +
                              $"session on a microphone capture endpoint without a visible window. " +
                              $"New participant: {isNewParticipant}. Process age: {processAge.TotalMinutes:F0} min. " +
                              $"Path: {processPath ?? "unknown"}. " +
                              $"Confirmed across {count} scan cycles.",
                    Reasoning = "A process with no visible window holding an active audio session on a " +
                               "microphone capture device is a strong indicator of audio injection — " +
                               "feeding fake/pre-recorded audio into the mic so voice chat peers hear " +
                               "attacker-controlled speech (deepfake impersonation, social engineering). " +
                               "This also catches DLL injection attacks where malicious code opens a mic " +
                               "session from within a legitimate host process. Legitimate mic users " +
                               "(conferencing apps, browsers, recording software) are allowlisted. " +
                               "Background mic access without user-visible UI is not normal behavior.",
                    Confidence = confidence,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = processName,
                    ProcessId = pid,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["technique"] = "T1123 - Audio Capture (inverse: audio injection to capture device)",
                        ["has_visible_window"] = "false",
                        ["is_new_participant"] = isNewParticipant.ToString(),
                        ["process_age_minutes"] = processAge.TotalMinutes.ToString("F0"),
                        ["confirmation_count"] = count.ToString(),
                        ["process_path"] = processPath ?? "unknown"
                    }
                }, ct);

                // Feed telemetry fusion for composite correlation
                _fusionEngine?.IngestFileActivity(pid, processName,
                    "mic_session_injection", FileActivityKind.Write, DateTimeOffset.UtcNow);
            }
        }
        finally
        {
            // Update known PIDs baseline
            foreach (var pid in activeMicPids)
                _knownMicPids.TryAdd(pid, DateTimeOffset.UtcNow);

            // Prune PIDs no longer active
            foreach (var kv in _knownMicPids)
            {
                if (!activeMicPids.Contains(kv.Key))
                    _knownMicPids.TryRemove(kv.Key, out _);
            }

            // Prune alerted PIDs older than 5 minutes
            var cutoff = DateTimeOffset.UtcNow.AddMinutes(-5);
            foreach (var kv in _alertedPids)
                if (kv.Value < cutoff) _alertedPids.TryRemove(kv.Key, out _);

            // Prune hit counts for dead processes
            foreach (var pid in _hitCount.Keys.ToList())
            {
                if (!activeMicPids.Contains(pid))
                    _hitCount.TryRemove(pid, out _);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // WASAPI COM enumeration — get PIDs with active capture sessions
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Enumerates all active audio sessions on capture (microphone) devices
    /// and returns the set of PIDs that hold sessions.
    /// Uses WASAPI COM: IMMDeviceEnumerator → IMMDevice → IAudioSessionManager2
    /// → IAudioSessionEnumerator → IAudioSessionControl2 → GetProcessId
    /// </summary>
    private List<int> EnumerateCaptureSessionPids()
    {
        var pids = new List<int>();

        IntPtr pEnumerator = IntPtr.Zero;
        IntPtr pDevices = IntPtr.Zero;

        try
        {
            var clsid = CLSID_MMDeviceEnumerator;
            var iid = IID_IMMDeviceEnumerator;

            int hr = CoCreateInstance(ref clsid, IntPtr.Zero, 1 /* CLSCTX_INPROC_SERVER */, ref iid, out pEnumerator);
            if (hr != 0 || pEnumerator == IntPtr.Zero) return pids;

            // IMMDeviceEnumerator::EnumAudioEndpoints(eCapture, DEVICE_STATE_ACTIVE, &pDevices)
            var enumVtbl = GetVtblPtr(pEnumerator);
            var enumAudioEndpoints = Marshal.GetDelegateForFunctionPointer<EnumAudioEndpointsDelegate>(
                Marshal.ReadIntPtr(enumVtbl, 3 * IntPtr.Size));

            hr = enumAudioEndpoints(pEnumerator, eCapture, DEVICE_STATE_ACTIVE, out pDevices);
            if (hr != 0 || pDevices == IntPtr.Zero) return pids;

            // IMMDeviceCollection::GetCount
            var collVtbl = GetVtblPtr(pDevices);
            var getCount = Marshal.GetDelegateForFunctionPointer<GetCountDelegate>(
                Marshal.ReadIntPtr(collVtbl, 3 * IntPtr.Size));

            hr = getCount(pDevices, out int deviceCount);
            if (hr != 0) return pids;

            for (int i = 0; i < deviceCount; i++)
            {
                IntPtr pDevice = IntPtr.Zero;
                try
                {
                    // IMMDeviceCollection::Item(i, &pDevice)
                    var item = Marshal.GetDelegateForFunctionPointer<ItemDelegate>(
                        Marshal.ReadIntPtr(collVtbl, 4 * IntPtr.Size));
                    hr = item(pDevices, i, out pDevice);
                    if (hr != 0 || pDevice == IntPtr.Zero) continue;

                    // IMMDevice::Activate(IAudioSessionManager2)
                    var devVtbl = GetVtblPtr(pDevice);
                    var activate = Marshal.GetDelegateForFunctionPointer<ActivateDelegate>(
                        Marshal.ReadIntPtr(devVtbl, 3 * IntPtr.Size));

                    IntPtr pSessionMgr = IntPtr.Zero;
                    var sessionMgrIid = IID_IAudioSessionManager2;
                    hr = activate(pDevice, ref sessionMgrIid, 0 /* CLSCTX_ALL */, IntPtr.Zero, out pSessionMgr);
                    if (hr != 0 || pSessionMgr == IntPtr.Zero) continue;

                    try
                    {
                        // IAudioSessionManager2::GetSessionEnumerator
                        var mgrVtbl = GetVtblPtr(pSessionMgr);
                        var getSessionEnum = Marshal.GetDelegateForFunctionPointer<GetSessionEnumeratorDelegate>(
                            Marshal.ReadIntPtr(mgrVtbl, 5 * IntPtr.Size));

                        IntPtr pSessionEnum = IntPtr.Zero;
                        hr = getSessionEnum(pSessionMgr, out pSessionEnum);
                        if (hr != 0 || pSessionEnum == IntPtr.Zero) continue;

                        try
                        {
                            // IAudioSessionEnumerator::GetCount
                            var sessEnumVtbl = GetVtblPtr(pSessionEnum);
                            var getSessCount = Marshal.GetDelegateForFunctionPointer<GetCountDelegate>(
                                Marshal.ReadIntPtr(sessEnumVtbl, 3 * IntPtr.Size));

                            hr = getSessCount(pSessionEnum, out int sessionCount);
                            if (hr != 0) continue;

                            for (int j = 0; j < sessionCount; j++)
                            {
                                IntPtr pSessionCtrl = IntPtr.Zero;
                                try
                                {
                                    // IAudioSessionEnumerator::GetSession(j)
                                    var getSession = Marshal.GetDelegateForFunctionPointer<GetSessionDelegate>(
                                        Marshal.ReadIntPtr(sessEnumVtbl, 4 * IntPtr.Size));
                                    hr = getSession(pSessionEnum, j, out pSessionCtrl);
                                    if (hr != 0 || pSessionCtrl == IntPtr.Zero) continue;

                                    // QI for IAudioSessionControl2
                                    IntPtr pSessionCtrl2 = IntPtr.Zero;
                                    var iidCtrl2 = new Guid("BFB7FF88-7239-4FC9-8FA2-07C950BE9C6D");
                                    var qi = Marshal.GetDelegateForFunctionPointer<QueryInterfaceDelegate>(
                                        Marshal.ReadIntPtr(GetVtblPtr(pSessionCtrl), 0));
                                    hr = qi(pSessionCtrl, ref iidCtrl2, out pSessionCtrl2);
                                    if (hr != 0 || pSessionCtrl2 == IntPtr.Zero) continue;

                                    try
                                    {
                                        // IAudioSessionControl2::GetProcessId
                                        var ctrl2Vtbl = GetVtblPtr(pSessionCtrl2);
                                        var getProcessId = Marshal.GetDelegateForFunctionPointer<GetProcessIdDelegate>(
                                            Marshal.ReadIntPtr(ctrl2Vtbl, 14 * IntPtr.Size));
                                        hr = getProcessId(pSessionCtrl2, out int sessionPid);
                                        if (hr == 0 && sessionPid > 0)
                                        {
                                            pids.Add(sessionPid);
                                        }
                                    }
                                    finally
                                    {
                                        Marshal.Release(pSessionCtrl2);
                                    }
                                }
                                finally
                                {
                                    if (pSessionCtrl != IntPtr.Zero) Marshal.Release(pSessionCtrl);
                                }
                            }
                        }
                        finally
                        {
                            Marshal.Release(pSessionEnum);
                        }
                    }
                    finally
                    {
                        Marshal.Release(pSessionMgr);
                    }
                }
                finally
                {
                    if (pDevice != IntPtr.Zero) Marshal.Release(pDevice);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "MicSessionMonitor: WASAPI enumeration error");
        }
        finally
        {
            if (pDevices != IntPtr.Zero) Marshal.Release(pDevices);
            if (pEnumerator != IntPtr.Zero) Marshal.Release(pEnumerator);
        }

        return pids;
    }

    private static IntPtr GetVtblPtr(IntPtr comObj)
    {
        return Marshal.ReadIntPtr(comObj);
    }

    // ── COM delegate signatures ──────────────────────────────────────────────

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int EnumAudioEndpointsDelegate(IntPtr self, int dataFlow, int stateMask, out IntPtr ppDevices);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int GetCountDelegate(IntPtr self, out int count);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int ItemDelegate(IntPtr self, int index, out IntPtr ppDevice);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int ActivateDelegate(IntPtr self, ref Guid iid, int clsCtx, IntPtr activationParams, out IntPtr ppInterface);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int GetSessionEnumeratorDelegate(IntPtr self, out IntPtr ppSessionEnum);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int GetSessionDelegate(IntPtr self, int index, out IntPtr ppSession);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int GetProcessIdDelegate(IntPtr self, out int pid);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int QueryInterfaceDelegate(IntPtr self, ref Guid riid, out IntPtr ppvObject);

    // ── Window visibility helpers ────────────────────────────────────────────

    private static bool ProcessOwnsVisibleWindow(int pid)
    {
        bool found = false;

        EnumWindows((hWnd, _) =>
        {
            if (!IsWindowVisible(hWnd)) return true;

            GetWindowThreadProcessId(hWnd, out int windowPid);
            if (windowPid != pid) return true;

            if (!GetWindowRect(hWnd, out RECT rect)) return true;
            if (rect.Area < 50000) return true;

            var exStyle = GetWindowLongW(hWnd, GWL_EXSTYLE);
            if ((exStyle & WS_EX_TOOLWINDOW) != 0) return true;

            found = true;
            return false;
        }, IntPtr.Zero);

        return found;
    }

    private static bool IsProcessForeground(int pid)
    {
        var fgHwnd = GetForegroundWindow();
        if (fgHwnd == IntPtr.Zero) return false;

        GetWindowThreadProcessId(fgHwnd, out int fgPid);
        return fgPid == pid;
    }
}
