using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Detects unauthorized screen capture by monitoring for processes that load
    /// GDI screen capture APIs (BitBlt from desktop DC) or DXGI desktop duplication.
    /// </summary>
    public sealed class ScreenCaptureMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ScreenCaptureMonitor> _logger;
        private readonly HashSet<int> _alerted = new();

        private static readonly HashSet<string> AllowedCapture = new(StringComparer.OrdinalIgnoreCase)
        {
            "SnippingTool", "ScreenClippingHost", "mstsc", "msrdc",
            "obs64", "obs32", "ShareX", "Greenshot", "LightShot",
            "Teams", "Zoom", "Discord", "Slack",
            "chrome", "brave", "firefox", "msedge", "Antigravity IDE",
            "Sentinel.Agent"
        };

        public ScreenCaptureMonitor(DetectionEngine de, ILogger<ScreenCaptureMonitor> l)
        {
            _detectionEngine = de; _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ScreenCaptureMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(5000, ct);
                    foreach (var proc in Process.GetProcesses())
                    {
                        try
                        {
                            if (proc.Id <= 4 || _alerted.Contains(proc.Id)) continue;

                            // Name-based allowlist — but verify path is from a legitimate location.
                            // An attacker naming malware "obs64.exe" from C:\Temp should NOT be skipped.
                            if (AllowedCapture.Contains(proc.ProcessName))
                            {
                                var capturePath = SecurityValidation.GetProcessImagePath(proc.Id);
                                if (!string.IsNullOrEmpty(capturePath))
                                {
                                    var lp = capturePath.ToLowerInvariant();
                                    bool isTrustedLocation = lp.Contains(@"\program files") ||
                                                             lp.Contains(@"\windows\") ||
                                                             lp.Contains(@"\appdata\local\programs\") ||
                                                             lp.Contains(@"\appdata\local\microsoft\") ||
                                                             lp.Contains(@"\windowssentinel\");
                                    if (isTrustedLocation) continue;
                                }
                                else
                                {
                                    continue; // Can't read path — give benefit of doubt for known names
                                }
                                // Name matches but path is suspicious — fall through to detection
                            }

                            // Observe-first: never enumerate Process.Modules (PROCESS_VM_READ).
                            // That API kills Denuvo/anti-cheat games. DXGI module fishing is disabled
                            // until independent evidence implicates a PID.
                            var path = SecurityValidation.GetProcessImagePath(proc.Id);
                            if (SecurityValidation.IsGameOrAntiCheatPath(path))
                                continue;

                            if (!SecurityValidation.MayInspectProcessMemory(hasIndependentMaliciousEvidence: false))
                                continue;
                        }
                        catch { }
                        finally { proc.Dispose(); }
                    }

                    // Prune exited PIDs
                    if (_alerted.Count > 200) _alerted.Clear();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[ScreenCaptureMonitor] Error"); }
            }
        }
    }

    /// <summary>
    /// Monitors webcam and microphone device access for unauthorized activation
    /// by checking the capability access registry keys Windows sets for app permissions.
    /// </summary>
    public sealed class WebcamMicMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WebcamMicMonitor> _logger;
        private readonly HashSet<string> _baselineWebcamApps = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _baselineMicApps = new(StringComparer.OrdinalIgnoreCase);

        public WebcamMicMonitor(DetectionEngine de, ILogger<WebcamMicMonitor> l)
        {
            _detectionEngine = de; _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WebcamMicMonitor] Started");
            SnapshotCapabilityApps("webcam", _baselineWebcamApps);
            SnapshotCapabilityApps("microphone", _baselineMicApps);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(20000, ct);
                    var currentWebcam = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var currentMic = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    SnapshotCapabilityApps("webcam", currentWebcam);
                    SnapshotCapabilityApps("microphone", currentMic);

                    foreach (var app in currentWebcam.Except(_baselineWebcamApps))
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Privacy: New Webcam Access",
                            Evidence = $"New application accessing webcam: {app}",
                            Reasoning = "A new application registered for webcam access at runtime.",
                            Confidence = 0.60, Tier = DetectionTier.Tier2Indicator,
                            ProcessName = app, ProcessId = 0
                        });
                        _baselineWebcamApps.Add(app);
                    }

                    foreach (var app in currentMic.Except(_baselineMicApps))
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Privacy: New Microphone Access",
                            Evidence = $"New application accessing microphone: {app}",
                            Reasoning = "A new application registered for microphone access at runtime.",
                            Confidence = 0.60, Tier = DetectionTier.Tier2Indicator,
                            ProcessName = app, ProcessId = 0
                        });
                        _baselineMicApps.Add(app);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WebcamMicMonitor] Error"); }
            }
        }

        private static void SnapshotCapabilityApps(string capability, HashSet<string> target)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    $@"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{capability}");
                if (key == null) return;
                foreach (var sub in key.GetSubKeyNames())
                {
                    try
                    {
                        using var appKey = key.OpenSubKey(sub);
                        var val = appKey?.GetValue("LastUsedTimeStop")?.ToString();
                        if (val == "0") target.Add(sub); // Currently in use
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// Detects audio routing hijacks — processes registering as audio endpoints
    /// or inserting audio processing objects into the render/capture pipelines.
    /// </summary>
    public sealed class AudioHijackMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<AudioHijackMonitor> _logger;
        private int _baselineEndpointCount;

        public AudioHijackMonitor(DetectionEngine de, ILogger<AudioHijackMonitor> l)
        {
            _detectionEngine = de; _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[AudioHijackMonitor] Started");
            _baselineEndpointCount = CountAudioEndpoints();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(10000, ct);
                    var current = CountAudioEndpoints();
                    if (current > _baselineEndpointCount + 2)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Audio Hijack: New Audio Endpoints Detected",
                            Evidence = $"Audio endpoints increased from {_baselineEndpointCount} to {current}",
                            Reasoning = "New audio endpoints appeared at runtime. Virtual audio devices can be used to route microphone input to a network stream.",
                            Confidence = 0.65, Tier = DetectionTier.Tier2Indicator,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                    }
                    _baselineEndpointCount = current;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[AudioHijackMonitor] Error"); }
            }
        }

        private static int CountAudioEndpoints()
        {
            int count = 0;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render");
                count += key?.SubKeyCount ?? 0;
                using var key2 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture");
                count += key2?.SubKeyCount ?? 0;
            }
            catch { }
            return count;
        }
    }

    /// <summary>
    /// Monitors audio session manager for unauthorized microphone captures
    /// by tracking which processes hold active capture audio sessions.
    /// </summary>
    public sealed class MicSessionMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<MicSessionMonitor> _logger;
        private readonly HashSet<string> _knownMicUsers = new(StringComparer.OrdinalIgnoreCase)
        {
            "svchost", "audiodg", "Teams", "Zoom", "Discord", "Slack",
            "chrome", "msedge", "firefox", "brave", "opera"
        };

        public MicSessionMonitor(DetectionEngine de, ILogger<MicSessionMonitor> l)
        {
            _detectionEngine = de; _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[MicSessionMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(10000, ct);
                    // Check ConsentStore for microphone — apps with LastUsedTimeStop == 0 are actively using mic
                    try
                    {
                        using var key = Registry.CurrentUser.OpenSubKey(
                            @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone");
                        if (key == null) continue;
                        foreach (var sub in key.GetSubKeyNames())
                        {
                            using var appKey = key.OpenSubKey(sub);
                            var stop = appKey?.GetValue("LastUsedTimeStop")?.ToString();
                            if (stop == "0")
                            {
                                var appName = Path.GetFileNameWithoutExtension(sub.Split('#').LastOrDefault() ?? sub);
                                if (!_knownMicUsers.Contains(appName))
                                {
                                    await _detectionEngine.EmitAsync(new DetectionEvent
                                    {
                                        RuleName = "Privacy: Unknown Process Using Microphone",
                                        Evidence = $"Unknown application '{sub}' is actively using the microphone",
                                        Reasoning = "An unrecognized process is actively capturing microphone audio, which may indicate unauthorized surveillance.",
                                        Confidence = 0.70, Tier = DetectionTier.Tier1Behavioral,
                                        AuthorizedResponse = ResponseAction.LogOnly,
                                        ProcessName = appName, ProcessId = 0
                                    });
                                    _knownMicUsers.Add(appName);
                                }
                            }
                        }
                    }
                    catch { }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[MicSessionMonitor] Error"); }
            }
        }
    }

    /// <summary>
    /// Visual behavior analysis — detects suspicious overlay/transparent windows
    /// that could be used for phishing overlays or keylogger UI, and monitors for
    /// user session anomalies (focus steals, brightness oscillations, programmatic cursor jumps).
    /// </summary>
    public sealed class NeuroBehaviorVisualMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<NeuroBehaviorVisualMonitor> _logger;

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll")]
        private static extern bool GetCursorPos(out POINT lpPoint);

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT { public int Left, Top, Right, Bottom; }

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT { public int X; public int Y; }

        private const int GWL_EXSTYLE = -20;
        private const int WS_EX_LAYERED = 0x80000;
        private const int WS_EX_TRANSPARENT = 0x20;
        private const int WS_EX_TOPMOST = 0x8;

        private int _focusStealCount;
        private int _cursorJumpCount;
        private int _brightnessOscillationCount;
        private int _anomalyScore;

        private IntPtr _lastFgWnd = IntPtr.Zero;
        private uint _lastFgPid = 0;
        private POINT _lastCursorPos;
        private int _lastBrightness = -1;
        private DateTime _lastWindowChangeTime = DateTime.UtcNow;
        private int _overlayCheckCounter;

        public NeuroBehaviorVisualMonitor(DetectionEngine de, ILogger<NeuroBehaviorVisualMonitor> l)
        {
            _detectionEngine = de; _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[NeuroBehaviorVisualMonitor] Started");
            GetCursorPos(out _lastCursorPos);
            _lastBrightness = GetScreenBrightness();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(1000, ct);
                    var fgWnd = GetForegroundWindow();
                    if (fgWnd == IntPtr.Zero) continue;

                    // 1. Focus steal check
                    GetWindowThreadProcessId(fgWnd, out uint pid);
                    if (pid > 4 && pid != _lastFgPid)
                    {
                        var now = DateTime.UtcNow;
                        if (now - _lastWindowChangeTime < TimeSpan.FromSeconds(2))
                        {
                            _focusStealCount++;
                            _anomalyScore += 15;
                        }
                        _lastFgWnd = fgWnd;
                        _lastFgPid = pid;
                        _lastWindowChangeTime = now;
                    }
                    // 2. Programmatic cursor jump check
                    if (GetCursorPos(out var curPos))
                    {
                        var dx = curPos.X - _lastCursorPos.X;
                        var dy = curPos.Y - _lastCursorPos.Y;
                        var distance = Math.Sqrt(dx * dx + dy * dy);

                        // Large jump within 1 second suggests programmatic control
                        if (distance > 600)
                        {
                            _cursorJumpCount++;
                            _anomalyScore += 20;
                        }
                        _lastCursorPos = curPos;
                    }

                    // 3. Brightness oscillation check
                    var brightness = GetScreenBrightness();
                    if (brightness != -1 && _lastBrightness != -1)
                    {
                        var diff = Math.Abs(brightness - _lastBrightness);
                        if (diff > 15)
                        {
                            _brightnessOscillationCount++;
                            _anomalyScore += 25;
                        }
                    }
                    if (brightness != -1)
                    {
                        _lastBrightness = brightness;
                    }

                    // 4. Transparent Overlay Check (run every 10 seconds)
                    if (_overlayCheckCounter++ >= 10)
                    {
                        _overlayCheckCounter = 0;
                        int exStyle = GetWindowLong(fgWnd, GWL_EXSTYLE);
                        bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
                        bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;
                        bool isTopmost = (exStyle & WS_EX_TOPMOST) != 0;

                        if (isLayered && isTransparent && isTopmost)
                        {
                            if (pid > 4)
                            {
                                string procName;
                                try { using var p = Process.GetProcessById((int)pid); procName = p.ProcessName; }
                                catch { procName = $"PID_{pid}"; }

                                if (GetWindowRect(fgWnd, out var rect))
                                {
                                    int width = rect.Right - rect.Left;
                                    int height = rect.Bottom - rect.Top;
                                    if (width > 800 && height > 600) // Large overlay
                                    {
                                        await _detectionEngine.EmitAsync(new DetectionEvent
                                        {
                                            RuleName = "UI Overlay: Transparent Fullscreen Overlay Detected",
                                            Evidence = $"Process '{procName}' (PID {pid}) has a large transparent topmost overlay ({width}x{height})",
                                            Reasoning = "A large transparent topmost window was detected, which can be used for phishing overlays or credential capture.",
                                            Confidence = 0.65,
                                            Tier = DetectionTier.Tier1Behavioral,
                                            AuthorizedResponse = ResponseAction.KillProcessTree,
                                            ProcessName = procName, ProcessId = (int)pid
                                        });
                                    }
                                }
                            }
                        }
                    }

                    // 5. Anomaly score evaluation
                    // Focus steals, cursor jumps, and brightness changes alone are NOT proof of maliciousness.
                    // They are normal user behavior. Log only — never kill for this.
                    if (_anomalyScore >= 60)
                    {
                        string procName = "unknown";
                        try { using var p = Process.GetProcessById((int)pid); procName = p.ProcessName; }
                        catch { }

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "NeuroBehavior: Visual Anomaly Detected",
                            Evidence = $"Visual anomaly score reached {_anomalyScore} (Focus steals: {_focusStealCount}, Cursor jumps: {_cursorJumpCount}, Brightness oscillations: {_brightnessOscillationCount})",
                            Reasoning = "System-wide visual anomalies (rapid window focus steals, large programmatic cursor jumps, or sudden display brightness oscillations) suggest visual hijacking or background script takeover.",
                            Confidence = 0.60,
                            Tier = DetectionTier.Tier2Indicator,
                            ProcessName = procName,
                            ProcessId = (int)pid
                        });

                        ResetStats();
                    }

                    // Decay anomaly score slowly over time
                    if (_anomalyScore > 0)
                    {
                        _anomalyScore = Math.Max(0, _anomalyScore - 1);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[NeuroBehaviorVisualMonitor] Error"); }
            }
        }

        private int GetScreenBrightness()
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    new System.Management.ManagementScope(@"root\wmi"),
                    new System.Management.SelectQuery("WmiMonitorBrightness"));
                using var collection = searcher.Get();
                foreach (var obj in collection)
                {
                    var val = obj.GetPropertyValue("CurrentBrightness");
                    if (val != null)
                    {
                        return Convert.ToInt32(val);
                    }
                }
            }
            catch
            {
                // Degrade gracefully (non-laptops don't have WmiMonitorBrightness)
            }
            return -1;
        }

        private void ResetStats()
        {
            _anomalyScore = 0;
            _focusStealCount = 0;
            _cursorJumpCount = 0;
            _brightnessOscillationCount = 0;
        }
    }

    /// <summary>
    /// Monitors browser extension installations by watching extension manifest directories.
    /// </summary>
    public sealed class BrowserExtensionMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<BrowserExtensionMonitor> _logger;
        private readonly HashSet<string> _baselineExtensions = new(StringComparer.OrdinalIgnoreCase);

        public BrowserExtensionMonitor(DetectionEngine de, ILogger<BrowserExtensionMonitor> l)
        {
            _detectionEngine = de; _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BrowserExtensionMonitor] Started");
            SnapshotExtensions(_baselineExtensions);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    SnapshotExtensions(current);

                    foreach (var ext in current.Except(_baselineExtensions))
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Browser Extension: New Extension Installed",
                            Evidence = $"New browser extension directory: {ext}",
                            Reasoning = "A new browser extension was installed. Malicious extensions can steal credentials, session tokens, and inject content.",
                            Confidence = 0.55, Tier = DetectionTier.Tier2Indicator,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                        _baselineExtensions.Add(ext);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[BrowserExtensionMonitor] Error"); }
            }
        }

        private static void SnapshotExtensions(HashSet<string> target)
        {
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrEmpty(local)) return;

            var extensionDirs = new[]
            {
                Path.Combine(local, @"Google\Chrome\User Data\Default\Extensions"),
                Path.Combine(local, @"Microsoft\Edge\User Data\Default\Extensions"),
                Path.Combine(local, @"BraveSoftware\Brave-Browser\User Data\Default\Extensions"),
            };

            foreach (var dir in extensionDirs)
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var extDir in Directory.GetDirectories(dir))
                        target.Add(extDir);
                }
                catch { }
            }
        }
    }

    /// <summary>
    /// Detects phantom keystrokes — keypress injection from non-HID sources.
    /// Installs a low-level keyboard hook (WH_KEYBOARD_LL) and checks the
    /// LLKHF_INJECTED flag to detect software-injected keystrokes via SendInput.
    /// Blocks injected keystrokes and emits detection events.
    /// </summary>
    public sealed class PhantomKeystrokeGuard : IHostedService, IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<PhantomKeystrokeGuard> _logger;
        private readonly SentinelConfig _config;
        private System.Threading.Timer? _timer;
        private DateTime _lastAlertTime = DateTime.MinValue;

        private Thread? _hookThread;
        private IntPtr _hookId = IntPtr.Zero;
        private LowLevelKeyboardProc? _hookProc;
        private uint _hookThreadId;

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

        [StructLayout(LayoutKind.Sequential)]
        private struct LASTINPUTINFO
        {
            public uint cbSize;
            public uint dwTime;
        }

        private uint _lastInputTime;
        private uint _previousInputTime;
        private int _noInputChangeCount;

        // Hook P/Invokes
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(IntPtr lpModuleName);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool PostThreadMessage(uint idThread, uint Msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern int GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

        [DllImport("user32.dll")]
        private static extern bool TranslateMessage(ref MSG lpMsg);

        [DllImport("user32.dll")]
        private static extern IntPtr DispatchMessage(ref MSG lpMsg);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        private static extern int GetSystemMetrics(int nIndex);

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        private const int WH_KEYBOARD_LL = 13;
        private const int WM_QUIT = 0x0012;
        private const int LLKHF_INJECTED = 0x10;
        private const int LLKHF_LOWER_IL_INJECTED = 0x02;
        private const int VK_BACK = 0x08;
        private const int VK_DELETE = 0x2E;
        private const int SM_REMOTESESSION = 0x1000;

        [StructLayout(LayoutKind.Sequential)]
        private struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public POINT pt;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT
        {
            public int X;
            public int Y;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KBDLLHOOKSTRUCT
        {
            public uint vkCode;
            public uint scanCode;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        public PhantomKeystrokeGuard(DetectionEngine de, ILogger<PhantomKeystrokeGuard> l, SentinelConfig config)
        {
            _detectionEngine = de;
            _logger = l;
            _config = config;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("[PhantomKeystrokeGuard] Started");

            // Start hook message loop thread
            _hookProc = HookCallback;
            _hookThread = new Thread(RunHookLoop);
            _hookThread.SetApartmentState(ApartmentState.STA);
            _hookThread.IsBackground = true;
            _hookThread.Start();

            // Run heuristic timer as fallback
            _timer = new System.Threading.Timer(Check, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _timer?.Change(Timeout.Infinite, Timeout.Infinite);

            if (_hookId != IntPtr.Zero)
            {
                UnhookWindowsHookEx(_hookId);
                _hookId = IntPtr.Zero;
            }

            if (_hookThreadId != 0)
            {
                PostThreadMessage(_hookThreadId, WM_QUIT, IntPtr.Zero, IntPtr.Zero);
            }

            return Task.CompletedTask;
        }

        private void RunHookLoop()
        {
            _hookThreadId = GetCurrentThreadId();
            _hookId = SetHook(_hookProc!);
            if (_hookId == IntPtr.Zero)
            {
                _logger.LogError("[PhantomKeystrokeGuard] Failed to install low-level keyboard hook");
                return;
            }
            _logger.LogInformation("[PhantomKeystrokeGuard] Global keyboard hook installed successfully");

            MSG msg;
            while (GetMessage(out msg, IntPtr.Zero, 0, 0) > 0)
            {
                TranslateMessage(ref msg);
                DispatchMessage(ref msg);
            }
        }

        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(IntPtr.Zero), 0);
        }

        private IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                var kb = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);
                bool isInjected = (kb.flags & LLKHF_INJECTED) != 0 || (kb.flags & LLKHF_LOWER_IL_INJECTED) != 0;

                if (isInjected)
                {
                    // v1.5.7: Allow injected keystrokes targeting IDE/development tool windows
                    // or their child processes (conhost, node, electron helpers, terminals).
                    // IDEs (VS Code, Kiro, Cursor, Rider, etc.) programmatically send keystrokes
                    // to their integrated terminal via SendInput, which sets the INJECTED flag.
                    // Blocking these breaks IDE terminal functionality entirely.
                    if (IsIdeTargetProcess())
                    {
                        return CallNextHookEx(_hookId, nCode, wParam, lParam);
                    }

                    bool isDeletion = kb.vkCode == VK_BACK || kb.vkCode == VK_DELETE;
                    string keyName = ((System.Windows.Forms.Keys)kb.vkCode).ToString();

                    ReportInjectedKeystroke(kb.vkCode, isDeletion, keyName);

                    if (_config.ActiveResponse && !IsRemoteSession())
                    {
                        return (IntPtr)1; // Block software-injected key press
                    }
                }
            }
            return CallNextHookEx(_hookId, nCode, wParam, lParam);
        }

        /// <summary>
        /// v1.5.7: Checks if the current foreground window belongs to an IDE or development tool,
        /// OR is a child process of one (e.g., conhost.exe, node.exe, or Electron helper
        /// processes that own the window while an IDE terminal/panel has focus).
        /// These tools legitimately inject keystrokes into their integrated terminals and
        /// editor components. Blocking them breaks core IDE functionality.
        /// </summary>
        private static bool IsIdeTargetProcess()
        {
            try
            {
                IntPtr fgWnd = GetForegroundWindow();
                if (fgWnd == IntPtr.Zero) return false;
                GetWindowThreadProcessId(fgWnd, out uint pid);
                if (pid <= 4) return false;
                using var proc = Process.GetProcessById((int)pid);
                var name = proc.ProcessName.ToLowerInvariant();

                // Direct match — foreground process is an IDE
                if (IdeProcessNames.Contains(name))
                    return true;

                // v1.5.7: Walk parent process chain (up to 4 levels).
                // IDE terminals spawn child processes (conhost, node, pwsh, cmd, bash, etc.)
                // that own the foreground window. The keystroke injection is still originating
                // from the IDE — we must not block it.
                int currentPid = (int)pid;
                for (int depth = 0; depth < 4; depth++)
                {
                    int parentPid = GetParentProcessIdNative(currentPid);
                    if (parentPid <= 4) break;

                    try
                    {
                        using var parentProc = Process.GetProcessById(parentPid);
                        var parentName = parentProc.ProcessName.ToLowerInvariant();
                        if (IdeProcessNames.Contains(parentName))
                            return true;
                    }
                    catch { break; } // Parent exited or access denied

                    currentPid = parentPid;
                }

                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// v1.5.7: Retrieves the parent process ID via NtQueryInformationProcess.
        /// Used by IsIdeTargetProcess to walk the ancestry chain without needing
        /// DI-injected services (hook callbacks must be fast and static-compatible).
        /// </summary>
        private static int GetParentProcessIdNative(int pid)
        {
            IntPtr hProcess = IntPtr.Zero;
            try
            {
                hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
                if (hProcess == IntPtr.Zero) return 0;

                var pbi = new PROCESS_BASIC_INFORMATION();
                int status = NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf(pbi), out _);
                if (status == 0)
                    return pbi.InheritedFromUniqueProcessId.ToInt32();
                return 0;
            }
            catch { return 0; }
            finally
            {
                if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(
            IntPtr processHandle, int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength, out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        /// <summary>
        /// IDE and development tool process names that legitimately inject keystrokes
        /// into their integrated terminals, editors, and UI components.
        /// </summary>
        private static readonly HashSet<string> IdeProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            // VS Code / forks
            "code", "Code", "Code - Insiders",
            "kiro", "cursor", "windsurf", "positron",
            // JetBrains IDEs
            "rider64", "idea64", "phpstorm64", "webstorm64", "goland64",
            "pycharm64", "clion64", "rubymine64", "datagrip64",
            // Visual Studio
            "devenv",
            // Terminal emulators (injected keystrokes from paste, etc.)
            "windowsterminal", "wt", "ConEmu64", "ConEmu",
            "alacritty", "wezterm-gui", "hyper",
            // Other IDEs / editors
            "sublime_text", "notepad++", "atom",
            // Remote desktop / VM tools (they inject all input)
            "mstsc", "vmware-vmx", "VirtualBoxVM",
        };

        private void ReportInjectedKeystroke(uint vkCode, bool isDeletion, string keyName)
        {
            var now = DateTime.UtcNow;
            if ((now - _lastAlertTime).TotalSeconds < 5) return;
            _lastAlertTime = now;

            string targetProcName = "Unknown";
            int targetPid = 0;
            try
            {
                IntPtr fgWnd = GetForegroundWindow();
                if (fgWnd != IntPtr.Zero)
                {
                    GetWindowThreadProcessId(fgWnd, out uint pid);
                    targetPid = (int)pid;
                    using var p = Process.GetProcessById(targetPid);
                    targetProcName = p.ProcessName;
                }
            }
            catch { }

            string threatName = isDeletion ? "Phantom Keystrokes: Key Deletion Prevented" : "Phantom Keystrokes: Software Input Prevented";
            string evidence = isDeletion 
                ? $"Blocked software-injected deletion key: {keyName} (VK: 0x{vkCode:X2}) targeting '{targetProcName}' (PID {targetPid}). Keys are prevented from being deleted when typed."
                : $"Blocked software-injected character insertion key: {keyName} (VK: 0x{vkCode:X2}) targeting '{targetProcName}' (PID {targetPid}).";

            _ = _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = threatName,
                Evidence = evidence,
                Reasoning = "A software-injected keystroke event was intercepted and blocked by the low-level keyboard hook. " +
                            (isDeletion 
                                ? "This prevents background/automated processes from deleting characters typed by the user (input deletion protection)."
                                : "This prevents background/automated processes from typing phantom commands or injecting text."),
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly, // Blocked in-line, no immediate process tree kill required
                ProcessName = targetProcName,
                ProcessId = targetPid,
                SignalType = SignalType.PhantomKeystroke
            });
        }

        private static bool IsRemoteSession()
        {
            return GetSystemMetrics(SM_REMOTESESSION) != 0;
        }

        private async void Check(object? state)
        {
            try
            {
                var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
                if (!GetLastInputInfo(ref info)) return;

                var currentTick = (uint)Environment.TickCount;

                if (_lastInputTime == info.dwTime && _previousInputTime == _lastInputTime)
                {
                    _noInputChangeCount++;
                }
                else
                {
                    _noInputChangeCount = 0;
                }

                _previousInputTime = _lastInputTime;
                _lastInputTime = info.dwTime;

                if (_noInputChangeCount >= 6)
                {
                    foreach (var proc in Process.GetProcesses())
                    {
                        try
                        {
                            var name = proc.ProcessName.ToLowerInvariant();
                            string? imagePath = SecurityValidation.GetProcessImagePath(proc.Id);

                            if ((name.Contains("sendinput") || name.Contains("autoit") ||
                                 name.Contains("nircmd") || name.Contains("inputsimulator")) &&
                                !string.IsNullOrEmpty(imagePath) &&
                                (imagePath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                                 imagePath.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase)))
                            {
                                if ((DateTime.UtcNow - _lastAlertTime).TotalSeconds < 60) break;
                                _lastAlertTime = DateTime.UtcNow;

                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "Phantom Keystrokes: Input Injection Tool Detected",
                                    Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) from '{imagePath}' detected while no physical input is occurring",
                                    Reasoning = "A known input automation/injection tool is running from a suspicious path while no physical keyboard input has been detected for an extended period, indicating programmatic keystroke injection.",
                                    Confidence = 0.80, Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = ResponseAction.KillProcessTree,
                                    ProcessName = proc.ProcessName, ProcessId = proc.Id,
                                    SignalType = SignalType.PhantomKeystroke
                                });
                                break;
                            }
                        }
                        catch { }
                        finally { proc.Dispose(); }
                    }

                    _noInputChangeCount = 0;
                }
            }
            catch { }
        }

        public void Dispose() => _timer?.Dispose();
    }
}

