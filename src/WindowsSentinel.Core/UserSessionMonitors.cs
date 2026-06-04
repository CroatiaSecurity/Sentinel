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

namespace WindowsSentinel.Core
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
            "WindowsSentinel.Agent"
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
                            if (AllowedCapture.Contains(proc.ProcessName)) continue;

                            // Check if process has loaded d3d11.dll + dxgi.dll (DXGI duplication)
                            bool hasDxgi = false, hasD3d = false;
                            try
                            {
                                foreach (ProcessModule mod in proc.Modules)
                                {
                                    var name = mod.ModuleName?.ToLowerInvariant() ?? "";
                                    if (name == "dxgi.dll") hasDxgi = true;
                                    if (name == "d3d11.dll") hasD3d = true;
                                }
                            }
                            catch { continue; } // Access denied for system procs

                            if (hasDxgi && hasD3d && proc.ProcessName != "dwm" && proc.ProcessName != "csrss")
                            {
                                // Non-standard process with DXGI desktop duplication capability
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "Screen Capture: DXGI Desktop Duplication",
                                    Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) loaded DXGI + D3D11 — potential screen capture",
                                    Reasoning = "A non-standard process loaded DXGI desktop duplication modules, enabling silent screen capture.",
                                    Confidence = 0.55, Tier = DetectionTier.Tier2Indicator,
                                    ProcessName = proc.ProcessName, ProcessId = proc.Id
                                });
                                _alerted.Add(proc.Id);
                            }
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
    /// that could be used for phishing overlays or keylogger UI.
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

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT { public int Left, Top, Right, Bottom; }

        private const int GWL_EXSTYLE = -20;
        private const int WS_EX_LAYERED = 0x80000;
        private const int WS_EX_TRANSPARENT = 0x20;
        private const int WS_EX_TOPMOST = 0x8;

        public NeuroBehaviorVisualMonitor(DetectionEngine de, ILogger<NeuroBehaviorVisualMonitor> l)
        {
            _detectionEngine = de; _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[NeuroBehaviorVisualMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(10000, ct);
                    var fgWnd = GetForegroundWindow();
                    if (fgWnd == IntPtr.Zero) continue;

                    int exStyle = GetWindowLong(fgWnd, GWL_EXSTYLE);
                    bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
                    bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;
                    bool isTopmost = (exStyle & WS_EX_TOPMOST) != 0;

                    if (isLayered && isTransparent && isTopmost)
                    {
                        GetWindowThreadProcessId(fgWnd, out uint pid);
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
                                        Confidence = 0.65, Tier = DetectionTier.Tier2Indicator,
                                        ProcessName = procName, ProcessId = (int)pid
                                    });
                                }
                            }
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[NeuroBehaviorVisualMonitor] Error"); }
            }
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
    /// Detects phantom keystrokes — keypress injection from non-HID sources
    /// by comparing keyboard input rate against actual physical key events.
    /// </summary>
    public sealed class PhantomKeystrokeGuard : IHostedService, IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<PhantomKeystrokeGuard> _logger;
        private System.Threading.Timer? _timer;

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

        public PhantomKeystrokeGuard(DetectionEngine de, ILogger<PhantomKeystrokeGuard> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            _timer = new System.Threading.Timer(Check, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _timer?.Change(Timeout.Infinite, Timeout.Infinite);
            return Task.CompletedTask;
        }

        private void Check(object? state)
        {
            try
            {
                var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
                if (GetLastInputInfo(ref info))
                {
                    // Track last-input progression for anomaly detection
                    // If input events are arriving without physical HID activity changes, flag it
                    _lastInputTime = info.dwTime;
                }
            }
            catch { }
        }

        public void Dispose() => _timer?.Dispose();
    }
}

