using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Text.Json;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Sentinel.Core;

namespace Sentinel.Agent
{
    public class TrayIconService : IHostedService, IDisposable
    {
        private readonly SentinelConfig _config;
        private NotifyIcon? _notifyIcon;
        private ContextMenuStrip? _contextMenu;
        private Thread? _uiThread;
        private readonly CancellationTokenSource _cts = new();
        private readonly string _version;
        private (string RuleName, string ProcessName, double Confidence, string Evidence)? _pendingDetection;

        public TrayIconService(SentinelConfig config)
        {
            _config = config;
            _version = LoadVersion();
        }

        private static string LoadVersion()
        {
            // 1. Try version.txt next to the executable (single source of truth)
            var exeDir = AppContext.BaseDirectory;
            var versionFile = Path.Combine(exeDir, "version.txt");
            if (File.Exists(versionFile))
            {
                var text = File.ReadAllText(versionFile).Trim();
                if (!string.IsNullOrEmpty(text)) return text;
            }

            // 2. Fallback to assembly version
            return typeof(TrayIconService).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            _uiThread = new Thread(RunUiThread);
            _uiThread.SetApartmentState(ApartmentState.STA);
            _uiThread.Start();
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _cts.Cancel();
            if (_notifyIcon != null)
            {
                _notifyIcon.Visible = false;
                _notifyIcon.Dispose();
            }
            Application.Exit();
            return Task.CompletedTask;
        }

        private void RunUiThread()
        {
            _contextMenu = new ContextMenuStrip();
            _contextMenu.Items.Add("Open Console", null, OnOpenConsole);
            _contextMenu.Items.Add("Open Quarantine Folder", null, OnOpenQuarantine);
            _contextMenu.Items.Add("Open Event Log", null, OnOpenEventLog);
            _contextMenu.Items.Add(new ToolStripSeparator());
            // SECURITY v1.4.4: Removed "Stop Protection" toggle. Previously, any user-level
            // process could automate this menu item to disable ActiveResponse — blinding all
            // Agent-side detection responses without elevation. The Service (running as SYSTEM)
            // is now the sole authority on response mode. Users who need to disable protection
            // must stop the Sentinel service via an elevated command prompt.
            _contextMenu.Items.Add("Exit Agent", null, OnExit);

            System.Drawing.Icon? appIcon = null;
            try
            {
                // Primary: load the deployed Sentinel.ico from the application directory
                var icoPath = Path.Combine(AppContext.BaseDirectory, "Sentinel.ico");
                if (File.Exists(icoPath))
                {
                    appIcon = new System.Drawing.Icon(icoPath);
                }
                else
                {
                    // Fallback: extract the icon embedded in the exe via ApplicationIcon
                    appIcon = System.Drawing.Icon.ExtractAssociatedIcon(Application.ExecutablePath);
                }
            }
            catch { }

            _notifyIcon = new NotifyIcon
            {
                Icon = appIcon ?? System.Drawing.SystemIcons.Shield,
                ContextMenuStrip = _contextMenu,
                Text = $"Sentinel v{_version} — Protection Active",
                Visible = true
            };

            _notifyIcon.DoubleClick += OnOpenConsole;

            // Start watching log file for new detections on a background thread.
            // Must NOT use fire-and-forget async on the STA pump — async continuations
            // would be posted to the WinForms sync context and starve the message loop.
            var watchThread = new Thread(() => WatchLogFileSync(_cts.Token))
            {
                IsBackground = true,
                Name = "SentinelLogWatcher"
            };
            watchThread.Start();

            Application.Run(new HiddenForm(_notifyIcon));
        }

        private class HiddenForm : Form
        {
            private readonly NotifyIcon _notifyIcon;
            private readonly int _taskbarCreatedMsg;

            [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            private static extern int RegisterWindowMessage(string lpString);

            public HiddenForm(NotifyIcon notifyIcon)
            {
                _notifyIcon = notifyIcon;
                _taskbarCreatedMsg = RegisterWindowMessage("TaskbarCreated");

                // Hidden window configuration
                this.ShowInTaskbar = false;
                this.WindowState = FormWindowState.Minimized;

                // Force creation of the window handle so it can receive messages
                var _ = this.Handle;
            }

            protected override void WndProc(ref Message m)
            {
                if (m.Msg == _taskbarCreatedMsg)
                {
                    try
                    {
                        // Explorer restarted, recreate notify icon
                        _notifyIcon.Visible = false;
                        _notifyIcon.Visible = true;
                    }
                    catch { }
                }
                base.WndProc(ref m);
            }
        }

        private void OnOpenConsole(object? sender, EventArgs e)
        {
            // v1.6.0: No cmd.exe / powershell LOLBin — open log in notepad (same as event log).
            OnOpenEventLog(sender, e);
        }

        private void OnOpenQuarantine(object? sender, EventArgs e)
        {
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var qDir = Path.Combine(programData, "Sentinel", "Quarantine");
                if (Directory.Exists(qDir))
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "explorer.exe",
                        UseShellExecute = false,
                        ArgumentList = { qDir }
                    };
                    Process.Start(psi);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open quarantine: {ex.Message}");
            }
        }

        private void OnOpenEventLog(object? sender, EventArgs e)
        {
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var logFile = Path.Combine(programData, "Sentinel", "events.jsonl");
                if (File.Exists(logFile))
                {
                    // v1.6.0: ArgumentList avoids shell metacharacter injection; no cmd/powershell
                    var psi = new ProcessStartInfo
                    {
                        FileName = "notepad.exe",
                        UseShellExecute = false,
                        ArgumentList = { logFile }
                    };
                    Process.Start(psi);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open event log: {ex.Message}");
            }
        }

        private void OnExit(object? sender, EventArgs e)
        {
            Application.Exit();
        }

        public void Dispose()
        {
            _notifyIcon?.Dispose();
            _contextMenu?.Dispose();
            _cts.Dispose();
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Synchronous log watcher running on a dedicated background thread.
        /// Never touches the STA message pump. Uses only blocking I/O.
        /// </summary>
        private void WatchLogFileSync(CancellationToken cancellationToken)
        {
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var logFile = Path.Combine(programData, "Sentinel", "events.jsonl");

            // Wait for log file to exist
            while (!File.Exists(logFile) && !cancellationToken.IsCancellationRequested)
            {
                Thread.Sleep(1000);
            }

            long lastOffset = 0;
            try
            {
                if (File.Exists(logFile))
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete);
                    lastOffset = fs.Length;
                }
            }
            catch { }

            var rateLimiter = new RateLimiter(3, TimeSpan.FromSeconds(5));
            var shownCache = new System.Collections.Generic.Dictionary<string, DateTime>();

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // Clean up shownCache occasionally
                    var now = DateTime.UtcNow;
                    var keysToRemove = new System.Collections.Generic.List<string>();
                    foreach (var kvp in shownCache)
                    {
                        if (now - kvp.Value > TimeSpan.FromSeconds(30))
                            keysToRemove.Add(kvp.Key);
                    }
                    foreach (var k in keysToRemove)
                        shownCache.Remove(k);

                    if (File.Exists(logFile))
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read,
                            FileShare.ReadWrite | FileShare.Delete);
                        if (fs.Length < lastOffset)
                            lastOffset = 0;

                        if (fs.Length > lastOffset)
                        {
                            fs.Seek(lastOffset, SeekOrigin.Begin);
                            using var reader = new StreamReader(fs, System.Text.Encoding.UTF8, false, 4096, true);
                            string? line;
                            while ((line = reader.ReadLine()) != null)
                            {
                                if (line.Contains("\"type\":\"detection\"", StringComparison.OrdinalIgnoreCase))
                                {
                                    try
                                    {
                                        using var doc = JsonDocument.Parse(line);
                                        var data = doc.RootElement.GetProperty("data");
                                        var ruleName = data.GetProperty("RuleName").GetString() ?? "Threat Detected";
                                        var processName = data.GetProperty("ProcessName").GetString() ?? "unknown";
                                        var confidence = data.GetProperty("Confidence").GetDouble();
                                        var evidence = data.GetProperty("Evidence").GetString() ?? "";

                                        int tierVal = 1;
                                        if (data.TryGetProperty("Tier", out var tierProp))
                                            tierVal = tierProp.GetInt32();

                                        if (tierVal == 0)
                                            _pendingDetection = (ruleName, processName, confidence, evidence);
                                    }
                                    catch { }
                                }
                                else if (line.Contains("\"type\":\"response\"", StringComparison.OrdinalIgnoreCase))
                                {
                                    try
                                    {
                                        using var doc = JsonDocument.Parse(line);
                                        var data = doc.RootElement.GetProperty("data");
                                        var actionTaken = data.GetProperty("ActionTaken").GetString() ?? "";

                                        if (_pendingDetection.HasValue &&
                                            (actionTaken == "KILL" || actionTaken == "QUARANTINE_AND_KILL" ||
                                             actionTaken == "NETWORK_ISOLATE" || actionTaken == "REMOVE_CERT_AND_KILL_ADDER"))
                                        {
                                            var (ruleName, processName, confidence, evidence) = _pendingDetection.Value;

                                            var cacheKey = $"{ruleName}:{processName}";
                                            if (shownCache.TryGetValue(cacheKey, out var lastShown))
                                            {
                                                if (DateTime.UtcNow - lastShown < TimeSpan.FromSeconds(30))
                                                {
                                                    _pendingDetection = null;
                                                    continue;
                                                }
                                            }
                                            shownCache[cacheKey] = DateTime.UtcNow;

                                            // No-op: balloon tips removed — WpnService disabled by hardening.
                                            // Detection is still logged in events.jsonl and visible in console.
                                        }
                                        _pendingDetection = null;
                                    }
                                    catch { _pendingDetection = null; }
                                }
                            }
                            lastOffset = fs.Position;
                        }
                    }
                }
                catch { }

                Thread.Sleep(1000);
            }
        }
    }
}

