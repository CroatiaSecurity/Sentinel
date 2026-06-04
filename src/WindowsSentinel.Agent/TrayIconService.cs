using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using WindowsSentinel.Core;

namespace WindowsSentinel.Agent
{
    public class TrayIconService : IHostedService, IDisposable
    {
        private readonly SentinelConfig _config;
        private NotifyIcon? _notifyIcon;
        private ContextMenuStrip? _contextMenu;
        private Thread? _uiThread;
        private readonly CancellationTokenSource _cts = new();

        public TrayIconService(SentinelConfig config)
        {
            _config = config;
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
            _contextMenu.Items.Add("Stop Protection", null, OnToggleProtection);
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
                Text = "Windows Sentinel v6.0.0 — Protection Active",
                Visible = true
            };

            _notifyIcon.DoubleClick += OnOpenConsole;

            // Show initial balloon tip
            _notifyIcon.ShowBalloonTip(3000, "Windows Sentinel", "Protection has started.", ToolTipIcon.Info);

            // Start watching log file for new detections
            _ = WatchLogFileAsync(_cts.Token);

            Application.Run();
        }

        private void OnOpenConsole(object? sender, EventArgs e)
        {
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var logFile = Path.Combine(programData, "WindowsSentinel", "events.jsonl");

                // Start cmd.exe to tail the file (using PowerShell Get-Content -Tail -Wait as per 4.4.0 fix)
                var pInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c powershell -Command \"Get-Content -Path '{logFile}' -Tail 20 -Wait\"",
                    UseShellExecute = true
                };
                Process.Start(pInfo);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open console: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OnOpenQuarantine(object? sender, EventArgs e)
        {
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var qDir = Path.Combine(programData, "WindowsSentinel", "Quarantine");
                if (Directory.Exists(qDir))
                {
                    Process.Start("explorer.exe", qDir);
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
                var logFile = Path.Combine(programData, "WindowsSentinel", "events.jsonl");
                if (File.Exists(logFile))
                {
                    Process.Start("notepad.exe", logFile);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open event log: {ex.Message}");
            }
        }

        private void OnToggleProtection(object? sender, EventArgs e)
        {
            _config.ActiveResponse = !_config.ActiveResponse;
            var status = _config.ActiveResponse ? "Active" : "Disabled";
            _notifyIcon!.Text = $"Windows Sentinel v6.0.0 — Protection {status}";
            _notifyIcon.ShowBalloonTip(2000, "Windows Sentinel", $"Protection mode set to {status}.", ToolTipIcon.Warning);
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

        private async Task WatchLogFileAsync(CancellationToken cancellationToken)
        {
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var logFile = Path.Combine(programData, "WindowsSentinel", "events.jsonl");

            while (!File.Exists(logFile) && !cancellationToken.IsCancellationRequested)
            {
                try { await Task.Delay(1000, cancellationToken); } catch { break; }
            }

            long lastOffset = 0;
            try
            {
                if (File.Exists(logFile))
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    lastOffset = fs.Length;
                }
            }
            catch { }

            var rateLimiter = new RateLimiter(3, TimeSpan.FromSeconds(5));
            bool isSilenced = false;
            var shownCache = new System.Collections.Generic.Dictionary<string, DateTime>();

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // Clean up shownCache occasionally (entries older than 30s)
                    var now = DateTime.UtcNow;
                    var keysToRemove = new System.Collections.Generic.List<string>();
                    foreach (var kvp in shownCache)
                    {
                        if (now - kvp.Value > TimeSpan.FromSeconds(30))
                        {
                            keysToRemove.Add(kvp.Key);
                        }
                    }
                    foreach (var k in keysToRemove)
                    {
                        shownCache.Remove(k);
                    }

                    if (File.Exists(logFile))
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        if (fs.Length < lastOffset)
                        {
                            lastOffset = 0;
                        }

                        if (fs.Length > lastOffset)
                        {
                            fs.Seek(lastOffset, SeekOrigin.Begin);
                            using var reader = new StreamReader(fs, System.Text.Encoding.UTF8, false, 4096, true);
                            string? line;
                            while ((line = await reader.ReadLineAsync(cancellationToken)) != null)
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

                                        int tierVal = 1; // default to Tier2
                                        if (data.TryGetProperty("Tier", out var tierProp))
                                        {
                                            tierVal = tierProp.GetInt32();
                                        }

                                        // Deduplication check
                                        var cacheKey = $"{ruleName}:{processName}";
                                        if (shownCache.TryGetValue(cacheKey, out var lastShown))
                                        {
                                            if (DateTime.UtcNow - lastShown < TimeSpan.FromSeconds(30))
                                            {
                                                continue; // Skip duplicate notification
                                            }
                                        }
                                        shownCache[cacheKey] = DateTime.UtcNow;

                                        string title;
                                        string statusText;
                                        if (tierVal == 0) // Tier1Behavioral
                                        {
                                            if (_config.ActiveResponse)
                                            {
                                                title = $"Threat Terminated: {ruleName}";
                                                statusText = "Terminated (Active Response Blocked)";
                                            }
                                            else
                                            {
                                                title = $"Threat Detected: {ruleName}";
                                                statusText = "Log Only (Active Response Off)";
                                            }
                                        }
                                        else // Tier2Indicator
                                        {
                                            title = $"Suspicious Activity: {ruleName}";
                                            statusText = "Logged (No Terminate Action)";
                                        }

                                        if (rateLimiter.AllowRequest())
                                        {
                                            isSilenced = false;
                                            _notifyIcon?.ShowBalloonTip(
                                                5000,
                                                title,
                                                $"Process: {processName} ({statusText})\nConfidence: {confidence:P0}\n{evidence}",
                                                ToolTipIcon.Warning
                                            );
                                        }
                                        else if (!isSilenced)
                                        {
                                            isSilenced = true;
                                            _notifyIcon?.ShowBalloonTip(
                                                3000,
                                                "Notifications Silenced",
                                                "Multiple alerts received in a short time. Alerts are suppressed to prevent spam. Check console or events.jsonl for complete logs.",
                                                ToolTipIcon.Info
                                            );
                                        }
                                    }
                                    catch { }
                                }
                            }
                            lastOffset = fs.Position;
                        }
                    }
                }
                catch { }

                try { await Task.Delay(1000, cancellationToken); } catch { break; }
            }
        }
    }
}

