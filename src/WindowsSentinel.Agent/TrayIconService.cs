using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
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

            _notifyIcon = new NotifyIcon
            {
                Icon = System.Drawing.SystemIcons.Shield,
                ContextMenuStrip = _contextMenu,
                Text = "Windows Sentinel v5.1.0 — Protection Active",
                Visible = true
            };

            _notifyIcon.DoubleClick += OnOpenConsole;

            // Show initial balloon tip
            _notifyIcon.ShowBalloonTip(3000, "Windows Sentinel", "Protection has started.", ToolTipIcon.Info);

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
            _notifyIcon!.Text = $"Windows Sentinel v5.1.0 — Protection {status}";
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
    }
}
