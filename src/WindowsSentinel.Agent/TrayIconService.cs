using System.Diagnostics;
using System.Drawing;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Agent;

/// <summary>
/// System tray icon for Windows Sentinel Agent.
/// Provides quick access to:
///   - Console view (shows real-time detection output)
///   - Quarantine folder
///   - Event log (opens in Notepad)
///   - Stop protection (graceful shutdown)
///   - Balloon tip notifications for detections/responses
///
/// Runs a WinForms message pump on a dedicated STA thread so the NotifyIcon
/// receives Windows messages without blocking the Generic Host.
/// </summary>
internal sealed class TrayIconService : IHostedService, IDisposable
{
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger<TrayIconService> _logger;
    private Thread? _uiThread;
    private System.Windows.Forms.NotifyIcon? _notifyIcon;
    private System.Windows.Forms.ContextMenuStrip? _contextMenu;
    private System.Windows.Forms.Form? _hiddenForm; // For cross-thread marshalling
    private CancellationTokenSource? _cts;
    private bool _stopConfirmationPending;

    // Paths
    private static readonly string DataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WindowsSentinel");

    private static readonly string EventsLogPath = Path.Combine(DataDir, "events.jsonl");
    private static readonly string QuarantinePath = Path.Combine(DataDir, "Quarantine");

    public TrayIconService(IHostApplicationLifetime lifetime, ILogger<TrayIconService> logger)
    {
        _lifetime = lifetime;
        _logger = logger;
    }

    /// <summary>
    /// Shows a balloon notification from the tray icon.
    /// Thread-safe — can be called from any thread.
    /// </summary>
    public void ShowBalloon(string title, string text, System.Windows.Forms.ToolTipIcon icon = System.Windows.Forms.ToolTipIcon.Info, int timeoutMs = 5000)
    {
        if (_notifyIcon == null || _hiddenForm == null || !_hiddenForm.IsHandleCreated)
            return;

        try
        {
            _hiddenForm.BeginInvoke(new Action(() =>
            {
                _notifyIcon?.ShowBalloonTip(timeoutMs, title, text, icon);
            }));
        }
        catch { /* UI thread may be gone */ }
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        // If launched by the Service with CREATE_NEW_CONSOLE, free it immediately
        // so it doesn't interfere with the WinForms message pump
        FreeConsole();

        _uiThread = new Thread(RunTrayIcon)
        {
            Name = "SentinelTrayIcon",
            IsBackground = true
        };
        _uiThread.SetApartmentState(ApartmentState.STA);
        _uiThread.Start();

        _logger.LogInformation("Tray icon service started");
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Tray icon service stopping");

        // Remove the icon and exit the message loop
        if (_hiddenForm != null && _hiddenForm.IsHandleCreated)
        {
            try
            {
                _hiddenForm.BeginInvoke(new Action(() =>
                {
                    if (_notifyIcon != null) _notifyIcon.Visible = false;
                    System.Windows.Forms.Application.ExitThread();
                }));
            }
            catch
            {
                // UI thread may already be gone
            }
        }

        _cts?.Cancel();
        return Task.CompletedTask;
    }

    private void RunTrayIcon()
    {
        try
        {
            System.Windows.Forms.Application.SetHighDpiMode(System.Windows.Forms.HighDpiMode.SystemAware);
            System.Windows.Forms.Application.EnableVisualStyles();

            _contextMenu = BuildContextMenu();

            var icon = LoadIcon();

            _notifyIcon = new System.Windows.Forms.NotifyIcon()
            {
                Icon = icon,
                Text = $"Windows Sentinel v{WindowsSentinel.Core.SentinelVersion.Version}\nProtection Active",
                ContextMenuStrip = _contextMenu,
                Visible = true
            };

            // Double-click opens console
            _notifyIcon.DoubleClick += (_, _) => OpenConsole();

            // Balloon click confirms stop protection
            _notifyIcon.BalloonTipClicked += (_, _) =>
            {
                if (_stopConfirmationPending)
                {
                    _stopConfirmationPending = false;
                    ConfirmStopProtection();
                }
            };

            // Balloon closed without clicking = cancel stop
            _notifyIcon.BalloonTipClosed += (_, _) =>
            {
                _stopConfirmationPending = false;
            };

            // Use ApplicationContext — this keeps the message loop alive without a visible form
            var appContext = new System.Windows.Forms.ApplicationContext();

            // Create a hidden form solely for cross-thread marshalling (BeginInvoke)
            _hiddenForm = new System.Windows.Forms.Form();
            _hiddenForm.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            _hiddenForm.ShowInTaskbar = false;
            _hiddenForm.Size = new System.Drawing.Size(0, 0);
            _hiddenForm.Opacity = 0;
            _hiddenForm.StartPosition = System.Windows.Forms.FormStartPosition.Manual;
            _hiddenForm.Location = new System.Drawing.Point(-32000, -32000);
            _hiddenForm.Show();
            _hiddenForm.Visible = false;

            // When the host shuts down, close the tray
            _lifetime.ApplicationStopping.Register(() =>
            {
                if (_hiddenForm != null && _hiddenForm.IsHandleCreated)
                {
                    _hiddenForm.BeginInvoke(new Action(() =>
                    {
                        if (_notifyIcon != null) _notifyIcon.Visible = false;
                        System.Windows.Forms.Application.ExitThread();
                    }));
                }
            });

            // ApplicationContext keeps the message loop running indefinitely
            System.Windows.Forms.Application.Run(appContext);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Tray icon thread crashed");
        }
    }

    private System.Windows.Forms.ToolStripMenuItem? _stopStartItem;

    private System.Windows.Forms.ContextMenuStrip BuildContextMenu()
    {
        var menu = new System.Windows.Forms.ContextMenuStrip();

        // Header (disabled, just for display)
        var header = new System.Windows.Forms.ToolStripMenuItem($"Windows Sentinel v{WindowsSentinel.Core.SentinelVersion.Version}")
        {
            Enabled = false,
            Font = new Font(menu.Font, FontStyle.Bold)
        };
        menu.Items.Add(header);
        menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());

        // Open Console
        var consoleItem = new System.Windows.Forms.ToolStripMenuItem("Open Console", null, (_, _) => OpenConsole());
        consoleItem.Font = new Font(menu.Font, FontStyle.Bold); // Default action
        menu.Items.Add(consoleItem);

        // Open Quarantine
        menu.Items.Add(new System.Windows.Forms.ToolStripMenuItem("Open Quarantine Folder", null, (_, _) => OpenQuarantine()));

        // Open Logs
        menu.Items.Add(new System.Windows.Forms.ToolStripMenuItem("Open Event Log", null, (_, _) => OpenLogs()));

        menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());

        // Stop/Start Protection (dynamic text based on service state)
        _stopStartItem = new System.Windows.Forms.ToolStripMenuItem("Stop Protection", null, (_, _) => ToggleProtection());
        _stopStartItem.ForeColor = Color.DarkRed;
        menu.Items.Add(_stopStartItem);

        // Update the menu item text when the menu opens
        menu.Opening += (_, _) => UpdateStopStartItem();

        return menu;
    }

    private void UpdateStopStartItem()
    {
        if (_stopStartItem == null) return;

        try
        {
            using var sc = new System.ServiceProcess.ServiceController("Windows Sentinel");
            if (sc.Status == System.ServiceProcess.ServiceControllerStatus.Running)
            {
                _stopStartItem.Text = "Stop Protection";
                _stopStartItem.ForeColor = Color.DarkRed;
            }
            else
            {
                _stopStartItem.Text = "Start Protection";
                _stopStartItem.ForeColor = Color.DarkGreen;
            }
        }
        catch
        {
            // Service not installed or inaccessible
            _stopStartItem.Text = "Stop Protection";
            _stopStartItem.ForeColor = Color.DarkRed;
        }
    }

    private void ToggleProtection()
    {
        try
        {
            using var sc = new System.ServiceProcess.ServiceController("Windows Sentinel");
            if (sc.Status == System.ServiceProcess.ServiceControllerStatus.Running)
            {
                StopProtection();
            }
            else
            {
                StartProtection();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to toggle protection");
            ShowBalloon("Error", "Could not change protection state. Run as Administrator?", System.Windows.Forms.ToolTipIcon.Error);
        }
    }

    private CancellationTokenSource? _consoleTailCts;

    private void OpenConsole()
    {
        try
        {
            // Allocate or attach to a console window to show real-time output
            if (!AttachConsole(unchecked((uint)-1))) // ATTACH_PARENT_PROCESS
            {
                AllocConsole();
            }

            // Set UTF-8 output so box-drawing characters render correctly
            SetConsoleOutputCP(65001);
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
            Console.SetError(new StreamWriter(Console.OpenStandardError()) { AutoFlush = true });

            Console.Title = "Windows Sentinel - Live Detection Console";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("+--------------------------------------------------------------+");
            Console.WriteLine("|         Windows Sentinel - Live Detection Console            |");
            Console.WriteLine("|  Detections and responses will appear here in real time.     |");
            Console.WriteLine("|  Close this window to hide (protection continues).           |");
            Console.WriteLine("+--------------------------------------------------------------+");
            Console.ResetColor();
            Console.WriteLine();

            // Stop any previous tail
            _consoleTailCts?.Cancel();
            _consoleTailCts = new CancellationTokenSource();

            // Start live tailing on a background thread
            var ct = _consoleTailCts.Token;
            Task.Run(() => LiveTailLog(ct), ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to open console");
        }
    }

    private void LiveTailLog(CancellationToken ct)
    {
        try
        {
            long lastPosition = 0;

            // Print last 20 lines first
            if (File.Exists(EventsLogPath))
            {
                using var fs = new FileStream(EventsLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var reader = new StreamReader(fs);
                var allLines = new List<string>();
                string? line;
                while ((line = reader.ReadLine()) != null)
                    allLines.Add(line);

                var tail = allLines.Skip(Math.Max(0, allLines.Count - 20)).ToArray();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"-- Last {tail.Length} events --");
                Console.ResetColor();

                foreach (var entry in tail)
                    WriteColoredLine(entry);

                lastPosition = fs.Position;
            }

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("-- Live tail active (new events appear below) --");
            Console.ResetColor();

            // Poll for new lines every second
            while (!ct.IsCancellationRequested)
            {
                Thread.Sleep(1000);

                if (!File.Exists(EventsLogPath)) continue;

                try
                {
                    using var fs = new FileStream(EventsLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    if (fs.Length < lastPosition)
                    {
                        // File was rotated — reset
                        lastPosition = 0;
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.WriteLine("-- Log rotated --");
                        Console.ResetColor();
                    }

                    if (fs.Length > lastPosition)
                    {
                        fs.Seek(lastPosition, SeekOrigin.Begin);
                        using var reader = new StreamReader(fs);
                        string? line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            if (!string.IsNullOrWhiteSpace(line))
                                WriteColoredLine(line);
                        }
                        lastPosition = fs.Position;
                    }
                }
                catch (IOException)
                {
                    // File briefly locked during rotation — skip this cycle
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Console.WriteLine($"[Tail error: {ex.Message}]");
        }
    }

    private static void WriteColoredLine(string line)
    {
        if (line.Contains("\"KillProcess\"", StringComparison.OrdinalIgnoreCase))
            Console.ForegroundColor = ConsoleColor.Red;
        else if (line.Contains("\"type\":\"detection\"", StringComparison.OrdinalIgnoreCase))
            Console.ForegroundColor = ConsoleColor.Yellow;
        else
            Console.ForegroundColor = ConsoleColor.Gray;

        Console.WriteLine(line);
        Console.ResetColor();
    }

    private void OpenQuarantine()
    {
        try
        {
            Directory.CreateDirectory(QuarantinePath);
            Process.Start(new ProcessStartInfo
            {
                FileName = QuarantinePath,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to open quarantine folder");
        }
    }

    private void OpenLogs()
    {
        try
        {
            if (!File.Exists(EventsLogPath))
            {
                // Create an empty file so Notepad doesn't complain
                Directory.CreateDirectory(Path.GetDirectoryName(EventsLogPath)!);
                File.Create(EventsLogPath).Dispose();
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = "notepad.exe",
                Arguments = EventsLogPath,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to open event log");
        }
    }

    private void StopProtection()
    {
        _stopConfirmationPending = true;
        _notifyIcon?.ShowBalloonTip(
            10000,
            "Stop Protection?",
            "Click this notification to confirm stopping Windows Sentinel.\nBoth the Agent and Service will be stopped.",
            System.Windows.Forms.ToolTipIcon.Warning);
    }

    private void ConfirmStopProtection()
    {
        _logger.LogCritical("User requested protection stop via tray icon");

        ShowBalloon("Stopping Protection", "Windows Sentinel is shutting down...", System.Windows.Forms.ToolTipIcon.Info, 3000);

        try
        {
            using var sc = new System.ServiceProcess.ServiceController("Windows Sentinel");
            if (sc.Status == System.ServiceProcess.ServiceControllerStatus.Running)
            {
                sc.Stop();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to stop service");
        }

        // Stop the Agent (ourselves)
        _lifetime.StopApplication();
    }

    private void StartProtection()
    {
        _logger.LogInformation("User requested protection start via tray icon");

        try
        {
            using var sc = new System.ServiceProcess.ServiceController("Windows Sentinel");
            if (sc.Status != System.ServiceProcess.ServiceControllerStatus.Running)
            {
                sc.Start();
                sc.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));
            }

            ShowBalloon("Protection Active", "Windows Sentinel service started.", System.Windows.Forms.ToolTipIcon.Info, 3000);
            _notifyIcon!.Text = $"Windows Sentinel v{WindowsSentinel.Core.SentinelVersion.Version}\nProtection Active";
        }
        catch (InvalidOperationException)
        {
            ShowBalloon("Error", "Service not installed. Reinstall Windows Sentinel.", System.Windows.Forms.ToolTipIcon.Error);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start service");
            ShowBalloon("Error", "Could not start service. Run as Administrator?", System.Windows.Forms.ToolTipIcon.Error);
        }
    }

    private Icon LoadIcon()
    {
        // Try to load the embedded icon from the assembly (set via ApplicationIcon in csproj)
        try
        {
            var exePath = Environment.ProcessPath
                ?? Process.GetCurrentProcess().MainModule?.FileName;

            if (exePath != null && File.Exists(exePath))
            {
                var icon = Icon.ExtractAssociatedIcon(exePath);
                if (icon != null)
                {
                    _logger.LogDebug("Tray icon: loaded from {Path}", exePath);
                    return icon;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Tray icon: failed to extract from exe");
        }

        // Fallback: use the Windows shield icon
        _logger.LogDebug("Tray icon: using SystemIcons.Shield fallback");
        return SystemIcons.Shield;
    }

    public void Dispose()
    {
        _cts?.Dispose();
        _notifyIcon?.Dispose();
        _contextMenu?.Dispose();
        _hiddenForm?.Dispose();
    }

    // P/Invoke for console allocation
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AllocConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleOutputCP(uint wCodePageID);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);
}
