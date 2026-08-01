using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;
using Sentinel.Core;

namespace Sentinel.Agent
{
    /// <summary>
    /// TrimKit-inspired dark sidebar dashboard for the user-session Agent.
    /// STA-only: all file I/O is synchronous; no async/await on this form.
    /// </summary>
    public sealed class AgentDashboardForm : Form
    {
        // TrimKit palette
        private static readonly Color Bg = Color.FromArgb(0x20, 0x21, 0x24);
        private static readonly Color SidebarBg = Color.FromArgb(0x1C, 0x1C, 0x1F);
        private static readonly Color PanelBg = Color.FromArgb(0x28, 0x29, 0x2D);
        private static readonly Color FieldBg = Color.FromArgb(0x29, 0x2A, 0x2D);
        private static readonly Color BorderSoft = Color.FromArgb(0x3C, 0x40, 0x43);
        private static readonly Color Accent = Color.FromArgb(0x8A, 0xB4, 0xF8);
        private static readonly Color TextPrimary = Color.FromArgb(0xFF, 0xFF, 0xFF);
        private static readonly Color TextMuted = Color.FromArgb(0x80, 0x86, 0x8E);
        private static readonly Color TextDim = Color.FromArgb(0x5F, 0x63, 0x68);
        private static readonly Color Green = Color.FromArgb(0x81, 0xC9, 0x95);
        private static readonly Color Danger = Color.FromArgb(0xF2, 0x8B, 0x82);
        private static readonly Color NavHover = Color.FromArgb(0x28, 0x29, 0x2D);
        private static readonly Color NavSelected = Color.FromArgb(0x2D, 0x2E, 0x32);

        private readonly string _version;
        private readonly AutoIncidentReportingConfig _reportConfig;
        private readonly QuarantineManager _quarantine;

        private readonly Panel _contentHost;
        private readonly Label _statusLabel;
        private readonly List<Button> _navButtons = new();
        private readonly Panel[] _pages;

        // Overview
        private Label? _overviewStatus;
        private Label? _overviewDetails;
        private ListBox? _recentEventsList;

        // Events
        private ListBox? _eventsList;
        private TextBox? _eventDetail;

        // Tools
        private TextBox? _toolsInfo;

        // Quarantine
        private ListBox? _quarantineList;

        public AgentDashboardForm(
            string version,
            AutoIncidentReportingConfig reportConfig,
            QuarantineManager quarantine)
        {
            _version = version;
            _reportConfig = reportConfig ?? new AutoIncidentReportingConfig();
            _quarantine = quarantine ?? new QuarantineManager();

            Text = $"Sentinel Settings — v{_version}";
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(980, 640);
            Size = new Size(1120, 720);
            BackColor = Bg;
            ForeColor = TextPrimary;
            Font = new Font("Segoe UI", 9.5f);
            ShowInTaskbar = true;
            FormBorderStyle = FormBorderStyle.Sizable;
            MaximizeBox = true;
            MinimizeBox = true;

            try
            {
                var icoPath = Path.Combine(AppContext.BaseDirectory, "Sentinel.ico");
                if (File.Exists(icoPath))
                    Icon = new Icon(icoPath);
                else
                    Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            }
            catch { /* icon optional */ }

            var root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1,
                BackColor = Bg,
                Padding = new Padding(0),
                Margin = new Padding(0)
            };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 200));
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            Controls.Add(root);

            // ── Sidebar ──
            var sidebar = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = SidebarBg,
                Padding = new Padding(0)
            };
            root.Controls.Add(sidebar, 0, 0);

            var brand = new Panel { Dock = DockStyle.Top, Height = 72, BackColor = SidebarBg, Padding = new Padding(16, 16, 16, 8) };
            brand.Controls.Add(new Label
            {
                Text = "Settings",
                Font = new Font("Segoe UI", 14f, FontStyle.Bold),
                ForeColor = Accent,
                AutoSize = true,
                Location = new Point(16, 16)
            });
            brand.Controls.Add(new Label
            {
                Text = $"Sentinel v{_version}",
                Font = new Font("Segoe UI", 8.5f),
                ForeColor = TextDim,
                AutoSize = true,
                Location = new Point(18, 42)
            });
            sidebar.Controls.Add(brand);

            var navHost = new Panel { Dock = DockStyle.Fill, BackColor = SidebarBg, Padding = new Padding(0, 4, 0, 0) };
            sidebar.Controls.Add(navHost);

            var bottomBar = new Panel { Dock = DockStyle.Bottom, Height = 48, BackColor = PanelBg, Padding = new Padding(12, 10, 12, 10) };
            _statusLabel = new Label
            {
                Text = "Ready",
                ForeColor = TextMuted,
                Font = new Font("Segoe UI", 8.5f),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };
            bottomBar.Controls.Add(_statusLabel);
            sidebar.Controls.Add(bottomBar);
            sidebar.Controls.SetChildIndex(bottomBar, 0);

            // Overview · Events · Quarantine · Tools · About  (Report to Police removed)
            string[] navLabels = { "Overview", "Events", "Quarantine", "Tools", "About" };
            for (int i = 0; i < navLabels.Length; i++)
            {
                var idx = i;
                var btn = CreateNavButton(navLabels[i], () => ShowPage(idx));
                btn.Dock = DockStyle.Top;
                _navButtons.Add(btn);
            }
            for (int i = _navButtons.Count - 1; i >= 0; i--)
                navHost.Controls.Add(_navButtons[i]);

            _contentHost = new Panel { Dock = DockStyle.Fill, BackColor = Bg, Padding = new Padding(0) };
            root.Controls.Add(_contentHost, 1, 0);

            _pages = new Panel[]
            {
                BuildOverviewPage(),
                BuildEventsPage(),
                BuildQuarantinePage(),
                BuildToolsPage(),
                BuildAboutPage()
            };
            foreach (var p in _pages)
            {
                p.Dock = DockStyle.Fill;
                p.Visible = false;
                _contentHost.Controls.Add(p);
            }

            ShowPage(0);
            Load += (_, _) => RefreshAll();
        }

        /// <summary>Select sidebar page by index (0 Overview … 3 Tools … 4 About).</summary>
        public void SelectPage(int index)
        {
            if (index < 0 || index >= _pages.Length) return;
            ShowPage(index);
        }

        private void ShowPage(int index)
        {
            for (int i = 0; i < _pages.Length; i++)
            {
                _pages[i].Visible = i == index;
                StyleNavButton(_navButtons[i], selected: i == index);
            }

            if (index == 0) RefreshOverview();
            else if (index == 1) RefreshEvents();
            else if (index == 2) RefreshQuarantine();
            else if (index == 3) RefreshTools();
        }

        private void RefreshAll()
        {
            RefreshOverview();
            RefreshEvents();
            RefreshQuarantine();
            RefreshTools();
        }

        // ═══════════════════════════════════════════════════════════════
        // Overview
        // ═══════════════════════════════════════════════════════════════

        private Panel BuildOverviewPage()
        {
            var page = new Panel { BackColor = Bg, Padding = new Padding(28) };
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 5,
                BackColor = Bg
            };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 160));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            page.Controls.Add(layout);

            layout.Controls.Add(MakeTitle("Protection overview"), 0, 0);

            var card = MakeCard();
            card.Dock = DockStyle.Fill;
            card.Padding = new Padding(20);
            _overviewStatus = new Label
            {
                Font = new Font("Segoe UI", 16f, FontStyle.Bold),
                ForeColor = Green,
                AutoSize = true,
                Location = new Point(20, 18)
            };
            _overviewDetails = new Label
            {
                ForeColor = TextMuted,
                AutoSize = false,
                Location = new Point(20, 55),
                Size = new Size(780, 90)
            };
            card.Controls.Add(_overviewStatus);
            card.Controls.Add(_overviewDetails);
            layout.Controls.Add(card, 0, 1);

            var quick = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false
            };
            quick.Controls.Add(MakeChromeButton("Refresh", (_, _) => RefreshOverview()));
            quick.Controls.Add(MakeChromeButton("Open Event Log", OpenEventLogFile));
            quick.Controls.Add(MakeChromeButton("Open Quarantine", (_, _) => OpenFolder(QuarantineDir)));
            quick.Controls.Add(MakeChromeButton("Open Data Folder", (_, _) => OpenFolder(ProgramDataRoot)));
            quick.Controls.Add(MakeAccentButton("Copy Diagnostics", (_, _) => CopyDiagnostics()));
            layout.Controls.Add(quick, 0, 2);

            layout.Controls.Add(new Label
            {
                Text = "Recent detections",
                Font = new Font("Segoe UI", 11f, FontStyle.Bold),
                ForeColor = TextPrimary,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            }, 0, 3);

            _recentEventsList = MakeListBox();
            _recentEventsList.Dock = DockStyle.Fill;
            layout.Controls.Add(_recentEventsList, 0, 4);

            return page;
        }

        private void RefreshOverview()
        {
            var serviceUp = IsProcessRunning("Sentinel.Service");
            var agentUp = IsProcessRunning("Sentinel.Agent");
            var svcState = GetWindowsServiceStatus("Sentinel");
            var packCount = CountPacks();
            var qCount = 0;
            try { qCount = _quarantine.ListQuarantined().Count; } catch { }
            var logSize = FormatFileSize(EventsLogPath);
            var lastDet = ReadRecentDetections(1).FirstOrDefault();

            if (_overviewStatus != null)
            {
                if (serviceUp)
                {
                    _overviewStatus.Text = "Protection active";
                    _overviewStatus.ForeColor = Green;
                }
                else
                {
                    _overviewStatus.Text = "Service not detected";
                    _overviewStatus.ForeColor = Danger;
                }
            }

            if (_overviewDetails != null)
            {
                _overviewDetails.Text =
                    $"Agent v{_version}  ·  Process: {(agentUp ? "running" : "not found")}\n" +
                    $"Service process: {(serviceUp ? "running" : "not found")}  ·  Windows service: {svcState}\n" +
                    $"Event log: {logSize}  ·  Evidence packs: {packCount}  ·  Quarantine: {qCount}\n" +
                    (lastDet != null
                        ? $"Latest detection: {lastDet.Summary}"
                        : "Latest detection: none yet") +
                    "\nActive response is controlled by the Sentinel service (SYSTEM) — not this UI.";
            }

            if (_recentEventsList != null)
            {
                _recentEventsList.BeginUpdate();
                _recentEventsList.Items.Clear();
                foreach (var line in ReadRecentDetections(12))
                    _recentEventsList.Items.Add(line.Summary);
                if (_recentEventsList.Items.Count == 0)
                    _recentEventsList.Items.Add("No detections logged yet.");
                _recentEventsList.EndUpdate();
            }

            _statusLabel.Text = serviceUp ? "Service online" : "Service offline — agent UI still available";
        }

        // ═══════════════════════════════════════════════════════════════
        // Events
        // ═══════════════════════════════════════════════════════════════

        private Panel BuildEventsPage()
        {
            var page = new Panel { BackColor = Bg, Padding = new Padding(28) };
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                BackColor = Bg
            };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 55));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 45));
            page.Controls.Add(layout);

            var header = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            header.Controls.Add(MakeTitle("Event log"));
            var refresh = MakeChromeButton("Refresh", (_, _) => RefreshEvents());
            refresh.Margin = new Padding(16, 4, 0, 0);
            header.Controls.Add(refresh);
            var openLog = MakeChromeButton("Open in Notepad", OpenEventLogFile);
            openLog.Margin = new Padding(8, 4, 0, 0);
            header.Controls.Add(openLog);
            var openFolder = MakeChromeButton("Open Data Folder", (_, _) => OpenFolder(ProgramDataRoot));
            openFolder.Margin = new Padding(8, 4, 0, 0);
            header.Controls.Add(openFolder);
            layout.Controls.Add(header, 0, 0);

            _eventsList = MakeListBox();
            _eventsList.Dock = DockStyle.Fill;
            _eventsList.SelectedIndexChanged += (_, _) =>
            {
                if (_eventsList.SelectedItem is DetectionListItem item && _eventDetail != null)
                    _eventDetail.Text = item.Detail;
            };
            layout.Controls.Add(_eventsList, 0, 1);

            _eventDetail = MakeMultiline(readOnly: true);
            _eventDetail.Dock = DockStyle.Fill;
            layout.Controls.Add(_eventDetail, 0, 2);

            return page;
        }

        private void RefreshEvents()
        {
            if (_eventsList == null) return;
            var items = ReadRecentDetections(200);
            _eventsList.BeginUpdate();
            _eventsList.Items.Clear();
            foreach (var item in items)
                _eventsList.Items.Add(item);
            if (_eventsList.Items.Count == 0)
                _eventsList.Items.Add(new DetectionListItem("No detection events found.", ""));
            _eventsList.EndUpdate();
            if (_eventDetail != null) _eventDetail.Text = "";
            _statusLabel.Text = $"Loaded {items.Count} detection event(s)";
        }

        // ═══════════════════════════════════════════════════════════════
        // Quarantine
        // ═══════════════════════════════════════════════════════════════

        private Panel BuildQuarantinePage()
        {
            var page = new Panel { BackColor = Bg, Padding = new Padding(28) };
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                BackColor = Bg
            };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            page.Controls.Add(layout);

            layout.Controls.Add(MakeTitle("Quarantine"), 0, 0);

            var bar = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight };
            bar.Controls.Add(MakeChromeButton("Refresh", (_, _) => RefreshQuarantine()));
            bar.Controls.Add(MakeAccentButton("Open Folder", (_, _) => OpenFolder(QuarantineDir)));
            layout.Controls.Add(bar, 0, 1);

            _quarantineList = MakeListBox();
            _quarantineList.Dock = DockStyle.Fill;
            layout.Controls.Add(_quarantineList, 0, 2);
            return page;
        }

        private void RefreshQuarantine()
        {
            if (_quarantineList == null) return;
            _quarantineList.BeginUpdate();
            _quarantineList.Items.Clear();
            try
            {
                var items = _quarantine.ListQuarantined();
                foreach (var item in items.OrderByDescending(i => i.QuarantineFile))
                {
                    var line = item.DisplayName;
                    if (!string.IsNullOrEmpty(item.OriginalPath))
                        line += $"  ←  {item.OriginalPath}";
                    _quarantineList.Items.Add(line);
                }
                if (_quarantineList.Items.Count == 0)
                    _quarantineList.Items.Add("Quarantine is empty.");
                _statusLabel.Text = $"{items.Count} quarantined item(s)";
            }
            catch (Exception ex)
            {
                _quarantineList.Items.Add($"Unable to list quarantine: {ex.Message}");
            }
            _quarantineList.EndUpdate();
        }

        // ═══════════════════════════════════════════════════════════════
        // Tools
        // ═══════════════════════════════════════════════════════════════

        private Panel BuildToolsPage()
        {
            var page = new Panel { BackColor = Bg, Padding = new Padding(28) };
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                BackColor = Bg
            };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 88));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            page.Controls.Add(layout);

            layout.Controls.Add(MakeTitle("Tools & folders"), 0, 0);

            var bar = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = true
            };
            bar.Controls.Add(MakeChromeButton("Refresh status", (_, _) => RefreshTools()));
            bar.Controls.Add(MakeChromeButton("Data folder", (_, _) => OpenFolder(ProgramDataRoot)));
            bar.Controls.Add(MakeChromeButton("Event log", OpenEventLogFile));
            bar.Controls.Add(MakeChromeButton("Quarantine", (_, _) => OpenFolder(QuarantineDir)));
            bar.Controls.Add(MakeChromeButton("Evidence packs", (_, _) => OpenFolder(GetReportRoot())));
            bar.Controls.Add(MakeChromeButton("Evidence raw", (_, _) => OpenFolder(Path.Combine(ProgramDataRoot, "Evidence"))));
            bar.Controls.Add(MakeChromeButton("Startup trace", (_, _) => OpenFileIfExists(Path.Combine(ProgramDataRoot, "startup_trace.log"))));
            bar.Controls.Add(MakeAccentButton("Copy diagnostics", (_, _) => CopyDiagnostics()));
            bar.Controls.Add(MakeChromeButton("Install folder", (_, _) => OpenFolder(AppContext.BaseDirectory.TrimEnd('\\'))));
            layout.Controls.Add(bar, 0, 1);

            _toolsInfo = MakeMultiline(readOnly: true);
            _toolsInfo.Dock = DockStyle.Fill;
            layout.Controls.Add(_toolsInfo, 0, 2);
            return page;
        }

        private void RefreshTools()
        {
            if (_toolsInfo == null) return;
            _toolsInfo.Text = BuildDiagnosticsText();
            _statusLabel.Text = "Tools status refreshed";
        }

        private void CopyDiagnostics()
        {
            try
            {
                Clipboard.SetText(BuildDiagnosticsText());
                _statusLabel.Text = "Diagnostics copied to clipboard";
                MessageBox.Show(this, "Diagnostics copied to clipboard.", "Sentinel",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not copy: {ex.Message}", "Sentinel",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private string BuildDiagnosticsText()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Sentinel diagnostics — {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
            sb.AppendLine($"Agent version: {_version}");
            sb.AppendLine($"Agent process: {(IsProcessRunning("Sentinel.Agent") ? "running" : "not found")}");
            sb.AppendLine($"Service process: {(IsProcessRunning("Sentinel.Service") ? "running" : "not found")}");
            sb.AppendLine($"Windows service 'Sentinel': {GetWindowsServiceStatus("Sentinel")}");
            sb.AppendLine($"Machine: {Environment.MachineName}");
            sb.AppendLine($"User: {Environment.UserDomainName}\\{Environment.UserName}");
            sb.AppendLine($"OS: {Environment.OSVersion}");
            sb.AppendLine();
            sb.AppendLine("Paths:");
            sb.AppendLine($"  Install:     {AppContext.BaseDirectory}");
            sb.AppendLine($"  ProgramData: {ProgramDataRoot}");
            sb.AppendLine($"  Events:      {EventsLogPath}  ({FormatFileSize(EventsLogPath)})");
            sb.AppendLine($"  Quarantine:  {QuarantineDir}");
            sb.AppendLine($"  Evidence:    {GetReportRoot()}  ({CountPacks()} packs)");
            sb.AppendLine($"  Evidence/:   {Path.Combine(ProgramDataRoot, "Evidence")}");
            sb.AppendLine($"  Startup log: {Path.Combine(ProgramDataRoot, "startup_trace.log")}");
            sb.AppendLine();
            sb.AppendLine("Config note:");
            sb.AppendLine("  ActiveResponse / kill policy is owned by Sentinel.Service (SYSTEM).");
            sb.AppendLine("  This agent has no kill toggle (by design).");
            sb.AppendLine();
            sb.AppendLine("Recent detections (up to 8):");
            var dets = ReadRecentDetections(8);
            if (dets.Count == 0)
                sb.AppendLine("  (none)");
            else
                foreach (var d in dets)
                    sb.AppendLine("  " + d.Summary);
            return sb.ToString();
        }

        // ═══════════════════════════════════════════════════════════════
        // About
        // ═══════════════════════════════════════════════════════════════

        private Panel BuildAboutPage()
        {
            var page = new Panel { BackColor = Bg, Padding = new Padding(28) };
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 2,
                BackColor = Bg
            };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            page.Controls.Add(layout);
            layout.Controls.Add(MakeTitle("About Sentinel"), 0, 0);

            var body = MakeMultiline(readOnly: true);
            body.Dock = DockStyle.Fill;
            body.Text =
                $"Windows Sentinel v{_version}\n\n" +
                "User-session agent for tray UI and local inspection.\n" +
                "The Sentinel service (SYSTEM) owns detection, kills, quarantine, and hardening.\n\n" +
                "Useful locations:\n" +
                $"  Data:        {ProgramDataRoot}\n" +
                $"  Events:      {EventsLogPath}\n" +
                $"  Quarantine:  {QuarantineDir}\n" +
                $"  Evidence:    {GetReportRoot()}\n\n" +
                "Constraints:\n" +
                "  • No ActiveResponse toggle in this UI (service-only authority)\n" +
                "  • No Exit from the tray (service owns lifetime)\n" +
                "  • No balloon tips (WpnService removed by hardening)\n" +
                "  • High-confidence responses still write sealed packs under IncidentReports\n";
            layout.Controls.Add(body, 0, 1);
            return page;
        }

        // ═══════════════════════════════════════════════════════════════
        // Shared helpers
        // ═══════════════════════════════════════════════════════════════

        private static string ProgramDataRoot =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");

        private string QuarantineDir =>
            !string.IsNullOrWhiteSpace(_quarantine.QuarantineDirectory)
                ? _quarantine.QuarantineDirectory
                : Path.Combine(ProgramDataRoot, "Quarantine");

        private string GetReportRoot() =>
            _reportConfig.ReportDirectory
            ?? Path.Combine(ProgramDataRoot, "IncidentReports");

        private static string EventsLogPath => Path.Combine(ProgramDataRoot, "events.jsonl");

        private int CountPacks()
        {
            try
            {
                var root = GetReportRoot();
                if (!Directory.Exists(root)) return 0;
                return Directory.EnumerateDirectories(root, "AUTO_*").Count();
            }
            catch { return 0; }
        }

        private static bool IsProcessRunning(string name)
        {
            try { return Process.GetProcessesByName(name).Length > 0; }
            catch { return false; }
        }

        private static string GetWindowsServiceStatus(string serviceName)
        {
            try
            {
                using var sc = new ServiceController(serviceName);
                return sc.Status.ToString();
            }
            catch
            {
                return "not installed / inaccessible";
            }
        }

        private static string FormatFileSize(string path)
        {
            try
            {
                if (!File.Exists(path)) return "missing";
                var len = new FileInfo(path).Length;
                if (len < 1024) return $"{len} B";
                if (len < 1024 * 1024) return $"{len / 1024.0:F1} KB";
                return $"{len / (1024.0 * 1024.0):F1} MB";
            }
            catch { return "n/a"; }
        }

        private static List<DetectionListItem> ReadRecentDetections(int max)
        {
            var results = new List<DetectionListItem>();
            var path = EventsLogPath;
            if (!File.Exists(path)) return results;

            try
            {
                var lines = new List<string>();
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(fs, Encoding.UTF8);
                string? line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (line.Contains("\"type\":\"detection\"", StringComparison.OrdinalIgnoreCase))
                        lines.Add(line);
                }

                foreach (var raw in lines.AsEnumerable().Reverse().Take(max))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(raw);
                        var data = doc.RootElement.GetProperty("data");
                        var rule = data.TryGetProperty("RuleName", out var r) ? r.GetString() ?? "?" : "?";
                        var proc = data.TryGetProperty("ProcessName", out var p) ? p.GetString() ?? "?" : "?";
                        var conf = data.TryGetProperty("Confidence", out var c) ? c.GetDouble() : 0;
                        var tier = data.TryGetProperty("Tier", out var t) ? t.GetInt32() : -1;
                        var evidence = data.TryGetProperty("Evidence", out var e) ? e.GetString() ?? "" : "";
                        var reasoning = data.TryGetProperty("Reasoning", out var re) ? re.GetString() ?? "" : "";
                        var ts = doc.RootElement.TryGetProperty("timestamp", out var tsProp)
                            ? tsProp.GetString() ?? ""
                            : "";

                        var summary = $"{ts}  [{(tier == 0 ? "T1" : tier == 1 ? "T2" : "?")}]  {rule}  —  {proc}  ({conf:F2})";
                        var detail = $"Rule: {rule}\nProcess: {proc}\nConfidence: {conf:F2}\nTier: {tier}\n\nEvidence:\n{evidence}\n\nReasoning:\n{reasoning}";
                        results.Add(new DetectionListItem(summary, detail));
                    }
                    catch { }
                }
            }
            catch { }

            return results;
        }

        private void OpenEventLogFile(object? sender, EventArgs e)
        {
            OpenFileIfExists(EventsLogPath, missingMessage: "Event log not found yet.");
        }

        private void OpenFileIfExists(string path, string? missingMessage = null)
        {
            try
            {
                if (!File.Exists(path))
                {
                    MessageBox.Show(this, missingMessage ?? $"File not found:\n{path}", "Sentinel",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                Process.Start(new ProcessStartInfo
                {
                    FileName = "notepad.exe",
                    UseShellExecute = false,
                    ArgumentList = { path }
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static void OpenFolder(string path)
        {
            try
            {
                if (!Directory.Exists(path))
                {
                    MessageBox.Show(
                        $"Folder does not exist yet:\n{path}",
                        "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    UseShellExecute = false,
                    ArgumentList = { path }
                });
            }
            catch { }
        }

        private Label MakeTitle(string text) => new()
        {
            Text = text,
            Font = new Font("Segoe UI", 14f, FontStyle.Bold),
            ForeColor = TextPrimary,
            AutoSize = true,
            Margin = new Padding(0, 4, 0, 8)
        };

        private Panel MakeCard() => new()
        {
            BackColor = PanelBg,
            Padding = new Padding(12)
        };

        private ListBox MakeListBox()
        {
            return new ListBox
            {
                BackColor = FieldBg,
                ForeColor = TextPrimary,
                BorderStyle = BorderStyle.FixedSingle,
                IntegralHeight = false,
                Font = new Font("Consolas", 9f),
                SelectionMode = SelectionMode.One
            };
        }

        private TextBox MakeMultiline(bool readOnly)
        {
            return new TextBox
            {
                BackColor = FieldBg,
                ForeColor = TextPrimary,
                BorderStyle = BorderStyle.FixedSingle,
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                ReadOnly = readOnly,
                Font = new Font(readOnly ? "Consolas" : "Segoe UI", 9f),
                WordWrap = true
            };
        }

        private Button CreateNavButton(string text, Action onClick)
        {
            var btn = new Button
            {
                Text = "  " + text,
                Height = 40,
                FlatStyle = FlatStyle.Flat,
                TextAlign = ContentAlignment.MiddleLeft,
                ForeColor = TextMuted,
                BackColor = SidebarBg,
                Font = new Font("Segoe UI", 10f),
                Cursor = Cursors.Hand,
                Padding = new Padding(12, 0, 0, 0)
            };
            btn.FlatAppearance.BorderSize = 0;
            btn.FlatAppearance.MouseOverBackColor = NavHover;
            btn.Click += (_, _) => onClick();
            return btn;
        }

        private void StyleNavButton(Button btn, bool selected)
        {
            btn.BackColor = selected ? NavSelected : SidebarBg;
            btn.ForeColor = selected ? Accent : TextMuted;
            btn.Font = new Font("Segoe UI", 10f, selected ? FontStyle.Bold : FontStyle.Regular);
        }

        private Button MakeChromeButton(string text, EventHandler onClick)
        {
            var btn = new Button
            {
                Text = text,
                AutoSize = true,
                MinimumSize = new Size(100, 32),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(0x35, 0x36, 0x3A),
                ForeColor = TextPrimary,
                Font = new Font("Segoe UI", 9f),
                Cursor = Cursors.Hand,
                Margin = new Padding(0, 0, 8, 6),
                Padding = new Padding(10, 4, 10, 4)
            };
            btn.FlatAppearance.BorderColor = BorderSoft;
            btn.FlatAppearance.BorderSize = 1;
            btn.Click += onClick;
            return btn;
        }

        private Button MakeAccentButton(string text, EventHandler onClick)
        {
            var btn = MakeChromeButton(text, onClick);
            btn.BackColor = Accent;
            btn.ForeColor = Color.FromArgb(0x20, 0x21, 0x24);
            btn.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
            btn.FlatAppearance.BorderColor = Accent;
            return btn;
        }

        private sealed class DetectionListItem
        {
            public string Summary { get; }
            public string Detail { get; }
            public DetectionListItem(string summary, string detail)
            {
                Summary = summary;
                Detail = detail;
            }
            public override string ToString() => Summary;
        }
    }
}
