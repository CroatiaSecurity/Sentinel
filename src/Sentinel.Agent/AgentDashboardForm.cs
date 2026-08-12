using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
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
        private static readonly Color Border = Color.FromArgb(0x30, 0x33, 0x36);
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

        // Report
        private ListBox? _packList;
        private TextBox? _packMeta;
        private TextBox? _txtName = null!;
        private TextBox? _txtEmail = null!;
        private TextBox? _txtPhone = null!;
        private TextBox? _txtAddress = null!;
        private TextBox? _txtNationalId = null!;
        private ComboBox? _cmbRelationship = null!;
        private TextBox? _txtNarrative = null!;
        private TextBox? _txtLoss = null!;
        private TextBox? _txtDataAffected = null!;
        private TextBox? _txtOtherHarm = null!;
        private ComboBox? _cmbCountry = null!;
        private CheckBox? _chkConsentFile = null!;
        private CheckBox? _chkConsentEvidence = null!;
        private CheckBox? _chkConsentTruth = null!;
        private Label? _reportStatus = null!;
        private readonly List<IncidentPackInfo> _packs = new();

        // Quarantine
        private ListBox? _quarantineList;

        // Tools
        private TextBox? _toolsInfo;

        // Ops (v2.0)
        private TextBox? _opsInfo;

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
            // Dock order: top first, then fill, then bottom — reverse add order for Dock
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

            // Report to Police stays in Settings; tray no longer deep-links here.
            // v2.0: Ops page for pipeline metrics (events/sec, correlation, monitors).
            string[] navLabels = { "Overview", "Events", "Report to Police", "Quarantine", "Safety", "Ops", "Tools", "About" };
            for (int i = 0; i < navLabels.Length; i++)
            {
                var idx = i;
                var btn = CreateNavButton(navLabels[i], () => ShowPage(idx));
                btn.Dock = DockStyle.Top;
                _navButtons.Add(btn);
            }
            // Dock Top stacks reverse of add order — add bottom-up
            for (int i = _navButtons.Count - 1; i >= 0; i--)
                navHost.Controls.Add(_navButtons[i]);

            // ── Content ──
            _contentHost = new Panel { Dock = DockStyle.Fill, BackColor = Bg, Padding = new Padding(0) };
            root.Controls.Add(_contentHost, 1, 0);

            _pages = new Panel[]
            {
                BuildOverviewPage(),
                BuildEventsPage(),
                BuildReportPage(),
                BuildQuarantinePage(),
                BuildSafetyPage(),
                BuildOpsPage(),
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

        /// <summary>Select sidebar page by index (0 Overview … 2 Report to Police …).</summary>
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
            else if (index == 2) RefreshPacks();
            else if (index == 3) RefreshQuarantine();
            else if (index == 5) RefreshOps();
            else if (index == 6) RefreshTools();
        }

        private void RefreshAll()
        {
            RefreshOverview();
            RefreshEvents();
            RefreshPacks();
            RefreshQuarantine();
            RefreshOps();
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
                RowCount = 4,
                BackColor = Bg
            };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 160));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            page.Controls.Add(layout);

            var title = MakeTitle("Protection overview");
            title.Dock = DockStyle.Fill;
            layout.Controls.Add(title, 0, 0);

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
            quick.Controls.Add(MakeChromeButton("Open Quarantine", (_, _) => OpenFolder(_quarantine.QuarantineDirectory)));
            quick.Controls.Add(MakeChromeButton("Open Data Folder", (_, _) => OpenFolder(ProgramDataRoot)));
            quick.Controls.Add(MakeAccentButton("Copy Diagnostics", (_, _) => CopyDiagnostics()));
            layout.Controls.Add(quick, 0, 2);

            var recentHeader = new Label
            {
                Text = "Recent detections",
                Font = new Font("Segoe UI", 11f, FontStyle.Bold),
                ForeColor = TextPrimary,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };
            layout.Controls.Add(recentHeader, 0, 3);

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
            var portal = LawEnforcementPortals.Resolve(_reportConfig.CountryCode);

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
                    $"Police portal region: {portal.CountryName} — {portal.PrimaryPortalName}\n" +
                    (lastDet != null ? $"Latest detection: {lastDet.Summary}" : "Latest detection: none yet") +
                    "\nActive response is controlled by the Sentinel service (SYSTEM).";
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
        // Report to Police
        // ═══════════════════════════════════════════════════════════════

        private Panel BuildReportPage()
        {
            var page = new Panel { BackColor = Bg, Padding = new Padding(20, 16, 20, 12) };
            var root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1,
                BackColor = Bg
            };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 300));
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            page.Controls.Add(root);

            // Left: pack list
            var left = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                BackColor = Bg
            };
            left.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
            left.RowStyles.Add(new RowStyle(SizeType.Percent, 70));
            left.RowStyles.Add(new RowStyle(SizeType.Percent, 30));
            root.Controls.Add(left, 0, 0);

            var leftHeader = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight };
            leftHeader.Controls.Add(MakeTitle("Evidence packs"));
            var refreshBtn = MakeChromeButton("Refresh", (_, _) => RefreshPacks());
            refreshBtn.Margin = new Padding(8, 2, 0, 0);
            leftHeader.Controls.Add(refreshBtn);
            left.Controls.Add(leftHeader, 0, 0);

            _packList = MakeListBox();
            _packList.Dock = DockStyle.Fill;
            _packList.SelectedIndexChanged += (_, _) => OnPackSelected();
            left.Controls.Add(_packList, 0, 1);

            _packMeta = MakeMultiline(readOnly: true);
            _packMeta.Dock = DockStyle.Fill;
            left.Controls.Add(_packMeta, 0, 2);

            // Right: editor + actions
            var right = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                BackColor = Bg,
                Padding = new Padding(12, 0, 0, 0)
            };
            right.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
            right.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            right.RowStyles.Add(new RowStyle(SizeType.Absolute, 96));
            root.Controls.Add(right, 1, 0);

            right.Controls.Add(MakeTitle("File with law enforcement"), 0, 0);

            var scroll = new Panel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                BackColor = Bg
            };
            right.Controls.Add(scroll, 0, 1);

            var form = new TableLayoutPanel
            {
                ColumnCount = 2,
                AutoSize = true,
                Dock = DockStyle.Top,
                BackColor = Bg,
                Padding = new Padding(0, 0, 12, 0)
            };
            form.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 140));
            form.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            scroll.Controls.Add(form);

            int row = 0;
            void AddField(string label, Control field, int height = 28)
            {
                form.RowStyles.Add(new RowStyle(SizeType.Absolute, height + 10));
                var lbl = new Label
                {
                    Text = label,
                    ForeColor = TextMuted,
                    Dock = DockStyle.Fill,
                    TextAlign = ContentAlignment.MiddleLeft
                };
                field.Dock = DockStyle.Fill;
                field.Height = height;
                form.Controls.Add(lbl, 0, row);
                form.Controls.Add(field, 1, row);
                row++;
            }

            _txtName = MakeTextBox();
            _txtEmail = MakeTextBox();
            _txtPhone = MakeTextBox();
            _txtAddress = MakeTextBox();
            _txtNationalId = MakeTextBox();
            _cmbRelationship = MakeComboBox(new[] { "owner", "authorized user", "administrator", "other" });
            _txtNarrative = MakeMultiline(readOnly: false);
            _txtNarrative.Height = 90;
            _txtLoss = MakeTextBox();
            _txtDataAffected = MakeTextBox();
            _txtOtherHarm = MakeTextBox();
            _cmbCountry = MakeComboBox(Array.Empty<string>());
            PopulateCountries(_cmbCountry);

            AddField("Full name *", _txtName);
            AddField("Email", _txtEmail);
            AddField("Phone", _txtPhone);
            AddField("Address", _txtAddress);
            AddField("National ID", _txtNationalId);
            AddField("I am the…", _cmbRelationship);
            form.RowStyles.Add(new RowStyle(SizeType.Absolute, 100));
            form.Controls.Add(new Label { Text = "Narrative", ForeColor = TextMuted, Dock = DockStyle.Fill, TextAlign = ContentAlignment.TopLeft, Padding = new Padding(0, 6, 0, 0) }, 0, row);
            form.Controls.Add(_txtNarrative, 1, row);
            row++;
            AddField("Financial loss", _txtLoss);
            AddField("Data affected", _txtDataAffected);
            AddField("Other harm", _txtOtherHarm);
            AddField("Filing country", _cmbCountry);

            _chkConsentFile = MakeCheck("I want to file a formal complaint with law enforcement / the national portal.");
            _chkConsentEvidence = MakeCheck("I authorize investigators to examine this evidence pack and quarantined samples.");
            _chkConsentTruth = MakeCheck("I understand false statements to authorities may be a criminal offense.");
            foreach (var chk in new[] { _chkConsentFile, _chkConsentEvidence, _chkConsentTruth })
            {
                form.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
                form.SetColumnSpan(chk, 2);
                form.Controls.Add(chk, 0, row);
                row++;
            }

            var note = new Label
            {
                Text = "Sentinel prepares sealed evidence for you. It does not submit complaints to INTERPOL, IC3, or any police API. " +
                       "Save the affidavit, then Send Report opens your national portal and the pack folder so you can attach the .zip.",
                ForeColor = TextDim,
                Dock = DockStyle.Fill,
                AutoSize = false,
                Height = 48
            };
            form.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
            form.SetColumnSpan(note, 2);
            form.Controls.Add(note, 0, row);
            row++;

            // Action bar
            var actions = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = true,
                BackColor = PanelBg,
                Padding = new Padding(10, 10, 10, 6)
            };
            actions.Controls.Add(MakeAccentButton("Save Affidavit", OnSaveAffidavit));
            actions.Controls.Add(MakeGreenButton("Send Report to Police", OnSendReport));
            actions.Controls.Add(MakeChromeButton("Open Pack Folder", OnOpenPackFolder));
            actions.Controls.Add(MakeChromeButton("Open ZIP", OnOpenZip));
            actions.Controls.Add(MakeChromeButton("Copy Summary", OnCopySummary));
            actions.Controls.Add(MakeChromeButton("Verify Integrity", OnVerifyIntegrity));
            actions.Controls.Add(MakeChromeButton("Open Portal Only", OnOpenPortalOnly));
            right.Controls.Add(actions, 0, 2);

            _reportStatus = new Label
            {
                Text = "",
                ForeColor = TextMuted,
                AutoSize = true,
                Margin = new Padding(8, 14, 0, 0)
            };
            actions.Controls.Add(_reportStatus);

            LoadPrefsIntoForm();
            return page;
        }

        private void LoadPrefsIntoForm()
        {
            var prefs = UserReportPrefs.Load();
            // Config prefill wins only when prefs empty
            if (string.IsNullOrWhiteSpace(prefs.FullName) && !string.IsNullOrWhiteSpace(_reportConfig.VictimFullName))
                prefs.FullName = _reportConfig.VictimFullName!;
            if (string.IsNullOrWhiteSpace(prefs.Email) && !string.IsNullOrWhiteSpace(_reportConfig.VictimEmail))
                prefs.Email = _reportConfig.VictimEmail!;
            if (string.IsNullOrWhiteSpace(prefs.Phone) && !string.IsNullOrWhiteSpace(_reportConfig.VictimPhone))
                prefs.Phone = _reportConfig.VictimPhone!;
            if (string.IsNullOrWhiteSpace(prefs.Address) && !string.IsNullOrWhiteSpace(_reportConfig.VictimAddress))
                prefs.Address = _reportConfig.VictimAddress!;

            _txtName!.Text = prefs.FullName;
            _txtEmail!.Text = prefs.Email;
            _txtPhone!.Text = prefs.Phone;
            _txtAddress!.Text = prefs.Address;
            _txtNationalId!.Text = prefs.NationalId;
            SelectCombo(_cmbRelationship!, prefs.Relationship);
            _txtNarrative!.Text = prefs.AdditionalNarrative;
            _txtLoss!.Text = prefs.FinancialLoss;
            _txtDataAffected!.Text = prefs.DataAffected;
            _txtOtherHarm!.Text = prefs.OtherHarm;

            var country = prefs.PreferredCountryCode
                ?? _reportConfig.CountryCode
                ?? LawEnforcementPortals.DetectSystemCountryCode();
            SelectCountry(_cmbCountry!, country);
        }

        private void RefreshPacks()
        {
            _packs.Clear();
            if (_packList == null) return;

            var root = GetReportRoot();
            try
            {
                if (Directory.Exists(root))
                {
                    foreach (var dir in Directory.EnumerateDirectories(root, "AUTO_*")
                                 .OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase))
                    {
                        _packs.Add(IncidentPackInfo.FromDirectory(dir));
                    }
                }
            }
            catch (Exception ex)
            {
                _statusLabel.Text = $"Could not list packs: {ex.Message}";
            }

            _packList.BeginUpdate();
            _packList.Items.Clear();
            foreach (var p in _packs)
                _packList.Items.Add(p);
            if (_packList.Items.Count == 0)
                _packList.Items.Add("(No evidence packs yet — high-confidence attacks create them automatically)");
            _packList.EndUpdate();

            if (_packs.Count > 0)
            {
                _packList.SelectedIndex = 0;
            }
            else if (_packMeta != null)
            {
                _packMeta.Text = "No packs available. When Sentinel kills or isolates a reportable-grade attack, " +
                                 "a sealed evidence pack appears here for filing.";
            }

            _statusLabel.Text = $"{_packs.Count} evidence pack(s)";
        }

        private void OnPackSelected()
        {
            if (_packList?.SelectedItem is not IncidentPackInfo pack || _packMeta == null)
                return;

            var verify = AutoIncidentReporter.VerifyPackIntegrity(pack.Directory);
            var sb = new StringBuilder();
            sb.AppendLine(pack.ReportId);
            sb.AppendLine($"Rule: {pack.Rule}");
            sb.AppendLine($"Confidence: {pack.Confidence}");
            sb.AppendLine($"Process: {pack.Process}");
            sb.AppendLine($"Portal: {pack.PortalUrl}");
            sb.AppendLine($"Integrity: {(verify.Ok ? "OK" : verify.Message)}");
            sb.AppendLine($"ZIP: {(pack.ZipPath != null && File.Exists(pack.ZipPath) ? Path.GetFileName(pack.ZipPath) : "none")}");
            sb.AppendLine(pack.Directory);
            _packMeta.Text = sb.ToString();

            // Load affidavit fields if present
            TryLoadAffidavitFromPack(pack);

            if (!string.IsNullOrWhiteSpace(pack.CountryCode))
                SelectCountry(_cmbCountry!, pack.CountryCode);
        }

        private void TryLoadAffidavitFromPack(IncidentPackInfo pack)
        {
            var path = Path.Combine(pack.Directory, "victim_affidavit.txt");
            if (!File.Exists(path)) return;
            try
            {
                var text = File.ReadAllText(path);
                ApplyIfPresent(text, @"Full legal name:\s*(.+)$", v => { if (!IsBlankTemplate(v)) _txtName!.Text = v; });
                ApplyIfPresent(text, @"Email:\s*(.+)$", v => { if (!IsBlankTemplate(v)) _txtEmail!.Text = v; });
                ApplyIfPresent(text, @"Phone:\s*(.+)$", v => { if (!IsBlankTemplate(v)) _txtPhone!.Text = v; });
                ApplyIfPresent(text, @"Address:\s*(.+)$", v => { if (!IsBlankTemplate(v)) _txtAddress!.Text = v; });
                ApplyIfPresent(text, @"National ID / other:\s*(.+)$", v => { if (!IsBlankTemplate(v)) _txtNationalId!.Text = v; });
                ApplyIfPresent(text, @"Estimated financial loss[^:]*:\s*(.+)$", v => { if (!IsBlankTemplate(v)) _txtLoss!.Text = v; });
                ApplyIfPresent(text, @"Data or accounts affected:\s*(.+)$", v => { if (!IsBlankTemplate(v)) _txtDataAffected!.Text = v; });
                ApplyIfPresent(text, @"Other harm:\s*(.+)$", v => { if (!IsBlankTemplate(v)) _txtOtherHarm!.Text = v; });

                // Narrative block: lines after "Additional narrative"
                var narrativeMatch = Regex.Match(text,
                    @"Additional narrative[^\r\n]*\r?\n(?<body>(?:[ \t].*\r?\n){1,12})",
                    RegexOptions.IgnoreCase);
                if (narrativeMatch.Success)
                {
                    var body = narrativeMatch.Groups["body"].Value;
                    var lines = body.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(l => l.Trim().Trim('_'))
                        .Where(l => !string.IsNullOrWhiteSpace(l) && !l.All(c => c == '_'))
                        .ToList();
                    if (lines.Count > 0)
                        _txtNarrative!.Text = string.Join(Environment.NewLine, lines);
                }
            }
            catch { /* keep form prefs */ }
        }

        private static void ApplyIfPresent(string text, string pattern, Action<string> apply)
        {
            var m = Regex.Match(text, pattern, RegexOptions.Multiline | RegexOptions.IgnoreCase);
            if (m.Success)
                apply(m.Groups[1].Value.Trim());
        }

        private static bool IsBlankTemplate(string v) =>
            string.IsNullOrWhiteSpace(v) || v.All(c => c == '_' || char.IsWhiteSpace(c));

        private IncidentPackInfo? SelectedPack() =>
            _packList?.SelectedItem as IncidentPackInfo;

        private void OnSaveAffidavit(object? sender, EventArgs e)
        {
            var pack = SelectedPack();
            if (pack == null)
            {
                MessageBox.Show(this,
                    "Select an evidence pack first. Packs appear after reportable-grade detections.",
                    "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            if (string.IsNullOrWhiteSpace(_txtName!.Text))
            {
                MessageBox.Show(this, "Full name is required for the affidavit.", "Sentinel",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            try
            {
                var portal = ResolveSelectedPortal();
                var text = BuildAffidavitText(pack, portal);
                File.WriteAllText(Path.Combine(pack.Directory, "victim_affidavit.txt"), text, Encoding.UTF8);
                SaveFormToPrefs();
                // Rebuild zip so filing package includes updated affidavit
                TryRebuildZip(pack);
                _reportStatus!.Text = "Affidavit saved";
                _reportStatus.ForeColor = Green;
                _statusLabel.Text = "Affidavit saved (excluded from integrity seal by design)";
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Failed to save affidavit: {ex.Message}", "Sentinel",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OnSendReport(object? sender, EventArgs e)
        {
            var pack = SelectedPack();
            if (pack == null)
            {
                // Still allow opening portal with no pack (manual filing)
                if (MessageBox.Show(this,
                        "No evidence pack selected. Open the national cybercrime portal anyway?",
                        "Sentinel", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                    return;
                OpenUrl(ResolveSelectedPortal().PrimaryPortalUrl);
                return;
            }

            if (string.IsNullOrWhiteSpace(_txtName!.Text))
            {
                MessageBox.Show(this, "Enter your full name before filing.", "Sentinel",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (_chkConsentFile != null && !_chkConsentFile.Checked)
            {
                MessageBox.Show(this,
                    "Check the consent box confirming you want to file a formal complaint.",
                    "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (_chkConsentTruth != null && !_chkConsentTruth.Checked)
            {
                MessageBox.Show(this,
                    "Confirm that you understand false statements may be a criminal offense.",
                    "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            try
            {
                var portal = ResolveSelectedPortal();
                var text = BuildAffidavitText(pack, portal);
                File.WriteAllText(Path.Combine(pack.Directory, "victim_affidavit.txt"), text, Encoding.UTF8);
                SaveFormToPrefs();
                TryRebuildZip(pack);

                // Clipboard helper for portal forms
                var summary = BuildFilingClipboard(pack, portal);
                try { Clipboard.SetText(summary); } catch { }

                OpenUrl(portal.PrimaryPortalUrl);

                var folder = pack.ZipPath != null && File.Exists(pack.ZipPath)
                    ? Path.GetDirectoryName(pack.ZipPath)!
                    : pack.Directory;
                try
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "explorer.exe",
                        UseShellExecute = true,
                        Arguments = folder
                    });
                }
                catch { }

                _reportStatus!.Text = "Portal opened — attach ZIP on the website";
                _reportStatus.ForeColor = Green;
                _statusLabel.Text = $"Filing: {portal.PrimaryPortalName}";

                MessageBox.Show(this,
                    $"Opened {portal.PrimaryPortalName}.\n\n" +
                    "A filing summary was copied to the clipboard.\n" +
                    "Attach the evidence .zip (and .zip.sha256 if present) on the portal form.\n\n" +
                    $"Pack folder:\n{pack.Directory}\n\n" +
                    "Sentinel does not file the complaint for you — complete the portal steps.",
                    "Report to police",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Send report failed: {ex.Message}", "Sentinel",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OnOpenPackFolder(object? sender, EventArgs e)
        {
            var pack = SelectedPack();
            if (pack == null)
            {
                var root = GetReportRoot();
                if (Directory.Exists(root))
                    OpenFolder(root);
                else
                    MessageBox.Show(this, "No evidence packs directory yet.", "Sentinel",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            OpenFolder(pack.Directory);
        }

        private void OnOpenZip(object? sender, EventArgs e)
        {
            var pack = SelectedPack();
            if (pack?.ZipPath == null || !File.Exists(pack.ZipPath))
            {
                MessageBox.Show(this, "No ZIP export for this pack.", "Sentinel",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    UseShellExecute = true,
                    Arguments = "/select,\"" + pack.ZipPath + "\""
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OnCopySummary(object? sender, EventArgs e)
        {
            var pack = SelectedPack();
            if (pack == null)
            {
                MessageBox.Show(this, "Select a pack first.", "Sentinel",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            try
            {
                Clipboard.SetText(BuildFilingClipboard(pack, ResolveSelectedPortal()));
                _reportStatus!.Text = "Summary copied";
                _reportStatus.ForeColor = Accent;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OnVerifyIntegrity(object? sender, EventArgs e)
        {
            var pack = SelectedPack();
            if (pack == null)
            {
                MessageBox.Show(this, "Select a pack first.", "Sentinel",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            var result = AutoIncidentReporter.VerifyPackIntegrity(pack.Directory);
            MessageBox.Show(this,
                result.Ok
                    ? "Integrity OK — sealed evidence hashes and HMAC match."
                    : $"Integrity check failed:\n{result.Message}",
                "Verify pack",
                MessageBoxButtons.OK,
                result.Ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            OnPackSelected();
        }

        private void OnOpenPortalOnly(object? sender, EventArgs e)
        {
            var portal = ResolveSelectedPortal();
            OpenUrl(portal.PrimaryPortalUrl);
            _statusLabel.Text = portal.PrimaryPortalUrl;
        }

        private LawEnforcementPortals.PortalEntry ResolveSelectedPortal()
        {
            string? code = null;
            if (_cmbCountry?.SelectedItem is CountryItem ci)
                code = ci.Code;
            else if (!string.IsNullOrWhiteSpace(_reportConfig.CountryCode))
                code = _reportConfig.CountryCode;
            return LawEnforcementPortals.Resolve(code);
        }

        private string BuildAffidavitText(IncidentPackInfo pack, LawEnforcementPortals.PortalEntry portal)
        {
            var name = _txtName!.Text.Trim();
            var email = BlankOr(_txtEmail!.Text);
            var phone = BlankOr(_txtPhone!.Text);
            var address = BlankOr(_txtAddress!.Text);
            var nationalId = BlankOr(_txtNationalId!.Text);
            var relationship = _cmbRelationship!.SelectedItem?.ToString() ?? "owner";
            var narrative = string.IsNullOrWhiteSpace(_txtNarrative!.Text)
                ? "___________________________________________________________________________"
                : _txtNarrative.Text.Trim();
            var loss = BlankOr(_txtLoss!.Text);
            var data = BlankOr(_txtDataAffected!.Text);
            var harm = BlankOr(_txtOtherHarm!.Text);

            string Mark(CheckBox? c) => c != null && c.Checked ? "[x]" : "[ ]";

            var sb = new StringBuilder();
            sb.AppendLine("VICTIM / COMPLAINANT AFFIDAVIT");
            sb.AppendLine("==============================");
            sb.AppendLine();
            sb.AppendLine("Completed via Sentinel Agent filing UI. Sign only if true to the best of your knowledge.");
            sb.AppendLine();
            sb.AppendLine($"Linked evidence pack:  {pack.ReportId}");
            sb.AppendLine($"Detection rule:        {pack.Rule}");
            sb.AppendLine($"Detection time (UTC):  {pack.DetectedAt ?? "see incident_report.txt"}");
            sb.AppendLine($"Recommended portal:    {portal.PrimaryPortalName}");
            sb.AppendLine($"Portal URL:            {portal.PrimaryPortalUrl}");
            sb.AppendLine($"Affidavit saved (UTC): {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();
            sb.AppendLine("1. COMPLAINANT IDENTITY");
            sb.AppendLine($"   Full legal name:     {name}");
            sb.AppendLine($"   Email:               {email}");
            sb.AppendLine($"   Phone:               {phone}");
            sb.AppendLine($"   Address:             {address}");
            sb.AppendLine($"   National ID / other: {nationalId}");
            sb.AppendLine();
            sb.AppendLine("2. RELATIONSHIP TO THE AFFECTED SYSTEM");
            sb.AppendLine($"   Machine name:        {Environment.MachineName}");
            sb.AppendLine($"   Windows account:     {Environment.UserDomainName}\\{Environment.UserName}");
            sb.AppendLine($"   I am the:            {relationship}");
            sb.AppendLine();
            sb.AppendLine("3. STATEMENT OF FACTS");
            sb.AppendLine("   I state that the computer system identified in this pack was the subject of");
            sb.AppendLine("   suspected unauthorized access, malware activity, or computer interference.");
            sb.AppendLine("   Sentinel automatically detected the activity, applied a defensive response");
            sb.AppendLine("   where authorized, and generated the accompanying integrity-sealed evidence package.");
            sb.AppendLine();
            sb.AppendLine($"   Observed rule / behaviour: {pack.Rule}");
            sb.AppendLine($"   Process involved:          {pack.Process}");
            sb.AppendLine($"   Confidence score:          {pack.Confidence}");
            sb.AppendLine();
            sb.AppendLine("   Additional narrative:");
            foreach (var line in narrative.Replace("\r\n", "\n").Split('\n'))
                sb.AppendLine($"   {line}");
            sb.AppendLine();
            sb.AppendLine("4. LOSS / HARM (if any)");
            sb.AppendLine($"   Estimated financial loss (currency): {loss}");
            sb.AppendLine($"   Data or accounts affected: {data}");
            sb.AppendLine($"   Other harm: {harm}");
            sb.AppendLine();
            sb.AppendLine("5. CONSENT");
            sb.AppendLine($"   {Mark(_chkConsentFile)} I wish to file a formal complaint with law enforcement / the portal above.");
            sb.AppendLine($"   {Mark(_chkConsentEvidence)} I authorize investigators to examine the attached evidence pack and,");
            sb.AppendLine("       where lawfully required, quarantined malware samples from this host.");
            sb.AppendLine($"   {Mark(_chkConsentTruth)} I understand false statements to authorities may be a criminal offense.");
            sb.AppendLine();
            sb.AppendLine("6. SIGNATURE");
            sb.AppendLine("   I declare that the information I completed above is true and correct to the");
            sb.AppendLine("   best of my knowledge.");
            sb.AppendLine();
            sb.AppendLine($"   Printed name: {name}");
            sb.AppendLine("   Signature: _______________________________    Date: _______________");
            sb.AppendLine("   Place: ___________________________________");
            sb.AppendLine();
            sb.AppendLine("Attach: incident_report.txt, indicators.txt, MANIFEST.sha256, chain_of_custody.txt,");
            sb.AppendLine("and the .zip export if filing electronically.");
            return sb.ToString();
        }

        private string BuildFilingClipboard(IncidentPackInfo pack, LawEnforcementPortals.PortalEntry portal)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Sentinel cybercrime filing summary");
            sb.AppendLine($"Complainant: {_txtName!.Text.Trim()}");
            if (!string.IsNullOrWhiteSpace(_txtEmail!.Text)) sb.AppendLine($"Email: {_txtEmail.Text.Trim()}");
            if (!string.IsNullOrWhiteSpace(_txtPhone!.Text)) sb.AppendLine($"Phone: {_txtPhone.Text.Trim()}");
            sb.AppendLine($"Machine: {Environment.MachineName}");
            sb.AppendLine($"Report ID: {pack.ReportId}");
            sb.AppendLine($"Rule: {pack.Rule}");
            sb.AppendLine($"Process: {pack.Process}");
            sb.AppendLine($"Confidence: {pack.Confidence}");
            sb.AppendLine($"Portal: {portal.PrimaryPortalName}");
            sb.AppendLine($"Portal URL: {portal.PrimaryPortalUrl}");
            if (pack.ZipPath != null && File.Exists(pack.ZipPath))
                sb.AppendLine($"ZIP path: {pack.ZipPath}");
            sb.AppendLine($"Pack folder: {pack.Directory}");
            if (!string.IsNullOrWhiteSpace(_txtNarrative!.Text))
            {
                sb.AppendLine();
                sb.AppendLine("Narrative:");
                sb.AppendLine(_txtNarrative.Text.Trim());
            }
            try
            {
                var ind = Path.Combine(pack.Directory, "indicators.txt");
                if (File.Exists(ind))
                {
                    sb.AppendLine();
                    sb.AppendLine("Indicators:");
                    sb.AppendLine(File.ReadAllText(ind));
                }
            }
            catch { }
            return sb.ToString();
        }

        private void SaveFormToPrefs()
        {
            var prefs = new UserReportPrefs
            {
                FullName = _txtName!.Text.Trim(),
                Email = _txtEmail!.Text.Trim(),
                Phone = _txtPhone!.Text.Trim(),
                Address = _txtAddress!.Text.Trim(),
                NationalId = _txtNationalId!.Text.Trim(),
                Relationship = _cmbRelationship!.SelectedItem?.ToString() ?? "owner",
                AdditionalNarrative = _txtNarrative!.Text.Trim(),
                FinancialLoss = _txtLoss!.Text.Trim(),
                DataAffected = _txtDataAffected!.Text.Trim(),
                OtherHarm = _txtOtherHarm!.Text.Trim(),
                PreferredCountryCode = (_cmbCountry!.SelectedItem as CountryItem)?.Code
            };
            prefs.Save();
        }

        private static void TryRebuildZip(IncidentPackInfo pack)
        {
            try
            {
                if (pack.ZipPath == null) return;
                if (File.Exists(pack.ZipPath))
                    File.Delete(pack.ZipPath);
                System.IO.Compression.ZipFile.CreateFromDirectory(
                    pack.Directory, pack.ZipPath,
                    System.IO.Compression.CompressionLevel.Optimal,
                    includeBaseDirectory: false);

                // Update zip hash if sidecar existed or always write for transport integrity
                using var sha = System.Security.Cryptography.SHA256.Create();
                using var fs = new FileStream(pack.ZipPath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                var hash = ConvertHex.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
                File.WriteAllText(pack.ZipPath + ".sha256",
                    $"{hash}  {Path.GetFileName(pack.ZipPath)}{Environment.NewLine}");
            }
            catch
            {
                // Affidavit is saved; zip rebuild is best-effort
            }
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
            bar.Controls.Add(MakeAccentButton("Open Folder", (_, _) => OpenFolder(_quarantine.QuarantineDirectory)));
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
            bar.Controls.Add(MakeChromeButton("Quarantine", (_, _) => OpenFolder(_quarantine.QuarantineDirectory)));
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
            sb.AppendLine($"  Quarantine:  {_quarantine.QuarantineDirectory}");
            sb.AppendLine($"  Evidence:    {GetReportRoot()}  ({CountPacks()} packs)");
            sb.AppendLine();
            sb.AppendLine("Config note:");
            sb.AppendLine("  ActiveResponse / kill policy is owned by Sentinel.Service (SYSTEM).");
            sb.AppendLine("  Report to Police is available under Settings (not the tray menu).");
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
                    UseShellExecute = true,
                    Arguments = "\"" + path + "\""
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // Ops (v2.0 — pipeline metrics from service ops_metrics.json)
        // ═══════════════════════════════════════════════════════════════

        private Panel BuildOpsPage()
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
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
            page.Controls.Add(layout);
            layout.Controls.Add(MakeTitle("Ops / Diagnostics"), 0, 0);

            _opsInfo = MakeMultiline(readOnly: true);
            _opsInfo.Dock = DockStyle.Fill;
            layout.Controls.Add(_opsInfo, 0, 1);

            var bar = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                BackColor = Bg,
                Padding = new Padding(0, 8, 0, 0)
            };
            bar.Controls.Add(MakeChromeButton("Refresh", (_, _) => RefreshOps()));
            bar.Controls.Add(MakeChromeButton("Open ops_metrics.json", (_, _) =>
            {
                var path = Path.Combine(ProgramDataRoot, "ops_metrics.json");
                OpenFileIfExists(path, "No ops_metrics.json yet. Is Sentinel.Service running?");
            }));
            layout.Controls.Add(bar, 0, 2);
            return page;
        }

        private void RefreshOps()
        {
            if (_opsInfo == null) return;
            try
            {
                // Prefer authenticated IPC (live); fall back to ops_metrics.json on disk.
                string? source = null;
                JsonElement r = default;
                bool fromIpc = false;

                try
                {
                    var ipcJson = ServiceAgentIpcClient.Request("ops");
                    if (!string.IsNullOrEmpty(ipcJson))
                    {
                        using var ipcDoc = JsonDocument.Parse(ipcJson!);
                        if (ipcDoc.RootElement.TryGetProperty("ok", out var okEl) && okEl.GetBoolean() &&
                            ipcDoc.RootElement.TryGetProperty("ops", out var opsEl))
                        {
                            // Re-parse ops object as standalone document for GetJson helpers
                            var opsRaw = opsEl.GetRawText();
                            using var opsDoc = JsonDocument.Parse(opsRaw);
                            r = opsDoc.RootElement.Clone();
                            fromIpc = true;
                            source = "IPC (authenticated named pipe)";
                        }
                    }
                }
                catch { /* fall through to file */ }

                if (!fromIpc)
                {
                    var path = Path.Combine(ProgramDataRoot, "ops_metrics.json");
                    if (!File.Exists(path))
                    {
                        _opsInfo.Text =
                            "No ops metrics yet.\n\n" +
                            "The service publishes metrics via:\n" +
                            "  • Authenticated named pipe SentinelIpc-v2 (live)\n" +
                            "  • %ProgramData%\\Sentinel\\ops_metrics.json (every ~10s)\n\n" +
                            "Start/restart the Sentinel service and click Refresh.";
                        return;
                    }
                    var json = File.ReadAllText(path);
                    using var doc = JsonDocument.Parse(json);
                    r = doc.RootElement.Clone();
                    source = "ops_metrics.json (file)";
                }
                var sb = new StringBuilder();
                sb.AppendLine("SENTINEL OPS SNAPSHOT (v2.0)");
                sb.AppendLine("===========================");
                sb.AppendLine();
                sb.AppendLine($"  Source:              {source ?? "—"}");
                sb.AppendLine($"  Product version:     {GetJsonString(r, "ProductVersion")}");
                sb.AppendLine($"  Snapshot (UTC):      {GetJsonString(r, "TimestampUtc")}");
                sb.AppendLine();
                sb.AppendLine("Throughput");
                sb.AppendLine($"  Telemetry/sec:       {GetJsonNumber(r, "TelemetryPerSecond")}");
                sb.AppendLine($"  Detections/sec:      {GetJsonNumber(r, "DetectionsPerSecond")}");
                sb.AppendLine($"  Telemetry total:     {GetJsonNumber(r, "TelemetryReceived")}");
                sb.AppendLine($"  Telemetry pressure:  {GetJsonNumber(r, "TelemetryDropped")} (near-capacity writes)");
                sb.AppendLine($"  Detections total:    {GetJsonNumber(r, "DetectionsTotal")}");
                sb.AppendLine($"  Responses total:     {GetJsonNumber(r, "ResponsesTotal")}");
                sb.AppendLine();
                sb.AppendLine("Correlation");
                sb.AppendLine($"  Hand-authored composites: {GetJsonNumber(r, "CompositesEmitted")}");
                sb.AppendLine($"  Weighted composites:      {GetJsonNumber(r, "WeightedCompositesEmitted")}");
                sb.AppendLine($"  Chain-confirmed:          {GetJsonNumber(r, "ChainConfirmed")}");
                sb.AppendLine($"  Weighted enabled:         {GetJsonString(r, "WeightedCorrelationEnabled")}");
                sb.AppendLine($"  Weighted threshold:       {GetJsonNumber(r, "WeightedThreshold")}");
                sb.AppendLine();
                sb.AppendLine("Latency (ms)");
                sb.AppendLine($"  Detection p50/p95:    {GetJsonNumber(r, "DetectionLatencyMsP50")} / {GetJsonNumber(r, "DetectionLatencyMsP95")}");
                sb.AppendLine($"  Response  p50/p95:    {GetJsonNumber(r, "ResponseLatencyMsP50")} / {GetJsonNumber(r, "ResponseLatencyMsP95")}");
                sb.AppendLine($"  Correlation p50/p95:  {GetJsonNumber(r, "CorrelationLatencyMsP50")} / {GetJsonNumber(r, "CorrelationLatencyMsP95")}");
                sb.AppendLine();
                sb.AppendLine("Health");
                sb.AppendLine($"  Monitors registered:  {GetJsonNumber(r, "RegisteredMonitors")}");
                sb.AppendLine($"  Monitors running:     {GetJsonNumber(r, "RunningMonitors")}");
                sb.AppendLine($"  Plugins loaded:       {GetJsonNumber(r, "PluginCount")}");
                sb.AppendLine();
                sb.AppendLine("Explainability");
                sb.AppendLine("  Detection events include ScoreCard* and AttackTechniques metadata");
                sb.AppendLine("  in events.jsonl when weighted correlation is active.");
                _opsInfo.Text = sb.ToString();
            }
            catch (Exception ex)
            {
                _opsInfo.Text = "Failed to read ops metrics:\n" + ex.Message;
            }
        }

        private static string GetJsonString(JsonElement r, string name)
        {
            if (r.TryGetProperty(name, out var p))
            {
                if (p.ValueKind == JsonValueKind.String) return p.GetString() ?? "";
                return p.ToString();
            }
            return "—";
        }

        private static string GetJsonNumber(JsonElement r, string name)
        {
            if (r.TryGetProperty(name, out var p))
            {
                if (p.ValueKind == JsonValueKind.Number) return p.ToString();
                if (p.ValueKind == JsonValueKind.True || p.ValueKind == JsonValueKind.False)
                    return p.GetBoolean().ToString();
                return p.ToString();
            }
            return "—";
        }

        // ═══════════════════════════════════════════════════════════════
        // Safety (digital coercion / surveillance toolkit — platform-agnostic)
        // ═══════════════════════════════════════════════════════════════

        private Panel BuildSafetyPage()
        {
            var page = new Panel { BackColor = Bg, Padding = new Padding(28) };
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 4,
                BackColor = Bg
            };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 160));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
            page.Controls.Add(layout);
            layout.Controls.Add(MakeTitle("Safety"), 0, 0);

            var body = MakeMultiline(readOnly: true);
            body.Dock = DockStyle.Fill;
            body.Text =
                "PROTECTING YOU FROM DIGITAL COERCION TOOLKITS\n" +
                "============================================\n\n" +
                "Sentinel does not identify people as offenders and does not read your chats.\n" +
                "It watches THIS Windows PC for tools predators and stalkers often use:\n\n" +
                "  • Remote control (RATs, abused AnyDesk/TeamViewer-class tools, reverse shells)\n" +
                "  • Covert surveillance (screen / camera / input capture + persistence)\n" +
                "  • Account session theft (browsers, messaging, email, social, games, banking)\n" +
                "  • Extortion malware (exfil + C2 chains)\n\n" +
                "Scope is platform-agnostic: Discord, email, social apps, browsers, games,\n" +
                "voice/video — anything that leaves host traces. Not chat moderation.\n\n" +
                "When a multi-signal chain confirms, Sentinel can kill/quarantine and write a\n" +
                "sealed evidence pack under:\n" +
                $"  {GetReportRoot()}\n\n" +
                "WHAT YOU SHOULD STILL DO\n" +
                "  1. Revoke sessions on important accounts (email, messaging, social, bank).\n" +
                "  2. Turn on 2FA everywhere you can.\n" +
                "  3. Block and report abusers on the platform — Sentinel cannot ban them.\n" +
                "  4. Use Report to Police with a sealed pack for device crimes.\n" +
                "  5. If you are in danger offline, contact emergency services / local support.\n\n" +
                "Honest limit: Sentinel cannot stop offline assault or prove someone's identity\n" +
                "from a Discord ban reason. It stops and documents machine-side abuse tools.\n";
            layout.Controls.Add(body, 0, 1);

            // v2.0.4: Hardened Mode panel
            var hardenPanel = BuildHardenedModePanel();
            layout.Controls.Add(hardenPanel, 0, 2);

            var bar = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                BackColor = Bg,
                Padding = new Padding(0, 8, 0, 0)
            };
            bar.Controls.Add(MakeChromeButton("Open evidence packs", (_, _) => OpenFolder(GetReportRoot())));
            bar.Controls.Add(MakeChromeButton("Open Events log", (_, _) =>
            {
                try
                {
                    var log = Path.Combine(ProgramDataRoot, "events.jsonl");
                    if (File.Exists(log))
                        Process.Start(new ProcessStartInfo { FileName = log, UseShellExecute = true });
                    else
                        MessageBox.Show(this, "No events.jsonl yet.", "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, ex.Message, "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }));
            bar.Controls.Add(MakeChromeButton("Report to Police", (_, _) => ShowPage(2)));
            layout.Controls.Add(bar, 0, 3);
            return page;
        }

        /// <summary>
        /// v2.0.4: Hardened Mode UI panel with toggle and explanation.
        /// Persists to DPAPI-encrypted config store. Requires service restart to apply.
        /// </summary>
        private Panel BuildHardenedModePanel()
        {
            var panel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = System.Drawing.Color.FromArgb(30, 30, 35),
                Padding = new Padding(12)
            };

            var title = new Label
            {
                Text = "\u26a0 HARDENED MODE",
                Font = new System.Drawing.Font("Segoe UI", 10f, System.Drawing.FontStyle.Bold),
                ForeColor = System.Drawing.Color.FromArgb(255, 180, 60),
                AutoSize = true,
                Dock = DockStyle.Top
            };
            panel.Controls.Add(title);

            var desc = new Label
            {
                Text = "Enables aggressive network lockdown: IPSec policy blocks all non-essential ports,\n" +
                       "ASR Block rules are enforced, RPC/DCOM ephemeral ports are firewalled.\n\n" +
                       "USE THIS when you are under active attack or on an untrusted network.\n" +
                       "WARNING: This WILL block RDP, SMB file sharing, SSH, DISM, and some admin tools.\n" +
                       "Normal work (browsers, apps, games) is unaffected.",
                ForeColor = System.Drawing.Color.FromArgb(200, 200, 200),
                AutoSize = true,
                Dock = DockStyle.Top,
                Padding = new Padding(0, 6, 0, 6)
            };
            panel.Controls.Add(desc);
            desc.BringToFront();

            var toggleBtn = MakeChromeButton(
                HardeningModule.RestrictivePortHardeningEnabled ? "\u2705 HARDENED (active)" : "\u274c NORMAL (work-first)",
                (sender, _) => OnToggleHardenedMode(sender));
            toggleBtn.Dock = DockStyle.Bottom;
            panel.Controls.Add(toggleBtn);
            toggleBtn.BringToFront();

            return panel;
        }

        private void OnToggleHardenedMode(object? sender)
        {
            bool current = HardeningModule.RestrictivePortHardeningEnabled;
            bool next = !current;

            string msg = next
                ? "ENABLE Hardened Mode?\n\n" +
                  "This will:\n" +
                  "  • Block all non-essential inbound/outbound ports (IPSec)\n" +
                  "  • Enable ASR Block rules\n" +
                  "  • Firewall RPC/DCOM ephemeral ports\n\n" +
                  "RDP, SMB, SSH, DISM, and some admin tools will stop working.\n" +
                  "Browsers, apps, and games are unaffected.\n\n" +
                  "The Sentinel service must restart for this to take effect."
                : "DISABLE Hardened Mode?\n\n" +
                  "This will return to work-first mode:\n" +
                  "  • Remove IPSec port blocking\n" +
                  "  • Remove Sentinel firewall rules\n" +
                  "  • Release ASR Block policy\n\n" +
                  "Detection and response remain fully active.\n" +
                  "The Sentinel service must restart for this to take effect.";

            var result = MessageBox.Show(this, msg, "Sentinel — Hardened Mode",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);

            if (result != DialogResult.Yes) return;

            try
            {
                var store = new EncryptedConfigStore();
                store.SetOverride("RestrictivePortHardening", next.ToString());
                if (store.Save())
                {
                    MessageBox.Show(this,
                        $"Hardened Mode {(next ? "ENABLED" : "DISABLED")} in config.\n\n" +
                        "Restart the Sentinel service for this to take effect.\n" +
                        "(The service will apply the change on next startup.)",
                        "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Information);

                    // Update button text
                    if (sender is Button btn)
                    {
                        btn.Text = next ? "\u2705 HARDENED (pending restart)" : "\u274c NORMAL (pending restart)";
                    }
                }
                else
                {
                    MessageBox.Show(this,
                        "Failed to save config. Run Sentinel Agent as Administrator,\n" +
                        "or use the command line:\n\n" +
                        $"  Sentinel.Service.exe --set-config RestrictivePortHardening={next}",
                        "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Error: {ex.Message}", "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
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
                "User-session agent for endpoint detection and response.\n" +
                "The Sentinel service (SYSTEM) owns kills, quarantine, and hardening.\n" +
                "This agent owns tray UI, keyboard guards, and filing helpers.\n\n" +
                "v2.0 platform:\n" +
                "  • Weighted multi-signal correlation with explainable score cards\n" +
                "  • MITRE ATT&CK technique tags on detections\n" +
                "  • Plugin interfaces (detectors / correlation / response)\n" +
                "  • Ops dashboard (Settings → Ops)\n" +
                "  • Hardlink-aware self-exclusion + DPAPI machine secret for HMAC keys\n\n" +
                "Digital coercion / surveillance toolkit defense:\n" +
                "  Stops remote-control, stalkerware, and session-theft toolkits on the PC.\n" +
                "  Does not moderate chat or identify offenders by social profile.\n" +
                "  See Settings → Safety.\n\n" +
                "Reportable-grade attacks produce integrity-sealed evidence packs under:\n" +
                $"  {GetReportRoot()}\n\n" +
                "Police filing:\n" +
                "  Use Settings → Report to Police (not the tray menu).\n" +
                "  Sentinel prepares packs + affidavit templates and opens your national cybercrime portal.\n" +
                "  It does NOT auto-submit to INTERPOL, FBI IC3, or any law-enforcement API.\n\n" +
                "Constraints:\n" +
                "  • No ActiveResponse toggle in this UI (service-only authority)\n" +
                "  • No Exit from the tray (service owns lifetime)\n" +
                "  • No balloon tips (WpnService removed by hardening)\n" +
                "  • Event log: %ProgramData%\\Sentinel\\events.jsonl\n";
            layout.Controls.Add(body, 0, 1);
            return page;
        }

        // ═══════════════════════════════════════════════════════════════
        // Shared helpers / styling
        // ═══════════════════════════════════════════════════════════════

        private static string ProgramDataRoot =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");

        private string GetReportRoot() =>
            _reportConfig.ReportDirectory
            ?? Path.Combine(ProgramDataRoot, "IncidentReports");

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

        private static string EventsLogPath => Path.Combine(ProgramDataRoot, "events.jsonl");

        private static List<DetectionListItem> ReadRecentDetections(int max)
        {
            var results = new List<DetectionListItem>();
            var path = EventsLogPath;
            if (!File.Exists(path)) return results;

            try
            {
                // Tail-read only — full-file scan on the STA thread freezes Settings open
                // when events.jsonl is large (and can leave the form in a half-shown state).
                var lines = new List<string>();
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                long keep = Math.Min(fs.Length, 512 * 1024); // last 512 KB
                if (fs.Length > keep)
                    fs.Seek(fs.Length - keep, SeekOrigin.Begin);
                using var reader = new StreamReader(fs, Encoding.UTF8);
                // If we sought mid-file, drop the first partial line
                if (fs.Position > 0)
                    reader.ReadLine();
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
            try
            {
                var log = EventsLogPath;
                if (!File.Exists(log))
                {
                    MessageBox.Show(this, "Event log not found yet.", "Sentinel",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                Process.Start(new ProcessStartInfo
                {
                    FileName = "notepad.exe",
                    UseShellExecute = true,
                    Arguments = "\"" + log + "\""
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
                // v1.8.1 RT-NEW-4: do not create SYSTEM-owned paths as the interactive user
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
                    UseShellExecute = true,
                    Arguments = path
                });
            }
            catch { }
        }

        private static void OpenUrl(string url)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                });
            }
            catch { }
        }

        private static string BlankOr(string? value) =>
            string.IsNullOrWhiteSpace(value) ? "________________________________" : value!.Trim();

        private static void SelectCombo(ComboBox box, string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            for (int i = 0; i < box.Items.Count; i++)
            {
                if (string.Equals(box.Items[i]?.ToString(), value, StringComparison.OrdinalIgnoreCase))
                {
                    box.SelectedIndex = i;
                    return;
                }
            }
            box.Items.Add(value);
            box.SelectedItem = value;
        }

        private static void PopulateCountries(ComboBox box)
        {
            box.Items.Clear();
            foreach (var p in LawEnforcementPortals.GetAllNationalPortals())
                box.Items.Add(new CountryItem(p.CountryCode, $"{p.CountryName} — {p.PrimaryPortalName}"));
            box.Items.Add(new CountryItem("EU", "EU directory (Europol links)"));
        }

        private static void SelectCountry(ComboBox box, string? code)
        {
            if (string.IsNullOrWhiteSpace(code)) return;
            code = code!.Trim().ToUpperInvariant();
            if (code == "UK") code = "GB";
            foreach (var item in box.Items)
            {
                if (item is CountryItem ci && ci.Code.Equals(code, StringComparison.OrdinalIgnoreCase))
                {
                    box.SelectedItem = item;
                    return;
                }
            }
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

        private TextBox MakeTextBox()
        {
            return new TextBox
            {
                BackColor = FieldBg,
                ForeColor = TextPrimary,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 9.5f)
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

        private ComboBox MakeComboBox(string[] items)
        {
            var box = new ComboBox
            {
                BackColor = FieldBg,
                ForeColor = TextPrimary,
                FlatStyle = FlatStyle.Flat,
                DropDownStyle = ComboBoxStyle.DropDownList,
                Font = new Font("Segoe UI", 9.5f)
            };
            foreach (var i in items) box.Items.Add(i);
            if (box.Items.Count > 0) box.SelectedIndex = 0;
            return box;
        }

        private CheckBox MakeCheck(string text) => new()
        {
            Text = text,
            ForeColor = TextPrimary,
            AutoSize = true,
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 2, 0, 2)
        };

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

        private Button MakeGreenButton(string text, EventHandler onClick)
        {
            var btn = MakeChromeButton(text, onClick);
            btn.BackColor = Green;
            btn.ForeColor = Color.FromArgb(0x20, 0x21, 0x24);
            btn.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
            btn.FlatAppearance.BorderColor = Green;
            btn.MinimumSize = new Size(160, 32);
            return btn;
        }

        // ═══════════════════════════════════════════════════════════════
        // Nested models
        // ═══════════════════════════════════════════════════════════════

        private sealed class CountryItem
        {
            public string Code { get; }
            public string Display { get; }
            public CountryItem(string code, string display) { Code = code; Display = display; }
            public override string ToString() => Display;
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

        private sealed class IncidentPackInfo
        {
            public string Directory { get; set; } = "";
            public string ReportId { get; set; } = "";
            public string Rule { get; set; } = "";
            public string Confidence { get; set; } = "";
            public string Process { get; set; } = "";
            public string? PortalUrl { get; set; }
            public string? CountryCode { get; set; }
            public string? DetectedAt { get; set; }
            public string? ZipPath { get; set; }

            public static IncidentPackInfo FromDirectory(string dir)
            {
                var id = Path.GetFileName(dir);
                var info = new IncidentPackInfo
                {
                    Directory = dir,
                    ReportId = id,
                    ZipPath = File.Exists(dir.TrimEnd(Path.DirectorySeparatorChar) + ".zip")
                        ? dir.TrimEnd(Path.DirectorySeparatorChar) + ".zip"
                        : null
                };

                try
                {
                    var ind = Path.Combine(dir, "indicators.txt");
                    if (File.Exists(ind))
                    {
                        foreach (var line in File.ReadAllLines(ind))
                        {
                            var idx = line.IndexOf('=');
                            if (idx <= 0) continue;
                            var key = line[..idx].Trim();
                            var val = line[(idx + 1)..].Trim();
                            switch (key)
                            {
                                case "rule": info.Rule = val; break;
                                case "confidence": info.Confidence = val; break;
                                case "process": info.Process = val; break;
                                case "portal_url": info.PortalUrl = val; break;
                                case "country": info.CountryCode = val; break;
                                case "report_id": info.ReportId = val; break;
                            }
                        }
                    }
                }
                catch { }

                if (string.IsNullOrEmpty(info.Rule))
                    info.Rule = id;

                return info;
            }

            public override string ToString()
            {
                var shortId = ReportId.Length > 42 ? ReportId[..42] + "…" : ReportId;
                if (!string.IsNullOrEmpty(Rule) && Rule != ReportId)
                    return $"{shortId}  ·  {Rule}";
                return shortId;
            }
        }
    }
}
