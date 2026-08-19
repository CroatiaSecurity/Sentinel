namespace Sentinel.Agent
{
    /// <summary>
    /// Self-contained HTML/CSS/JS for the Sentinel web dashboard.
    /// Embedded as a static string to avoid external file dependencies.
    /// </summary>
    public static class DashboardHtml
    {
        public static string GetHtml(string csrfToken) => $@"<!DOCTYPE html>
<html lang=""en"">
<head>
<meta charset=""UTF-8"">
<meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
<title>Sentinel Dashboard</title>
<style>
:root {{
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #1c2128;
    --bg-card: #21262d;
    --border: #30363d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --text-muted: #6e7681;
    --accent: #58a6ff;
    --accent-hover: #79c0ff;
    --success: #3fb950;
    --warning: #d29922;
    --danger: #f85149;
    --critical: #da3633;
    --purple: #bc8cff;
    --sidebar-width: 240px;
    --header-height: 64px;
    --radius: 8px;
    --shadow: 0 1px 3px rgba(0,0,0,0.3), 0 4px 6px rgba(0,0,0,0.2);
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.5;
    overflow: hidden;
    height: 100vh;
}}
.layout {{ display: flex; height: 100vh; }}
.sidebar {{
    width: var(--sidebar-width);
    background: var(--bg-secondary);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
}}
.sidebar-header {{
    padding: 20px 16px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 10px;
}}
.sidebar-header .logo {{
    width: 32px; height: 32px;
    background: linear-gradient(135deg, var(--accent), var(--purple));
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-weight: bold; font-size: 16px; color: white;
}}
.sidebar-header h1 {{ font-size: 16px; font-weight: 600; }}
.sidebar-header .version {{ font-size: 11px; color: var(--text-muted); }}
.nav {{ flex: 1; padding: 8px; overflow-y: auto; }}
.nav-item {{
    display: flex; align-items: center; gap: 10px;
    padding: 10px 12px; border-radius: var(--radius);
    cursor: pointer; color: var(--text-secondary);
    transition: all 0.15s ease; font-size: 14px; margin-bottom: 2px;
    border: 1px solid transparent;
}}
.nav-item:hover {{ background: var(--bg-tertiary); color: var(--text-primary); }}
.nav-item.active {{
    background: rgba(88,166,255,0.1);
    color: var(--accent);
    border-color: rgba(88,166,255,0.2);
}}
.nav-item svg {{ width: 18px; height: 18px; flex-shrink: 0; }}
.main {{ flex: 1; display: flex; flex-direction: column; overflow: hidden; }}
.header {{
    height: var(--header-height);
    padding: 0 24px;
    display: flex; align-items: center; justify-content: space-between;
    border-bottom: 1px solid var(--border);
    background: var(--bg-secondary);
}}
.header h2 {{ font-size: 18px; font-weight: 600; }}
.status-badge {{
    display: flex; align-items: center; gap: 6px;
    padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 500;
}}
.status-badge.active {{ background: rgba(63,185,80,0.15); color: var(--success); }}
.status-badge.inactive {{ background: rgba(248,81,73,0.15); color: var(--danger); }}
.status-dot {{ width: 8px; height: 8px; border-radius: 50%; animation: pulse 2s infinite; }}
.status-badge.active .status-dot {{ background: var(--success); }}
.status-badge.inactive .status-dot {{ background: var(--danger); }}
@keyframes pulse {{ 0%,100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}
.content {{ flex: 1; overflow-y: auto; padding: 24px; }}
.page {{ display: none; }}
.page.active {{ display: block; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.card {{
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 20px;
    box-shadow: var(--shadow); transition: border-color 0.2s;
}}
.card:hover {{ border-color: var(--accent); }}
.card-label {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }}
.card-value {{ font-size: 28px; font-weight: 700; }}
.card-value.success {{ color: var(--success); }}
.card-value.warning {{ color: var(--warning); }}
.card-value.danger {{ color: var(--danger); }}
.card-sub {{ font-size: 12px; color: var(--text-secondary); margin-top: 4px; }}
.panel {{
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: var(--radius); box-shadow: var(--shadow); margin-bottom: 24px;
}}
.panel-header {{
    padding: 16px 20px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
}}
.panel-header h3 {{ font-size: 14px; font-weight: 600; }}
.panel-body {{ padding: 16px 20px; }}
.event-list {{ max-height: 400px; overflow-y: auto; }}
.event-item {{
    display: flex; align-items: flex-start; gap: 12px; padding: 12px 0;
    border-bottom: 1px solid var(--border); font-size: 13px;
}}
.event-item:last-child {{ border-bottom: none; }}
.event-icon {{
    width: 32px; height: 32px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0; font-size: 14px;
}}
.event-icon.detection {{ background: rgba(248,81,73,0.15); color: var(--danger); }}
.event-icon.response {{ background: rgba(63,185,80,0.15); color: var(--success); }}
.event-icon.info {{ background: rgba(88,166,255,0.15); color: var(--accent); }}
.event-body {{ flex: 1; min-width: 0; }}
.event-title {{ font-weight: 500; color: var(--text-primary); }}
.event-detail {{ color: var(--text-secondary); margin-top: 2px; word-break: break-word; }}
.event-time {{ color: var(--text-muted); font-size: 11px; white-space: nowrap; }}
.btn {{
    padding: 8px 16px; border-radius: var(--radius); border: 1px solid var(--border);
    background: var(--bg-tertiary); color: var(--text-primary); cursor: pointer;
    font-size: 13px; font-weight: 500; transition: all 0.15s;
    display: inline-flex; align-items: center; gap: 6px;
}}
.btn:hover {{ background: var(--bg-card); border-color: var(--accent); }}
.btn-primary {{ background: var(--accent); border-color: var(--accent); color: #fff; }}
.btn-primary:hover {{ background: var(--accent-hover); }}
.btn-danger {{ background: var(--danger); border-color: var(--danger); color: #fff; }}
.scan-progress {{ margin: 20px 0; }}
.progress-bar {{
    height: 6px; background: var(--bg-tertiary); border-radius: 3px; overflow: hidden;
}}
.progress-fill {{
    height: 100%; background: linear-gradient(90deg, var(--accent), var(--purple));
    border-radius: 3px; transition: width 0.3s; animation: shimmer 1.5s infinite;
}}
@keyframes shimmer {{ 0% {{ opacity: 0.8; }} 50% {{ opacity: 1; }} 100% {{ opacity: 0.8; }} }}
.findings-grid {{ display: grid; gap: 8px; }}
.finding {{
    display: flex; align-items: flex-start; gap: 12px; padding: 12px 16px;
    border-radius: var(--radius); border: 1px solid var(--border); background: var(--bg-tertiary);
}}
.finding-severity {{
    width: 8px; height: 8px; border-radius: 50%; margin-top: 6px; flex-shrink: 0;
}}
.finding-severity.critical {{ background: var(--critical); }}
.finding-severity.high {{ background: var(--danger); }}
.finding-severity.medium {{ background: var(--warning); }}
.finding-severity.low {{ background: var(--text-muted); }}
.finding-body {{ flex: 1; }}
.finding-title {{ font-weight: 500; font-size: 13px; }}
.finding-desc {{ font-size: 12px; color: var(--text-secondary); margin-top: 2px; }}
.chart-container {{ height: 200px; position: relative; margin: 16px 0; }}
.bar-chart {{ display: flex; align-items: flex-end; gap: 4px; height: 100%; padding: 0 8px; }}
.bar {{
    flex: 1; min-width: 3px; background: var(--accent); border-radius: 2px 2px 0 0;
    transition: height 0.3s ease; opacity: 0.8;
}}
.bar:hover {{ opacity: 1; }}
.metric-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }}
.metric {{
    padding: 12px; border-radius: var(--radius); background: var(--bg-tertiary);
    border: 1px solid var(--border);
}}
.metric-label {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; }}
.metric-value {{ font-size: 20px; font-weight: 600; margin-top: 2px; }}
.empty-state {{
    text-align: center; padding: 48px 24px; color: var(--text-secondary);
}}
.empty-state svg {{ width: 48px; height: 48px; margin-bottom: 12px; opacity: 0.5; }}
.tab-bar {{ display: flex; gap: 0; border-bottom: 1px solid var(--border); margin-bottom: 16px; }}
.tab {{
    padding: 8px 16px; cursor: pointer; font-size: 13px; color: var(--text-secondary);
    border-bottom: 2px solid transparent; transition: all 0.15s;
}}
.tab:hover {{ color: var(--text-primary); }}
.tab.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
.quarantine-item {{
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 0; border-bottom: 1px solid var(--border); font-size: 13px;
}}
.quarantine-item:last-child {{ border-bottom: none; }}
.q-path {{ color: var(--text-secondary); font-family: monospace; font-size: 12px; }}
::-webkit-scrollbar {{ width: 8px; }}
::-webkit-scrollbar-track {{ background: var(--bg-primary); }}
::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 4px; }}
::-webkit-scrollbar-thumb:hover {{ background: var(--text-muted); }}
</style>
</head>
<body>
<div class=""layout"">
<aside class=""sidebar"">
    <div class=""sidebar-header"">
        <div class=""logo"">S</div>
        <div><h1>Sentinel</h1><div class=""version"" id=""version"">v2.1.2</div></div>
    </div>
    <nav class=""nav"">
        <div class=""nav-item active"" data-page=""overview"">
            <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2""><rect x=""3"" y=""3"" width=""7"" height=""7"" rx=""1""/><rect x=""14"" y=""3"" width=""7"" height=""7"" rx=""1""/><rect x=""3"" y=""14"" width=""7"" height=""7"" rx=""1""/><rect x=""14"" y=""14"" width=""7"" height=""7"" rx=""1""/></svg>
            Overview
        </div>
        <div class=""nav-item"" data-page=""events"">
            <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2""><path d=""M12 8v4l3 3""/><circle cx=""12"" cy=""12"" r=""10""/></svg>
            Events
        </div>
        <div class=""nav-item"" data-page=""scan"">
            <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2""><circle cx=""11"" cy=""11"" r=""8""/><path d=""M21 21l-4.35-4.35""/></svg>
            System Scan
        </div>
        <div class=""nav-item"" data-page=""quarantine"">
            <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2""><path d=""M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z""/></svg>
            Quarantine
        </div>
        <div class=""nav-item"" data-page=""ops"">
            <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2""><path d=""M22 12h-4l-3 9L9 3l-3 9H2""/></svg>
            Ops Metrics
        </div>
        <div class=""nav-item"" data-page=""about"">
            <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2""><circle cx=""12"" cy=""12"" r=""10""/><path d=""M12 16v-4""/><path d=""M12 8h.01""/></svg>
            About
        </div>
    </nav>
</aside>
<main class=""main"">
    <header class=""header"">
        <h2 id=""page-title"">Overview</h2>
        <div class=""status-badge active"" id=""status-badge"">
            <div class=""status-dot""></div>
            <span id=""status-text"">Protection Active</span>
        </div>
    </header>
    <div class=""content"">
        <!-- OVERVIEW -->
        <div class=""page active"" id=""page-overview"">
            <div class=""cards"">
                <div class=""card""><div class=""card-label"">Service Status</div><div class=""card-value success"" id=""ov-status"">Active</div><div class=""card-sub"" id=""ov-monitors"">Loading...</div></div>
                <div class=""card""><div class=""card-label"">Detections Today</div><div class=""card-value"" id=""ov-detections"">0</div><div class=""card-sub"">Last 24 hours</div></div>
                <div class=""card""><div class=""card-label"">Events/sec</div><div class=""card-value"" id=""ov-rate"">0</div><div class=""card-sub"">Telemetry throughput</div></div>
                <div class=""card""><div class=""card-label"">Quarantined</div><div class=""card-value warning"" id=""ov-quarantine"">0</div><div class=""card-sub"">Files isolated</div></div>
            </div>
            <div class=""panel"">
                <div class=""panel-header""><h3>Recent Activity</h3><button class=""btn"" onclick=""refreshEvents()"">Refresh</button></div>
                <div class=""panel-body""><div class=""event-list"" id=""ov-events""><div class=""empty-state"">Loading events...</div></div></div>
            </div>
            <div class=""panel"">
                <div class=""panel-header""><h3>Detection Rate (last 60 ticks)</h3></div>
                <div class=""panel-body""><div class=""chart-container""><div class=""bar-chart"" id=""ov-chart""></div></div></div>
            </div>
        </div>

        <!-- EVENTS -->
        <div class=""page"" id=""page-events"">
            <div class=""panel"">
                <div class=""panel-header""><h3>Live Event Stream</h3><span class=""card-sub"" id=""ev-count"">0 events</span></div>
                <div class=""panel-body""><div class=""event-list"" id=""ev-list""><div class=""empty-state"">Connecting...</div></div></div>
            </div>
        </div>

        <!-- SCAN -->
        <div class=""page"" id=""page-scan"">
            <div class=""cards"">
                <div class=""card""><div class=""card-label"">Scan Status</div><div class=""card-value"" id=""sc-status"">Idle</div><div class=""card-sub"" id=""sc-time"">No scan run yet</div></div>
                <div class=""card""><div class=""card-label"">Findings</div><div class=""card-value"" id=""sc-findings"">—</div><div class=""card-sub"" id=""sc-critical""></div></div>
            </div>
            <div class=""panel"">
                <div class=""panel-header"">
                    <h3>One-Time System Scan</h3>
                    <button class=""btn btn-primary"" id=""btn-scan"" onclick=""startScan()"">Run Full Scan</button>
                </div>
                <div class=""panel-body"">
                    <p style=""color:var(--text-secondary);font-size:13px;margin-bottom:12px"">
                        Scans running processes, persistence mechanisms (Run keys, scheduled tasks, startup folder, services, IFEO, Winlogon),
                        certificate stores, LNK shortcuts, staging paths, and network state for indicators of compromise.
                    </p>
                    <div class=""scan-progress"" id=""scan-progress"" style=""display:none"">
                        <div class=""progress-bar""><div class=""progress-fill"" id=""scan-bar"" style=""width:0%""></div></div>
                    </div>
                    <div class=""findings-grid"" id=""scan-findings""></div>
                </div>
            </div>
        </div>

        <!-- QUARANTINE -->
        <div class=""page"" id=""page-quarantine"">
            <div class=""panel"">
                <div class=""panel-header""><h3>Quarantined Files</h3><button class=""btn"" onclick=""loadQuarantine()"">Refresh</button></div>
                <div class=""panel-body""><div id=""q-list""><div class=""empty-state"">Loading...</div></div></div>
            </div>
        </div>

        <!-- OPS -->
        <div class=""page"" id=""page-ops"">
            <div class=""panel"">
                <div class=""panel-header""><h3>Pipeline Metrics</h3><button class=""btn"" onclick=""loadOps()"">Refresh</button></div>
                <div class=""panel-body""><div class=""metric-grid"" id=""ops-grid""><div class=""empty-state"">Loading metrics...</div></div></div>
            </div>
        </div>

        <!-- ABOUT -->
        <div class=""page"" id=""page-about"">
            <div class=""panel"">
                <div class=""panel-header""><h3>About Sentinel</h3></div>
                <div class=""panel-body"">
                    <p style=""margin-bottom:12px""><strong>Sentinel</strong> is a userland IDS/EDR for Windows built to battle hackers on machines people actually use.</p>
                    <div class=""metric-grid"">
                        <div class=""metric""><div class=""metric-label"">Architecture</div><div class=""metric-value"" style=""font-size:14px"">Two-process (Service + Agent)</div></div>
                        <div class=""metric""><div class=""metric-label"">Framework</div><div class=""metric-value"" style=""font-size:14px"">.NET Framework 4.8</div></div>
                        <div class=""metric""><div class=""metric-label"">Platform</div><div class=""metric-value"" style=""font-size:14px"">Windows x64</div></div>
                        <div class=""metric""><div class=""metric-label"">License</div><div class=""metric-value"" style=""font-size:14px"">MIT</div></div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</main>
</div>
<script>
const CSRF = '{csrfToken}';
const API = '';
let ws = null;
let eventBuffer = [];
let chartData = new Array(60).fill(0);
let chartIdx = 0;
let scanPolling = null;

// Navigation
document.querySelectorAll('.nav-item').forEach(item => {{
    item.addEventListener('click', () => {{
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        item.classList.add('active');
        const page = item.dataset.page;
        document.getElementById('page-' + page).classList.add('active');
        document.getElementById('page-title').textContent = item.textContent.trim();
        if (page === 'ops') loadOps();
        if (page === 'quarantine') loadQuarantine();
        if (page === 'scan') checkScanStatus();
    }});
}});

// API helpers
async function api(path, opts) {{
    try {{
        const res = await fetch(API + path, opts);
        return await res.json();
    }} catch(e) {{ return {{ ok: false, error: e.message }}; }}
}}

// Status
async function loadStatus() {{
    const data = await api('/api/status');
    if (data && data.ok) {{
        document.getElementById('version').textContent = 'v' + data.version;
        const badge = document.getElementById('status-badge');
        const text = document.getElementById('status-text');
        if (data.serviceRunning) {{
            badge.className = 'status-badge active';
            text.textContent = 'Protection Active';
            document.getElementById('ov-status').textContent = 'Active';
            document.getElementById('ov-status').className = 'card-value success';
        }} else {{
            badge.className = 'status-badge inactive';
            text.textContent = 'Service Stopped';
            document.getElementById('ov-status').textContent = 'Stopped';
            document.getElementById('ov-status').className = 'card-value danger';
        }}
    }}
    const health = await api('/api/health');
    if (health && health.ok) {{
        document.getElementById('ov-monitors').textContent =
            health.monitorsRunning + '/' + health.monitorsRegistered + ' monitors running';
    }}
}}

// Events
async function refreshEvents() {{
    const data = await api('/api/events?count=20');
    if (data && data.ok) {{
        renderEvents(data.events, 'ov-events');
        // Count detections
        let detCount = 0;
        data.events.forEach(e => {{ if (e.type === 'detection') detCount++; }});
        document.getElementById('ov-detections').textContent = detCount;
    }}
}}

function renderEvents(events, containerId) {{
    const container = document.getElementById(containerId);
    if (!events || events.length === 0) {{
        container.innerHTML = '<div class=""empty-state"">No events recorded yet</div>';
        return;
    }}
    container.innerHTML = events.map(ev => {{
        let parsed;
        try {{ parsed = JSON.parse(ev.data || ev); }} catch {{ parsed = ev; }}
        const type = parsed.type || ev.type || 'info';
        const ts = parsed.timestamp || ev.timestamp || '';
        let title = '', detail = '';
        if (parsed.data) {{
            const d = parsed.data;
            title = d.RuleName || d.ActionTaken || type;
            detail = d.ProcessName ? (d.ProcessName + ' (PID ' + d.ProcessId + ')') : (d.Evidence || '');
        }} else {{
            title = type;
        }}
        const iconClass = type === 'detection' ? 'detection' : type === 'response' ? 'response' : 'info';
        const icon = type === 'detection' ? '!' : type === 'response' ? '\u2713' : '\u2022';
        const timeStr = ts ? new Date(ts).toLocaleTimeString() : '';
        return `<div class=""event-item""><div class=""event-icon ${{iconClass}}"">${{icon}}</div><div class=""event-body""><div class=""event-title"">${{title}}</div><div class=""event-detail"">${{detail}}</div></div><div class=""event-time"">${{timeStr}}</div></div>`;
    }}).join('');
}}

// WebSocket
function connectWs() {{
    try {{
        ws = new WebSocket('ws://localhost:19845/ws/events');
        ws.onmessage = (msg) => {{
            eventBuffer.unshift(msg.data);
            if (eventBuffer.length > 200) eventBuffer.pop();
            // Update live events page
            const evList = document.getElementById('ev-list');
            if (document.getElementById('page-events').classList.contains('active')) {{
                const events = eventBuffer.slice(0, 50).map(d => ({{ data: d, type: 'info' }}));
                renderEvents(events, 'ev-list');
                document.getElementById('ev-count').textContent = eventBuffer.length + ' events';
            }}
            // Update chart
            try {{
                const parsed = JSON.parse(msg.data);
                if (parsed.type === 'detection') chartData[chartIdx % 60]++;
            }} catch {{}}
        }};
        ws.onclose = () => setTimeout(connectWs, 3000);
        ws.onerror = () => ws.close();
    }} catch {{
        setTimeout(connectWs, 3000);
    }}
}}

// Chart
function updateChart() {{
    const container = document.getElementById('ov-chart');
    const max = Math.max(...chartData, 1);
    container.innerHTML = chartData.map(v =>
        `<div class=""bar"" style=""height:${{Math.max(2, (v/max)*100)}}%"" title=""${{v}}""></div>`
    ).join('');
    chartIdx++;
    chartData[chartIdx % 60] = 0;
}}

// Ops
async function loadOps() {{
    const data = await api('/api/ops');
    const grid = document.getElementById('ops-grid');
    if (data && (data.ok || data.ops)) {{
        const ops = data.ops || data;
        const metrics = [
            ['Events/sec', ops.EventsPerSecond || ops.eventsPerSecond || 0],
            ['Detections/min', ops.DetectionsPerMinute || ops.detectionsPerMinute || 0],
            ['Drop Rate', (ops.DropRate || ops.dropRate || 0) + '%'],
            ['Correlation Latency', (ops.CorrelationLatencyMs || ops.correlationLatencyMs || 0) + 'ms'],
            ['Monitors', ops.RegisteredMonitors || ops.registeredMonitors || 0],
            ['Plugins', ops.PluginCount || ops.pluginCount || 0],
            ['Weighted Correlation', ops.WeightedCorrelationEnabled || ops.weightedCorrelationEnabled ? 'Enabled' : 'Disabled'],
            ['Product Version', ops.ProductVersion || ops.productVersion || '—'],
        ];
        grid.innerHTML = metrics.map(([label, value]) =>
            `<div class=""metric""><div class=""metric-label"">${{label}}</div><div class=""metric-value"">${{value}}</div></div>`
        ).join('');
        document.getElementById('ov-rate').textContent = ops.EventsPerSecond || ops.eventsPerSecond || 0;
    }} else {{
        grid.innerHTML = '<div class=""empty-state"">Unable to reach Sentinel Service</div>';
    }}
}}

// Quarantine
async function loadQuarantine() {{
    const data = await api('/api/quarantine');
    const container = document.getElementById('q-list');
    if (data && data.ok && data.items && data.items.length > 0) {{
        container.innerHTML = data.items.map(item => {{
            const name = item.OriginalName || item.originalName || item.Name || 'Unknown';
            const path = item.OriginalPath || item.originalPath || '';
            const date = item.QuarantinedAt || item.quarantinedAt || '';
            return `<div class=""quarantine-item""><div><div style=""font-weight:500"">${{name}}</div><div class=""q-path"">${{path}}</div></div><div class=""event-time"">${{date ? new Date(date).toLocaleDateString() : ''}}</div></div>`;
        }}).join('');
        document.getElementById('ov-quarantine').textContent = data.items.length;
    }} else {{
        container.innerHTML = '<div class=""empty-state"">No files in quarantine</div>';
        document.getElementById('ov-quarantine').textContent = '0';
    }}
}}

// Scan
async function startScan() {{
    const btn = document.getElementById('btn-scan');
    btn.disabled = true;
    btn.textContent = 'Scanning...';
    document.getElementById('scan-progress').style.display = 'block';
    document.getElementById('scan-bar').style.width = '30%';
    document.getElementById('sc-status').textContent = 'Running';
    document.getElementById('sc-status').className = 'card-value warning';

    await api('/api/scan', {{ method: 'POST', headers: {{ 'X-CSRF-Token': CSRF }} }});

    // Poll for results
    scanPolling = setInterval(checkScanStatus, 2000);
}}

async function checkScanStatus() {{
    const data = await api('/api/scan/status');
    if (!data || !data.ok) return;

    if (data.status === 'running') {{
        document.getElementById('scan-progress').style.display = 'block';
        document.getElementById('scan-bar').style.width = '60%';
        document.getElementById('sc-status').textContent = 'Running';
        document.getElementById('sc-status').className = 'card-value warning';
        document.getElementById('btn-scan').disabled = true;
        document.getElementById('btn-scan').textContent = 'Scanning...';
    }} else if (data.status === 'completed' && data.result) {{
        if (scanPolling) {{ clearInterval(scanPolling); scanPolling = null; }}
        const r = data.result;
        document.getElementById('scan-progress').style.display = 'none';
        document.getElementById('sc-status').textContent = 'Complete';
        document.getElementById('sc-status').className = 'card-value success';
        document.getElementById('sc-time').textContent = 'Duration: ' + (r.DurationMs || r.durationMs || 0) + 'ms';

        const findings = r.Findings || r.findings || [];
        document.getElementById('sc-findings').textContent = findings.length;
        const critical = findings.filter(f => (f.Severity || f.severity) >= 4).length;
        const high = findings.filter(f => (f.Severity || f.severity) === 3).length;
        document.getElementById('sc-critical').textContent = critical + ' critical, ' + high + ' high';
        if (critical > 0) document.getElementById('sc-findings').className = 'card-value danger';
        else if (high > 0) document.getElementById('sc-findings').className = 'card-value warning';
        else document.getElementById('sc-findings').className = 'card-value success';

        const container = document.getElementById('scan-findings');
        if (findings.length === 0) {{
            container.innerHTML = '<div class=""empty-state"" style=""padding:24px"">No threats found. System appears clean.</div>';
        }} else {{
            container.innerHTML = findings.sort((a,b) => (b.Severity||b.severity) - (a.Severity||a.severity)).map(f => {{
                const sev = f.Severity || f.severity || 0;
                const sevClass = sev >= 4 ? 'critical' : sev === 3 ? 'high' : sev === 2 ? 'medium' : 'low';
                return `<div class=""finding""><div class=""finding-severity ${{sevClass}}""></div><div class=""finding-body""><div class=""finding-title"">${{f.Title || f.title}}</div><div class=""finding-desc"">${{f.Description || f.description}}</div></div></div>`;
            }}).join('');
        }}

        document.getElementById('btn-scan').disabled = false;
        document.getElementById('btn-scan').textContent = 'Run Full Scan';
    }} else {{
        // idle
        document.getElementById('btn-scan').disabled = false;
        document.getElementById('btn-scan').textContent = 'Run Full Scan';
    }}
}}

// Init
loadStatus();
refreshEvents();
connectWs();
loadQuarantine();
setInterval(updateChart, 5000);
setInterval(loadStatus, 30000);
setInterval(refreshEvents, 15000);
</script>
</body>
</html>";
    }
}
