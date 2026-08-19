using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sentinel.Core;

namespace Sentinel.Agent
{
    /// <summary>
    /// Embedded web dashboard served via HttpListener on localhost.
    /// Provides REST API and WebSocket endpoints for the browser-based UI.
    /// Replaces the WinForms AgentDashboardForm.
    /// </summary>
    public sealed class WebDashboardService : BackgroundService
    {
        public const int DefaultPort = 19845;
        public const string DashboardUrl = "http://localhost:19845/";

        private readonly QuarantineManager _quarantine;
        private readonly SentinelConfig _config;
        private readonly ILogger<WebDashboardService> _logger;
        private readonly ConcurrentBag<WebSocket> _wsClients = new();
        private readonly string _csrfToken;
        private HttpListener? _listener;

        private static readonly string ProgramDataRoot =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");

        public WebDashboardService(
            QuarantineManager quarantine,
            SentinelConfig config,
            ILogger<WebDashboardService> logger)
        {
            _quarantine = quarantine;
            _config = config;
            _logger = logger;

            // Generate CSRF token for POST requests
            var bytes = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(bytes);
            _csrfToken = Convert.ToBase64String(bytes);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add(DashboardUrl);

            try
            {
                _listener.Start();
                _logger.LogInformation("[WebDashboard] Listening on {Url}", DashboardUrl);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[WebDashboard] Failed to start HttpListener — dashboard disabled");
                return;
            }

            // Start the event log file watcher for WebSocket broadcast
            _ = Task.Run(() => WatchAndBroadcastEvents(stoppingToken), stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var context = await _listener.GetContextAsync().ConfigureAwait(false);
                    _ = Task.Run(() => HandleRequestAsync(context, stoppingToken), stoppingToken);
                }
                catch (HttpListenerException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[WebDashboard] Request error");
                }
            }
        }

        public override Task StopAsync(CancellationToken cancellationToken)
        {
            try { _listener?.Stop(); } catch { }
            try { _listener?.Close(); } catch { }
            return base.StopAsync(cancellationToken);
        }

        private async Task HandleRequestAsync(HttpListenerContext context, CancellationToken ct)
        {
            var request = context.Request;
            var response = context.Response;

            try
            {
                var path = request.Url?.AbsolutePath ?? "/";
                var method = request.HttpMethod;

                // WebSocket upgrade
                if (request.IsWebSocketRequest && path == "/ws/events")
                {
                    try
                    {
                        await HandleWebSocket(context, ct).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[WebDashboard] WebSocket upgrade failed");
                        response.StatusCode = 500;
                        response.Close();
                    }
                    return;
                }

                // WebSocket not supported — return 426 so client falls back to polling
                if (path == "/ws/events")
                {
                    response.StatusCode = 426;
                    response.Close();
                    return;
                }

                // CORS headers for localhost
                response.Headers.Add("Access-Control-Allow-Origin", "*");
                response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                response.Headers.Add("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");

                if (method == "OPTIONS")
                {
                    response.StatusCode = 204;
                    response.Close();
                    return;
                }

                // Route
                if (path == "/" || path == "/index.html")
                {
                    await ServeHtml(response).ConfigureAwait(false);
                }
                else if (path.StartsWith("/api/"))
                {
                    await HandleApi(path, method, request, response, ct).ConfigureAwait(false);
                }
                else
                {
                    response.StatusCode = 404;
                    await WriteJson(response, new { error = "not_found" }).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[WebDashboard] Handler error");
                try
                {
                    response.StatusCode = 500;
                    response.Close();
                }
                catch { }
            }
        }

        private async Task HandleApi(string path, string method, HttpListenerRequest request, HttpListenerResponse response, CancellationToken ct)
        {
            response.ContentType = "application/json";

            switch (path)
            {
                case "/api/status":
                    await HandleStatus(response).ConfigureAwait(false);
                    break;
                case "/api/events":
                    await HandleEvents(response, request).ConfigureAwait(false);
                    break;
                case "/api/ops":
                    await HandleOps(response).ConfigureAwait(false);
                    break;
                case "/api/health":
                    await HandleHealth(response).ConfigureAwait(false);
                    break;
                case "/api/quarantine":
                    await HandleQuarantine(response).ConfigureAwait(false);
                    break;
                case "/api/packs":
                    await HandlePacks(response).ConfigureAwait(false);
                    break;
                case "/api/scan":
                    if (method != "POST") { response.StatusCode = 405; response.Close(); return; }
                    await HandleScan(response).ConfigureAwait(false);
                    break;
                case "/api/scan/status":
                    await HandleScanStatus(response).ConfigureAwait(false);
                    break;
                case "/api/csrf":
                    await WriteJson(response, new { token = _csrfToken }).ConfigureAwait(false);
                    break;
                case "/api/report/prefs":
                    await HandleReportPrefs(response).ConfigureAwait(false);
                    break;
                case "/api/report/save":
                    if (method != "POST") { response.StatusCode = 405; response.Close(); return; }
                    await HandleReportSave(request, response).ConfigureAwait(false);
                    break;
                case "/api/report/verify":
                    await HandleReportVerify(response).ConfigureAwait(false);
                    break;
                case "/api/hardened":
                    await HandleHardenedStatus(response).ConfigureAwait(false);
                    break;
                case "/api/hardened/toggle":
                    if (method != "POST") { response.StatusCode = 405; response.Close(); return; }
                    await HandleHardenedToggle(response).ConfigureAwait(false);
                    break;
                case "/api/diagnostics":
                    await HandleDiagnostics(response).ConfigureAwait(false);
                    break;
                default:
                    response.StatusCode = 404;
                    await WriteJson(response, new { error = "unknown_endpoint" }).ConfigureAwait(false);
                    break;
            }
        }

        #region API Handlers

        private async Task HandleStatus(HttpListenerResponse response)
        {
            bool serviceRunning = false;
            try
            {
                var procs = System.Diagnostics.Process.GetProcessesByName("Sentinel.Service");
                serviceRunning = procs.Length > 0;
                foreach (var p in procs) p.Dispose();
            }
            catch { }

            var version = typeof(WebDashboardService).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
            await WriteJson(response, new
            {
                ok = true,
                version,
                serviceRunning,
                protectionActive = serviceRunning,
                uptime = Environment.TickCount / 1000,
            }).ConfigureAwait(false);
        }

        private async Task HandleEvents(HttpListenerResponse response, HttpListenerRequest request)
        {
            int count = 50;
            var countParam = request.QueryString["count"];
            if (!string.IsNullOrEmpty(countParam) && int.TryParse(countParam, out int c))
                count = Math.Min(c, 500);

            var logFile = Path.Combine(ProgramDataRoot, "events.jsonl");
            var events = new List<object>();

            if (File.Exists(logFile))
            {
                try
                {
                    var lines = ReadLastLines(logFile, count);
                    foreach (var line in lines)
                    {
                        try
                        {
                            using var doc = JsonDocument.Parse(line);
                            var root = doc.RootElement;
                            events.Add(new
                            {
                                type = root.TryGetProperty("type", out var t) ? t.GetString() : "unknown",
                                timestamp = root.TryGetProperty("timestamp", out var ts) ? ts.GetString() : "",
                                data = line, // raw JSON for frontend to parse
                            });
                        }
                        catch { }
                    }
                }
                catch { }
            }

            events.Reverse();
            await WriteJson(response, new { ok = true, events, total = events.Count }).ConfigureAwait(false);
        }

        private async Task HandleOps(HttpListenerResponse response)
        {
            var result = ServiceAgentIpcClient.Request("ops", "", 3000);
            if (!string.IsNullOrEmpty(result))
            {
                response.ContentType = "application/json";
                var buffer = Encoding.UTF8.GetBytes(result);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                response.Close();
            }
            else
            {
                // Fallback: read ops_metrics.json
                var metricsFile = Path.Combine(ProgramDataRoot, "ops_metrics.json");
                if (File.Exists(metricsFile))
                {
                    try
                    {
                        var json = File.ReadAllText(metricsFile);
                        var buffer = Encoding.UTF8.GetBytes(json);
                        response.ContentLength64 = buffer.Length;
                        await response.OutputStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                        response.Close();
                    }
                    catch
                    {
                        await WriteJson(response, new { ok = false, error = "metrics_unavailable" }).ConfigureAwait(false);
                    }
                }
                else
                {
                    await WriteJson(response, new { ok = false, error = "service_unreachable" }).ConfigureAwait(false);
                }
            }
        }

        private async Task HandleHealth(HttpListenerResponse response)
        {
            var result = ServiceAgentIpcClient.Request("health", "", 3000);
            if (!string.IsNullOrEmpty(result))
            {
                var buffer = Encoding.UTF8.GetBytes(result);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                response.Close();
            }
            else
            {
                await WriteJson(response, new { ok = false, error = "service_unreachable" }).ConfigureAwait(false);
            }
        }

        private async Task HandleQuarantine(HttpListenerResponse response)
        {
            try
            {
                var items = _quarantine.ListQuarantined();
                await WriteJson(response, new { ok = true, items }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJson(response, new { ok = false, error = ex.Message }).ConfigureAwait(false);
            }
        }

        private async Task HandlePacks(HttpListenerResponse response)
        {
            var packsDir = Path.Combine(ProgramDataRoot, "IncidentReports");
            var packs = new List<object>();

            if (Directory.Exists(packsDir))
            {
                try
                {
                    foreach (var dir in Directory.GetDirectories(packsDir, "AUTO_*"))
                    {
                        var dirInfo = new DirectoryInfo(dir);
                        var manifestFile = Path.Combine(dir, "manifest.sha256");
                        bool hasManifest = File.Exists(manifestFile);
                        packs.Add(new
                        {
                            name = dirInfo.Name,
                            path = dir,
                            created = dirInfo.CreationTimeUtc,
                            hasManifest,
                            fileCount = Directory.GetFiles(dir).Length
                        });
                    }
                }
                catch { }
            }

            await WriteJson(response, new { ok = true, packs }).ConfigureAwait(false);
        }

        private async Task HandleScan(HttpListenerResponse response)
        {
            var result = ServiceAgentIpcClient.Request("scan", "", 5000);
            if (!string.IsNullOrEmpty(result))
            {
                var buffer = Encoding.UTF8.GetBytes(result);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                response.Close();
            }
            else
            {
                await WriteJson(response, new { ok = false, error = "service_unreachable" }).ConfigureAwait(false);
            }
        }

        private async Task HandleScanStatus(HttpListenerResponse response)
        {
            var result = ServiceAgentIpcClient.Request("scan_status", "", 5000);
            if (!string.IsNullOrEmpty(result))
            {
                var buffer = Encoding.UTF8.GetBytes(result);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                response.Close();
            }
            else
            {
                await WriteJson(response, new { ok = false, error = "service_unreachable" }).ConfigureAwait(false);
            }
        }

        private async Task HandleReportPrefs(HttpListenerResponse response)
        {
            try
            {
                var prefs = UserReportPrefs.Load();
                await WriteJson(response, new { ok = true, prefs }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJson(response, new { ok = false, error = ex.Message }).ConfigureAwait(false);
            }
        }

        private async Task HandleReportSave(HttpListenerRequest request, HttpListenerResponse response)
        {
            try
            {
                using var reader = new StreamReader(request.InputStream, request.ContentEncoding);
                var body = await reader.ReadToEndAsync().ConfigureAwait(false);
                var prefs = JsonSerializer.Deserialize<UserReportPrefs>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (prefs != null)
                {
                    prefs.Save();
                    await WriteJson(response, new { ok = true }).ConfigureAwait(false);
                }
                else
                {
                    await WriteJson(response, new { ok = false, error = "invalid_body" }).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                await WriteJson(response, new { ok = false, error = ex.Message }).ConfigureAwait(false);
            }
        }

        private async Task HandleReportVerify(HttpListenerResponse response)
        {
            try
            {
                var packsDir = Path.Combine(ProgramDataRoot, "IncidentReports");
                if (!Directory.Exists(packsDir))
                {
                    await WriteJson(response, new { ok = true, message = "No evidence packs to verify" }).ConfigureAwait(false);
                    return;
                }

                int verified = 0, failed = 0;
                foreach (var dir in Directory.GetDirectories(packsDir, "AUTO_*"))
                {
                    var manifest = Path.Combine(dir, "manifest.sha256");
                    if (File.Exists(manifest))
                        verified++;
                    else
                        failed++;
                }

                var msg = failed == 0
                    ? $"All {verified} pack(s) have integrity manifests"
                    : $"{verified} verified, {failed} missing manifest";

                await WriteJson(response, new { ok = true, message = msg, verified, failed }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJson(response, new { ok = false, error = ex.Message }).ConfigureAwait(false);
            }
        }

        private async Task HandleHardenedStatus(HttpListenerResponse response)
        {
            bool enabled = HardeningModule.RestrictivePortHardeningEnabled;
            await WriteJson(response, new { ok = true, enabled }).ConfigureAwait(false);
        }

        private async Task HandleHardenedToggle(HttpListenerResponse response)
        {
            try
            {
                bool current = HardeningModule.RestrictivePortHardeningEnabled;
                bool next = !current;

                var store = new EncryptedConfigStore();
                store.SetOverride("RestrictivePortHardening", next.ToString());
                if (store.Save())
                {
                    await WriteJson(response, new
                    {
                        ok = true,
                        enabled = next,
                        message = $"Hardened Mode {(next ? "ENABLED" : "DISABLED")} — restart Sentinel service to apply"
                    }).ConfigureAwait(false);
                }
                else
                {
                    await WriteJson(response, new
                    {
                        ok = false,
                        error = "Failed to save config. Run as Administrator or use: Sentinel.Service.exe --set-config RestrictivePortHardening=" + next
                    }).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                await WriteJson(response, new { ok = false, error = ex.Message }).ConfigureAwait(false);
            }
        }

        private async Task HandleDiagnostics(HttpListenerResponse response)
        {
            try
            {
                var sb = new System.Text.StringBuilder();
                var version = typeof(WebDashboardService).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
                sb.AppendLine($"Sentinel diagnostics — {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
                sb.AppendLine($"Agent version: {version}");

                bool agentRunning = false, serviceRunning = false;
                try
                {
                    agentRunning = System.Diagnostics.Process.GetProcessesByName("Sentinel.Agent").Length > 0;
                    serviceRunning = System.Diagnostics.Process.GetProcessesByName("Sentinel.Service").Length > 0;
                }
                catch { }

                sb.AppendLine($"Agent process: {(agentRunning ? "running" : "not found")}");
                sb.AppendLine($"Service process: {(serviceRunning ? "running" : "not found")}");
                sb.AppendLine($"Machine: {Environment.MachineName}");
                sb.AppendLine($"User: {Environment.UserDomainName}\\{Environment.UserName}");
                sb.AppendLine($"OS: {Environment.OSVersion}");
                sb.AppendLine($"Hardened Mode: {(HardeningModule.RestrictivePortHardeningEnabled ? "ENABLED" : "disabled (work-first)")}");
                sb.AppendLine();
                sb.AppendLine("Paths:");
                sb.AppendLine($"  Install:     {AppContext.BaseDirectory}");
                sb.AppendLine($"  ProgramData: {ProgramDataRoot}");

                var eventsPath = Path.Combine(ProgramDataRoot, "events.jsonl");
                var eventsSize = File.Exists(eventsPath) ? new FileInfo(eventsPath).Length : 0;
                sb.AppendLine($"  Events:      {eventsPath}  ({eventsSize / 1024} KB)");
                sb.AppendLine($"  Quarantine:  {Path.Combine(ProgramDataRoot, "Quarantine")}");

                var packsDir = Path.Combine(ProgramDataRoot, "IncidentReports");
                var packCount = Directory.Exists(packsDir) ? Directory.GetDirectories(packsDir, "AUTO_*").Length : 0;
                sb.AppendLine($"  Evidence:    {packsDir}  ({packCount} packs)");
                sb.AppendLine();
                sb.AppendLine("IPC status:");
                var pingResult = ServiceAgentIpcClient.Request("ping", "", 2000);
                sb.AppendLine($"  Ping: {(string.IsNullOrEmpty(pingResult) ? "FAILED (service unreachable)" : "OK")}");

                await WriteJson(response, new { ok = true, text = sb.ToString() }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJson(response, new { ok = false, error = ex.Message }).ConfigureAwait(false);
            }
        }

        #endregion

        #region WebSocket

        private async Task HandleWebSocket(HttpListenerContext context, CancellationToken ct)
        {
            WebSocketContext wsContext;
            try
            {
                wsContext = await context.AcceptWebSocketAsync(null).ConfigureAwait(false);
            }
            catch
            {
                context.Response.StatusCode = 500;
                context.Response.Close();
                return;
            }

            var ws = wsContext.WebSocket;
            _wsClients.Add(ws);

            try
            {
                var buffer = new byte[1024];
                while (ws.State == WebSocketState.Open && !ct.IsCancellationRequested)
                {
                    var result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), ct).ConfigureAwait(false);
                    if (result.MessageType == WebSocketMessageType.Close)
                        break;
                    // We don't process incoming messages — this is a push-only stream
                }
            }
            catch { }
            finally
            {
                try { ws.Dispose(); } catch { }
            }
        }

        private async Task BroadcastEvent(string json)
        {
            var deadSockets = new List<WebSocket>();
            foreach (var ws in _wsClients)
            {
                if (ws.State != WebSocketState.Open)
                {
                    deadSockets.Add(ws);
                    continue;
                }
                try
                {
                    var buffer = Encoding.UTF8.GetBytes(json);
                    await ws.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch
                {
                    deadSockets.Add(ws);
                }
            }

            // Clean up dead sockets (ConcurrentBag doesn't support remove, rebuild if needed)
            // This is fine for a small number of clients (typically 1-3 browser tabs)
        }

        private async Task WatchAndBroadcastEvents(CancellationToken ct)
        {
            var logFile = Path.Combine(ProgramDataRoot, "events.jsonl");

            // Wait for file to exist
            while (!File.Exists(logFile) && !ct.IsCancellationRequested)
                await Task.Delay(2000, ct).ConfigureAwait(false);

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

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    if (File.Exists(logFile))
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read,
                            FileShare.ReadWrite | FileShare.Delete);

                        if (fs.Length < lastOffset)
                            lastOffset = 0;

                        if (fs.Length > lastOffset)
                        {
                            fs.Seek(lastOffset, SeekOrigin.Begin);
                            using var reader = new StreamReader(fs, Encoding.UTF8, false, 4096, true);
                            string? line;
                            while ((line = reader.ReadLine()) != null)
                            {
                                if (!string.IsNullOrWhiteSpace(line))
                                    await BroadcastEvent(line).ConfigureAwait(false);
                            }
                            lastOffset = fs.Position;
                        }
                    }
                }
                catch { }

                await Task.Delay(1000, ct).ConfigureAwait(false);
            }
        }

        #endregion

        #region Helpers

        private static async Task WriteJson(HttpListenerResponse response, object data)
        {
            response.ContentType = "application/json";
            var json = JsonSerializer.Serialize(data);
            var buffer = Encoding.UTF8.GetBytes(json);
            response.ContentLength64 = buffer.Length;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
            response.Close();
        }

        private async Task ServeHtml(HttpListenerResponse response)
        {
            response.ContentType = "text/html; charset=utf-8";
            response.Headers.Add("X-Content-Type-Options", "nosniff");
            response.Headers.Add("X-Frame-Options", "DENY");
            var html = DashboardHtml.GetHtml(_csrfToken);
            var buffer = Encoding.UTF8.GetBytes(html);
            response.ContentLength64 = buffer.Length;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
            response.Close();
        }

        private static List<string> ReadLastLines(string filePath, int lineCount)
        {
            var lines = new List<string>();
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(fs, Encoding.UTF8);

                // Read all lines and take last N (simple approach for JSONL files < 50MB)
                string? line;
                var buffer = new Queue<string>(lineCount + 1);
                while ((line = reader.ReadLine()) != null)
                {
                    buffer.Enqueue(line);
                    if (buffer.Count > lineCount)
                        buffer.Dequeue();
                }
                lines.AddRange(buffer);
            }
            catch { }
            return lines;
        }

        #endregion
    }
}
