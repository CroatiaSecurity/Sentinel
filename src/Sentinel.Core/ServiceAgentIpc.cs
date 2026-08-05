using System;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// v2.0 RT-HIGH-4 — Authenticated local named-pipe IPC between Service (SYSTEM) and Agent (user).
    ///
    /// Auth model:
    ///   1. Service generates a random 32-byte token at start, writes
    ///      %ProgramData%\Sentinel\Secure\.ipc_token (SYSTEM full, Authenticated Users read).
    ///   2. Client proves possession via HMAC-SHA256 over timestamp|nonce|op|body.
    ///   3. 60-second timestamp window blocks replay.
    ///
    /// Read-only ops only (ping / ops / health). No ActiveResponse toggle over IPC.
    /// </summary>
    public static class ServiceAgentIpc
    {
        public const string PipeName = "SentinelIpc-v2";
        public const string ProtocolVersion = "2.0";
        private static readonly TimeSpan MaxSkew = TimeSpan.FromSeconds(60);

        public static string TokenPath
        {
            get
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                return Path.Combine(programData, "Sentinel", "Secure", ".ipc_token");
            }
        }

        public static byte[]? TryLoadToken()
        {
            try
            {
                var path = TokenPath;
                if (!File.Exists(path)) return null;
                var bytes = File.ReadAllBytes(path);
                return bytes.Length == 32 ? bytes : null;
            }
            catch
            {
                return null;
            }
        }

        public static byte[] EnsureServerToken()
        {
            var path = TokenPath;
            var dir = Path.GetDirectoryName(path)!;
            if (!Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            if (File.Exists(path))
            {
                try
                {
                    var existing = File.ReadAllBytes(path);
                    if (existing.Length == 32)
                    {
                        LockTokenAcl(path);
                        return existing;
                    }
                }
                catch { }
            }

            var token = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(token);
            File.WriteAllBytes(path, token);
            LockTokenAcl(path);
            return token;
        }

        /// <summary>
        /// SYSTEM full control; Authenticated Users read — Agent (user session) can auth.
        /// </summary>
        public static void LockTokenAcl(string path)
        {
            try
            {
                var fi = new FileInfo(path);
                var security = fi.GetAccessControl();
                security.SetAccessRuleProtection(true, false);
                foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    security.RemoveAccessRuleAll(rule);

                var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    system, FileSystemRights.FullControl, AccessControlType.Allow));

                var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    admins, FileSystemRights.FullControl, AccessControlType.Allow));

                var authUsers = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    authUsers, FileSystemRights.Read, AccessControlType.Allow));

                fi.SetAccessControl(security);
            }
            catch { }
        }

        public static string Sign(byte[] token, string payload)
        {
            using var hmac = new HMACSHA256(token);
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        public static bool Verify(byte[] token, string payload, string? providedHex)
        {
            if (string.IsNullOrEmpty(providedHex) || providedHex.Length != 64)
                return false;
            var expected = Sign(token, payload);
            return SecurityValidation.SecureCompare(
                Encoding.ASCII.GetBytes(expected),
                Encoding.ASCII.GetBytes(providedHex.ToLowerInvariant()));
        }

        public static bool IsTimestampFresh(long unixSeconds)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            return Math.Abs(now - unixSeconds) <= (long)MaxSkew.TotalSeconds;
        }

        public static string BuildAuthPayload(long ts, string nonce, string op, string body)
            => $"{ts}|{nonce}|{op}|{body}";
    }

    /// <summary>Service-side named pipe host (SYSTEM).</summary>
    public sealed class ServiceAgentIpcHost : BackgroundService
    {
        private readonly SentinelMetrics _metrics;
        private readonly MonitorRegistry? _registry;
        private readonly WeightedCorrelationConfig _weighted;
        private readonly Plugins.PluginRegistry _plugins;
        private readonly ILogger<ServiceAgentIpcHost> _logger;
        private byte[] _token = Array.Empty<byte>();

        public ServiceAgentIpcHost(
            SentinelMetrics metrics,
            WeightedCorrelationConfig weighted,
            Plugins.PluginRegistry plugins,
            ILogger<ServiceAgentIpcHost> logger,
            MonitorRegistry? registry = null)
        {
            _metrics = metrics;
            _weighted = weighted;
            _plugins = plugins;
            _logger = logger;
            _registry = registry;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try
            {
                _token = ServiceAgentIpc.EnsureServerToken();
                _logger.LogInformation("[IPC] Named pipe host ready ({Pipe})", ServiceAgentIpc.PipeName);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[IPC] Failed to create IPC token — host disabled");
                return;
            }

            while (!stoppingToken.IsCancellationRequested)
            {
                NamedPipeServerStream? pipe = null;
                try
                {
                    pipe = CreatePipe();
                    await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
                    await HandleClientAsync(pipe, stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[IPC] Client session error");
                }
                finally
                {
                    try { pipe?.Dispose(); } catch { }
                }
            }
        }

        private static NamedPipeServerStream CreatePipe()
        {
            // Allow Authenticated Users to connect; SYSTEM owns the server end.
            // net48: PipeSecurity ctor overload (NamedPipeServerStreamAcl is .NET 5+ only).
            var security = new PipeSecurity();
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            security.AddAccessRule(new PipeAccessRule(
                system, PipeAccessRights.FullControl, AccessControlType.Allow));
            var authUsers = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
            security.AddAccessRule(new PipeAccessRule(
                authUsers, PipeAccessRights.ReadWrite, AccessControlType.Allow));

            return new NamedPipeServerStream(
                ServiceAgentIpc.PipeName,
                PipeDirection.InOut,
                2,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous,
                0,
                0,
                security);
        }

        private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
        {
            using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };

            // One request per connection (simple + avoids session fixation).
            var line = await reader.ReadLineAsync().ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(line))
            {
                await writer.WriteLineAsync("{\"ok\":false,\"error\":\"empty\"}").ConfigureAwait(false);
                return;
            }

            try
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                var op = root.TryGetProperty("op", out var opEl) ? opEl.GetString() ?? "" : "";
                var ts = root.TryGetProperty("ts", out var tsEl) ? tsEl.GetInt64() : 0;
                var nonce = root.TryGetProperty("nonce", out var nEl) ? nEl.GetString() ?? "" : "";
                var sig = root.TryGetProperty("sig", out var sEl) ? sEl.GetString() : null;
                var body = root.TryGetProperty("body", out var bEl) ? bEl.GetRawText() : "";

                if (!ServiceAgentIpc.IsTimestampFresh(ts) || string.IsNullOrEmpty(nonce) || nonce.Length < 8)
                {
                    await writer.WriteLineAsync("{\"ok\":false,\"error\":\"auth_freshness\"}").ConfigureAwait(false);
                    return;
                }

                var payload = ServiceAgentIpc.BuildAuthPayload(ts, nonce, op, body);
                if (!ServiceAgentIpc.Verify(_token, payload, sig))
                {
                    await writer.WriteLineAsync("{\"ok\":false,\"error\":\"auth_sig\"}").ConfigureAwait(false);
                    return;
                }

                string response;
                switch (op.ToLowerInvariant())
                {
                    case "ping":
                        response = JsonSerializer.Serialize(new
                        {
                            ok = true,
                            protocol = ServiceAgentIpc.ProtocolVersion,
                            version = ProductInfo.Version,
                            pong = true
                        });
                        break;
                    case "ops":
                        _metrics.TickRates();
                        var snap = _metrics.CreateSnapshot();
                        snap.ProductVersion = ProductInfo.Version;
                        snap.WeightedCorrelationEnabled = _weighted.Enabled;
                        snap.WeightedThreshold = _weighted.Threshold;
                        snap.PluginCount = _plugins.TotalCount;
                        if (_registry != null)
                        {
                            var st = _registry.GetStats();
                            snap.RegisteredMonitors = st.TotalRegistered;
                            snap.RunningMonitors = st.Running;
                        }
                        response = JsonSerializer.Serialize(new { ok = true, ops = snap });
                        break;
                    case "health":
                        var stats = _registry?.GetStats();
                        response = JsonSerializer.Serialize(new
                        {
                            ok = true,
                            version = ProductInfo.Version,
                            monitorsRegistered = stats?.TotalRegistered ?? 0,
                            monitorsRunning = stats?.Running ?? 0,
                            monitorsFailed = stats?.Failed ?? 0,
                            plugins = _plugins.TotalCount
                        });
                        break;
                    default:
                        response = "{\"ok\":false,\"error\":\"unknown_op\"}";
                        break;
                }

                await writer.WriteLineAsync(response).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[IPC] Bad request");
                await writer.WriteLineAsync("{\"ok\":false,\"error\":\"bad_request\"}").ConfigureAwait(false);
            }
        }
    }

    /// <summary>Agent-side client (user session).</summary>
    public static class ServiceAgentIpcClient
    {
        public static async Task<string?> RequestAsync(string op, string body = "", int timeoutMs = 3000)
        {
            var token = ServiceAgentIpc.TryLoadToken();
            if (token == null) return null;

            try
            {
                using var pipe = new NamedPipeClientStream(
                    ".", ServiceAgentIpc.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                var connectTask = pipe.ConnectAsync(timeoutMs);
                await connectTask.ConfigureAwait(false);
                if (!pipe.IsConnected) return null;

                var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var nonce = Guid.NewGuid().ToString("N");
                var payload = ServiceAgentIpc.BuildAuthPayload(ts, nonce, op, body);
                var sig = ServiceAgentIpc.Sign(token, payload);

                var req = JsonSerializer.Serialize(new
                {
                    op,
                    ts,
                    nonce,
                    sig,
                    body
                });

                using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
                using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
                await writer.WriteLineAsync(req).ConfigureAwait(false);
                return await reader.ReadLineAsync().ConfigureAwait(false);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>Synchronous helper for STA Agent UI.</summary>
        public static string? Request(string op, string body = "", int timeoutMs = 3000)
        {
            try
            {
                return RequestAsync(op, body, timeoutMs).GetAwaiter().GetResult();
            }
            catch
            {
                return null;
            }
        }
    }
}
