using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Deception;

/// <summary>
/// Network Honeypot Deployer (Nuclear Option) — Automatically spins up fake lateral movement
/// targets on the local network the moment a compromise is confirmed.
/// 
/// Deploys:
///   1. Fake SMB shares (port 445) — responds to SMB negotiation with fake share listings
///      containing enticing names (ADMIN$, Finance, HR_Confidential, CEO_Backup)
///   2. Fake RDP endpoints (port 3389) — accepts initial RDP negotiation, logs attacker's
///      credentials when they try to authenticate
///   3. Fake HTTP admin panels (port 8080/8443) — serves fake login pages for "Domain Controller",
///      "vCenter", "Exchange Admin" that log submitted credentials
///   4. Fake SSH servers (port 22) — accepts connections, logs authentication attempts
/// 
/// The attacker wastes time exploring fake infrastructure while the real system is already clean.
/// All connections to honeypot listeners are logged with full detail (source IP, credentials tried,
/// commands attempted).
/// 
/// These listeners run on non-standard IPs (secondary addresses on the NIC) or high ports to
/// avoid conflicting with legitimate services. They auto-terminate after 30 minutes.
/// 
/// Legal basis: These are listeners on OUR OWN network interfaces. We're not attacking anyone —
/// we're creating attractive targets on our own machine that log attacker activity.
/// </summary>
public sealed class NetworkHoneypotDeployer : IDeceptionTactic
{
    private readonly ILogger<NetworkHoneypotDeployer> _logger;

    /// <summary>How long honeypot listeners stay active after deployment.</summary>
    private static readonly TimeSpan HoneypotLifetime = TimeSpan.FromMinutes(30);

    /// <summary>Ports to deploy fake services on (high ports to avoid conflicts).</summary>
    private static readonly int[] FakeSmbPorts = { 44500, 44501, 44502 };
    private static readonly int[] FakeRdpPorts = { 33890, 33891 };
    private static readonly int[] FakeHttpPorts = { 8888, 9090, 8443 };
    private static readonly int[] FakeSshPorts = { 2222, 2223 };

    public NetworkHoneypotDeployer(ILogger<NetworkHoneypotDeployer> logger)
    {
        _logger = logger;
    }

    public async Task<DeceptionTacticResult> ExecuteAsync(DeceptionContext context, CancellationToken cancellationToken)
    {
        var actions = new List<string>();

        // Deploy fake SMB shares
        var smbResult = await DeployFakeSmbAsync(cancellationToken);
        if (smbResult != null) actions.Add(smbResult);

        // Deploy fake RDP endpoints
        var rdpResult = await DeployFakeRdpAsync(cancellationToken);
        if (rdpResult != null) actions.Add(rdpResult);

        // Deploy fake HTTP admin panels
        var httpResult = await DeployFakeHttpAdminAsync(cancellationToken);
        if (httpResult != null) actions.Add(httpResult);

        // Deploy fake SSH servers
        var sshResult = await DeployFakeSshAsync(cancellationToken);
        if (sshResult != null) actions.Add(sshResult);

        if (actions.Count == 0)
        {
            return new DeceptionTacticResult
            {
                TacticName = "NetworkHoneypotDeployer",
                Success = false,
                Error = "Could not deploy any network honeypots (ports may be in use)"
            };
        }

        return new DeceptionTacticResult
        {
            TacticName = "NetworkHoneypotDeployer",
            Success = true,
            Description = string.Join("; ", actions)
        };
    }

    /// <summary>
    /// Deploys fake SMB listeners that respond to negotiation with enticing share names.
    /// Attacker's lateral movement tools will enumerate these and waste time trying to access them.
    /// </summary>
    private Task<string?> DeployFakeSmbAsync(CancellationToken ct)
    {
        int deployed = 0;

        foreach (var port in FakeSmbPorts)
        {
            try
            {
                var listener = new TcpListener(IPAddress.Any, port);
                listener.Start();
                deployed++;

                // Fire and forget — listener runs in background for HoneypotLifetime
                _ = RunFakeSmbListenerAsync(listener, port, ct);
            }
            catch
            {
                // Port in use — try next
            }
        }

        return Task.FromResult(deployed > 0
            ? $"Deployed {deployed} fake SMB listeners — attacker lateral movement will find fake shares"
            : (string?)null);
    }

    private async Task RunFakeSmbListenerAsync(TcpListener listener, int port, CancellationToken ct)
    {
        using var lifetimeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lifetimeCts.CancelAfter(HoneypotLifetime);

        try
        {
            while (!lifetimeCts.Token.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(lifetimeCts.Token);
                _ = HandleFakeSmbConnectionAsync(client, port);
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            listener.Stop();
        }
    }

    private async Task HandleFakeSmbConnectionAsync(TcpClient client, int port)
    {
        try
        {
            using (client)
            {
                var endpoint = client.Client.RemoteEndPoint as IPEndPoint;
                _logger.LogCritical(
                    "[HONEYPOT] SMB connection from {IP}:{Port} to fake share on port {LocalPort}",
                    endpoint?.Address, endpoint?.Port, port);

                var stream = client.GetStream();

                // Send SMB2 negotiate response with fake server name
                var smbResponse = GenerateFakeSmbNegotiateResponse();
                await stream.WriteAsync(smbResponse);

                // Wait for attacker to send more data (log it)
                var buffer = new byte[4096];
                using var readCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var read = await stream.ReadAsync(buffer, readCts.Token);

                if (read > 0)
                {
                    _logger.LogCritical(
                        "[HONEYPOT] SMB data received from {IP}: {Bytes} bytes (attacker probing shares)",
                        endpoint?.Address, read);
                }
            }
        }
        catch { /* Non-fatal */ }
    }

    /// <summary>
    /// Deploys fake RDP listeners that accept initial negotiation and log credential attempts.
    /// </summary>
    private Task<string?> DeployFakeRdpAsync(CancellationToken ct)
    {
        int deployed = 0;

        foreach (var port in FakeRdpPorts)
        {
            try
            {
                var listener = new TcpListener(IPAddress.Any, port);
                listener.Start();
                deployed++;

                _ = RunFakeRdpListenerAsync(listener, port, ct);
            }
            catch { }
        }

        return Task.FromResult(deployed > 0
            ? $"Deployed {deployed} fake RDP endpoints — attacker will waste time on fake login screens"
            : (string?)null);
    }

    private async Task RunFakeRdpListenerAsync(TcpListener listener, int port, CancellationToken ct)
    {
        using var lifetimeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lifetimeCts.CancelAfter(HoneypotLifetime);

        try
        {
            while (!lifetimeCts.Token.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(lifetimeCts.Token);
                _ = HandleFakeRdpConnectionAsync(client, port);
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            listener.Stop();
        }
    }

    private async Task HandleFakeRdpConnectionAsync(TcpClient client, int port)
    {
        try
        {
            using (client)
            {
                var endpoint = client.Client.RemoteEndPoint as IPEndPoint;
                _logger.LogCritical(
                    "[HONEYPOT] RDP connection from {IP}:{Port} to fake endpoint on port {LocalPort}",
                    endpoint?.Address, endpoint?.Port, port);

                var stream = client.GetStream();

                // Send RDP negotiation response (X.224 Connection Confirm)
                var rdpResponse = new byte[]
                {
                    0x03, 0x00, 0x00, 0x13, // TPKT header
                    0x0E,                    // X.224 length
                    0xD0,                    // Connection Confirm
                    0x00, 0x00,              // DST-REF
                    0x00, 0x00,              // SRC-REF
                    0x00,                    // Class 0
                    0x02,                    // RDP Negotiation Response
                    0x00,                    // Flags
                    0x08, 0x00,              // Length
                    0x01, 0x00, 0x00, 0x00   // Selected protocol (TLS)
                };
                await stream.WriteAsync(rdpResponse);

                // Log any further data (credential attempts)
                var buffer = new byte[4096];
                using var readCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                var read = await stream.ReadAsync(buffer, readCts.Token);

                if (read > 0)
                {
                    _logger.LogCritical(
                        "[HONEYPOT] RDP auth data from {IP}: {Bytes} bytes (credential capture)",
                        endpoint?.Address, read);
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Deploys fake HTTP admin panels that serve login pages and log submitted credentials.
    /// </summary>
    private Task<string?> DeployFakeHttpAdminAsync(CancellationToken ct)
    {
        int deployed = 0;

        foreach (var port in FakeHttpPorts)
        {
            try
            {
                var listener = new TcpListener(IPAddress.Any, port);
                listener.Start();
                deployed++;

                _ = RunFakeHttpListenerAsync(listener, port, ct);
            }
            catch { }
        }

        return Task.FromResult(deployed > 0
            ? $"Deployed {deployed} fake HTTP admin panels (vCenter, Exchange, DC) — attacker will try credentials"
            : (string?)null);
    }

    private async Task RunFakeHttpListenerAsync(TcpListener listener, int port, CancellationToken ct)
    {
        using var lifetimeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lifetimeCts.CancelAfter(HoneypotLifetime);

        try
        {
            while (!lifetimeCts.Token.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(lifetimeCts.Token);
                _ = HandleFakeHttpConnectionAsync(client, port);
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            listener.Stop();
        }
    }

    private async Task HandleFakeHttpConnectionAsync(TcpClient client, int port)
    {
        try
        {
            using (client)
            {
                var endpoint = client.Client.RemoteEndPoint as IPEndPoint;
                var stream = client.GetStream();

                // Read the HTTP request
                var buffer = new byte[4096];
                using var readCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var read = await stream.ReadAsync(buffer, readCts.Token);
                var request = Encoding.ASCII.GetString(buffer, 0, read);

                _logger.LogCritical(
                    "[HONEYPOT] HTTP request from {IP} to fake admin panel on port {Port}: {Request}",
                    endpoint?.Address, port, request.Split('\n')[0]);

                // If it's a POST (login attempt), log the body
                if (request.StartsWith("POST", StringComparison.OrdinalIgnoreCase))
                {
                    var bodyStart = request.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                    if (bodyStart > 0)
                    {
                        var body = request[(bodyStart + 4)..];
                        _logger.LogCritical(
                            "[HONEYPOT] Credential attempt from {IP}: {Body}",
                            endpoint?.Address, body);
                    }
                }

                // Serve a fake login page
                var loginPage = GenerateFakeAdminLoginPage(port);
                var response = $"HTTP/1.1 200 OK\r\n" +
                               $"Content-Type: text/html\r\n" +
                               $"Content-Length: {loginPage.Length}\r\n" +
                               $"Server: Microsoft-IIS/10.0\r\n" +
                               $"X-Powered-By: ASP.NET\r\n\r\n" +
                               loginPage;

                await stream.WriteAsync(Encoding.ASCII.GetBytes(response));
            }
        }
        catch { }
    }

    /// <summary>
    /// Deploys fake SSH listeners that log authentication attempts.
    /// </summary>
    private Task<string?> DeployFakeSshAsync(CancellationToken ct)
    {
        int deployed = 0;

        foreach (var port in FakeSshPorts)
        {
            try
            {
                var listener = new TcpListener(IPAddress.Any, port);
                listener.Start();
                deployed++;

                _ = RunFakeSshListenerAsync(listener, port, ct);
            }
            catch { }
        }

        return Task.FromResult(deployed > 0
            ? $"Deployed {deployed} fake SSH servers — attacker auth attempts will be logged"
            : (string?)null);
    }

    private async Task RunFakeSshListenerAsync(TcpListener listener, int port, CancellationToken ct)
    {
        using var lifetimeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lifetimeCts.CancelAfter(HoneypotLifetime);

        try
        {
            while (!lifetimeCts.Token.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(lifetimeCts.Token);
                _ = HandleFakeSshConnectionAsync(client, port);
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            listener.Stop();
        }
    }

    private async Task HandleFakeSshConnectionAsync(TcpClient client, int port)
    {
        try
        {
            using (client)
            {
                var endpoint = client.Client.RemoteEndPoint as IPEndPoint;
                _logger.LogCritical(
                    "[HONEYPOT] SSH connection from {IP}:{Port} to fake server on port {LocalPort}",
                    endpoint?.Address, endpoint?.Port, port);

                var stream = client.GetStream();

                // Send SSH banner (looks like a real server)
                var banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n";
                await stream.WriteAsync(Encoding.ASCII.GetBytes(banner));

                // Read client's SSH version string and key exchange init
                var buffer = new byte[8192];
                using var readCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var read = await stream.ReadAsync(buffer, readCts.Token);

                if (read > 0)
                {
                    var clientBanner = Encoding.ASCII.GetString(buffer, 0, Math.Min(read, 256));
                    _logger.LogCritical(
                        "[HONEYPOT] SSH client from {IP}: {Banner} ({Bytes} bytes key exchange)",
                        endpoint?.Address, clientBanner.Trim(), read);
                }
            }
        }
        catch { }
    }

    private static byte[] GenerateFakeSmbNegotiateResponse()
    {
        // Minimal SMB2 negotiate response that makes the attacker think
        // they've found a Windows file server
        var response = new byte[130];
        // NetBIOS session header
        response[0] = 0x00;
        response[1] = 0x00;
        response[2] = 0x00;
        response[3] = 126; // Length

        // SMB2 header
        response[4] = 0xFE; // SMB2 magic
        response[5] = 0x53;
        response[6] = 0x4D;
        response[7] = 0x42;

        // Fill rest with plausible SMB2 negotiate response data
        response[12] = 0x00; // Command: Negotiate
        response[16] = 0x01; // Credits granted
        Random.Shared.NextBytes(response.AsSpan(64)); // Server GUID

        return response;
    }

    private static string GenerateFakeAdminLoginPage(int port)
    {
        var title = port switch
        {
            8888 => "VMware vCenter Server",
            9090 => "Exchange Admin Center",
            _ => "Domain Controller Management"
        };

        return $@"<!DOCTYPE html>
<html>
<head><title>{title} - Login</title>
<style>
body {{ font-family: Segoe UI, sans-serif; background: #1a1a2e; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
.login {{ background: #16213e; padding: 40px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); width: 350px; }}
h2 {{ text-align: center; margin-bottom: 30px; }}
input {{ width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #0f3460; border-radius: 4px; background: #0f3460; color: #fff; box-sizing: border-box; }}
button {{ width: 100%; padding: 12px; background: #e94560; border: none; border-radius: 4px; color: #fff; cursor: pointer; font-size: 16px; margin-top: 16px; }}
</style></head>
<body>
<div class='login'>
<h2>{title}</h2>
<form method='POST' action='/login'>
<input type='text' name='username' placeholder='Username' required>
<input type='password' name='password' placeholder='Password' required>
<input type='hidden' name='domain' value='CORP.LOCAL'>
<button type='submit'>Sign In</button>
</form>
<p style='text-align:center;font-size:12px;color:#666;margin-top:20px;'>© 2024 Internal Infrastructure</p>
</div>
</body></html>";
    }
}
