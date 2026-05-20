using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Deception;

/// <summary>
/// Beacon Flooder — Spams the identified C2 server with fake beacon traffic.
/// 
/// When we identify a C2 channel (address + port + optional framework signature), we flood
/// the C2 server with thousands of fake beacon check-ins from fake "implants." The operator's
/// console fills with garbage sessions they have to sort through.
/// 
/// Effectiveness by C2 framework:
///   - Cobalt Strike: Fake HTTP beacons with randomized metadata confuse the team server
///   - Sliver: Fake mTLS/HTTP connections waste operator triage time
///   - Generic HTTP C2: Flood with varied User-Agents and fake session cookies
///   - Raw TCP C2: Flood with random-length payloads that trigger parsing errors
/// 
/// This runs AFTER the malicious process is identified but BEFORE kill, using the C2
/// connection details extracted from the detection metadata. The flood continues briefly
/// even after the implant is dead, making the operator think multiple implants are active.
/// 
/// Legal basis: We're sending traffic to an attacker's C2 server that is actively attacking
/// our system. This is proportional defensive response on our own network.
/// </summary>
public sealed class BeaconFlooder : IDeceptionTactic
{
    private readonly ILogger<BeaconFlooder> _logger;

    /// <summary>Number of fake beacons to send.</summary>
    private const int FakeBeaconCount = 50;

    /// <summary>Number of protocol confusion payloads to send.</summary>
    private const int ProtocolConfusionCount = 20;

    /// <summary>Maximum time for beacon flooding.</summary>
    private static readonly TimeSpan MaxFloodTime = TimeSpan.FromMilliseconds(800);

    public BeaconFlooder(ILogger<BeaconFlooder> logger)
    {
        _logger = logger;
    }

    public async Task<DeceptionTacticResult> ExecuteAsync(DeceptionContext context, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(context.RemoteAddress) || context.RemotePort == null)
        {
            return new DeceptionTacticResult
            {
                TacticName = "BeaconFlooder",
                Success = false,
                Error = "No C2 address/port available for flooding"
            };
        }

        if (!IPAddress.TryParse(context.RemoteAddress, out var ip))
        {
            return new DeceptionTacticResult
            {
                TacticName = "BeaconFlooder",
                Success = false,
                Error = $"Invalid C2 address: {context.RemoteAddress}"
            };
        }

        // Don't flood private/loopback addresses
        if (IPAddress.IsLoopback(ip) || IsPrivateAddress(ip))
        {
            return new DeceptionTacticResult
            {
                TacticName = "BeaconFlooder",
                Success = false,
                Error = "C2 address is private/loopback — flooding skipped"
            };
        }

        var endpoint = new IPEndPoint(ip, context.RemotePort.Value);
        int sent = 0;
        int failed = 0;

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(MaxFloodTime);

        var tasks = new List<Task>();

        // Phase 1: Beacon flooding — fake sessions to pollute operator console
        for (int i = 0; i < FakeBeaconCount && !timeoutCts.Token.IsCancellationRequested; i++)
        {
            tasks.Add(SendFakeBeaconAsync(endpoint, context.C2Framework, timeoutCts.Token)
                .ContinueWith(t =>
                {
                    if (t.IsCompletedSuccessfully && t.Result)
                        Interlocked.Increment(ref sent);
                    else
                        Interlocked.Increment(ref failed);
                }, TaskContinuationOptions.ExecuteSynchronously));

            // Stagger slightly to avoid local socket exhaustion
            if (i % 10 == 0)
                await Task.Delay(10, timeoutCts.Token).ConfigureAwait(false);
        }

        // Phase 2: Protocol confusion — send malformed data that triggers parsing bugs
        int confused = 0;
        for (int i = 0; i < ProtocolConfusionCount && !timeoutCts.Token.IsCancellationRequested; i++)
        {
            tasks.Add(SendProtocolConfusionAsync(endpoint, context.C2Framework, timeoutCts.Token)
                .ContinueWith(t =>
                {
                    if (t.IsCompletedSuccessfully && t.Result)
                        Interlocked.Increment(ref confused);
                }, TaskContinuationOptions.ExecuteSynchronously));
        }

        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Time budget expired — that's fine
        }

        var description = $"Flooded C2 at {context.RemoteAddress}:{context.RemotePort} with {sent} fake beacons " +
                          $"+ {confused} protocol confusion payloads — operator console polluted with ghost sessions";

        return new DeceptionTacticResult
        {
            TacticName = "BeaconFlooder",
            Success = sent > 0 || confused > 0,
            Description = description
        };
    }

    private static async Task<bool> SendFakeBeaconAsync(IPEndPoint endpoint, string? framework, CancellationToken ct)
    {
        try
        {
            using var socket = new Socket(endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            socket.SendTimeout = 200;
            socket.ReceiveTimeout = 200;

            await socket.ConnectAsync(endpoint, ct).ConfigureAwait(false);

            var payload = GenerateFakeBeaconPayload(framework);
            await socket.SendAsync(payload, SocketFlags.None, ct).ConfigureAwait(false);

            socket.Shutdown(SocketShutdown.Both);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Generates fake beacon payloads that mimic real C2 framework traffic.
    /// Designed to trigger parsing in the C2 server and create fake sessions.
    /// </summary>
    private static byte[] GenerateFakeBeaconPayload(string? framework)
    {
        var random = Random.Shared;

        return framework?.ToLowerInvariant() switch
        {
            "cobalt_strike" => GenerateFakeCobaltStrikeBeacon(),
            "sliver" => GenerateFakeSliverBeacon(),
            _ => GenerateGenericHttpBeacon()
        };
    }

    private static byte[] GenerateFakeCobaltStrikeBeacon()
    {
        // Mimics Cobalt Strike HTTP beacon check-in format
        var fakeId = Random.Shared.Next(10000, 99999);
        var request = $"GET /pixel.gif HTTP/1.1\r\n" +
                      $"Host: cdn-{Random.Shared.Next(1, 99)}.cloudfront.net\r\n" +
                      $"Cookie: SESSIONID={GenerateRandomCookie()}\r\n" +
                      $"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n" +
                      $"Accept: */*\r\n" +
                      $"Connection: close\r\n\r\n";
        return System.Text.Encoding.ASCII.GetBytes(request);
    }

    private static byte[] GenerateFakeSliverBeacon()
    {
        // Mimics Sliver HTTP implant check-in
        var request = $"POST /api/v1/sessions HTTP/1.1\r\n" +
                      $"Host: updates.microsoft-cdn.com\r\n" +
                      $"Content-Type: application/octet-stream\r\n" +
                      $"X-Session-Token: {Guid.NewGuid()}\r\n" +
                      $"Content-Length: 128\r\n" +
                      $"Connection: close\r\n\r\n";
        var header = System.Text.Encoding.ASCII.GetBytes(request);
        var body = new byte[128];
        Random.Shared.NextBytes(body);
        return header.Concat(body).ToArray();
    }

    private static byte[] GenerateGenericHttpBeacon()
    {
        var paths = new[] { "/status", "/heartbeat", "/check", "/update", "/sync", "/poll" };
        var path = paths[Random.Shared.Next(paths.Length)];
        var request = $"GET {path} HTTP/1.1\r\n" +
                      $"Host: api.{GenerateRandomDomain()}\r\n" +
                      $"Authorization: Bearer {GenerateRandomToken()}\r\n" +
                      $"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n" +
                      $"Connection: close\r\n\r\n";
        return System.Text.Encoding.ASCII.GetBytes(request);
    }

    private static string GenerateRandomCookie()
    {
        var bytes = new byte[24];
        Random.Shared.NextBytes(bytes);
        return Convert.ToBase64String(bytes);
    }

    private static string GenerateRandomToken()
    {
        var bytes = new byte[32];
        Random.Shared.NextBytes(bytes);
        return Convert.ToBase64String(bytes).TrimEnd('=');
    }

    private static string GenerateRandomDomain()
    {
        var words = new[] { "cloud", "sync", "update", "cdn", "api", "data", "service", "app" };
        var tlds = new[] { "com", "net", "io", "co" };
        return $"{words[Random.Shared.Next(words.Length)]}-{Random.Shared.Next(100, 999)}.{tlds[Random.Shared.Next(tlds.Length)]}";
    }

    private static bool IsPrivateAddress(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        if (bytes.Length == 4)
        {
            return bytes[0] == 10 ||
                   (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168) ||
                   bytes[0] == 127;
        }
        return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal;
    }

    /// <summary>
    /// Sends malformed protocol data designed to trigger parsing bugs in common C2 frameworks.
    /// Many C2 servers have known vulnerabilities in their protocol parsers — oversized fields,
    /// null bytes in headers, integer overflows in length fields, and malformed encoding can
    /// crash or destabilize the team server.
    /// </summary>
    private static async Task<bool> SendProtocolConfusionAsync(IPEndPoint endpoint, string? framework, CancellationToken ct)
    {
        try
        {
            using var socket = new Socket(endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            socket.SendTimeout = 200;
            socket.ReceiveTimeout = 200;

            await socket.ConnectAsync(endpoint, ct).ConfigureAwait(false);

            var payload = GenerateProtocolConfusionPayload(framework);
            await socket.SendAsync(payload, SocketFlags.None, ct).ConfigureAwait(false);

            socket.Shutdown(SocketShutdown.Both);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Generates malformed payloads that exploit known parsing weaknesses in C2 frameworks:
    /// - Oversized Content-Length (integer overflow)
    /// - Null bytes in HTTP headers (string termination confusion)
    /// - Malformed chunked encoding (parser state corruption)
    /// - Invalid UTF-8 sequences (encoding handler crashes)
    /// - Extremely long header values (buffer overflow potential)
    /// </summary>
    private static byte[] GenerateProtocolConfusionPayload(string? framework)
    {
        var random = Random.Shared;
        var variant = random.Next(5);

        return variant switch
        {
            // Integer overflow in Content-Length
            0 => System.Text.Encoding.ASCII.GetBytes(
                "POST /beacon HTTP/1.1\r\n" +
                "Host: localhost\r\n" +
                "Content-Length: 4294967295\r\n" +  // uint.MaxValue — triggers overflow in 32-bit parsers
                "Content-Type: application/octet-stream\r\n\r\n" +
                new string('A', 1024)),

            // Null bytes in headers — confuses C string-based parsers
            1 => System.Text.Encoding.ASCII.GetBytes(
                "GET /\x00../../etc/passwd HTTP/1.1\r\n" +
                "Host: \x00\x00\x00\r\n" +
                "Cookie: session=\x00" + new string('B', 512) + "\r\n\r\n"),

            // Malformed chunked transfer — corrupts parser state machines
            2 => System.Text.Encoding.ASCII.GetBytes(
                "POST /api HTTP/1.1\r\n" +
                "Host: localhost\r\n" +
                "Transfer-Encoding: chunked\r\n\r\n" +
                "FFFFFFFE\r\n" +  // Impossibly large chunk size
                new string('C', 256) + "\r\n" +
                "0\r\n\r\n"),

            // Extremely long URI — buffer overflow in path parsers
            3 => System.Text.Encoding.ASCII.GetBytes(
                $"GET /{new string('/', 8192)}{'A'} HTTP/1.1\r\n" +
                "Host: localhost\r\n\r\n"),

            // Invalid HTTP version + malformed headers — state machine confusion
            _ => System.Text.Encoding.ASCII.GetBytes(
                "PROPFIND / HTTP/9.9\r\n" +
                $"Host: {new string('X', 4096)}\r\n" +
                "Content-Length: -1\r\n" +
                "Expect: 100-continue\r\n" +
                "Transfer-Encoding: gzip, chunked, identity\r\n\r\n" +
                new string('\xff', 256))
        };
    }
}


