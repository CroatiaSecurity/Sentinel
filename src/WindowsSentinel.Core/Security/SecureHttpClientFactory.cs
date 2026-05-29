using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Security;

/// <summary>
/// Secure HTTP Client Factory — Creates HttpClient instances with certificate validation
/// and security hardening for threat intelligence API communication.
///
/// Security features:
///   - TLS 1.2+ enforcement (no SSL3, TLS 1.0, TLS 1.1)
///   - Certificate chain validation
///   - Domain validation against expected hosts
///   - Timeout enforcement
///   - User-Agent identification
///   - No automatic redirect following (prevents SSRF)
///
/// This does NOT implement certificate pinning (which would break on cert rotation),
/// but does enforce strict certificate validation and domain allowlisting.
/// </summary>
public sealed class SecureHttpClientFactory : IDisposable
{
    private readonly ILogger<SecureHttpClientFactory> _logger;
    private readonly HttpClient _httpClient;
    private bool _disposed;

    /// <summary>
    /// Allowed domains for threat intelligence API communication.
    /// Only these domains will be contacted.
    /// </summary>
    private static readonly HashSet<string> AllowedDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "api.abuseipdb.com",
        "urlhaus-api.abuse.ch",
        "mb-api.abuse.ch",
        "bazaar.abuse.ch",
        "hashlookup.circl.lu",
        "hash.cymru.com"
    };

    /// <summary>
    /// Default request timeout.
    /// </summary>
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(15);

    public SecureHttpClientFactory(ILogger<SecureHttpClientFactory> logger)
    {
        _logger = logger;

        var handler = new HttpClientHandler
        {
            // Enforce TLS 1.2+
            SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | 
                          System.Security.Authentication.SslProtocols.Tls13,
            
            // Custom certificate validation
            ServerCertificateCustomValidationCallback = ValidateServerCertificate,
            
            // Disable automatic redirects (prevents SSRF)
            AllowAutoRedirect = false,
            
            // Disable cookies (not needed for API calls)
            UseCookies = false,
            
            // Set max connections per server
            MaxConnectionsPerServer = 5
        };

        _httpClient = new HttpClient(handler)
        {
            Timeout = DefaultTimeout
        };

        // Set default headers
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("WindowsSentinel-EDR/4.5.0");
        _httpClient.DefaultRequestHeaders.Accept.ParseAdd("application/json");
    }

    /// <summary>
    /// Gets the secure HTTP client instance.
    /// </summary>
    public HttpClient Client => _httpClient;

    /// <summary>
    /// Validates if a URL is allowed for outbound communication.
    /// </summary>
    /// <param name="url">The URL to validate.</param>
    /// <returns>True if the URL is allowed, false otherwise.</returns>
    public bool IsAllowedUrl(string url)
    {
        try
        {
            var uri = new Uri(url);
            
            // Must be HTTPS
            if (uri.Scheme != "https")
            {
                _logger.LogWarning("SecureHttpClient: Rejected non-HTTPS URL: {Url}", url);
                return false;
            }

            // Must be in allowed domains
            if (!AllowedDomains.Contains(uri.Host))
            {
                _logger.LogWarning("SecureHttpClient: Rejected URL to non-allowed domain: {Host}", uri.Host);
                return false;
            }

            return true;
        }
        catch (UriFormatException)
        {
            _logger.LogWarning("SecureHttpClient: Rejected malformed URL: {Url}", url);
            return false;
        }
    }

    /// <summary>
    /// Sends a request only if the URL is in the allowed domain list.
    /// </summary>
    public async Task<HttpResponseMessage?> SendSecureAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (request.RequestUri == null)
        {
            _logger.LogWarning("SecureHttpClient: Request has no URI");
            return null;
        }

        if (!IsAllowedUrl(request.RequestUri.ToString()))
        {
            return null;
        }

        try
        {
            return await _httpClient.SendAsync(request, ct);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning(ex, "SecureHttpClient: Request failed to {Host}", request.RequestUri.Host);
            return null;
        }
        catch (TaskCanceledException)
        {
            _logger.LogWarning("SecureHttpClient: Request timed out to {Host}", request.RequestUri.Host);
            return null;
        }
    }

    /// <summary>
    /// Custom certificate validation callback.
    /// </summary>
    private bool ValidateServerCertificate(HttpRequestMessage request, X509Certificate2? certificate, 
        X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        // Reject if no certificate
        if (certificate == null)
        {
            _logger.LogWarning("SecureHttpClient: Server presented no certificate for {Host}", 
                request.RequestUri?.Host);
            return false;
        }

        // Reject if there are any SSL policy errors
        if (sslPolicyErrors != SslPolicyErrors.None)
        {
            _logger.LogWarning(
                "SecureHttpClient: Certificate validation failed for {Host}: {Errors}",
                request.RequestUri?.Host, sslPolicyErrors);
            return false;
        }

        // Verify the certificate is not expired
        if (certificate.NotAfter < DateTime.UtcNow)
        {
            _logger.LogWarning(
                "SecureHttpClient: Certificate expired for {Host} (expired: {Expiry})",
                request.RequestUri?.Host, certificate.NotAfter);
            return false;
        }

        // Verify the certificate is not too far in the future (possible clock manipulation)
        if (certificate.NotBefore > DateTime.UtcNow.AddDays(1))
        {
            _logger.LogWarning(
                "SecureHttpClient: Certificate not yet valid for {Host} (valid from: {NotBefore})",
                request.RequestUri?.Host, certificate.NotBefore);
            return false;
        }

        // Verify chain is valid
        if (chain != null)
        {
            foreach (var status in chain.ChainStatus)
            {
                if (status.Status != X509ChainStatusFlags.NoError)
                {
                    _logger.LogWarning(
                        "SecureHttpClient: Certificate chain error for {Host}: {Status} - {Info}",
                        request.RequestUri?.Host, status.Status, status.StatusInformation);
                    return false;
                }
            }
        }

        _logger.LogDebug(
            "SecureHttpClient: Certificate validated for {Host} (Subject: {Subject}, Expires: {Expiry})",
            request.RequestUri?.Host, certificate.Subject, certificate.NotAfter);

        return true;
    }

    /// <summary>
    /// Disposes the HTTP client and handler.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            _httpClient.Dispose();
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}

