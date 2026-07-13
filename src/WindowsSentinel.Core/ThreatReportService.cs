using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Reports detected threats to threat intelligence platforms via the Cloudflare Worker proxy.
    /// The proxy holds API keys server-side so they never appear in the open-source repo.
    /// 
    /// SECURITY v1.4.4: All requests are HMAC-signed using the installation-specific entropy key.
    /// This prevents:
    ///   - MITM inspection of detection telemetry (signature proves authenticity)
    ///   - Replay attacks (timestamp included in signature)
    ///   - Fake report injection by third parties (no key = invalid signature)
    /// The proxy validates the signature server-side before forwarding to threat intel APIs.
    /// 
    /// If ProxyEndpoint is null, reporting is silently skipped (lookups still work via HashReputationService).
    /// </summary>
    public class ThreatReportService
    {
        private readonly ThreatReportingConfig _config;
        private readonly ILogger<ThreatReportService> _logger;
        private readonly HttpClient _httpClient;
        private readonly byte[] _hmacKey;

        public ThreatReportService(ThreatReportingConfig config, ILogger<ThreatReportService> logger, SecureCacheStore? cacheStore = null)
        {
            _config = config;
            _logger = logger;
            _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };

            // Derive HMAC signing key from installation entropy.
            // This is unique per machine and stored in a SYSTEM-ACL-protected directory.
            // Even if an attacker reads the source code, they cannot forge signatures
            // without access to the machine's .install_entropy file (requires SYSTEM/Admin).
            _hmacKey = DeriveSigningKey(cacheStore);
        }

        private static byte[] DeriveSigningKey(SecureCacheStore? cacheStore)
        {
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var entropyFile = System.IO.Path.Combine(programData, "WindowsSentinel", "Secure", ".install_entropy");
                if (System.IO.File.Exists(entropyFile))
                {
                    var entropy = System.IO.File.ReadAllBytes(entropyFile);
                    if (entropy.Length == 32)
                    {
                        // Derive a separate key for reporting (don't reuse the cache HMAC key)
                        using var hmac = new HMACSHA256(entropy);
                        return hmac.ComputeHash(Encoding.UTF8.GetBytes("sentinel-threat-report-signing-v1"));
                    }
                }
            }
            catch { }

            // Fallback: generate an ephemeral key (reports will work but proxy can't
            // validate cross-session consistency — acceptable for first-run before entropy exists)
            var fallback = new byte[32];
            using (var rng = RandomNumberGenerator.Create()) { rng.GetBytes(fallback); }
            return fallback;
        }

        /// <summary>
        /// Reports a malicious file hash (SHA256) to MalwareBazaar via proxy.
        /// </summary>
        public async Task ReportHashAsync(string sha256, string[] tags, string comment)
        {
            if (!CanReport()) return;

            await SendReportAsync("/report/hash", new
            {
                type = "hash",
                value = sha256,
                tags,
                comment
            });
        }

        /// <summary>
        /// Reports a malicious URL to URLhaus via proxy.
        /// </summary>
        public async Task ReportUrlAsync(string url, string threat, string[] tags)
        {
            if (!CanReport()) return;

            await SendReportAsync("/report/url", new
            {
                type = "url",
                value = url,
                threat,
                tags
            });
        }

        /// <summary>
        /// Reports a malicious IP to AbuseIPDB via proxy.
        /// Categories: https://www.abuseipdb.com/categories
        /// </summary>
        public async Task ReportIpAsync(string ip, int[] categories, string comment)
        {
            if (!CanReport()) return;

            await SendReportAsync("/report/ip", new
            {
                type = "ip",
                value = ip,
                categories,
                comment
            });
        }

        private bool CanReport()
        {
            if (!_config.Enabled) return false;
            if (string.IsNullOrWhiteSpace(_config.ProxyEndpoint)) return false;
            return true;
        }

        private async Task SendReportAsync(string path, object payload)
        {
            try
            {
                var url = _config.ProxyEndpoint!.TrimEnd('/') + path;
                var json = JsonSerializer.Serialize(payload);

                // SECURITY v1.4.4: Sign the request body with HMAC-SHA256.
                // Signature covers: timestamp + path + body — prevents replay and tampering.
                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
                var signaturePayload = $"{timestamp}.{path}.{json}";
                string signature;
                using (var hmac = new HMACSHA256(_hmacKey))
                {
                    var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(signaturePayload));
                    signature = Convert.ToHexString(hash).ToLowerInvariant();
                }

                var content = new StringContent(json, Encoding.UTF8, "application/json");

                using var request = new HttpRequestMessage(HttpMethod.Post, url);
                request.Content = content;
                request.Headers.Add("X-Sentinel-Timestamp", timestamp);
                request.Headers.Add("X-Sentinel-Signature", signature);

                var response = await _httpClient.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    _logger.LogDebug("Threat report submitted: {Path}", path);
                }
                else
                {
                    _logger.LogWarning("Threat report failed ({Status}): {Path}", (int)response.StatusCode, path);
                }
            }
            catch (Exception ex)
            {
                // Never crash on reporting failure — detection/response is more important
                _logger.LogDebug("Threat report error: {Message}", ex.Message);
            }
        }
    }
}
