using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Core
{
    /// <summary>
    /// v1.6.0: Shared HMAC auth for the Cloudflare threat-proxy Worker.
    ///
    /// Protocol:
    ///   - Signing key = ThreatReportingConfig.ProxySharedSecret (server-side secret;
    ///     never a client-generated key).
    ///   - Payload = $"{unixTimestamp}.{path}.{rawJsonBody}"
    ///   - Headers: X-Sentinel-Timestamp, X-Sentinel-Signature (hex HMAC-SHA256),
    ///              optional X-Sentinel-Auth (same secret, dual-check).
    ///
    /// The worker fails closed if SENTINEL_SHARED_SECRET is unset and never
    /// accepts a client-supplied signing key (removed X-Sentinel-Key).
    /// </summary>
    public static class ProxyAuthHelper
    {
        public static bool HasSharedSecret(ThreatReportingConfig? config) =>
            config != null && !string.IsNullOrWhiteSpace(config.ProxySharedSecret)
            && config.ProxySharedSecret.Length >= 16;

        /// <summary>
        /// Signs <paramref name="jsonBody"/> and applies auth headers to <paramref name="request"/>.
        /// Returns false if the shared secret is missing/too short (caller should skip the call).
        /// </summary>
        public static bool TryApplyAuthHeaders(
            HttpRequestMessage request,
            ThreatReportingConfig config,
            string path,
            string jsonBody)
        {
            if (!HasSharedSecret(config))
                return false;

            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            var signaturePayload = $"{timestamp}.{path}.{jsonBody}";
            string signature;
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(config.ProxySharedSecret!)))
            {
                var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(signaturePayload));
                signature = Convert.ToHexString(hash).ToLowerInvariant();
            }

            request.Headers.TryAddWithoutValidation("X-Sentinel-Timestamp", timestamp);
            request.Headers.TryAddWithoutValidation("X-Sentinel-Signature", signature);
            request.Headers.TryAddWithoutValidation("X-Sentinel-Auth", config.ProxySharedSecret!);
            return true;
        }

        /// <summary>
        /// Convenience: build StringContent and a fully-authenticated POST request.
        /// </summary>
        public static (HttpRequestMessage? request, string? error) CreateAuthenticatedPost(
            string baseEndpoint,
            string path,
            string jsonBody,
            ThreatReportingConfig config)
        {
            if (!HasSharedSecret(config))
                return (null, "ProxySharedSecret missing or shorter than 16 characters");

            if (string.IsNullOrWhiteSpace(baseEndpoint))
                return (null, "ProxyEndpoint not configured");

            var url = baseEndpoint.TrimEnd('/') + path;
            var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(jsonBody, Encoding.UTF8, "application/json")
            };

            if (!TryApplyAuthHeaders(request, config, path, jsonBody))
            {
                request.Dispose();
                return (null, "Failed to apply auth headers");
            }

            return (request, null);
        }
    }
}
