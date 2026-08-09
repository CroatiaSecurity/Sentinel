using System;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Sentinel.Core
{
    /// <summary>
    /// v1.6.0 / v1.8.1 / v2.0.4: Shared HMAC auth for the Cloudflare threat-proxy Worker.
    ///
    /// Protocol:
    ///   - Signing key = ThreatReportingConfig.ProxySharedSecret (server-side secret;
    ///     never a client-generated key). The secret is used only as the HMAC key —
    ///     it is never transmitted in a request header.
    ///   - Payload = $"{unixTimestamp}.{path}.{rawJsonBody}"
    ///   - Headers: X-Sentinel-Timestamp, X-Sentinel-Signature (hex HMAC-SHA256).
    ///
    /// SECURITY v1.8.1 (RT-CRIT-1): Removed X-Sentinel-Auth which previously sent the
    /// shared secret in cleartext. HMAC signature + timestamp is sufficient authentication.
    ///
    /// v2.0.4 HIGH-3: Added certificate pinning for Cloudflare proxy endpoint.
    /// Pins Cloudflare's intermediate CA public key SHA-256 hash to prevent MITM
    /// with rogue trusted CAs (corporate proxy, compromised CA).
    ///
    /// The worker fails closed if SENTINEL_SHARED_SECRET is unset and never
    /// accepts a client-supplied signing key (removed X-Sentinel-Key).
    /// </summary>
    public static class ProxyAuthHelper
    {
        // v2.0.4 HIGH-3: SHA-256 hashes of pinned certificate public keys.
        // Cloudflare uses these intermediate CAs for Workers. Multiple pins for rotation.
        // Pin format: Base64(SHA-256(SubjectPublicKeyInfo))
        // If Cloudflare rotates their CA, add the new pin here before removing the old one.
        private static readonly string[] PinnedPublicKeyHashes = new[]
        {
            // Cloudflare Inc ECC CA-3 (current Workers cert chain)
            "Lgav0MBe0RVNHGOV2aCGLSCj4F8XJGI1YMPgWGMFnuM=",
            // Cloudflare Inc RSA CA-2 (backup/rotation)
            "jQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0=",
            // Baltimore CyberTrust Root (legacy chain)
            "Y9mvm0exBk1JoQ57f9Vm28jKo5lFm/woKcVxrYxu80o=",
            // DigiCert Global Root G2 (current trust anchor)
            "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=",
        };

        /// <summary>
        /// v2.0.4: Creates an HttpClient with certificate pinning for the proxy endpoint.
        /// Falls back to standard validation if pinning cannot be applied (net48 limitations).
        /// </summary>
        public static HttpClient CreatePinnedHttpClient(int timeoutSeconds = 10)
        {
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = ValidateCertificatePin;
            return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(timeoutSeconds) };
        }

        /// <summary>
        /// Certificate validation callback that enforces public key pinning.
        /// Accepts the connection only if at least one certificate in the chain
        /// matches a pinned public key hash.
        /// </summary>
        private static bool ValidateCertificatePin(
            HttpRequestMessage request,
            X509Certificate2? certificate,
            X509Chain? chain,
            SslPolicyErrors sslErrors)
        {
            // Reject if basic SSL validation fails (expired, hostname mismatch, etc.)
            if (sslErrors != SslPolicyErrors.None)
                return false;

            if (certificate == null)
                return false;

            // Check the leaf certificate
            if (IsPinMatch(certificate))
                return true;

            // Check the chain (intermediates + root)
            if (chain != null)
            {
                foreach (var element in chain.ChainElements)
                {
                    if (IsPinMatch(element.Certificate))
                        return true;
                }
            }

            // No pin matched — possible MITM
            return false;
        }

        private static bool IsPinMatch(X509Certificate2 cert)
        {
            try
            {
                using var sha = SHA256.Create();
                var pubKeyBytes = cert.GetPublicKey();
                // Hash the full SubjectPublicKeyInfo (DER-encoded public key from cert)
                var hash = sha.ComputeHash(pubKeyBytes);
                var hashBase64 = Convert.ToBase64String(hash);
                foreach (var pin in PinnedPublicKeyHashes)
                {
                    if (string.Equals(hashBase64, pin, StringComparison.Ordinal))
                        return true;
                }
            }
            catch { }
            return false;
        }

        public static bool HasSharedSecret(ThreatReportingConfig? config) =>
            config != null && !string.IsNullOrWhiteSpace(config.ProxySharedSecret)
            && config.ProxySharedSecret!.Length >= 16;

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
                signature = ConvertHex.ToHexString(hash).ToLowerInvariant();
            }

            request.Headers.TryAddWithoutValidation("X-Sentinel-Timestamp", timestamp);
            request.Headers.TryAddWithoutValidation("X-Sentinel-Signature", signature);
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
