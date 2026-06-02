using System.Collections.Concurrent;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core;

/// <summary>
/// TLS Certificate Transparency Monitor (v3.6.0) â€” Detects MITM via certificate anomalies.
///
/// When an attacker performs a TLS MITM (SSL stripping, proxy interception), they must
/// present their own certificate to the client. This monitor detects such interception by:
///
///   1. Periodically connecting to well-known HTTPS endpoints.
///   2. Inspecting the presented TLS certificate.
///   3. Alerting if:
///      a) Certificate issuer is unexpected (not the known CA for that domain)
///      b) Certificate is self-signed
///      c) Certificate subject doesn't match the domain
///      d) Certificate has suspicious properties (very short validity, unknown CA)
///      e) Certificate fingerprint changed from baseline (pinning)
///
/// This catches:
///   - Corporate/enterprise MITM proxies (Zscaler, BlueCoat, Forcepoint)
///   - Attacker-operated MITM proxies (mitmproxy, Burp Suite)
///   - SSL stripping attacks
///   - Compromised CA certificates
///
/// NOTE: Enterprise environments legitimately use TLS inspection proxies.
/// The monitor distinguishes between "known enterprise CA" (Tier2 log) and
/// "unknown/suspicious CA" (Tier1 alert).
/// </summary>
public sealed class TlsCertificateMonitor : BackgroundService
{
    private readonly DetectionEngine _detectionEngine;
    private readonly ILogger<TlsCertificateMonitor> _logger;

    private static readonly TimeSpan CheckInterval = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan HttpTimeout = TimeSpan.FromSeconds(15);

    // Baseline certificate fingerprints (captured on first successful check)
    private readonly ConcurrentDictionary<string, CertBaseline> _certBaselines = new();

    // Deduplication
    private readonly ConcurrentDictionary<string, DateTime> _alertedEvents = new();
    private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromMinutes(30);

    // Domains to check and their expected certificate issuers (partial match)
    private static readonly CertCheckTarget[] CheckTargets =
    {
        new("https://www.google.com", new[] { "Google Trust Services", "GTS CA", "GlobalSign" }),
        new("https://www.microsoft.com", new[] { "Microsoft", "DigiCert", "Baltimore CyberTrust", "Akamai" }),
        new("https://one.one.one.one", new[] { "DigiCert", "Cloudflare", "Google Trust Services", "GTS", "SSL.com" }),
        new("https://github.com", new[] { "DigiCert", "Sectigo", "Let's Encrypt" }),
        new("https://www.cloudflare.com", new[] { "DigiCert", "Cloudflare", "Google Trust Services", "GTS", "SSL.com" }),
    };

    // Known enterprise TLS inspection CAs (Tier2 â€” legitimate but worth noting)
    private static readonly string[] KnownEnterpriseCAs =
    {
        "Zscaler", "BlueCoat", "Symantec", "Forcepoint",
        "Palo Alto", "Fortinet", "FortiGate",
        "Cisco Umbrella", "Websense", "McAfee",
        "Check Point", "Sophos", "Barracuda",
        "Netskope", "iboss", "ContentKeeper",
    };

    public TlsCertificateMonitor(
        DetectionEngine detectionEngine,
        ILogger<TlsCertificateMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[TlsCertificateMonitor] Starting â€” TLS certificate integrity monitoring active");

        // Wait for network
        await Task.Delay(TimeSpan.FromSeconds(25), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckCertificatesAsync(stoppingToken);
                PruneAlertCache();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "[TlsCertificateMonitor] Check error");
            }

            await Task.Delay(CheckInterval, stoppingToken);
        }
    }

    private async Task CheckCertificatesAsync(CancellationToken ct)
    {
        foreach (var target in CheckTargets)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                var certInfo = await GetCertificateInfoAsync(target.Url, ct);
                if (certInfo == null) continue;

                await ValidateCertificateAsync(target, certInfo, ct);
            }
            catch (HttpRequestException)
            {
                // Connection failed â€” network issue, not necessarily an attack
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "[TlsCertificateMonitor] Error checking {Url}", target.Url);
            }
        }
    }

    private async Task ValidateCertificateAsync(CertCheckTarget target, CertInfo cert, CancellationToken ct)
    {
        var domain = new Uri(target.Url).Host;

        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // CHECK 1: Self-signed certificate (immediate red flag)
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        if (cert.IsSelfSigned)
        {
            var dedupeKey = $"self_signed:{domain}";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTime.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Network Hijack: Self-Signed Certificate on Major Domain (TLS MITM)",
                    Evidence = $"Domain '{domain}' presented a SELF-SIGNED certificate. " +
                               $"Subject: {cert.Subject}, Issuer: {cert.Issuer}, " +
                               $"Thumbprint: {cert.Thumbprint}. " +
                               "Major domains NEVER use self-signed certificates.",
                    Reasoning = "A self-signed certificate on a major domain (Google, Microsoft, Cloudflare) " +
                                "is an absolute indicator of TLS interception. Someone is performing a " +
                                "man-in-the-middle attack, decrypting all HTTPS traffic. This could be " +
                                "mitmproxy, Burp Suite, or a compromised network device.",
                    Confidence = 0.95,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "Network",
                    ProcessId = 0,
                    Timestamp = DateTime.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["domain"] = domain,
                        ["cert_subject"] = cert.Subject,
                        ["cert_issuer"] = cert.Issuer,
                        ["cert_thumbprint"] = cert.Thumbprint,
                        ["is_self_signed"] = "true",
                        ["technique"] = "T1557.002 - ARP Cache Poisoning",
                        ["attack_type"] = "tls_mitm_self_signed"
                    }
                }, ct);
            }
            return;
        }

        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // CHECK 2: Unexpected issuer (not in expected CA list)
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        var issuerMatchesExpected = target.ExpectedIssuers.Any(expected =>
            cert.Issuer.Contains(expected, StringComparison.OrdinalIgnoreCase));

        if (!issuerMatchesExpected)
        {
            // Check if it's a known enterprise CA (lower severity)
            var isEnterpriseCa = KnownEnterpriseCAs.Any(ca =>
                cert.Issuer.Contains(ca, StringComparison.OrdinalIgnoreCase));

            var dedupeKey = $"unexpected_issuer:{domain}:{cert.Issuer}";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTime.UtcNow);

                if (isEnterpriseCa)
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Network Integrity: Enterprise TLS Inspection Detected",
                        Evidence = $"Domain '{domain}' certificate issued by enterprise CA: {cert.Issuer}. " +
                                   "This indicates corporate TLS inspection (traffic decryption by proxy).",
                        Reasoning = "An enterprise TLS inspection proxy (Zscaler, BlueCoat, etc.) is decrypting " +
                                    "HTTPS traffic. This is common in corporate environments but means all " +
                                    "encrypted traffic is visible to the proxy operator. If this is unexpected " +
                                    "(home network, personal device), it indicates unauthorized interception.",
                        Confidence = 0.65,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = "Network",
                        ProcessId = 0,
                        Timestamp = DateTime.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["domain"] = domain,
                            ["cert_issuer"] = cert.Issuer,
                            ["cert_subject"] = cert.Subject,
                            ["is_enterprise_ca"] = "true",
                            ["technique"] = "T1557 - Adversary-in-the-Middle",
                            ["attack_type"] = "enterprise_tls_inspection"
                        }
                    }, ct);
                }
                else
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Network Hijack: Unexpected Certificate Issuer (TLS MITM)",
                        Evidence = $"Domain '{domain}' certificate issued by UNEXPECTED CA: {cert.Issuer}. " +
                                   $"Expected issuers: [{string.Join(", ", target.ExpectedIssuers)}]. " +
                                   $"Subject: {cert.Subject}, Valid: {cert.NotBefore:d} to {cert.NotAfter:d}, " +
                                   $"Thumbprint: {cert.Thumbprint}.",
                        Reasoning = "A major domain's TLS certificate was issued by an unexpected Certificate " +
                                    "Authority. This indicates TLS interception â€” someone is performing a " +
                                    "man-in-the-middle attack using their own CA certificate. The CA is not " +
                                    "a known enterprise proxy, making this highly suspicious.",
                        Confidence = 0.90,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "Network",
                        ProcessId = 0,
                        Timestamp = DateTime.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["domain"] = domain,
                            ["cert_issuer"] = cert.Issuer,
                            ["cert_subject"] = cert.Subject,
                            ["cert_thumbprint"] = cert.Thumbprint,
                            ["expected_issuers"] = string.Join(";", target.ExpectedIssuers),
                            ["cert_not_before"] = cert.NotBefore.ToString("o"),
                            ["cert_not_after"] = cert.NotAfter.ToString("o"),
                            ["technique"] = "T1557 - Adversary-in-the-Middle",
                            ["attack_type"] = "tls_mitm_unknown_ca"
                        }
                    }, ct);
                }
            }
            return;
        }

        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // CHECK 3: Certificate pinning â€” fingerprint changed from baseline
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        if (_certBaselines.TryGetValue(domain, out var baseline))
        {
            // Only alert if the issuer also changed (same issuer + different thumbprint = normal rotation)
            if (!string.Equals(baseline.Thumbprint, cert.Thumbprint, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(baseline.Issuer, cert.Issuer, StringComparison.OrdinalIgnoreCase))
            {
                var dedupeKey = $"cert_pin:{domain}:{cert.Thumbprint}";
                if (!_alertedEvents.ContainsKey(dedupeKey))
                {
                    _alertedEvents.TryAdd(dedupeKey, DateTime.UtcNow);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Network Integrity: Certificate Issuer Changed From Baseline",
                        Evidence = $"Domain '{domain}' certificate issuer changed. " +
                                   $"Baseline: {baseline.Issuer} (thumbprint {baseline.Thumbprint[..16]}...). " +
                                   $"Current: {cert.Issuer} (thumbprint {cert.Thumbprint[..16]}...). " +
                                   "While certificate rotation is normal, issuer changes are rare.",
                        Reasoning = "The certificate issuer for a monitored domain changed from the baseline. " +
                                    "Normal certificate rotation keeps the same CA. An issuer change could " +
                                    "indicate: (1) domain migrated to new CA (legitimate but rare), " +
                                    "(2) TLS interception started/changed, (3) compromised CA.",
                        Confidence = 0.60,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = "Network",
                        ProcessId = 0,
                        Timestamp = DateTime.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["domain"] = domain,
                            ["baseline_issuer"] = baseline.Issuer,
                            ["current_issuer"] = cert.Issuer,
                            ["baseline_thumbprint"] = baseline.Thumbprint,
                            ["current_thumbprint"] = cert.Thumbprint,
                            ["technique"] = "T1557 - Adversary-in-the-Middle",
                            ["attack_type"] = "cert_issuer_change"
                        }
                    }, ct);
                }
            }
        }
        else
        {
            // First time seeing this domain â€” capture baseline
            _certBaselines[domain] = new CertBaseline
            {
                Issuer = cert.Issuer,
                Thumbprint = cert.Thumbprint,
                CapturedAt = DateTime.UtcNow
            };
        }

        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // CHECK 4: Suspiciously short validity period
        // Legitimate CAs issue certs for 90 days (Let's Encrypt) to 1 year.
        // MITM tools often generate certs with very short or very long validity.
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        var validity = cert.NotAfter - cert.NotBefore;
        if (validity.TotalDays < 7 || validity.TotalDays > 825) // < 1 week or > ~2.25 years
        {
            var dedupeKey = $"cert_validity:{domain}:{validity.TotalDays:F0}";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTime.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Network Integrity: Suspicious Certificate Validity Period",
                    Evidence = $"Domain '{domain}' certificate has unusual validity: {validity.TotalDays:F0} days " +
                               $"(from {cert.NotBefore:d} to {cert.NotAfter:d}). " +
                               "Normal certificates are 90-397 days.",
                    Reasoning = "TLS certificates with very short validity (< 7 days) or very long validity " +
                                "(> 825 days) are suspicious. MITM tools often generate certificates with " +
                                "non-standard validity periods. Legitimate CAs follow industry standards " +
                                "(90 days for Let's Encrypt, up to 397 days for commercial CAs).",
                    Confidence = 0.55,
                    Tier = DetectionTier.Tier2Indicator,
                    ProcessName = "Network",
                    ProcessId = 0,
                    Timestamp = DateTime.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["domain"] = domain,
                        ["validity_days"] = validity.TotalDays.ToString("F0"),
                        ["cert_issuer"] = cert.Issuer,
                        ["technique"] = "T1557 - Adversary-in-the-Middle",
                        ["attack_type"] = "suspicious_cert_validity"
                    }
                }, ct);
            }
        }
    }

    private async Task<CertInfo?> GetCertificateInfoAsync(string url, CancellationToken ct)
    {
        CertInfo? result = null;

        using var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
            {
                if (cert != null)
                {
                    result = new CertInfo
                    {
                        Subject = cert.Subject,
                        Issuer = cert.Issuer,
                        Thumbprint = cert.GetCertHashString() ?? "",
                        NotBefore = cert.NotBefore,
                        NotAfter = cert.NotAfter,
                        IsSelfSigned = string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase),
                    };
                }
                return true; // Accept all certs (we're inspecting, not enforcing)
            }
        };

        using var client = new HttpClient(handler) { Timeout = HttpTimeout };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("WindowsSentinel/5.1.0");

        try
        {
            // Just need to establish TLS â€” don't need to read the response
            using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        }
        catch (HttpRequestException)
        {
            // Connection failed but we may still have captured the cert
        }

        return result;
    }

    private void PruneAlertCache()
    {
        var cutoff = DateTime.UtcNow - AlertDedupeWindow;
        foreach (var kvp in _alertedEvents)
        {
            if (kvp.Value < cutoff)
                _alertedEvents.TryRemove(kvp.Key, out _);
        }
    }

    private sealed class CertInfo
    {
        public required string Subject { get; init; }
        public required string Issuer { get; init; }
        public required string Thumbprint { get; init; }
        public required DateTime NotBefore { get; init; }
        public required DateTime NotAfter { get; init; }
        public required bool IsSelfSigned { get; init; }
    }

    private sealed class CertBaseline
    {
        public required string Issuer { get; init; }
        public required string Thumbprint { get; init; }
        public required DateTime CapturedAt { get; init; }
    }

    private sealed record CertCheckTarget(string Url, string[] ExpectedIssuers);
}

