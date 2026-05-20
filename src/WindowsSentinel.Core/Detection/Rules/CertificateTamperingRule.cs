using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Detects certificate store tampering and unauthorized certificate installations.
/// 
/// Protects against:
/// - Rogue root CA installation
/// - Certificate substitution attacks
/// - Unauthorized code signing certs
/// - Certificate pinning bypass attempts
/// </summary>
public sealed class CertificateTamperingRule : IDetectionRule
{
    public string Name => "Certificate Store Tampering";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    private readonly ILogger<CertificateTamperingRule> _logger;
    private readonly IServiceProvider _serviceProvider;
    
    // Baseline of legitimate root CAs (thumbprints)
    private readonly HashSet<string> _knownRootCAs = new(StringComparer.OrdinalIgnoreCase)
    {
        // Microsoft
        "A43489159A520F0D93D032CCAF37E7FE20A8B419", // Microsoft Root CA
        "8F43288AD272F3103B6FB1428485EA3014C0BCFE", // Microsoft ECC Root
        "D4DE20D05E66FC53FE1A50882C78DB2852CAE474", // Microsoft RSA Root
        // DigiCert
        "A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436", // DigiCert Global Root
        "43DF5774B03E7FEF5FE40D931A7BEDF1BB2E6B60", // DigiCert Assured ID
        // GlobalSign
        "B1BC968BD4F49D622AA89A81F2150152A41D829C", // GlobalSign Root
        "FF856C8DAF6B2B1625E0E8F87D5674A623A11F2A", // GlobalSign ECC
        // Let's Encrypt / ISRG
        "CABD2A79A1076A31F21D253635CB039D4329A586", // ISRG Root X1
        "6D99FB265EB1C543B4E3C23C5F79A10C4D7C21F8", // ISRG Root X2
        // Cloudflare
        "E4E507B29E24EEFAD09FE9654193876C8D37F5E2", // Cloudflare Inc ECC
        "F83F21EFB5D0EC3C8A8A5DD6E85D42D17D6D5E1A", // Cloudflare Inc RSA
    };

    // Suspicious certificate patterns
    private static readonly string[] SuspiciousPatterns = new[]
    {
        "ninja", "hack", "backdoor", "root", "test", "temp", "fake", "rogue",
        "bypass", "shadow", "ghost", "hidden", "secret", "proxy", "mitm"
    };

    public CertificateTamperingRule(
        ILogger<CertificateTamperingRule> logger,
        IServiceProvider serviceProvider)
    {
        _logger = logger;
        _serviceProvider = serviceProvider;
    }

    /// <summary>
    /// IDetectionRule implementation - evaluates telemetry for certificate tampering.
    /// Certificate tampering is detected via scheduled scans, not process telemetry.
    /// </summary>
    public DetectionEvent? Evaluate(object telemetry)
    {
        // Certificate tampering is detected via scheduled scans, not process telemetry
        return null;
    }

    /// <summary>
    /// Scans certificate stores for tampering. Call this periodically.
    /// </summary>
    public async Task ScanCertificateStoresAsync(CancellationToken ct = default)
    {
        try
        {
            // Check LocalMachine\Root for new/unknown certificates
            await CheckRootStoreAsync(ct);
            
            // Check TrustedPublisher for suspicious additions
            await CheckTrustedPublisherStoreAsync(ct);
            
            // Check ThirdPartyRoot (enterprise CAs)
            await CheckThirdPartyRootStoreAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "CertificateTampering: Error scanning stores");
        }
    }

    private async Task CheckRootStoreAsync(CancellationToken ct)
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);

        foreach (var cert in store.Certificates)
        {
            var thumbprint = cert.Thumbprint;
            var subject = cert.Subject;
            
            // Check if this is a known root CA
            if (_knownRootCAs.Contains(thumbprint))
                continue;

            // Check if recently added (last 24 hours)
            if (cert.NotBefore > DateTime.Now.AddHours(-24))
            {
                _logger.LogCritical(
                    "CertificateTampering: NEW ROOT CA DETECTED - {Subject} (Thumbprint: {Thumbprint})",
                    subject, thumbprint);

                await EmitDetectionAsync(
                    "CRITICAL: New Root CA Installed",
                    $"A new root certificate was added to the trust store: {subject}",
                    $"Unknown root certificate installed. This could allow MITM attacks, code signing bypass, or system compromise. " +
                    $"Subject: {subject}, Issuer: {cert.Issuer}, NotBefore: {cert.NotBefore}, Thumbprint: {thumbprint}",
                    0.95,
                    new Dictionary<string, string>
                    {
                        ["certificate_subject"] = subject,
                        ["certificate_issuer"] = cert.Issuer,
                        ["certificate_thumbprint"] = thumbprint,
                        ["certificate_notbefore"] = cert.NotBefore.ToString("O"),
                        ["certificate_notafter"] = cert.NotAfter.ToString("O"),
                        ["store"] = "LocalMachine\\Root",
                        ["technique"] = "T1553.004 - Subvert Trust Controls: Install Root Certificate"
                    },
                    ct);
            }

            // Check for suspicious names
            var subjectLower = subject.ToLowerInvariant();
            if (SuspiciousPatterns.Any(p => subjectLower.Contains(p)))
            {
                _logger.LogCritical(
                    "CertificateTampering: SUSPICIOUS CERTIFICATE NAME - {Subject}",
                    subject);

                await EmitDetectionAsync(
                    "HIGH: Suspicious Certificate Name Detected",
                    $"Certificate with suspicious name in root store: {subject}",
                    $"The certificate subject contains suspicious keywords that may indicate malicious intent. " +
                    $"This could be a rogue CA or attack tool certificate.",
                    0.90,
                    new Dictionary<string, string>
                    {
                        ["certificate_subject"] = subject,
                        ["certificate_thumbprint"] = thumbprint,
                        ["suspicious_keywords"] = string.Join(", ", 
                            SuspiciousPatterns.Where(p => subjectLower.Contains(p))),
                        ["store"] = "LocalMachine\\Root",
                        ["technique"] = "T1553.004 - Subvert Trust Controls: Install Root Certificate"
                    },
                    ct);
            }

            // Check for self-signed that isn't a known root
            if (cert.Subject == cert.Issuer && !_knownRootCAs.Contains(thumbprint))
            {
                _logger.LogWarning(
                    "CertificateTampering: Self-signed certificate in Root store - {Subject}",
                    subject);

                await EmitDetectionAsync(
                    "MEDIUM: Self-Signed Certificate in Root Store",
                    $"Self-signed certificate installed as trusted root: {subject}",
                    $"Self-signed certificates in the root store can be used to bypass security checks. " +
                    $"Verify this certificate is legitimate.",
                    0.75,
                    new Dictionary<string, string>
                    {
                        ["certificate_subject"] = subject,
                        ["certificate_thumbprint"] = thumbprint,
                        ["store"] = "LocalMachine\\Root",
                        ["technique"] = "T1553.004 - Subvert Trust Controls: Install Root Certificate"
                    },
                    ct);
            }
        }
    }

    private async Task CheckTrustedPublisherStoreAsync(CancellationToken ct)
    {
        using var store = new X509Store(StoreName.TrustedPublisher, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);

        foreach (var cert in store.Certificates)
        {
            // Check for recently added code signing certs
            if (cert.NotBefore > DateTime.Now.AddHours(-24))
            {
                _logger.LogWarning(
                    "CertificateTampering: New Trusted Publisher - {Subject}",
                    cert.Subject);

                await EmitDetectionAsync(
                    "MEDIUM: New Trusted Publisher Certificate",
                    $"New code signing certificate trusted: {cert.Subject}",
                    $"A new code signing certificate was added to Trusted Publishers. " +
                    $"This could allow malicious signed executables to run without warnings.",
                    0.70,
                    new Dictionary<string, string>
                    {
                        ["certificate_subject"] = cert.Subject,
                        ["certificate_issuer"] = cert.Issuer,
                        ["certificate_thumbprint"] = cert.Thumbprint,
                        ["store"] = "LocalMachine\\TrustedPublisher",
                        ["technique"] = "T1553.002 - Subvert Trust Controls: Code Signing"
                    },
                    ct);
            }
        }
    }

    private async Task CheckThirdPartyRootStoreAsync(CancellationToken ct)
    {
        try
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            // Look for enterprise/AD certificates
            foreach (var cert in store.Certificates)
            {
                var subject = cert.Subject;
                if (subject.Contains("AD") || subject.Contains("Domain") || 
                    subject.Contains("Enterprise") || subject.Contains("Corp"))
                {
                    if (cert.NotBefore > DateTime.Now.AddDays(-7))
                    {
                        _logger.LogWarning(
                            "CertificateTampering: New Enterprise/AD Certificate - {Subject}",
                            subject);

                        await EmitDetectionAsync(
                            "MEDIUM: New Enterprise Certificate",
                            $"New enterprise/AD certificate: {subject}",
                            $"A new enterprise certificate authority was added. If this is unexpected, " +
                            $"it could indicate domain compromise or unauthorized GPO deployment.",
                            0.65,
                            new Dictionary<string, string>
                            {
                                ["certificate_subject"] = subject,
                                ["certificate_thumbprint"] = cert.Thumbprint,
                                ["registry_key"] = @"HKLM\SYSTEM\CurrentControlSet\Services\Windows Sentinel",
                                ["store"] = "LocalMachine\\Root (Enterprise)",
                                ["technique"] = "T1553.004 - Subvert Trust Controls: Install Root Certificate"
                            },
                            ct);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "CertificateTampering: Error checking ThirdPartyRoot");
        }
    }

    private async Task EmitDetectionAsync(
        string ruleName,
        string evidence,
        string reasoning,
        double confidence,
        Dictionary<string, string> metadata,
        CancellationToken ct)
    {
        // Lazily resolve IDetectionEngine to avoid circular dependency
        var detectionEngine = _serviceProvider.GetRequiredService<IDetectionEngine>();
        await detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = ruleName,
            Evidence = evidence,
            Reasoning = reasoning,
            Confidence = confidence,
            Tier = DetectionTier.Tier1Behavioral,
            ProcessName = "System",
            ProcessId = 0,
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = metadata
        }, ct);
    }
}


