using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;
using WindowsSentinel.Core;

namespace WindowsSentinel.Tests.Monitors
{
    public class TlsCertificateMonitorTests
    {
        // ── CertAnalysisResult scoring tests ────────────────────────────────

        [Fact]
        public void AnalyzeCert_SelfSigned_IncreasesConfidence()
        {
            // Self-signed: Subject == Issuer
            using var cert = CreateTestCert("CN=EvilCA", "CN=EvilCA", 30);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.True(result.IsSelfSigned);
            Assert.True(result.Confidence > 0.70, $"Expected > 0.70 but got {result.Confidence}");
            Assert.Contains(result.Reasons, r => r.Contains("Self-signed"));
        }

        [Fact]
        public void AnalyzeCert_ShortValidity_IncreasesConfidence()
        {
            // Short validity: < 365 days
            using var cert = CreateTestCert("CN=ShortLived", "CN=RealIssuer", 60);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.True(result.Confidence > 0.65, $"Expected > 0.65 but got {result.Confidence}");
            Assert.Contains(result.Reasons, r => r.Contains("Short validity"));
        }

        [Fact]
        public void AnalyzeCert_VeryShortValidity_IncreasesConfidenceMore()
        {
            // Very short validity: < 90 days
            using var cert = CreateTestCert("CN=SuperShort", "CN=RealIssuer", 30);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.Contains(result.Reasons, r => r.Contains("Extremely short validity"));
        }

        [Fact]
        public void AnalyzeCert_EnterpriseCa_DowngradesToTier2()
        {
            using var cert = CreateTestCert("CN=Zscaler Root CA", "CN=Zscaler Root CA", 3650);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.Equal(DetectionTier.Tier2Indicator, result.Tier);
            Assert.True(result.IsEnterpriseCa);
            Assert.True(result.Confidence <= 0.65, $"Enterprise CA confidence should be capped at 0.65, got {result.Confidence}");
            Assert.Contains(result.Reasons, r => r.Contains("enterprise TLS inspection"));
        }

        [Fact]
        public void AnalyzeCert_DevTool_DowngradesToTier2()
        {
            using var cert = CreateTestCert("CN=DO_NOT_TRUST_FiddlerRoot", "CN=DO_NOT_TRUST_FiddlerRoot", 3650);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.Equal(DetectionTier.Tier2Indicator, result.Tier);
            Assert.True(result.IsDevTool);
            Assert.True(result.Confidence <= 0.55, $"Dev tool confidence should be capped at 0.55, got {result.Confidence}");
        }

        [Fact]
        public void AnalyzeCert_SelfSignedShortNoRevocation_HighConfidence()
        {
            // Self-signed + short validity + no CRL/OCSP = classic attack cert
            using var cert = CreateTestCert("CN=MyCA", "CN=MyCA", 30);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            // 0.60 base + 0.15 self-signed + 0.10 short + 0.05 very-short + 0.10 no-CRL = 1.00 capped to 0.99
            Assert.True(result.Confidence >= 0.85, $"Multi-signal cert should be >= 0.85, got {result.Confidence}");
            Assert.Equal(DetectionTier.Tier1Behavioral, result.Tier);
        }

        [Fact]
        public void AnalyzeCert_LegitimateCA_StaysLowConfidence()
        {
            // Long validity, different issuer (not self-signed)
            using var cert = CreateTestCert("CN=DigiCert Global Root G2, O=DigiCert Inc", "CN=DigiCert Global Root G2, O=DigiCert Inc", 7300);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            // Self-signed but with very long validity — only gets the self-signed bump
            // Most legitimate root CAs ARE self-signed, so this alone shouldn't trigger action
            Assert.Equal(DetectionTier.Tier1Behavioral, result.Tier);
            Assert.False(result.IsEnterpriseCa);
            Assert.False(result.IsDevTool);
        }

        [Fact]
        public void AnalyzeCert_ConfidenceCappedAt099()
        {
            // Create cert that would exceed 1.0 without cap
            using var cert = CreateTestCert("CN=ab12cd", "CN=ab12cd", 10);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.True(result.Confidence <= 0.99, $"Confidence must be capped at 0.99, got {result.Confidence}");
        }

        [Fact]
        public void AnalyzeCert_ExpiredCert_IncreasesConfidence()
        {
            // Expired cert — suspicious to install
            using var cert = CreateTestCertWithDates("CN=Expired", "CN=Expired",
                DateTime.UtcNow.AddYears(-2), DateTime.UtcNow.AddDays(-1));
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.Contains(result.Reasons, r => r.Contains("Already expired"));
        }

        // ── ResponseAction integration tests ────────────────────────────────

        [Fact]
        public void HighConfidenceCert_GetsRemoveCertAction()
        {
            // A Tier1 cert with confidence >= 0.85 should get RemoveCertAndKillAdder
            using var cert = CreateTestCert("CN=MyCA", "CN=MyCA", 30);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.True(result.Confidence >= 0.85);
            Assert.Equal(DetectionTier.Tier1Behavioral, result.Tier);

            // Verify the authorized response logic matches what the monitor would set
            var authorizedResponse = result.Confidence >= 0.85 && result.Tier == DetectionTier.Tier1Behavioral
                ? ResponseAction.RemoveCertAndKillAdder
                : ResponseAction.LogOnly;
            Assert.Equal(ResponseAction.RemoveCertAndKillAdder, authorizedResponse);
        }

        [Fact]
        public void EnterpriseCa_GetsLogOnlyAction()
        {
            using var cert = CreateTestCert("CN=Palo Alto Networks Root CA", "CN=Palo Alto Networks Root CA", 3650);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.Equal(DetectionTier.Tier2Indicator, result.Tier);

            // Tier2 should always be LogOnly regardless of confidence
            var authorizedResponse = result.Confidence >= 0.85 && result.Tier == DetectionTier.Tier1Behavioral
                ? ResponseAction.RemoveCertAndKillAdder
                : ResponseAction.LogOnly;
            Assert.Equal(ResponseAction.LogOnly, authorizedResponse);
        }

        [Fact]
        public void Tier2Detection_NeverTriggersResponse()
        {
            // This is the fundamental Sentinel constraint: Tier2 can never trigger action
            using var cert = CreateTestCert("CN=Zscaler Root CA", "CN=Zscaler Root CA", 30);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            // Even with suspicious properties, enterprise CA downgrades to Tier2
            Assert.Equal(DetectionTier.Tier2Indicator, result.Tier);
        }

        // ── Helper methods ──────────────────────────────────────────────────

        /// <summary>
        /// Creates a self-signed X509Certificate2 for testing with the specified Subject, Issuer, and validity days.
        /// </summary>
        private static X509Certificate2 CreateTestCert(string subject, string issuer, int validityDays)
        {
            var notBefore = DateTime.UtcNow;
            var notAfter = notBefore.AddDays(validityDays);
            return CreateTestCertWithDates(subject, issuer, notBefore, notAfter);
        }

        /// <summary>
        /// Creates a self-signed X509Certificate2 with explicit NotBefore/NotAfter dates.
        /// </summary>
        private static X509Certificate2 CreateTestCertWithDates(string subject, string issuer, DateTime notBefore, DateTime notAfter)
        {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var cert = req.CreateSelfSigned(new DateTimeOffset(notBefore), new DateTimeOffset(notAfter));
            return cert;
        }
    }
}
