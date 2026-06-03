using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using WindowsSentinel.Core;

namespace WindowsSentinel.Tests
{
    public class AllowlistServiceTests
    {
        private AllowlistService CreateService()
        {
            // Unique temp dir per test to avoid cross-test data leakage
            var dir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sentinel_test_" + System.Guid.NewGuid().ToString("N")[..8]);
            var cache = new SecureCacheStore(dir);
            return new AllowlistService(cache, NullLogger<AllowlistService>.Instance);
        }

        // ── ShouldSuppress ──────────────────────────────────────────────────

        [Fact]
        public void ShouldSuppress_ReturnsFalse_ForPresidentsLawRule_Lsass()
        {
            var svc = CreateService();
            Assert.False(svc.ShouldSuppress("steam", null, "LSASS Memory Dump"));
        }

        [Fact]
        public void ShouldSuppress_ReturnsFalse_ForPresidentsLawRule_Ransomware()
        {
            var svc = CreateService();
            Assert.False(svc.ShouldSuppress("steam", null, "Ransomware Shadow Copy Deletion"));
        }

        [Fact]
        public void ShouldSuppress_ReturnsTrue_ForGamingProcess()
        {
            var svc = CreateService();
            Assert.True(svc.ShouldSuppress("steam", null, "UnsignedBinaryRule"));
        }

        [Fact]
        public void ShouldSuppress_ReturnsTrue_ForGamingProcess_AntiCheat()
        {
            var svc = CreateService();
            Assert.True(svc.ShouldSuppress("EasyAntiCheat", null, "SomeRule"));
        }

        [Fact]
        public void ShouldSuppress_ReturnsFalse_ForUnknownProcess()
        {
            var svc = CreateService();
            Assert.False(svc.ShouldSuppress("unknown_malware.exe", null, "SomeRule"));
        }

        // ── GetConfidenceReduction ──────────────────────────────────────────

        [Fact]
        public void GetConfidenceReduction_ReturnsZero_ForPresidentsLawRule()
        {
            var svc = CreateService();
            double reduction = svc.GetConfidenceReduction("devenv", null, "Microsoft Corporation", "LSASS Access");
            Assert.Equal(0.0, reduction);
        }

        [Fact]
        public void GetConfidenceReduction_ReducesForTrustedPublisher()
        {
            var svc = CreateService();
            double reduction = svc.GetConfidenceReduction("chrome", null, "Google LLC", "UnsignedBinaryRule");
            Assert.True(reduction >= 0.3);
        }

        [Fact]
        public void GetConfidenceReduction_ReducesForDevelopmentProcess()
        {
            var svc = CreateService();
            double reduction = svc.GetConfidenceReduction("dotnet", null, null, "UnsignedBinaryRule");
            Assert.True(reduction >= 0.2);
        }

        [Fact]
        public void GetConfidenceReduction_ReducesForTrustedPath()
        {
            var svc = CreateService();
            double reduction = svc.GetConfidenceReduction("app.exe",
                @"C:\Program Files\MyApp\app.exe", null, "SomeRule");
            Assert.True(reduction >= 0.1);
        }

        [Fact]
        public void GetConfidenceReduction_CapsAt50Percent()
        {
            var svc = CreateService();
            // Trusted publisher + dev process + trusted path = 0.3 + 0.2 + 0.1 = 0.6, capped at 0.5
            double reduction = svc.GetConfidenceReduction("dotnet",
                @"C:\Program Files\dotnet\dotnet.exe", "Microsoft Corporation", "SomeRule");
            Assert.True(reduction <= 0.5);
        }

        [Fact]
        public void GetConfidenceReduction_ReturnsZero_ForUnknown()
        {
            var svc = CreateService();
            double reduction = svc.GetConfidenceReduction("malware.exe", @"C:\temp\malware.exe", null, "SomeRule");
            Assert.Equal(0.0, reduction);
        }

        // ── Helper methods ──────────────────────────────────────────────────

        [Fact]
        public void IsDevelopmentProcess_Recognizes_DevTools()
        {
            var svc = CreateService();
            Assert.True(svc.IsDevelopmentProcess("code"));
            Assert.True(svc.IsDevelopmentProcess("dotnet"));
            Assert.True(svc.IsDevelopmentProcess("cargo"));
            Assert.False(svc.IsDevelopmentProcess("malware"));
        }

        [Fact]
        public void IsGamingProcess_Recognizes_Games()
        {
            var svc = CreateService();
            Assert.True(svc.IsGamingProcess("steam"));
            Assert.True(svc.IsGamingProcess("EpicGamesLauncher"));
            Assert.False(svc.IsGamingProcess("malware"));
        }

        [Fact]
        public void IsTrustedPublisher_Recognizes_Publishers()
        {
            var svc = CreateService();
            Assert.True(svc.IsTrustedPublisher("Microsoft Corporation"));
            Assert.True(svc.IsTrustedPublisher("Google LLC"));
            Assert.False(svc.IsTrustedPublisher("Evil Corp"));
            Assert.False(svc.IsTrustedPublisher(null));
            Assert.False(svc.IsTrustedPublisher(""));
        }

        // ── User allowlist ──────────────────────────────────────────────────

        [Fact]
        public void UserAllowlist_AddAndRemove()
        {
            var svc = CreateService();
            svc.AddToUserAllowlist("myapp.exe", @"C:\MyApp\myapp.exe", "User trusted");
            Assert.True(svc.ShouldSuppress("myapp.exe", null, "UnsignedBinaryRule"));

            svc.RemoveFromUserAllowlist("myapp.exe");
            Assert.False(svc.ShouldSuppress("myapp.exe", null, "UnsignedBinaryRule"));
        }

        [Fact]
        public void UserAllowlist_NeverSuppressesPresidentsLaw()
        {
            var svc = CreateService();
            svc.AddToUserAllowlist("myapp.exe", null, "I trust it");
            Assert.False(svc.ShouldSuppress("myapp.exe", null, "LSASS Access"));
        }

        [Fact]
        public void UserAllowlist_GetReturnsEntries()
        {
            var svc = CreateService();
            svc.AddToUserAllowlist("app1.exe", null, "Test");
            svc.AddToUserAllowlist("app2.exe", null, "Test");
            var list = svc.GetUserAllowlist();
            Assert.Equal(2, list.Count);
        }
    }
}
