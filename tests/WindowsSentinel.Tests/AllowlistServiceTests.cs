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
        public void ShouldSuppress_ReturnsFalse_ForGamingProcess_WithoutAllowlist()
        {
            var svc = CreateService();
            // Gaming processes get NO special treatment — only user allowlist matters
            Assert.False(svc.ShouldSuppress("steam", @"D:\Steam\steam.exe", "UnsignedBinaryRule"));
            Assert.False(svc.ShouldSuppress("EasyAntiCheat", @"D:\Games\EasyAntiCheat.exe", "SomeRule"));
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
        public void GetConfidenceReduction_OnlyReducesForUserAllowlisted()
        {
            var svc = CreateService();
            // Not allowlisted — no reduction
            double reduction = svc.GetConfidenceReduction("dotnet", null, null, "UnsignedBinaryRule");
            Assert.Equal(0.0, reduction);

            // User-allowlisted — gets reduction
            svc.AddToUserAllowlist("dotnet", null, "Dev tool");
            reduction = svc.GetConfidenceReduction("dotnet", null, null, "UnsignedBinaryRule");
            Assert.Equal(0.3, reduction);
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

        [Fact]
        public void ShouldSuppress_NoBuiltInExemptions_ForBeaconing()
        {
            var svc = CreateService();
            // No built-in gaming/path exemptions exist anymore
            Assert.False(svc.ShouldSuppress("steam", @"D:\Steam\steam.exe", "C2 Beaconing Behavior (Statistical)"));
            // Even user allowlist cannot suppress President's Law rules (beaconing is one)
            svc.AddToUserAllowlist("steam", @"D:\Steam\steam.exe", "Game launcher");
            Assert.False(svc.ShouldSuppress("steam", @"D:\Steam\steam.exe", "C2 Beaconing Behavior (Statistical)"));
            // But user allowlist CAN suppress non-President's-Law rules
            Assert.True(svc.ShouldSuppress("steam", @"D:\Steam\steam.exe", "UnsignedBinaryRule"));
        }
    }
}
