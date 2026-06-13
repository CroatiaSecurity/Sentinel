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
            // Requires BOTH name AND gaming path — name alone is no longer sufficient
            Assert.True(svc.ShouldSuppress("steam", @"C:\Program Files (x86)\Steam\steam.exe", "UnsignedBinaryRule"));
            // Name alone should NOT suppress (attacker could rename)
            Assert.False(svc.ShouldSuppress("steam", null, "UnsignedBinaryRule"));
        }

        [Fact]
        public void ShouldSuppress_ReturnsTrue_ForGamingProcess_AntiCheat()
        {
            var svc = CreateService();
            // EasyAntiCheat typically runs from a game directory
            Assert.True(svc.ShouldSuppress("EasyAntiCheat", @"D:\Steam\steamapps\common\SomeGame\EasyAntiCheat\EasyAntiCheat.exe", "SomeRule"));
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
            svc.AddToUserAllowlist("dotnet", @"C:\Program Files\dotnet\dotnet.exe", "User trust");
            // dev process + trusted path + user allowlist = 0.2 + 0.1 + 0.4 = 0.7, capped at 0.5
            double reduction = svc.GetConfidenceReduction("dotnet",
                @"C:\Program Files\dotnet\dotnet.exe", null, "SomeRule");
            Assert.Equal(0.5, reduction);
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
        public void IsGamingPath_Recognizes_GamingPaths()
        {
            var svc = CreateService();
            Assert.True(svc.IsGamingPath(@"D:\SteamLibrary\steamapps\common\game.exe"));
            Assert.True(svc.IsGamingPath(@"C:\Riot Games\League of Legends\game.exe"));
            Assert.True(svc.IsGamingPath(@"C:\Program Files (x86)\Epic Games\Launcher.exe"));
            Assert.True(svc.IsGamingPath(@"D:\games\lotroclient.exe"));
            Assert.False(svc.IsGamingPath(@"C:\Windows\System32\cmd.exe"));
        }

        [Fact]
        public void ShouldSuppress_AllowsSuppressingBeaconing_ForGamingProcess()
        {
            var svc = CreateService();
            // Beaconing for gaming: requires gaming path
            Assert.True(svc.ShouldSuppress("steam", @"D:\Steam\steam.exe", "C2 Beaconing Behavior (Statistical)"));
            // Non-gaming path should NOT suppress even with gaming name
            Assert.False(svc.ShouldSuppress("unknowngame", @"C:\Temp\unknowngame.exe", "C2 Beaconing Behavior (Statistical)"));
        }

        [Fact]
        public void ShouldSuppress_AllowsSuppressingBeaconing_ForGamingPath()
        {
            var svc = CreateService();
            Assert.True(svc.ShouldSuppress("lotroclient", @"D:\StandingStoneGames\LOTRO\lotroclient.exe", "C2 Beaconing Behavior (Statistical)"));
        }
    }
}
