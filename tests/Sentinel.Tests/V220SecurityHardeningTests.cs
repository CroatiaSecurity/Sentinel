using System;
using System.IO;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v2.2.0 red-team remediations: dashboard auth, game-path reputation skip,
    /// ChainTracer system-path, President's Law scope.
    /// </summary>
    public class V220SecurityHardeningTests
    {
        [Fact]
        public void ProductInfo_Version_Is220()
        {
            Assert.Equal("2.2.0", ProductInfo.Version);
        }

        [Fact]
        public void DashboardAuth_RejectsRefererAsProofOfOrigin()
        {
            Assert.False(LoopbackDashboardAuth.RefererGrantsAccess("http://localhost:19845/"));
            Assert.False(LoopbackDashboardAuth.RefererGrantsAccess("http://localhost:19845.evil.test/"));
            Assert.False(LoopbackDashboardAuth.RefererGrantsAccess(null));
        }

        [Fact]
        public void DashboardAuth_RequiresMatchingBearer()
        {
            const string secret = "test-bearer-token-value-ok";
            Assert.False(LoopbackDashboardAuth.Authenticate(null, null, secret));
            Assert.False(LoopbackDashboardAuth.Authenticate("Bearer wrong", null, secret));
            Assert.True(LoopbackDashboardAuth.Authenticate("Bearer " + secret, null, secret));
            Assert.True(LoopbackDashboardAuth.Authenticate(null, secret, secret));
            Assert.False(LoopbackDashboardAuth.Authenticate("Bearer " + secret, null, "other"));
        }

        [Fact]
        public void DashboardAuth_IgnoresEmptyExpected()
        {
            Assert.False(LoopbackDashboardAuth.Authenticate("Bearer x", null, ""));
        }

        [Fact]
        public void GameReputationSkip_RejectsUserProfileSubstring()
        {
            Assert.False(SecurityValidation.ShouldSkipReputationForGamePath(
                @"C:\Users\Player\AppData\Roaming\steamapps\common\payload.exe"));
            Assert.False(SecurityValidation.ShouldSkipReputationForGamePath(
                @"C:\Users\Player\AppData\Roaming\ubisoft\cheat.exe"));
            Assert.False(SecurityValidation.ShouldSkipReputationForGamePath(
                @"C:\Users\Player\Desktop\vanguard\evil.exe"));
        }

        [Fact]
        public void GameReputationSkip_AllowsProgramFilesAndXbox()
        {
            Assert.True(SecurityValidation.ShouldSkipReputationForGamePath(
                @"C:\Program Files (x86)\Steam\steamapps\common\Game\game.exe"));
            Assert.True(SecurityValidation.ShouldSkipReputationForGamePath(
                @"C:\XboxGames\SomeGame\Content\game.exe"));
            Assert.True(SecurityValidation.ShouldSkipReputationForGamePath(
                @"C:\Program Files\WindowsApps\Microsoft.GamingApp_1.0\XboxPcApp.exe"));
            Assert.True(SecurityValidation.ShouldSkipReputationForGamePath(
                @"D:\SteamLibrary\steamapps\common\Game\game.exe"));
        }

        [Fact]
        public void ChainTracer_DoesNotTreatWindowsTempAsSystem()
        {
            var winTemp = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp", "dropper.exe");
            Assert.False(ChainTracer.IsSystemBinary(winTemp, "dropper"));

            var sys32 = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "svchost.exe");
            Assert.True(ChainTracer.IsSystemBinary(sys32, "svchost"));
        }

        [Fact]
        public void PresidentsLaw_DoesNotIncludeDnsOrNetworkAnomaly()
        {
            Assert.False(ScoringEngine.IsPresidentsLawRule("DNS Tunnel: Unusual Query Volume"));
            Assert.False(ScoringEngine.IsPresidentsLawRule("ARP Spoof Detected"));
            Assert.True(ScoringEngine.IsPresidentsLawRule("LSASS Memory Access"));
        }

        [Fact]
        public void EncryptedConfigStore_RoundTripWithHmacEnvelope()
        {
            var dir = Path.Combine(Path.GetTempPath(), "sentinel-v220-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var path = Path.Combine(dir, "config.enc");
                var store = new EncryptedConfigStore(customPath: path);
                store.SetOverride("RestrictivePortHardening", "true");
                Assert.True(store.Save());

                var bytes = File.ReadAllBytes(path);
                Assert.True(bytes.Length > 5);
                Assert.Equal((byte)'S', bytes[0]);
                Assert.Equal((byte)'C', bytes[1]);
                Assert.Equal((byte)'F', bytes[2]);
                Assert.Equal((byte)'G', bytes[3]);
                Assert.Equal((byte)'2', bytes[4]);

                var reloaded = new EncryptedConfigStore(customPath: path);
                Assert.Equal("true", reloaded.GetOverride("RestrictivePortHardening"));
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch { }
            }
        }
    }
}
