using System;
using System.IO;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class V212WorkFirstTests
    {
        [Fact]
        public void DefaultConfig_DoesNotLockdownUsbOrMitm()
        {
            var c = new SentinelConfig();
            Assert.False(c.RestrictivePortHardening);
            Assert.False(c.MitmDefense.Enabled);
            Assert.False(c.AutoDisableFailedUsbEnumeration);
            Assert.False(ProductPosture.AllowsProactiveHostLockdown(c));
            Assert.False(ProductPosture.AllowsMitmDefenseMutations(c));
        }

        [Fact]
        public void MitmDefense_DoesNotUnlockArbitraryInlineMutations()
        {
            var cfg = new SentinelConfig
            {
                ObserveUntilChain = true,
                MitmDefense = new MitmDefenseConfig { Enabled = true }
            };
            Assert.True(ProductPosture.AllowsMitmDefenseMutations(cfg));
            Assert.False(ResponsePolicy.MayPerformInlineHostMutation(cfg));
        }

        [Fact]
        public void EncryptedStore_AppliesRestrictivePortHardeningOverride()
        {
            var dir = Path.Combine(Path.GetTempPath(), "sentinel-v212-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var store = new EncryptedConfigStore(customPath: Path.Combine(dir, "config.enc"));
                store.SetOverride("RestrictivePortHardening", "true");
                var cfg = new SentinelConfig();
                store.ApplyOverrides(cfg);
                Assert.True(cfg.RestrictivePortHardening);
            }
            finally
            {
                try { Directory.Delete(dir, recursive: true); } catch { }
            }
        }

        [Fact]
        public void UnmappedThread_LargeJitRegion_IsNotShellcode()
        {
            Assert.False(EtwThreatIntelMonitor.IsCompactPrivateExecutable(
                NativeProcessMemory.MEM_COMMIT, 0, NativeProcessMemory.PAGE_EXECUTE_READWRITE, 256 * 1024));
        }

        [Fact]
        public void UnmappedThread_CompactPrivateRx_IsShellcode()
        {
            Assert.True(EtwThreatIntelMonitor.IsCompactPrivateExecutable(
                NativeProcessMemory.MEM_COMMIT, 0, NativeProcessMemory.PAGE_EXECUTE_READ, 4096));
        }

        [Fact]
        public void VolumeMount_RejectsNonLetterDrive()
        {
            Assert.False(VolumeMountMonitor.IsSingleDriveLetter("C:\\Windows"));
            Assert.False(VolumeMountMonitor.IsSingleDriveLetter("'; calc; #"));
            Assert.True(VolumeMountMonitor.IsSingleDriveLetter("D"));
            Assert.True(VolumeMountMonitor.IsSingleDriveLetter("e:"));
        }

        [Fact]
        public void GameWorkSurface_IncludesObsXboxAndStore()
        {
            Assert.True(SecurityValidation.IsGameOrAntiCheatPath(@"C:\Program Files\obs-studio\bin\64bit\obs64.exe"));
            Assert.True(SecurityValidation.IsGameOrAntiCheatPath(@"C:\XboxGames\SomeGame\Content\game.exe"));
            Assert.True(SecurityValidation.IsGameOrAntiCheatPath(@"C:\Program Files\WindowsApps\Microsoft.GamingApp_1.0\XboxPcApp.exe"));
            Assert.False(SecurityValidation.IsGameOrAntiCheatPath(@"C:\Temp\obs-studio\malware.exe"));
        }

        [Fact]
        public void InstallerHeuristics_RecognizeSteamXboxObsSetups()
        {
            Assert.True(InstallerHeuristics.LooksLikeInstallerName("SteamSetup"));
            Assert.True(InstallerHeuristics.LooksLikeInstallerName("XboxInstaller"));
            Assert.True(InstallerHeuristics.LooksLikeInstallerName("OBS-Studio-31.0-Windows"));
        }

        [Fact]
        public void ThreatIntelInjection_IgnoresSyntheticEventIdLabel()
        {
            var rule = new ThreatIntelInjectionRule();
            var ctx = new FusedTelemetryContext
            {
                TriggeringEvent = new ThreatIntelTelemetry
                {
                    ProcessName = "malware",
                    ProcessId = 4242,
                    TargetProcessId = 4,
                    ApiName = "ThreatIntel_EventId_12"
                }
            };
            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public void ProductInfo_MatchesTwoOneTwo()
        {
            Assert.Equal("2.2.1", ProductInfo.Version);
        }

        [Theory]
        [InlineData("Reverse Shell: Suspicious Outbound Connection")]
        [InlineData("Network Indicator: Classic Malware Port")]
        [InlineData("DNS Bypass: Application-Level DoH Detected")]
        [InlineData("C2 Pairing: Defensive Process Spawn After Drop")]
        [InlineData("Process Hollowing: Image File Missing")]
        [InlineData("Clickjacking: Suspicious Overlay")]
        [InlineData("LPE Scaffold: Privilege Escalation Tool")]
        [InlineData("Evasion: Unmapped Thread Start Address")]
        public void BrowsePlayHeuristics_AreWeakObserveSeeds(string rule)
        {
            var d = new DetectionEvent { RuleName = rule, Confidence = 0.90, ProcessId = 9 };
            Assert.True(ResponsePolicy.IsWeakObserveSeed(d));
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
        }

        [Fact]
        public void LpeScaffold_IsNotTokenTheftTerminal()
        {
            var d = new DetectionEvent
            {
                RuleName = "LPE Scaffold: Privilege Escalation Tool",
                Confidence = 0.88,
                ProcessId = 11,
                SignalType = SignalType.SecurityEvasion
            };
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
        }
    }
}
