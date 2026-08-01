using System.Collections.Generic;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class ResponsePolicyTests
    {
        public ResponsePolicyTests()
        {
            ResponsePolicy.ResetForTests();
        }

        private static SentinelConfig ObserveConfig() => new()
        {
            ActiveResponse = true,
            ObserveUntilChain = true,
            ChainConfirmMinSignals = 2,
            ChainConfirmWindowSeconds = 300,
            SilentObserve = true,
        };

        [Fact]
        public void DirectX_System32_Write_Is_Benign_Noise_Never_Chain()
        {
            var d = new DetectionEvent
            {
                RuleName = "System Integrity: Unauthorized Write to System Directory",
                Evidence = @"File 'C:\WINDOWS\System32\vulkan-1-999-0-0-0.dll' was changed by process 'unknown' (PID 0)",
                ProcessId = 0,
                ProcessName = "unknown",
                Confidence = 0.92,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Metadata = new Dictionary<string, string>
                {
                    ["FilePath"] = @"C:\WINDOWS\System32\vulkan-1-999-0-0-0.dll"
                }
            };

            Assert.True(ResponsePolicy.IsBenignInstallerNoise(d));
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.False(ResponsePolicy.MayPerformDestructiveResponse(d, ObserveConfig()));
        }

        [Fact]
        public void Single_C2_Beacon_Does_Not_Nuke_Alone()
        {
            var d = new DetectionEvent
            {
                RuleName = "C2 Beaconing: Statistical Beacon Detected",
                SignalType = SignalType.NetworkC2,
                ProcessId = 4242,
                ProcessName = "evil.exe",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };

            Assert.Equal("C2Beacon", ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.False(ResponsePolicy.MayPerformDestructiveResponse(d, ObserveConfig()));
        }

        [Fact]
        public void C2_Plus_Second_Signal_Chain_Nukes()
        {
            var cfg = ObserveConfig();
            var c2 = new DetectionEvent
            {
                RuleName = "C2 Beaconing: Statistical Beacon Detected",
                SignalType = SignalType.NetworkC2,
                ProcessId = 7777,
                ProcessName = "evil.exe",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.NetworkIsolate,
            };
            var inject = new DetectionEvent
            {
                RuleName = "Threat Intel: Remote Memory Injection",
                SignalType = SignalType.ProcessInjection,
                ProcessId = 7777,
                ProcessName = "evil.exe",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };

            Assert.False(ResponsePolicy.MayPerformDestructiveResponse(c2, cfg));
            Assert.True(ResponsePolicy.MayPerformDestructiveResponse(inject, cfg));
            Assert.True(inject.Metadata.ContainsKey(ResponsePolicy.ChainConfirmedKey));
        }

        [Fact]
        public void Composite_Is_Immediately_Authorized()
        {
            var d = new DetectionEvent
            {
                RuleName = "Injected C2 Beacon",
                Evidence = "[COMPOSITE] injection + C2",
                ProcessId = 100,
                ProcessName = "host.exe",
                Confidence = 0.98,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.QuarantineAndKill,
            };

            Assert.True(ResponsePolicy.IsNukeComposite(d));
            Assert.True(ResponsePolicy.MayPerformDestructiveResponse(d, ObserveConfig()));
        }

        [Fact]
        public void DllUnload_Exempt_Always_May_Act()
        {
            var d = new DetectionEvent
            {
                RuleName = "DLL Sideloading: Proven Load — Unloaded & Quarantined",
                ProcessId = 55,
                ProcessName = "host.exe",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.QuarantineAndKill,
            };

            Assert.True(ResponsePolicy.IsDllUnloadExempt(d));
            Assert.True(ResponsePolicy.MayPerformDestructiveResponse(d, ObserveConfig()));
        }

        [Fact]
        public void Inline_Host_Mutation_Blocked_While_Observing()
        {
            Assert.False(ResponsePolicy.MayPerformInlineHostMutation(ObserveConfig()));
        }
    }
}
