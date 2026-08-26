using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Permanent regression guard: default posture must stay observe/work-first.
    /// If you break these tests, you are about to ship another "new block" that
    /// forces the user to yell at the agent again. Don't.
    /// </summary>
    public class ProductPostureTests
    {
        [Fact]
        public void Default_Config_Is_WorkFirst_Observe()
        {
            var c = new SentinelConfig();
            Assert.False(c.RestrictivePortHardening);
            Assert.True(c.ObserveUntilChain);
            Assert.True(c.SilentObserve);
            Assert.False(c.AutoDisableFailedUsbEnumeration);
            Assert.False(c.ThreatIntelProactiveFirewall);
            Assert.False(c.BlockFcmPushChannel);
            Assert.False(ProductPosture.AllowsProactiveHostLockdown(c));
            Assert.True(ProductPosture.ModuleIdentityUnloadAlwaysOn);
        }

        [Fact]
        public void TryProactiveHostLockdown_Denies_By_Default()
        {
            Assert.False(ProductPosture.TryProactiveHostLockdown(new SentinelConfig(), out var reason));
            Assert.Contains("denied", reason, System.StringComparison.OrdinalIgnoreCase);
            Assert.Contains("RestrictivePortHardening", reason);
        }

        [Fact]
        public void TryProactiveHostLockdown_Allows_When_Restrictive()
        {
            var c = new SentinelConfig { RestrictivePortHardening = true };
            Assert.True(ProductPosture.AllowsProactiveHostLockdown(c));
            Assert.True(ProductPosture.TryProactiveHostLockdown(c, out _));
        }

        [Fact]
        public void HardeningModule_Default_ApplyOrFail_Is_Release_Not_Lockdown()
        {
            // Must not throw; work-first path releases leftovers rather than applying IPSec/ASR.
            HardeningModule.RestrictivePortHardeningEnabled = false;
            var ex = Record.Exception(() =>
            {
                HardeningModule.ApplyOrFail();
                HardeningModule.ReleaseUserWorkSurface();
                HardeningModule.ApplyAsrRules(); // should release, not force Block
            });
            Assert.Null(ex);
        }

        [Fact]
        public void RestrictivePortHardening_Is_The_Only_Proactive_Lockdown_Switch()
        {
            // Documented contract: one opt-in flag for kiosk, not a zoo of silent defaults.
            var c = new SentinelConfig();
            Assert.False(c.RestrictivePortHardening);
            c.RestrictivePortHardening = true;
            Assert.True(ProductPosture.AllowsProactiveHostLockdown(c));
        }
    }
}
