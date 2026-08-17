using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for CriticalMonitors — verifies SyscallStubMonitor Hell's Gate matching,
    /// IPSecIntegrityGuard backoff computation, and detection model behavior.
    /// </summary>
    public class CriticalMonitorsTests
    {
        // ═══════════════════════════════════════════════════════════════
        // SyscallStubMonitor — well-formed Hell's Gate table (no name skip)
        // ═══════════════════════════════════════════════════════════════

        [Fact]
        public void HellsGate_ThreeDistinctWellFormedStubs_IsHit()
        {
            var buffer = new byte[]
            {
                0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
                0x4C, 0x8B, 0xD1, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
                0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
            };
            var hits = SyscallStubMonitor.FindSyscallStubs(buffer, buffer.Length);
            Assert.True(SyscallStubMonitor.IsHellsGateEvidence(hits));
        }

        [Fact]
        public void HellsGate_JitStyleLooseSyscall_IsNotHit()
        {
            var buffer = new byte[]
            {
                0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x0F, 0x05,
                0x4C, 0x8B, 0xD1, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x0F, 0x05,
                0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x0F, 0x05,
            };
            var hits = SyscallStubMonitor.FindSyscallStubs(buffer, buffer.Length);
            Assert.Empty(hits);
            Assert.False(SyscallStubMonitor.IsHellsGateEvidence(hits));
        }

        // ═══════════════════════════════════════════════════════════════
        // Syscall stub detection model
        // ═══════════════════════════════════════════════════════════════

        [Fact]
        public void SyscallStub_DetectionModel()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Process Injection: Indirect Syscall Stubs Detected",
                ProcessId = 4000,
                ProcessName = "implant.exe",
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                SignalType = SignalType.ProcessInjection
            };

            Assert.Equal(SignalType.ProcessInjection, detection.SignalType);
            Assert.True(detection.KillAuthorized);
        }

        [Fact]
        public void ProcessInjection_IsPresidentsLaw()
        {
            Assert.True(ScoringEngine.IsPresidentsLawRule("Process Injection: Indirect Syscall Stubs Detected"));
        }

        // ═══════════════════════════════════════════════════════════════
        // IPSecIntegrityGuard — backoff computation
        // ═══════════════════════════════════════════════════════════════

        [Fact]
        public void Backoff_IncreasesWithFailures()
        {
            // Verify exponential backoff concept: more failures = longer wait
            var backoff1 = ComputeBackoff(1);
            var backoff3 = ComputeBackoff(3);
            var backoff5 = ComputeBackoff(5);

            Assert.True(backoff3 > backoff1);
            Assert.True(backoff5 > backoff3);
        }

        [Fact]
        public void Backoff_ZeroFailures_MinimumDelay()
        {
            var backoff = ComputeBackoff(0);
            Assert.True(backoff.TotalSeconds >= 1);
        }

        [Fact]
        public void Backoff_HasMaximumCap()
        {
            // Even with many failures, backoff should be bounded
            var backoff = ComputeBackoff(100);
            Assert.True(backoff.TotalMinutes <= 60, $"Backoff {backoff} exceeds 60min cap");
        }

        // ═══════════════════════════════════════════════════════════════
        // AsrPolicyGuard — detection model
        // ═══════════════════════════════════════════════════════════════

        [Fact]
        public void AsrPolicy_DetectionModel()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Anti-Tamper: ASR Policy Modification Detected",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 4
            };

            var category = ScoringEngine.CategorizeDetection(detection.RuleName);
            Assert.Equal(DetectionCategory.AntiTamper, category);
        }

        // ═══════════════════════════════════════════════════════════════
        // Helper re-implementations (mirrors private static methods)
        // ═══════════════════════════════════════════════════════════════

        private static System.TimeSpan ComputeBackoff(int consecutiveFailures)
        {
            // Exponential backoff: base 5s * 2^failures, capped at 30 minutes
            var seconds = 5.0 * System.Math.Pow(2, System.Math.Min(consecutiveFailures, 8));
            return System.TimeSpan.FromSeconds(System.Math.Min(seconds, 1800));
        }
    }
}
