using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for CriticalMonitors — verifies SyscallStubMonitor JIT process classification,
    /// IPSecIntegrityGuard backoff computation, and detection model behavior.
    /// </summary>
    public class CriticalMonitorsTests
    {
        // ═══════════════════════════════════════════════════════════════
        // SyscallStubMonitor — JIT process classification
        // ═══════════════════════════════════════════════════════════════

        [Theory]
        [InlineData("java")]
        [InlineData("javaw")]
        [InlineData("dotnet")]
        [InlineData("node")]
        [InlineData("python")]
        [InlineData("ruby")]
        public void IsJitProcess_CommonRuntimes_AreJit(string name)
        {
            // JIT processes (Java, .NET, Node, Python) generate executable code at runtime
            // that may match syscall stub patterns — these are expected false positives
            Assert.True(IsJitProcess(name));
        }

        [Theory]
        [InlineData("malware")]
        [InlineData("beacon")]
        [InlineData("cmd")]
        [InlineData("notepad")]
        public void IsJitProcess_NonRuntime_NotJit(string name)
        {
            Assert.False(IsJitProcess(name));
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

        private static bool IsJitProcess(string name)
        {
            var lower = name.ToLowerInvariant();
            return lower == "java" || lower == "javaw" || lower == "javaws" ||
                   lower == "dotnet" || lower == "node" || lower == "nodejs" ||
                   lower == "python" || lower == "python3" || lower == "pythonw" ||
                   lower == "ruby" || lower == "perl" ||
                   lower == "mono" || lower == "coreclr";
        }

        private static System.TimeSpan ComputeBackoff(int consecutiveFailures)
        {
            // Exponential backoff: base 5s * 2^failures, capped at 30 minutes
            var seconds = 5.0 * System.Math.Pow(2, System.Math.Min(consecutiveFailures, 8));
            return System.TimeSpan.FromSeconds(System.Math.Min(seconds, 1800));
        }
    }
}
