using System;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v1.8.0 — TokenTheft OS false-positive suppressions + evidence pack gates.
    /// </summary>
    public class V180FeatureTests
    {
        [Theory]
        [InlineData("Memory Compression")]
        [InlineData("memory compression")]
        [InlineData("Registry")]
        [InlineData("Secure System")]
        [InlineData("System")]
        [InlineData("csrss")]
        [InlineData("lsass")]
        [InlineData("Memory Compression.exe")]
        public void TokenTheft_OsProcessNames_AreAllowlisted(string name)
        {
            Assert.True(TokenTheftMonitor.IsLikelyProtectedOsProcess(name) ||
                        TokenTheftMonitor.IsLegitimateSystemTokenHolder(name));
        }

        [Theory]
        [InlineData("evil.exe")]
        [InlineData("GodPotato")]
        [InlineData("mimikatz")]
        [InlineData("TotallyNormal")]
        public void TokenTheft_UserMalwareNames_NotAllowlisted(string name)
        {
            Assert.False(TokenTheftMonitor.IsLikelyProtectedOsProcess(name));
            Assert.False(TokenTheftMonitor.IsLegitimateSystemTokenHolder(name));
        }

        [Fact]
        public void TokenTheft_EmptyPath_IsNotSuspicious()
        {
            Assert.False(TokenTheftMonitor.IsSuspiciousPath(""));
            Assert.False(TokenTheftMonitor.IsSuspiciousPath("   "));
            Assert.False(TokenTheftMonitor.IsSuspiciousPath(null!));
        }

        [Theory]
        [InlineData(@"C:\Users\bob\AppData\Local\Temp\potato.exe")]
        [InlineData(@"C:\Users\bob\Downloads\tool.exe")]
        [InlineData(@"C:\Users\Public\evil.exe")]
        public void TokenTheft_UserWritablePaths_AreSuspicious(string path)
        {
            Assert.True(TokenTheftMonitor.IsSuspiciousPath(path));
        }

        [Theory]
        [InlineData(@"C:\Windows\System32\svchost.exe")]
        [InlineData(@"C:\Program Files\App\app.exe")]
        public void TokenTheft_SystemPaths_NotSuspicious(string path)
        {
            Assert.False(TokenTheftMonitor.IsSuspiciousPath(path));
        }

        [Fact]
        public void AutoIncident_ShouldNotPack_MemoryCompression_TokenTheft()
        {
            var det = new DetectionEvent
            {
                RuleName = "Token Theft: Non-Service Process with SYSTEM Token",
                ProcessName = "Memory Compression",
                ProcessId = 2520,
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                SignalType = SignalType.CredentialTheft,
                Evidence = "Process 'Memory Compression' (PID 2520) at '' holds a NT AUTHORITY\\SYSTEM token"
            };

            Assert.True(AutoIncidentReporter.IsTokenTheftOsFalsePositive(det));
        }

        [Fact]
        public void AutoIncident_ShouldNotPack_Registry_SeImpersonate()
        {
            var det = new DetectionEvent
            {
                RuleName = "Token Theft: SeImpersonatePrivilege from Suspicious Path",
                ProcessName = "Registry",
                ProcessId = 340,
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                SignalType = SignalType.CredentialTheft,
                Evidence = "Process 'Registry' (PID 340) at '' has SeImpersonatePrivilege"
            };

            Assert.True(AutoIncidentReporter.IsTokenTheftOsFalsePositive(det));
        }

        [Fact]
        public void AutoIncident_ShouldStillPack_RealPotatoPath()
        {
            var det = new DetectionEvent
            {
                RuleName = "Token Theft: SeImpersonatePrivilege from Suspicious Path",
                ProcessName = "GodPotato",
                ProcessId = 9999,
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                SignalType = SignalType.CredentialTheft,
                Evidence = @"Process 'GodPotato' (PID 9999) at 'C:\Users\bob\AppData\Local\Temp\gp.exe' has SeImpersonatePrivilege"
            };

            Assert.False(AutoIncidentReporter.IsTokenTheftOsFalsePositive(det));
        }

        [Fact]
        public void AutoIncident_NonTokenTheftRules_NotBlockedByOsFpGate()
        {
            var det = new DetectionEvent
            {
                RuleName = "Ransomware: Mass Encryption",
                ProcessName = "Memory Compression", // weird but shouldn't use token-theft FP gate
                ProcessId = 1,
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                SignalType = SignalType.Ransomware
            };

            Assert.False(AutoIncidentReporter.IsTokenTheftOsFalsePositive(det));
        }
    }
}
