using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;
using WindowsSentinel.Core;

namespace WindowsSentinel.Tests
{
    public class BehavioralCorrelationEngineTests
    {
        [Fact]
        public async Task EvaluateComposites_RansomwareChain_Fires()
        {
            // Arrange
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev =>
            {
                composite = ev;
                return Task.CompletedTask;
            });

            // Act
            // Feed first ransomware signal (shadow copy deletion)
            var signal1 = new DetectionEvent
            {
                RuleName = "RansomwareDetectionRule",
                ProcessId = 1234,
                ProcessName = "ransomware.exe",
                SignalType = SignalType.Ransomware,
                Timestamp = DateTime.UtcNow
            };
            await engine.RegisterSignalAsync(signal1);

            // Feed second ransomware signal (file rename)
            var signal2 = new DetectionEvent
            {
                RuleName = "Ransomware: Mass File Rename",
                ProcessId = 1234,
                ProcessName = "ransomware.exe",
                SignalType = SignalType.Ransomware,
                Timestamp = DateTime.UtcNow
            };
            await engine.RegisterSignalAsync(signal2);

            // Assert
            Assert.NotNull(composite);
            Assert.Equal("Active Ransomware Chain", composite!.RuleName);
            Assert.Equal(0.99, composite.Confidence);
            Assert.Equal(1234, composite.ProcessId);
        }

        [Fact]
        public async Task EvaluateComposites_FilelessAttackChain_Fires()
        {
            // Arrange
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev =>
            {
                composite = ev;
                return Task.CompletedTask;
            });

            // Act
            // Feed evasion signal
            var signal1 = new DetectionEvent
            {
                RuleName = "PrivilegeEscalationRule",
                ProcessId = 5555,
                ProcessName = "powershell.exe",
                SignalType = SignalType.SecurityEvasion,
                Timestamp = DateTime.UtcNow
            };
            await engine.RegisterSignalAsync(signal1);

            // Feed shell signal
            var signal2 = new DetectionEvent
            {
                RuleName = "ReverseShellRule",
                ProcessId = 5555,
                ProcessName = "powershell.exe",
                SignalType = SignalType.ReverseShell,
                Timestamp = DateTime.UtcNow
            };
            await engine.RegisterSignalAsync(signal2);

            // Assert
            Assert.NotNull(composite);
            Assert.Equal("Fileless Attack Chain", composite!.RuleName);
            Assert.Equal(0.95, composite.Confidence);
        }

        [Fact]
        public async Task EvaluateComposites_CredentialDumpAndExfil_Fires()
        {
            // Arrange
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev =>
            {
                composite = ev;
                return Task.CompletedTask;
            });

            // Act
            // Feed LSASS access
            var signal1 = new DetectionEvent
            {
                RuleName = "Credential Theft: LSASS Process Access",
                ProcessId = 9999,
                ProcessName = "mimikatz.exe",
                SignalType = SignalType.LsassAccess,
                Timestamp = DateTime.UtcNow
            };
            await engine.RegisterSignalAsync(signal1);

            // Feed network connection
            var signal2 = new DetectionEvent
            {
                RuleName = "C2 Beaconing Behavior (Statistical)",
                ProcessId = 9999,
                ProcessName = "mimikatz.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            };
            await engine.RegisterSignalAsync(signal2);

            // Assert
            Assert.NotNull(composite);
            Assert.Equal("Credential Dump + Exfiltration", composite!.RuleName);
            Assert.Equal(0.96, composite.Confidence);
        }
    }
}
