using System;
using Xunit;
using WindowsSentinel.Core;

namespace WindowsSentinel.Tests
{
    public class RulesTests
    {
        private static FusedTelemetryContext MakeContext(ProcessTelemetry pt)
        {
            return new FusedTelemetryContext
            {
                ProcessId = pt.ProcessId,
                ProcessName = pt.ProcessName,
                TriggeringEvent = pt
            };
        }

        [Fact]
        public void PrivilegeEscalationRule_DetectsPotatoAndPrintSpoof()
        {
            var rule = new PrivilegeEscalationRule();
            
            // Test GodPotato/JuicyPotato
            var pt1 = new ProcessTelemetry
            {
                ProcessName = "godpotato.exe",
                ImagePath = @"C:\Temp\godpotato.exe",
                CommandLine = "godpotato.exe -cmd cmd.exe",
                ProcessId = 1234
            };
            var context1 = MakeContext(pt1);
            var result1 = rule.Evaluate(context1);
            Assert.NotNull(result1);
            Assert.Equal("PrivilegeEscalationRule", result1.RuleName);
            Assert.Equal(ResponseAction.KillProcessTree, result1.AuthorizedResponse);

            // Test PrintSpoofer
            var pt2 = new ProcessTelemetry
            {
                ProcessName = "PrintSpoofer.exe",
                ImagePath = @"C:\Temp\PrintSpoofer.exe",
                CommandLine = "PrintSpoofer.exe -c cmd.exe",
                ProcessId = 1235
            };
            var context2 = MakeContext(pt2);
            var result2 = rule.Evaluate(context2);
            Assert.NotNull(result2);
        }

        [Fact]
        public void PrivilegeEscalationRule_DetectsWevtutilLogClearing()
        {
            var rule = new PrivilegeEscalationRule();

            var pt = new ProcessTelemetry
            {
                ProcessName = "wevtutil.exe",
                ImagePath = @"C:\Windows\System32\wevtutil.exe",
                CommandLine = "wevtutil.exe cl System",
                ProcessId = 1236
            };
            var context = MakeContext(pt);
            var result = rule.Evaluate(context);
            Assert.NotNull(result);
            Assert.Contains("wevtutil", result.Evidence);
        }

        [Fact]
        public void AttackToolsRule_DetectsEarthLamiaToolsets()
        {
            var rule = new AttackToolsRule();

            // Test fscan
            var pt1 = new ProcessTelemetry
            {
                ProcessName = "fscan.exe",
                ImagePath = @"C:\Temp\fscan.exe",
                CommandLine = "fscan.exe -h 192.168.1.1/24",
                ProcessId = 1237
            };
            var result1 = rule.Evaluate(MakeContext(pt1));
            Assert.NotNull(result1);
            Assert.Equal("AttackToolsRule", result1.RuleName);

            // Test rakshasa
            var pt2 = new ProcessTelemetry
            {
                ProcessName = "rakshasa.exe",
                ImagePath = @"C:\Temp\rakshasa.exe",
                CommandLine = "rakshasa.exe -p 1080",
                ProcessId = 1238
            };
            var result2 = rule.Evaluate(MakeContext(pt2));
            Assert.NotNull(result2);

            // Test ntdsutil
            var pt3 = new ProcessTelemetry
            {
                ProcessName = "ntdsutil.exe",
                ImagePath = @"C:\Windows\System32\ntdsutil.exe",
                CommandLine = "ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\\temp\"",
                ProcessId = 1239
            };
            var result3 = rule.Evaluate(MakeContext(pt3));
            Assert.NotNull(result3);
        }
    }
}
