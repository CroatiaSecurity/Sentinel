using System.Net;
using System.Reflection;
using WindowsSentinel.Core.Monitors;
using Xunit;

namespace WindowsSentinel.Tests.Monitors;

/// <summary>
/// Tests for AppNetworkPolicyMonitor subnet calculation and address classification.
/// </summary>
public sealed class AppNetworkPolicyTests
{
    // ── Subnet Calculation Tests ────────────────────────────────────────────

    [Theory]
    [InlineData("192.168.1.100", "192.168.1.0/24")]
    [InlineData("10.0.0.1", "10.0.0.0/24")]
    [InlineData("172.16.255.254", "172.16.255.0/24")]
    [InlineData("8.8.8.8", "8.8.8.0/24")]
    [InlineData("1.2.3.4", "1.2.3.0/24")]
    [InlineData("255.255.255.255", "255.255.255.0/24")]
    public void GetSubnet24_CalculatesCorrectly(string ip, string expectedSubnet)
    {
        var method = typeof(AppNetworkPolicyMonitor).GetMethod("GetSubnet24",
            BindingFlags.NonPublic | BindingFlags.Static);
        var result = (string?)method!.Invoke(null, new object[] { ip });
        Assert.Equal(expectedSubnet, result);
    }

    [Theory]
    [InlineData("invalid")]
    [InlineData("")]
    [InlineData("not.an.ip")]
    public void GetSubnet24_ReturnsNullForInvalidIp(string ip)
    {
        var method = typeof(AppNetworkPolicyMonitor).GetMethod("GetSubnet24",
            BindingFlags.NonPublic | BindingFlags.Static);
        var result = (string?)method!.Invoke(null, new object[] { ip });
        Assert.Null(result);
    }

    // ── Local Address Detection Tests ───────────────────────────────────────

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.0.0.2", true)]
    [InlineData("127.255.255.255", true)]
    [InlineData("169.254.1.1", true)]
    [InlineData("169.254.255.255", true)]
    [InlineData("0.0.0.0", true)]
    [InlineData("192.168.1.1", false)]
    [InlineData("10.0.0.1", false)]
    [InlineData("8.8.8.8", false)]
    [InlineData("1.1.1.1", false)]
    public void IsLocalAddress_ClassifiesCorrectly(string ip, bool expectedLocal)
    {
        var method = typeof(AppNetworkPolicyMonitor).GetMethod("IsLocalAddress",
            BindingFlags.NonPublic | BindingFlags.Static);
        var result = (bool)method!.Invoke(null, new object[] { ip })!;
        Assert.Equal(expectedLocal, result);
    }
}
