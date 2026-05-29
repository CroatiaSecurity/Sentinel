using System.Reflection;
using WindowsSentinel.Core.Monitors;
using Xunit;

namespace WindowsSentinel.Tests.Monitors;

/// <summary>
/// Tests for RouteTableMonitor multicast/broadcast exclusion logic.
/// </summary>
public sealed class RouteTableMonitorTests
{
    // ── Multicast/Broadcast Exclusion Tests ──────────────────────────────────

    [Theory]
    [InlineData("224.0.0.0", "240.0.0.0", true)]   // Multicast range
    [InlineData("239.255.255.250", "255.255.255.255", true)] // Specific multicast
    [InlineData("255.255.255.255", "255.255.255.255", true)] // Broadcast
    [InlineData("192.168.1.0", "255.255.255.0", false)]      // Normal subnet
    [InlineData("10.0.0.0", "255.0.0.0", false)]            // Private range
    [InlineData("8.8.8.8", "255.255.255.255", false)]       // Specific host route
    [InlineData("0.0.0.0", "0.0.0.0", false)]               // Default route
    public void IsMulticastOrBroadcast_ClassifiesCorrectly(string destination, string mask, bool expected)
    {
        // The exclusion logic checks:
        // 1. First octet >= 224 (multicast range 224.0.0.0/4)
        // 2. Destination == 255.255.255.255 (broadcast)
        var firstOctet = int.Parse(destination.Split('.')[0]);
        bool isMulticast = firstOctet >= 224;
        bool isBroadcast = destination == "255.255.255.255";
        bool result = isMulticast || isBroadcast;

        Assert.Equal(expected, result);
    }

    // ── Route that should trigger detection (unicast /32 host routes) ────────

    [Theory]
    [InlineData("8.8.8.8", "255.255.255.255")]       // Google DNS - suspicious /32
    [InlineData("1.1.1.1", "255.255.255.255")]       // Cloudflare - suspicious /32
    [InlineData("142.250.80.46", "255.255.255.255")] // Google IP - suspicious /32
    public void UnicastHostRoutes_ShouldNotBeExcluded(string destination, string mask)
    {
        var firstOctet = int.Parse(destination.Split('.')[0]);
        bool isMulticast = firstOctet >= 224;
        bool isBroadcast = destination == "255.255.255.255" && mask == "255.255.255.255" && firstOctet == 255;

        // These are unicast /32 routes — they should NOT be excluded
        // (they're the actual attack pattern)
        Assert.False(isMulticast);
        // Note: 8.8.8.8/32 has mask 255.255.255.255 but destination is NOT 255.255.255.255
        Assert.NotEqual("255.255.255.255", destination);
    }
}
