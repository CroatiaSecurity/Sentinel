using System.Reflection;
using WindowsSentinel.Core.Monitors;
using Xunit;

namespace WindowsSentinel.Tests.Monitors;

/// <summary>
/// Tests for UsbDeviceFingerprinter device ID parsing and classification.
/// </summary>
public sealed class UsbDeviceFingerprinterTests
{
    // ── Device ID Parsing Tests ─────────────────────────────────────────────

    [Fact]
    public void ParseDeviceId_ExtractsVidPidSerial()
    {
        var method = typeof(UsbDeviceFingerprinter).GetMethod("ParseDeviceId",
            BindingFlags.NonPublic | BindingFlags.Static);
        var result = ((int vid, int pid, string? serial))method!.Invoke(null,
            new object[] { @"USB\VID_046D&PID_C52B\5&12345678&0&2" })!;

        Assert.Equal(0x046D, result.vid); // Logitech
        Assert.Equal(0xC52B, result.pid);
        Assert.Equal("5&12345678&0&2", result.serial);
    }

    [Fact]
    public void ParseDeviceId_HandlesCompositeDevice()
    {
        var method = typeof(UsbDeviceFingerprinter).GetMethod("ParseDeviceId",
            BindingFlags.NonPublic | BindingFlags.Static);
        var result = ((int vid, int pid, string? serial))method!.Invoke(null,
            new object[] { @"USB\VID_1532&PID_0084&MI_00\7&abcdef&0&0000" })!;

        Assert.Equal(0x1532, result.vid); // Razer
        Assert.Equal(0x0084, result.pid);
    }

    [Fact]
    public void ParseDeviceId_HandlesNoSerial()
    {
        var method = typeof(UsbDeviceFingerprinter).GetMethod("ParseDeviceId",
            BindingFlags.NonPublic | BindingFlags.Static);
        var result = ((int vid, int pid, string? serial))method!.Invoke(null,
            new object[] { @"USB\VID_045E&PID_0745" })!;

        Assert.Equal(0x045E, result.vid); // Microsoft
        Assert.Equal(0x0745, result.pid);
        Assert.Null(result.serial);
    }

    [Fact]
    public void ParseDeviceId_HandlesEmptyString()
    {
        var method = typeof(UsbDeviceFingerprinter).GetMethod("ParseDeviceId",
            BindingFlags.NonPublic | BindingFlags.Static);
        var result = ((int vid, int pid, string? serial))method!.Invoke(null,
            new object[] { "" })!;

        Assert.Equal(0, result.vid);
        Assert.Equal(0, result.pid);
    }

    // ── HID Device Detection Tests ──────────────────────────────────────────

    [Theory]
    [InlineData("Keyboard", null, true)]
    [InlineData("HIDClass", null, true)]
    [InlineData("HID", null, true)]
    [InlineData(null, "USB Keyboard Device", true)]
    [InlineData(null, "HID-compliant device", true)]
    [InlineData("DiskDrive", null, false)]
    [InlineData("USB", "USB Mass Storage", false)]
    [InlineData(null, null, false)]
    public void IsHidDevice_ClassifiesCorrectly(string? deviceClass, string? description, bool expected)
    {
        var method = typeof(UsbDeviceFingerprinter).GetMethod("IsHidDevice",
            BindingFlags.NonPublic | BindingFlags.Static);

        var device = new UsbDeviceRecord
        {
            DeviceId = "USB\\VID_1234&PID_5678\\serial",
            Vid = 0x1234,
            Pid = 0x5678,
            DeviceClass = deviceClass,
            Description = description,
            FirstSeen = DateTimeOffset.UtcNow,
            LastSeen = DateTimeOffset.UtcNow
        };

        var result = (bool)method!.Invoke(null, new object[] { device })!;
        Assert.Equal(expected, result);
    }

    // ── Known-Good VID Tests ────────────────────────────────────────────────

    [Theory]
    [InlineData(0x046D, true)]  // Logitech
    [InlineData(0x045E, true)]  // Microsoft
    [InlineData(0x1B1C, true)]  // Corsair
    [InlineData(0x1532, true)]  // Razer
    [InlineData(0x05AC, true)]  // Apple
    [InlineData(0x3434, true)]  // Keychron
    [InlineData(0x1234, false)] // Unknown
    [InlineData(0x0000, false)] // Zero
    [InlineData(0xFFFF, false)] // Max
    public void IsKnownGoodKeyboardVid_ClassifiesCorrectly(int vid, bool expected)
    {
        var method = typeof(UsbDeviceFingerprinter).GetMethod("IsKnownGoodKeyboardVid",
            BindingFlags.NonPublic | BindingFlags.Static);
        var result = (bool)method!.Invoke(null, new object[] { vid })!;
        Assert.Equal(expected, result);
    }

    // ── Mass Storage Detection Tests ────────────────────────────────────────

    [Theory]
    [InlineData("DiskDrive", null, true)]
    [InlineData("USB", "USB Mass Storage Device", true)]
    [InlineData(null, "Flash Drive", true)]
    [InlineData(null, "USB Storage Device", true)]
    [InlineData("Keyboard", null, false)]
    [InlineData("HIDClass", null, false)]
    [InlineData(null, "Logitech Mouse", false)]
    public void IsMassStorageDevice_ClassifiesCorrectly(string? deviceClass, string? description, bool expected)
    {
        var method = typeof(UsbDeviceFingerprinter).GetMethod("IsMassStorageDevice",
            BindingFlags.NonPublic | BindingFlags.Static);

        var device = new UsbDeviceRecord
        {
            DeviceId = "USB\\VID_1234&PID_5678\\serial",
            Vid = 0x1234,
            Pid = 0x5678,
            DeviceClass = deviceClass,
            Description = description,
            FirstSeen = DateTimeOffset.UtcNow,
            LastSeen = DateTimeOffset.UtcNow
        };

        var result = (bool)method!.Invoke(null, new object[] { device })!;
        Assert.Equal(expected, result);
    }
}
