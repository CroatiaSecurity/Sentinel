using Xunit;

namespace WindowsSentinel.Tests.Monitors;

/// <summary>
/// Tests for AudioHijackMonitor module hint accuracy.
/// Verifies that generic DLLs are NOT in the hints (FP fix)
/// and that actual virtual cable indicators ARE present.
/// </summary>
public sealed class AudioHijackTests
{
    // Access the static arrays via reflection
    private static string[] GetMicInputModuleHints()
    {
        var field = typeof(WindowsSentinel.Core.Monitors.AudioHijackMonitor)
            .GetField("MicInputModuleHints",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        return (string[])field!.GetValue(null)!;
    }

    private static string[] GetAudioOutputModuleHints()
    {
        var field = typeof(WindowsSentinel.Core.Monitors.AudioHijackMonitor)
            .GetField("AudioOutputModuleHints",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        return (string[])field!.GetValue(null)!;
    }

    // ── FP Fix: Generic DLLs must NOT be in MicInputModuleHints ─────────────

    [Theory]
    [InlineData("winmm.dll")]
    [InlineData("mf.dll")]
    [InlineData("mfreadwrite.dll")]
    [InlineData("directsound")]
    public void MicInputHints_DoesNotContainGenericDlls(string genericDll)
    {
        var hints = GetMicInputModuleHints();
        Assert.DoesNotContain(genericDll, hints);
    }

    // ── Virtual cable indicators MUST be present ────────────────────────────

    [Theory]
    [InlineData("vbcable")]
    [InlineData("voicemeeter")]
    [InlineData("virtualcable")]
    [InlineData("loopback")]
    [InlineData("wasapiloopback")]
    public void MicInputHints_ContainsVirtualCableIndicators(string indicator)
    {
        var hints = GetMicInputModuleHints();
        Assert.Contains(indicator, hints);
    }

    // ── Audio output hints should still have the core Windows audio DLLs ────

    [Theory]
    [InlineData("audioses.dll")]
    [InlineData("audioeng.dll")]
    [InlineData("mmdevapi.dll")]
    public void AudioOutputHints_ContainsCoreAudioDlls(string dll)
    {
        var hints = GetAudioOutputModuleHints();
        Assert.Contains(dll, hints);
    }
}
