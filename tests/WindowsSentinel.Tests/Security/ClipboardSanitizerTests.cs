using WindowsSentinel.Core.Security;
using Xunit;

namespace WindowsSentinel.Tests.Security;

/// <summary>
/// Tests for ClipboardSanitizer text sanitization logic.
/// </summary>
public sealed class ClipboardSanitizerTests
{
    private static (string sanitized, List<string> findings) Sanitize(string input)
    {
        // Create instance without DI (SanitizeText doesn't use injected services)
        var instance = (ClipboardSanitizer)System.Runtime.CompilerServices.RuntimeHelpers
            .GetUninitializedObject(typeof(ClipboardSanitizer));
        return instance.SanitizeText(input);
    }

    // ── Zero-Width Character Tests ──────────────────────────────────────────

    [Fact]
    public void RemovesZeroWidthSpace()
    {
        var (sanitized, findings) = Sanitize("hello\u200Bworld");
        Assert.Equal("helloworld", sanitized);
        Assert.Contains("zero-width characters", findings);
    }

    [Fact]
    public void RemovesZeroWidthJoiner()
    {
        var (sanitized, findings) = Sanitize("test\u200Dvalue");
        Assert.Equal("testvalue", sanitized);
        Assert.Contains("zero-width characters", findings);
    }

    [Fact]
    public void RemovesBOM()
    {
        var (sanitized, findings) = Sanitize("\uFEFFhello");
        Assert.Equal("hello", sanitized);
        Assert.Contains("zero-width characters", findings);
    }

    [Fact]
    public void RemovesWordJoiner()
    {
        var (sanitized, findings) = Sanitize("word\u2060break");
        Assert.Equal("wordbreak", sanitized);
        Assert.Contains("zero-width characters", findings);
    }

    // ── RTL Override Tests ───────────────────────────────────────────────────

    [Fact]
    public void RemovesRtlOverride()
    {
        var (sanitized, findings) = Sanitize("document\u202Efdp.exe");
        Assert.Equal("documentfdp.exe", sanitized);
        Assert.Contains("RTL override characters", findings);
    }

    [Fact]
    public void RemovesAllBidiControls()
    {
        var input = "\u202A\u202B\u202C\u202D\u202Etext";
        var (sanitized, findings) = Sanitize(input);
        Assert.Equal("text", sanitized);
        Assert.Contains("RTL override characters", findings);
    }

    // ── Homoglyph Tests ─────────────────────────────────────────────────────

    [Fact]
    public void ReplacesCyrillicA()
    {
        var (sanitized, findings) = Sanitize("p\u0430ypal.com");
        Assert.Equal("paypal.com", sanitized);
        Assert.Contains("Cyrillic homoglyphs", findings);
    }

    [Fact]
    public void ReplacesCyrillicE()
    {
        var (sanitized, findings) = Sanitize("s\u0435curity");
        Assert.Equal("security", sanitized);
        Assert.Contains("Cyrillic homoglyphs", findings);
    }

    [Fact]
    public void ReplacesCyrillicO()
    {
        var (sanitized, findings) = Sanitize("g\u043E\u043Egle.com");
        Assert.Equal("google.com", sanitized);
        Assert.Contains("Cyrillic homoglyphs", findings);
    }

    [Fact]
    public void ReplacesCyrillicP()
    {
        var (sanitized, findings) = Sanitize("\u0440assword");
        Assert.Equal("password", sanitized);
        Assert.Contains("Cyrillic homoglyphs", findings);
    }

    [Fact]
    public void ReplacesCyrillicC()
    {
        var (sanitized, findings) = Sanitize("se\u0441ure");
        Assert.Equal("secure", sanitized);
        Assert.Contains("Cyrillic homoglyphs", findings);
    }

    // ── Clean Input Tests ───────────────────────────────────────────────────

    [Fact]
    public void LeavesCleanTextUnchanged()
    {
        var (sanitized, findings) = Sanitize("Hello, World! This is normal text.");
        Assert.Equal("Hello, World! This is normal text.", sanitized);
        Assert.Empty(findings);
    }

    [Fact]
    public void LeavesEmptyStringUnchanged()
    {
        var (sanitized, findings) = Sanitize("");
        Assert.Equal("", sanitized);
        Assert.Empty(findings);
    }

    [Fact]
    public void LeavesNormalUnicodeUnchanged()
    {
        var input = "Hello \u4e16\u754c"; // Hello 世界
        var (sanitized, findings) = Sanitize(input);
        Assert.Equal(input, sanitized);
        Assert.Empty(findings);
    }

    // ── Multiple Findings Tests ─────────────────────────────────────────────

    [Fact]
    public void DetectsMultipleIssues()
    {
        var input = "\u200Bp\u0430yp\u202Eal";
        var (sanitized, findings) = Sanitize(input);
        Assert.Equal("paypal", sanitized);
        Assert.Contains("zero-width characters", findings);
        Assert.Contains("Cyrillic homoglyphs", findings);
        Assert.Contains("RTL override characters", findings);
    }
}
