using System;
using Xunit;
using Behavedr.Core;

namespace Behavedr.Tests
{
    /// <summary>
    /// ClipboardSanitizer tests (v4.5.0 changelog spec) — 14 tests
    /// Covers: zero-width character stripping, RTL override removal, 
    /// Cyrillic homoglyph replacement, clean input passthrough, multiple findings.
    /// </summary>
    public class ClipboardSanitizerTests
    {
        // ═══════════════════════════════════════════════════════════════════
        // ZERO-WIDTH CHARACTER STRIPPING (4 tests)
        // ═══════════════════════════════════════════════════════════════════

        [Fact]
        public void ZeroWidth_ZWSP_Stripped()
        {
            var result = ClipboardSanitizer.SanitizeText("hello\u200Bworld", out var modified);
            Assert.True(modified);
            Assert.Equal("helloworld", result);
        }

        [Fact]
        public void ZeroWidth_ZWNJ_Stripped()
        {
            var result = ClipboardSanitizer.SanitizeText("te\u200Cst", out var modified);
            Assert.True(modified);
            Assert.Equal("test", result);
        }

        [Fact]
        public void ZeroWidth_ZWJ_Stripped()
        {
            var result = ClipboardSanitizer.SanitizeText("a\u200Db", out var modified);
            Assert.True(modified);
            Assert.Equal("ab", result);
        }

        [Fact]
        public void ZeroWidth_BOM_Stripped()
        {
            var result = ClipboardSanitizer.SanitizeText("\uFEFFhello", out var modified);
            Assert.True(modified);
            Assert.Equal("hello", result);
        }

        // ═══════════════════════════════════════════════════════════════════
        // RTL OVERRIDE REMOVAL (3 tests)
        // ═══════════════════════════════════════════════════════════════════

        [Fact]
        public void RTL_OverrideCharacter_Stripped()
        {
            // U+202E = Right-to-Left Override (used to disguise filenames)
            var result = ClipboardSanitizer.SanitizeText("doc\u202Eexe.txt", out var modified);
            Assert.True(modified);
            Assert.Equal("docexe.txt", result);
        }

        [Fact]
        public void RTL_LRE_Stripped()
        {
            // U+202A = Left-to-Right Embedding
            var result = ClipboardSanitizer.SanitizeText("test\u202Avalue", out var modified);
            Assert.True(modified);
            Assert.Equal("testvalue", result);
        }

        [Fact]
        public void RTL_AllBidiOverrides_Stripped()
        {
            // U+202A through U+202E
            var input = "\u202A\u202B\u202C\u202D\u202Eclean";
            var result = ClipboardSanitizer.SanitizeText(input, out var modified);
            Assert.True(modified);
            Assert.Equal("clean", result);
        }

        [Fact]
        public void InvisibleUnicodeTags_Plane14_Stripped()
        {
            // \uD83F\uDC01 represents U+E0001 (Plane 14 Tag character)
            var input = "hello\uD83F\uDC01world";
            var result = ClipboardSanitizer.SanitizeText(input, out var modified);
            Assert.True(modified);
            Assert.Equal("helloworld", result);
        }

        // ═══════════════════════════════════════════════════════════════════
        // HOMOGLYPH REPLACEMENT (3 tests)
        // ═══════════════════════════════════════════════════════════════════

        [Fact]
        public void Homoglyph_CyrillicA_ReplacedWithLatinA()
        {
            // U+0430 Cyrillic 'а' → Latin 'a'
            var result = ClipboardSanitizer.SanitizeText("\u0430pple", out var modified);
            Assert.True(modified);
            Assert.Equal("apple", result);
        }

        [Fact]
        public void Homoglyph_CyrillicE_ReplacedWithLatinE()
        {
            // U+0435 Cyrillic 'е' → Latin 'e'
            var result = ClipboardSanitizer.SanitizeText("t\u0435st", out var modified);
            Assert.True(modified);
            Assert.Equal("test", result);
        }

        [Fact]
        public void Homoglyph_CyrillicO_ReplacedWithLatinO()
        {
            // U+043E Cyrillic 'о' → Latin 'o'
            var result = ClipboardSanitizer.SanitizeText("g\u043E\u043Egle.com", out var modified);
            Assert.True(modified);
            Assert.Equal("google.com", result);
        }

        // ═══════════════════════════════════════════════════════════════════
        // CLEAN INPUT (2 tests)
        // ═══════════════════════════════════════════════════════════════════

        [Fact]
        public void CleanInput_NoModification()
        {
            var result = ClipboardSanitizer.SanitizeText("Hello World 123", out var modified);
            Assert.False(modified);
            Assert.Equal("Hello World 123", result);
        }

        [Fact]
        public void CleanInput_EmptyString()
        {
            var result = ClipboardSanitizer.SanitizeText("", out var modified);
            Assert.False(modified);
            Assert.Equal("", result);
        }

        // ═══════════════════════════════════════════════════════════════════
        // MULTIPLE FINDINGS (2 tests)
        // ═══════════════════════════════════════════════════════════════════

        [Fact]
        public void MultipleFindings_MixedDangerousChars()
        {
            // Zero-width + RTL + homoglyph all in one string
            var input = "\u200B\u202E\u0430\u0435test";
            var result = ClipboardSanitizer.SanitizeText(input, out var modified);
            Assert.True(modified);
            Assert.Equal("aetest", result);
        }

        [Fact]
        public void MultipleFindings_AllCyrillicHomoglyphs()
        {
            // All 5 Cyrillic homoglyphs: а е о р с
            var input = "\u0430\u0435\u043E\u0440\u0441";
            var result = ClipboardSanitizer.SanitizeText(input, out var modified);
            Assert.True(modified);
            Assert.Equal("aeopc", result);
        }
    }
}
