using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Security;

/// <summary>
/// Clipboard Sanitizer — Actively strips dangerous Unicode content from the clipboard.
///
/// Removes:
///   1. Zero-width characters (U+200B, U+200C, U+200D, U+FEFF, U+2060)
///   2. Right-to-left overrides (U+202A–U+202E) used for filename spoofing
///   3. Homoglyph Cyrillic lookalikes (а/е/о/р/с → Latin a/e/o/p/c)
///   4. Invisible Unicode tags (U+E0001–U+E007F) used for fingerprinting/steganography
///
/// Only modifies clipboard when dangerous characters are actually found.
/// Emits a Tier2 detection when sanitization occurs.
/// Runs on an STA thread (clipboard API requirement).
/// </summary>
public sealed class ClipboardSanitizer : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<ClipboardSanitizer> _logger;

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);

    // Zero-width characters
    private static readonly HashSet<char> ZeroWidthChars = new()
    {
        '\u200B', // Zero Width Space
        '\u200C', // Zero Width Non-Joiner
        '\u200D', // Zero Width Joiner
        '\uFEFF', // Zero Width No-Break Space (BOM)
        '\u2060', // Word Joiner
    };

    // Right-to-left override characters
    private static readonly HashSet<char> RtlOverrideChars = new()
    {
        '\u202E', // Right-to-Left Override
        '\u202D', // Left-to-Right Override
        '\u202A', // Left-to-Right Embedding
        '\u202B', // Right-to-Left Embedding
        '\u202C', // Pop Directional Formatting
    };

    // Cyrillic homoglyphs → Latin equivalents
    private static readonly Dictionary<char, char> HomoglyphMap = new()
    {
        { '\u0430', 'a' }, // Cyrillic а → Latin a
        { '\u0435', 'e' }, // Cyrillic е → Latin e
        { '\u043E', 'o' }, // Cyrillic о → Latin o
        { '\u0440', 'p' }, // Cyrillic р → Latin p
        { '\u0441', 'c' }, // Cyrillic с → Latin c
    };

    // P/Invoke for clipboard access
    [DllImport("user32.dll")]
    private static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll")]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll")]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll")]
    private static extern IntPtr GetClipboardData(uint uFormat);

    [DllImport("user32.dll")]
    private static extern IntPtr SetClipboardData(uint uFormat, IntPtr hMem);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalUnlock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GlobalAlloc(uint uFlags, UIntPtr dwBytes);

    [DllImport("kernel32.dll")]
    private static extern UIntPtr GlobalSize(IntPtr hMem);

    private const uint CF_UNICODETEXT = 13;
    private const uint GMEM_MOVEABLE = 0x0002;

    public ClipboardSanitizer(
        IDetectionEngine detectionEngine,
        ILogger<ClipboardSanitizer> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Clipboard Sanitizer starting ===");

        // Initial delay to let system stabilize
        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Clipboard requires STA thread
                await RunOnStaThread(() => SanitizeClipboard(stoppingToken), stoppingToken);
                await Task.Delay(PollInterval, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ClipboardSanitizer: Scan error");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
    }

    private void SanitizeClipboard(CancellationToken ct)
    {
        if (!OpenClipboard(IntPtr.Zero))
            return;

        try
        {
            var hData = GetClipboardData(CF_UNICODETEXT);
            if (hData == IntPtr.Zero)
                return;

            var pData = GlobalLock(hData);
            if (pData == IntPtr.Zero)
                return;

            string? clipboardText;
            try
            {
                clipboardText = Marshal.PtrToStringUni(pData);
            }
            finally
            {
                GlobalUnlock(hData);
            }

            if (string.IsNullOrEmpty(clipboardText))
                return;

            var (sanitized, findings) = SanitizeText(clipboardText);

            if (findings.Count == 0)
                return; // Nothing dangerous found

            // Replace clipboard content with sanitized text
            EmptyClipboard();

            var bytes = Encoding.Unicode.GetBytes(sanitized + '\0');
            var hGlobal = GlobalAlloc(GMEM_MOVEABLE, (UIntPtr)bytes.Length);
            if (hGlobal == IntPtr.Zero)
                return;

            var pGlobal = GlobalLock(hGlobal);
            if (pGlobal != IntPtr.Zero)
            {
                Marshal.Copy(bytes, 0, pGlobal, bytes.Length);
                GlobalUnlock(hGlobal);
                SetClipboardData(CF_UNICODETEXT, hGlobal);
            }

            // Log and emit detection
            var findingSummary = string.Join(", ", findings);
            _logger.LogWarning(
                "Clipboard sanitized: removed dangerous content [{Findings}] from {Length} chars",
                findingSummary, clipboardText.Length);

            // Emit detection asynchronously (fire-and-forget from STA context)
            _ = EmitSanitizationDetection(findingSummary, clipboardText.Length, ct);
        }
        finally
        {
            CloseClipboard();
        }
    }

    internal (string sanitized, List<string> findings) SanitizeText(string input)
    {
        var findings = new List<string>();
        var sb = new StringBuilder(input.Length);
        bool hasZeroWidth = false;
        bool hasRtlOverride = false;
        bool hasHomoglyphs = false;
        bool hasInvisibleTags = false;

        for (int i = 0; i < input.Length; i++)
        {
            char c = input[i];

            // Check for invisible Unicode tags (U+E0001–U+E007F) — these are in supplementary plane
            // They appear as surrogate pairs in UTF-16
            if (char.IsHighSurrogate(c) && i + 1 < input.Length && char.IsLowSurrogate(input[i + 1]))
            {
                int codePoint = char.ConvertToUtf32(c, input[i + 1]);
                if (codePoint >= 0xE0001 && codePoint <= 0xE007F)
                {
                    hasInvisibleTags = true;
                    i++; // Skip the low surrogate
                    continue; // Strip the tag character
                }

                // Not a tag — keep both surrogates
                sb.Append(c);
                sb.Append(input[i + 1]);
                i++;
                continue;
            }

            // Check zero-width characters
            if (ZeroWidthChars.Contains(c))
            {
                hasZeroWidth = true;
                continue; // Strip
            }

            // Check RTL overrides
            if (RtlOverrideChars.Contains(c))
            {
                hasRtlOverride = true;
                continue; // Strip
            }

            // Check homoglyphs
            if (HomoglyphMap.TryGetValue(c, out char latinEquivalent))
            {
                hasHomoglyphs = true;
                sb.Append(latinEquivalent); // Replace with Latin equivalent
                continue;
            }

            sb.Append(c);
        }

        if (hasZeroWidth) findings.Add("zero-width characters");
        if (hasRtlOverride) findings.Add("RTL override characters");
        if (hasHomoglyphs) findings.Add("Cyrillic homoglyphs");
        if (hasInvisibleTags) findings.Add("invisible Unicode tags");

        return (sb.ToString(), findings);
    }

    private async Task EmitSanitizationDetection(string findings, int originalLength, CancellationToken ct)
    {
        try
        {
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Clipboard Sanitization: Dangerous Content Removed",
                Evidence = $"Clipboard content ({originalLength} chars) contained dangerous Unicode: [{findings}]. " +
                          "Content was sanitized to prevent potential attacks.",
                Reasoning = "Dangerous Unicode characters in clipboard content can be used for: " +
                           "RTL override attacks (filename spoofing like 'document[RLO]fdp.exe' appearing as 'document.pdf'), " +
                           "homoglyph phishing (Cyrillic lookalikes in URLs/addresses), " +
                           "zero-width character fingerprinting/tracking, " +
                           "and invisible tag-based steganography. Sanitization prevents these attack vectors.",
                Confidence = 0.60,
                Tier = DetectionTier.Tier2Indicator,
                ProcessName = "ClipboardSanitizer",
                ProcessId = Environment.ProcessId,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["findings"] = findings,
                    ["original_length"] = originalLength.ToString(),
                    ["technique"] = "T1204 - User Execution (clipboard manipulation)"
                }
            }, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to emit clipboard sanitization detection");
        }
    }

    private static Task RunOnStaThread(Action action, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource();
        var thread = new Thread(() =>
        {
            try
            {
                action();
                tcs.SetResult();
            }
            catch (Exception ex)
            {
                tcs.SetException(ex);
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.IsBackground = true;
        thread.Start();

        // Register cancellation
        ct.Register(() => tcs.TrySetCanceled(ct));

        return tcs.Task;
    }
}
