using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Validates process information to prevent various bypass techniques:
/// - Unicode spoofing (RTL override, homoglyphs)
/// - Invalid PID values
/// - Path traversal in process names
/// - Process name vs executable name mismatches
/// </summary>
public sealed class ProcessValidator
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, [Out] StringBuilder lpExeName, ref int lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    private const int PROCESS_QUERY_INFORMATION = 0x0400;
    private const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    private readonly ILogger<ProcessValidator> _logger;

    // Unicode characters used for spoofing
    private static readonly char[] DangerousUnicodeChars = new[]
    {
        '\u202E', // Right-to-Left Override (RLO)
        '\u202D', // Left-to-Right Override (LRO)
        '\u202A', // Left-to-Right Embedding (LRE)
        '\u202B', // Right-to-Left Embedding (RLE)
        '\u202C', // Pop Directional Formatting (PDF)
        '\u2066', // Left-to-Right Isolate (LRI)
        '\u2067', // Right-to-Left Isolate (RLI)
        '\u2068', // First Strong Isolate (FSI)
        '\u2069', // Pop Directional Isolate (PDI)
        '\u200E', // Left-to-Right Mark (LRM)
        '\u200F', // Right-to-Left Mark (RLM)
        '\u061C', // Arabic Letter Mark (ALM)
    };

    // Homoglyph mappings - Cyrillic/Greek characters that look like Latin letters
    // These are used to detect spoofing attacks (e.g., "svchоst.exe" with Cyrillic 'о')
    private static readonly Dictionary<char, char> HomoglyphMap = new()
    {
        ['а'] = 'a', // Cyrillic а (U+0430) -> Latin a (U+0061)
        ['е'] = 'e', // Cyrillic е (U+0435) -> Latin e (U+0065)
        ['о'] = 'o', // Cyrillic о (U+043E) -> Latin o (U+006F)
        ['р'] = 'p', // Cyrillic р (U+0440) -> Latin p (U+0070)
        ['с'] = 'c', // Cyrillic с (U+0441) -> Latin c (U+0063)
        ['х'] = 'x', // Cyrillic х (U+0445) -> Latin x (U+0078)
        ['і'] = 'i', // Cyrillic і (U+0456) -> Latin i (U+0069)
        ['ј'] = 'j', // Cyrillic ј (U+0458) -> Latin j (U+006A)
        ['ԛ'] = 'q', // Cyrillic ԛ (U+051B) -> Latin q (U+0071)
        ['ѕ'] = 's', // Cyrillic ѕ (U+0455) -> Latin s (U+0073)
        ['ս'] = 'u', // Cyrillic ս (U+057D) -> Latin u (U+0075)
        ['ν'] = 'v', // Greek ν (U+03BD) -> Latin v (U+0076)
        ['ω'] = 'w', // Greek ω (U+03C9) -> Latin w (U+0077)
        ['γ'] = 'y', // Greek γ (U+03B3) -> Latin y (U+0079)
        ['\uFF10'] = '0', // Fullwidth zero (U+FF10) -> ASCII 0
        ['\uFF11'] = '1', // Fullwidth one (U+FF11) -> ASCII 1
        ['\uFF12'] = '2', // Fullwidth two (U+FF12) -> ASCII 2
        ['\uFF13'] = '3', // Fullwidth three (U+FF13) -> ASCII 3
        ['\uFF14'] = '4', // Fullwidth four (U+FF14) -> ASCII 4
        ['\uFF15'] = '5', // Fullwidth five (U+FF15) -> ASCII 5
        ['\uFF16'] = '6', // Fullwidth six (U+FF16) -> ASCII 6
        ['\uFF17'] = '7', // Fullwidth seven (U+FF17) -> ASCII 7
        ['\uFF18'] = '8', // Fullwidth eight (U+FF18) -> ASCII 8
        ['\uFF19'] = '9', // Fullwidth nine (U+FF19) -> ASCII 9
    };

    public ProcessValidator(ILogger<ProcessValidator> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Validates and normalizes a process name to prevent spoofing attacks.
    /// Returns null if the process name is suspicious/invalid.
    /// </summary>
    public string? ValidateAndNormalizeProcessName(string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName))
            return null;

        // Check for dangerous Unicode characters (RTL override, etc.)
        if (ContainsDangerousUnicode(processName))
        {
            _logger.LogWarning("ProcessValidator: Rejected process name with dangerous Unicode characters: {ProcessName}", processName);
            return null;
        }

        // Normalize Unicode (decompose combined characters)
        var normalized = processName.Normalize(NormalizationForm.FormD);

        // Remove non-spacing marks (accents, etc.)
        var withoutAccents = new string(normalized
            .Where(c => CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark)
            .ToArray());

        // Replace homoglyphs with ASCII equivalents
        var withHomoglyphsReplaced = ReplaceHomoglyphs(withoutAccents);

        // Final normalization to composed form
        var result = withHomoglyphsReplaced.Normalize(NormalizationForm.FormC);

        // Validate the result
        if (!IsValidProcessName(result))
        {
            _logger.LogWarning("ProcessValidator: Rejected invalid process name: {ProcessName}", result);
            return null;
        }

        return result;
    }

    /// <summary>
    /// Validates a PID is within acceptable range.
    /// </summary>
    public bool IsValidPid(int pid)
    {
        // PIDs on Windows are typically 4-65535 for user processes
        // System processes: 0 (idle), 4 (system)
        // Allow some buffer for edge cases but reject obvious invalid values
        return pid > 0 && pid <= 999999;
    }

    /// <summary>
    /// Attempts to securely retrieve the full image path for a running PID using native APIs.
    /// Used as a fallback when ETW or WMI events are missing the ImagePath.
    /// </summary>
    public string? TryGetProcessImagePath(int pid)
    {
        if (!IsValidPid(pid)) return null;

        IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero)
            return null;

        try
        {
            int capacity = 1024;
            StringBuilder sb = new StringBuilder(capacity);
            if (QueryFullProcessImageName(hProcess, 0, sb, ref capacity))
            {
                return sb.ToString();
            }
            return null;
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// Validates that the process name matches the executable file name.
    /// Helps detect process hollowing and PID reuse attacks.
    /// </summary>
    public bool ValidateProcessNameMatchesExecutable(string processName, string imagePath)
    {
        if (string.IsNullOrWhiteSpace(processName) || string.IsNullOrWhiteSpace(imagePath))
            return false;

        try
        {
            var executableName = Path.GetFileNameWithoutExtension(imagePath);
            
            // Exact match (case-insensitive)
            if (string.Equals(processName, executableName, StringComparison.OrdinalIgnoreCase))
                return true;

            // Some system processes have different names (e.g., "svchost" vs "svchost.exe")
            if (string.Equals(processName, Path.GetFileName(imagePath), StringComparison.OrdinalIgnoreCase))
                return true;

            _logger.LogDebug("ProcessValidator: Name mismatch - Process: {ProcessName}, Executable: {Executable}", 
                processName, executableName);
            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Detects if the process name is trying to impersonate a system process.
    /// </summary>
    public bool IsSystemProcessImpersonation(string processName)
    {
        var normalized = processName?.ToLowerInvariant() ?? "";
        
        // System processes that are commonly impersonated
        var criticalProcesses = new[]
        {
            "svchost", "lsass", "csrss", "services", "smss",
            "wininit", "winlogon", "dwm", "explorer", "conhost"
        };

        // Check if it's trying to impersonate but isn't exactly matching
        foreach (var critical in criticalProcesses)
        {
            // Contains critical name but isn't exactly it (e.g., "svchost1", "lsass_backup")
            if (normalized.Contains(critical) && normalized != critical)
            {
                _logger.LogWarning("ProcessValidator: Detected possible system process impersonation: {ProcessName} (impersonating {Critical})",
                    processName, critical);
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Validates that a file path is safe - no traversal, proper format, within expected directories.
    /// </summary>
    public bool IsValidPath(string path, string? expectedBasePath = null)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        // Check for null bytes (null byte injection)
        if (path.Contains('\0'))
        {
            _logger.LogWarning("ProcessValidator: Rejected path with null byte: {Path}", path);
            return false;
        }

        // Check for invalid characters
        var invalidChars = Path.GetInvalidPathChars();
        if (path.Any(c => invalidChars.Contains(c)))
        {
            _logger.LogWarning("ProcessValidator: Rejected path with invalid characters: {Path}", path);
            return false;
        }

        try
        {
            // Normalize the path to resolve . and .. components
            var fullPath = Path.GetFullPath(path);
            
            // Check for path traversal after normalization
            // If base path provided, ensure the path is within it
            if (!string.IsNullOrEmpty(expectedBasePath))
            {
                var fullBasePath = Path.GetFullPath(expectedBasePath);
                if (!fullPath.StartsWith(fullBasePath, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("ProcessValidator: Rejected path outside expected directory: {Path}", path);
                    return false;
                }
            }
            
            // Check for UNC paths (network paths) - could be used for traversal
            if (fullPath.StartsWith("\\\\", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("ProcessValidator: Rejected UNC path: {Path}", path);
                return false;
            }
            
            // Check for device paths (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
            var fileName = Path.GetFileName(fullPath).ToUpperInvariant();
            var deviceNames = new[] { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" };
            if (deviceNames.Any(d => fileName == d || fileName.StartsWith(d + ".", StringComparison.OrdinalIgnoreCase)))
            {
                _logger.LogWarning("ProcessValidator: Rejected device path: {Path}", path);
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning("ProcessValidator: Path normalization failed for {Path}: {Error}", path, ex.Message);
            return false;
        }

        return true;
    }

    /// <summary>
    /// Checks if the process name contains dangerous Unicode characters.
    /// </summary>
    private static bool ContainsDangerousUnicode(string text)
    {
        if (string.IsNullOrEmpty(text))
            return false;

        // Check for RTL override and other spoofing characters
        foreach (var ch in text)
        {
            if (DangerousUnicodeChars.Contains(ch))
                return true;

            // Check for high Unicode ranges often used in spoofing
            // Private Use Area (PUA), etc.
            if (ch >= '\uE000' && ch <= '\uF8FF')
                return true; // Private Use Area
            if (ch >= '\uF900' && ch <= '\uFAFF')
                continue; // CJK Compatibility Ideographs (legitimate)
            if (ch >= 0x1F600 && ch <= 0x1F64F)
                continue; // Emojis (could be suspicious but not necessarily dangerous)
        }

        // Check for mixed scripts (e.g., Latin + Cyrillic)
        // This is a simplified check - a real implementation would use ICU
        var hasLatin = text.Any(c => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
        var hasCyrillic = text.Any(c => c >= '\u0400' && c <= '\u04FF');
        var hasGreek = text.Any(c => c >= '\u0370' && c <= '\u03FF');

        if ((hasLatin && hasCyrillic) || (hasLatin && hasGreek) || (hasCyrillic && hasGreek))
        {
            // Mixed scripts detected - could be homoglyph attack
            return true;
        }

        return false;
    }

    /// <summary>
    /// Replaces homoglyph characters with their ASCII equivalents.
    /// </summary>
    private static string ReplaceHomoglyphs(string text)
    {
        var result = new StringBuilder(text.Length);
        
        foreach (var ch in text)
        {
            if (HomoglyphMap.TryGetValue(ch, out var replacement))
            {
                result.Append(replacement);
            }
            else
            {
                result.Append(ch);
            }
        }

        return result.ToString();
    }

    /// <summary>
    /// Validates that a process name is reasonable (not too long, no invalid chars).
    /// </summary>
    private static bool IsValidProcessName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return false;

        // Max length for Windows process names
        if (name.Length > 255)
            return false;

        // Should not contain path separators
        if (name.Contains('/') || name.Contains('\\'))
            return false;

        // Should not start with a dot (hidden file convention)
        if (name.StartsWith('.'))
            return false;

        return true;
    }
}


