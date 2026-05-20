using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// ELF Catcher - Detects Linux ELF binaries on Windows (WSL abuse detection).
/// </summary>
public sealed class ElfCatcher
{
    private readonly ILogger<ElfCatcher> _logger;

    // ELF magic bytes
    private static readonly byte[] ElfMagic = { 0x7F, 0x45, 0x4C, 0x46 }; // \x7FELF

    public ElfCatcher(ILogger<ElfCatcher> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Checks if a file is an ELF binary.
    /// </summary>
    public bool IsElfBinary(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
                return false;

            using var fs = File.OpenRead(filePath);
            var header = new byte[4];
            var read = fs.Read(header, 0, 4);

            if (read < 4)
                return false;

            // Check ELF magic
            for (int i = 0; i < 4; i++)
            {
                if (header[i] != ElfMagic[i])
                    return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ElfCatcher: Error checking {File}", filePath);
            return false;
        }
    }

    /// <summary>
    /// Analyzes an ELF file for suspicious characteristics.
    /// </summary>
    public ElfAnalysisResult? AnalyzeElf(string filePath)
    {
        try
        {
            if (!IsElfBinary(filePath))
                return null;

            using var fs = File.OpenRead(filePath);
            var header = new byte[64];
            var read = fs.Read(header, 0, 64);

            if (read < 20)
                return null;

            var result = new ElfAnalysisResult
            {
                FilePath = filePath,
                IsElf = true
            };

            // EI_CLASS (32/64 bit)
            result.Bitness = header[4] switch
            {
                1 => "32-bit",
                2 => "64-bit",
                _ => "Unknown"
            };

            // EI_DATA (endianness)
            result.Endianness = header[5] switch
            {
                1 => "Little Endian",
                2 => "Big Endian",
                _ => "Unknown"
            };

            // e_type
            if (read >= 18)
            {
                var type = BitConverter.ToUInt16(header, 16);
                result.Type = type switch
                {
                    1 => "REL (Relocatable)",
                    2 => "EXEC (Executable)",
                    3 => "DYN (Shared Object)",
                    4 => "CORE (Core Dump)",
                    _ => $"Unknown ({type})"
                };
            }

            // e_machine
            if (read >= 20)
            {
                var machine = BitConverter.ToUInt16(header, 18);
                result.Architecture = machine switch
                {
                    0x03 => "x86",
                    0x3E => "x86-64",
                    0xB7 => "ARM64",
                    0x28 => "ARM",
                    0xF3 => "RISC-V",
                    _ => $"Unknown (0x{machine:X4})"
                };
            }

            // Check for suspicious indicators
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                // ELF on Windows is suspicious
                result.IsSuspicious = true;
                result.SuspicionReason = "ELF binary on Windows system - possible WSL abuse or cross-platform malware";
            }

            // Check file location
            var lowerPath = filePath.ToLowerInvariant();
            if (lowerPath.Contains("\\temp\\") ||
                lowerPath.Contains("\\appdata\\local\\temp") ||
                lowerPath.Contains("\\downloads\\"))
            {
                result.IsSuspicious = true;
                result.SuspicionReason = "ELF binary in temporary/suspicious location";
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ElfCatcher: Error analyzing {File}", filePath);
            return null;
        }
    }

    /// <summary>
    /// Scans a directory for ELF files.
    /// </summary>
    public List<ElfAnalysisResult> ScanDirectory(string path, bool recursive = false)
    {
        var results = new List<ElfAnalysisResult>();

        try
        {
            if (!Directory.Exists(path))
                return results;

            var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            var files = Directory.GetFiles(path, "*", searchOption);

            foreach (var file in files)
            {
                var analysis = AnalyzeElf(file);
                if (analysis != null)
                {
                    results.Add(analysis);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ElfCatcher: Error scanning directory {Path}", path);
        }

        return results;
    }
}

/// <summary>
/// Result of ELF analysis.
/// </summary>
public sealed class ElfAnalysisResult
{
    public string FilePath { get; set; } = "";
    public bool IsElf { get; set; }
    public string Bitness { get; set; } = "";
    public string Endianness { get; set; } = "";
    public string Type { get; set; } = "";
    public string Architecture { get; set; } = "";
    public bool IsSuspicious { get; set; }
    public string? SuspicionReason { get; set; }

    public string Summary => IsSuspicious
        ? $"SUSPICIOUS {Type} ({Bitness} {Architecture}) - {SuspicionReason}"
        : $"{Type} ({Bitness} {Architecture})";
}

