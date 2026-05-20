using System.Buffers.Binary;
using System.Text;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// HeadersCheck Engine - Analyzes file headers for malformed structures and exploits.
/// Detects Zombie ZIP (CVE-2026-0866), malformed PE headers, and other header-based attacks.
/// </summary>
public sealed class HeadersCheckEngine
{
    private readonly ILogger<HeadersCheckEngine> _logger;

    // Known file signatures
    private static readonly Dictionary<string, byte[]> FileSignatures = new(StringComparer.OrdinalIgnoreCase)
    {
        ["MZ"] = new byte[] { 0x4D, 0x5A },           // DOS/PE executable
        ["PE"] = new byte[] { 0x50, 0x45, 0x00, 0x00 }, // PE header
        ["PK"] = new byte[] { 0x50, 0x4B, 0x03, 0x04 }, // ZIP
        ["ELF"] = new byte[] { 0x7F, 0x45, 0x4C, 0x46 }, // ELF
        ["PDF"] = new byte[] { 0x25, 0x50, 0x44, 0x46 }, // PDF
        ["PDF_End"] = new byte[] { 0x25, 0x25, 0x45, 0x4F, 0x46 }, // %%EOF
        ["RAR"] = new byte[] { 0x52, 0x61, 0x72, 0x21 }, // RAR
        ["GIF87a"] = new byte[] { 0x47, 0x49, 0x46, 0x38, 0x37, 0x61 },
        ["GIF89a"] = new byte[] { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 },
        ["PNG"] = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A },
        ["JPEG_SOI"] = new byte[] { 0xFF, 0xD8 },
        ["JPEG_APP0"] = new byte[] { 0xFF, 0xE0 },
        ["JPEG_APP1"] = new byte[] { 0xFF, 0xE1 },
        ["MP3"] = new byte[] { 0xFF, 0xFB },
        ["MP3_ID3"] = new byte[] { 0x49, 0x44, 0x33 },
        ["CLASS"] = new byte[] { 0xCA, 0xFE, 0xBA, 0xBE },
        ["MachO_32"] = new byte[] { 0xFE, 0xED, 0xFA, 0xCE },
        ["MachO_64"] = new byte[] { 0xFE, 0xED, 0xFA, 0xCF },
        ["MachO_Rev32"] = new byte[] { 0xCE, 0xFA, 0xED, 0xFE },
        ["MachO_Rev64"] = new byte[] { 0xCF, 0xFA, 0xED, 0xFE },
    };

    public HeadersCheckEngine(ILogger<HeadersCheckEngine> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Analyzes a file's header structure.
    /// </summary>
    public HeaderAnalysisResult AnalyzeFile(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
                return new HeaderAnalysisResult { FilePath = filePath, Error = "File not found" };

            using var fs = File.OpenRead(filePath);
            var header = new byte[Math.Min(4096, fs.Length)];
            var read = fs.Read(header, 0, header.Length);
            
            if (read < 16)
                return new HeaderAnalysisResult { FilePath = filePath, Error = "File too small" };

            var result = new HeaderAnalysisResult
            {
                FilePath = filePath,
                FileSize = fs.Length,
                DetectedType = DetectFileType(header),
                IsValidStructure = true
            };

            // Analyze based on detected type
            switch (result.DetectedType)
            {
                case "PE":
                    AnalyzePEHeader(header, result);
                    break;
                case "ZIP":
                    AnalyzeZIPHeader(header, result);
                    break;
                case "ELF":
                    AnalyzeELFHeader(header, result);
                    break;
                case "PDF":
                    AnalyzePDFHeader(header, result);
                    break;
                default:
                    AnalyzeGenericHeader(header, result);
                    break;
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "HeadersCheck: Error analyzing {File}", filePath);
            return new HeaderAnalysisResult { FilePath = filePath, Error = ex.Message };
        }
    }

    /// <summary>
    /// Quick check for suspicious/malformed headers.
    /// </summary>
    public bool IsSuspiciousHeader(string filePath)
    {
        var analysis = AnalyzeFile(filePath);
        return analysis.IsSuspicious || !analysis.IsValidStructure || analysis.Anomalies.Any();
    }

    private string DetectFileType(byte[] header)
    {
        // Check MZ (PE/DOS)
        if (header.Length >= 2 && header[0] == 0x4D && header[1] == 0x5A)
        {
            // Check for PE header at offset indicated by MZ header
            if (header.Length >= 64)
            {
                var peOffset = BitConverter.ToInt32(header, 60);
                if (peOffset > 0 && peOffset < header.Length - 4)
                {
                    if (header[peOffset] == 0x50 && header[peOffset + 1] == 0x45)
                        return "PE";
                }
            }
            return "MZ";
        }

        // Check other signatures
        if (CheckSignature(header, "PK")) return "ZIP";
        if (CheckSignature(header, "ELF")) return "ELF";
        if (CheckSignature(header, "PDF")) return "PDF";
        if (CheckSignature(header, "RAR")) return "RAR";
        if (CheckSignature(header, "GIF87a") || CheckSignature(header, "GIF89a")) return "GIF";
        if (CheckSignature(header, "PNG")) return "PNG";
        if (CheckSignature(header, "CLASS")) return "CLASS";
        if (CheckSignature(header, "MachO_32") || CheckSignature(header, "MachO_64") ||
            CheckSignature(header, "MachO_Rev32") || CheckSignature(header, "MachO_Rev64")) return "MACHO";

        // JPEG
        if (header.Length >= 2 && header[0] == 0xFF && header[1] == 0xD8) return "JPEG";

        // MP3
        if (CheckSignature(header, "MP3") || CheckSignature(header, "MP3_ID3")) return "MP3";

        return "UNKNOWN";
    }

    private void AnalyzePEHeader(byte[] header, HeaderAnalysisResult result)
    {
        try
        {
            var peOffset = BitConverter.ToInt32(header, 60);
            if (peOffset < 0 || peOffset > header.Length - 24)
            {
                result.Anomalies.Add("Invalid PE header offset");
                result.IsValidStructure = false;
                return;
            }

            // Check PE signature
            if (header[peOffset] != 0x50 || header[peOffset + 1] != 0x45)
            {
                result.Anomalies.Add("Invalid PE signature");
                result.IsValidStructure = false;
                return;
            }

            // Machine type
            var machine = BitConverter.ToUInt16(header, peOffset + 4);
            result.Properties["Machine"] = machine switch
            {
                0x014C => "i386",
                0x8664 => "x64",
                0xAA64 => "ARM64",
                _ => $"Unknown (0x{machine:X4})"
            };

            // Characteristics
            var characteristics = BitConverter.ToUInt16(header, peOffset + 18);
            if ((characteristics & 0x2000) != 0)
                result.Properties["Type"] = "DLL";
            else if ((characteristics & 0x0002) != 0)
                result.Properties["Type"] = "EXE";

            // Number of sections
            var numSections = BitConverter.ToUInt16(header, peOffset + 6);
            result.Properties["Sections"] = numSections.ToString();

            // Suspicious indicators
            if (numSections == 0)
            {
                result.Anomalies.Add("PE has zero sections");
                result.IsSuspicious = true;
            }

            if (numSections > 20)
            {
                result.Anomalies.Add($"Unusually high section count: {numSections}");
                result.IsSuspicious = true;
            }

            // Check for entropy/packing indicators in first section
            if (header.Length > peOffset + 24)
            {
                var sizeOfOptionalHeader = BitConverter.ToUInt16(header, peOffset + 20);
                var sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;
                
                if (sectionTableOffset < header.Length)
                {
                    // Could analyze section names and entropy here
                }
            }
        }
        catch (Exception ex)
        {
            result.Anomalies.Add($"PE analysis error: {ex.Message}");
        }
    }

    private void AnalyzeZIPHeader(byte[] header, HeaderAnalysisResult result)
    {
        try
        {
            // Zombie ZIP / ZIP bomb detection
            var localFileHeaderOffset = 0;
            var fileCount = 0;
            long totalCompressed = 0;
            long totalUncompressed = 0;

            while (localFileHeaderOffset < header.Length - 30 && fileCount < 10)
            {
                // Check local file header signature
                if (header[localFileHeaderOffset] != 0x50 || 
                    header[localFileHeaderOffset + 1] != 0x4B ||
                    header[localFileHeaderOffset + 2] != 0x03 ||
                    header[localFileHeaderOffset + 3] != 0x04)
                {
                    break;
                }

                var compressedSize = BitConverter.ToUInt32(header, localFileHeaderOffset + 18);
                var uncompressedSize = BitConverter.ToUInt32(header, localFileHeaderOffset + 22);
                var compressionMethod = BitConverter.ToUInt16(header, localFileHeaderOffset + 8);
                var fileNameLength = BitConverter.ToUInt16(header, localFileHeaderOffset + 26);
                var extraFieldLength = BitConverter.ToUInt16(header, localFileHeaderOffset + 28);

                totalCompressed += compressedSize;
                totalUncompressed += uncompressedSize;

                // Check for suspicious compression ratios (ZIP bomb)
                if (compressedSize > 0 && uncompressedSize > 0)
                {
                    var ratio = (double)uncompressedSize / compressedSize;
                    if (ratio > 100)
                    {
                        result.Anomalies.Add($"ZIP bomb indicator: compression ratio {ratio:F1}:1");
                        result.IsSuspicious = true;
                    }
                }

                // Check for CVE-2026-0866 Zombie ZIP indicator (overlapping headers)
                var nextHeaderOffset = localFileHeaderOffset + 30 + fileNameLength + extraFieldLength + (int)compressedSize;
                if (nextHeaderOffset < header.Length - 4 && nextHeaderOffset > localFileHeaderOffset)
                {
                    // Normal ZIP structure
                }
                else if (nextHeaderOffset <= localFileHeaderOffset)
                {
                    result.Anomalies.Add("Possible Zombie ZIP (CVE-2026-0866) - overlapping headers");
                    result.IsSuspicious = true;
                    result.CVEIndicators.Add("CVE-2026-0866");
                }

                // Check for empty or suspicious filenames
                if (fileNameLength == 0)
                {
                    result.Anomalies.Add("ZIP entry with empty filename");
                }
                else if (fileNameLength > 255)
                {
                    result.Anomalies.Add($"Suspiciously long filename: {fileNameLength} chars");
                    result.IsSuspicious = true;
                }

                fileCount++;
                localFileHeaderOffset = nextHeaderOffset;
            }

            result.Properties["ZIP_Entries"] = fileCount.ToString();
            result.Properties["ZIP_Compressed"] = totalCompressed.ToString();
            result.Properties["ZIP_Uncompressed"] = totalUncompressed.ToString();

            // Check overall compression ratio
            if (totalCompressed > 0 && totalUncompressed > 0)
            {
                var overallRatio = (double)totalUncompressed / totalCompressed;
                if (overallRatio > 1000)
                {
                    result.Anomalies.Add($"Extreme ZIP compression ratio: {overallRatio:F0}:1 - likely ZIP bomb");
                    result.IsSuspicious = true;
                }
            }
        }
        catch (Exception ex)
        {
            result.Anomalies.Add($"ZIP analysis error: {ex.Message}");
        }
    }

    private void AnalyzeELFHeader(byte[] header, HeaderAnalysisResult result)
    {
        try
        {
            var eiClass = header[4];
            result.Properties["ELF_Class"] = eiClass switch
            {
                1 => "32-bit",
                2 => "64-bit",
                _ => "Unknown"
            };

            var eiData = header[5];
            result.Properties["ELF_Data"] = eiData switch
            {
                1 => "Little Endian",
                2 => "Big Endian",
                _ => "Unknown"
            };

            var eType = BitConverter.ToUInt16(header, 16);
            result.Properties["ELF_Type"] = eType switch
            {
                1 => "REL (Relocatable)",
                2 => "EXEC (Executable)",
                3 => "DYN (Shared Object)",
                4 => "CORE (Core Dump)",
                _ => $"Unknown (0x{eType:X4})"
            };

            // Suspicious: ELF on Windows
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                result.Anomalies.Add("ELF binary on Windows system (possible WSL abuse)");
                result.IsSuspicious = true;
            }
        }
        catch (Exception ex)
        {
            result.Anomalies.Add($"ELF analysis error: {ex.Message}");
        }
    }

    private void AnalyzePDFHeader(byte[] header, HeaderAnalysisResult result)
    {
        try
        {
            // Check for PDF trailer (basic validation)
            var pdfString = Encoding.ASCII.GetString(header);
            
            if (!pdfString.Contains("%PDF-"))
            {
                result.Anomalies.Add("PDF header not found");
                result.IsValidStructure = false;
            }
            else
            {
                // Extract version
                var versionMatch = System.Text.RegularExpressions.Regex.Match(pdfString, @"%PDF-(\d\.\d)");
                if (versionMatch.Success)
                {
                    result.Properties["PDF_Version"] = versionMatch.Groups[1].Value;
                }
            }

            // Check for JavaScript indicators
            if (pdfString.Contains("/JavaScript", StringComparison.OrdinalIgnoreCase) ||
                pdfString.Contains("/JS", StringComparison.OrdinalIgnoreCase))
            {
                result.Anomalies.Add("PDF contains JavaScript");
                result.IsSuspicious = true;
            }

            // Check for embedded files
            if (pdfString.Contains("/EmbeddedFile", StringComparison.OrdinalIgnoreCase))
            {
                result.Anomalies.Add("PDF contains embedded files");
                result.IsSuspicious = true;
            }

            // Check for launch actions
            if (pdfString.Contains("/Launch", StringComparison.OrdinalIgnoreCase))
            {
                result.Anomalies.Add("PDF contains launch action - high risk");
                result.IsSuspicious = true;
            }
        }
        catch (Exception ex)
        {
            result.Anomalies.Add($"PDF analysis error: {ex.Message}");
        }
    }

    private void AnalyzeGenericHeader(byte[] header, HeaderAnalysisResult result)
    {
        // Calculate entropy of first 256 bytes
        var entropy = CalculateEntropy(header.Take(256).ToArray());
        result.Properties["Entropy_256"] = entropy.ToString("F2");

        if (entropy > 7.5)
        {
            result.Anomalies.Add($"High entropy header ({entropy:F2}) - possible packed/encrypted");
            result.IsSuspicious = true;
        }

        // Check for executable code patterns
        if (header.Any(b => b == 0x90)) // NOP sled
        {
            var nopCount = header.Count(b => b == 0x90);
            if (nopCount > 10)
            {
                result.Anomalies.Add($"NOP sled detected ({nopCount} bytes)");
                result.IsSuspicious = true;
            }
        }
    }

    private bool CheckSignature(byte[] data, string signatureName)
    {
        if (!FileSignatures.TryGetValue(signatureName, out var signature))
            return false;

        if (data.Length < signature.Length)
            return false;

        for (int i = 0; i < signature.Length; i++)
        {
            if (data[i] != signature[i])
                return false;
        }

        return true;
    }

    private double CalculateEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;

        var frequencies = new int[256];
        foreach (var b in data)
            frequencies[b]++;

        double entropy = 0;
        foreach (var freq in frequencies)
        {
            if (freq == 0) continue;
            var p = (double)freq / data.Length;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }
}

/// <summary>
/// Result of header analysis.
/// </summary>
public sealed class HeaderAnalysisResult
{
    public string FilePath { get; set; } = "";
    public long FileSize { get; set; }
    public string DetectedType { get; set; } = "UNKNOWN";
    public bool IsValidStructure { get; set; } = true;
    public bool IsSuspicious { get; set; } = false;
    public List<string> Anomalies { get; set; } = new();
    public List<string> CVEIndicators { get; set; } = new();
    public Dictionary<string, string> Properties { get; set; } = new();
    public string? Error { get; set; }

    public string Summary => IsSuspicious
        ? $"SUSPICIOUS {DetectedType}: {string.Join(", ", Anomalies.Take(3))}"
        : $"{DetectedType} - {(IsValidStructure ? "Valid" : "Invalid")} structure";
}

