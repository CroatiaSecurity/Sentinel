using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// CrudePayload Guard - Detects crude/stageless malware payloads.
/// Identifies simple shellcode, unpacked malware, and unsophisticated implants.
/// </summary>
public sealed class CrudePayloadGuard
{
    private readonly ILogger<CrudePayloadGuard> _logger;

    // Common x86/x64 shellcode patterns
    private static readonly byte[][] ShellcodePatterns = new[]
    {
        new byte[] { 0xFC, 0x48, 0x83, 0xE4 }, // Windows x64 shellcode prologue
        new byte[] { 0x4D, 0x5A },             // MZ header in shellcode
        new byte[] { 0x90, 0x90, 0x90, 0x90 }, // NOP sled
        new byte[] { 0xEB },                   // Short jump
        new byte[] { 0xE9 },                   // Near jump
        new byte[] { 0x55, 0x8B, 0xEC },       // push ebp; mov ebp, esp
        new byte[] { 0x48, 0x89, 0x5C },       // x64 register setup
        new byte[] { 0x48, 0x83, 0xEC },       // x64 stack adjustment
        new byte[] { 0xFF, 0xD0 },             // call eax
        new byte[] { 0xFF, 0xD1 },             // call ecx
        new byte[] { 0x41, 0x54 },             // push r12
        new byte[] { 0x41, 0x55 },             // push r13
    };

    // Common strings in crude payloads
    private static readonly string[] CrudeStrings = new[]
    {
        "cmd.exe /c",
        "powershell -enc",
        "powershell -w hidden",
        "Invoke-Expression",
        "IEX(New-Object",
        "FromBase64String",
        "VirtualAlloc",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "WSASocket",
        "connect",
        "shell",
        "cmdshell",
        "recv",
        "send",
        "LoadLibraryA",
        "GetProcAddress",
        "WinExec",
        "ShellExecute",
        "URLDownloadToFile",
        "InternetOpen",
        "CreateProcess",
        "cmd /c",
        "powershell.exe",
        "wscript.shell",
        "scripting.filesystemobject",
        "shell.application"
    };

    public CrudePayloadGuard(ILogger<CrudePayloadGuard> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Analyzes a file for crude payload indicators.
    /// </summary>
    public CrudePayloadAnalysis AnalyzeFile(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
                return new CrudePayloadAnalysis { FilePath = filePath, Error = "File not found" };

            var result = new CrudePayloadAnalysis
            {
                FilePath = filePath,
                FileSize = new FileInfo(filePath).Length
            };

            // Quick size check - crude payloads are often small
            if (result.FileSize < 1000)
            {
                result.Indicators.Add("Very small file size (likely stageless)");
                result.SuspicionScore += 20;
            }

            // Read file content
            var content = File.ReadAllBytes(filePath);
            
            // Check for shellcode patterns
            CheckShellcodePatterns(content, result);
            
            // Check for crude strings
            CheckCrudeStrings(content, result);
            
            // Check for high entropy (packed/encrypted)
            var entropy = CalculateEntropy(content);
            result.Entropy = entropy;
            if (entropy > 7.5)
            {
                result.Indicators.Add($"High entropy ({entropy:F2}) - possible packed/encrypted payload");
                result.SuspicionScore += 15;
            }

            // Check for low entropy (unpacked shellcode)
            if (entropy < 5.0 && result.FileSize < 10000)
            {
                result.Indicators.Add($"Low entropy in small file ({entropy:F2}) - possible unpacked shellcode");
                result.SuspicionScore += 10;
            }

            // Determine verdict
            result.IsCrudePayload = result.SuspicionScore >= 50;
            result.Verdict = result.SuspicionScore switch
            {
                >= 70 => "Highly Suspicious (Crude Payload)",
                >= 50 => "Suspicious (Possible Payload)",
                >= 30 => "Questionable",
                _ => "Clean"
            };

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "CrudePayloadGuard: Error analyzing {File}", filePath);
            return new CrudePayloadAnalysis { FilePath = filePath, Error = ex.Message };
        }
    }

    /// <summary>
    /// Quick check for crude payload indicators.
    /// </summary>
    public bool IsLikelyCrudePayload(string filePath)
    {
        var analysis = AnalyzeFile(filePath);
        return analysis.IsCrudePayload && string.IsNullOrEmpty(analysis.Error);
    }

    /// <summary>
    /// Scans memory buffer for crude payload indicators.
    /// </summary>
    public CrudePayloadAnalysis AnalyzeMemory(byte[] memory, int pid = 0)
    {
        var result = new CrudePayloadAnalysis
        {
            FilePath = $"memory://{pid}",
            FileSize = memory.Length
        };

        try
        {
            CheckShellcodePatterns(memory, result);
            CheckCrudeStrings(memory, result);
            
            var entropy = CalculateEntropy(memory);
            result.Entropy = entropy;
            
            if (entropy > 7.0)
            {
                result.SuspicionScore += 10;
            }

            result.IsCrudePayload = result.SuspicionScore >= 50;
            
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "CrudePayloadGuard: Error analyzing memory");
            return result;
        }
    }

    private void CheckShellcodePatterns(byte[] content, CrudePayloadAnalysis result)
    {
        foreach (var pattern in ShellcodePatterns)
        {
            if (pattern.Length == 0) continue;
            
            // Count occurrences
            int count = 0;
            for (int i = 0; i <= content.Length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (content[i + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) count++;
            }

            if (count > 0)
            {
                var patternName = pattern[0] switch
                {
                    0xFC => "Windows x64 shellcode prologue",
                    0x4D => "MZ header in shellcode",
                    0x90 => "NOP sled",
                    0xEB => "Short jump",
                    0xE9 => "Near jump",
                    0x55 => "Function prologue (x86)",
                    0x48 => "x64 register/stack setup",
                    0xFF => "Dynamic call",
                    0x41 => "x64 push register",
                    _ => $"Pattern 0x{pattern[0]:X2}"
                };

                result.ShellcodeIndicators.Add($"{patternName}: {count} occurrences");
                result.SuspicionScore += Math.Min(count * 5, 25);
            }
        }
    }

    private void CheckCrudeStrings(byte[] content, CrudePayloadAnalysis result)
    {
        // Convert to string for searching
        var text = System.Text.Encoding.ASCII.GetString(content);
        var lowerText = text.ToLowerInvariant();

        foreach (var crudeString in CrudeStrings)
        {
            var lowerCrude = crudeString.ToLowerInvariant();
            if (lowerText.Contains(lowerCrude))
            {
                result.CrudeStringsFound.Add(crudeString);
                result.SuspicionScore += 5;
            }
        }

        if (result.CrudeStringsFound.Count > 0)
        {
            result.Indicators.Add($"Found {result.CrudeStringsFound.Count} crude payload strings");
        }
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
/// Analysis result for crude payload detection.
/// </summary>
public sealed class CrudePayloadAnalysis
{
    public string FilePath { get; set; } = "";
    public long FileSize { get; set; }
    public double Entropy { get; set; }
    public int SuspicionScore { get; set; }
    public bool IsCrudePayload { get; set; }
    public string Verdict { get; set; } = "Unknown";
    public List<string> Indicators { get; set; } = new();
    public List<string> ShellcodeIndicators { get; set; } = new();
    public List<string> CrudeStringsFound { get; set; } = new();
    public string? Error { get; set; }

    public string Summary => IsCrudePayload
        ? $"{Verdict} - Score: {SuspicionScore}/100, {Indicators.Count} indicators"
        : $"{Verdict} - Score: {SuspicionScore}/100";
}


