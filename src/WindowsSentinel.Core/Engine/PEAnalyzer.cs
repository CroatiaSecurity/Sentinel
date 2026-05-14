using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// PE (Portable Executable) file analyzer ported from HydraDragonAntivirus's pe_feature_extractor.py
/// Performs static analysis on Windows executables: entropy calculation, import/export analysis,
/// section analysis, and suspicious indicator detection.
/// </summary>
public sealed class PEAnalyzer
{
    private readonly ILogger<PEAnalyzer> _logger;

    // MZ header signature
    private static readonly byte[] MZSignature = { 0x4D, 0x5A };
    // PE header signature
    private static readonly byte[] PESignature = { 0x50, 0x45, 0x00, 0x00 };

    // High-entropy threshold (packed/encrypted data typically > 7.0)
    private const double HighEntropyThreshold = 7.0;
    private const double VeryHighEntropyThreshold = 7.5;

    // Suspicious import APIs commonly used by malware
    private static readonly HashSet<string> SuspiciousImports = new(StringComparer.OrdinalIgnoreCase)
    {
        // Process injection
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
        "SetThreadContext", "SuspendThread", "ResumeThread",
        "NtUnmapViewOfSection", "VirtualProtectEx", "ReadProcessMemory",
        
        // Memory manipulation
        "VirtualAlloc", "VirtualProtect", "HeapAlloc", "GlobalAlloc",
        "VirtualLock", "VirtualUnlock",
        
        // Code execution
        "WinExec", "ShellExecute", "ShellExecuteEx", "CreateProcess",
        "CreateProcessInternal", "System", "Exec",
        
        // Network
        "InternetOpen", "InternetConnect", "InternetReadFile",
        "URLDownloadToFile", "URLDownloadToCacheFile", "WinHttpOpen",
        "WinHttpConnect", "socket", "connect", "send", "recv",
        
        // Persistence
        "RegSetValueEx", "RegCreateKeyEx", "CreateService",
        "OpenSCManager", "StartServiceCtrlDispatcher",
        
        // Evasion
        "GetTickCount", "Sleep", "NtSetTimerResolution",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "OutputDebugString", "NtQueryInformationProcess",
        
        // Cryptography (ransomware indicators)
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
        "BCryptEncrypt", "BCryptDecrypt", "NCryptEncrypt",
        
        // DLL manipulation
        "LoadLibrary", "LoadLibraryEx", "GetProcAddress",
        "LdrLoadDll", "LdrGetProcedureAddress",
        
        // Process manipulation
        "OpenProcess", "TerminateProcess", "CreateToolhelp32Snapshot",
        "Process32First", "Process32Next", "Module32First",
        
        // Thread manipulation
        "CreateThread", "OpenThread", "TerminateThread"
    };

    // Section names commonly associated with packing/encryption
    private static readonly HashSet<string> SuspiciousSectionNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "UPX0", "UPX1", "UPX2", "UPX!",
        "aspack", "aspck",
        "petite", "petite1",
        "MEW", "MEW0", "MEW1",
        "PACK", "PACK1", "PACK2",
        "Themida", "WinLicence",
        "VMProtect", "VMP",
        "ENIGMA", "ENIGMA1", "ENIGMA2",
        "Armadillo", "ARMA",
        "PECompact", "PEC",
        "NSPack", "NSP",
        "FSG", "FSG!",
        "ASProtect", "ASPR",
        "Yoda", "Yodas",
        ".vmp", ".vmp0", ".vmp1",
        "code", "DATA", "text"
    };

    public PEAnalyzer(ILogger<PEAnalyzer> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Analyze a PE file and return comprehensive results
    /// </summary>
    public PEAnalysisResult Analyze(string filePath, CancellationToken cancellationToken = default)
    {
        var result = new PEAnalysisResult { FilePath = filePath };

        try
        {
            if (!File.Exists(filePath))
            {
                result.Error = "File not found";
                return result;
            }

            // Calculate file hash
            result.FileHash = CalculateFileHash(filePath, cancellationToken);
            result.FileSize = new FileInfo(filePath).Length;

            // Read file into memory for analysis
            var fileBytes = File.ReadAllBytes(filePath);
            
            // Check if valid PE
            if (!IsValidPE(fileBytes))
            {
                result.Error = "Not a valid PE file";
                return result;
            }

            result.IsPE = true;

            // Analyze PE structure
            AnalyzePEStructure(fileBytes, result);
            
            // Calculate overall entropy
            result.OverallEntropy = CalculateEntropy(fileBytes);
            result.IsLikelyPacked = result.OverallEntropy > HighEntropyThreshold;

            _logger.LogDebug("PE Analysis complete for {File}: Entropy={Entropy:F2}, Sections={Sections}, Imports={Imports}",
                filePath, result.OverallEntropy, result.Sections.Count, result.Imports.Count);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PE analysis failed for {File}", filePath);
            result.Error = ex.Message;
        }

        return result;
    }

    /// <summary>
    /// Quick analysis - returns only key indicators
    /// </summary>
    public QuickPEAnalysis QuickAnalyze(string filePath, CancellationToken cancellationToken = default)
    {
        var result = new QuickPEAnalysis { FilePath = filePath };

        try
        {
            if (!File.Exists(filePath))
                return result;

            result.FileHash = CalculateFileHash(filePath, cancellationToken);
            result.FileSize = new FileInfo(filePath).Length;

            // Read only first 1MB for quick analysis
            using var stream = File.OpenRead(filePath);
            var buffer = new byte[Math.Min(1024 * 1024, result.FileSize)];
            stream.ReadExactly(buffer, 0, buffer.Length);

            result.IsPE = IsValidPE(buffer);
            
            if (result.IsPE)
            {
                result.Entropy = CalculateEntropy(buffer);
                result.HasImports = HasImportTable(buffer);
                result.IsPacked = result.Entropy > HighEntropyThreshold;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Quick PE analysis failed for {File}", filePath);
        }

        return result;
    }

    private bool IsValidPE(byte[] data)
    {
        if (data.Length < 64) return false;

        // Check MZ signature
        if (data[0] != 0x4D || data[1] != 0x5A) return false;

        // Get PE header offset from DOS header
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(0x3C, 4));
        if (peOffset < 0 || peOffset > data.Length - 4) return false;

        // Check PE signature
        if (data[peOffset] != 0x50 || data[peOffset + 1] != 0x45) return false;

        return true;
    }

    private void AnalyzePEStructure(byte[] data, PEAnalysisResult result)
    {
        try
        {
            var peOffset = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(0x3C, 4));
            var optionalHeaderOffset = peOffset + 24;
            var fileHeaderOffset = peOffset + 4;

            // Read File Header
            result.Machine = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(fileHeaderOffset + 0, 2));
            result.NumberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(fileHeaderOffset + 2, 2));
            result.TimeDateStamp = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(fileHeaderOffset + 4, 4));
            result.Characteristics = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(fileHeaderOffset + 18, 2));

            // Determine if 32-bit or 64-bit
            var magic = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(optionalHeaderOffset, 2));
            result.Is64Bit = magic == 0x20B; // PE32+ (64-bit)

            // Analyze sections
            var sectionTableOffset = optionalHeaderOffset + (result.Is64Bit ? 240 : 224);
            
            for (int i = 0; i < result.NumberOfSections; i++)
            {
                var sectionOffset = sectionTableOffset + (i * 40);
                if (sectionOffset + 40 > data.Length) break;

                var section = new PESectionInfo
                {
                    Name = Encoding.UTF8.GetString(data, sectionOffset, 8).TrimEnd('\0'),
                    VirtualSize = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(sectionOffset + 8, 4)),
                    VirtualAddress = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(sectionOffset + 12, 4)),
                    RawSize = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(sectionOffset + 16, 4)),
                    RawAddress = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(sectionOffset + 20, 4)),
                    Characteristics = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(sectionOffset + 36, 4))
                };

                // Calculate section entropy
                if (section.RawAddress > 0 && section.RawSize > 0 && 
                    section.RawAddress + section.RawSize <= data.Length)
                {
                    var sectionData = data.AsSpan(section.RawAddress, Math.Min(section.RawSize, 4096));
                    section.Entropy = CalculateEntropy(sectionData.ToArray());
                    section.IsHighEntropy = section.Entropy > HighEntropyThreshold;
                    section.IsSuspiciousName = SuspiciousSectionNames.Contains(section.Name);
                    section.IsExecutable = (section.Characteristics & 0x20000000) != 0;
                    section.IsWritable = (section.Characteristics & 0x80000000) != 0;
                }

                result.Sections.Add(section);
            }

            // Analyze imports (simplified - would need full PE parsing for complete import analysis)
            ScanForSuspiciousPatterns(data, result);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "PE structure analysis failed");
        }
    }

    private void ScanForSuspiciousPatterns(byte[] data, PEAnalysisResult result)
    {
        try
        {
            // Convert to string for pattern matching (ASCII strings only)
            var asciiString = Encoding.ASCII.GetString(data);
            var utf8String = Encoding.UTF8.GetString(data);

            // Check for suspicious imports by string scanning
            foreach (var import in SuspiciousImports)
            {
                if (asciiString.Contains(import, StringComparison.OrdinalIgnoreCase) ||
                    utf8String.Contains(import, StringComparison.OrdinalIgnoreCase))
                {
                    if (!result.Imports.Contains(import))
                    {
                        result.Imports.Add(import);
                    }
                }
            }

            // Check for suspicious strings
            var suspiciousStrings = new[]
            {
                "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
                "LoadLibrary", "GetProcAddress", "WinExec", "ShellExecute",
                "InternetOpen", "URLDownloadToFile", "RegSetValueEx",
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                "CryptEncrypt", "CryptDecrypt"
            };

            foreach (var str in suspiciousStrings)
            {
                if (asciiString.Contains(str) || utf8String.Contains(str))
                {
                    result.SuspiciousStrings.Add(str);
                }
            }

            // Score based on findings
            CalculateSuspicionScore(result);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Pattern scanning failed");
        }
    }

    private void CalculateSuspicionScore(PEAnalysisResult result)
    {
        double score = 0;

        // Entropy scoring
        if (result.OverallEntropy > VeryHighEntropyThreshold) score += 30;
        else if (result.OverallEntropy > HighEntropyThreshold) score += 20;

        // Suspicious imports
        score += result.Imports.Count * 3;

        // Suspicious strings
        score += result.SuspiciousStrings.Count * 2;

        // Packed section detection
        var packedSections = result.Sections.Count(s => s.IsHighEntropy || s.IsSuspiciousName);
        score += packedSections * 10;

        // No imports (common in packed malware)
        if (result.Imports.Count == 0 && result.IsLikelyPacked) score += 15;

        // Executable and writable sections (code injection indicator)
        var execWritable = result.Sections.Count(s => s.IsExecutable && s.IsWritable);
        score += execWritable * 15;

        result.SuspicionScore = Math.Min(score, 100);
        result.RiskLevel = result.SuspicionScore switch
        {
            >= 70 => PERiskLevel.High,
            >= 40 => PERiskLevel.Medium,
            >= 20 => PERiskLevel.Low,
            _ => PERiskLevel.Clean
        };
    }

    private double CalculateEntropy(byte[] data)
    {
        if (data == null || data.Length == 0) return 0;

        var frequencies = new int[256];
        foreach (var b in data)
        {
            frequencies[b]++;
        }

        double entropy = 0;
        var length = data.Length;

        foreach (var freq in frequencies)
        {
            if (freq == 0) continue;

            var probability = (double)freq / length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    private bool HasImportTable(byte[] data)
    {
        // Simplified check - look for common import descriptors
        var asciiData = Encoding.ASCII.GetString(data);
        return asciiData.Contains("kernel32.dll", StringComparison.OrdinalIgnoreCase) ||
               asciiData.Contains("ntdll.dll", StringComparison.OrdinalIgnoreCase) ||
               asciiData.Contains("user32.dll", StringComparison.OrdinalIgnoreCase);
    }

    private string CalculateFileHash(string filePath, CancellationToken cancellationToken)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        var hash = sha256.ComputeHash(stream);
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    /// <summary>
    /// Calculate entropy for a specific file section
    /// </summary>
    public double CalculateSectionEntropy(string filePath, long offset, int length)
    {
        try
        {
            using var stream = File.OpenRead(filePath);
            if (offset + length > stream.Length) return 0;

            stream.Seek(offset, SeekOrigin.Begin);
            var buffer = new byte[length];
            stream.ReadExactly(buffer, 0, length);

            return CalculateEntropy(buffer);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Section entropy calculation failed for {File}", filePath);
            return 0;
        }
    }
}

/// <summary>
/// Comprehensive PE analysis results
/// </summary>
public sealed class PEAnalysisResult
{
    public string FilePath { get; set; } = "";
    public string FileHash { get; set; } = "";
    public long FileSize { get; set; }
    public bool IsPE { get; set; }
    public string? Error { get; set; }

    // PE Header Info
    public uint Machine { get; set; }
    public ushort NumberOfSections { get; set; }
    public int TimeDateStamp { get; set; }
    public ushort Characteristics { get; set; }
    public bool Is64Bit { get; set; }

    // Analysis Results
    public double OverallEntropy { get; set; }
    public bool IsLikelyPacked { get; set; }
    public double SuspicionScore { get; set; }
    public PERiskLevel RiskLevel { get; set; }

    public List<PESectionInfo> Sections { get; set; } = new();
    public List<string> Imports { get; set; } = new();
    public List<string> SuspiciousStrings { get; set; } = new();
}

/// <summary>
/// Section information from PE analysis
/// </summary>
public sealed class PESectionInfo
{
    public string Name { get; set; } = "";
    public int VirtualSize { get; set; }
    public int VirtualAddress { get; set; }
    public int RawSize { get; set; }
    public int RawAddress { get; set; }
    public int Characteristics { get; set; }
    public double Entropy { get; set; }
    public bool IsHighEntropy { get; set; }
    public bool IsSuspiciousName { get; set; }
    public bool IsExecutable { get; set; }
    public bool IsWritable { get; set; }
}

/// <summary>
/// Quick PE analysis results
/// </summary>
public sealed class QuickPEAnalysis
{
    public string FilePath { get; set; } = "";
    public string FileHash { get; set; } = "";
    public long FileSize { get; set; }
    public bool IsPE { get; set; }
    public double Entropy { get; set; }
    public bool IsPacked { get; set; }
    public bool HasImports { get; set; }
}

public enum PERiskLevel
{
    Clean,
    Low,
    Medium,
    High
}
