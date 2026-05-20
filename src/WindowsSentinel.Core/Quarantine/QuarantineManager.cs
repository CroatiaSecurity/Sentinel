using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Quarantine;

/// <summary>
/// Quarantine Manager - Manages quarantined files.
/// Provides listing, restore, and purge operations.
/// 
/// SECURITY: All quarantined files are encrypted using DPAPI (machine scope) before
/// being written to disk. This ensures that even though the quarantine folder is
/// excluded from Defender scanning, raw malware bytes are never stored in executable form.
/// The quarantine directory is also ACL-hardened to SYSTEM + Administrators only.
/// </summary>
public sealed class QuarantineManager
{
    private readonly ILogger<QuarantineManager> _logger;
    private readonly string _quarantinePath;

    // DPAPI entropy for quarantine encryption — distinct from SecureCacheStore
    private static readonly byte[] QuarantineEntropy = Encoding.UTF8.GetBytes("WindowsSentinel.Quarantine.v1");

    public QuarantineManager(ILogger<QuarantineManager> logger)
    {
        _logger = logger;
        // Use ProgramData so the quarantine folder is accessible regardless of which
        // account the service runs under (SYSTEM's %LocalAppData% is buried in
        // C:\Windows\System32\config\systemprofile and is invisible to normal users).
        _quarantinePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "WindowsSentinel", "Quarantine");
        Directory.CreateDirectory(_quarantinePath);
        // ACL hardening runs on a background thread to avoid blocking SCM startup
        Task.Run(() => { try { ApplyQuarantineDirectoryAcl(_quarantinePath); } catch { } });
    }

    /// <summary>
    /// Gets the list of all quarantined files.
    /// </summary>
    public List<QuarantinedFile> ListQuarantinedFiles()
    {
        var files = new List<QuarantinedFile>();

        try
        {
            if (!Directory.Exists(_quarantinePath))
                return files;

            var quarantinedFiles = Directory.GetFiles(_quarantinePath, "*.quarantined");

            foreach (var file in quarantinedFiles)
            {
                try
                {
                    var info = ParseQuarantineFilename(file);
                    if (info != null)
                    {
                        var fi = new FileInfo(file);
                        info.Size = fi.Length;
                        info.CurrentPath = file;
                        files.Add(info);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "QuarantineManager: Error parsing file {File}", file);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "QuarantineManager: Error listing quarantined files");
        }

        return files.OrderByDescending(f => f.QuarantineTime).ToList();
    }

    /// <summary>
    /// Restores a quarantined file to its original location.
    /// </summary>
    public QuarantineResult RestoreFile(int index, string? destinationPath = null)
    {
        var files = ListQuarantinedFiles();

        if (index < 0 || index >= files.Count)
        {
            return new QuarantineResult
            {
                Success = false,
                Message = $"Invalid index. Valid range: 0-{files.Count - 1}"
            };
        }

        var file = files[index];
        var restorePath = destinationPath ?? file.OriginalPath;

        if (string.IsNullOrEmpty(restorePath))
        {
            return new QuarantineResult
            {
                Success = false,
                Message = "Cannot restore: original path is null or empty"
            };
        }

        try
        {
            // Check if original location exists
            var originalDir = Path.GetDirectoryName(restorePath);
            if (!string.IsNullOrEmpty(originalDir) && !Directory.Exists(originalDir))
            {
                Directory.CreateDirectory(originalDir);
            }

            // Decrypt quarantined file and write to restore path
            var decryptedBytes = DecryptQuarantinedFile(file.CurrentPath);
            File.WriteAllBytes(restorePath, decryptedBytes);

            _logger.LogInformation(
                "QuarantineManager: Restored file [{Index}] {FileName} to {Path}",
                index, file.FileName, restorePath);

            return new QuarantineResult
            {
                Success = true,
                Message = $"File restored to: {restorePath}",
                FilePath = restorePath,
                Action = "Restore"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "QuarantineManager: Restore failed");
            return new QuarantineResult
            {
                Success = false,
                Message = $"Restore failed: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Permanently deletes a quarantined file.
    /// </summary>
    public QuarantineResult PurgeFile(int index)
    {
        var files = ListQuarantinedFiles();

        if (index < 0 || index >= files.Count)
        {
            return new QuarantineResult
            {
                Success = false,
                Message = $"Invalid index. Valid range: 0-{files.Count - 1}"
            };
        }

        var file = files[index];

        try
        {
            // Secure delete: overwrite then delete
            SecureDelete(file.CurrentPath);

            _logger.LogInformation(
                "QuarantineManager: Purged file [{Index}] {FileName}",
                index, file.FileName);

            return new QuarantineResult
            {
                Success = true,
                Message = $"File permanently deleted: {file.FileName}",
                FilePath = file.CurrentPath,
                Action = "Purge"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "QuarantineManager: Purge failed");
            return new QuarantineResult
            {
                Success = false,
                Message = $"Purge failed: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Purges all quarantined files.
    /// </summary>
    public QuarantineResult PurgeAll()
    {
        var files = ListQuarantinedFiles();
        var successCount = 0;
        var failCount = 0;

        foreach (var file in files)
        {
            try
            {
                SecureDelete(file.CurrentPath);
                successCount++;
            }
            catch
            {
                failCount++;
            }
        }

        _logger.LogInformation(
            "QuarantineManager: Purged all files. Success: {Success}, Failed: {Fail}",
            successCount, failCount);

        return new QuarantineResult
        {
            Success = failCount == 0,
            Message = $"Purged {successCount} files, {failCount} failed"
        };
    }

    /// <summary>
    /// Gets information about a specific quarantined file.
    /// </summary>
    public QuarantinedFile? GetFileInfo(int index)
    {
        var files = ListQuarantinedFiles();
        return index >= 0 && index < files.Count ? files[index] : null;
    }

    /// <summary>
    /// Gets quarantine statistics.
    /// </summary>
    public QuarantineStats GetStats()
    {
        var files = ListQuarantinedFiles();

        return new QuarantineStats
        {
            TotalFiles = files.Count,
            TotalSize = files.Sum(f => f.Size),
            OldestQuarantine = files.MinBy(f => f.QuarantineTime)?.QuarantineTime,
            NewestQuarantine = files.MaxBy(f => f.QuarantineTime)?.QuarantineTime,
            QuarantinePath = _quarantinePath
        };
    }

    /// <summary>
    /// Analyzes a quarantined file for additional information.
    /// </summary>
    public Task<QuarantineAnalysis> AnalyzeFileAsync(int index)
    {
        var files = ListQuarantinedFiles();

        if (index < 0 || index >= files.Count)
        {
            return Task.FromResult(new QuarantineAnalysis { Error = "Invalid index" });
        }

        var file = files[index];
        var analysis = new QuarantineAnalysis { File = file };

        try
        {
            // Decrypt quarantined file into memory for analysis
            var content = DecryptQuarantinedFile(file.CurrentPath);

            // Calculate hash
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(content);
            analysis.Sha256Hash = Convert.ToHexString(hash);

            // Get file info
            analysis.FileSize = content.Length;
            analysis.FileType = GetFileType(file.FileName);

            // Basic entropy check
            var buffer = new byte[Math.Min(4096, content.Length)];
            Array.Copy(content, buffer, buffer.Length);
            analysis.Entropy = CalculateEntropy(buffer);

            // Check if packed/encrypted
            analysis.IsPacked = analysis.Entropy > 7.0;

            // Extract strings
            var strings = ExtractStrings(content, 1000);
            analysis.InterestingStrings = strings.Take(20).ToList();

            // Check for suspicious patterns
            analysis.SuspiciousIndicators = FindSuspiciousIndicators(strings);
        }
        catch (Exception ex)
        {
            analysis.Error = ex.Message;
        }

        return Task.FromResult(analysis);
    }

    /// <summary>
    /// Encrypts raw file bytes using DPAPI (machine scope) for safe quarantine storage.
    /// Even if Defender exclusions cover this folder, the raw malware is never on disk.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static byte[] EncryptForQuarantine(byte[] plainBytes)
    {
        return ProtectedData.Protect(plainBytes, QuarantineEntropy, DataProtectionScope.LocalMachine);
    }

    /// <summary>
    /// Decrypts a quarantined file from disk back to its original bytes.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private byte[] DecryptQuarantinedFile(string quarantinedFilePath)
    {
        var cipherBytes = File.ReadAllBytes(quarantinedFilePath);
        return ProtectedData.Unprotect(cipherBytes, QuarantineEntropy, DataProtectionScope.LocalMachine);
    }

    /// <summary>
    /// Applies restrictive ACL to the quarantine directory: SYSTEM + Administrators only.
    /// Prevents non-admin users from dropping files into the Defender-excluded folder.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private void ApplyQuarantineDirectoryAcl(string path)
    {
        try
        {
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            var dirInfo = new DirectoryInfo(path);
            var sec = dirInfo.GetAccessControl();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            // Remove all existing rules
            foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                sec.RemoveAccessRule(rule);

            // Grant SYSTEM full control
            sec.AddAccessRule(new FileSystemAccessRule(
                systemSid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));

            // Grant Administrators full control
            sec.AddAccessRule(new FileSystemAccessRule(
                adminsSid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));

            dirInfo.SetAccessControl(sec);
            _logger.LogDebug("QuarantineManager: ACL hardened on {Path}", path);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "QuarantineManager: Failed to apply ACL to quarantine directory (non-fatal)");
        }
    }

    private QuarantinedFile? ParseQuarantineFilename(string fullPath)
    {
        // SECURITY FIX: Validate the full path is within quarantine directory
        // This prevents path traversal attacks using filenames like "../../../etc/passwd"
        var expectedDir = Path.GetFullPath(_quarantinePath);
        var fullPathResolved = Path.GetFullPath(fullPath);
        
        if (!fullPathResolved.StartsWith(expectedDir, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("QuarantineManager: Rejected file outside quarantine directory: {Path}", fullPath);
            return null;
        }

        // SECURITY FIX: Get just the filename and validate it
        var filename = Path.GetFileName(fullPath);
        
        // Reject filenames with path traversal attempts or dangerous characters
        if (filename.Contains("..") || filename.Contains("/") || filename.Contains("\\") || 
            filename.Contains(":") || filename.Contains("<") || filename.Contains(">") ||
            filename.Contains("|") || filename.Contains("*") || filename.Contains("?"))
        {
            _logger.LogWarning("QuarantineManager: Rejected filename with dangerous characters: {Filename}", filename);
            return null;
        }

        // Format: {timestamp}_{pid}_{filename}.{ext}.quarantined
        var parts = filename.Split('_', 3);

        if (parts.Length < 3)
            return null;

        // SECURITY FIX: Strict validation of timestamp format
        if (!DateTime.TryParseExact(parts[0], "yyyyMMdd", null, System.Globalization.DateTimeStyles.None, out _))
            return null;

        // SECURITY FIX: Strict validation of PID (must be positive integer in valid range)
        if (!int.TryParse(parts[1], out var pid) || pid <= 0 || pid > 999999)
            return null;

        var originalName = parts[2].Replace(".quarantined", "");
        
        // SECURITY FIX: Validate original filename doesn't contain path traversal
        if (originalName.Contains("..") || originalName.Contains("/") || originalName.Contains("\\"))
        {
            _logger.LogWarning("QuarantineManager: Rejected filename with path traversal: {Filename}", originalName);
            return null;
        }

        // Parse timestamp from first part
        var timestamp = DateTime.ParseExact(parts[0] + "_" + parts[1].Substring(0, 4), "yyyyMMdd_HHmm", null);

        return new QuarantinedFile
        {
            FileName = originalName,
            ProcessId = pid,
            QuarantineTime = timestamp,
            OriginalPath = "Unknown" // Would be stored in metadata in production
        };
    }

    private void SecureDelete(string filePath)
    {
        try
        {
            // Overwrite file with random data
            var fi = new FileInfo(filePath);
            if (fi.Exists)
            {
                var buffer = new byte[fi.Length];
                new Random().NextBytes(buffer);
                File.WriteAllBytes(filePath, buffer);
            }

            // Delete file
            File.Delete(filePath);
        }
        catch
        {
            // If secure delete fails, try regular delete
            File.Delete(filePath);
        }
    }

    private string GetFileType(string filePath)
    {
        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        return ext switch
        {
            ".exe" => "Windows Executable",
            ".dll" => "Dynamic Link Library",
            ".sys" => "System Driver",
            ".ps1" => "PowerShell Script",
            ".bat" or ".cmd" => "Batch Script",
            ".vbs" => "VBScript",
            ".js" => "JavaScript",
            ".scr" => "Screensaver/Executable",
            ".hta" => "HTML Application",
            _ => "Unknown"
        };
    }

    private double CalculateEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;
        var frequencies = new int[256];
        foreach (var b in data) frequencies[b]++;
        
        double entropy = 0;
        foreach (var freq in frequencies)
        {
            if (freq == 0) continue;
            var p = (double)freq / data.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private List<string> ExtractStrings(byte[] data, int maxLength)
    {
        var strings = new List<string>();
        var current = new StringBuilder();

        for (int i = 0; i < Math.Min(data.Length, maxLength); i++)
        {
            var b = data[i];
            if (b >= 32 && b < 127) // Printable ASCII
            {
                current.Append((char)b);
                if (current.Length > 100) // Limit string length
                {
                    strings.Add(current.ToString());
                    current.Clear();
                }
            }
            else
            {
                if (current.Length >= 4)
                {
                    strings.Add(current.ToString());
                }
                current.Clear();
            }
        }

        if (current.Length >= 4)
            strings.Add(current.ToString());

        return strings;
    }

    private List<string> FindSuspiciousIndicators(List<string> strings)
    {
        var indicators = new List<string>();
        var allText = string.Join(" ", strings).ToLowerInvariant();

        var patterns = new Dictionary<string, string>
        {
            ["powershell"] = "PowerShell reference",
            ["cmd.exe"] = "Command prompt execution",
            ["reg.exe"] = "Registry manipulation",
            ["schtasks"] = "Scheduled task creation",
            ["netsh"] = "Network configuration",
            ["certutil"] = "Certificate/encoding utility",
            ["bitsadmin"] = "Background transfer",
            ["wscript"] = "Windows script host",
            ["cscript"] = "Windows script host",
            ["mshta"] = "HTML application",
            ["rundll32"] = "DLL execution",
            ["regsvr32"] = "COM registration",
            ["http"] = "Network communication",
            ["https"] = "Encrypted communication",
            ["base64"] = "Base64 encoding",
            ["frombase64string"] = "PowerShell Base64 decode",
            ["virtualalloc"] = "Memory allocation API",
            ["writeprocessmemory"] = "Process memory writing",
            ["createremotethread"] = "Remote thread creation",
            ["urlmon"] = "URL monitoring DLL",
            ["wininet"] = "Internet API",
            ["ws2_32"] = "Winsock library"
        };

        foreach (var pattern in patterns)
        {
            if (allText.Contains(pattern.Key))
            {
                indicators.Add(pattern.Value);
            }
        }

        return indicators.Distinct().ToList();
    }
}

/// <summary>
/// Represents a quarantined file.
/// </summary>
public sealed class QuarantinedFile
{
    public string FileName { get; set; } = "";
    public int ProcessId { get; set; }
    public DateTime QuarantineTime { get; set; }
    public string? OriginalPath { get; set; }
    public long Size { get; set; }
    public string CurrentPath { get; set; } = "";

    public string SizeFormatted => Size switch
    {
        < 1024 => $"{Size} B",
        < 1024 * 1024 => $"{Size / 1024.0:F1} KB",
        < 1024 * 1024 * 1024 => $"{Size / (1024.0 * 1024):F1} MB",
        _ => $"{Size / (1024.0 * 1024 * 1024):F1} GB"
    };
}

/// <summary>
/// Result of a quarantine operation.
/// </summary>
public sealed class QuarantineResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = "";
    public string? FilePath { get; set; }
    public string Action { get; set; } = "";
}

/// <summary>
/// Quarantine statistics.
/// </summary>
public sealed class QuarantineStats
{
    public int TotalFiles { get; set; }
    public long TotalSize { get; set; }
    public DateTime? OldestQuarantine { get; set; }
    public DateTime? NewestQuarantine { get; set; }
    public string QuarantinePath { get; set; } = "";

    public string TotalSizeFormatted => TotalSize switch
    {
        < 1024 => $"{TotalSize} B",
        < 1024 * 1024 => $"{TotalSize / 1024.0:F1} KB",
        < 1024 * 1024 * 1024 => $"{TotalSize / (1024.0 * 1024):F1} MB",
        _ => $"{TotalSize / (1024.0 * 1024 * 1024):F1} GB"
    };
}

/// <summary>
/// Analysis of a quarantined file.
/// </summary>
public sealed class QuarantineAnalysis
{
    public QuarantinedFile? File { get; set; }
    public string? Sha256Hash { get; set; }
    public long FileSize { get; set; }
    public string? FileType { get; set; }
    public double Entropy { get; set; }
    public bool IsPacked { get; set; }
    public List<string> InterestingStrings { get; set; } = new();
    public List<string> SuspiciousIndicators { get; set; } = new();
    public string? Error { get; set; }

    public string Verdict => SuspiciousIndicators.Count switch
    {
        >= 5 => "Highly Suspicious",
        >= 3 => "Suspicious",
        >= 1 => "Questionable",
        _ => IsPacked ? "Packed (Possible Obfuscation)" : "Clean"
    };
}

