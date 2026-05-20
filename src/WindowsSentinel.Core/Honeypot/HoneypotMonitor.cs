using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Honeypot;

/// <summary>
/// Honeypot Monitor - Creates and monitors decoy files to detect unauthorized access.
/// Early warning system for ransomware and lateral movement.
/// </summary>
public sealed class HoneypotMonitor : BackgroundService
{
    private readonly ILogger<HoneypotMonitor> _logger;
    private readonly IDetectionEngine _detectionEngine;
    private readonly List<HoneypotFile> _honeypotFiles;
    private readonly string _honeypotBasePath;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastAccessTimes;
    
    private FileSystemWatcher? _watcher;

    public HoneypotMonitor(
        ILogger<HoneypotMonitor> logger,
        IDetectionEngine detectionEngine)
    {
        _logger = logger;
        _detectionEngine = detectionEngine;
        _honeypotFiles = new List<HoneypotFile>();
        _lastAccessTimes = new ConcurrentDictionary<string, DateTimeOffset>();
        
        _honeypotBasePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WindowsSentinel", "Honeypot");
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Honeypot Monitor starting ===");

        // Create honeypot directory
        Directory.CreateDirectory(_honeypotBasePath);

        // Create decoy files
        CreateHoneypotFiles();

        // Setup watcher
        SetupWatcher();

        // Periodic integrity check
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken);
                await VerifyHoneypotIntegrityAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Honeypot: Error in main loop");
            }
        }

        // Cleanup
        CleanupHoneypot();
    }

    private void CreateHoneypotFiles()
    {
        // Create various decoy files that look attractive to attackers
        var decoyFiles = new[]
        {
            ("important_documents.zip", "application/zip", CreateZipContent()),
            ("financial_records.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", CreateOfficeContent()),
            ("passwords.txt", "text/plain", CreatePasswordContent()),
            ("confidential.pdf", "application/pdf", CreatePDFContent()),
            ("customer_database.csv", "text/csv", CreateDatabaseContent()),
            ("banking_info.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", CreateOfficeContent()),
            ("tax_returns_2025.pdf", "application/pdf", CreatePDFContent()),
            ("crypto_wallet.dat", "application/octet-stream", CreateWalletContent()),
            ("ssh_keys.pem", "application/x-pem-file", CreateSSHKeyContent()),
            ("README_DECRYPT.txt", "text/plain", CreateRansomwareBaitContent())
        };

        foreach (var (filename, mimeType, content) in decoyFiles)
        {
            try
            {
                var filePath = Path.Combine(_honeypotBasePath, filename);
                
                // Write content
                File.WriteAllBytes(filePath, content);
                
                // Calculate hash
                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(content);
                var hashString = Convert.ToHexString(hash);
                
                // Set file attributes (hidden)
                File.SetAttributes(filePath, FileAttributes.Hidden | FileAttributes.System);
                
                _honeypotFiles.Add(new HoneypotFile
                {
                    FilePath = filePath,
                    FileName = filename,
                    OriginalContent = content,
                    OriginalHash = hashString,
                    CreatedAt = DateTimeOffset.UtcNow,
                    MimeType = mimeType,
                    IsIntact = true
                });

                _logger.LogDebug("Honeypot: Created {File} (hash: {Hash})", filename, hashString[..16] + "...");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Honeypot: Failed to create {File}", filename);
            }
        }

        _logger.LogInformation("Honeypot: Created {Count} decoy files in {Path}", 
            _honeypotFiles.Count, _honeypotBasePath);
    }

    private void SetupWatcher()
    {
        try
        {
            _watcher = new FileSystemWatcher(_honeypotBasePath)
            {
                NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite | 
                              NotifyFilters.FileName | NotifyFilters.Size,
                EnableRaisingEvents = true,
                IncludeSubdirectories = false
            };

            _watcher.Changed += OnHoneypotAccess;
            _watcher.Created += OnHoneypotCreated;
            _watcher.Deleted += OnHoneypotDeleted;
            _watcher.Renamed += OnHoneypotRenamed;

            _logger.LogDebug("Honeypot: File system watcher active");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Honeypot: Failed to setup watcher");
        }
    }

    private void OnHoneypotAccess(object sender, FileSystemEventArgs e)
    {
        try
        {
            var now = DateTimeOffset.UtcNow;
            
            // Debounce - don't alert on same file within 5 seconds
            if (_lastAccessTimes.TryGetValue(e.FullPath, out var lastAccess))
            {
                if ((now - lastAccess).TotalSeconds < 5)
                    return;
            }
            _lastAccessTimes[e.FullPath] = now;

            // Check which process accessed the file
            var accessingProcess = GetAccessingProcess(e.FullPath);
            
            _logger.LogCritical(
                "HONEYPOT ACCESS: {File} accessed by {Process}",
                Path.GetFileName(e.FullPath),
                accessingProcess ?? "Unknown");

            // Emit detection
            _ = Task.Run(async () =>
            {
                try
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Honeypot: Decoy File Accessed",
                        Evidence = $"Honeypot file '{e.Name}' was accessed. This is a strong indicator of unauthorized scanning, ransomware, or file enumeration.",
                        Reasoning = "Honeypot files are hidden decoys that legitimate software should never access. Access indicates malicious scanning or lateral movement.",
                        Confidence = 0.95,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = accessingProcess ?? "Unknown",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["honeypot_file"] = e.FullPath,
                            ["event_type"] = e.ChangeType.ToString(),
                            ["accessing_process"] = accessingProcess ?? "Unknown",
                            ["technique"] = "T1083 - File and Directory Discovery"
                        }
                    }, CancellationToken.None);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Honeypot: Failed to emit detection");
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Honeypot: Error handling access event");
        }
    }

    private void OnHoneypotCreated(object sender, FileSystemEventArgs e)
    {
        _logger.LogCritical("HONEYPOT: New file created in honeypot directory: {File}", e.Name);
        
        // This could be a ransomware note
        if (e.Name?.Contains("README", StringComparison.OrdinalIgnoreCase) == true ||
            e.Name?.Contains("DECRYPT", StringComparison.OrdinalIgnoreCase) == true ||
            e.Name?.Contains("RECOVER", StringComparison.OrdinalIgnoreCase) == true)
        {
            _ = Task.Run(async () =>
            {
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Honeypot: Ransomware Note Detected",
                    Evidence = $"Ransomware-style file '{e.Name}' created in honeypot directory. This indicates active ransomware encryption.",
                    Reasoning = "Ransomware typically drops README/DECRYPT files. Creating such a file in the honeypot directory confirms ransomware is active.",
                    Confidence = 0.98,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "Unknown",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["honeypot_file"] = e.FullPath,
                        ["event_type"] = "RansomwareNote",
                        ["technique"] = "T1490 - Inhibit System Recovery"
                    }
                }, CancellationToken.None);
            });
        }
    }

    private void OnHoneypotDeleted(object sender, FileSystemEventArgs e)
    {
        _logger.LogCritical("HONEYPOT: Honeypot file deleted: {File}", e.Name);
        
        var honeypot = _honeypotFiles.FirstOrDefault(h => h.FilePath == e.FullPath);
        if (honeypot != null)
        {
            honeypot.IsIntact = false;
            honeypot.DeletedAt = DateTimeOffset.UtcNow;
        }
    }

    private void OnHoneypotRenamed(object sender, RenamedEventArgs e)
    {
        _logger.LogCritical("HONEYPOT: Honeypot file renamed: {Old} -> {New}", e.OldName, e.Name);
        
        // This is typical ransomware behavior - rename files before encrypting
        if (e.Name?.EndsWith(".encrypted", StringComparison.OrdinalIgnoreCase) == true ||
            e.Name?.EndsWith(".locked", StringComparison.OrdinalIgnoreCase) == true ||
            e.Name?.Contains(".ransom", StringComparison.OrdinalIgnoreCase) == true)
        {
            _ = Task.Run(async () =>
            {
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Honeypot: Ransomware Encryption Detected",
                    Evidence = $"Honeypot file '{e.OldName}' renamed to '{e.Name}' - ransomware encryption pattern confirmed.",
                    Reasoning = "File renaming with encryption extensions in the honeypot directory is definitive ransomware activity.",
                    Confidence = 0.99,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "Unknown",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["original_name"] = e.OldFullPath,
                        ["new_name"] = e.FullPath,
                        ["event_type"] = "RansomwareEncryption",
                        ["technique"] = "T1486 - Data Encrypted for Impact"
                    }
                }, CancellationToken.None);
            });
        }
    }

    private async Task VerifyHoneypotIntegrityAsync(CancellationToken cancellationToken)
    {
        foreach (var honeypot in _honeypotFiles.Where(h => h.IsIntact))
        {
            try
            {
                if (!File.Exists(honeypot.FilePath))
                {
                    honeypot.IsIntact = false;
                    honeypot.DeletedAt = DateTimeOffset.UtcNow;
                    continue;
                }

                // Check if content was modified
                var currentContent = await File.ReadAllBytesAsync(honeypot.FilePath, cancellationToken);
                using var sha256 = SHA256.Create();
                var currentHash = sha256.ComputeHash(currentContent);
                var currentHashString = Convert.ToHexString(currentHash);

                if (currentHashString != honeypot.OriginalHash)
                {
                    honeypot.IsIntact = false;
                    honeypot.ModifiedAt = DateTimeOffset.UtcNow;
                    honeypot.ModifiedHash = currentHashString;

                    _logger.LogCritical(
                        "HONEYPOT MODIFIED: {File} - Content changed (possible encryption)",
                        honeypot.FileName);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Honeypot: File Content Modified",
                        Evidence = $"Honeypot file '{honeypot.FileName}' content was modified (hash mismatch). Original: {honeypot.OriginalHash[..16]}..., Current: {currentHashString[..16]}...",
                        Reasoning = "Honeypot file integrity failure indicates file modification/encryption by ransomware or malicious process.",
                        Confidence = 0.97,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "Unknown",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["honeypot_file"] = honeypot.FilePath,
                            ["original_hash"] = honeypot.OriginalHash,
                            ["current_hash"] = currentHashString,
                            ["event_type"] = "IntegrityFailure",
                            ["technique"] = "T1486 - Data Encrypted for Impact"
                        }
                    }, cancellationToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Honeypot: Error verifying {File}", honeypot.FileName);
            }
        }
    }

    private string? GetAccessingProcess(string filePath)
    {
        // In production, this would use ETW or handle enumeration
        // to determine which process accessed the file
        // For now, return null (unknown)
        return null;
    }

    private void CleanupHoneypot()
    {
        try
        {
            _watcher?.Dispose();
            
            // Clean up honeypot files
            if (Directory.Exists(_honeypotBasePath))
            {
                foreach (var file in Directory.GetFiles(_honeypotBasePath))
                {
                    try
                    {
                        File.SetAttributes(file, FileAttributes.Normal);
                        File.Delete(file);
                    }
                    catch { }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Honeypot: Cleanup error");
        }
    }

    // Content generators for decoy files
    private byte[] CreateZipContent()
    {
        // Minimal ZIP header
        return new byte[]
        {
            0x50, 0x4B, 0x03, 0x04, 0x0A, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x50, 0x4B, 0x01, 0x02, 0x14, 0x00
        }.Concat(Encoding.UTF8.GetBytes("HONEYPOT_DECOY_DO_NOT_TOUCH")).ToArray();
    }

    private byte[] CreateOfficeContent()
    {
        // Minimal Office Open XML structure
        return Encoding.UTF8.GetBytes("PK\x03\x04" + new string('\0', 26) + 
            "[Content_Types].xml\x00" + 
            "HONEYPOT_DECOY - This file is a decoy. Access indicates malicious activity.");
    }

    private byte[] CreatePasswordContent()
    {
        return Encoding.UTF8.GetBytes(@"
# HONEYPOT DECOY FILE - DO NOT USE THESE PASSWORDS
# Any access to this file indicates malicious scanning activity

admin:P@ssw0rd123!
root:SuperSecret2025!
bank_account:FakePassword999
email:NotRealCredentials
vpn:DecoyOnlyDoNotUse

# THIS FILE IS MONITORED - UNAUTHORIZED ACCESS WILL BE DETECTED
");
    }

    private byte[] CreatePDFContent()
    {
        return Encoding.UTF8.GetBytes(@"%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj

4 0 obj
<<
/Length 50
>>
stream
BT
/F1 12 Tf
100 700 Td
(HONEYPOT DECOY FILE) Tj
ET
endstream
endobj

xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000214 00000 n 

trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
315
%%EOF");
    }

    private byte[] CreateDatabaseContent()
    {
        return Encoding.UTF8.GetBytes(@"id,username,password,email,credit_card
1,admin,HONEYPOT_DECOY,admin@honeypot.local,1234-5678-9012-3456
2,john.doe,HONEYPOT_DECOY,john@honeypot.local,9876-5432-1098-7654
3,jane.smith,HONEYPOT_DECOY,jane@honeypot.local,1111-2222-3333-4444

# THIS FILE IS A HONEYPOT - ANY ACCESS INDICATES MALICIOUS ACTIVITY");
    }

    private byte[] CreateWalletContent()
    {
        return Encoding.UTF8.GetBytes(@"{
    ""version"": 1,
    ""crypto"": {
        ""cipher"": ""aes-128-ctr"",
        ""ciphertext"": ""HONEYPOT_DECOY_DO_NOT_USE_THIS_WALLET"",
        ""cipherparams"": {
            ""iv"": ""decoyiv123456789""
        },
        ""kdf"": ""scrypt"",
        ""kdfparams"": {},
        ""mac"": ""honeypotmac""
    },
    ""id"": ""honeypot-wallet-decoy"",
    ""address"": ""0xDECOY123456789012345678901234567890""
}");
    }

    private byte[] CreateSSHKeyContent()
    {
        return Encoding.UTF8.GetBytes(@"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBVT0lQVE9QX0RFQ09ZX0tFWV9ET19OT1RfVVNFX1RISVMAAAAEaG9uZXk=
-----END OPENSSH PRIVATE KEY-----

# HONEYPOT DECOY - THIS IS NOT A REAL SSH KEY
# Any use of this key indicates unauthorized access");
    }

    private byte[] CreateRansomwareBaitContent()
    {
        return Encoding.UTF8.GetBytes(@"YOUR FILES HAVE BEEN ENCRYPTED

This is a HONEYPOT decoy file. If you are reading this, your system has been
compromised and is attempting to encrypt files.

Sentinel EDR has detected this activity.

DO NOT PAY ANY RANSOM.
Contact your IT security team immediately.");
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Honeypot: Stopping monitor...");
        CleanupHoneypot();
        await base.StopAsync(cancellationToken);
    }
}

/// <summary>
/// Represents a honeypot file.
/// </summary>
public sealed class HoneypotFile
{
    public string FilePath { get; set; } = "";
    public string FileName { get; set; } = "";
    public byte[] OriginalContent { get; set; } = Array.Empty<byte>();
    public string OriginalHash { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public string MimeType { get; set; } = "";
    public bool IsIntact { get; set; } = true;
    public DateTimeOffset? ModifiedAt { get; set; }
    public DateTimeOffset? DeletedAt { get; set; }
    public string? ModifiedHash { get; set; }
}

