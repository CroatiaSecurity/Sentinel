using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// YARA-X (modern YARA) integration for signature-based scanning.
/// YARA-X is a ground-up rewrite of YARA in Rust with significantly better performance.
/// Ported from HydraDragonAntivirus's YARA-X integration pattern.
/// </summary>
public sealed class YaraXEngine : IAsyncDisposable
{
    private readonly ILogger<YaraXEngine> _logger;
    private readonly string _rulesDirectory;
    private readonly List<string> _ruleFiles = new();
    private string? _yaraXPath;
    private bool _isInitialized;

    public YaraXEngine(ILogger<YaraXEngine> logger, string? rulesDirectory = null)
    {
        _logger = logger;
        _rulesDirectory = rulesDirectory ?? Path.Combine(AppContext.BaseDirectory, "YaraRules");
    }

    /// <summary>
    /// Initialize the YARA-X engine
    /// </summary>
    public async Task<bool> InitializeAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("YARA-X Engine: Initializing...");

            // Find YARA-X executable
            _yaraXPath = FindYaraXExecutable();
            if (string.IsNullOrEmpty(_yaraXPath))
            {
                _logger.LogWarning("YARA-X: yara-x.exe not found. Install YARA-X to enable scanning.");
                _logger.LogInformation("Download from: https://github.com/VirusTotal/yara-x/releases");
                return false;
            }

            // Verify YARA-X is working
            var versionResult = await RunYaraXAsync("--version", cancellationToken);
            if (versionResult.ExitCode == 0)
            {
                _logger.LogInformation("YARA-X initialized: {Version}", versionResult.Output.Trim());
            }
            else
            {
                _logger.LogWarning("YARA-X version check failed");
                return false;
            }

            // Ensure rules directory exists
            if (!Directory.Exists(_rulesDirectory))
            {
                Directory.CreateDirectory(_rulesDirectory);
                _logger.LogInformation("YARA-X: Created rules directory: {Path}", _rulesDirectory);
            }

            // Load rule files
            _ruleFiles.AddRange(Directory.GetFiles(_rulesDirectory, "*.yar", SearchOption.AllDirectories));
            _ruleFiles.AddRange(Directory.GetFiles(_rulesDirectory, "*.yara", SearchOption.AllDirectories));
            _ruleFiles.AddRange(Directory.GetFiles(_rulesDirectory, "*.yr", SearchOption.AllDirectories));

            // If no rules exist, create built-in rules
            if (_ruleFiles.Count == 0)
            {
                _logger.LogInformation("YARA-X: No rules found, creating built-in rules...");
                await CreateEmbeddedRulesAsync(cancellationToken);
            }

            _isInitialized = _ruleFiles.Count > 0;
            
            if (_isInitialized)
            {
                _logger.LogInformation("YARA-X: Loaded {Count} rule files", _ruleFiles.Count);
            }

            return _isInitialized;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "YARA-X initialization failed");
            return false;
        }
    }

    /// <summary>
    /// Scan a single file with all YARA rules
    /// </summary>
    public async Task<YaraXScanResult> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
        if (!_isInitialized || _ruleFiles.Count == 0)
        {
            return new YaraXScanResult
            {
                FilePath = filePath,
                IsError = true,
                ErrorMessage = "YARA-X not initialized or no rules loaded"
            };
        }

        if (!File.Exists(filePath))
        {
            return new YaraXScanResult
            {
                FilePath = filePath,
                IsError = true,
                ErrorMessage = "File not found"
            };
        }

        var result = new YaraXScanResult { FilePath = filePath };

        try
        {
            foreach (var ruleFile in _ruleFiles)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var scanResult = await ScanWithRuleAsync(filePath, ruleFile, cancellationToken);
                
                if (scanResult.Matches.Count > 0)
                {
                    result.Matches.AddRange(scanResult.Matches);
                }

                if (scanResult.IsError)
                {
                    _logger.LogDebug("YARA-X rule error in {Rule}: {Error}", ruleFile, scanResult.ErrorMessage);
                }
            }

            result.IsMatch = result.Matches.Count > 0;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "YARA-X scan failed for {File}", filePath);
            result.IsError = true;
            result.ErrorMessage = ex.Message;
        }

        return result;
    }

    /// <summary>
    /// Scan a directory recursively
    /// </summary>
    public async Task<List<YaraXScanResult>> ScanDirectoryAsync(string directoryPath, bool recursive = true, CancellationToken cancellationToken = default)
    {
        var results = new List<YaraXScanResult>();

        if (!_isInitialized)
        {
            _logger.LogWarning("YARA-X not initialized");
            return results;
        }

        if (!Directory.Exists(directoryPath))
        {
            _logger.LogWarning("Directory not found: {Path}", directoryPath);
            return results;
        }

        try
        {
            // Get all files to scan
            var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            var files = Directory.GetFiles(directoryPath, "*", searchOption)
                .Where(f => IsScannableFile(f))
                .Take(1000); // Limit to prevent overload

            foreach (var file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                var result = await ScanFileAsync(file, cancellationToken);
                if (result.IsMatch || result.IsError)
                {
                    results.Add(result);
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "YARA-X directory scan failed for {Path}", directoryPath);
        }

        return results;
    }

    /// <summary>
    /// Hunt for malware in suspicious locations
    /// </summary>
    public async Task<List<YaraXScanResult>> HuntAsync(CancellationToken cancellationToken = default)
    {
        var suspiciousPaths = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks")
        };

        var allResults = new List<YaraXScanResult>();

        foreach (var path in suspiciousPaths.Where(Directory.Exists))
        {
            cancellationToken.ThrowIfCancellationRequested();
            _logger.LogDebug("YARA-X: Hunting in {Path}", path);
            
            var results = await ScanDirectoryAsync(path, recursive: false, cancellationToken);
            allResults.AddRange(results);
        }

        return allResults;
    }

    /// <summary>
    /// Compile a YARA rule (validate syntax)
    /// </summary>
    public async Task<(bool Success, string? Error)> CompileRuleAsync(string ruleFilePath, CancellationToken cancellationToken = default)
    {
        if (!_isInitialized)
        {
            return (false, "YARA-X not initialized");
        }

        try
        {
            // YARA-X doesn't have a separate compile command like YARA 4.x
            // Just try to scan with it and see if it parses
            var result = await RunYaraXAsync($"\"{ruleFilePath}\" --help", cancellationToken);
            
            // If it doesn't error on the rule file, it's valid
            if (result.ExitCode == 0 || !result.Error.Contains("error"))
            {
                return (true, null);
            }
            
            return (false, result.Error);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    private async Task<YaraXScanResult> ScanWithRuleAsync(string filePath, string ruleFile, CancellationToken cancellationToken)
    {
        try
        {
            // YARA-X syntax: yr scan [OPTIONS] <RULES_FILE> <TARGET>
            var args = $"scan \"{ruleFile}\" \"{filePath}\"";
            var result = await RunYaraXAsync(args, cancellationToken);

            var scanResult = new YaraXScanResult { FilePath = filePath };

            if (result.ExitCode == 0 && !string.IsNullOrWhiteSpace(result.Output))
            {
                // Parse YARA-X output format
                var matches = ParseYaraXOutput(result.Output, filePath);
                scanResult.Matches.AddRange(matches);
                scanResult.IsMatch = matches.Count > 0;
            }
            else if (result.ExitCode != 0 && !string.IsNullOrWhiteSpace(result.Error))
            {
                scanResult.IsError = true;
                scanResult.ErrorMessage = result.Error;
            }

            return scanResult;
        }
        catch (Exception ex)
        {
            return new YaraXScanResult
            {
                FilePath = filePath,
                IsError = true,
                ErrorMessage = ex.Message
            };
        }
    }

    private List<YaraXMatch> ParseYaraXOutput(string output, string filePath)
    {
        var matches = new List<YaraXMatch>();
        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed)) continue;

            // YARA-X output format: rule_name [metadata] file_path
            // Example: "Malware_Rule [author="test"] C:\path\file.exe"
            var parts = trimmed.Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 1)
            {
                var ruleName = parts[0];
                var match = new YaraXMatch
                {
                    RuleName = ruleName,
                    FilePath = filePath
                };

                // Extract metadata if present
                if (parts.Length > 1 && parts[1].Contains('[') && parts[1].Contains(']'))
                {
                    var metaStart = parts[1].IndexOf('[');
                    var metaEnd = parts[1].IndexOf(']');
                    if (metaEnd > metaStart)
                    {
                        var metaStr = parts[1].Substring(metaStart + 1, metaEnd - metaStart - 1);
                        // Parse key=value pairs
                        var pairs = metaStr.Split(',');
                        foreach (var pair in pairs)
                        {
                            var kv = pair.Split('=');
                            if (kv.Length == 2)
                            {
                                match.Metadata[kv[0].Trim()] = kv[1].Trim().Trim('"', '\'');
                            }
                        }
                    }
                }

                matches.Add(match);
            }
        }

        return matches;
    }

    private async Task<YaraXRunResult> RunYaraXAsync(string arguments, CancellationToken cancellationToken)
    {
        var tcs = new TaskCompletionSource<YaraXRunResult>();

        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = _yaraXPath,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        var outputBuilder = new StringBuilder();
        var errorBuilder = new StringBuilder();

        process.OutputDataReceived += (sender, e) =>
        {
            if (e.Data != null) outputBuilder.AppendLine(e.Data);
        };

        process.ErrorDataReceived += (sender, e) =>
        {
            if (e.Data != null) errorBuilder.AppendLine(e.Data);
        };

        process.EnableRaisingEvents = true;
        process.Exited += (sender, e) =>
        {
            tcs.TrySetResult(new YaraXRunResult
            {
                ExitCode = process.ExitCode,
                Output = outputBuilder.ToString(),
                Error = errorBuilder.ToString()
            });
        };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        // Set up cancellation
        using (cancellationToken.Register(() =>
        {
            try { process.Kill(); } catch { }
            tcs.TrySetCanceled();
        }))
        {
            return await tcs.Task;
        }
    }

    private async Task CreateEmbeddedRulesAsync(CancellationToken cancellationToken)
    {
        try
        {
            // Create comprehensive built-in rules based on Hydra's approach
            await CreateMalwareGenericRules(cancellationToken);
            await CreateRansomwareRules(cancellationToken);
            await CreateLolbinRules(cancellationToken);
            await CreateProcessInjectionRules(cancellationToken);
            await CreateCredentialDumpingRules(cancellationToken);
            await CreatePackerRules(cancellationToken);

            // Reload rule files
            _ruleFiles.Clear();
            _ruleFiles.AddRange(Directory.GetFiles(_rulesDirectory, "*.yar", SearchOption.AllDirectories));
            _ruleFiles.AddRange(Directory.GetFiles(_rulesDirectory, "*.yara", SearchOption.AllDirectories));

            _logger.LogInformation("YARA-X: Created {Count} embedded rule files", _ruleFiles.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "YARA-X: Failed to create embedded rules");
        }
    }

    private async Task CreateMalwareGenericRules(CancellationToken cancellationToken)
    {
        var rule = @"rule Suspicious_PE_Headers {
    meta:
        description = ""Detects suspicious PE characteristics""
        author = ""Sentinel YARA-X""
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
        $dos_msg = ""This program cannot be run in DOS mode""
    condition:
        $mz at 0 and $pe at uint32(0x3C) and not $dos_msg
}

rule High_Entropy_PE {
    meta:
        description = ""Detects high entropy (likely packed/encrypted) PE files""
    condition:
        uint16(0) == 0x5A4D and
        math.entropy(0, filesize) > 7.0
}

rule Suspected_Shellcode_Loader {
    meta:
        description = ""Detects shellcode loading patterns""
    strings:
        $alloc1 = ""VirtualAlloc"" ascii wide nocase
        $alloc2 = ""VirtualAllocEx"" ascii wide nocase
        $write = ""WriteProcessMemory"" ascii wide nocase
        $thread = ""CreateRemoteThread"" ascii wide nocase
        $apc = ""QueueUserAPC"" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        2 of them
}";

        await File.WriteAllTextAsync(
            Path.Combine(_rulesDirectory, "malware_generic.yar"), 
            rule, 
            cancellationToken);
    }

    private async Task CreateRansomwareRules(CancellationToken cancellationToken)
    {
        var rule = @"rule Ransomware_Indicators {
    meta:
        description = ""Detects ransomware indicators""
    strings:
        $ext1 = "".locked"" nocase
        $ext2 = "".encrypted"" nocase
        $ext3 = "".crypto"" nocase
        $note1 = ""ransom"" nocase
        $note2 = ""decrypt"" nocase
        $note3 = ""bitcoin"" nocase
        $btc_addr = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
        $shadow1 = ""vssadmin delete shadows"" nocase
        $shadow2 = ""wmic shadowcopy delete"" nocase
    condition:
        any of ($ext*) or 2 of ($note*) or $btc_addr or any of ($shadow*)
}

rule Crypto_Ransomware_API {
    meta:
        description = ""Detects cryptographic API abuse patterns""
    strings:
        $crypt1 = ""CryptEncrypt"" ascii wide nocase
        $crypt2 = ""CryptDecrypt"" ascii wide nocase
        $bcrypt1 = ""BCryptEncrypt"" ascii wide nocase
        $bcrypt2 = ""BCryptDecrypt"" ascii wide nocase
        $ncrypt1 = ""NCryptEncrypt"" ascii wide nocase
        $gen_key = ""CryptGenKey"" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        3 of them
}";

        await File.WriteAllTextAsync(
            Path.Combine(_rulesDirectory, "ransomware.yar"), 
            rule, 
            cancellationToken);
    }

    private async Task CreateLolbinRules(CancellationToken cancellationToken)
    {
        var rule = @"rule LOLBin_Execute_Pattern {
    meta:
        description = ""Detects LOLBin abuse patterns""
    strings:
        $certutil_dl = ""certutil"" nocase ascii wide
        $certutil_url = ""-urlcache"" nocase ascii wide
        $bits_dl = ""bitsadmin"" nocase ascii wide
        $bits_transfer = ""/transfer"" nocase ascii wide
        $mshta_http = ""mshta"" nocase ascii wide
        $regsvr_scrobj = ""scrobj.dll"" nocase ascii wide
        $wmic_process = ""wmic process call create"" nocase ascii wide
    condition:
        any of them
}

rule Encoded_Command_Execution {
    meta:
        description = ""Detects encoded command execution patterns""
    strings:
        $enc_ps = /-[eE][nN][cC][oO][dD][eE][dD]?[cC]?[oO]?[mM]?[mM]?[aA]?[nN]?[dD]?/
        $b64_iex = ""IEX([System.Convert]::FromBase64String"" nocase
        $b64_2 = ""FromBase64String"" nocase
    condition:
        any of them
}";

        await File.WriteAllTextAsync(
            Path.Combine(_rulesDirectory, "lolbins.yar"), 
            rule, 
            cancellationToken);
    }

    private async Task CreateProcessInjectionRules(CancellationToken cancellationToken)
    {
        var rule = @"rule Process_Injection_Techniques {
    meta:
        description = ""Detects process injection API patterns""
    strings:
        $inject1 = ""VirtualAllocEx"" ascii wide nocase
        $inject2 = ""WriteProcessMemory"" ascii wide nocase
        $inject3 = ""CreateRemoteThread"" ascii wide nocase
        $inject4 = ""NtCreateThreadEx"" ascii wide nocase
        $inject5 = ""QueueUserAPC"" ascii wide nocase
        $inject6 = ""SetThreadContext"" ascii wide nocase
        $hollow1 = ""NtUnmapViewOfSection"" ascii wide nocase
        $hollow2 = ""ZwUnmapViewOfSection"" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        3 of them
}

rule Reflective_DLL_Injection {
    meta:
        description = ""Detects reflective DLL injection indicators""
    strings:
        $reflective = ""ReflectiveLoader"" ascii wide nocase
        $reflective2 = ""ReflectiveDll"" ascii wide nocase
        $r_dll = ""rDLL"" ascii wide nocase
        $manual_map = ""ManualMap"" ascii wide nocase
    condition:
        any of them
}";

        await File.WriteAllTextAsync(
            Path.Combine(_rulesDirectory, "process_injection.yar"), 
            rule, 
            cancellationToken);
    }

    private async Task CreateCredentialDumpingRules(CancellationToken cancellationToken)
    {
        var rule = @"rule LSASS_Credential_Dumping {
    meta:
        description = ""Detects LSASS credential dumping indicators""
        reference = ""T1003.001""
    strings:
        $lsass1 = ""lsass.exe"" ascii wide nocase
        $lsass2 = ""lsass.dmp"" ascii wide nocase
        $sekurlsa = ""sekurlsa"" ascii wide nocase
        $logonpass = ""logonpasswords"" ascii wide nocase
        $wdigest = ""wdigest"" ascii wide nocase
        $minidump = ""minidump"" ascii wide nocase
        $procdump = ""procdump -ma"" ascii wide nocase
        $comsvcs = ""comsvcs.dll,MiniDump"" ascii wide nocase
    condition:
        any of them
}

rule Mimikatz_Indicators {
    meta:
        description = ""Detects Mimikatz artifacts""
    strings:
        $mimi1 = ""mimikatz"" ascii wide nocase
        $mimi2 = ""sekurlsa::logonpasswords"" ascii wide nocase
        $mimi3 = ""sekurlsa::minidump"" ascii wide nocase
        $mimi4 = ""lsadump::sam"" ascii wide nocase
        $mimi5 = ""token::elevate"" ascii wide nocase
        $mimi6 = ""privilege::debug"" ascii wide nocase
        $mimi7 = ""kerberos::list"" ascii wide nocase
    condition:
        any of them
}";

        await File.WriteAllTextAsync(
            Path.Combine(_rulesDirectory, "credential_dumping.yar"), 
            rule, 
            cancellationToken);
    }

    private async Task CreatePackerRules(CancellationToken cancellationToken)
    {
        var rule = @"rule UPX_Packed {
    meta:
        description = ""Detects UPX packed executables""
    strings:
        $upx0 = ""UPX0"" ascii
        $upx1 = ""UPX1"" ascii
        $upx2 = ""UPX2"" ascii
        $upx_sig = { 55 50 58 21 }
    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule Common_Packers {
    meta:
        description = ""Detects common executable packers""
    strings:
        $aspack = ""aspack"" ascii nocase
        $petite = ""petite"" ascii nocase
        $pec = ""PEC2"" ascii
        $pecompact = ""PECompact"" ascii nocase
        $themida = ""Themida"" ascii nocase
        $vmprotect = ""VMProtect"" ascii nocase
        $enigma = ""Enigma"" ascii nocase
        $armadillo = ""Armadillo"" ascii nocase
        $mew = ""MEW"" ascii
        $nspack = ""NSPack"" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        any of them
}";

        await File.WriteAllTextAsync(
            Path.Combine(_rulesDirectory, "packers.yar"), 
            rule, 
            cancellationToken);
    }

    private string? FindYaraXExecutable()
    {
        // Check common installation paths
        var possiblePaths = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "yara-x.exe"),
            Path.Combine(AppContext.BaseDirectory, "yr.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "yara-x", "yara-x.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "yara-x", "yara-x.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "yara-x", "yara-x.exe"),
            Path.Combine(@"C:\Program Files\yara-x", "yara-x.exe"),
            Path.Combine(@"C:\Program Files (x86)\yara-x", "yara-x.exe"),
        };

        foreach (var path in possiblePaths)
        {
            if (File.Exists(path))
                return path;
        }

        // Check PATH
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathEnv.Split(';'))
        {
            var fullPath = Path.Combine(dir, "yara-x.exe");
            if (File.Exists(fullPath))
                return fullPath;
            
            fullPath = Path.Combine(dir, "yr.exe");
            if (File.Exists(fullPath))
                return fullPath;
        }

        return null;
    }

    private bool IsScannableFile(string filePath)
    {
        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        var scannableExts = new[] { 
            ".exe", ".dll", ".sys", ".scr", ".drv",
            ".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta", ".wsf",
            ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
            ".pdf", ".zip", ".rar", ".7z"
        };
        return scannableExts.Contains(ext);
    }

    public ValueTask DisposeAsync()
    {
        _isInitialized = false;
        return ValueTask.CompletedTask;
    }

    private class YaraXRunResult
    {
        public int ExitCode { get; set; }
        public string Output { get; set; } = "";
        public string Error { get; set; } = "";
    }
}

/// <summary>
/// YARA-X scan result
/// </summary>
public sealed class YaraXScanResult
{
    public string FilePath { get; set; } = "";
    public bool IsMatch { get; set; }
    public List<YaraXMatch> Matches { get; set; } = new();
    public bool IsError { get; set; }
    public string? ErrorMessage { get; set; }
}

/// <summary>
/// Individual YARA rule match
/// </summary>
public sealed class YaraXMatch
{
    public string RuleName { get; set; } = "";
    public string FilePath { get; set; } = "";
    public Dictionary<string, string> Metadata { get; set; } = new();
}


