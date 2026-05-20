using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// YARA rule engine integration for signature-based scanning.
/// Wraps native YARA library for .NET integration.
/// </summary>
public sealed class YaraEngine : IAsyncDisposable
{
    private readonly ILogger<YaraEngine> _logger;
    private readonly string _rulesDirectory;
    private readonly List<string> _ruleFiles = new();
    private IntPtr _yaraCompiler = IntPtr.Zero;
    private IntPtr _yaraRules = IntPtr.Zero;
    private bool _isInitialized = false;

    // YARA native constants
    private const int YARA_ERROR_SUCCESS = 0;
    private const int YARA_ERROR_INSUFFICIENT_MEMORY = 1;
    private const int YARA_ERROR_COULD_NOT_OPEN_FILE = 2;
    private const int YARA_ERROR_INVALID_FILE = 3;
    private const int YARA_ERROR_UNSUPPORTED_FILE_VERSION = 4;

    public YaraEngine(ILogger<YaraEngine> logger, string? rulesDirectory = null)
    {
        _logger = logger;
        _rulesDirectory = rulesDirectory ?? Path.Combine(AppContext.BaseDirectory, "Rules");
    }

    /// <summary>
    /// Initializes the YARA engine and compiles all rule files.
    /// </summary>
    public async Task<bool> InitializeAsync(CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogInformation("YARA Engine: Initializing...");

            // Check if YARA is available (via yara.exe for now - native binding later)
            var yaraPath = FindYaraExecutable();
            if (string.IsNullOrEmpty(yaraPath))
            {
                _logger.LogWarning("YARA Engine: YARA executable not found. Run 'sentinel bootstrap' to download YARA.");
                return false;
            }

            // Load rule files
            if (Directory.Exists(_rulesDirectory))
            {
                _ruleFiles.AddRange(Directory.GetFiles(_rulesDirectory, "*.yar"));
                _ruleFiles.AddRange(Directory.GetFiles(_rulesDirectory, "*.yara"));
                _logger.LogInformation("YARA Engine: Found {Count} rule files", _ruleFiles.Count);
            }
            else
            {
                _logger.LogWarning("YARA Engine: Rules directory not found: {Path}", _rulesDirectory);
            }

            // Create embedded rules if none exist
            if (_ruleFiles.Count == 0)
            {
                await CreateEmbeddedRulesAsync(cancellationToken);
            }

            _isInitialized = _ruleFiles.Count > 0;
            return _isInitialized;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "YARA Engine: Initialization failed");
            return false;
        }
    }

    /// <summary>
    /// Scans a file or directory with YARA rules.
    /// </summary>
    public async Task<List<YaraMatch>> ScanAsync(string path, bool recursive = false, CancellationToken cancellationToken = default)
    {
        var matches = new List<YaraMatch>();

        if (!_isInitialized)
        {
            _logger.LogWarning("YARA Engine: Not initialized");
            return matches;
        }

        try
        {
            if (File.Exists(path))
            {
                var fileMatch = await ScanFileAsync(path, cancellationToken);
                if (fileMatch != null && fileMatch.Matches.Count > 0)
                    matches.Add(fileMatch);
            }
            else if (Directory.Exists(path))
            {
                var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
                var files = Directory.GetFiles(path, "*", searchOption)
                    .Where(f => IsScannableFile(f))
                    .Take(1000); // Limit to prevent overload

                foreach (var file in files)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var fileMatch = await ScanFileAsync(file, cancellationToken);
                    if (fileMatch != null && fileMatch.Matches.Count > 0)
                        matches.Add(fileMatch);
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "YARA Engine: Scan failed for {Path}", path);
        }

        return matches;
    }

    /// <summary>
    /// Scans a single file with YARA rules.
    /// </summary>
    private async Task<YaraMatch?> ScanFileAsync(string filePath, CancellationToken cancellationToken)
    {
        var yaraPath = FindYaraExecutable();
        if (string.IsNullOrEmpty(yaraPath))
            return null;

        var matches = new List<string>();

        foreach (var ruleFile in _ruleFiles)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = yaraPath,
                    Arguments = $"-w \"{ruleFile}\" \"{filePath}\"", // -w = no warnings
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null) continue;

                var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
                var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);

                await Task.WhenAll(outputTask, errorTask);

                var output = await outputTask;
                var exitCode = process.ExitCode;

                // YARA returns 0 if rule matched, 1 if no match
                if (exitCode == 0 && !string.IsNullOrWhiteSpace(output))
                {
                    var ruleName = Path.GetFileNameWithoutExtension(ruleFile);
                    var matchDetails = ParseYaraOutput(output, filePath);
                    matches.AddRange(matchDetails.Select(m => $"{ruleName}:{m}"));
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "YARA Engine: Rule {Rule} scan error for {File}", ruleFile, filePath);
            }
        }

        if (matches.Count == 0)
            return null;

        return new YaraMatch
        {
            FilePath = filePath,
            Matches = matches
        };
    }

    /// <summary>
    /// Quick scan for suspicious locations (hunt mode).
    /// </summary>
    public async Task<List<YaraMatch>> HuntAsync(CancellationToken cancellationToken = default)
    {
        var suspiciousPaths = new[]
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup)),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup))
        };

        var allMatches = new List<YaraMatch>();

        foreach (var path in suspiciousPaths.Where(Directory.Exists))
        {
            cancellationToken.ThrowIfCancellationRequested();
            _logger.LogDebug("YARA Engine: Hunting in {Path}", path);
            
            var matches = await ScanAsync(path, recursive: false, cancellationToken);
            allMatches.AddRange(matches);
        }

        return allMatches;
    }

    private IEnumerable<string> ParseYaraOutput(string output, string filePath)
    {
        // YARA output format: rule_name file_path
        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            var parts = line.Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 1)
            {
                yield return parts[0];
            }
        }
    }

    private bool IsScannableFile(string filePath)
    {
        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        var scannableExts = new[] { ".exe", ".dll", ".sys", ".scr", ".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta", ".wsf" };
        return scannableExts.Contains(ext);
    }

    private string? FindYaraExecutable()
    {
        // Check common locations
        var possiblePaths = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "yara.exe"),
            Path.Combine(AppContext.BaseDirectory, "yara64.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "YARA", "yara.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "YARA", "yara.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "YARA", "yara.exe"),
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
            var fullPath = Path.Combine(dir, "yara.exe");
            if (File.Exists(fullPath))
                return fullPath;
        }

        return null;
    }

    private async Task CreateEmbeddedRulesAsync(CancellationToken cancellationToken)
    {
        try
        {
            Directory.CreateDirectory(_rulesDirectory);

            // Create built-in rule files
            await CreateC2FrameworksRuleAsync(cancellationToken);
            await CreateCredentialToolsRuleAsync(cancellationToken);
            await CreateProcessInjectionRuleAsync(cancellationToken);
            await CreateRansomwareRuleAsync(cancellationToken);
            await CreatePersistenceRuleAsync(cancellationToken);
            await CreateLolbinsRuleAsync(cancellationToken);
            await CreateAmsiBypassRuleAsync(cancellationToken);
            await CreateExfiltrationRuleAsync(cancellationToken);
            await CreateMalwareGenericRuleAsync(cancellationToken);

            // Reload rule files
            _ruleFiles.Clear();
            _ruleFiles.AddRange(Directory.GetFiles(_rulesDirectory, "*.yar"));
            _ruleFiles.AddRange(Directory.GetFiles(_rulesDirectory, "*.yara"));

            _logger.LogInformation("YARA Engine: Created {Count} embedded rule files", _ruleFiles.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "YARA Engine: Failed to create embedded rules");
        }
    }

    private async Task CreateC2FrameworksRuleAsync(CancellationToken cancellationToken)
    {
        var rule = @"rule CobaltStrike {
    meta:
        description = ""Detects Cobalt Strike beacon artifacts""
        author = ""Sentinel""
    strings:
        $s1 = ""%%PROCESS%%"" ascii
        $s2 = ""%%MALLEABLE%%"" ascii
        $s3 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 }
        $c1 = ""cobaltstrike"" nocase
        $c2 = ""beacon.dll"" nocase
    condition:
        any of them
}

rule Metasploit {
    meta:
        description = ""Detects Metasploit payloads""
    strings:
        $s1 = ""meterpreter"" nocase
        $s2 = ""msfvenom"" nocase
        $s3 = ""stageless"" nocase
        $s4 = ""reflective_dll"" nocase
    condition:
        any of them
}

rule Empire {
    meta:
        description = ""Detects Empire framework""
    strings:
        $s1 = ""empire"" nocase
        $s2 = ""powershell-empire"" nocase
    condition:
        any of them
}";

        await File.WriteAllTextAsync(Path.Combine(_rulesDirectory, "c2_frameworks.yar"), rule, cancellationToken);
    }

    private async Task CreateCredentialToolsRuleAsync(CancellationToken cancellationToken)
    {
        var rule = @"rule Mimikatz {
    meta:
        description = ""Detects Mimikatz credential dumping tool""
        author = ""Sentinel""
    strings:
        $s1 = ""mimikatz"" nocase wide ascii
        $s2 = ""sekurlsa::logonpasswords"" nocase wide ascii
        $s3 = ""sekurlsa::minidump"" nocase wide ascii
        $s4 = ""lsadump::sam"" nocase wide ascii
        $s5 = ""token::elevate"" nocase wide ascii
        $s6 = ""privilege::debug"" nocase wide ascii
        $s7 = ""kerberos::list"" nocase wide ascii
    condition:
        any of them
}

rule LaZagne {
    meta:
        description = ""Detects LaZagne password recovery tool""
    strings:
        $s1 = ""lazagne"" nocase
        $s2 = ""all_passwords"" nocase
    condition:
        any of them
}

rule Procdump_Lsass {
    meta:
        description = ""Detects procdump targeting LSASS""
    strings:
        $s1 = ""procdump"" nocase
        $s2 = ""lsass.exe"" nocase
        $cmd = /procdump.*lsass/i
    condition:
        any of them
}";

        await File.WriteAllTextAsync(Path.Combine(_rulesDirectory, "credential_tools.yar"), rule, cancellationToken);
    }

    private async Task CreateProcessInjectionRuleAsync(CancellationToken cancellationToken)
    {
        var rule = @"rule Shellcode_Loader {
    meta:
        description = ""Detects shellcode loaders""
        author = ""Sentinel""
    strings:
        $s1 = ""VirtualAlloc"" nocase
        $s2 = ""VirtualProtect"" nocase
        $s3 = ""WriteProcessMemory"" nocase
        $s4 = ""CreateRemoteThread"" nocase
        $s5 = ""NtCreateThreadEx"" nocase
        $s6 = ""QueueUserAPC"" nocase
        $s7 = ""SetThreadContext"" nocase
        $s8 = ""SuspendThread"" nocase
        $s9 = ""ResumeThread"" nocase
    condition:
        3 of them
}

rule Reflective_DLL {
    meta:
        description = ""Detects reflective DLL injection""
    strings:
        $s1 = ""ReflectiveLoader"" nocase
        $s2 = ""ReflectiveDll"" nocase
        $s3 = ""rDLL"" nocase
    condition:
        any of them
}

rule Process_Hollowing {
    meta:
        description = ""Detects process hollowing techniques""
    strings:
        $s1 = ""NtUnmapViewOfSection"" nocase
        $s2 = ""VirtualAllocEx"" nocase
        $s3 = ""WriteProcessMemory"" nocase
        $s4 = ""SetThreadContext"" nocase
        $s5 = ""ResumeThread"" nocase
        $s6 = ""hollow"" nocase
    condition:
        4 of them
}";

        await File.WriteAllTextAsync(Path.Combine(_rulesDirectory, "process_injection.yar"), rule, cancellationToken);
    }

    private async Task CreateRansomwareRuleAsync(CancellationToken cancellationToken)
    {
        var rule = @"rule Ransomware_Indicators {
    meta:
        description = ""Detects ransomware indicators""
        author = ""Sentinel""
    strings:
        $ext1 = "".locked"" nocase
        $ext2 = "".encrypted"" nocase
        $ext3 = "".crypto"" nocase
        $ext4 = "".crypt"" nocase
        $ext5 = "".vault"" nocase
        $note1 = ""ransom"" nocase
        $note2 = ""decrypt"" nocase
        $note3 = ""bitcoin"" nocase
        $note4 = ""btc"" nocase
        $note5 = ""wallet"" nocase
        $shadow1 = ""vssadmin delete shadows"" nocase
        $shadow2 = ""wmic shadowcopy delete"" nocase
    condition:
        any of ($ext*) or 2 of ($note*) or any of ($shadow*)
}

rule Crypto_API_Abuse {
    meta:
        description = ""Detects cryptographic API abuse patterns""
    strings:
        $s1 = ""CryptEncrypt"" nocase
        $s2 = ""CryptDecrypt"" nocase
        $s3 = ""BCryptEncrypt"" nocase
        $s4 = ""NCryptEncrypt"" nocase
        $s5 = ""CreateIoCompletionPort"" nocase
    condition:
        3 of them
}";

        await File.WriteAllTextAsync(Path.Combine(_rulesDirectory, "ransomware.yar"), rule, cancellationToken);
    }

    private async Task CreatePersistenceRuleAsync(CancellationToken cancellationToken)
    {
        var rule = @"rule Registry_Persistence {
    meta:
        description = ""Detects registry persistence mechanisms""
        author = ""Sentinel""
    strings:
        $run1 = ""\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"" nocase
        $run2 = ""\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"" nocase
        $run3 = ""\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"" nocase
        $svc1 = ""\\SYSTEM\\CurrentControlSet\\Services\\"" nocase
    condition:
        any of them
}

rule Scheduled_Task_Persistence {
    meta:
        description = ""Detects scheduled task persistence""
    strings:
        $s1 = ""schtasks"" nocase
        $s2 = ""/create"" nocase
        $s3 = ""onlogon"" nocase
        $s4 = ""onidle"" nocase
        $s5 = ""taskscheduler"" nocase
    condition:
        3 of them
}

rule WMI_Persistence {
    meta:
        description = ""Detects WMI event subscription persistence""
    strings:
        $s1 = ""__EventFilter"" nocase
        $s2 = ""__EventConsumer"" nocase
        $s3 = ""__FilterToConsumerBinding"" nocase
        $s4 = ""CommandLineEventConsumer"" nocase
    condition:
        any of them
}";

        await File.WriteAllTextAsync(Path.Combine(_rulesDirectory, "persistence.yar"), rule, cancellationToken);
    }

    private async Task CreateLolbinsRuleAsync(CancellationToken cancellationToken)
    {
        var rule = @"rule LOLBin_Usage {
    meta:
        description = ""Detects Living Off The Land binary abuse""
        author = ""Sentinel""
    strings:
        $certutil = ""certutil"" nocase
        $bitsadmin = ""bitsadmin"" nocase
        $mshta = ""mshta"" nocase
        $regsvr32 = ""regsvr32"" nocase
        $wmic = ""wmic"" nocase
        $cscript = ""cscript"" nocase
        $wscript = ""wscript"" nocase
        $rundll32 = ""rundll32"" nocase
        $cmd1 = ""/urlcache"" nocase
        $cmd2 = ""/split"" nocase
        $cmd3 = ""/transfer"" nocase
        $cmd4 = ""/download"" nocase
        $cmd5 = ""/encode"" nocase
        $cmd6 = ""/decode"" nocase
    condition:
        any of ($certutil, $bitsadmin, $mshta, $regsvr32, $wmic, $cscript, $wscript, $rundll32) and any of ($cmd*)
}

rule Encoded_PowerShell {
    meta:
        description = ""Detects encoded PowerShell commands""
    strings:
        $s1 = ""-enc"" nocase
        $s2 = ""-encodedcommand"" nocase
        $s3 = ""JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA"" // Base64 encoded PowerShell
        $s4 = ""powershell.exe"" nocase
        $s5 = ""pwsh"" nocase
        $s6 = ""FromBase64String"" nocase
    condition:
        any of them
}";

        await File.WriteAllTextAsync(Path.Combine(_rulesDirectory, "lolbins.yar"), rule, cancellationToken);
    }

    private async Task CreateAmsiBypassRuleAsync(CancellationToken cancellationToken)
    {
        var rule = @"rule AMSI_Bypass {
    meta:
        description = ""Detects AMSI bypass attempts""
        author = ""Sentinel""
    strings:
        $s1 = ""AmsiScanBuffer"" nocase
        $s2 = ""AmsiInitialize"" nocase
        $s3 = ""amsi.dll"" nocase
        $s4 = ""AmsiUtils"" nocase
        $s5 = ""amsiInitFailed"" nocase
        $bypass1 = ""Patching amsi"" nocase
        $bypass2 = ""amsi bypass"" nocase
    condition:
        any of them
}

rule ETW_Bypass {
    meta:
        description = ""Detects ETW tampering attempts""
    strings:
        $s1 = ""EtwEventWrite"" nocase
        $s2 = ""EtwEventProvider"" nocase
        $s3 = ""ntdll.dll"" nocase
        $s4 = ""etw patching"" nocase
    condition:
        any of them
}

rule Defender_Tampering {
    meta:
        description = ""Detects Windows Defender tampering""
    strings:
        $s1 = ""MpPreference"" nocase
        $s2 = ""DisableRealtimeMonitoring"" nocase
        $s3 = ""DisableBehaviorMonitoring"" nocase
        $s4 = ""DisableBlockAtFirstSeen"" nocase
        $s5 = ""ExclusionPath"" nocase
    condition:
        any of them
}";

        await File.WriteAllTextAsync(Path.Combine(_rulesDirectory, "amsi_bypass.yar"), rule, cancellationToken);
    }

    private async Task CreateExfiltrationRuleAsync(CancellationToken cancellationToken)
    {
        var rule = @"rule DNS_Exfiltration {
    meta:
        description = ""Detects DNS exfiltration patterns""
        author = ""Sentinel""
    strings:
        $s1 = ""nslookup"" nocase
        $s2 = ""Resolve-DnsName"" nocase
        $s3 = "".test.com"" nocase
        $s4 = ""base64"" nocase
        $pattern = /[a-zA-Z0-9+/]{50,}\.[a-zA-Z0-9]{2,6}/
    condition:
        any of ($s*) or #pattern > 5
}

rule Data_Staging {
    meta:
        description = ""Detects data staging for exfiltration""
    strings:
        $s1 = ""rundll32"" nocase
        $s2 = ""compress"" nocase
        $s3 = ""archive"" nocase
        $s4 = ""7z"" nocase
        $s5 = ""rar"" nocase
        $s6 = ""zip"" nocase
    condition:
        any of them
}";

        await File.WriteAllTextAsync(Path.Combine(_rulesDirectory, "exfiltration.yar"), rule, cancellationToken);
    }

    private async Task CreateMalwareGenericRuleAsync(CancellationToken cancellationToken)
    {
        var rule = @"rule Suspicious_PE {
    meta:
        description = ""Detects suspicious PE characteristics""
        author = ""Sentinel""
    strings:
        $mz = { 4D 5A } // MZ header
        $pe = { 50 45 00 00 } // PE header
        $s1 = ""LoadLibrary"" nocase
        $s2 = ""GetProcAddress"" nocase
        $s3 = ""VirtualAlloc"" nocase
        $s4 = ""InternetOpen"" nocase
        $s5 = ""WinExec"" nocase
        $s6 = ""CreateProcess"" nocase
    condition:
        ($mz at 0) and any of ($s*)
}

rule Keylogging_Indicators {
    meta:
        description = ""Detects keylogging indicators""
    strings:
        $s1 = ""GetAsyncKeyState"" nocase
        $s2 = ""SetWindowsHookEx"" nocase
        $s3 = ""WH_KEYBOARD"" nocase
        $s4 = ""keylogger"" nocase
        $s5 = ""keystroke"" nocase
    condition:
        any of them
}";

        await File.WriteAllTextAsync(Path.Combine(_rulesDirectory, "malware_generic.yar"), rule, cancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        _isInitialized = false;
        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Represents a YARA scan match result.
/// </summary>
public sealed class YaraMatch
{
    public string FilePath { get; set; } = "";
    public List<string> Matches { get; set; } = new();
}


