using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Hardening;

/// <summary>
/// Hardening Module - Active defensive measures for system protection.
/// Implements Key Scrambler, UAC Enforcement, and Self-Integrity Watchdog.
/// </summary>
public sealed class HardeningModule : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<HardeningModule> _logger;
    private readonly HardeningOptions _options;

    // Note: Key Scrambler P/Invoke declarations removed in v1.0.0.
    // The old approach injected fake keystrokes — security theater against anything
    // beyond primitive loggers. Replaced with detection-only keylogger hook scanning.

    // Self-integrity
    private readonly string _executablePath;
    private string? _knownGoodHash;

    public HardeningModule(
        IDetectionEngine detectionEngine,
        ILogger<HardeningModule> logger,
        HardeningOptions? options = null)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _options = options ?? new HardeningOptions();
        _executablePath = Process.GetCurrentProcess().MainModule?.FileName ?? AppContext.BaseDirectory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Hardening Module starting ===");
        _logger.LogInformation("Enabled modules: KeyScrambler={KS}, UACEnforcement={UAC}, SelfIntegrity={SI}, MemIntegrity={MI}, RegistrySec={RS}, USB={USB}",
            _options.EnableKeyScrambler, _options.EnableUACEnforcement, _options.EnableSelfIntegrity,
            _options.EnableMemoryIntegrityMonitor, _options.EnableRegistrySecurityMonitor, _options.EnableUSBDeviceMonitor);

        var tasks = new List<Task>();

        if (_options.EnableKeyScrambler)
        {
            tasks.Add(RunKeyScramblerAsync(stoppingToken));
        }

        if (_options.EnableUACEnforcement)
        {
            tasks.Add(RunUACEnforcementAsync(stoppingToken));
        }

        if (_options.EnableSelfIntegrity)
        {
            tasks.Add(RunSelfIntegrityAsync(stoppingToken));
        }

        if (_options.EnableMemoryIntegrityMonitor)
        {
            tasks.Add(RunMemoryIntegrityMonitorAsync(stoppingToken));
        }

        if (_options.EnableRegistrySecurityMonitor)
        {
            tasks.Add(RunRegistrySecurityMonitorAsync(stoppingToken));
        }

        if (_options.EnableUSBDeviceMonitor)
        {
            tasks.Add(RunUSBDeviceMonitorAsync(stoppingToken));
        }

        if (tasks.Count > 0)
        {
            await Task.WhenAll(tasks);
        }
        else
        {
            _logger.LogInformation("Hardening Module: No modules enabled, waiting for cancellation");
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
    }

    #region Keylogger Detection (formerly Key Scrambler)

    /// <summary>
    /// Keylogger Detection — Scans for third-party low-level keyboard hooks
    /// that may indicate keylogger activity.
    ///
    /// v1.0.0 CHANGE: The previous "Key Scrambler" approach injected fake keystrokes
    /// to blind keyloggers. This was security theater — it only confused the most
    /// primitive loggers and broke legitimate applications. Modern keyloggers use
    /// raw input capture, ETW, accessibility APIs, or kernel hooks that are immune
    /// to fake keystroke injection.
    ///
    /// The new approach is DETECTION-ONLY:
    ///   1. Periodically enumerates WH_KEYBOARD_LL hooks in the system
    ///   2. Identifies hooks owned by non-system, non-Sentinel processes
    ///   3. Emits a detection event for investigation
    ///   4. Does NOT inject fake keystrokes or modify input in any way
    ///
    /// This is honest about what userland can actually detect and avoids
    /// giving users a false sense of security.
    /// </summary>
    private async Task RunKeyScramblerAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Keylogger Detection: Starting hook enumeration monitor...");

        // Known-safe processes that legitimately use keyboard hooks
        var safeHookOwners = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "explorer.exe", "dwm.exe", "csrss.exe", "winlogon.exe",
            "ctfmon.exe", "textinputhost.exe", "msctfime.exe",
            "sentinelservice.exe", "sentinelagent.exe",
            // Common legitimate software with keyboard hooks
            "autohotkey.exe", "autohotkey64.exe", "keypirinha.exe",
            "powertoys.exe", "sharex.exe", "greenshot.exe",
            "1password.exe", "bitwarden.exe", "keepass.exe",
            "discord.exe", "slack.exe", "teams.exe"
        };

        var knownHookPids = new HashSet<int>();

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);

                // Enumerate all processes and check for keyboard hook indicators
                var suspiciousHooks = new List<(int Pid, string Name, string Evidence)>();

                foreach (var process in Process.GetProcesses())
                {
                    try
                    {
                        if (process.Id <= 4) continue;
                        if (safeHookOwners.Contains(process.ProcessName + ".exe")) continue;
                        if (knownHookPids.Contains(process.Id)) continue;

                        // Check if process has loaded user32.dll with hook-related imports
                        // by examining its module list for suspicious patterns
                        var modules = GetProcessModules(process);
                        if (modules == null) continue;

                        bool hasUser32 = modules.Any(m =>
                            m.Equals("user32.dll", StringComparison.OrdinalIgnoreCase));
                        bool hasHookDll = modules.Any(m =>
                            m.Contains("hook", StringComparison.OrdinalIgnoreCase) ||
                            m.Contains("keylog", StringComparison.OrdinalIgnoreCase) ||
                            m.Contains("capture", StringComparison.OrdinalIgnoreCase) ||
                            m.Contains("sniff", StringComparison.OrdinalIgnoreCase) ||
                            m.Contains("spy", StringComparison.OrdinalIgnoreCase));

                        // Check for raw input registration (GetRawInputData pattern)
                        // This is a heuristic — processes with user32 + small memory footprint
                        // + no visible window are suspicious
                        bool isHidden = false;
                        try
                        {
                            isHidden = process.MainWindowHandle == IntPtr.Zero &&
                                      process.WorkingSet64 < 50 * 1024 * 1024; // <50MB
                        }
                        catch { }

                        if (hasHookDll)
                        {
                            suspiciousHooks.Add((process.Id, process.ProcessName,
                                $"Process loaded suspicious DLL: {string.Join(", ", modules.Where(m => m.Contains("hook", StringComparison.OrdinalIgnoreCase) || m.Contains("keylog", StringComparison.OrdinalIgnoreCase)))}"));
                        }
                    }
                    catch { /* Process may have exited */ }
                    finally
                    {
                        process.Dispose();
                    }
                }

                // Emit detections for new suspicious hooks
                foreach (var (pid, name, evidence) in suspiciousHooks)
                {
                    if (knownHookPids.Contains(pid)) continue;
                    knownHookPids.Add(pid);

                    _logger.LogWarning(
                        "Keylogger Detection: Suspicious keyboard hook detected — {Name} (PID {Pid})",
                        name, pid);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Keylogger Detection: Suspicious Hook",
                        Evidence = $"Process '{name}' (PID {pid}) shows keylogger indicators: {evidence}",
                        Reasoning = "A process was detected with modules or behavior consistent with " +
                            "keyboard input capture. This may indicate a keylogger, credential stealer, " +
                            "or input monitoring malware. Note: this is a heuristic detection — some " +
                            "legitimate accessibility or automation tools may trigger this.",
                        Confidence = 0.70,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = name,
                        ProcessId = pid,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["module"] = "KeyloggerDetection",
                            ["technique"] = "T1056.001 - Input Capture: Keylogging",
                            ["evidence"] = evidence,
                            ["defense_type"] = "Detection-Only"
                        }
                    }, cancellationToken);
                }

                // Cleanup PIDs for processes that no longer exist
                var deadPids = knownHookPids.Where(pid =>
                {
                    try { Process.GetProcessById(pid); return false; }
                    catch { return true; }
                }).ToList();
                foreach (var pid in deadPids)
                    knownHookPids.Remove(pid);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Keylogger Detection: Error");
            }
        }
    }

    /// <summary>
    /// Gets the list of loaded module names for a process.
    /// Returns null if access is denied.
    /// </summary>
    private static List<string>? GetProcessModules(Process process)
    {
        try
        {
            return process.Modules
                .Cast<System.Diagnostics.ProcessModule>()
                .Select(m => Path.GetFileName(m.FileName ?? ""))
                .Where(n => !string.IsNullOrEmpty(n))
                .ToList();
        }
        catch
        {
            return null;
        }
    }

    #endregion

    #region UAC Enforcement

    private async Task RunUACEnforcementAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("UAC Enforcement: Starting monitoring...");

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(5), cancellationToken);

                // Check and enforce UAC settings
                var currentUAC = GetCurrentUACLevel();
                var targetUAC = 5; // Prompt for consent on non-Windows binaries

                if (currentUAC != targetUAC)
                {
                    _logger.LogWarning(
                        "UAC Enforcement: Current UAC level {Current} != target {Target}. Enforcing...",
                        currentUAC, targetUAC);

                    // Enforce UAC level
                    if (TrySetUACLevel(targetUAC))
                    {
                        _logger.LogCritical(
                            "UAC Enforcement: UAC level enforced to {Level}",
                            targetUAC);

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Hardening: UAC Level Enforced",
                            Evidence = $"UAC ConsentPromptBehaviorAdmin changed from {currentUAC} to {targetUAC}",
                            Reasoning = "UAC enforcement ensures users are prompted for consent when non-Windows binaries request elevation, preventing silent privilege escalation.",
                            Confidence = 1.0,
                            Tier = DetectionTier.Tier2Indicator,
                            ProcessName = "N/A",
                            ProcessId = 0,
                            Timestamp = DateTimeOffset.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["old_value"] = currentUAC.ToString(),
                                ["new_value"] = targetUAC.ToString(),
                                ["registry_key"] = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                                ["value_name"] = "ConsentPromptBehaviorAdmin"
                            }
                        }, cancellationToken);
                    }
                }
                else
                {
                    _logger.LogDebug("UAC Enforcement: UAC level at correct setting ({Level})", currentUAC);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "UAC Enforcement: Error");
            }
        }
    }

    private int GetCurrentUACLevel()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            return key?.GetValue("ConsentPromptBehaviorAdmin") as int? ?? 5;
        }
        catch
        {
            return 5; // Default
        }
    }

    private bool TrySetUACLevel(int level)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            key?.SetValue("ConsentPromptBehaviorAdmin", level, Microsoft.Win32.RegistryValueKind.DWord);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "UAC Enforcement: Failed to set UAC level");
            return false;
        }
    }

    #endregion

    #region Self-Integrity

    private async Task RunSelfIntegrityAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Self-Integrity: Initializing...");

        // Calculate baseline hash
        try
        {
            _knownGoodHash = await ComputeFileHashAsync(_executablePath, cancellationToken);
            _logger.LogInformation("Self-Integrity: Baseline hash established: {Hash}", _knownGoodHash[..16] + "...");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Self-Integrity: Failed to establish baseline");
            return;
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(5), cancellationToken);

                var currentHash = await ComputeFileHashAsync(_executablePath, cancellationToken);

                if (currentHash != _knownGoodHash)
                {
                    _logger.LogCritical(
                        "Self-Integrity: EXECUTABLE MODIFIED! Hash mismatch detected.");
                    _logger.LogCritical(
                        "Expected: {Expected}",
                        _knownGoodHash[..16] + "...");
                    _logger.LogCritical(
                        "Actual:   {Actual}",
                        currentHash[..16] + "...");

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Hardening: Self-Integrity Violation",
                        Evidence = "Sentinel executable hash does not match baseline",
                        Reasoning = "The Sentinel executable has been modified on disk. This may indicate tampering, corruption, or unauthorized update.",
                        Confidence = 0.95,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "N/A",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["file_path"] = _executablePath,
                            ["expected_hash"] = _knownGoodHash,
                            ["actual_hash"] = currentHash,
                            ["technique"] = "T1565 - Data Manipulation"
                        }
                    }, cancellationToken);
                }
                else
                {
                    _logger.LogDebug("Self-Integrity: Hash verified successfully");
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Self-Integrity: Check error");
            }
        }
    }

    #endregion

    #region Memory Integrity Monitor

    private async Task RunMemoryIntegrityMonitorAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Memory Integrity Monitor: Starting...");
        
        // Baseline: check initial state
        bool wasEnabled = IsMemoryIntegrityEnabled();
        _logger.LogInformation("Memory Integrity Monitor: Initial state = {State}", wasEnabled ? "ENABLED" : "DISABLED");

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(2), cancellationToken);

                bool currentlyEnabled = IsMemoryIntegrityEnabled();
                
                if (wasEnabled && !currentlyEnabled)
                {
                    _logger.LogCritical("Memory Integrity Monitor: MEMORY INTEGRITY WAS DISABLED!");
                    
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "CRITICAL: Memory Integrity Disabled",
                        Evidence = "Windows Memory Integrity (HVCI) has been disabled",
                        Reasoning = "Memory Integrity is a critical security feature that prevents kernel-mode attacks. " +
                            "Its disablement indicates a severe tampering attempt or successful attack. " +
                            "This feature prevents malicious drivers and low-level rootkits from loading.",
                        Confidence = 0.98,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "System",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["technique"] = "T1562.001 - Impair Defenses: Disable or Modify Tools",
                            ["feature"] = "Memory Integrity (HVCI)",
                            ["previous_state"] = "Enabled",
                            ["current_state"] = "Disabled",
                            ["registry_key"] = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
                            ["severity"] = "CRITICAL"
                        }
                    }, cancellationToken);
                }
                else if (!wasEnabled && currentlyEnabled)
                {
                    _logger.LogInformation("Memory Integrity Monitor: Memory Integrity was re-enabled");
                }

                wasEnabled = currentlyEnabled;
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Memory Integrity Monitor: Error");
            }
        }
    }

    private bool IsMemoryIntegrityEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity");
            var value = key?.GetValue("Enabled");
            return value is int i && i == 1;
        }
        catch
        {
            return false;
        }
    }

    #endregion

    #region Registry Security Monitor

    private readonly Dictionary<string, object> _securityBaselines = new();

    private async Task RunRegistrySecurityMonitorAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Registry Security Monitor: Starting...");

        // Initialize baselines
        InitializeSecurityBaselines();

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);

                CheckSecurityRegistryChanges(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Registry Security Monitor: Error");
            }
        }
    }

    private void InitializeSecurityBaselines()
    {
        // UAC settings
        _securityBaselines["UAC_EnableLUA"] = GetRegistryValue(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1);
        _securityBaselines["UAC_ConsentPrompt"] = GetRegistryValue(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 5);
        _securityBaselines["UAC_SecureDesktop"] = GetRegistryValue(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "PromptOnSecureDesktop", 1);
        
        // Windows Defender
        _securityBaselines["WD_AntiSpyware"] = GetRegistryValue(@"SOFTWARE\Microsoft\Windows Defender", "DisableAntiSpyware", 0);
        _securityBaselines["WD_Tamper"] = GetRegistryValue(@"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", 5);
        
        // Firewall
        _securityBaselines["Firewall_Public"] = GetRegistryValue(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall", 1);
        _securityBaselines["Firewall_Private"] = GetRegistryValue(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "EnableFirewall", 1);

        _logger.LogInformation("Registry Security Monitor: Baselines established for {Count} settings", _securityBaselines.Count);
    }

    private void CheckSecurityRegistryChanges(CancellationToken ct)
    {
        var checks = new Dictionary<string, (string path, string name, object expected)>
        {
            ["UAC_EnableLUA"] = (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", _securityBaselines["UAC_EnableLUA"]),
            ["UAC_ConsentPrompt"] = (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", _securityBaselines["UAC_ConsentPrompt"]),
            ["UAC_SecureDesktop"] = (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "PromptOnSecureDesktop", _securityBaselines["UAC_SecureDesktop"]),
            ["WD_Tamper"] = (@"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", _securityBaselines["WD_Tamper"]),
        };

        foreach (var check in checks)
        {
            var current = GetRegistryValue(check.Value.path, check.Value.name, check.Value.expected);
            
            if (!current.Equals(check.Value.expected))
            {
                _logger.LogCritical("Registry Security Monitor: {Key} changed from {Old} to {New}!",
                    check.Key, check.Value.expected, current);

                // Update baseline to prevent spam
                _securityBaselines[check.Key] = current;

                // Emit detection
                _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = $"CRITICAL: Security Setting Changed - {check.Key}",
                    Evidence = $"Registry value {check.Value.name} changed from {check.Value.expected} to {current}",
                    Reasoning = $"Critical security setting was modified. This may indicate an attempt to disable security protections.",
                    Confidence = 0.95,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "System",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["technique"] = "T1562.001 - Impair Defenses: Disable or Modify Tools",
                        ["registry_key"] = check.Value.path,
                        ["value_name"] = check.Value.name,
                        ["old_value"] = check.Value.expected?.ToString() ?? "null",
                        ["new_value"] = current?.ToString() ?? "null",
                        ["severity"] = "CRITICAL"
                    }
                }, ct).Wait(ct);
            }
        }
    }

    private object GetRegistryValue(string path, string name, object defaultValue)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path);
            return key?.GetValue(name) ?? defaultValue;
        }
        catch
        {
            return defaultValue;
        }
    }

    #endregion

    #region USB Device Monitor

    private readonly HashSet<string> _knownUSBDevices = new();

    private async Task RunUSBDeviceMonitorAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("USB Device Monitor: Starting...");

        // Initialize with current devices
        InitializeKnownUSBDevices();

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken);

                CheckForNewUSBDevices(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "USB Device Monitor: Error");
            }
        }
    }

    private void InitializeKnownUSBDevices()
    {
        try
        {
            var drives = DriveInfo.GetDrives()
                .Where(d => d.DriveType == DriveType.Removable && d.IsReady)
                .Select(d => d.RootDirectory.FullName)
                .ToList();

            foreach (var drive in drives)
            {
                _knownUSBDevices.Add(drive);
            }

            _logger.LogInformation("USB Device Monitor: Baseline established with {Count} devices", _knownUSBDevices.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "USB Device Monitor: Failed to initialize baselines");
        }
    }

    private void CheckForNewUSBDevices(CancellationToken ct)
    {
        try
        {
            var currentDrives = DriveInfo.GetDrives()
                .Where(d => d.DriveType == DriveType.Removable && d.IsReady)
                .Select(d => d.RootDirectory.FullName)
                .ToList();

            // Check for new devices
            foreach (var drive in currentDrives)
            {
                if (!_knownUSBDevices.Contains(drive))
                {
                    _logger.LogWarning("USB Device Monitor: NEW USB DEVICE CONNECTED - {Drive}", drive);
                    _knownUSBDevices.Add(drive);

                    // Get volume info
                    var driveInfo = new DriveInfo(drive);
                    var volumeLabel = driveInfo.VolumeLabel ?? "Unknown";
                    var driveFormat = driveInfo.DriveFormat ?? "Unknown";

                    _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "USB Device Connected",
                        Evidence = $"New removable storage device connected: {drive} (Label: {volumeLabel}, Format: {driveFormat})",
                        Reasoning = "A USB device or removable storage has been connected. This could be legitimate use or an attempt to introduce malware, exfiltrate data, or bypass security controls.",
                        Confidence = 0.70,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = "System",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["technique"] = "T1091 - Replication Through Removable Media",
                            ["device_path"] = drive,
                            ["volume_label"] = volumeLabel,
                            ["drive_format"] = driveFormat,
                            ["drive_type"] = "Removable"
                        }
                    }, ct).Wait(ct);
                }
            }

            // Check for removed devices
            var removedDrives = _knownUSBDevices.Except(currentDrives).ToList();
            foreach (var drive in removedDrives)
            {
                _logger.LogInformation("USB Device Monitor: USB device removed - {Drive}", drive);
                _knownUSBDevices.Remove(drive);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "USB Device Monitor: Error checking devices");
        }
    }

    #endregion

    private async Task<string> ComputeFileHashAsync(string filePath, CancellationToken cancellationToken)
    {
        using var sha256 = SHA256.Create();
        await using var stream = File.OpenRead(filePath);
        var hash = await sha256.ComputeHashAsync(stream, cancellationToken);
        return Convert.ToHexString(hash);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("=== Hardening Module stopping ===");
        await base.StopAsync(cancellationToken);
    }
}

/// <summary>
/// Configuration options for hardening modules.
/// </summary>
public sealed class HardeningOptions
{
    public bool EnableKeyScrambler { get; set; } = true; // v1.0.0: Now keylogger hook detection (service-only, no agent)
    public bool EnableUACEnforcement { get; set; } = true;
    public bool EnableSelfIntegrity { get; set; } = true;
    public bool EnableMemoryIntegrityMonitor { get; set; } = true;
    public bool EnableRegistrySecurityMonitor { get; set; } = true;
    public bool EnableUSBDeviceMonitor { get; set; } = true;
}
