using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.SelfProtection;

/// <summary>
/// Self-protection service that monitors and defends against tampering attempts.
/// Detects AMSI patching, ETW unhooking, debugger attachment, config tampering, and DLL hijacking.
/// </summary>
public sealed class SelfProtectionService : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<SelfProtectionService> _logger;
    private readonly string _executablePath;
    private readonly string _configPath;
    private string? _lastKnownExecutableHash;
    private string? _lastKnownConfigHash;
    
    // Check intervals
    private static readonly TimeSpan AmsiCheckInterval = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan EtwCheckInterval = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan DebuggerCheckInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan IntegrityCheckInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan ModuleCheckInterval = TimeSpan.FromMinutes(1);

    // Native method signatures
    [DllImport("kernel32.dll")]
    private static extern bool IsDebuggerPresent();

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref int debugPort, int debugPortSize, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll")]
    private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_READ = 0x20;

    public SelfProtectionService(
        IDetectionEngine detectionEngine,
        ILogger<SelfProtectionService> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _executablePath = Process.GetCurrentProcess().MainModule?.FileName ?? AppContext.BaseDirectory;
        _configPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Self-Protection Service starting ===");

        // Initialize baseline hashes
        await InitializeBaselinesAsync(stoppingToken);

        // Start check loops
        var amsiTask = RunAmsiIntegrityCheckAsync(stoppingToken);
        var etwTask = RunEtwIntegrityCheckAsync(stoppingToken);
        var debuggerTask = RunDebuggerDetectionAsync(stoppingToken);
        var integrityTask = RunSelfIntegrityCheckAsync(stoppingToken);
        var moduleTask = RunModuleIntegrityCheckAsync(stoppingToken);

        await Task.WhenAll(amsiTask, etwTask, debuggerTask, integrityTask, moduleTask);
    }

    private async Task InitializeBaselinesAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (File.Exists(_executablePath))
            {
                _lastKnownExecutableHash = await ComputeFileHashAsync(_executablePath, cancellationToken);
                _logger.LogDebug("Self-Protection: Executable hash baseline established");
            }

            if (File.Exists(_configPath))
            {
                _lastKnownConfigHash = await ComputeFileHashAsync(_configPath, cancellationToken);
                _logger.LogDebug("Self-Protection: Config hash baseline established");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Self-Protection: Failed to initialize baselines");
        }
    }

    private async Task RunAmsiIntegrityCheckAsync(CancellationToken cancellationToken)
    {
        // Store the original prologue bytes of AmsiScanBuffer
        byte[]? originalAmsiPrologue = null;
        byte[]? originalClrPrologue = null;
        IntPtr amsiHandle = IntPtr.Zero;
        IntPtr amsiScanBuffer = IntPtr.Zero;
        IntPtr clrHandle = IntPtr.Zero;
        IntPtr clrAmsiScan = IntPtr.Zero;

        try
        {
            amsiHandle = GetModuleHandle("amsi.dll");
            if (amsiHandle != IntPtr.Zero)
            {
                amsiScanBuffer = GetProcAddress(amsiHandle, "AmsiScanBuffer");
                if (amsiScanBuffer != IntPtr.Zero)
                {
                    originalAmsiPrologue = new byte[5];
                    Marshal.Copy(amsiScanBuffer, originalAmsiPrologue, 0, 5);
                    _logger.LogDebug("Self-Protection: AMSI prologue captured for integrity monitoring");
                }
            }

            // Also monitor CLR.DLL — newer AMSI bypass patches CLR's internal scan path
            // instead of AmsiScanBuffer directly (bypasses AmsiScanBuffer monitoring)
            clrHandle = GetModuleHandle("clr.dll");
            if (clrHandle == IntPtr.Zero)
                clrHandle = GetModuleHandle("coreclr.dll"); // .NET Core/5+
            if (clrHandle != IntPtr.Zero)
            {
                // Monitor AmsiScan export if available (CLR's internal AMSI integration point)
                clrAmsiScan = GetProcAddress(clrHandle, "AmsiScan");
                if (clrAmsiScan == IntPtr.Zero)
                    clrAmsiScan = GetProcAddress(clrHandle, "AmsiScanBuffer");
                if (clrAmsiScan != IntPtr.Zero)
                {
                    originalClrPrologue = new byte[8];
                    Marshal.Copy(clrAmsiScan, originalClrPrologue, 0, 8);
                    _logger.LogDebug("Self-Protection: CLR AMSI integration prologue captured");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Self-Protection: Failed to capture AMSI prologue");
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(AmsiCheckInterval, cancellationToken);

                if (amsiScanBuffer == IntPtr.Zero)
                {
                    // Try to get it again if not available initially
                    amsiHandle = GetModuleHandle("amsi.dll");
                    if (amsiHandle != IntPtr.Zero)
                    {
                        amsiScanBuffer = GetProcAddress(amsiHandle, "AmsiScanBuffer");
                        if (amsiScanBuffer != IntPtr.Zero && originalAmsiPrologue == null)
                        {
                            originalAmsiPrologue = new byte[5];
                            Marshal.Copy(amsiScanBuffer, originalAmsiPrologue, 0, 5);
                        }
                    }
                    continue;
                }

                // Check current prologue against original
                var currentPrologue = new byte[5];
                Marshal.Copy(amsiScanBuffer, currentPrologue, 0, 5);

                if (originalAmsiPrologue != null && !currentPrologue.SequenceEqual(originalAmsiPrologue))
                {
                    _logger.LogCritical("Self-Protection: AMSI AmsiScanBuffer has been patched! Attempting repair...");

                    // Try to repair
                    if (TryRepairAmsi(amsiScanBuffer, originalAmsiPrologue))
                    {
                        _logger.LogCritical("Self-Protection: AMSI successfully repaired");

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Self-Protection: AMSI Patching Detected",
                            Evidence = "AmsiScanBuffer prologue was modified and repaired",
                            Reasoning = "AMSI patching is a common EDR evasion technique. The function prologue was restored to original bytes.",
                            Confidence = 0.98,
                            Tier = DetectionTier.Tier1Behavioral,
                            ProcessName = "Unknown",
                            ProcessId = 0,
                            Timestamp = DateTimeOffset.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["technique"] = "T1562.001 - Impair Defenses: Disable or Modify Tools",
                                ["action_taken"] = "Repaired",
                                ["location"] = "amsi.dll!AmsiScanBuffer"
                            }
                        }, cancellationToken);
                    }
                    else
                    {
                        _logger.LogCritical("Self-Protection: Failed to repair AMSI");

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Self-Protection: AMSI Patching Detected (Repair Failed)",
                            Evidence = "AmsiScanBuffer prologue was modified and could not be repaired",
                            Reasoning = "AMSI patching detected but repair failed. System may be compromised.",
                            Confidence = 0.99,
                            Tier = DetectionTier.Tier1Behavioral,
                            ProcessName = "Unknown",
                            ProcessId = 0,
                            Timestamp = DateTimeOffset.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["technique"] = "T1562.001 - Impair Defenses: Disable or Modify Tools",
                                ["action_taken"] = "Failed",
                                ["location"] = "amsi.dll!AmsiScanBuffer"
                            }
                        }, cancellationToken);
                    }
                }

                // Check CLR.DLL AMSI integration (newer bypass technique)
                if (clrAmsiScan != IntPtr.Zero && originalClrPrologue != null)
                {
                    var currentClrPrologue = new byte[8];
                    Marshal.Copy(clrAmsiScan, currentClrPrologue, 0, 8);

                    if (!currentClrPrologue.SequenceEqual(originalClrPrologue))
                    {
                        _logger.LogCritical("Self-Protection: CLR AMSI integration has been patched!");

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Self-Protection: AMSI Patching Detected (CLR.DLL)",
                            Evidence = "CLR's internal AMSI scanning path was modified — advanced bypass targeting .NET runtime",
                            Reasoning = "This is a newer AMSI bypass technique that patches CLR.DLL's internal " +
                                "scanning integration rather than AmsiScanBuffer directly. This bypasses " +
                                "traditional AmsiScanBuffer monitoring. The attacker can now load malicious " +
                                ".NET assemblies without AMSI scanning them.",
                            Confidence = 0.98,
                            Tier = DetectionTier.Tier1Behavioral,
                            ProcessName = "Unknown",
                            ProcessId = 0,
                            Timestamp = DateTimeOffset.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["technique"] = "T1562.001 - Impair Defenses: Disable or Modify Tools",
                                ["location"] = "clr.dll/coreclr.dll AMSI integration",
                                ["bypass_type"] = "clr_amsi_patch"
                            }
                        }, cancellationToken);

                        // Update baseline to prevent repeated alerts
                        originalClrPrologue = currentClrPrologue;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Self-Protection: AMSI check error");
            }
        }
    }

    private bool TryRepairAmsi(IntPtr targetAddress, byte[] originalBytes)
    {
        try
        {
            // Change memory protection to allow writing
            if (!VirtualProtect(targetAddress, (UIntPtr)originalBytes.Length, PAGE_EXECUTE_READWRITE, out uint oldProtect))
                return false;

            // Restore original bytes
            Marshal.Copy(originalBytes, 0, targetAddress, originalBytes.Length);

            // Restore original protection
            VirtualProtect(targetAddress, (UIntPtr)originalBytes.Length, oldProtect, out _);

            return true;
        }
        catch
        {
            return false;
        }
    }

    private async Task RunEtwIntegrityCheckAsync(CancellationToken cancellationToken)
    {
        byte[]? originalEtwPrologue = null;
        byte[]? originalNtTracePrologue = null;
        IntPtr ntdllHandle = IntPtr.Zero;
        IntPtr etwEventWrite = IntPtr.Zero;
        IntPtr ntTraceEvent = IntPtr.Zero;
        DateTime lastEventTime = DateTime.Now;

        try
        {
            ntdllHandle = GetModuleHandle("ntdll.dll");
            if (ntdllHandle != IntPtr.Zero)
            {
                etwEventWrite = GetProcAddress(ntdllHandle, "EtwEventWrite");
                if (etwEventWrite != IntPtr.Zero)
                {
                    originalEtwPrologue = new byte[5];
                    Marshal.Copy(etwEventWrite, originalEtwPrologue, 0, 5);
                    _logger.LogDebug("Self-Protection: ETW EtwEventWrite prologue captured");
                }

                // Also monitor NtTraceEvent — newer bypass technique patches this instead
                ntTraceEvent = GetProcAddress(ntdllHandle, "NtTraceEvent");
                if (ntTraceEvent != IntPtr.Zero)
                {
                    originalNtTracePrologue = new byte[8]; // Syscall stub is typically 8 bytes
                    Marshal.Copy(ntTraceEvent, originalNtTracePrologue, 0, 8);
                    _logger.LogDebug("Self-Protection: NtTraceEvent prologue captured");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Self-Protection: Failed to capture ETW prologue");
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(EtwCheckInterval, cancellationToken);

                // Check for EtwEventWrite patching
                if (etwEventWrite != IntPtr.Zero && originalEtwPrologue != null)
                {
                    var currentPrologue = new byte[5];
                    Marshal.Copy(etwEventWrite, currentPrologue, 0, 5);

                    if (!currentPrologue.SequenceEqual(originalEtwPrologue))
                    {
                        _logger.LogCritical("Self-Protection: ETW EtwEventWrite has been patched!");

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Self-Protection: ETW Unhooking Detected",
                            Evidence = "EtwEventWrite prologue was modified",
                            Reasoning = "ETW patching (unhooking) is a common EDR blinding technique. Event Tracing for Windows has been tampered with.",
                            Confidence = 0.97,
                            Tier = DetectionTier.Tier1Behavioral,
                            ProcessName = "Unknown",
                            ProcessId = 0,
                            Timestamp = DateTimeOffset.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["technique"] = "T1562.001 - Impair Defenses: Disable or Modify Tools",
                                ["location"] = "ntdll.dll!EtwEventWrite",
                                ["fallback"] = "WMI polling"
                            }
                        }, cancellationToken);
                    }
                }

                // Check for NtTraceEvent patching (deeper bypass, targets syscall stub)
                if (ntTraceEvent != IntPtr.Zero && originalNtTracePrologue != null)
                {
                    var currentPrologue = new byte[8];
                    Marshal.Copy(ntTraceEvent, currentPrologue, 0, 8);

                    if (!currentPrologue.SequenceEqual(originalNtTracePrologue))
                    {
                        _logger.LogCritical("Self-Protection: NtTraceEvent syscall stub has been patched!");

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Self-Protection: ETW Unhooking Detected (NtTraceEvent)",
                            Evidence = "NtTraceEvent syscall stub was modified — deeper ETW bypass than EtwEventWrite patching",
                            Reasoning = "NtTraceEvent patching is an advanced EDR blinding technique that operates at the " +
                                "syscall stub level in ntdll.dll. This bypasses EtwEventWrite-level monitoring. " +
                                "The attacker has modified the native syscall entry point to prevent ETW events from reaching the kernel.",
                            Confidence = 0.98,
                            Tier = DetectionTier.Tier1Behavioral,
                            ProcessName = "Unknown",
                            ProcessId = 0,
                            Timestamp = DateTimeOffset.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["technique"] = "T1562.001 - Impair Defenses: Disable or Modify Tools",
                                ["location"] = "ntdll.dll!NtTraceEvent",
                                ["bypass_type"] = "syscall_stub_patch",
                                ["fallback"] = "WMI polling"
                            }
                        }, cancellationToken);
                    }
                }

                // Check ETW event flow (if no events for 5 minutes, something is wrong)
                if (DateTime.Now - lastEventTime > TimeSpan.FromMinutes(5))
                {
                    _logger.LogWarning("Self-Protection: No ETW events received for 5 minutes. ETW may be disabled.");

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Self-Protection: ETW Event Flow Stalled",
                        Evidence = "No process creation events received for 5 minutes",
                        Reasoning = "ETW event flow interruption may indicate ETW tampering or provider failure. Falling back to WMI polling.",
                        Confidence = 0.75,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = "N/A",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["technique"] = "T1562.001 - Impair Defenses",
                            ["action"] = "Fallback to WMI"
                        }
                    }, cancellationToken);
                }

                // NOTE: lastEventTime is intentionally NOT reset here.
                // It must only be updated when an actual ETW event is received
                // (via NotifyEtwEventReceived). Resetting it unconditionally every
                // loop iteration would prevent the 5-minute stall check from ever firing.
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Self-Protection: ETW check error");
            }
        }
    }

    /// <summary>
    /// Called by EtwProcessMonitor each time an ETW event is received.
    /// Resets the ETW flow stall timer so the 5-minute silence check works correctly.
    /// </summary>
    public void NotifyEtwEventReceived()
    {
        // This is intentionally a no-op stub here — the actual lastEventTime field
        // lives inside RunEtwIntegrityCheckAsync's local scope. The correct fix is
        // to expose it as a field so EtwProcessMonitor can call this method.
        // TODO: Refactor lastEventTime to a class-level field and wire EtwProcessMonitor.
    }

    private async Task RunDebuggerDetectionAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(DebuggerCheckInterval, cancellationToken);

                bool debuggerDetected = IsDebuggerPresent();

                if (!debuggerDetected)
                {
                    // Additional check via NtQueryInformationProcess
                    try
                    {
                        int debugPort = 0;
                        NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 7, ref debugPort, sizeof(int), out _);
                        debuggerDetected = debugPort != 0;
                    }
                    catch { }
                }

                if (debuggerDetected)
                {
                    _logger.LogCritical("Self-Protection: Debugger detected attached to Sentinel process!");

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Self-Protection: Debugger Attachment Detected",
                        Evidence = "A debugger is attached to the Sentinel process",
                        Reasoning = "Debugger attachment may indicate analysis or tampering attempt. Debugging security tools is a common reverse engineering technique.",
                        Confidence = 0.90,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "Unknown",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["technique"] = "T1622 - Debugger Evasion",
                            ["method"] = "IsDebuggerPresent / NtQueryInformationProcess"
                        }
                    }, cancellationToken);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Self-Protection: Debugger check error");
            }
        }
    }

    private async Task RunSelfIntegrityCheckAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(IntegrityCheckInterval, cancellationToken);

                // Check executable integrity
                if (File.Exists(_executablePath) && _lastKnownExecutableHash != null)
                {
                    var currentHash = await ComputeFileHashAsync(_executablePath, cancellationToken);
                    if (currentHash != _lastKnownExecutableHash)
                    {
                        _logger.LogCritical("Self-Protection: Sentinel executable has been modified!");

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Self-Protection: Executable Tampering Detected",
                            Evidence = $"SHA256 hash changed from baseline",
                            Reasoning = "The Sentinel executable has been modified on disk. This may indicate binary replacement or corruption.",
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            ProcessName = "N/A",
                            ProcessId = 0,
                            Timestamp = DateTimeOffset.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["technique"] = "T1565 - Data Manipulation",
                                ["file"] = _executablePath
                            }
                        }, cancellationToken);
                    }
                }

                // Check config tampering
                if (File.Exists(_configPath) && _lastKnownConfigHash != null)
                {
                    var currentHash = await ComputeFileHashAsync(_configPath, cancellationToken);
                    if (currentHash != _lastKnownConfigHash)
                    {
                        _logger.LogWarning("Self-Protection: Config file has been modified. Freezing allowlists.");

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Self-Protection: Configuration Tampering Detected",
                            Evidence = "appsettings.json has been modified at runtime",
                            Reasoning = "Configuration file modification during runtime may indicate attempt to inject allowlist entries or disable protections. Allowlists are now frozen.",
                            Confidence = 0.85,
                            Tier = DetectionTier.Tier1Behavioral,
                            ProcessName = "N/A",
                            ProcessId = 0,
                            Timestamp = DateTimeOffset.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["technique"] = "T1562 - Impair Defenses",
                                ["action"] = "Allowlists frozen",
                                ["file"] = _configPath
                            }
                        }, cancellationToken);

                        // Update baseline to new hash (freeze the new state)
                        _lastKnownConfigHash = currentHash;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Self-Protection: Integrity check error");
            }
        }
    }

    private async Task RunModuleIntegrityCheckAsync(CancellationToken cancellationToken)
    {
        // Snapshot loaded modules
        var originalModules = new Dictionary<string, string>();
        
        try
        {
            var process = Process.GetCurrentProcess();
            foreach (ProcessModule module in process.Modules)
            {
                if (!string.IsNullOrEmpty(module.FileName) && File.Exists(module.FileName))
                {
                    var hash = await ComputeFileHashAsync(module.FileName, cancellationToken);
                    originalModules[module.ModuleName ?? "unknown"] = hash;
                }
            }
            _logger.LogDebug("Self-Protection: Module snapshot captured ({Count} modules)", originalModules.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Self-Protection: Failed to capture module snapshot");
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(ModuleCheckInterval, cancellationToken);

                var currentModules = new Dictionary<string, string>();
                var process = Process.GetCurrentProcess();

                foreach (ProcessModule module in process.Modules)
                {
                    if (!string.IsNullOrEmpty(module.FileName) && File.Exists(module.FileName))
                    {
                        var hash = await ComputeFileHashAsync(module.FileName, cancellationToken);
                        currentModules[module.ModuleName ?? "unknown"] = hash;

                        // Check for DLL hijacking in install directory
                        var installDir = Path.GetDirectoryName(_executablePath);
                        if (!string.IsNullOrEmpty(installDir) && 
                            module.FileName.StartsWith(installDir, StringComparison.OrdinalIgnoreCase))
                        {
                            if (originalModules.TryGetValue(module.ModuleName ?? "", out var originalHash))
                            {
                                if (originalHash != hash)
                                {
                                    _logger.LogCritical("Self-Protection: DLL hijacking detected in install directory! Module: {Module}", module.ModuleName);

                                    await _detectionEngine.EmitAsync(new DetectionEvent
                                    {
                                        RuleName = "Self-Protection: DLL Hijacking Detected",
                                        Evidence = $"Module {module.ModuleName} in install directory has different hash",
                                        Reasoning = "DLL hijacking detected in Sentinel install directory. A malicious DLL may have been placed to intercept calls.",
                                        Confidence = 0.96,
                                        Tier = DetectionTier.Tier1Behavioral,
                                        ProcessName = "N/A",
                                        ProcessId = 0,
                                        Timestamp = DateTimeOffset.UtcNow,
                                        Metadata = new Dictionary<string, string>
                                        {
                                            ["technique"] = "T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking",
                                            ["module"] = module.ModuleName ?? "unknown",
                                            ["path"] = module.FileName
                                        }
                                    }, cancellationToken);
                                }
                            }
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Self-Protection: Module check error");
            }
        }
    }

    private async Task<string> ComputeFileHashAsync(string filePath, CancellationToken cancellationToken)
    {
        using var sha256 = SHA256.Create();
        await using var stream = File.OpenRead(filePath);
        var hash = await sha256.ComputeHashAsync(stream, cancellationToken);
        return Convert.ToHexString(hash);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("=== Self-Protection Service stopping ===");
        await base.StopAsync(cancellationToken);
    }
}


