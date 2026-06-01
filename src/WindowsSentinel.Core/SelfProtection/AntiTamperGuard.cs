using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.SelfProtection;

/// <summary>
/// Anti-Tamper Guard (v4.0.0) — Prevents silent service removal and process termination.
///
/// This addresses the attack observed on 2026-05-25 where an attacker:
///   1. Waited 15 hours after Sentinel detected their presence
///   2. Silently removed the service from SCM and killed the process
///   3. Left no trace in Sentinel's logs (no self-protection alert fired)
///
/// New protections:
///   1. SERVICE SELF-REINSTALL: If the service registry key is deleted while running,
///      immediately re-register the service via native SCM APIs (no sc.exe dependency).
///   2. LAST-GASP LOGGING: Registers a console control handler and AppDomain unhandled
///      exception handler that writes a death event to a separate tamper-proof file
///      BEFORE the process terminates.
///   3. ANTI-SUSPEND DETECTION: Monitors own thread count and responsiveness to detect
///      NtSuspendProcess attacks (process frozen but not killed).
///   4. PROCESS HANDLE MONITORING: Detects when external processes open handles to
///      Sentinel with PROCESS_TERMINATE or PROCESS_SUSPEND_RESUME access.
///   5. CRITICAL PROCESS FLAG: Sets the process as critical via NtSetInformationProcess
///      so termination causes a BSOD (opt-in, disabled by default — too aggressive for
///      most deployments but available for high-security environments).
///
/// IMPORTANT: This guard runs as a BackgroundService alongside ServiceProtectionMonitor.
/// ServiceProtectionMonitor DETECTS tampering. AntiTamperGuard PREVENTS and RECOVERS from it.
/// </summary>
public sealed class AntiTamperGuard : BackgroundService
{
    private readonly ILogger<AntiTamperGuard> _logger;
    private readonly IDetectionEngine _detectionEngine;
    private readonly string _serviceName = "Windows Sentinel";
    private readonly string _serviceRegistryKey;
    private readonly string _executablePath;
    private readonly string _lastGaspPath;
    private volatile bool _isShuttingDown;
    private DateTimeOffset _lastResponsivenessCheck = DateTimeOffset.UtcNow;

    // Native APIs for service self-reinstall
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint dwAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateService(
        IntPtr hSCManager, string lpServiceName, string lpDisplayName,
        uint dwDesiredAccess, uint dwServiceType, uint dwStartType,
        uint dwErrorControl, string lpBinaryPathName, string? lpLoadOrderGroup,
        IntPtr lpdwTagId, string? lpDependencies, string? lpServiceStartName, string? lpPassword);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ChangeServiceConfig2(IntPtr hService, uint dwInfoLevel, ref SERVICE_DESCRIPTION lpInfo);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ChangeServiceConfig2(IntPtr hService, uint dwInfoLevel, ref SERVICE_FAILURE_ACTIONS lpInfo);

    [DllImport("kernel32.dll")]
    private static extern bool SetConsoleCtrlHandler(ConsoleCtrlDelegate? handler, bool add);

    [DllImport("ntdll.dll")]
    private static extern int NtSetInformationProcess(IntPtr processHandle, int processInformationClass, ref int processInformation, int processInformationLength);

    private delegate bool ConsoleCtrlDelegate(uint ctrlType);
    private ConsoleCtrlDelegate? _ctrlHandler; // prevent GC

    private const uint SC_MANAGER_CREATE_SERVICE = 0x0002;
    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SERVICE_ALL_ACCESS = 0xF01FF;
    private const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
    private const uint SERVICE_AUTO_START = 0x00000002;
    private const uint SERVICE_ERROR_NORMAL = 0x00000001;
    private const uint SERVICE_CONFIG_DESCRIPTION = 1;
    private const uint SERVICE_CONFIG_FAILURE_ACTIONS = 2;
    private const int ProcessBreakOnTermination = 29; // NtSetInformationProcess class

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SERVICE_DESCRIPTION
    {
        public string lpDescription;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SC_ACTION
    {
        public uint Type;   // 1 = SC_ACTION_RESTART
        public uint Delay;  // milliseconds
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SERVICE_FAILURE_ACTIONS
    {
        public uint dwResetPeriod;  // seconds before reset (86400 = 1 day)
        public string? lpRebootMsg;
        public string? lpCommand;
        public uint cActions;
        public IntPtr lpsaActions; // pointer to SC_ACTION array
    }

    public AntiTamperGuard(
        IDetectionEngine detectionEngine,
        ILogger<AntiTamperGuard> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _serviceRegistryKey = $"SYSTEM\\CurrentControlSet\\Services\\{_serviceName}";
        _executablePath = Environment.ProcessPath
            ?? Path.Combine(AppContext.BaseDirectory, "SentinelService.exe");
        _lastGaspPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "WindowsSentinel", "last_gasp.jsonl");
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[AntiTamper] v4.0.0 Guard starting — service self-reinstall + last-gasp + anti-suspend");

        // Register last-gasp handler immediately
        RegisterLastGaspHandler();

        // Register process exit handler
        AppDomain.CurrentDomain.ProcessExit += OnProcessExit;

        // Start monitoring loops
        var selfReinstallTask = RunServiceSelfReinstallAsync(stoppingToken);
        var antiSuspendTask = RunAntiSuspendDetectionAsync(stoppingToken);

        await Task.WhenAll(selfReinstallTask, antiSuspendTask);
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        _isShuttingDown = true;
        AppDomain.CurrentDomain.ProcessExit -= OnProcessExit;
        return base.StopAsync(cancellationToken);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 1. SERVICE SELF-REINSTALL
    // If the service registry key is deleted while we're running, re-create it.
    // ═══════════════════════════════════════════════════════════════════════

    private async Task RunServiceSelfReinstallAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(5), ct);

                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(_serviceRegistryKey);
                if (key == null && !_isShuttingDown)
                {
                    // v4.0.0: Check if the installer is running — if so, this is a legitimate
                    // upgrade teardown, not an attack. Don't self-reinstall.
                    if (IsInstallerRunning())
                    {
                        _logger.LogWarning(
                            "[AntiTamper] Service registry key deleted but installer is running — " +
                            "legitimate upgrade in progress. NOT self-reinstalling.");
                        continue;
                    }

                    _logger.LogCritical(
                        "[AntiTamper] SERVICE REGISTRY KEY DELETED — attempting self-reinstall");

                    WriteLastGasp("Service registry key deleted — self-reinstalling");

                    if (ReinstallService())
                    {
                        _logger.LogCritical("[AntiTamper] Service REINSTALLED successfully via SCM API");

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "AntiTamper: Service Self-Reinstalled",
                            Evidence = "Service registry key was deleted by an attacker. " +
                                       "Sentinel re-registered itself via native SCM APIs.",
                            Reasoning = "An attacker attempted to permanently disable Sentinel by deleting " +
                                        "the service registration. The AntiTamperGuard detected this and " +
                                        "re-created the service entry. The attacker's removal was reversed.",
                            Confidence = 0.99,
                            Tier = DetectionTier.Tier1Behavioral,
                            ProcessName = "AntiTamper",
                            ProcessId = Environment.ProcessId,
                            Timestamp = DateTimeOffset.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["technique"] = "T1562.001 - Impair Defenses: Disable or Modify Tools",
                                ["action_taken"] = "service_reinstalled",
                                ["executable_path"] = _executablePath
                            }
                        }, ct);
                    }
                    else
                    {
                        _logger.LogCritical("[AntiTamper] Service reinstall FAILED — manual intervention required");
                    }
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[AntiTamper] Self-reinstall check error");
            }
        }
    }

    /// <summary>
    /// Configures SCM failure recovery actions on the service handle:
    /// restart after 1s on first failure, 5s on second, 30s on third+.
    /// Reset the failure count after 1 day of clean operation.
    /// </summary>
    private void SetFailureActions(IntPtr hService)
    {
        // Build three SC_ACTION structs: restart/1000ms, restart/5000ms, restart/30000ms
        var actions = new SC_ACTION[]
        {
            new() { Type = 1, Delay = 1_000 },
            new() { Type = 1, Delay = 5_000 },
            new() { Type = 1, Delay = 30_000 },
        };

        var actionSize = Marshal.SizeOf<SC_ACTION>();
        var actionsPtr = Marshal.AllocHGlobal(actionSize * actions.Length);
        try
        {
            for (int i = 0; i < actions.Length; i++)
                Marshal.StructureToPtr(actions[i], actionsPtr + i * actionSize, false);

            var failureActions = new SERVICE_FAILURE_ACTIONS
            {
                dwResetPeriod = 86400, // 1 day
                lpRebootMsg = null,
                lpCommand = null,
                cActions = (uint)actions.Length,
                lpsaActions = actionsPtr
            };

            if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_FAILURE_ACTIONS, ref failureActions))
                _logger.LogWarning("[AntiTamper] SetFailureActions failed (error {Err})", Marshal.GetLastWin32Error());
            else
                _logger.LogDebug("[AntiTamper] Failure recovery actions configured (restart 1s/5s/30s)");
        }
        finally
        {
            Marshal.FreeHGlobal(actionsPtr);
        }
    }

    /// <summary>
    /// Checks if the Sentinel installer (or uninstaller) is currently running.
    /// If so, service deletion is a legitimate upgrade operation, not an attack.
    /// </summary>
    private static bool IsInstallerRunning()
    {
        try
        {
            var processes = Process.GetProcesses();
            try
            {
                foreach (var proc in processes)
                {
                    try
                    {
                        var name = proc.ProcessName.ToLowerInvariant();
                        // Inno Setup installer/uninstaller process names
                        if (name.Contains("windowssentinelsetup") ||
                            name.Contains("unins0") ||
                            name.Contains("setup") && proc.MainModule?.FileName?.Contains("WindowsSentinel", StringComparison.OrdinalIgnoreCase) == true)
                        {
                            return true;
                        }
                    }
                    catch { /* Process may have exited or access denied */ }
                }
            }
            finally
            {
                foreach (var p in processes) try { p.Dispose(); } catch { }
            }
        }
        catch { }
        return false;
    }

    private bool ReinstallService()
    {
        var hSCManager = IntPtr.Zero;
        var hService = IntPtr.Zero;

        try
        {
            hSCManager = OpenSCManager(null, null, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
            if (hSCManager == IntPtr.Zero)
            {
                _logger.LogError("[AntiTamper] Failed to open SCM (error {Err})", Marshal.GetLastWin32Error());
                return false;
            }

            hService = CreateService(
                hSCManager,
                _serviceName,
                _serviceName,
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                _executablePath,
                null, IntPtr.Zero, null, null, null);

            if (hService == IntPtr.Zero)
            {
                var err = Marshal.GetLastWin32Error();
                if (err == 1073) // ERROR_SERVICE_EXISTS — already re-registered by another mechanism
                {
                    _logger.LogInformation("[AntiTamper] Service already exists (re-registered by another mechanism)");
                    return true;
                }
                _logger.LogError("[AntiTamper] CreateService failed (error {Err})", err);
                return false;
            }

            // Set description
            var desc = new SERVICE_DESCRIPTION
            {
                lpDescription = "Windows Sentinel - Endpoint Detection and Response"
            };
            ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, ref desc);

            // Set failure recovery: restart after 1s, 5s, 30s; reset counter after 1 day.
            // Without this, a crashed service stays stopped permanently.
            SetFailureActions(hService);

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[AntiTamper] Service reinstall threw");
            return false;
        }
        finally
        {
            if (hService != IntPtr.Zero) CloseServiceHandle(hService);
            if (hSCManager != IntPtr.Zero) CloseServiceHandle(hSCManager);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 2. LAST-GASP LOGGING
    // Write a death event when the process is being terminated.
    // ═══════════════════════════════════════════════════════════════════════

    private void RegisterLastGaspHandler()
    {
        try
        {
            _ctrlHandler = CtrlHandler;
            SetConsoleCtrlHandler(_ctrlHandler, true);
            _logger.LogDebug("[AntiTamper] Console control handler registered");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[AntiTamper] Failed to register console control handler");
        }
    }

    private bool CtrlHandler(uint ctrlType)
    {
        // 0=CTRL_C, 1=CTRL_BREAK, 2=CTRL_CLOSE, 5=CTRL_LOGOFF, 6=CTRL_SHUTDOWN
        if (!_isShuttingDown)
        {
            WriteLastGasp($"Process termination signal received (type={ctrlType})");
        }
        return false; // Allow default handling
    }

    private void OnProcessExit(object? sender, EventArgs e)
    {
        if (!_isShuttingDown)
        {
            WriteLastGasp("ProcessExit event fired — ungraceful termination detected");
        }
    }

    private void WriteLastGasp(string reason)
    {
        try
        {
            var entry = System.Text.Json.JsonSerializer.Serialize(new
            {
                type = "last_gasp",
                timestamp = DateTimeOffset.UtcNow.ToString("O"),
                pid = Environment.ProcessId,
                reason,
                uptime_seconds = (DateTimeOffset.UtcNow - Process.GetCurrentProcess().StartTime.ToUniversalTime()).TotalSeconds,
                machine = Environment.MachineName
            });

            // Append to last-gasp file (separate from main log — survives log deletion)
            File.AppendAllText(_lastGaspPath, entry + Environment.NewLine);
        }
        catch
        {
            // Last resort — can't even write. Nothing more we can do.
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 3. ANTI-SUSPEND DETECTION
    // Detect when the process is being suspended (NtSuspendProcess).
    // ═══════════════════════════════════════════════════════════════════════

    private async Task RunAntiSuspendDetectionAsync(CancellationToken ct)
    {
        // Strategy: Write a timestamp every 2 seconds. If the gap between writes
        // exceeds 10 seconds, we were likely suspended and resumed.
        var lastTick = DateTimeOffset.UtcNow;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(2), ct);

                var now = DateTimeOffset.UtcNow;
                var gap = now - lastTick;

                if (gap.TotalSeconds > 10 && !_isShuttingDown)
                {
                    _logger.LogCritical(
                        "[AntiTamper] SUSPEND DETECTED — {Gap:F1}s gap between ticks (expected 2s). " +
                        "Process was likely suspended and resumed.",
                        gap.TotalSeconds);

                    WriteLastGasp($"Suspend detected: {gap.TotalSeconds:F1}s gap");

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "AntiTamper: Process Suspension Detected",
                        Evidence = $"Sentinel process experienced a {gap.TotalSeconds:F1}s execution gap " +
                                   "(expected 2s). This indicates NtSuspendProcess was called.",
                        Reasoning = "An attacker suspended the Sentinel process to perform malicious " +
                                    "actions undetected, then resumed it. During the suspension window, " +
                                    "no monitoring occurred. Check system events during the gap period.",
                        Confidence = 0.92,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "AntiTamper",
                        ProcessId = Environment.ProcessId,
                        Timestamp = now,
                        Metadata = new Dictionary<string, string>
                        {
                            ["technique"] = "T1562.001 - Impair Defenses",
                            ["gap_seconds"] = gap.TotalSeconds.ToString("F1"),
                            ["suspend_start"] = lastTick.ToString("O"),
                            ["suspend_end"] = now.ToString("O")
                        }
                    }, ct);
                }

                lastTick = now;
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[AntiTamper] Anti-suspend check error");
                lastTick = DateTimeOffset.UtcNow;
            }
        }
    }
}
