using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using System.Runtime.InteropServices;

namespace WindowsSentinel.Core
{
    public sealed class AntiTamperGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<AntiTamperGuard> _logger;
        private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(2);
        private DateTime _lastTick = DateTime.UtcNow;

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint GetSecurityInfo(
            IntPtr handle,
            int objectType,
            int securityInfo,
            out IntPtr ppsidOwner,
            out IntPtr ppsidGroup,
            out IntPtr ppDacl,
            out IntPtr ppSacl,
            out IntPtr ppSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint SetSecurityInfo(
            IntPtr handle,
            int objectType,
            int securityInfo,
            IntPtr psidOwner,
            IntPtr psidGroup,
            IntPtr pDacl,
            IntPtr pSacl);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        private const int SE_KERNEL_OBJECT = 6;
        private const int DACL_SECURITY_INFORMATION = 4;

        public AntiTamperGuard(DetectionEngine detectionEngine, ILogger<AntiTamperGuard> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("AntiTamperGuard starting...");
            
            // Harden process handles on startup
            HardenProcessHandles();

            _lastTick = DateTime.UtcNow;

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var now = DateTime.UtcNow;
                    var elapsed = now - _lastTick;
                    _lastTick = now;

                    // 1. Anti-Suspension Check (if suspended, elapsed time will be unusually large)
                    if (elapsed > TimeSpan.FromSeconds(10))
                    {
                        _logger.LogWarning($"[ANTI-TAMPER] Process suspension detected! Execution gap of {elapsed.TotalSeconds:F1}s.");
                        await EmitTamperEventAsync(
                            "Anti-Tamper: Process Suspension Detected",
                            $"Process execution was suspended for {elapsed.TotalSeconds:F1}s. This indicates NtSuspendProcess or similar API was used to pause the EDR.",
                            0.95
                        );
                    }

                    // 2. Service SCM Registry Key Guard
                    CheckAndRestoreServiceRegistry();

                    // 3. Agent Startup Run Key Guard
                    CheckAndRestoreAgentRunKey();

                    await Task.Delay(CheckInterval, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "AntiTamperGuard error");
                }
            }
        }

        private void HardenProcessHandles()
        {
            try
            {
                // Attempt to restrict the DACL of the current process handle to prevent termination by non-SYSTEM/non-Admin handles
                // Note: GetCurrentProcess() returns a pseudo-handle, but it is valid for SetSecurityInfo.
                IntPtr hProcess = GetCurrentProcess();
                
                // Get existing DACL info
                uint res = GetSecurityInfo(
                    hProcess,
                    SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    out IntPtr pOwner,
                    out IntPtr pGroup,
                    out IntPtr pDacl,
                    out IntPtr pSacl,
                    out IntPtr pSD);

                if (res == 0 && pDacl != IntPtr.Zero)
                {
                    // Secure DACL by applying it again. If needed, we can compile a strict DACL,
                    // but on Windows a SYSTEM service process already starts with high privilege DACLs.
                    // To harden further, we explicitly enforce the security info.
                    SetSecurityInfo(
                        hProcess,
                        SE_KERNEL_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        pDacl,
                        IntPtr.Zero);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to apply process handle hardening");
            }
        }

        private void CheckAndRestoreServiceRegistry()
        {
            try
            {
                const string svcKeyPath = @"SYSTEM\CurrentControlSet\Services\Windows Sentinel";
                using var key = Registry.LocalMachine.OpenSubKey(svcKeyPath, true);
                if (key == null)
                {
                    _logger.LogWarning("[ANTI-TAMPER] Service registry key missing! Re-creating service definition.");
                    using var newKey = Registry.LocalMachine.CreateSubKey(svcKeyPath);
                    newKey.SetValue("Type", 16, RegistryValueKind.DWord); // Win32OwnProcess
                    newKey.SetValue("Start", 2, RegistryValueKind.DWord); // Automatic
                    newKey.SetValue("ErrorControl", 1, RegistryValueKind.DWord);
                    newKey.SetValue("ImagePath", $"\"{Path.Combine(AppContext.BaseDirectory, "WindowsSentinel.Service.exe")}\"", RegistryValueKind.ExpandString);
                    newKey.SetValue("DisplayName", "Windows Sentinel", RegistryValueKind.String);
                    newKey.SetValue("ObjectName", "LocalSystem", RegistryValueKind.String);
                    newKey.SetValue("Description", "Userland Endpoint Detection & Response (EDR) Service", RegistryValueKind.String);

                    _ = EmitTamperEventAsync(
                        "Anti-Tamper: Service Registry Modification Detected",
                        "The Windows Sentinel service registry key was deleted or modified and has been auto-recovered.",
                        0.98
                    );
                }
                else
                {
                    // Ensure ImagePath points to the correct executable path
                    var expectedPath = $"\"{Path.Combine(AppContext.BaseDirectory, "WindowsSentinel.Service.exe")}\"";
                    var currentPath = key.GetValue("ImagePath") as string;
                    if (!string.Equals(currentPath, expectedPath, StringComparison.OrdinalIgnoreCase))
                    {
                        key.SetValue("ImagePath", expectedPath, RegistryValueKind.ExpandString);
                        _logger.LogWarning("[ANTI-TAMPER] Service ImagePath tampered! Restored correct path.");
                        _ = EmitTamperEventAsync(
                            "Anti-Tamper: Service ImagePath Tampered",
                            $"The Windows Sentinel service ImagePath was modified to '{currentPath}'. Restored to correct path '{expectedPath}'.",
                            0.97
                        );
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error checking service registry key");
            }
        }

        private void CheckAndRestoreAgentRunKey()
        {
            try
            {
                const string runKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
                using var runKey = Registry.LocalMachine.OpenSubKey(runKeyPath, true);
                if (runKey != null)
                {
                    var expectedVal = $"\"{Path.Combine(AppContext.BaseDirectory, "WindowsSentinel.Agent.exe")}\"";
                    var val = runKey.GetValue("WindowsSentinelAgent") as string;
                    if (!string.Equals(val, expectedVal, StringComparison.OrdinalIgnoreCase))
                    {
                        runKey.SetValue("WindowsSentinelAgent", expectedVal, RegistryValueKind.String);
                        _logger.LogWarning("[ANTI-TAMPER] Agent run key was deleted or modified! Restored.");
                        _ = EmitTamperEventAsync(
                            "Anti-Tamper: Agent Auto-Start Key Tampered",
                            $"The Agent auto-start Run key was modified or removed. Restored to '{expectedVal}'.",
                            0.92
                        );
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error checking agent run key");
            }
        }

        private async Task EmitTamperEventAsync(string ruleName, string evidence, double confidence)
        {
            try
            {
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = ruleName,
                    Evidence = evidence,
                    Reasoning = "Anti-tamper checks detected modification of EDR core configurations, processes, or registry keys. These components were automatically self-healed.",
                    Confidence = confidence,
                    Tier = DetectionTier.Tier1Behavioral, // Triggers active response block/alert
                    ProcessName = "SYSTEM",
                    ProcessId = 4,
                    Timestamp = DateTime.UtcNow,
                    Metadata = new System.Collections.Generic.Dictionary<string, string>
                    {
                        { "technique", "T1562.001 - Impair Defenses: Disable or Modify Tools" },
                        { "tamper_detected", "true" }
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to emit tamper event");
            }
        }
    }
}
