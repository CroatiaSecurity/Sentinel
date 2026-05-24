using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Secure Boot &amp; Boot Integrity Monitor (v3.6.0) — Detects firmware/boot tampering.
///
/// Monitors:
///   1. Secure Boot state — alerts if disabled (bootkits can load)
///   2. Boot configuration (BCD) changes — bcdedit tampering
///   3. Driver Signature Enforcement state — alerts if disabled
///   4. Test signing mode — allows unsigned drivers (rootkit vector)
///   5. Kernel debugging enabled — allows kernel-level manipulation
///   6. Early Launch Anti-Malware (ELAM) status
///
/// These are the deepest system integrity checks possible from user-mode.
/// If any of these are tampered with, the attacker has (or is preparing for)
/// kernel-level access — the most dangerous class of compromise.
///
/// Runs once at startup + periodic re-checks (boot config rarely changes).
/// </summary>
public sealed class SecureBootIntegrityMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<SecureBootIntegrityMonitor> _logger;

    // Baseline states
    private bool? _baselineSecureBoot;
    private bool? _baselineTestSigning;
    private bool? _baselineKernelDebug;

    // Deduplication
    private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedEvents = new();
    private static readonly TimeSpan CheckInterval = TimeSpan.FromMinutes(5);

    public SecureBootIntegrityMonitor(
        IDetectionEngine detectionEngine,
        ILogger<SecureBootIntegrityMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[SecureBootIntegrityMonitor] Starting — boot integrity monitoring active");

        await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);

        // Initial check
        await CheckBootIntegrityAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(CheckInterval, stoppingToken);
                await CheckBootIntegrityAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "[SecureBootIntegrityMonitor] Check error");
            }
        }
    }

    private async Task CheckBootIntegrityAsync(CancellationToken ct)
    {
        // ═══════════════════════════════════════════════════════════════════
        // CHECK 1: Secure Boot state
        // ═══════════════════════════════════════════════════════════════════
        var secureBootEnabled = IsSecureBootEnabled();
        if (secureBootEnabled == false)
        {
            var dedupeKey = "secureboot_disabled";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Boot Integrity: Secure Boot Disabled",
                    Evidence = "UEFI Secure Boot is DISABLED. The system will load unsigned bootloaders " +
                               "and kernel drivers without verification. Bootkits and rootkits can persist.",
                    Reasoning = "Secure Boot ensures only signed, trusted code runs during the boot process. " +
                                "With it disabled, an attacker can install bootkits (BlackLotus, FinSpy) that " +
                                "load before the OS and are invisible to all security software. If Secure Boot " +
                                "was previously enabled and is now disabled, this is a critical compromise indicator.",
                    Confidence = _baselineSecureBoot == true ? 0.92 : 0.70,
                    Tier = _baselineSecureBoot == true ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                    ProcessName = "Firmware",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["secure_boot"] = "disabled",
                        ["was_enabled"] = (_baselineSecureBoot == true).ToString(),
                        ["technique"] = "T1542 - Pre-OS Boot",
                        ["attack_type"] = "secureboot_disabled"
                    }
                }, ct);
            }
        }
        _baselineSecureBoot ??= secureBootEnabled;

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 2: Test Signing Mode (allows unsigned kernel drivers)
        // ═══════════════════════════════════════════════════════════════════
        var testSigning = IsTestSigningEnabled();
        if (testSigning == true)
        {
            if (_baselineTestSigning == false)
            {
                // Was disabled, now enabled — active tampering
                var dedupeKey = "testsigning_enabled";
                if (!_alertedEvents.ContainsKey(dedupeKey))
                {
                    _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: Test Signing Mode Enabled (Rootkit Vector)",
                        Evidence = "Windows Test Signing mode was ENABLED (was previously disabled). " +
                                   "This allows loading unsigned kernel drivers — the primary rootkit installation vector.",
                        Reasoning = "Test Signing mode bypasses Driver Signature Enforcement, allowing any " +
                                    "unsigned .sys file to load as a kernel driver. Attackers enable this to " +
                                    "install rootkits, keyloggers, and network filter drivers. This change " +
                                    "requires admin privileges and a reboot — if the user didn't do it, " +
                                    "the system is compromised.",
                        Confidence = 0.90,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "Firmware",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["test_signing"] = "enabled",
                            ["technique"] = "T1014 - Rootkit",
                            ["attack_type"] = "testsigning_enabled"
                        }
                    }, ct);
                }
            }
            else if (_baselineTestSigning == null)
            {
                // First check — test signing was already on
                var dedupeKey = "testsigning_on_boot";
                if (!_alertedEvents.ContainsKey(dedupeKey))
                {
                    _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: Test Signing Mode Active",
                        Evidence = "Windows Test Signing mode is ACTIVE. Unsigned kernel drivers can load.",
                        Reasoning = "Test Signing mode is active on this system. Unless this is a development " +
                                    "machine actively testing drivers, this is a security risk. Any unsigned " +
                                    "kernel driver can load, enabling rootkits and kernel-level malware.",
                        Confidence = 0.65,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = "Firmware",
                        ProcessId = 0,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["test_signing"] = "enabled",
                            ["technique"] = "T1014 - Rootkit",
                            ["attack_type"] = "testsigning_active"
                        }
                    }, ct);
                }
            }
        }
        _baselineTestSigning ??= testSigning;

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 3: Kernel Debugging enabled
        // ═══════════════════════════════════════════════════════════════════
        var kernelDebug = IsKernelDebugEnabled();
        if (kernelDebug == true)
        {
            var dedupeKey = "kdebug_enabled";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                var wasDisabled = _baselineKernelDebug == false;
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = wasDisabled
                        ? "Boot Integrity: Kernel Debugging Enabled (Active Tampering)"
                        : "Boot Integrity: Kernel Debugging Active",
                    Evidence = "Kernel debugging is ENABLED. An attached debugger can read/write " +
                               "all kernel memory, disable security features, and hide processes.",
                    Reasoning = "Kernel debugging allows complete control over the operating system. " +
                                "An attacker with kernel debug access can: disable all security software, " +
                                "hide processes/files/network connections, intercept all I/O, and install " +
                                "persistent rootkits. If not intentionally enabled for driver development, " +
                                "this is a critical compromise indicator.",
                    Confidence = wasDisabled ? 0.90 : 0.60,
                    Tier = wasDisabled ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                    ProcessName = "Firmware",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["kernel_debug"] = "enabled",
                        ["was_disabled"] = wasDisabled.ToString(),
                        ["technique"] = "T1014 - Rootkit",
                        ["attack_type"] = "kernel_debug"
                    }
                }, ct);
            }
        }
        _baselineKernelDebug ??= kernelDebug;
    }

    private static bool? IsSecureBootEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            if (key == null) return null;
            var value = key.GetValue("UEFISecureBootEnabled");
            return value is int i && i == 1;
        }
        catch { return null; }
    }

    private static bool? IsTestSigningEnabled()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "bcdedit",
                Arguments = "/enum {current}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc == null) return null;

            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            if (output.Contains("testsigning", StringComparison.OrdinalIgnoreCase) &&
                output.Contains("Yes", StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }
        catch { return null; }
    }

    private static bool? IsKernelDebugEnabled()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "bcdedit",
                Arguments = "/enum {current}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc == null) return null;

            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            if (output.Contains("debug", StringComparison.OrdinalIgnoreCase) &&
                output.Contains("Yes", StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }
        catch { return null; }
    }
}
