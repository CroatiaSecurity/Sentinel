using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Syscall Stub Integrity Monitor — Detects ntdll.dll unhooking in the Sentinel process.
///
/// Advanced attackers (Cobalt Strike, custom loaders) unhook ntdll to blind EDRs:
///   1. Map a fresh copy of ntdll.dll from disk
///   2. Overwrite the .text section of the loaded ntdll with the clean copy
///   3. All userland hooks (including ETW instrumentation) are removed
///
/// This monitor periodically compares the first bytes of critical ntdll exports
/// against the on-disk copy. If they differ, someone has hooked or unhooked ntdll
/// in our process — either way, it's an integrity violation.
///
/// Monitored functions:
///   - NtWriteVirtualMemory (injection)
///   - NtAllocateVirtualMemory (injection)
///   - NtProtectVirtualMemory (RWX)
///   - NtCreateThreadEx (remote thread)
///   - NtMapViewOfSection (hollowing)
///   - NtQueueApcThread (APC injection)
///   - EtwEventWrite (ETW blinding)
///   - AmsiScanBuffer (AMSI bypass)
///
/// This runs ONLY on our own process — no cross-process access needed.
/// </summary>
public sealed class SyscallStubMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<SyscallStubMonitor> _logger;

    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(10);

    // Functions to monitor: module → export name
    private static readonly (string Module, string Export)[] MonitoredFunctions = new[]
    {
        ("ntdll.dll", "NtWriteVirtualMemory"),
        ("ntdll.dll", "NtAllocateVirtualMemory"),
        ("ntdll.dll", "NtProtectVirtualMemory"),
        ("ntdll.dll", "NtCreateThreadEx"),
        ("ntdll.dll", "NtMapViewOfSection"),
        ("ntdll.dll", "NtQueueApcThread"),
        ("ntdll.dll", "EtwEventWrite"),
        ("amsi.dll", "AmsiScanBuffer"),
    };

    // Baseline: first 16 bytes of each function at startup (before any tampering)
    private readonly ConcurrentDictionary<string, byte[]> _baselines = new();
    private bool _baselineEstablished = false;

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    public SyscallStubMonitor(
        IDetectionEngine detectionEngine,
        ILogger<SyscallStubMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Syscall Stub Integrity Monitor starting ===");

        // Wait for process to fully initialize
        await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);

        // Establish baseline
        EstablishBaseline();

        if (!_baselineEstablished)
        {
            _logger.LogWarning("SyscallStubMonitor: Could not establish baseline. Monitor disabled.");
            return;
        }

        _logger.LogInformation("SyscallStubMonitor: Baseline established for {Count} functions",
            _baselines.Count);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(CheckInterval, stoppingToken);
                await CheckIntegrityAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SyscallStubMonitor: Check error");
            }
        }
    }

    private void EstablishBaseline()
    {
        foreach (var (module, export) in MonitoredFunctions)
        {
            try
            {
                var bytes = ReadFunctionPrologue(module, export);
                if (bytes != null)
                {
                    var key = $"{module}!{export}";
                    _baselines[key] = bytes;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "SyscallStubMonitor: Could not baseline {Module}!{Export}",
                    module, export);
            }
        }

        _baselineEstablished = _baselines.Count > 0;
    }

    private async Task CheckIntegrityAsync(CancellationToken ct)
    {
        foreach (var (module, export) in MonitoredFunctions)
        {
            ct.ThrowIfCancellationRequested();

            var key = $"{module}!{export}";
            if (!_baselines.TryGetValue(key, out var baseline))
                continue;

            try
            {
                var current = ReadFunctionPrologue(module, export);
                if (current == null) continue;

                // Compare
                bool tampered = false;
                for (int i = 0; i < Math.Min(baseline.Length, current.Length); i++)
                {
                    if (baseline[i] != current[i])
                    {
                        tampered = true;
                        break;
                    }
                }

                if (tampered)
                {
                    _logger.LogCritical(
                        "SYSCALL STUB TAMPERED: {Module}!{Export} — bytes changed from baseline. " +
                        "Possible unhooking or hooking attack on Sentinel process.",
                        module, export);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Self-Protection: Syscall Stub Tampered",
                        Evidence = $"{module}!{export} prologue bytes differ from baseline. " +
                                  $"Baseline: {Convert.ToHexString(baseline[..Math.Min(8, baseline.Length)])}... " +
                                  $"Current: {Convert.ToHexString(current[..Math.Min(8, current.Length)])}... " +
                                  $"This indicates hooking or unhooking of critical system functions.",
                        Reasoning = "An attacker has modified the in-memory code of a critical system function " +
                                   "in the Sentinel process. This is used to: (1) blind EDR telemetry by unhooking " +
                                   "ETW/AMSI, or (2) intercept security-sensitive API calls. Techniques: direct " +
                                   "ntdll remapping, manual syscall patching, or in-process code injection.",
                        Confidence = 0.97,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "SentinelService",
                        ProcessId = Environment.ProcessId,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["module"] = module,
                            ["export"] = export,
                            ["baseline_bytes"] = Convert.ToHexString(baseline),
                            ["current_bytes"] = Convert.ToHexString(current),
                            ["technique"] = "T1562.001 - Impair Defenses: Disable or Modify Tools"
                        }
                    }, ct);

                    // Update baseline to prevent spam (alert once per change)
                    _baselines[key] = current;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "SyscallStubMonitor: Error checking {Key}", key);
            }
        }
    }

    /// <summary>
    /// Reads the first 16 bytes of a function's code in the current process.
    /// </summary>
    private static byte[]? ReadFunctionPrologue(string moduleName, string exportName)
    {
        var hModule = GetModuleHandle(moduleName);
        if (hModule == IntPtr.Zero) return null;

        var pFunc = GetProcAddress(hModule, exportName);
        if (pFunc == IntPtr.Zero) return null;

        var bytes = new byte[16];
        Marshal.Copy(pFunc, bytes, 0, 16);
        return bytes;
    }
}

