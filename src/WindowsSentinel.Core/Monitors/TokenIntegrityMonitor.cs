using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Token Integrity Monitor — Detects privilege escalation by monitoring process
/// token integrity levels for unauthorized elevation.
///
/// How it works:
///   - Periodically scans running processes and records their integrity level
///   - If a medium-integrity process suddenly has a high-integrity token WITHOUT
///     going through UAC consent, that's privilege escalation
///   - Tracks integrity level transitions over time
///
/// This catches:
///   - UAC bypass exploits (COM elevation, DLL hijacking, manifest abuse)
///   - Token manipulation (NtSetInformationToken)
///   - Token theft (duplicating a high-integrity token into a medium process)
///   - Named pipe impersonation escalation
///
/// False positive handling:
///   - UAC consent (consent.exe) legitimately elevates processes — excluded
///   - Service processes start at System integrity — excluded from transition checks
///   - Only flags TRANSITIONS from lower to higher (not processes that start elevated)
/// </summary>
public sealed class TokenIntegrityMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<TokenIntegrityMonitor> _logger;

    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(20);

    // Track known integrity levels per PID
    private readonly ConcurrentDictionary<int, IntegrityRecord> _knownIntegrity = new();

    // Processes that legitimately change integrity
    private static readonly HashSet<string> ExcludedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "consent.exe",      // UAC consent dialog
        "svchost.exe",      // Service host (various integrity levels)
        "services.exe",     // Service Control Manager
        "lsass.exe",        // Local Security Authority
        "csrss.exe",        // Client/Server Runtime
        "wininit.exe",      // Windows Initialization
        "winlogon.exe",     // Windows Logon
        "smss.exe",         // Session Manager
        "system",           // System process
        "registry"          // Registry process
    };

    // Native methods for token inspection
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInfoClass,
        IntPtr tokenInfo, int tokenInfoLength, out int returnLength);

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint TOKEN_QUERY = 0x0008;
    private const int TokenIntegrityLevel = 25; // TOKEN_INFORMATION_CLASS.TokenIntegrityLevel

    // Well-known integrity level RIDs
    private const int SECURITY_MANDATORY_LOW_RID = 0x1000;
    private const int SECURITY_MANDATORY_MEDIUM_RID = 0x2000;
    private const int SECURITY_MANDATORY_HIGH_RID = 0x3000;
    private const int SECURITY_MANDATORY_SYSTEM_RID = 0x4000;

    public TokenIntegrityMonitor(
        IDetectionEngine detectionEngine,
        ILogger<TokenIntegrityMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Token Integrity Monitor starting ===");

        // Initial delay
        await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanProcessIntegrityAsync(stoppingToken);
                await Task.Delay(ScanInterval, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "TokenIntegrityMonitor: Scan error");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
    }

    private async Task ScanProcessIntegrityAsync(CancellationToken ct)
    {
        var selfPid = Environment.ProcessId;
        var processes = Process.GetProcesses();

        foreach (var process in processes)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                if (process.Id <= 4 || process.Id == selfPid) continue;
                if (ExcludedProcesses.Contains(process.ProcessName)) continue;

                var integrity = GetProcessIntegrityLevel(process.Id);
                if (integrity == IntegrityLevel.Unknown) continue;

                var key = process.Id;

                if (_knownIntegrity.TryGetValue(key, out var previous))
                {
                    // Check for escalation: lower → higher without expected path
                    if (integrity > previous.Level && previous.Level != IntegrityLevel.Unknown)
                    {
                        // This is a privilege escalation!
                        _logger.LogCritical(
                            "TOKEN INTEGRITY ESCALATION: '{Name}' (PID {Pid}) went from {Old} to {New}",
                            process.ProcessName, process.Id, previous.Level, integrity);

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Privilege Escalation: Token Integrity Change",
                            Evidence = $"Process '{process.ProcessName}' (PID {process.Id}) integrity level " +
                                      $"changed from {previous.Level} to {integrity} without UAC consent. " +
                                      $"Previous scan: {previous.LastSeen:HH:mm:ss}, Current: {DateTimeOffset.UtcNow:HH:mm:ss}.",
                            Reasoning = "A process's integrity level increased without going through the " +
                                       "normal UAC elevation path (consent.exe). This indicates token manipulation, " +
                                       "UAC bypass exploit, or privilege escalation via named pipe impersonation. " +
                                       "Legitimate elevation always involves consent.exe or starts at the higher level.",
                            Confidence = 0.93,
                            Tier = DetectionTier.Tier2Indicator, // Corroborating signal — feeds correlation engine
                            ProcessName = process.ProcessName,
                            ProcessId = process.Id,
                            Timestamp = DateTimeOffset.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["previous_integrity"] = previous.Level.ToString(),
                                ["current_integrity"] = integrity.ToString(),
                                ["technique"] = "T1134 - Access Token Manipulation"
                            }
                        }, ct);
                    }

                    // Update record
                    previous.Level = integrity;
                    previous.LastSeen = DateTimeOffset.UtcNow;
                }
                else
                {
                    // First time seeing this process — record baseline
                    _knownIntegrity[key] = new IntegrityRecord
                    {
                        Pid = process.Id,
                        ProcessName = process.ProcessName,
                        Level = integrity,
                        FirstSeen = DateTimeOffset.UtcNow,
                        LastSeen = DateTimeOffset.UtcNow
                    };
                }
            }
            catch (InvalidOperationException) { /* process exited */ }
            catch (System.ComponentModel.Win32Exception) { /* access denied */ }
            finally
            {
                process.Dispose();
            }
        }

        // Cleanup dead processes
        var deadPids = _knownIntegrity.Keys.Where(pid =>
        {
            try { Process.GetProcessById(pid); return false; }
            catch { return true; }
        }).ToList();

        foreach (var pid in deadPids)
            _knownIntegrity.TryRemove(pid, out _);
    }

    private IntegrityLevel GetProcessIntegrityLevel(int pid)
    {
        var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero) return IntegrityLevel.Unknown;

        try
        {
            if (!OpenProcessToken(hProcess, TOKEN_QUERY, out var hToken))
                return IntegrityLevel.Unknown;

            try
            {
                // First call to get required buffer size
                GetTokenInformation(hToken, TokenIntegrityLevel, IntPtr.Zero, 0, out int needed);
                if (needed == 0) return IntegrityLevel.Unknown;

                var buffer = Marshal.AllocHGlobal(needed);
                try
                {
                    if (!GetTokenInformation(hToken, TokenIntegrityLevel, buffer, needed, out _))
                        return IntegrityLevel.Unknown;

                    // TOKEN_MANDATORY_LABEL structure: first field is SID_AND_ATTRIBUTES
                    // The SID pointer is at offset 0
                    var sidPtr = Marshal.ReadIntPtr(buffer);
                    if (sidPtr == IntPtr.Zero) return IntegrityLevel.Unknown;

                    // Get the last sub-authority (RID) which is the integrity level
                    var rid = GetSidLastRid(sidPtr);

                    return rid switch
                    {
                        >= SECURITY_MANDATORY_SYSTEM_RID => IntegrityLevel.System,
                        >= SECURITY_MANDATORY_HIGH_RID => IntegrityLevel.High,
                        >= SECURITY_MANDATORY_MEDIUM_RID => IntegrityLevel.Medium,
                        >= SECURITY_MANDATORY_LOW_RID => IntegrityLevel.Low,
                        _ => IntegrityLevel.Untrusted
                    };
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            finally
            {
                CloseHandle(hToken);
            }
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

    private static int GetSidLastRid(IntPtr pSid)
    {
        try
        {
            var countPtr = GetSidSubAuthorityCount(pSid);
            if (countPtr == IntPtr.Zero) return 0;
            var count = Marshal.ReadByte(countPtr);
            if (count == 0) return 0;

            var ridPtr = GetSidSubAuthority(pSid, (uint)(count - 1));
            if (ridPtr == IntPtr.Zero) return 0;
            return Marshal.ReadInt32(ridPtr);
        }
        catch
        {
            return 0;
        }
    }
}

internal enum IntegrityLevel
{
    Unknown = -1,
    Untrusted = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    System = 4
}

internal sealed class IntegrityRecord
{
    public int Pid { get; init; }
    public string ProcessName { get; init; } = "";
    public IntegrityLevel Level { get; set; }
    public DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen { get; set; }
}


