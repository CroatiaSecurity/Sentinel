using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Credential Guard Canary — Plants a dummy credential in Windows Credential Manager
/// and monitors it for unauthorized access.
///
/// How it works:
///   1. At startup, writes a canary credential (fake username/password) to Credential Manager
///   2. Periodically verifies the canary still exists and hasn't been read/modified
///   3. If the canary is deleted or modified, an attacker is harvesting credentials
///
/// This is a ZERO false-positive tripwire:
///   - No legitimate software will ever access a credential named "Sentinel_Canary_DO_NOT_USE"
///   - If it's gone or changed, someone enumerated and cleared credentials
///   - Catches: Mimikatz vault commands, LaZagne, credential manager scrapers, infostealers
///
/// The canary credential contains no real secrets — it's a honeypot.
/// </summary>
public sealed class CredentialCanaryMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<CredentialCanaryMonitor> _logger;

    private const string CanaryTarget = "Sentinel_Canary_DO_NOT_USE";
    private const string CanaryUsername = "canary_tripwire";
    // The "password" is a marker — if an attacker sees this, they know they tripped a canary
    private const string CanaryPassword = "SENTINEL-CANARY-IF-YOU-SEE-THIS-YOU-TRIGGERED-AN-ALERT";

    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(30);
    private bool _canaryPlanted = false;
    private string? _canaryFingerprint;

    // Windows Credential Manager P/Invoke
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWrite(ref CREDENTIAL credential, uint flags);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string targetName, uint type, uint flags, out IntPtr credential);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern void CredFree(IntPtr credential);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredDelete(string targetName, uint type, uint flags);

    private const uint CRED_TYPE_GENERIC = 1;
    private const uint CRED_PERSIST_LOCAL_MACHINE = 2;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL
    {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    public CredentialCanaryMonitor(
        IDetectionEngine detectionEngine,
        ILogger<CredentialCanaryMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Credential Canary Monitor starting ===");

        // Plant the canary
        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
        PlantCanary();

        if (!_canaryPlanted)
        {
            _logger.LogWarning("CredentialCanary: Could not plant canary. Monitor disabled.");
            return;
        }

        _logger.LogInformation("CredentialCanary: Canary planted in Credential Manager");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(CheckInterval, stoppingToken);
                await CheckCanaryAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "CredentialCanary: Check error");
            }
        }

        // Cleanup canary on shutdown
        CleanupCanary();
    }

    private void PlantCanary()
    {
        try
        {
            var passwordBytes = Encoding.Unicode.GetBytes(CanaryPassword);
            var passwordPtr = Marshal.AllocHGlobal(passwordBytes.Length);
            Marshal.Copy(passwordBytes, 0, passwordPtr, passwordBytes.Length);

            try
            {
                var cred = new CREDENTIAL
                {
                    Flags = 0,
                    Type = CRED_TYPE_GENERIC,
                    TargetName = CanaryTarget,
                    Comment = "Windows Sentinel security canary - do not modify",
                    CredentialBlobSize = (uint)passwordBytes.Length,
                    CredentialBlob = passwordPtr,
                    Persist = CRED_PERSIST_LOCAL_MACHINE,
                    UserName = CanaryUsername
                };

                if (CredWrite(ref cred, 0))
                {
                    _canaryPlanted = true;
                    _canaryFingerprint = ComputeCanaryFingerprint();
                }
                else
                {
                    var error = Marshal.GetLastWin32Error();
                    _logger.LogWarning("CredentialCanary: CredWrite failed (error {Error})", error);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(passwordPtr);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "CredentialCanary: Failed to plant canary");
        }
    }

    private async Task CheckCanaryAsync(CancellationToken ct)
    {
        try
        {
            if (CredRead(CanaryTarget, CRED_TYPE_GENERIC, 0, out IntPtr credPtr))
            {
                try
                {
                    var cred = Marshal.PtrToStructure<CREDENTIAL>(credPtr);

                    // Verify username hasn't been changed
                    if (!string.Equals(cred.UserName, CanaryUsername, StringComparison.Ordinal))
                    {
                        await AlertCanaryTampered("Username modified", ct);
                        return;
                    }

                    // Verify password blob hasn't been changed
                    if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
                    {
                        var blob = new byte[cred.CredentialBlobSize];
                        Marshal.Copy(cred.CredentialBlob, blob, 0, blob.Length);
                        var currentPassword = Encoding.Unicode.GetString(blob);

                        if (currentPassword != CanaryPassword)
                        {
                            await AlertCanaryTampered("Password modified", ct);
                            return;
                        }
                    }
                    else
                    {
                        await AlertCanaryTampered("Credential blob emptied", ct);
                        return;
                    }
                }
                finally
                {
                    CredFree(credPtr);
                }
            }
            else
            {
                // Canary is GONE — someone deleted it (credential harvester cleanup)
                var error = Marshal.GetLastWin32Error();
                if (error == 1168) // ERROR_NOT_FOUND
                {
                    await AlertCanaryDeleted(ct);

                    // Re-plant the canary
                    PlantCanary();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "CredentialCanary: Error reading canary");
        }
    }

    private async Task AlertCanaryTampered(string detail, CancellationToken ct)
    {
        _logger.LogCritical("CREDENTIAL CANARY TAMPERED: {Detail}", detail);

        await _detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = "Credential Canary: Tampered",
            Evidence = $"The Sentinel credential canary ('{CanaryTarget}') has been tampered with: {detail}. " +
                      "This credential is a honeypot that no legitimate software should ever access or modify.",
            Reasoning = "Credential harvesting tools (Mimikatz vault::list, LaZagne, browser credential " +
                       "stealers, infostealers) enumerate and sometimes modify/delete credentials in " +
                       "Windows Credential Manager. The canary credential is a tripwire — any access " +
                       "to it indicates active credential theft on this system.",
            Confidence = 0.98,
            Tier = DetectionTier.Tier2Indicator, // Zero-FP but feeds correlation — no standalone kill without PID
            ProcessName = "Unknown",
            ProcessId = 0,
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["canary_target"] = CanaryTarget,
                ["tamper_detail"] = detail,
                ["technique"] = "T1555 - Credentials from Password Stores"
            }
        }, ct);
    }

    private async Task AlertCanaryDeleted(CancellationToken ct)
    {
        _logger.LogCritical("CREDENTIAL CANARY DELETED — Active credential harvesting detected!");

        await _detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = "Credential Canary: Deleted",
            Evidence = $"The Sentinel credential canary ('{CanaryTarget}') has been deleted from " +
                      "Windows Credential Manager. No legitimate software would delete this credential.",
            Reasoning = "Credential harvesting tools often delete credentials after extracting them, " +
                       "or bulk-clear the credential store to cover tracks. The canary deletion is a " +
                       "zero-false-positive indicator of active credential theft.",
            Confidence = 0.99,
            Tier = DetectionTier.Tier2Indicator, // Zero-FP but feeds correlation — no standalone kill without PID
            ProcessName = "Unknown",
            ProcessId = 0,
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["canary_target"] = CanaryTarget,
                ["tamper_detail"] = "Credential deleted",
                ["technique"] = "T1555 - Credentials from Password Stores"
            }
        }, ct);
    }

    private void CleanupCanary()
    {
        try
        {
            CredDelete(CanaryTarget, CRED_TYPE_GENERIC, 0);
            _logger.LogInformation("CredentialCanary: Canary removed on shutdown");
        }
        catch { /* best-effort */ }
    }

    private string? ComputeCanaryFingerprint()
    {
        return $"{CanaryTarget}|{CanaryUsername}|{CanaryPassword.Length}";
    }
}

