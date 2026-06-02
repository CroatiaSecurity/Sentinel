using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Credential Canary Monitor — Plants a dummy credential in Windows Credential Manager
    /// and monitors it for unauthorized access/tampering.
    /// </summary>
    public class CredentialCanaryMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<CredentialCanaryMonitor> _logger;
        private readonly System.Threading.Timer _timer;

        private const string CanaryTarget = "Sentinel_Canary_DO_NOT_USE";
        private const string CanaryUsername = "canary_tripwire";
        private const string CanaryPassword = "SENTINEL-CANARY-IF-YOU-SEE-THIS-YOU-TRIGGERED-AN-ALERT";

        private bool _canaryPlanted = false;

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
            DetectionEngine detectionEngine,
            ILogger<CredentialCanaryMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;

            // Start after 10 seconds, run every 30 seconds
            _timer = new System.Threading.Timer(OnTimerTick, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(30));
        }

        private void OnTimerTick(object? state)
        {
            try
            {
                if (!_canaryPlanted)
                {
                    PlantCanary();
                }
                else
                {
                    CheckCanary();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "CredentialCanaryMonitor check error");
            }
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
                        _logger.LogInformation("CredentialCanary: Canary successfully planted in Credential Manager.");
                    }
                    else
                    {
                        var error = Marshal.GetLastWin32Error();
                        _logger.LogWarning("CredentialCanary: CredWrite failed with error code {Error}", error);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(passwordPtr);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "CredentialCanary: Exception when planting canary.");
            }
        }

        private void CheckCanary()
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
                            AlertCanaryTampered("Username modified");
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
                                AlertCanaryTampered("Password modified");
                                return;
                            }
                        }
                        else
                        {
                            AlertCanaryTampered("Credential blob emptied");
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
                    var error = Marshal.GetLastWin32Error();
                    if (error == 1168) // ERROR_NOT_FOUND
                    {
                        AlertCanaryDeleted();
                        // Re-plant next interval
                        _canaryPlanted = false;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "CredentialCanary: Error checking canary credential");
            }
        }

        private void AlertCanaryTampered(string detail)
        {
            _logger.LogCritical("CREDENTIAL CANARY TAMPERED: {Detail}", detail);

            var detection = new DetectionEvent
            {
                RuleName = "Credential Canary: Tampered",
                Evidence = $"The Sentinel credential canary ('{CanaryTarget}') has been tampered with: {detail}. This credential is a honeypot that no legitimate software should ever access or modify.",
                Reasoning = "Credential harvesting tools (Mimikatz vault::list, LaZagne, browser credential stealers, infostealers) enumerate and sometimes modify/delete credentials in Windows Credential Manager. The canary credential is a tripwire — any access to it indicates active credential theft on this system.",
                Confidence = 0.98,
                Tier = DetectionTier.Tier2Indicator, // Zero-FP but feeds correlation — no standalone kill without PID
                ProcessName = "Unknown",
                ProcessId = 0,
                Timestamp = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["canary_target"] = CanaryTarget,
                    ["tamper_detail"] = detail,
                    ["technique"] = "T1555 - Credentials from Password Stores"
                }
            };

            _ = _detectionEngine.EmitAsync(detection);
        }

        private void AlertCanaryDeleted()
        {
            _logger.LogCritical("CREDENTIAL CANARY DELETED — Active credential harvesting detected!");

            var detection = new DetectionEvent
            {
                RuleName = "Credential Canary: Deleted",
                Evidence = $"The Sentinel credential canary ('{CanaryTarget}') has been deleted from Windows Credential Manager. No legitimate software would delete this credential.",
                Reasoning = "Credential harvesting tools often delete credentials after extracting them, or bulk-clear the credential store to cover tracks. The canary deletion is a zero-false-positive indicator of active credential theft.",
                Confidence = 0.99,
                Tier = DetectionTier.Tier2Indicator, // Zero-FP but feeds correlation — no standalone kill without PID
                ProcessName = "Unknown",
                ProcessId = 0,
                Timestamp = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["canary_target"] = CanaryTarget,
                    ["tamper_detail"] = "Credential deleted",
                    ["technique"] = "T1555 - Credentials from Password Stores"
                }
            };

            _ = _detectionEngine.EmitAsync(detection);
        }

        private void CleanupCanary()
        {
            try
            {
                if (_canaryPlanted)
                {
                    CredDelete(CanaryTarget, CRED_TYPE_GENERIC, 0);
                    _logger.LogInformation("CredentialCanary: Canary removed on shutdown");
                }
            }
            catch { /* best-effort */ }
        }

        public void Dispose()
        {
            _timer.Dispose();
            CleanupCanary();
            GC.SuppressFinalize(this);
        }
    }
}
