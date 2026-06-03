using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Plants a dummy credential in Windows Credential Manager and monitors it.
    /// Any unauthorized access/modification indicates active credential harvesting.
    /// Purely behavioral honeypot — no tool names or signatures.
    /// </summary>
    public sealed class CredentialCanaryMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<CredentialCanaryMonitor> _logger;
        private readonly System.Threading.Timer _timer;

        private const string CanaryTarget = "Sentinel_Canary_DO_NOT_USE";
        private const string CanaryUsername = "canary_tripwire";
        private bool _canaryPlanted = false;

        private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(15);

        public CredentialCanaryMonitor(
            DetectionEngine detectionEngine,
            ILogger<CredentialCanaryMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            PlantCanary();
            _timer = new System.Threading.Timer(CheckCanary, null, CheckInterval, CheckInterval);
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CredWrite(ref CREDENTIAL credential, uint flags);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credential);

        [DllImport("advapi32.dll")]
        private static extern void CredFree(IntPtr buffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public int Flags;
            public int Type;
            public string TargetName;
            public string Comment;
            public long LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }

        private const int CRED_TYPE_GENERIC = 1;
        private const int CRED_PERSIST_LOCAL_MACHINE = 2;

        private void PlantCanary()
        {
            try
            {
                var password = "SentinelCanary_" + Guid.NewGuid().ToString("N").Substring(0, 8);
                var passBytes = System.Text.Encoding.Unicode.GetBytes(password);
                var passPtr = Marshal.AllocHGlobal(passBytes.Length);
                Marshal.Copy(passBytes, 0, passPtr, passBytes.Length);

                var cred = new CREDENTIAL
                {
                    Type = CRED_TYPE_GENERIC,
                    TargetName = CanaryTarget,
                    UserName = CanaryUsername,
                    CredentialBlob = passPtr,
                    CredentialBlobSize = passBytes.Length,
                    Persist = CRED_PERSIST_LOCAL_MACHINE,
                    Comment = "WindowsSentinel honeypot credential"
                };

                if (CredWrite(ref cred, 0))
                {
                    _canaryPlanted = true;
                    _logger.LogDebug("[CredentialCanaryMonitor] Canary credential planted");
                }
                else
                {
                    _logger.LogWarning("[CredentialCanaryMonitor] CredWrite failed: {Error}", Marshal.GetLastWin32Error());
                }

                Marshal.FreeHGlobal(passPtr);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[CredentialCanaryMonitor] Failed to plant canary");
            }
        }

        private void CheckCanary(object? state)
        {
            if (!_canaryPlanted) return;

            try
            {
                if (!CredRead(CanaryTarget, CRED_TYPE_GENERIC, 0, out var credPtr))
                {
                    // Canary was deleted — credential harvester detected
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Credential Theft: Canary Credential Deleted",
                        Evidence = $"Honeypot credential '{CanaryTarget}' was removed from Windows Credential Manager",
                        Reasoning = "A canary credential planted by Sentinel was deleted, indicating active credential harvesting. Legitimate tools do not interact with Sentinel canary credentials.",
                        Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0
                    });
                    _canaryPlanted = false;
                    // Re-plant after detection
                    PlantCanary();
                }
                else
                {
                    CredFree(credPtr);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[CredentialCanaryMonitor] Check error");
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }
}
