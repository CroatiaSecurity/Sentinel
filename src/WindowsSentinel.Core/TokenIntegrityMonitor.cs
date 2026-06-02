using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    public class TokenIntegrityMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<TokenIntegrityMonitor> _logger;
        private readonly System.Threading.Timer _timer;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(45);

        private readonly ConcurrentDictionary<int, IntegrityRecord> _knownIntegrity = new();

        private static readonly HashSet<string> ExcludedProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "consent.exe",
            "svchost.exe",
            "services.exe",
            "lsass.exe",
            "csrss.exe",
            "wininit.exe",
            "winlogon.exe",
            "smss.exe",
            "system",
            "registry"
        };

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInfoClass,
            IntPtr tokenInfo, int tokenInfoLength, out int returnLength);

        [DllImport("advapi32.dll")]
        private static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);

        [DllImport("advapi32.dll")]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const uint TOKEN_QUERY = 0x0008;
        private const int TokenIntegrityLevel = 25;

        private const int SECURITY_MANDATORY_LOW_RID = 0x1000;
        private const int SECURITY_MANDATORY_MEDIUM_RID = 0x2000;
        private const int SECURITY_MANDATORY_HIGH_RID = 0x3000;
        private const int SECURITY_MANDATORY_SYSTEM_RID = 0x4000;

        public TokenIntegrityMonitor(
            DetectionEngine detectionEngine,
            ILogger<TokenIntegrityMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            // Scan process tokens every 45 seconds
            _timer = new System.Threading.Timer(ScanProcessIntegrity, null, TimeSpan.FromSeconds(15), ScanInterval);
        }

        private void ScanProcessIntegrity(object? state)
        {
            try
            {
                var selfPid = Environment.ProcessId;
                var processes = Process.GetProcesses();

                foreach (var process in processes)
                {
                    try
                    {
                        var pid = process.Id;
                        if (pid <= 4 || pid == selfPid) continue;
                        if (ExcludedProcesses.Contains(process.ProcessName)) continue;

                        var integrity = GetProcessIntegrityLevel(pid);
                        if (integrity == IntegrityLevel.Unknown) continue;

                        if (_knownIntegrity.TryGetValue(pid, out var previous))
                        {
                            if (integrity > previous.Level && previous.Level != IntegrityLevel.Unknown)
                            {
                                _logger.LogCritical($"TOKEN INTEGRITY ESCALATION: '{process.ProcessName}' (PID {pid}) went from {previous.Level} to {integrity}");

                                var alert = new DetectionEvent
                                {
                                    RuleName = "Privilege Escalation: Token Integrity Change",
                                    ProcessName = process.ProcessName + ".exe",
                                    ProcessId = pid,
                                    Confidence = 0.93,
                                    Tier = DetectionTier.Tier2Indicator,
                                    Evidence = $"Process '{process.ProcessName}' (PID {pid}) integrity level changed from {previous.Level} to {integrity} without UAC consent.",
                                    Reasoning = "A process's integrity level increased without going through the normal UAC elevation path (consent.exe). This indicates token manipulation, UAC bypass exploit, or privilege escalation via named pipe impersonation.",
                                    Timestamp = DateTime.UtcNow,
                                    Metadata = new Dictionary<string, string>
                                    {
                                        { "previous_integrity", previous.Level.ToString() },
                                        { "current_integrity", integrity.ToString() },
                                        { "technique", "T1134 - Access Token Manipulation" }
                                    }
                                };

                                _ = _detectionEngine.EmitAsync(alert);
                            }

                            previous.Level = integrity;
                            previous.LastSeen = DateTimeOffset.UtcNow;
                        }
                        else
                        {
                            _knownIntegrity[pid] = new IntegrityRecord
                            {
                                Pid = pid,
                                ProcessName = process.ProcessName,
                                Level = integrity,
                                FirstSeen = DateTimeOffset.UtcNow,
                                LastSeen = DateTimeOffset.UtcNow
                            };
                        }
                    }
                    catch (InvalidOperationException) { }
                    catch (System.ComponentModel.Win32Exception) { }
                    finally
                    {
                        process.Dispose();
                    }
                }

                // Cleanup dead processes
                var deadPids = _knownIntegrity.Keys.Where(pid =>
                {
                    try { using var p = Process.GetProcessById(pid); return false; }
                    catch { return true; }
                }).ToList();

                foreach (var pid in deadPids)
                {
                    _knownIntegrity.TryRemove(pid, out _);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"TokenIntegrityMonitor error: {ex.Message}");
            }
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
                    GetTokenInformation(hToken, TokenIntegrityLevel, IntPtr.Zero, 0, out int needed);
                    if (needed == 0) return IntegrityLevel.Unknown;

                    var buffer = Marshal.AllocHGlobal(needed);
                    try
                    {
                        if (!GetTokenInformation(hToken, TokenIntegrityLevel, buffer, needed, out _))
                            return IntegrityLevel.Unknown;

                        var sidPtr = Marshal.ReadIntPtr(buffer);
                        if (sidPtr == IntPtr.Zero) return IntegrityLevel.Unknown;

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

        public void Dispose()
        {
            _timer.Dispose();
            GC.SuppressFinalize(this);
        }

        private enum IntegrityLevel
        {
            Unknown = -1,
            Untrusted = 0,
            Low = 1,
            Medium = 2,
            High = 3,
            System = 4
        }

        private class IntegrityRecord
        {
            public int Pid { get; set; }
            public string ProcessName { get; set; } = string.Empty;
            public IntegrityLevel Level { get; set; }
            public DateTimeOffset FirstSeen { get; set; }
            public DateTimeOffset LastSeen { get; set; }
        }
    }
}
