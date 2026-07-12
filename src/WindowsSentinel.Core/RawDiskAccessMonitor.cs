using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Detects processes performing raw disk I/O by opening physical disk
    /// device paths (\\.\PhysicalDrive0, \\.\C:, etc.) directly.
    ///
    /// Raw disk access bypasses the filesystem entirely — no FileSystemWatcher,
    /// no NTFS journaling, no file-level ADS verdicts. Attackers use this to:
    /// - Read/write disk sectors without triggering file monitors
    /// - Bypass NTFS ACLs and encryption
    /// - Plant bootkits directly to MBR/VBR
    /// - Exfiltrate data below filesystem abstraction
    ///
    /// Detection method: Periodic process handle scan looking for open handles
    /// to PhysicalDrive or volume device objects.
    ///
    /// v1.0.1: New monitor.
    /// </summary>
    public sealed class RawDiskAccessMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SignerTrustService _signerTrust;
        private readonly ILogger<RawDiskAccessMonitor> _logger;
        private readonly SentinelConfig _config;
        private readonly TimeSpan _scanInterval;

        private readonly ConcurrentDictionary<(int Pid, string Device), DateTimeOffset> _alertedAccess = new();
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);

        // Legitimate processes that access raw disk.
        // SECURITY NOTE: Name-only matching is NOT sufficient. The allowlist check
        // in ScanForRawDiskHandles also verifies the binary is:
        //   1. Located in a Windows system directory (%SystemRoot%)
        //   2. Has a valid Authenticode signature (via IsSignedSystemBinary)
        // An attacker naming malware "Taskmgr.exe" in a non-system path will FAIL
        // both checks and be detected normally.
        private static readonly HashSet<string> AllowedProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            // Windows built-in disk/system management tools
            "vds", "vdsldr", "diskmgmt", "diskpart", "defrag",
            "chkdsk", "sfc", "dism", "wbengine", "vssvc",
            "msiexec", "trustedinstaller", "tiworker",
            // v1.3.10: DISM host worker and NTLite open raw volume handles during WIM mount/unmount
            // and offline image servicing — these are legitimate OS-image operations.
            "dismhost", "ntlite",
            // Arsenal Image Mounter and similar WIM/ISO mounting tools open virtual disk handles
            "imagemounter", "arsenalimager", "aimdevice", "aim_ll",
            // Windows monitoring tools that legitimately enumerate disk handles
            "Taskmgr", "resmon", "perfmon", "mmc", "SystemInformer",
            // Hypervisor/VM tools
            "vboxsvc", "vboxheadless", "vmware-vmx", "vmms",
            "wudfhost", "storagecraft", "veeam", "acronis",
            "macrium", "clonezilla", "dd", "wimgapi",
            "WindowsSentinel.Service", "WindowsSentinel.Agent", // Self-exclusion
            "svchost", "taskhostw", "services", "system" // Legitimate system processes accessing raw disk
        };

        // NT kernel object manager paths that indicate raw disk access
        private static readonly string[] RawDiskPatterns = new[]
        {
            @"\\.\PhysicalDrive",
            @"\\.\PHYSICALDRIVE",
            @"\Device\Harddisk",
            @"\Device\HarddiskVolume",
            @"\\.\GLOBALROOT\Device\Harddisk",
            @"\\.\Volume{",
            @"\\.\Scsi"
        };

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int bufferSize, out int returnLength);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryObject(IntPtr handle, int infoClass, IntPtr buffer, int bufferSize, out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(int access, bool inheritHandle, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DuplicateHandle(IntPtr hSourceProcess, IntPtr hSourceHandle,
            IntPtr hTargetProcess, out IntPtr hTargetHandle, int access, bool inherit, int options);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        private const int PROCESS_DUP_HANDLE = 0x0040;
        private const int DUPLICATE_SAME_ACCESS = 0x0002;
        private const int SystemHandleInformation = 16;
        private const int ObjectNameInformation = 1;

        public RawDiskAccessMonitor(
            DetectionEngine detectionEngine,
            SignerTrustService signerTrust,
            SentinelConfig config,
            ILogger<RawDiskAccessMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _signerTrust = signerTrust;
            _config = config;
            _logger = logger;
            _scanInterval = TimeSpan.FromSeconds(config.RawDiskScanIntervalSeconds > 0 ? config.RawDiskScanIntervalSeconds : 20);
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[RawDiskAccessMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_scanInterval, ct);
                    await ScanForRawDiskHandles(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[RawDiskAccessMonitor] Error"); }
            }
        }

        private async Task ScanForRawDiskHandles(CancellationToken ct)
        {
            // Use WMI to enumerate processes with open handles to disk devices
            // This is more reliable than NtQuerySystemInformation for userland
            try
            {
                var selfPid = Environment.ProcessId;
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (ct.IsCancellationRequested) break;

                        // Hard self-exclusion: never detect our own process
                        if (proc.Id == selfPid) continue;

                        var procName = proc.ProcessName;

                        // Skip allowed processes — but only if running from expected system paths
                        // AND validly signed. An attacker could name malware "Taskmgr.exe" in a
                        // user-writable directory — the dual check (path + signature) prevents bypass.
                        if (AllowedProcesses.Contains(procName))
                        {
                            string? allowedPath = null;
                            try { allowedPath = SecurityValidation.GetProcessImagePath(proc.Id); } catch { }
                            if (!string.IsNullOrEmpty(allowedPath) &&
                                IsInWindowsDirectory(allowedPath) &&
                                IsSignedSystemBinary(allowedPath))
                                continue;
                            // Name matches but path or signature is suspicious — fall through to detection
                        }

                        // Check if process has any open device handles matching raw disk patterns
                        var deviceHandles = GetProcessDeviceHandles(proc.Id);
                        foreach (var devicePath in deviceHandles)
                        {
                            if (!IsRawDiskPath(devicePath)) continue;

                            var key = (proc.Id, devicePath);
                            if (_alertedAccess.TryGetValue(key, out var lastAlert) &&
                                DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                                continue;

                            _alertedAccess[key] = DateTimeOffset.UtcNow;

                            // Check if the process is signed by a trusted publisher
                            bool isTrusted = false;
                            try
                            {
                                var mainModule = SecurityValidation.GetProcessImagePath(proc.Id);
                                if (mainModule != null)
                                    isTrusted = _signerTrust.IsSignedFile(mainModule);
                            }
                            catch { }

                            var confidence = isTrusted ? 0.55 : 0.85;
                            var tier = isTrusted ? DetectionTier.Tier2Indicator : DetectionTier.Tier1Behavioral;
                            var response = isTrusted ? ResponseAction.LogOnly : ResponseAction.KillProcessTree;

                            string imagePath = "";
                            try { imagePath = SecurityValidation.GetProcessImagePath(proc.Id) ?? ""; } catch { }

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Raw Disk Access: Direct Physical Device I/O",
                                Evidence = $"Process '{procName}' (PID {proc.Id}, Path: {imagePath}) " +
                                           $"has open handle to raw device: {devicePath}",
                                Reasoning = "A process has opened a raw disk device path (e.g., \\\\.\\PhysicalDrive0), " +
                                            "bypassing the filesystem layer entirely. This allows reading/writing disk sectors " +
                                            "without triggering file-level monitors, NTFS journaling, or ADS verdict tags. " +
                                            "Legitimate uses include disk management and backup tools. Malicious uses include " +
                                            "bootkit installation, forensic evidence wiping, and filesystem-level exfiltration.",
                                Confidence = confidence,
                                Tier = tier,
                                AuthorizedResponse = response,
                                ProcessName = procName,
                                ProcessId = proc.Id,
                                SignalType = SignalType.SuspiciousProcess,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["DevicePath"] = devicePath,
                                    ["ImagePath"] = imagePath,
                                    ["IsTrusted"] = isTrusted.ToString()
                                }
                            });
                        }
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch { }

            // Cleanup stale alerts
            var stale = _alertedAccess
                .Where(kv => DateTimeOffset.UtcNow - kv.Value > TimeSpan.FromHours(1))
                .Select(kv => kv.Key).ToList();
            foreach (var key in stale) _alertedAccess.TryRemove(key, out _);
        }

        private List<string> GetProcessDeviceHandles(int pid)
        {
            var results = new List<string>();

            // Use WMI CIM_DataFile association — more reliable than kernel handle enum
            // for detecting processes that have opened device objects
            IntPtr processHandle = IntPtr.Zero;
            try
            {
                processHandle = OpenProcess(PROCESS_DUP_HANDLE, false, pid);
                if (processHandle == IntPtr.Zero) return results;

                // Query system handles filtered by PID
                int bufferSize = 1024 * 1024; // 1MB initial
                IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
                try
                {
                    int status;
                    int returnLength;

                    // Retry with larger buffer if needed
                    for (int attempt = 0; attempt < 3; attempt++)
                    {
                        status = NtQuerySystemInformation(SystemHandleInformation, buffer, bufferSize, out returnLength);
                        if (status == 0) break; // STATUS_SUCCESS
                        if (status == unchecked((int)0xC0000004)) // STATUS_INFO_LENGTH_MISMATCH
                        {
                            Marshal.FreeHGlobal(buffer);
                            bufferSize = returnLength + 4096;
                            buffer = Marshal.AllocHGlobal(bufferSize);
                        }
                        else break;
                    }

                    // Parse handle entries
                    int handleCount = Marshal.ReadInt32(buffer);
                    int entrySize = IntPtr.Size == 8 ? 26 : 16; // Approximate SYSTEM_HANDLE_INFORMATION entry size
                    int offset = IntPtr.Size; // Skip count field

                    int maxHandles = Math.Min(handleCount, 100000); // Safety cap

                    for (int i = 0; i < maxHandles && offset + entrySize <= bufferSize; i++)
                    {
                        int ownerPid;
                        IntPtr handleValue;

                        if (IntPtr.Size == 8)
                        {
                            // 64-bit: UniqueProcessId is at offset 0 (4 bytes)
                            ownerPid = Marshal.ReadInt32(buffer, offset);
                            // Handle is at offset 8 (2 bytes, but read as IntPtr)
                            handleValue = new IntPtr(Marshal.ReadInt16(buffer, offset + 6));
                        }
                        else
                        {
                            ownerPid = Marshal.ReadInt16(buffer, offset);
                            handleValue = new IntPtr(Marshal.ReadInt16(buffer, offset + 2));
                        }

                        offset += entrySize;

                        if (ownerPid != pid) continue;

                        // Try to get the object name by duplicating the handle
                        IntPtr dupHandle = IntPtr.Zero;
                        try
                        {
                            if (!DuplicateHandle(processHandle, handleValue,
                                GetCurrentProcess(), out dupHandle, 0, false, DUPLICATE_SAME_ACCESS))
                                continue;

                            var name = GetObjectName(dupHandle);
                            if (!string.IsNullOrEmpty(name) && IsRawDiskPath(name))
                            {
                                results.Add(name);
                                if (results.Count >= 5) break; // Don't enumerate everything
                            }
                        }
                        catch { }
                        finally
                        {
                            if (dupHandle != IntPtr.Zero) CloseHandle(dupHandle);
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch { }
            finally
            {
                if (processHandle != IntPtr.Zero) CloseHandle(processHandle);
            }

            return results;
        }

        private static string? GetObjectName(IntPtr handle)
        {
            int bufferSize = 1024;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                int status = NtQueryObject(handle, ObjectNameInformation, buffer, bufferSize, out _);
                if (status != 0) return null;

                // UNICODE_STRING structure: Length (2), MaxLength (2), Buffer (ptr)
                int length = Marshal.ReadInt16(buffer);
                if (length == 0) return null;

                IntPtr namePtr = Marshal.ReadIntPtr(buffer, IntPtr.Size); // After the UNICODE_STRING header
                if (IntPtr.Size == 8)
                    namePtr = Marshal.ReadIntPtr(buffer, 8);
                else
                    namePtr = Marshal.ReadIntPtr(buffer, 4);

                return Marshal.PtrToStringUni(namePtr, length / 2);
            }
            catch { return null; }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        /// <summary>
        /// Verifies a binary is a legitimate system tool by checking its Authenticode signature.
        /// No path-based trust — only signature verification.
        /// </summary>
        private bool IsSignedSystemBinary(string imagePath)
        {
            return _signerTrust.IsSignedFile(imagePath);
        }

        /// <summary>
        /// Checks if a binary resides within the Windows directory hierarchy.
        /// This includes System32, SysWOW64, WinSxS, and other Windows-owned paths.
        /// Used as a FIRST gate before signature verification to reduce attack surface.
        /// An attacker cannot place files in %SystemRoot% without elevation + bypassing WRP.
        /// </summary>
        private static bool IsInWindowsDirectory(string imagePath)
        {
            if (string.IsNullOrEmpty(imagePath)) return false;
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (string.IsNullOrEmpty(winDir)) return false;
            var winDirTrailing = winDir.EndsWith('\\') ? winDir : winDir + '\\';
            return imagePath.StartsWith(winDirTrailing, StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsRawDiskPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;

            // If it contains a subpath after the device prefix, it is a file/directory handle inside the volume, not raw disk access.
            // Example of raw: \Device\HarddiskVolume3 or \Device\HarddiskVolume3\ or \\.\PhysicalDrive0
            // Example of file: \Device\HarddiskVolume3\Windows\System32\winlogon.exe
            
            // 1. Check if it matches any pattern
            bool matches = RawDiskPatterns.Any(p => path.Contains(p, StringComparison.OrdinalIgnoreCase));
            if (!matches) return false;

            // 2. If it is a file/folder inside a volume (has a subpath), ignore it.
            // A subpath is indicated by a backslash after the volume name.
            if (path.StartsWith(@"\Device\HarddiskVolume", StringComparison.OrdinalIgnoreCase))
            {
                var remaining = path[@"\Device\HarddiskVolume".Length..];
                int firstBackslash = remaining.IndexOf('\\');
                if (firstBackslash >= 0 && firstBackslash < remaining.Length - 1)
                {
                    return false;
                }
            }
            else if (path.StartsWith(@"\Device\Harddisk", StringComparison.OrdinalIgnoreCase))
            {
                var remaining = path[@"\Device\Harddisk".Length..];
                if (remaining.Contains("Volume", StringComparison.OrdinalIgnoreCase))
                {
                    int volIdx = remaining.IndexOf("Volume", StringComparison.OrdinalIgnoreCase);
                    var volRemaining = remaining[(volIdx + "Volume".Length)..];
                    int firstBackslash = volRemaining.IndexOf('\\');
                    if (firstBackslash >= 0 && firstBackslash < volRemaining.Length - 1)
                    {
                        return false;
                    }
                }
            }

            return true;
        }
    }
}
