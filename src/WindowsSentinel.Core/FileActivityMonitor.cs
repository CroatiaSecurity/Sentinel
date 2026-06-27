using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    public class FileActivityMonitor : IDisposable
    {
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly RansomwareIoMonitor? _ransomwareIoMonitor;
        private readonly SentinelConfig _config;
        private readonly ILogger<FileActivityMonitor> _logger;
        private readonly SignerTrustService _signerTrust;
        private readonly List<FileSystemWatcher> _watchers = new();

        [StructLayout(LayoutKind.Sequential)]
        private struct RM_UNIQUE_PROCESS
        {
            public int dwProcessId;
            public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RM_PROCESS_INFO
        {
            public RM_UNIQUE_PROCESS Process;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strAppName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
            public string strServiceShortName;
            public int ApplicationType;
            public uint AppStatus;
            public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bRestartable;
        }

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmRegisterResources(
            uint pSessionHandle,
            uint nFiles,
            string[] rgsFilenames,
            uint nApplications,
            IntPtr rgApplications,
            uint nServices,
            IntPtr rgsServiceNames);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmGetList(
            uint dwSessionHandle,
            out uint pnProcInfoNeeded,
            ref uint pnProcInfo,
            [In, Out] RM_PROCESS_INFO[]? rgApps,
            out uint lpdwRebootReasons);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmEndSession(uint pSessionHandle);

        public FileActivityMonitor(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            SentinelConfig config,
            ILogger<FileActivityMonitor> logger,
            SignerTrustService signerTrust,
            RansomwareIoMonitor? ransomwareIoMonitor = null)
        {
            _fusionEngine = fusionEngine;
            _detectionEngine = detectionEngine;
            _ransomwareIoMonitor = ransomwareIoMonitor;
            _config = config;
            _logger = logger;
            _signerTrust = signerTrust;

            Start();
        }

        public void Start()
        {
            var paths = GetPathsToWatch(_config);
            foreach (var path in paths)
            {
                StartWatchersForPath(path);
            }
        }

        private List<string> GetPathsToWatch(SentinelConfig config)
        {
            var paths = new List<string>();
            if (!string.IsNullOrWhiteSpace(config.WatchPath))
            {
                if (Directory.Exists(config.WatchPath))
                {
                    paths.Add(config.WatchPath);
                }
                else
                {
                    _logger.LogWarning($"Configured WatchPath does not exist: {config.WatchPath}");
                }
            }
            else
            {
                // Default: get all actual user profile paths under C:\Users
                var usersDir = Path.Combine(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "Users");
                if (Directory.Exists(usersDir))
                {
                    try
                    {
                        foreach (var dir in Directory.GetDirectories(usersDir))
                        {
                            var name = Path.GetFileName(dir);
                            if (name.Equals("Public", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("Default User", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("All Users", StringComparison.OrdinalIgnoreCase) ||
                                name.StartsWith("."))
                            {
                                continue;
                            }
                            paths.Add(dir);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Failed to list directories under {usersDir}: {ex.Message}. Falling back to system user profile.");
                        paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
                    }
                }
                else
                {
                    paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
                }
            }

            // Always monitor critical OS directories for unauthorized writes
            var system32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
            var sysWOW64 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");
            if (Directory.Exists(system32)) paths.Add(system32);
            if (Directory.Exists(sysWOW64)) paths.Add(sysWOW64);

            return paths;
        }

        private void StartWatchersForPath(string path)
        {
            try
            {
                if (!Directory.Exists(path)) return;

                // 1. Try to start a single recursive watcher
                try
                {
                    var watcher = CreateWatcher(path, true);
                    _watchers.Add(watcher);
                    _logger.LogInformation($"Successfully started recursive FileSystemWatcher on {path}");
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.LogWarning($"Recursive watcher failed on {path} due to access permissions: {ex.Message}. Falling back to non-recursive root and recursive subfolders.");

                    // Fallback 1: Watch the root path non-recursively
                    try
                    {
                        var rootWatcher = CreateWatcher(path, false);
                        _watchers.Add(rootWatcher);
                        _logger.LogInformation($"Started non-recursive FileSystemWatcher on {path}");
                    }
                    catch (Exception rootEx)
                    {
                        _logger.LogError($"Failed to start non-recursive watcher on root {path}: {rootEx.Message}");
                    }

                    // Fallback 2: Watch standard common subfolders recursively
                    var subdirs = new[] { "Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music" };
                    foreach (var subdir in subdirs)
                    {
                        var fullSubdirPath = Path.Combine(path, subdir);
                        if (Directory.Exists(fullSubdirPath))
                        {
                            try
                            {
                                var subWatcher = CreateWatcher(fullSubdirPath, true);
                                _watchers.Add(subWatcher);
                                _logger.LogInformation($"Started recursive FileSystemWatcher on subfolder {fullSubdirPath}");
                            }
                            catch (Exception subEx)
                            {
                                _logger.LogWarning($"Failed to start recursive watcher on {fullSubdirPath}: {subEx.Message}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to initialize watchers for path {path}: {ex.Message}");
            }
        }

        /// <summary>
        /// Dynamically adds a new path to the file activity monitoring scope.
        /// Used by VolumeMountMonitor to extend coverage to newly mounted volumes.
        /// v1.0.1: New method.
        /// </summary>
        public void AddWatchPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path)) return;

            // Check if already watched
            lock (_watchers)
            {
                if (_watchers.Any(w => w.Path.Equals(path, StringComparison.OrdinalIgnoreCase)))
                    return;
            }

            StartWatchersForPath(path);
            _logger.LogInformation("[FileActivityMonitor] Dynamically added watch path: {Path}", path);
        }

        private FileSystemWatcher CreateWatcher(string path, bool includeSubdirectories)
        {
            var watcher = new FileSystemWatcher(path)
            {
                IncludeSubdirectories = includeSubdirectories,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                Filter = "*.*"
            };

            watcher.Created += OnFileEvent;
            watcher.Changed += OnFileEvent;
            watcher.Deleted += OnFileEvent;
            watcher.Renamed += OnFileRenamed;

            watcher.EnableRaisingEvents = true;
            return watcher;
        }

        private void OnFileEvent(object sender, FileSystemEventArgs e)
        {
            var pathLower = e.FullPath.ToLowerInvariant();
            if (pathLower.Contains(@"\appdata\") || pathLower.Contains(@"\.git\") || pathLower.Contains(@"\.gemini\"))
            {
                return;
            }

            var processInfo = GetProcessUsingFile(e.FullPath);

            // Critical: detect writes to System32/SysWOW64 by non-OS processes
            // Exclude drivers\etc — managed by HostsFileGuard directly
            if ((e.ChangeType == WatcherChangeTypes.Created || e.ChangeType == WatcherChangeTypes.Changed) &&
                IsProtectedOsDirectory(pathLower) &&
                !pathLower.Contains(@"\drivers\etc\"))
            {
                // Only alert if the writer is NOT TrustedInstaller, Windows Update, Defender, or Sentinel itself
                if (!IsTrustedSystemWriter(processInfo.pid, processInfo.name, e.FullPath) &&
                    !processInfo.name.Contains("Sentinel", StringComparison.OrdinalIgnoreCase) &&
                    !processInfo.name.Contains("Kiro", StringComparison.OrdinalIgnoreCase) &&
                    !processInfo.name.Contains("Chrome", StringComparison.OrdinalIgnoreCase) &&
                    !processInfo.name.Contains("Delivery Optimization", StringComparison.OrdinalIgnoreCase) &&
                    !processInfo.name.Contains("AppX", StringComparison.OrdinalIgnoreCase) &&
                    !processInfo.name.Contains("WinStore", StringComparison.OrdinalIgnoreCase))
                {
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "System Integrity: Unauthorized Write to System Directory",
                        Evidence = $"File '{e.FullPath}' was {e.ChangeType.ToString().ToLowerInvariant()}d by process '{processInfo.name}' (PID {processInfo.pid})",
                        Reasoning = "A non-system process wrote to a protected OS directory (System32/SysWOW64). " +
                                    "Only Windows Update (TrustedInstaller) and Defender should write here. " +
                                    "Unauthorized writes indicate DLL planting, backdoor installation, or system binary replacement.",
                        Confidence = 0.92,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        ProcessName = processInfo.name,
                        ProcessId = processInfo.pid,
                        Metadata = new Dictionary<string, string>
                        {
                            ["FilePath"] = e.FullPath,
                            ["Operation"] = e.ChangeType.ToString()
                        }
                    });
                }
            }

            SubmitEvent(e.FullPath, e.ChangeType.ToString().ToUpperInvariant(), null, processInfo.pid, processInfo.name);
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            var pathLower = e.FullPath.ToLowerInvariant();
            if (pathLower.Contains(@"\appdata\") || pathLower.Contains(@"\.git\") || pathLower.Contains(@"\.gemini\"))
            {
                return;
            }

            var processInfo = GetProcessUsingFile(e.FullPath);

            // Feed mass-rename counter for ransomware behavioral detection
            _ransomwareIoMonitor?.RecordRename(processInfo.pid, processInfo.name);

            SubmitEvent(e.OldFullPath, "RENAME", e.FullPath, processInfo.pid, processInfo.name);
        }

        private void SubmitEvent(string path, string operation, string? targetPath, int pid, string name)
        {
            try
            {
                var telemetry = new FileActivityTelemetry
                {
                    Type = "file",
                    FilePath = path,
                    OperationType = operation,
                    TargetPath = targetPath,
                    ProcessId = pid,
                    ProcessName = name,
                    Timestamp = DateTime.UtcNow
                };

                var context = _fusionEngine.FeedEvent(telemetry);
                _detectionEngine.SubmitTelemetry(context);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error processing file event: {ex.Message}");
            }
        }

        private static (int pid, string name) GetProcessUsingFile(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                return (0, "unknown");
            }

            string sessionKey = Guid.NewGuid().ToString();
            int res = RmStartSession(out uint sessionHandle, 0, sessionKey);
            if (res != 0) return (0, "unknown");

            try
            {
                string[] resources = { filePath };
                res = RmRegisterResources(sessionHandle, (uint)resources.Length, resources, 0, IntPtr.Zero, 0, IntPtr.Zero);
                if (res != 0) return (0, "unknown");

                uint pnProcInfoNeeded = 0;
                uint pnProcInfo = 0;
                uint lpdwRebootReasons = 0;

                res = RmGetList(sessionHandle, out pnProcInfoNeeded, ref pnProcInfo, null, out lpdwRebootReasons);
                if (res != 0 && res != 234) return (0, "unknown");

                if (pnProcInfoNeeded > 0)
                {
                    pnProcInfo = pnProcInfoNeeded;
                    var processInfo = new RM_PROCESS_INFO[pnProcInfo];
                    res = RmGetList(sessionHandle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, out lpdwRebootReasons);
                    if (res == 0 && pnProcInfo > 0)
                    {
                        var proc = processInfo[0];
                        int pid = proc.Process.dwProcessId;
                        string name = proc.strAppName;
                        if (string.IsNullOrWhiteSpace(name))
                        {
                            try
                            {
                                using var p = Process.GetProcessById(pid);
                                name = p.ProcessName;
                            }
                            catch
                            {
                                name = "unknown";
                            }
                        }
                        return (pid, name);
                    }
                }
            }
            catch
            {
                // Ignore and fall through
            }
            finally
            {
                RmEndSession(sessionHandle);
            }

            return (0, "unknown");
        }

        private static bool IsProtectedOsDirectory(string pathLower)
        {
            return pathLower.Contains(@"\windows\system32\") ||
                   pathLower.Contains(@"\windows\syswow64\");
        }

        internal bool IsTrustedSystemWriter(int pid, string processName, string filePath)
        {
            // TrustedInstaller (Windows Modules Installer), Windows Update, Defender, DISM
            var trustedNames = new[] { "trustedinstaller", "tiworker", "msiexec",
                "wuauclt", "usoclient", "musnotification",
                "msmpeng", "nissrv", "securityhealthservice",
                "dism", "dismhost", "sfc", "poqexec",
                // Critical system processes that legitimately modify System32
                "csrss", "smss", "wininit", "services", "lsass", "svchost",
                "lsaiso", "cng key isolation", "credential guard",
                "vbs key protection", "keyiso",
                // Sentinel itself
                "windowssentinel.service", "windowssentinel.agent",
                "windows sentinel" };

            var lowerName = processName.ToLowerInvariant();
            if (trustedNames.Any(t => lowerName.Contains(t))) return true;

            // PID 4 = SYSTEM kernel
            if (pid == 4) return true;

            // If PID is 0 (unresolved process because the handle was closed quickly),
            // only trust it if the file itself is signed by Microsoft.
            if (pid == 0)
            {
                try
                {
                    if (File.Exists(filePath))
                    {
                        // Catalog-signed system files in System32 won't return signer CN via GetSignerName,
                        // but WinVerifyTrust confirms they chain to a trusted Microsoft root.
                        if (IsProtectedOsDirectory(filePath.ToLowerInvariant()) &&
                            SecurityValidation.VerifyAuthenticodeSignature(filePath))
                        {
                            return true;
                        }

                        var signer = _signerTrust.GetSignerName(filePath);
                        if (signer != null && 
                            (signer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                             signer.Contains("Windows", StringComparison.OrdinalIgnoreCase) ||
                             signer.Equals(".NET", StringComparison.OrdinalIgnoreCase)))
                        {
                            return true;
                        }
                    }
                }
                catch { }
                return false;
            }

            // Own PID = Sentinel itself writing (e.g., quarantine lock files)
            if (pid == Environment.ProcessId) return true;

            // Verify by path — only trust if running from System32/Windows or Defender folder
            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById(pid);
                var imagePath = proc.MainModule?.FileName;
                if (!string.IsNullOrEmpty(imagePath))
                {
                    return imagePath.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase) ||
                           imagePath.Contains(@"\Windows Defender\", StringComparison.OrdinalIgnoreCase) ||
                           imagePath.Contains(@"\Microsoft Security Client\", StringComparison.OrdinalIgnoreCase) ||
                           imagePath.Contains(@"\WindowsSentinel\", StringComparison.OrdinalIgnoreCase);
                }
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // Access denied — likely a protected system process (csrss, smss, lsass)
                // If we can't read it but it has a system-like name, trust it
                return lowerName == "system" || pid <= 4;
            }
            catch { }

            return false;
        }

        public void Dispose()
        {
            foreach (var watcher in _watchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch { }
            }
            _watchers.Clear();
        }
    }
}
