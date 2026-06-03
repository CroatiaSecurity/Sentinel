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
        private readonly SentinelConfig _config;
        private readonly ILogger<FileActivityMonitor> _logger;
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
            ILogger<FileActivityMonitor> logger)
        {
            _fusionEngine = fusionEngine;
            _detectionEngine = detectionEngine;
            _config = config;
            _logger = logger;

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

            // Always watch Sentinel's own installation folder to prevent tampering
            var appDir = AppContext.BaseDirectory.TrimEnd('\\');
            if (Directory.Exists(appDir) && !paths.Contains(appDir))
            {
                paths.Add(appDir);
            }

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
            var processInfo = GetProcessUsingFile(e.FullPath);

            if (IsSentinelTampering(e.FullPath, processInfo.pid, processInfo.name, out var tamperReason))
            {
                TryDeleteFile(e.FullPath);
                SubmitTamperAlert(e.FullPath, processInfo.pid, processInfo.name, tamperReason!);
                return;
            }

            if (IsSuspiciousDbghelpDrop(e.FullPath, out var dropReason))
            {
                if (!IsWriterTrusted(processInfo.pid, processInfo.name))
                {
                    TryDeleteFile(e.FullPath);
                    SubmitSideloadAlert(e.FullPath, processInfo.pid, processInfo.name, dropReason!);
                    return;
                }
            }

            SubmitEvent(e.FullPath, e.ChangeType.ToString().ToUpperInvariant(), null, processInfo.pid, processInfo.name);
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            var processInfo = GetProcessUsingFile(e.FullPath);

            if (IsSentinelTampering(e.FullPath, processInfo.pid, processInfo.name, out var tamperReason))
            {
                TryDeleteFile(e.FullPath);
                SubmitTamperAlert(e.FullPath, processInfo.pid, processInfo.name, tamperReason!);
                return;
            }

            if (IsSuspiciousDbghelpDrop(e.FullPath, out var dropReason))
            {
                if (!IsWriterTrusted(processInfo.pid, processInfo.name))
                {
                    TryDeleteFile(e.FullPath);
                    SubmitSideloadAlert(e.FullPath, processInfo.pid, processInfo.name, dropReason!);
                    return;
                }
            }

            SubmitEvent(e.OldFullPath, "RENAME", e.FullPath, processInfo.pid, processInfo.name);
        }

        private static bool IsWriterTrusted(int pid, string name)
        {
            if (pid <= 4) return true;

            var lowerName = name.ToLowerInvariant();
            if (lowerName == "svchost" || lowerName == "services" || lowerName == "wininit" ||
                lowerName == "msmpeng" || lowerName == "sentinelservice" || lowerName == "sentinelagent" ||
                lowerName == "trustedinstaller" || lowerName == "tiworker" || lowerName == "msiexec")
            {
                return true;
            }

            try
            {
                using var p = Process.GetProcessById(pid);
                string? path = p.MainModule?.FileName;
                if (string.IsNullOrEmpty(path)) return false;

                var pathLower = path.ToLowerInvariant();
                if (pathLower.Contains(@"\windows\") ||
                    pathLower.Contains(@"\program files\") ||
                    pathLower.Contains(@"\program files (x86)\") ||
                    pathLower.Contains(@"\steamapps\") ||
                    pathLower.Contains(@"\steam\") ||
                    pathLower.Contains(@"\epic games\") ||
                    pathLower.Contains(@"\gog galaxy\") ||
                    pathLower.Contains(@"\riot games\") ||
                    pathLower.Contains(@"\battle.net\") ||
                    pathLower.Contains(@"\ubisoft\") ||
                    pathLower.Contains(@"\ea games\") ||
                    pathLower.Contains(@"\origin\"))
                {
                    return true;
                }

                // Check signature
                using var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                    System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path));
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsSuspiciousDbghelpDrop(string filePath, out string? reason)
        {
            reason = null;
            if (string.IsNullOrWhiteSpace(filePath)) return false;

            var fileName = Path.GetFileName(filePath);
            if (!string.Equals(fileName, "dbghelp.dll", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(fileName, "dbgcore.dll", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var pathLower = filePath.ToLowerInvariant();
            if (pathLower.Contains(@"\windows\system32\") ||
                pathLower.Contains(@"\windows\syswow64\") ||
                pathLower.Contains(@"\windows\winsxs\") ||
                pathLower.Contains(@"\windows\systemapps\"))
            {
                return false;
            }

            reason = $"System DLL '{fileName}' was written to a non-system path: {filePath}";
            return true;
        }

        private static bool IsSentinelTampering(string filePath, int pid, string processName, out string? reason)
        {
            reason = null;
            if (string.IsNullOrWhiteSpace(filePath)) return false;

            var appDir = AppContext.BaseDirectory.ToLowerInvariant().TrimEnd('\\') + "\\";
            var pathLower = filePath.ToLowerInvariant();
            if (!pathLower.StartsWith(appDir)) return false;

            // Allow Sentinel's own components and Windows installer
            var lowerName = processName.ToLowerInvariant();
            if (lowerName == "sentinelservice" || lowerName == "sentinelagent" ||
                lowerName == "trustedinstaller" || lowerName == "tiworker" || lowerName == "msiexec")
            {
                return false;
            }

            reason = $"Unauthorized process '{processName}' (PID {pid}) attempted to write file '{Path.GetFileName(filePath)}' inside Sentinel's directory.";
            return true;
        }

        private static bool TryDeleteFile(string path)
        {
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    if (File.Exists(path))
                    {
                        File.Delete(path);
                        return true;
                    }
                }
                catch
                {
                    Thread.Sleep(50);
                }
            }
            return false;
        }

        private void SubmitTamperAlert(string filePath, int pid, string processName, string reason)
        {
            _ = _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Anti-Tamper: Unauthorized Write to Sentinel Directory",
                ProcessName = processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? processName : processName + ".exe",
                ProcessId = pid,
                Confidence = 0.99,
                Tier = DetectionTier.Tier1Behavioral,
                Evidence = reason,
                Reasoning = "An unauthorized process attempted to create, modify, or drop files inside the Sentinel EDR installation directory. This is an anti-tamper violation (T1562.001) targeting EDR components. The file was immediately deleted, and the process was flagged for active response termination.",
                Timestamp = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    { "technique", "T1562.001 - Impair Defenses: Disable or Modify Tools" },
                    { "file_path", filePath },
                    { "tamper_target", "Sentinel installation folder" }
                }
            });
        }

        private void SubmitSideloadAlert(string filePath, int pid, string processName, string reason)
        {
            _ = _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "DLL Sideloading: Suspicious System DLL Dropped",
                ProcessName = processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? processName : processName + ".exe",
                ProcessId = pid,
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                Evidence = $"Process '{processName}' dropped system DLL '{Path.GetFileName(filePath)}' at '{filePath}'. File was deleted by Sentinel to prevent sideloading.",
                Reasoning = "Untrusted process attempted to write a critical system DLL to a user-writable path. This is a characteristic indicator of DLL sideloading/hijacking (T1574.002) which targets legitimate executables. The file was immediately deleted to prevent successful execution, and the writing process is flagged for active response termination.",
                Timestamp = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    { "technique", "T1574.002 - DLL Side-Loading" },
                    { "file_path", filePath },
                    { "dll_name", Path.GetFileName(filePath) }
                }
            });
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

            // Exclude common gaming directories to prevent Restart Manager lock contention on game saves/simulations
            if (filePath.Contains(@"\My Games\", StringComparison.OrdinalIgnoreCase) ||
                filePath.Contains(@"\Saved Games\", StringComparison.OrdinalIgnoreCase) ||
                filePath.Contains(@"\Sports Interactive\", StringComparison.OrdinalIgnoreCase) ||
                filePath.Contains(@"\Football Manager\", StringComparison.OrdinalIgnoreCase) ||
                filePath.Contains(@"\Paradox Interactive\", StringComparison.OrdinalIgnoreCase) ||
                filePath.Contains(@"\Steam\", StringComparison.OrdinalIgnoreCase) ||
                filePath.Contains(@"\steamapps\", StringComparison.OrdinalIgnoreCase) ||
                filePath.Contains(@"\Epic Games\", StringComparison.OrdinalIgnoreCase) ||
                filePath.Contains(@"\Origin\", StringComparison.OrdinalIgnoreCase) ||
                filePath.Contains(@"\Battle.net\", StringComparison.OrdinalIgnoreCase) ||
                filePath.Contains(@"\GOG Galaxy\", StringComparison.OrdinalIgnoreCase) ||
                filePath.Contains(@"\Ubisoft\", StringComparison.OrdinalIgnoreCase) ||
                filePath.Contains(@"\Electronic Arts\", StringComparison.OrdinalIgnoreCase) ||
                filePath.Contains(@"\BioWare\", StringComparison.OrdinalIgnoreCase))
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
