using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Traces the full attack chain from a detected malicious process back to its
    /// origin. Walks the parent process tree, identifies the attack root (first
    /// non-system process), and performs chain-level response:
    ///   1. Kill all processes in the chain (except critical system processes)
    ///   2. Quarantine non-system binaries
    ///   3. Remove persistence (Run keys, scheduled tasks)
    ///   4. Log complete chain evidence
    /// Only invoked for Tier1 detections with KillAuthorized when ActiveResponse is enabled.
    /// </summary>
    public sealed class ChainTracer
    {
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly QuarantineManager _quarantineManager;
        private readonly JsonlEventLogger _eventLogger;
        private readonly SentinelConfig _config;
        private readonly ILogger<ChainTracer> _logger;

        private static readonly HashSet<string> CriticalSystemProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "system", "registry", "smss", "csrss", "wininit", "services", "lsass", "svchost",
            "explorer", "dwm", "sihost", "fontdrvhost", "winlogon"
        };

        private static readonly HashSet<string> SystemBinaries = new(StringComparer.OrdinalIgnoreCase)
        {
            "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
            "conhost", "conhost.exe", "rundll32", "rundll32.exe",
            "mshta", "mshta.exe", "wscript", "wscript.exe", "cscript", "cscript.exe",
            "regsvr32", "regsvr32.exe", "msiexec", "msiexec.exe",
        };

        private static readonly string[] SystemPaths = new[]
        {
            @"C:\Windows\System32\",
            @"C:\Windows\SysWOW64\",
            @"C:\Windows\",
        };

        public ChainTracer(
            ProcessAncestryCache ancestryCache,
            QuarantineManager quarantineManager,
            JsonlEventLogger eventLogger,
            SentinelConfig config,
            ILogger<ChainTracer> logger)
        {
            _ancestryCache = ancestryCache;
            _quarantineManager = quarantineManager;
            _eventLogger = eventLogger;
            _config = config;
            _logger = logger;
        }

        /// <summary>
        /// Traces and responds to the attack chain rooted at the detected process.
        /// </summary>
        public async Task<ChainTraceResult> TraceAndRespondAsync(DetectionEvent detection, CancellationToken ct = default)
        {
            var result = new ChainTraceResult
            {
                RootDetection = detection,
                StartTime = DateTimeOffset.UtcNow
            };

            try
            {
                // 1. Walk parent chain
                var chain = WalkParentChain(detection.ProcessId, detection.ProcessName);
                result.ParentChain = chain;
                result.AllChainProcesses = chain;

                // 2. Identify attack root (first non-system binary)
                result.AttackRoot = chain.LastOrDefault(n => !IsSystemBinary(n.ImagePath, n.ProcessName)) ?? chain.LastOrDefault();

                // 3. Kill chain if active response is enabled
                if (_config.ActiveResponse && detection.KillAuthorized)
                {
                    foreach (var node in chain)
                    {
                        // Protect critical system processes ONLY if they reside in legitimate system paths.
                        // Prevents malware from renaming itself to svchost.exe/explorer.exe/etc. to evade kill.
                        var cleanName = node.ProcessName.Replace(".exe", "");
                        if (CriticalSystemProcesses.Contains(cleanName) && IsSystemBinary(node.ImagePath, node.ProcessName))
                            continue;

                        try
                        {
                            HardeningModule.SafeKillProcessTree(node.ProcessId);
                            result.KilledProcesses.Add(new KilledProcessInfo
                            {
                                ProcessId = node.ProcessId,
                                ProcessName = node.ProcessName,
                                ImagePath = node.ImagePath,
                                IsSystemBinary = IsSystemBinary(node.ImagePath, node.ProcessName),
                                KillTime = DateTimeOffset.UtcNow
                            });
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug(ex, "[ChainTracer] Failed to kill PID {Pid}", node.ProcessId);
                        }
                    }

                    // 4. Quarantine non-system binaries
                    foreach (var node in chain.Where(n => !string.IsNullOrEmpty(n.ImagePath) && !IsSystemBinary(n.ImagePath, n.ProcessName)))
                    {
                        try
                        {
                            if (File.Exists(node.ImagePath))
                            {
                                var hash = await ComputeFileHashAsync(node.ImagePath!, ct);
                                await _quarantineManager.QuarantineFileAtomicAsync(node.ImagePath!);
                                result.QuarantinedFiles.Add(new QuarantinedFileInfo
                                {
                                    OriginalPath = node.ImagePath!,
                                    ProcessId = node.ProcessId,
                                    ProcessName = node.ProcessName,
                                    FileHash = hash,
                                    QuarantineTime = DateTimeOffset.UtcNow
                                });
                            }
                        }
                        catch { }
                    }

                    // 5. Remove persistence
                    await RemovePersistenceAsync(chain, result, ct);
                }

                // 6. Log chain evidence
                result.EndTime = DateTimeOffset.UtcNow;
                result.Success = true;
                await LogChainEvidenceAsync(result);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                _logger.LogError(ex, "[ChainTracer] Chain trace failed for PID {Pid}", detection.ProcessId);
            }

            return result;
        }

        private List<ProcessNode> WalkParentChain(int pid, string processName)
        {
            var chain = new List<ProcessNode>();
            var visited = new HashSet<int>();
            int currentPid = pid;
            string currentName = processName;

            for (int depth = 0; depth < 20; depth++)
            {
                if (currentPid <= 4 || visited.Contains(currentPid)) break;
                visited.Add(currentPid);

                string? imagePath = null;
                try
                {
                    using var proc = Process.GetProcessById(currentPid);
                    try { imagePath = proc.MainModule?.FileName; } catch { }
                    if (string.IsNullOrEmpty(currentName)) currentName = proc.ProcessName;
                }
                catch { }

                chain.Add(new ProcessNode
                {
                    ProcessId = currentPid,
                    ProcessName = currentName,
                    ImagePath = imagePath,
                    IsSystemBinary = IsSystemBinary(imagePath, currentName)
                });

                var (parentPid, parentName) = _ancestryCache.GetParent(currentPid);
                if (parentPid <= 0) break;
                currentPid = parentPid;
                currentName = parentName;
            }

            return chain;
        }

        private async Task RemovePersistenceAsync(List<ProcessNode> chain, ChainTraceResult result, CancellationToken ct)
        {
            var imagePaths = chain
                .Where(n => !string.IsNullOrEmpty(n.ImagePath))
                .Select(n => n.ImagePath!.ToLowerInvariant())
                .ToHashSet();

            // Check Run keys
            var runKeyPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            };

            foreach (var keyPath in runKeyPaths)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: true);
                    if (key == null) continue;
                    foreach (var name in key.GetValueNames())
                    {
                        var val = key.GetValue(name)?.ToString()?.ToLowerInvariant() ?? "";
                        if (imagePaths.Any(p => val.Contains(p)))
                        {
                            key.DeleteValue(name);
                            result.PersistenceRemoved.Add(new PersistenceInfo
                            {
                                Type = "RunKey", Location = $"HKLM\\{keyPath}", Name = name, Value = val, Removed = true
                            });
                        }
                    }
                }
                catch { }
            }
        }

        private async Task LogChainEvidenceAsync(ChainTraceResult result)
        {
            var evidence = new
            {
                Type = "ChainTrace",
                result.RootDetection.RuleName,
                result.RootDetection.ProcessId,
                result.RootDetection.ProcessName,
                AttackRoot = result.AttackRoot?.ProcessName,
                ChainLength = result.AllChainProcesses.Count,
                Killed = result.KilledProcesses.Count,
                Quarantined = result.QuarantinedFiles.Count,
                PersistenceRemoved = result.PersistenceRemoved.Count,
                result.StartTime,
                result.EndTime,
                DurationMs = (result.EndTime - result.StartTime).TotalMilliseconds
            };
            await _eventLogger.LogEventAsync("chain_trace", evidence);
        }

        private static bool IsSystemBinary(string? imagePath, string processName)
        {
            if (SystemBinaries.Contains(processName)) return true;
            if (string.IsNullOrEmpty(imagePath)) return false;
            return SystemPaths.Any(sp => imagePath.StartsWith(sp, StringComparison.OrdinalIgnoreCase));
        }

        private static async Task<string> ComputeFileHashAsync(string filePath, CancellationToken ct)
        {
            try
            {
                using var sha256 = SHA256.Create();
                await using var stream = File.OpenRead(filePath);
                var hash = await sha256.ComputeHashAsync(stream, ct);
                return Convert.ToHexString(hash);
            }
            catch { return ""; }
        }
    }

    public sealed class ProcessNode
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public string? ImagePath { get; set; }
        public bool IsSystemBinary { get; set; }
    }

    public sealed class KilledProcessInfo
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public string? ImagePath { get; set; }
        public bool IsSystemBinary { get; set; }
        public DateTimeOffset KillTime { get; set; }
    }

    public sealed class QuarantinedFileInfo
    {
        public string OriginalPath { get; set; } = "";
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public string FileHash { get; set; } = "";
        public DateTimeOffset QuarantineTime { get; set; }
    }

    public sealed class PersistenceInfo
    {
        public string Type { get; set; } = "";
        public string Location { get; set; } = "";
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
        public bool Removed { get; set; }
    }

    public sealed class ChainTraceResult
    {
        public DetectionEvent RootDetection { get; set; } = null!;
        public DateTimeOffset StartTime { get; set; }
        public DateTimeOffset EndTime { get; set; }
        public List<ProcessNode> ParentChain { get; set; } = new();
        public ProcessNode? AttackRoot { get; set; }
        public List<ProcessNode> AllChainProcesses { get; set; } = new();
        public List<KilledProcessInfo> KilledProcesses { get; set; } = new();
        public List<QuarantinedFileInfo> QuarantinedFiles { get; set; } = new();
        public List<PersistenceInfo> PersistenceRemoved { get; set; } = new();
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
    }
}
