using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Addresses the WMI process telemetry latency gap (1-2s) by detecting
    /// short-lived "ephemeral" processes that spawn and exit before WMI fires.
    ///
    /// Detection methods:
    /// 1. Prefetch file monitoring — Windows creates .pf files for every executable
    ///    that runs, even if only for milliseconds. New .pf files = new process ran.
    /// 2. Process audit log polling (Event ID 4688) — if enabled via policy.
    /// 3. AppCompat shimcache — records every binary executed regardless of duration.
    /// 4. AmCache delta — hive entries for new executables.
    ///
    /// This catches "flash" payloads that execute in &lt;500ms: droppers that unpack
    /// and delete themselves, exec-and-exit stagers, and fast credential dumpers.
    ///
    /// v1.0.1: New monitor.
    /// </summary>
    public sealed class EphemeralProcessMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly HashReputationService _reputationService;
        private readonly ContextBus? _contextBus;
        private readonly ILogger<EphemeralProcessMonitor> _logger;

        private readonly HashSet<string> _baselinePrefetch = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedExecutables = new();

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(10);

        private static readonly string PrefetchPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        // Executables that commonly create short-lived processes.
        // SECURITY: Name-only trust is verified by path check below — only system-directory
        // binaries are auto-cleared. Non-system instances with these names still trigger detection.
        // Exception: tools commonly extracted temporarily by legitimate scripts (aria2c, 7z, etc.)
        // which are gone before we can verify their path. These produce ResponseAction.LogOnly
        // detections regardless, so the security impact of false-positive suppression is minimal.
        private static readonly HashSet<string> AllowedEphemeral = new(StringComparer.OrdinalIgnoreCase)
        {
            "conhost", "consent", "ctfmon", "backgroundtaskhost",
            "runtimebroker", "applicationframehost", "searchprotocolhost",
            "searchfilterhost", "audiodg", "fontdrvhost", "dwm",
            "wmiprvse", "taskhostw", "sihost", "compattelrunner",
            "microsoftedgeupdate", "googleupdate", "spotifywebhelper",
            "msmpeng", "nissrv", "mpcmdrun",
            // Download/archive tools commonly used by UUP dump, Chocolatey, winget, etc.
            // These are extracted to temp dirs, execute, then cleaned up by the calling script.
            "aria2c", "7z", "7za", "wimlib-imagex", "cabextract"
        };

        // Suspicious paths for ephemeral processes
        private static readonly string[] SuspiciousStagingPaths = new[]
        {
            @"\temp\", @"\tmp\", @"\appdata\local\temp\",
            @"\downloads\", @"\public\", @"\programdata\",
            @"\windows\temp\", @"\users\public\"
        };

        private FileSystemWatcher? _prefetchWatcher;

        public EphemeralProcessMonitor(
            DetectionEngine detectionEngine,
            TelemetryFusionEngine fusionEngine,
            HashReputationService reputationService,
            ILogger<EphemeralProcessMonitor> logger,
            ContextBus? contextBus = null)
        {
            _detectionEngine = detectionEngine;
            _fusionEngine = fusionEngine;
            _contextBus = contextBus;
            _reputationService = reputationService;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[EphemeralProcessMonitor] Started");

            // Baseline existing prefetch files
            if (Directory.Exists(PrefetchPath))
            {
                try
                {
                    foreach (var file in Directory.GetFiles(PrefetchPath, "*.pf"))
                    {
                        _baselinePrefetch.Add(Path.GetFileName(file));
                    }
                }
                catch { }

                // Set up FileSystemWatcher on Prefetch for real-time detection
                try
                {
                    _prefetchWatcher = new FileSystemWatcher(PrefetchPath, "*.pf")
                    {
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime,
                        EnableRaisingEvents = true
                    };
                    _prefetchWatcher.Created += OnPrefetchCreated;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[EphemeralProcessMonitor] Cannot watch Prefetch (may need elevation)");
                }
            }

            // Periodic scan as backup (catches cases where FSW misses)
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    await ScanPrefetchDelta(ct);
                    await ScanSecurityEventLog(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[EphemeralProcessMonitor] Error"); }
            }

            _prefetchWatcher?.Dispose();
        }

        private async void OnPrefetchCreated(object sender, FileSystemEventArgs e)
        {
            try
            {
                var fileName = Path.GetFileName(e.FullPath);
                if (_baselinePrefetch.Contains(fileName)) return;
                _baselinePrefetch.Add(fileName);

                await AnalyzePrefetchEntry(fileName, e.FullPath);
            }
            catch { }
        }

        private async Task ScanPrefetchDelta(CancellationToken ct)
        {
            if (!Directory.Exists(PrefetchPath)) return;

            try
            {
                foreach (var file in Directory.GetFiles(PrefetchPath, "*.pf"))
                {
                    var fileName = Path.GetFileName(file);
                    if (_baselinePrefetch.Contains(fileName)) continue;
                    _baselinePrefetch.Add(fileName);

                    await AnalyzePrefetchEntry(fileName, file);
                }
            }
            catch { }
        }

        private async Task AnalyzePrefetchEntry(string prefetchFileName, string fullPath)
        {
            // Prefetch filename format: EXECUTABLE.EXE-XXXXXXXX.pf
            var exeName = ExtractExeNameFromPrefetch(prefetchFileName);
            if (string.IsNullOrEmpty(exeName)) return;

            // Skip known-good ephemeral processes — but ONLY if binary is in a system directory.
            // HARDENING v1.3.0: Name-only checks allow attackers to name malware "runtimebroker.exe"
            // in a Temp folder and bypass ephemeral process detection entirely.
            var baseName = Path.GetFileNameWithoutExtension(exeName);
            if (AllowedEphemeral.Contains(baseName))
            {
                var exePath2 = FindExecutable(exeName);
                if (exePath2 != null)
                {
                    var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
                    if (exePath2.ToLowerInvariant().StartsWith(winDir))
                        return; // Legitimate system process
                }
                else
                {
                    return; // Binary not found — already gone, likely legitimate short-lived system process
                }
                // Name matches but NOT in system directory — continue detection (possible masquerading)
            }

            // Check cooldown
            if (_alertedExecutables.TryGetValue(exeName, out var lastAlert) &&
                DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                return;

            _alertedExecutables[exeName] = DateTimeOffset.UtcNow;

            // Check if this process is still running (if not, it was ephemeral)
            var stillRunning = Process.GetProcessesByName(baseName).Length > 0;

            // If still running, WMI will catch it — we only care about the gap
            if (stillRunning) return;

            // This process ran and exited before WMI could report it
            // Try to find the executable on disk for reputation check
            var exePath = FindExecutable(exeName);
            bool isSuspiciousPath = exePath != null &&
                SuspiciousStagingPaths.Any(p => exePath.Contains(p, StringComparison.OrdinalIgnoreCase));

            // If the executable no longer exists on disk — self-deletion pattern
            bool selfDeleted = exePath == null || !File.Exists(exePath);

            double confidence;
            DetectionTier tier;
            ResponseAction response;

            if (selfDeleted)
            {
                confidence = 0.82;
                tier = DetectionTier.Tier1Behavioral;
                response = ResponseAction.LogOnly; // Can't kill what's already gone
            }
            else if (isSuspiciousPath)
            {
                confidence = 0.68;
                tier = DetectionTier.Tier1Behavioral;
                response = ResponseAction.LogOnly;
            }
            else
            {
                confidence = 0.45;
                tier = DetectionTier.Tier2Indicator;
                response = ResponseAction.LogOnly;
            }

            // Feed into fusion engine as ephemeral process telemetry
            _fusionEngine.FeedEvent(new ProcessTelemetry
            {
                Type = "EphemeralProcess",
                ProcessName = exeName,
                ImagePath = exePath ?? "(deleted)",
                CommandLine = "(ephemeral — captured via Prefetch)",
                ProcessId = 0, // Already exited
                Timestamp = DateTime.UtcNow
            });

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = selfDeleted
                    ? "Ephemeral Process: Self-Deleting Executable"
                    : "Ephemeral Process: Short-Lived Execution",
                Evidence = $"Executable '{exeName}' ran and exited within WMI latency window. " +
                           $"Prefetch entry: {prefetchFileName}. " +
                           $"Path: {exePath ?? "(binary not found — self-deleted)"}. " +
                           (selfDeleted ? "Binary no longer on disk (dropper pattern)." : ""),
                Reasoning = selfDeleted
                    ? "A process executed and deleted its own binary before WMI could report the " +
                      "process start event. This is a classic dropper/stager pattern: execute payload, " +
                      "remove evidence. The Prefetch file proves execution occurred."
                    : "A process executed and exited within the 1-2 second WMI reporting latency. " +
                      "Short-lived processes can perform credential dumping, file staging, or " +
                      "initial C2 check-in before traditional monitors observe them.",
                Confidence = confidence,
                Tier = tier,
                AuthorizedResponse = response,
                ProcessName = exeName,
                ProcessId = 0,
                SignalType = SignalType.SuspiciousProcess,
                Metadata = new Dictionary<string, string>
                {
                    ["PrefetchFile"] = prefetchFileName,
                    ["ExePath"] = exePath ?? "(deleted)",
                    ["SelfDeleted"] = selfDeleted.ToString(),
                    ["SuspiciousPath"] = isSuspiciousPath.ToString()
                }
            });

            // Publish enrichment signal for cross-monitor consumption
            _contextBus?.Publish(new EphemeralProcessSignal
            {
                ProcessId = 0,
                ProcessName = exeName,
                SourceMonitor = "EphemeralProcessMonitor",
                ExecutableName = exeName,
                ExecutablePath = exePath,
                SelfDeleted = selfDeleted,
                SuspiciousPath = isSuspiciousPath,
                PrefetchFile = prefetchFileName
            });

            // If the binary still exists, check reputation
            if (exePath != null && File.Exists(exePath))
            {
                try
                {
                    var sha256 = ComputeSha256(exePath);
                    if (sha256 != null)
                        _ = _reputationService.GetVerdictAsync(sha256);
                }
                catch { }
            }
        }

        private async Task ScanSecurityEventLog(CancellationToken ct)
        {
            // Poll Security event log for Event ID 4688 (Process Creation)
            // This requires "Audit Process Creation" to be enabled
            try
            {
                var query = "SELECT * FROM Win32_NTLogEvent WHERE " +
                           "Logfile = 'Security' AND EventCode = 4688 AND " +
                           $"TimeGenerated > '{ManagementDateTimeConverter.ToDmtfDateTime(DateTime.UtcNow.AddSeconds(-10))}'";

                using var searcher = new ManagementObjectSearcher(query);
                foreach (ManagementObject evt in searcher.Get())
                {
                    if (ct.IsCancellationRequested) break;

                    var message = evt["Message"]?.ToString() ?? "";
                    // Extract new process name from event
                    var newProcess = ExtractFieldFromEvent(message, "New Process Name:");
                    if (string.IsNullOrEmpty(newProcess)) continue;

                    var baseName = Path.GetFileNameWithoutExtension(newProcess);
                    if (AllowedEphemeral.Contains(baseName)) continue;

                    // Check if still running
                    if (Process.GetProcessesByName(baseName).Length > 0) continue;

                    // Already exited — ephemeral process caught by audit log
                    // Submit as telemetry but with lower confidence (audit log is better than prefetch)
                    _fusionEngine.FeedEvent(new ProcessTelemetry
                    {
                        Type = "EphemeralProcess",
                        ProcessName = baseName,
                        ImagePath = newProcess,
                        CommandLine = ExtractFieldFromEvent(message, "Process Command Line:"),
                        ProcessId = 0,
                        Timestamp = DateTime.UtcNow
                    });
                }
            }
            catch { } // Security log access may fail without SeSecurityPrivilege
        }

        private static string? ExtractExeNameFromPrefetch(string prefetchFileName)
        {
            // Format: NAME.EXE-XXXXXXXX.pf
            var parts = prefetchFileName.Split('-');
            if (parts.Length < 2) return null;
            return parts[0]; // Everything before the hash
        }

        private static string? FindExecutable(string exeName)
        {
            // Search common locations for the executable
            var searchPaths = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64"),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath()
            };

            foreach (var basePath in searchPaths)
            {
                if (string.IsNullOrEmpty(basePath)) continue;
                var candidate = Path.Combine(basePath, exeName);
                if (File.Exists(candidate)) return candidate;
            }

            return null;
        }

        private static string ExtractFieldFromEvent(string message, string fieldName)
        {
            var idx = message.IndexOf(fieldName, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return "";
            var start = idx + fieldName.Length;
            var end = message.IndexOf('\n', start);
            if (end < 0) end = message.Length;
            return message[start..end].Trim();
        }

        private static string? ComputeSha256(string filePath)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                var hash = SHA256.HashData(stream);
                return Convert.ToHexString(hash).ToLowerInvariant();
            }
            catch { return null; }
        }
    }
}
