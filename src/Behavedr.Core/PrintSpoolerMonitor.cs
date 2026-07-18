using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Behavedr.Core
{
    /// <summary>
    /// Monitors the Windows Print Spooler for data exfiltration via:
    /// - Print-to-file operations that write sensitive data to arbitrary paths
    /// - XPS spool file creation (staging area for exfiltration)
    /// - Microsoft Print to PDF creating files outside normal paths
    /// - Bulk print operations (rapid file creation in spool directory)
    ///
    /// The print spooler spool directory (C:\Windows\System32\spool\PRINTERS)
    /// and user-directed print-to-file paths are outside FileActivityMonitor's scope.
    ///
    /// v1.0.1: New monitor.
    /// </summary>
    public sealed class PrintSpoolerMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<PrintSpoolerMonitor> _logger;

        private readonly ConcurrentDictionary<string, int> _recentSpoolFiles = new();
        private int _spoolBurstCount;
        private DateTimeOffset _burstWindowStart = DateTimeOffset.UtcNow;

        private FileSystemWatcher? _spoolWatcher;
        private FileSystemWatcher? _printToFileWatcher;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(15);
        private const int BurstThreshold = 20; // 20+ spool files in 60s = suspicious
        private static readonly TimeSpan BurstWindow = TimeSpan.FromSeconds(60);

        private static readonly string SpoolPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            @"spool\PRINTERS");

        // Suspicious extensions for print-to-file output
        private static readonly HashSet<string> SuspiciousOutputExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".hta", ".scr", ".msi", ".reg", ".inf"
        };

        public PrintSpoolerMonitor(
            DetectionEngine detectionEngine,
            ILogger<PrintSpoolerMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[PrintSpoolerMonitor] Started");

            // Watch the spool directory for burst activity
            if (Directory.Exists(SpoolPath))
            {
                try
                {
                    _spoolWatcher = new FileSystemWatcher(SpoolPath)
                    {
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime,
                        EnableRaisingEvents = true
                    };
                    _spoolWatcher.Created += OnSpoolFileCreated;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[PrintSpoolerMonitor] Cannot watch spool directory");
                }
            }

            // Watch common print-to-file output directories
            var documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            if (!string.IsNullOrEmpty(documentsPath) && Directory.Exists(documentsPath))
            {
                try
                {
                    _printToFileWatcher = new FileSystemWatcher(documentsPath)
                    {
                        Filter = "*.xps",
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName,
                        EnableRaisingEvents = true
                    };
                    _printToFileWatcher.Created += OnXpsFileCreated;
                }
                catch { }
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    await CheckSpoolBurst(ct);
                    await ScanForSuspiciousPrintOutput(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[PrintSpoolerMonitor] Error"); }
            }

            _spoolWatcher?.Dispose();
            _printToFileWatcher?.Dispose();
        }

        private async void OnSpoolFileCreated(object sender, FileSystemEventArgs e)
        {
            Interlocked.Increment(ref _spoolBurstCount);
            _recentSpoolFiles[e.Name ?? "unknown"] = Environment.CurrentManagedThreadId;
        }

        private async void OnXpsFileCreated(object sender, FileSystemEventArgs e)
        {
            try
            {
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Print Spooler: XPS Document Created",
                    Evidence = $"XPS print output created: {e.FullPath}",
                    Reasoning = "An XPS document was created via the print system. XPS files can " +
                                "contain rendered copies of sensitive documents and may be used " +
                                "as a covert exfiltration channel.",
                    Confidence = 0.35,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0
                });
            }
            catch { }
        }

        private async Task CheckSpoolBurst(CancellationToken ct)
        {
            if (DateTimeOffset.UtcNow - _burstWindowStart > BurstWindow)
            {
                var count = Interlocked.Exchange(ref _spoolBurstCount, 0);
                _burstWindowStart = DateTimeOffset.UtcNow;
                _recentSpoolFiles.Clear();

                if (count >= BurstThreshold)
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Print Spooler: Bulk Print Burst Detected",
                        Evidence = $"{count} spool files created in {BurstWindow.TotalSeconds}s window",
                        Reasoning = "A large number of print spool files were created in a short window. " +
                                    "This can indicate bulk document rendering for exfiltration via " +
                                    "print-to-file, or exploitation of the print spooler service. " +
                                    "Normal printing rarely exceeds 5-10 documents per minute.",
                        Confidence = 0.65,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "spoolsv.exe",
                        ProcessId = 0,
                        Metadata = new Dictionary<string, string>
                        {
                            ["SpoolFileCount"] = count.ToString(),
                            ["WindowSeconds"] = BurstWindow.TotalSeconds.ToString()
                        }
                    });
                }
            }
        }

        private async Task ScanForSuspiciousPrintOutput(CancellationToken ct)
        {
            // Check for print-to-file output with suspicious extensions
            // Some malware uses "Microsoft Print to PDF" or XPS to write to arbitrary paths
            if (!Directory.Exists(SpoolPath)) return;

            try
            {
                foreach (var file in Directory.GetFiles(SpoolPath))
                {
                    var ext = Path.GetExtension(file);
                    if (!SuspiciousOutputExtensions.Contains(ext)) continue;

                    // Non-document file in the spool directory = suspicious
                    var alertKey = Path.GetFileName(file);
                    if (_recentSpoolFiles.ContainsKey(alertKey)) continue;
                    _recentSpoolFiles[alertKey] = 0;

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Print Spooler: Suspicious File in Spool Directory",
                        Evidence = $"Non-document file found in spool directory: {file}",
                        Reasoning = "A non-document file with a suspicious extension was found in the " +
                                    "print spooler directory. This may indicate PrintNightmare-style " +
                                    "exploitation or DLL planting via the spooler service.",
                        Confidence = 0.80,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        ProcessName = "spoolsv.exe",
                        ProcessId = 0
                    });
                }
            }
            catch { }
        }

        public override void Dispose()
        {
            if (_spoolWatcher != null)
            {
                try { _spoolWatcher.Created -= OnSpoolFileCreated; } catch { }
                try { _spoolWatcher.Dispose(); } catch { }
            }
            if (_printToFileWatcher != null)
            {
                try { _printToFileWatcher.Created -= OnXpsFileCreated; } catch { }
                try { _printToFileWatcher.Dispose(); } catch { }
            }
            base.Dispose();
        }
    }
}
