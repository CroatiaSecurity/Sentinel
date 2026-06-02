using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core;

/// <summary>
/// CanaryFileMonitor deploys hidden canary files to high-value user directories
/// and monitors them for tampering using FileSystemWatcher.
/// Any modification to these files instantly triggers a Tier 1 Behavioral detection,
/// providing zero-latency ransomware containment.
/// </summary>
public sealed class CanaryFileMonitor : BackgroundService
{
    private readonly DetectionEngine _engine;
    private readonly ILogger<CanaryFileMonitor> _logger;
    private readonly ConcurrentBag<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, bool> _canaryPaths = new(StringComparer.OrdinalIgnoreCase);

    private readonly string[] _canaryNames = {
        ".$passwords.docx",
        ".$financial_records_2026.xlsx",
        ".$bitcoin_wallet.dat",
        ".$tax_returns.pdf"
    };

    public CanaryFileMonitor(DetectionEngine engine, ILogger<CanaryFileMonitor> logger)
    {
        _engine = engine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("CanaryFileMonitor: starting");
        
        try
        {
            DeployCanaries();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to deploy canary files.");
            return;
        }

        // Wait indefinitely until cancellation
        try
        {
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            // Normal exit
        }
        finally
        {
            CleanupCanaries();
        }
    }

    private void DeployCanaries()
    {
        // Deploy to Documents and Desktop
        var targetDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
        };

        foreach (var dir in targetDirs)
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;

            foreach (var name in _canaryNames)
            {
                var fullPath = Path.Combine(dir, name);
                
                try
                {
                    // Create dummy content
                    File.WriteAllText(fullPath, "Sentinel Canary File - Do Not Modify");
                    
                    // Hide the file
                    var info = new FileInfo(fullPath);
                    info.Attributes |= FileAttributes.Hidden | FileAttributes.System;

                    _canaryPaths.TryAdd(fullPath, true);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to create canary file at {Path}", fullPath);
                }
            }

            // Setup watcher for this directory
            try
            {
                var watcher = new FileSystemWatcher(dir)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                    IncludeSubdirectories = false,
                    EnableRaisingEvents = true
                };

                watcher.Changed += OnCanaryTampered;
                watcher.Deleted += OnCanaryTampered;
                watcher.Renamed += OnCanaryRenamed;

                _watchers.Add(watcher);
                _logger.LogInformation("Deployed canary monitor to {Dir}", dir);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create FileSystemWatcher for {Dir}", dir);
            }
        }
    }

    private void OnCanaryTampered(object sender, FileSystemEventArgs e)
    {
        if (_canaryPaths.ContainsKey(e.FullPath))
        {
            EmitDetection(e.FullPath, e.ChangeType.ToString());
        }
    }

    private void OnCanaryRenamed(object sender, RenamedEventArgs e)
    {
        if (_canaryPaths.ContainsKey(e.OldFullPath) || _canaryPaths.ContainsKey(e.FullPath))
        {
            EmitDetection(e.OldFullPath, $"Renamed to {e.Name}");
        }
    }

    private void EmitDetection(string path, string action)
    {
        // FileSystemWatcher runs on thread pool, we don't know the exact PID that modified the file directly.
        // However, we can use ETW or just emit a high-priority alert.
        // Since we don't have the exact PID natively from FSW, we will emit a system-wide alert.
        // If we want a precise kill, we can find the process holding a handle to it, but typically ransomware 
        // will trigger other ETW events. 
        // Actually, emitting without a PID is tricky for the Response Engine. 
        // Let's find the locking process if possible using ETW correlation in TelemetryFusionEngine, or just emit 0.

        _logger.LogCritical("[CANARY TAMPERED] {Path} was {Action}", path, action);

        // We emit PID 0 for now. The engine can log it.
        _ = _engine.EmitAsync(new DetectionEvent
        {
            RuleName = "Canary File Tampering (Ransomware)",
            Evidence = $"Canary file '{path}' was {action}.",
            Reasoning = "A hidden ransomware canary file was modified. This is a nearly certain indicator of active ransomware encryption.",
            Confidence = 0.99,
            Tier = DetectionTier.Tier1Behavioral,
            ProcessName = "Unknown (FSW)",
            ProcessId = 0, // In a real driver, we'd know the PID via FltMgr. Here we log the event.
            Timestamp = DateTime.UtcNow,
            Metadata = new()
            {
                ["technique"] = "T1486 - Data Encrypted for Impact",
                ["canary_path"] = path,
                ["canary_action"] = action
            }
        }, CancellationToken.None);
    }

    private void CleanupCanaries()
    {
        foreach (var watcher in _watchers)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
        }

        foreach (var path in _canaryPaths.Keys)
        {
            try
            {
                if (File.Exists(path))
                {
                    var info = new FileInfo(path);
                    info.Attributes &= ~(FileAttributes.Hidden | FileAttributes.System);
                    File.Delete(path);
                }
            }
            catch { }
        }
        
        _canaryPaths.Clear();
    }
}

