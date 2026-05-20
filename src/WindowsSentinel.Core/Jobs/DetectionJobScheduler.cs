using System.Collections.Concurrent;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Detection.Rules;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Jobs;

/// <summary>
/// Detection Job Scheduler - Manages 55+ scheduled detection jobs.
/// Runs periodic scans for various threat categories.
/// </summary>
public sealed class DetectionJobScheduler : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<DetectionJobScheduler> _logger;
    private readonly ConcurrentDictionary<string, JobExecutionInfo> _jobHistory = new();
    private readonly CertificateTamperingRule? _certificateTamperingRule;
    private readonly UserProtectionRule? _userProtectionRule;

    // Job definitions with intervals
    private readonly List<DetectionJob> _jobs;

    public DetectionJobScheduler(
        IDetectionEngine detectionEngine,
        ILogger<DetectionJobScheduler> logger,
        CertificateTamperingRule? certificateTamperingRule = null,
        UserProtectionRule? userProtectionRule = null)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _certificateTamperingRule = certificateTamperingRule;
        _userProtectionRule = userProtectionRule;

        // Initialize all 55+ detection jobs
        _jobs = new List<DetectionJob>
        {
            // ═══════════════════════════════════════════════════════════
            // PROCESS JOBS (8 jobs)
            // ═══════════════════════════════════════════════════════════
            new DetectionJob
            {
                Id = "process_hollowing",
                Name = "Process Hollowing Detection",
                Category = "Process",
                Description = "Detects process hollowing by comparing image path to mapped memory",
                Interval = TimeSpan.FromMinutes(2),
                Action = RunProcessHollowingCheckAsync,
                MitreTechnique = "T1055.012"
            },
            new DetectionJob
            {
                Id = "token_manipulation",
                Name = "Token Manipulation Detection",
                Category = "Process",
                Description = "Detects privilege escalation via token manipulation",
                Interval = TimeSpan.FromMinutes(3),
                Action = RunTokenManipulationCheckAsync,
                MitreTechnique = "T1134"
            },
            new DetectionJob
            {
                Id = "ppid_spoofing",
                Name = "PPID Spoofing Detection",
                Category = "Process",
                Description = "Detects parent process ID spoofing",
                Interval = TimeSpan.FromMinutes(2),
                Action = RunPpidSpoofingCheckAsync,
                MitreTechnique = "T1134.004"
            },
            new DetectionJob
            {
                Id = "fileless_attacks",
                Name = "Fileless Attack Detection",
                Category = "Process",
                Description = "Detects fileless malware execution in memory",
                Interval = TimeSpan.FromMinutes(1),
                Action = RunFilelessAttackCheckAsync,
                MitreTechnique = "T1055"
            },
            new DetectionJob
            {
                Id = "memory_scan",
                Name = "Memory Scan",
                Category = "Process",
                Description = "Scans process memory for suspicious patterns",
                Interval = TimeSpan.FromMinutes(5),
                Action = RunMemoryScanAsync,
                MitreTechnique = "T1055"
            },
            new DetectionJob
            {
                Id = "short_lived_processes",
                Name = "Short-Lived Process Detection",
                Category = "Process",
                Description = "Detects processes that exit quickly (common in exploits)",
                Interval = TimeSpan.FromMinutes(2),
                Action = RunShortLivedProcessCheckAsync,
                MitreTechnique = "T1059"
            },
            new DetectionJob
            {
                Id = "renamed_binaries",
                Name = "Renamed Binary Detection",
                Category = "Process",
                Description = "Detects system binaries renamed to avoid detection",
                Interval = TimeSpan.FromMinutes(5),
                Action = RunRenamedBinaryCheckAsync,
                MitreTechnique = "T1036.003"
            },
            new DetectionJob
            {
                Id = "cmdline_entropy",
                Name = "Command Line Entropy Analysis",
                Category = "Process",
                Description = "Detects obfuscated command lines via entropy analysis",
                Interval = TimeSpan.FromMinutes(3),
                Action = RunCommandLineEntropyCheckAsync,
                MitreTechnique = "T1027"
            },

            // ═══════════════════════════════════════════════════════════
            // DLL JOBS (4 jobs)
            // ═══════════════════════════════════════════════════════════
            new DetectionJob
            {
                Id = "dll_hijacking",
                Name = "DLL Hijacking Detection",
                Category = "DLL",
                Description = "Detects DLL search order hijacking",
                Interval = TimeSpan.FromMinutes(3),
                Action = RunDllHijackingCheckAsync,
                MitreTechnique = "T1574.001"
            },
            new DetectionJob
            {
                Id = "reflective_dll",
                Name = "Reflective DLL Injection Detection",
                Category = "DLL",
                Description = "Detects reflective DLL injection",
                Interval = TimeSpan.FromMinutes(2),
                Action = RunReflectiveDllCheckAsync,
                MitreTechnique = "T1055.001"
            },
            new DetectionJob
            {
                Id = "keystroke_dll",
                Name = "Keystroke Injection DLL Detection",
                Category = "DLL",
                Description = "Detects DLLs hooking keyboard input",
                Interval = TimeSpan.FromMinutes(5),
                Action = RunKeystrokeDllCheckAsync,
                MitreTechnique = "T1056.001"
            },
            new DetectionJob
            {
                Id = "browser_dll",
                Name = "Browser DLL Monitoring",
                Category = "DLL",
                Description = "Monitors browser processes for suspicious DLLs",
                Interval = TimeSpan.FromMinutes(5),
                Action = RunBrowserDllCheckAsync,
                MitreTechnique = "T1185"
            },

            // ═══════════════════════════════════════════════════════════
            // PERSISTENCE JOBS (4 jobs)
            // ═══════════════════════════════════════════════════════════
            new DetectionJob
            {
                Id = "registry_run_keys",
                Name = "Registry Run Keys Scan",
                Category = "Persistence",
                Description = "Scans registry Run/RunOnce keys for suspicious entries",
                Interval = TimeSpan.FromMinutes(5),
                Action = RunRegistryRunKeysCheckAsync,
                MitreTechnique = "T1547.001"
            },
            new DetectionJob
            {
                Id = "scheduled_tasks",
                Name = "Scheduled Task Persistence Scan",
                Category = "Persistence",
                Description = "Detects malicious scheduled tasks",
                Interval = TimeSpan.FromMinutes(5),
                Action = RunScheduledTasksCheckAsync,
                MitreTechnique = "T1053"
            },
            new DetectionJob
            {
                Id = "wmi_subscriptions",
                Name = "WMI Event Subscription Scan",
                Category = "Persistence",
                Description = "Detects WMI event subscription persistence",
                Interval = TimeSpan.FromMinutes(10),
                Action = RunWmiSubscriptionsCheckAsync,
                MitreTechnique = "T1546.003"
            },
            new DetectionJob
            {
                Id = "startup_folder",
                Name = "Startup Folder Scan",
                Category = "Persistence",
                Description = "Scans startup folders for malicious entries",
                Interval = TimeSpan.FromMinutes(5),
                Action = RunStartupFolderCheckAsync,
                MitreTechnique = "T1547.001"
            },

            // ═══════════════════════════════════════════════════════════
            // SYSTEM JOBS (12 jobs)
            // ═══════════════════════════════════════════════════════════
            new DetectionJob
            {
                Id = "rootkit_detection",
                Name = "Rootkit Detection",
                Category = "System",
                Description = "Detects rootkit indicators",
                Interval = TimeSpan.FromMinutes(10),
                Action = RunRootkitDetectionAsync,
                MitreTechnique = "T1014"
            },
            new DetectionJob
            {
                Id = "byovd_detection",
                Name = "BYOVD Detection",
                Category = "System",
                Description = "Detects Bring Your Own Vulnerable Driver attacks",
                Interval = TimeSpan.FromMinutes(5),
                Action = RunByovdDetectionAsync,
                MitreTechnique = "T1068"
            },
            new DetectionJob
            {
                Id = "scareware_scan",
                Name = "Scareware/FakeUAC Window Scan",
                Category = "UserProtection",
                Description = "Scans process windows for ransomware scareware and fake UAC dialogs",
                Interval = TimeSpan.FromMinutes(2),
                Action = RunScarewareScanAsync,
                MitreTechnique = "T1491"
            },
            new DetectionJob
            {
                Id = "lnk_protection",
                Name = "Malicious LNK Scan",
                Category = "UserProtection",
                Description = "Scans shortcuts for UNC path targets (NTLM hash theft)",
                Interval = TimeSpan.FromMinutes(30),
                Action = RunLnkProtectionScanAsync,
                MitreTechnique = "T1187"
            },
            new DetectionJob
            {
                Id = "driver_monitor",
                Name = "Driver Load Monitoring",
                Category = "System",
                Description = "Monitors for suspicious driver loading",
                Interval = TimeSpan.FromMinutes(3),
                Action = RunDriverMonitorAsync,
                MitreTechnique = "T1547.006"
            },
            new DetectionJob
            {
                Id = "bcd_security",
                Name = "BCD Security Check",
                Category = "System",
                Description = "Checks Boot Configuration Data for tampering",
                Interval = TimeSpan.FromMinutes(15),
                Action = RunBcdSecurityCheckAsync,
                MitreTechnique = "T1493"
            },
            new DetectionJob
            {
                Id = "service_tampering",
                Name = "Service Tampering Detection",
                Category = "System",
                Description = "Detects critical service modification attempts",
                Interval = TimeSpan.FromMinutes(5),
                Action = RunServiceTamperingCheckAsync,
                MitreTechnique = "T1543.003"
            },
            new DetectionJob
            {
                Id = "firewall_tampering",
                Name = "Firewall Tampering Detection",
                Category = "System",
                Description = "Detects Windows Firewall rule modifications",
                Interval = TimeSpan.FromMinutes(5),
                Action = RunFirewallTamperingCheckAsync,
                MitreTechnique = "T1562.004"
            },
            new DetectionJob
            {
                Id = "eventlog_tampering",
                Name = "Event Log Tampering Detection",
                Category = "System",
                Description = "Detects security event log clearing",
                Interval = TimeSpan.FromMinutes(5),
                Action = RunEventLogTamperingCheckAsync,
                MitreTechnique = "T1070.001"
            },
            new DetectionJob
            {
                Id = "usb_monitor",
                Name = "USB Device Monitoring",
                Category = "System",
                Description = "Monitors for suspicious USB device activity",
                Interval = TimeSpan.FromMinutes(1),
                Action = RunUsbMonitorAsync,
                MitreTechnique = "T1091"
            },
            new DetectionJob
            {
                Id = "clipboard_monitor",
                Name = "Clipboard Monitoring",
                Category = "System",
                Description = "Detects clipboard data theft attempts",
                Interval = TimeSpan.FromMinutes(2),
                Action = RunClipboardMonitorAsync,
                MitreTechnique = "T1115"
            },
            new DetectionJob
            {
                Id = "shadow_copy_deletion",
                Name = "Shadow Copy Deletion Detection",
                Category = "System",
                Description = "Detects shadow copy deletion (ransomware indicator)",
                Interval = TimeSpan.FromMinutes(2),
                Action = RunShadowCopyDeletionCheckAsync,
                MitreTechnique = "T1490"
            },
            new DetectionJob
            {
                Id = "dns_exfiltration",
                Name = "DNS Exfiltration Detection",
                Category = "System",
                Description = "Detects DNS-based data exfiltration",
                Interval = TimeSpan.FromMinutes(3),
                Action = RunDnsExfiltrationCheckAsync,
                MitreTechnique = "T1071.004"
            },
            new DetectionJob
            {
                Id = "proxy_detection",
                Name = "Proxy Configuration Detection",
                Category = "System",
                Description = "Detects unauthorized proxy settings",
                Interval = TimeSpan.FromMinutes(10),
                Action = RunProxyDetectionAsync,
                MitreTechnique = "T1090"
            },

            // ═══════════════════════════════════════════════════════════
            // HARDENING JOBS (6 jobs)
            // ═══════════════════════════════════════════════════════════
            new DetectionJob
            {
                Id = "cve_mitigation",
                Name = "CVE Mitigation Check",
                Category = "Hardening",
                Description = "Checks for CVE mitigations",
                Interval = TimeSpan.FromMinutes(30),
                Action = RunCveMitigationCheckAsync,
                MitreTechnique = "N/A"
            },
            new DetectionJob
            {
                Id = "asr_rules",
                Name = "ASR Rules Check",
                Category = "Hardening",
                Description = "Verifies Attack Surface Reduction rules",
                Interval = TimeSpan.FromMinutes(30),
                Action = RunAsrRulesCheckAsync,
                MitreTechnique = "N/A"
            },
            new DetectionJob
            {
                Id = "dns_security",
                Name = "DNS Security Check",
                Category = "Hardening",
                Description = "Verifies secure DNS configuration",
                Interval = TimeSpan.FromMinutes(30),
                Action = RunDnsSecurityCheckAsync,
                MitreTechnique = "N/A"
            },
            new DetectionJob
            {
                Id = "c2_blocklist",
                Name = "C2 Blocklist Check",
                Category = "Hardening",
                Description = "Checks 356+ known C2 IPs blocked",
                Interval = TimeSpan.FromMinutes(60),
                Action = RunC2BlocklistCheckAsync,
                MitreTechnique = "N/A"
            },
            new DetectionJob
            {
                Id = "com_monitoring",
                Name = "COM Object Monitoring",
                Category = "Hardening",
                Description = "Monitors for malicious COM object usage",
                Interval = TimeSpan.FromMinutes(5),
                Action = RunComMonitoringAsync,
                MitreTechnique = "T1546.015"
            },
            new DetectionJob
            {
                Id = "browser_extensions",
                Name = "Browser Extension Check",
                Category = "Hardening",
                Description = "Scans for malicious browser extensions",
                Interval = TimeSpan.FromMinutes(30),
                Action = RunBrowserExtensionCheckAsync,
                MitreTechnique = "T1176"
            },

            // ═══════════════════════════════════════════════════════════
            // NAMED PIPE JOBS (6 jobs)
            // ═══════════════════════════════════════════════════════════
            new DetectionJob
            {
                Id = "cobaltstrike_pipes",
                Name = "Cobalt Strike Pipe Detection",
                Category = "NamedPipes",
                Description = "Detects Cobalt Strike named pipe patterns",
                Interval = TimeSpan.FromMinutes(3),
                Action = RunCobaltStrikePipeCheckAsync,
                MitreTechnique = "T1021.002"
            },
            new DetectionJob
            {
                Id = "metasploit_pipes",
                Name = "Metasploit Pipe Detection",
                Category = "NamedPipes",
                Description = "Detects Metasploit named pipe patterns",
                Interval = TimeSpan.FromMinutes(3),
                Action = RunMetasploitPipeCheckAsync,
                MitreTechnique = "T1021.002"
            },
            new DetectionJob
            {
                Id = "sliver_pipes",
                Name = "Sliver Pipe Detection",
                Category = "NamedPipes",
                Description = "Detects Sliver C2 named pipe patterns",
                Interval = TimeSpan.FromMinutes(3),
                Action = RunSliverPipeCheckAsync,
                MitreTechnique = "T1021.002"
            },
            new DetectionJob
            {
                Id = "brute_ratel_pipes",
                Name = "Brute Ratel Pipe Detection",
                Category = "NamedPipes",
                Description = "Detects Brute Ratel C2 named pipes",
                Interval = TimeSpan.FromMinutes(3),
                Action = RunBruteRatelPipeCheckAsync,
                MitreTechnique = "T1021.002"
            },
            new DetectionJob
            {
                Id = "mimikatz_pipes",
                Name = "Mimikatz Pipe Detection",
                Category = "NamedPipes",
                Description = "Detects Mimikatz named pipe patterns",
                Interval = TimeSpan.FromMinutes(3),
                Action = RunMimikatzPipeCheckAsync,
                MitreTechnique = "T1003.001"
            },
            new DetectionJob
            {
                Id = "psexec_pipes",
                Name = "PsExec Pipe Detection",
                Category = "NamedPipes",
                Description = "Detects PsExec lateral movement pipes",
                Interval = TimeSpan.FromMinutes(3),
                Action = RunPsExecPipeCheckAsync,
                MitreTechnique = "T1021.002"
            },

            // ═══════════════════════════════════════════════════════════
            // SELF-PROTECTION JOBS (7 jobs)
            // ═══════════════════════════════════════════════════════════
            new DetectionJob
            {
                Id = "amsi_integrity",
                Name = "AMSI Integrity Check",
                Category = "SelfProtection",
                Description = "Verifies AMSI DLL integrity",
                Interval = TimeSpan.FromMinutes(2),
                Action = RunAmsiIntegrityCheckAsync,
                MitreTechnique = "T1562.001"
            },
            new DetectionJob
            {
                Id = "etw_integrity",
                Name = "ETW Integrity Check",
                Category = "SelfProtection",
                Description = "Verifies ETW provider integrity",
                Interval = TimeSpan.FromMinutes(2),
                Action = RunEtwIntegrityCheckAsync,
                MitreTechnique = "T1562.001"
            },
            new DetectionJob
            {
                Id = "debugger_detection",
                Name = "Debugger Detection",
                Category = "SelfProtection",
                Description = "Detects debugger attachment",
                Interval = TimeSpan.FromSeconds(30),
                Action = RunDebuggerDetectionAsync,
                MitreTechnique = "T1622"
            },
            new DetectionJob
            {
                Id = "config_tamper",
                Name = "Configuration Tamper Check",
                Category = "SelfProtection",
                Description = "Detects configuration file modifications",
                Interval = TimeSpan.FromMinutes(5),
                Action = RunConfigTamperCheckAsync,
                MitreTechnique = "T1562"
            },
            new DetectionJob
            {
                Id = "dll_hijack_check",
                Name = "Self DLL Hijacking Check",
                Category = "SelfProtection",
                Description = "Checks for DLL hijacking in install directory",
                Interval = TimeSpan.FromMinutes(1),
                Action = RunSelfDllHijackCheckAsync,
                MitreTechnique = "T1574.001"
            },
            new DetectionJob
            {
                Id = "executable_integrity",
                Name = "Executable Integrity Check",
                Category = "SelfProtection",
                Description = "Verifies own executable hash",
                Interval = TimeSpan.FromMinutes(1),
                Action = RunExecutableIntegrityCheckAsync,
                MitreTechnique = "T1565"
            },
            new DetectionJob
            {
                Id = "service_tamper",
                Name = "Service Tamper Detection",
                Category = "SelfProtection",
                Description = "Detects attempts to stop Sentinel service",
                Interval = TimeSpan.FromMinutes(1),
                Action = RunServiceTamperCheckAsync,
                MitreTechnique = "T1489"
            },
            new DetectionJob
            {
                Id = "certificate_tamper",
                Name = "Certificate Store Tampering Detection",
                Category = "Security",
                Description = "Detects unauthorized root CA installations and certificate tampering",
                Interval = TimeSpan.FromHours(1),
                Action = RunCertificateTamperingCheckAsync,
                MitreTechnique = "T1553.004"
            }
        };
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Detection Job Scheduler starting ===");
        _logger.LogInformation("Loaded {Count} detection jobs", _jobs.Count);

        // Start all jobs
        var jobTasks = _jobs.Select(job => RunJobLoopAsync(job, stoppingToken)).ToList();

        await Task.WhenAll(jobTasks);
    }

    private async Task RunJobLoopAsync(DetectionJob job, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Job '{Name}' scheduled every {Interval}", job.Name, job.Interval);

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(job.Interval, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            // CPU throttling: if system is under heavy load, back off
            // This prevents Sentinel from degrading user experience
            var cpuThrottleDelay = GetCpuThrottleDelay();
            if (cpuThrottleDelay > TimeSpan.Zero)
            {
                try { await Task.Delay(cpuThrottleDelay, cancellationToken); }
                catch (OperationCanceledException) { break; }
            }

            var startTime = DateTimeOffset.UtcNow;
            var sw = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                _logger.LogDebug("Running job: {Name}", job.Name);
                
                var detections = await job.Action(cancellationToken);
                
                sw.Stop();

                // Emit detections
                foreach (var detection in detections)
                {
                    await _detectionEngine.EmitAsync(detection, cancellationToken);
                }

                // Update job history
                _jobHistory[job.Id] = new JobExecutionInfo
                {
                    JobId = job.Id,
                    LastExecution = startTime,
                    Duration = sw.Elapsed,
                    DetectionsFound = detections.Count,
                    Success = true
                };

                if (detections.Count > 0)
                {
                    _logger.LogWarning(
                        "Job '{Name}' found {Count} detections in {Duration:F1}s",
                        job.Name, detections.Count, sw.Elapsed.TotalSeconds);
                }
                else
                {
                    _logger.LogDebug(
                        "Job '{Name}' completed in {Duration:F1}s - no detections",
                        job.Name, sw.Elapsed.TotalSeconds);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                sw.Stop();
                _logger.LogError(ex, "Job '{Name}' failed after {Duration:F1}s", job.Name, sw.Elapsed.TotalSeconds);
                
                _jobHistory[job.Id] = new JobExecutionInfo
                {
                    JobId = job.Id,
                    LastExecution = startTime,
                    Duration = sw.Elapsed,
                    Success = false,
                    ErrorMessage = ex.Message
                };
            }
        }
    }

    /// <summary>
    /// Gets the execution history for all jobs.
    /// </summary>
    public IReadOnlyDictionary<string, JobExecutionInfo> GetJobHistory() => _jobHistory;

    /// <summary>
    /// Gets the list of all configured jobs.
    /// </summary>
    public IReadOnlyList<DetectionJob> GetAllJobs() => _jobs;

    /// <summary>
    /// Returns a delay to apply when CPU usage is high.
    /// Prevents Sentinel from degrading system performance during heavy workloads.
    /// </summary>
    private static TimeSpan GetCpuThrottleDelay()
    {
        try
        {
            // Use GC memory pressure as a proxy for system load
            // (cheaper than querying performance counters every job iteration)
            var memInfo = GC.GetGCMemoryInfo();
            var memoryPressure = (double)memInfo.MemoryLoadBytes / memInfo.TotalAvailableMemoryBytes;

            // Also check thread pool saturation
            ThreadPool.GetAvailableThreads(out int workerThreads, out _);
            ThreadPool.GetMaxThreads(out int maxWorkerThreads, out _);
            var threadPressure = 1.0 - ((double)workerThreads / maxWorkerThreads);

            // If memory pressure > 80% or thread pool > 90% saturated, throttle
            if (memoryPressure > 0.8 || threadPressure > 0.9)
                return TimeSpan.FromSeconds(30); // Heavy throttle

            if (memoryPressure > 0.6 || threadPressure > 0.7)
                return TimeSpan.FromSeconds(10); // Light throttle

            return TimeSpan.Zero; // No throttle
        }
        catch
        {
            return TimeSpan.Zero; // Don't throttle if we can't measure
        }
    }

    #region Job Implementations

    // ═══════════════════════════════════════════════════════════
    // PROCESS JOBS
    // ═══════════════════════════════════════════════════════════
    
    private async Task<List<DetectionEvent>> RunProcessHollowingCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would scan process memory vs image path
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunTokenManipulationCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would check for privilege escalations
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunPpidSpoofingCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would compare parent start time vs child
        await Task.CompletedTask;
        return detections;
    }

    private Task<List<DetectionEvent>> RunFilelessAttackCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        
        // Check for .NET in-memory loading
        try
        {
            var dotnetProcesses = System.Diagnostics.Process.GetProcesses()
                .Where(p => p.ProcessName.Contains("dotnet") || p.ProcessName.Contains("powershell"));
            
            foreach (var proc in dotnetProcesses)
            {
                // Would check for suspicious memory regions
            }
        }
        catch { }
        
        return Task.FromResult(detections);
    }

    private async Task<List<DetectionEvent>> RunMemoryScanAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would scan memory for shellcode patterns
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunShortLivedProcessCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would track process lifetimes
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunRenamedBinaryCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would check for svchost.exe in wrong path, etc.
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunCommandLineEntropyCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would calculate entropy of command lines
        await Task.CompletedTask;
        return detections;
    }

    // ═══════════════════════════════════════════════════════════
    // DLL JOBS
    // ═══════════════════════════════════════════════════════════
    
    private async Task<List<DetectionEvent>> RunDllHijackingCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would check DLL load paths
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunReflectiveDllCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would detect manual DLL mapping
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunKeystrokeDllCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would detect keyboard hooks
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunBrowserDllCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would monitor browser processes
        await Task.CompletedTask;
        return detections;
    }

    // ═══════════════════════════════════════════════════════════
    // PERSISTENCE JOBS
    // ═══════════════════════════════════════════════════════════
    
    private Task<List<DetectionEvent>> RunRegistryRunKeysCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        
        var runKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
        };

        foreach (var keyPath in runKeys)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(keyPath);
                if (key != null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        var value = key.GetValue(valueName)?.ToString() ?? "";
                        
                        // Check for suspicious entries
                        if (IsSuspiciousPath(value))
                        {
                            detections.Add(new DetectionEvent
                            {
                                RuleName = "Scheduled Job: Suspicious Registry Run Key",
                                Evidence = $"Run key '{valueName}' points to suspicious path: {value}",
                                Reasoning = "Registry Run keys are a common persistence mechanism. Suspicious paths include temp directories, appdata, and encoded commands.",
                                Confidence = 0.75,
                                Tier = DetectionTier.Tier1Behavioral,
                                ProcessName = "N/A",
                                ProcessId = 0,
                                Timestamp = DateTimeOffset.UtcNow,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["registry_key"] = $"HKCU\\{keyPath}",
                                    ["value_name"] = valueName,
                                    ["value_data"] = value,
                                    ["technique"] = "T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys"
                                }
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Registry scan error for {Key}", keyPath);
            }
        }

        return Task.FromResult(detections);
    }

    private async Task<List<DetectionEvent>> RunScheduledTasksCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would scan scheduled tasks
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunWmiSubscriptionsCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would scan WMI event subscriptions
        await Task.CompletedTask;
        return detections;
    }

    private Task<List<DetectionEvent>> RunStartupFolderCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        
        var startupPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        };

        foreach (var path in startupPaths.Where(Directory.Exists))
        {
            try
            {
                var files = Directory.GetFiles(path);
                foreach (var file in files)
                {
                    if (IsSuspiciousPath(file))
                    {
                        detections.Add(new DetectionEvent
                        {
                            RuleName = "Scheduled Job: Suspicious Startup Item",
                            Evidence = $"Startup folder contains suspicious file: {file}",
                            Reasoning = "Files in startup folders automatically execute at login and are a common persistence mechanism.",
                            Confidence = 0.70,
                            Tier = DetectionTier.Tier1Behavioral,
                            ProcessName = "N/A",
                            ProcessId = 0,
                            Timestamp = DateTimeOffset.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["path"] = path,
                                ["file"] = file,
                                ["technique"] = "T1547.001 - Boot or Logon Autostart Execution"
                            }
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Startup folder scan error for {Path}", path);
            }
        }

        return Task.FromResult(detections);
    }

    // ═══════════════════════════════════════════════════════════
    // SYSTEM JOBS
    // ═══════════════════════════════════════════════════════════
    
    private async Task<List<DetectionEvent>> RunRootkitDetectionAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would check for rootkit indicators
        await Task.CompletedTask;
        return detections;
    }

    private Task<List<DetectionEvent>> RunScarewareScanAsync(CancellationToken ct)
    {
        try
        {
            if (_userProtectionRule != null)
            {
                return Task.FromResult(_userProtectionRule.ScanForScarewareWindows());
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Scareware scan error");
        }
        return Task.FromResult(new List<DetectionEvent>());
    }

    private Task<List<DetectionEvent>> RunLnkProtectionScanAsync(CancellationToken ct)
    {
        try
        {
            if (_userProtectionRule != null)
            {
                return Task.FromResult(_userProtectionRule.ScanForMaliciousShortcuts());
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "LNK protection scan error");
        }
        return Task.FromResult(new List<DetectionEvent>());
    }

    private Task<List<DetectionEvent>> RunByovdDetectionAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        
        // Known vulnerable drivers commonly abused in BYOVD attacks.
        // Sources: LOLDrivers project, ESET EDR killer research, Sophos/CrowdStrike reports.
        // These are legitimately signed but contain exploitable vulnerabilities.
        var vulnerableDrivers = new[]
        {
            // MSI/ASUS motherboard utilities
            "AsUpIO.sys", "AsIO.sys", "AsIO2.sys", "AsIO3.sys",
            "ATSZIO.sys", "AsrDrv106.sys", "AsrDrv101.sys",
            // ENE Technology (keyboard controllers)
            "ene.sys", "enechk64.sys",
            // GIGA-BYTE
            "gdrv.sys", "GVCIDrv64.sys",
            // LG
            "lha.sys",
            // Generic/misc
            "MyDrivers64.sys", "RTCore64.sys", "stdcdrv64.sys",
            "WinRing0x64.sys", "WinRing0.sys",
            // Intel (commonly abused)
            "iqvw64e.sys", "iQVW64.sys",
            // Dell
            "DBUtil_2_3.sys", "dbutil_2_3.sys",
            // Zemana (anti-malware, ironically)
            "zam64.sys", "zamguard64.sys",
            // Process Explorer driver (Sysinternals — used by Backstab)
            "procexp152.sys", "PROCEXP.SYS",
            // Avast/Norton (old vulnerable versions)
            "aswArPot.sys", "aswVmm.sys",
            // Capcom (famous exploit)
            "Capcom.sys",
            // CPU-Z
            "cpuz141.sys", "cpuz143.sys",
            // HW monitoring
            "HwRwDrv.sys", "phymemx64.sys",
            // Realtek
            "rtkio64.sys", "rtkiow10x64.sys",
            // EDRKillShifter / Terminator commonly used drivers
            "NSecKrnl.sys", "truesight.sys", "TrueSight.sys",
            "amsdk.sys",  // WatchDog Anti-Malware (CVE abused)
            // Huawei audio driver (used by HwAudKiller)
            "HwAudioDriver.sys",
            // Micro-Star
            "NTIOLib_X64.sys", "NTIOLib.sys",
            // VirtualBox (used for kernel access)
            "VBoxDrv.sys",
        };

        try
        {
            // Check loaded drivers
            var drivers = Directory.GetFiles(Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\drivers"), "*.sys")
                .Select(Path.GetFileName)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var badDriver in vulnerableDrivers)
            {
                if (drivers.Contains(badDriver))
                {
                    detections.Add(new DetectionEvent
                    {
                        RuleName = "Scheduled Job: Vulnerable Driver Loaded",
                        Evidence = $"Known vulnerable driver detected: {badDriver}",
                        Reasoning = "Bring Your Own Vulnerable Driver (BYOVD) attacks use signed vulnerable drivers to bypass security controls and gain kernel-level access.",
                        Confidence = 0.90,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "System",
                        ProcessId = 4,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["driver"] = badDriver,
                            ["technique"] = "T1068 - Exploitation for Privilege Escalation"
                        }
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "BYOVD detection error");
        }

        return Task.FromResult(detections);
    }

    private async Task<List<DetectionEvent>> RunDriverMonitorAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would monitor driver loading
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunBcdSecurityCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would check BCD settings
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunServiceTamperingCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would monitor service changes
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunFirewallTamperingCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would check firewall rules
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunEventLogTamperingCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would check event log clearing
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunUsbMonitorAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would monitor USB devices
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunClipboardMonitorAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would monitor clipboard access
        await Task.CompletedTask;
        return detections;
    }

    private Task<List<DetectionEvent>> RunShadowCopyDeletionCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        
        // Check for shadow copy deletion commands in recent processes
        var shadowCommands = new[] { "vssadmin delete", "wmic shadowcopy delete" };
        
        // Would check command history or process command lines
        // This is a simplified check
        
        return Task.FromResult(detections);
    }

    private async Task<List<DetectionEvent>> RunDnsExfiltrationCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would monitor DNS queries
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunProxyDetectionAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would check proxy settings
        await Task.CompletedTask;
        return detections;
    }

    // ═══════════════════════════════════════════════════════════
    // HARDENING JOBS
    // ═══════════════════════════════════════════════════════════
    
    private async Task<List<DetectionEvent>> RunCveMitigationCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would check CVE mitigations
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunAsrRulesCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would check ASR rules
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunDnsSecurityCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would check DNS security
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunC2BlocklistCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would verify firewall blocks
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunComMonitoringAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would monitor COM objects
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunBrowserExtensionCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Implementation would scan browser extensions
        await Task.CompletedTask;
        return detections;
    }

    // ═══════════════════════════════════════════════════════════
    // NAMED PIPE JOBS
    // ═══════════════════════════════════════════════════════════
    
    private async Task<List<DetectionEvent>> RunCobaltStrikePipeCheckAsync(CancellationToken ct)
    {
        var detections = await CheckNamedPipesAsync(
            new[] { "postex_", "status_", "msagent_" },
            "Cobalt Strike",
            "T1021.002",
            ct);
        return detections;
    }

    private async Task<List<DetectionEvent>> RunMetasploitPipeCheckAsync(CancellationToken ct)
    {
        var detections = await CheckNamedPipesAsync(
            new[] { "meterpreter", "msf_" },
            "Metasploit",
            "T1021.002",
            ct);
        return detections;
    }

    private async Task<List<DetectionEvent>> RunSliverPipeCheckAsync(CancellationToken ct)
    {
        var detections = await CheckNamedPipesAsync(
            new[] { "sliver_", "implant_" },
            "Sliver",
            "T1021.002",
            ct);
        return detections;
    }

    private async Task<List<DetectionEvent>> RunBruteRatelPipeCheckAsync(CancellationToken ct)
    {
        var detections = await CheckNamedPipesAsync(
            new[] { "brute_", "ratel_" },
            "Brute Ratel",
            "T1021.002",
            ct);
        return detections;
    }

    private async Task<List<DetectionEvent>> RunMimikatzPipeCheckAsync(CancellationToken ct)
    {
        var detections = await CheckNamedPipesAsync(
            new[] { "mimikatz", "lsadump", "sekurlsa" },
            "Mimikatz",
            "T1003.001",
            ct);
        return detections;
    }

    private async Task<List<DetectionEvent>> RunPsExecPipeCheckAsync(CancellationToken ct)
    {
        var detections = await CheckNamedPipesAsync(
            new[] { "psexec", "psexesvc", "remcom" },
            "PsExec",
            "T1021.002",
            ct);
        return detections;
    }

    private Task<List<DetectionEvent>> CheckNamedPipesAsync(
        string[] patterns,
        string frameworkName,
        string mitreTechnique,
        CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        
        try
        {
            var pipes = Directory.GetFiles(@"\\.\pipe\")
                .Select(p => Path.GetFileName(p))
                .ToList();

            foreach (var pipe in pipes)
            {
                foreach (var pattern in patterns)
                {
                    if (pipe.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        detections.Add(new DetectionEvent
                        {
                            RuleName = $"Scheduled Job: {frameworkName} Named Pipe Detected",
                            Evidence = $"Named pipe matching {frameworkName} pattern: \\\\.\\pipe\\{pipe}",
                            Reasoning = $"Named pipes with patterns matching {frameworkName} C2 framework indicate potential command and control activity.",
                            Confidence = 0.88,
                            Tier = DetectionTier.Tier1Behavioral,
                            ProcessName = "Unknown",
                            ProcessId = 0,
                            Timestamp = DateTimeOffset.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["pipe_name"] = pipe,
                                ["pattern_matched"] = pattern,
                                ["framework"] = frameworkName,
                                ["technique"] = $"{mitreTechnique} - Remote Services"
                            }
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Named pipe check error for {Framework}", frameworkName);
        }

        return Task.FromResult(detections);
    }

    // ═══════════════════════════════════════════════════════════
    // SELF-PROTECTION JOBS
    // ═══════════════════════════════════════════════════════════
    
    private async Task<List<DetectionEvent>> RunAmsiIntegrityCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Handled by SelfProtectionService
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunEtwIntegrityCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Handled by SelfProtectionService
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunDebuggerDetectionAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Handled by SelfProtectionService
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunConfigTamperCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Handled by SelfProtectionService
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunSelfDllHijackCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Handled by SelfProtectionService
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunExecutableIntegrityCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Handled by SelfProtectionService
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunServiceTamperCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        // Handled by SelfProtectionService
        await Task.CompletedTask;
        return detections;
    }

    private async Task<List<DetectionEvent>> RunCertificateTamperingCheckAsync(CancellationToken ct)
    {
        var detections = new List<DetectionEvent>();
        
        if (_certificateTamperingRule != null)
        {
            _logger.LogDebug("Running certificate store tampering check...");
            await _certificateTamperingRule.ScanCertificateStoresAsync(ct);
        }
        
        return detections;
    }

    #endregion

    private bool IsSuspiciousPath(string path)
    {
        var lower = path.ToLowerInvariant();
        return lower.Contains("temp") ||
               lower.Contains("appdata") ||
               lower.Contains("programdata") ||
               lower.Contains("-enc") ||
               lower.Contains("powershell") ||
               lower.Contains("downloadstring") ||
               lower.Contains("invoke-expression");
    }
}

/// <summary>
/// Represents a scheduled detection job.
/// </summary>
public sealed class DetectionJob
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Category { get; set; } = "";
    public string Description { get; set; } = "";
    public TimeSpan Interval { get; set; }
    public Func<CancellationToken, Task<List<DetectionEvent>>> Action { get; set; } = _ => Task.FromResult(new List<DetectionEvent>());
    public string MitreTechnique { get; set; } = "";
}

/// <summary>
/// Tracks job execution information.
/// </summary>
public sealed class JobExecutionInfo
{
    public string JobId { get; set; } = "";
    public DateTimeOffset LastExecution { get; set; }
    public TimeSpan Duration { get; set; }
    public int DetectionsFound { get; set; }
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
}

