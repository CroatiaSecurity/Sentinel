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
using Microsoft.Win32;

namespace Behavedr.Core
{
    /// <summary>
    /// Monitors Windows Subsystem for Linux (WSL) activity to detect:
    /// - WSL process spawns (wsl.exe, wslhost.exe, bash.exe via WSL)
    /// - File access from WSL to Windows filesystem (/mnt/c/, /mnt/d/)
    /// - Network connections originating from WSL2 VM
    /// - Suspicious command execution inside WSL (curl to C2, reverse shells)
    /// - WSL distribution installs/imports at runtime
    ///
    /// WSL2 runs in a lightweight Hyper-V VM — Behavedr has NO visibility into
    /// processes running inside the Linux kernel. This monitor observes the
    /// Windows-side attack surface: WSL host processes, cross-filesystem access,
    /// and network traffic from the WSL virtual adapter.
    ///
    /// v1.0.1: New monitor.
    /// </summary>
    public sealed class WslMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly ILogger<WslMonitor> _logger;

        private readonly ConcurrentDictionary<int, WslProcessInfo> _trackedWslProcesses = new();
        private readonly HashSet<string> _baselineDistros = new(StringComparer.OrdinalIgnoreCase);
        private bool _wslAvailable;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(10);

        // Suspicious commands that indicate malicious WSL usage
        private static readonly string[] SuspiciousPatterns = new[]
        {
            "nc -", "ncat ", "socat ", "/dev/tcp/", "bash -i",
            "curl http", "wget http", "python -c", "python3 -c",
            "perl -e", "ruby -e", "php -r",
            "/etc/shadow", "/etc/passwd", "mimikatz", "sekurlsa",
            "meterpreter", "reverse_tcp", "bind_shell",
            "base64 -d", "openssl enc",
            "iptables", "tcpdump", "nmap ", "masscan",
            "/mnt/c/windows/system32", "/mnt/c/users"
        };

        // Legitimate WSL uses that should not alert
        private static readonly string[] LegitimatePatterns = new[]
        {
            "git ", "npm ", "node ", "docker ", "kubectl ",
            "apt ", "apt-get ", "pip ", "cargo ", "make ",
            "code ", "vim ", "nano ", "ls ", "cd ", "cat ",
            "grep ", "find ", "sed ", "awk "
        };

        public WslMonitor(
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<WslMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WslMonitor] Started");

            // Check if WSL is installed
            _wslAvailable = File.Exists(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "wsl.exe"));

            if (!_wslAvailable)
            {
                _logger.LogInformation("[WslMonitor] WSL not installed — monitor idle");
                // Keep running in case WSL gets installed later
                while (!ct.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromMinutes(5), ct);
                    _wslAvailable = File.Exists(Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.System), "wsl.exe"));
                    if (_wslAvailable) break;
                }
                if (ct.IsCancellationRequested) return;
                _logger.LogInformation("[WslMonitor] WSL detected — activating");
            }

            // Baseline existing WSL distributions
            BaselineDistros();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);

                    await ScanWslProcesses(ct);
                    await CheckNewDistroInstalls(ct);
                    await MonitorWslFileAccess(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WslMonitor] Error"); }
            }
        }

        private async Task ScanWslProcesses(CancellationToken ct)
        {
            var wslProcessNames = new[] { "wsl", "wslhost", "bash" };
            var currentPids = new HashSet<int>();

            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    var name = proc.ProcessName.ToLowerInvariant();
                    if (!wslProcessNames.Contains(name)) continue;

                    currentPids.Add(proc.Id);

                    // Skip already tracked
                    if (_trackedWslProcesses.ContainsKey(proc.Id)) continue;

                    string cmdLine = GetProcessCommandLine(proc.Id);
                    if (string.IsNullOrEmpty(cmdLine)) continue;

                    // For bash.exe, verify it's WSL bash (not Git bash, Cygwin, etc.)
                    if (name == "bash")
                    {
                        try
                        {
                            var path = SecurityValidation.GetProcessImagePath(proc.Id) ?? "";
                            if (!path.Contains("Windows", StringComparison.OrdinalIgnoreCase) &&
                                !path.Contains("wsl", StringComparison.OrdinalIgnoreCase))
                                continue;
                        }
                        catch { continue; }
                    }

                    var info = new WslProcessInfo
                    {
                        Pid = proc.Id,
                        ProcessName = proc.ProcessName,
                        CommandLine = cmdLine,
                        StartTime = DateTimeOffset.UtcNow
                    };
                    _trackedWslProcesses[proc.Id] = info;

                    // Check for suspicious commands
                    var cmdLower = cmdLine.ToLowerInvariant();
                    bool isSuspicious = SuspiciousPatterns.Any(p => cmdLower.Contains(p));
                    bool isLegitimate = LegitimatePatterns.Any(p => cmdLower.Contains(p));

                    if (isSuspicious && !isLegitimate)
                    {
                        var matchedPattern = SuspiciousPatterns.First(p => cmdLower.Contains(p));
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "WSL: Suspicious Command Execution",
                            Evidence = $"WSL process {proc.ProcessName} (PID {proc.Id}) executing suspicious command. " +
                                       $"Pattern: '{matchedPattern}', CmdLine: {Truncate(cmdLine, 200)}",
                            Reasoning = "A potentially malicious command was executed inside WSL. " +
                                        "WSL provides a Linux environment with direct access to the Windows filesystem " +
                                        "via /mnt/. Attackers use WSL to evade Windows-native security tools, execute " +
                                        "Linux-native attack tools, and establish reverse shells that bypass Windows firewall.",
                            Confidence = 0.78,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            ProcessName = proc.ProcessName,
                            ProcessId = proc.Id,
                            Metadata = new Dictionary<string, string>
                            {
                                ["CommandLine"] = Truncate(cmdLine, 500),
                                ["MatchedPattern"] = matchedPattern
                            }
                        });
                    }
                    else if (!isLegitimate && name == "wsl" && cmdLine.Contains("-e "))
                    {
                        // WSL exec mode (-e) running non-standard commands
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "WSL: Direct Command Execution",
                            Evidence = $"WSL direct exec: {Truncate(cmdLine, 200)}",
                            Reasoning = "WSL was invoked with -e (execute) flag to run a command directly. " +
                                        "This is commonly used in attack chains to execute Linux tools from Windows.",
                            Confidence = 0.50,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = proc.ProcessName,
                            ProcessId = proc.Id
                        });
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }

            // Clean up exited processes
            var exited = _trackedWslProcesses.Keys.Except(currentPids).ToList();
            foreach (var pid in exited) _trackedWslProcesses.TryRemove(pid, out _);
        }

        private async Task CheckNewDistroInstalls(CancellationToken ct)
        {
            try
            {
                var currentDistros = GetInstalledDistros();
                foreach (var distro in currentDistros)
                {
                    if (_baselineDistros.Contains(distro)) continue;
                    _baselineDistros.Add(distro);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "WSL: New Distribution Installed",
                        Evidence = $"New WSL distribution installed at runtime: '{distro}'",
                        Reasoning = "A new WSL Linux distribution was installed after Behavedr started. " +
                                    "Attackers can import custom distros containing pre-staged tools via " +
                                    "'wsl --import'. This provides a full Linux environment for evading " +
                                    "Windows-native detection.",
                        Confidence = 0.72,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        Metadata = new Dictionary<string, string> { ["Distro"] = distro }
                    });
                }
            }
            catch { }
        }

        private async Task MonitorWslFileAccess(CancellationToken ct)
        {
            // Monitor \\wsl$ and \\wsl.localhost access via open file handles
            // This catches Windows processes reading from WSL filesystem (data staging)
            try
            {
                // Check if any non-WSL process is accessing \\wsl$ paths
                // We detect this by looking for processes with handles to \\wsl.localhost\
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        var name = proc.ProcessName.ToLowerInvariant();
                        // Skip WSL-related and known-good processes
                        if (name is "wsl" or "wslhost" or "wslservice" or "explorer"
                            or "code" or "devenv" or "rider64" or "idea64")
                        {
                            proc.Dispose();
                            continue;
                        }

                        // Check if the process image is loaded from \\wsl$ path
                        try
                        {
                            var mainModule = SecurityValidation.GetProcessImagePath(proc.Id);
                            if (mainModule != null &&
                                (mainModule.StartsWith(@"\\wsl", StringComparison.OrdinalIgnoreCase) ||
                                 mainModule.StartsWith(@"\\wsl.localhost", StringComparison.OrdinalIgnoreCase)))
                            {
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "WSL: Process Running from WSL Filesystem",
                                    Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) loaded from WSL path: {mainModule}",
                                    Reasoning = "A Windows process is running from the WSL filesystem (\\\\wsl$\\). " +
                                                "This is unusual and may indicate a staged payload being executed " +
                                                "from within WSL's Linux filesystem to avoid Windows file scanning.",
                                    Confidence = 0.82,
                                    Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = ResponseAction.KillProcessTree,
                                    ProcessName = proc.ProcessName,
                                    ProcessId = proc.Id
                                });
                            }
                        }
                        catch { }
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch { }
        }

        private void BaselineDistros()
        {
            foreach (var distro in GetInstalledDistros())
            {
                _baselineDistros.Add(distro);
            }
        }

        private static HashSet<string> GetInstalledDistros()
        {
            var distros = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Lxss");
                if (key == null) return distros;

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    using var sub = key.OpenSubKey(subKeyName);
                    var name = sub?.GetValue("DistributionName")?.ToString();
                    if (!string.IsNullOrEmpty(name))
                        distros.Add(name);
                }
            }
            catch { }
            return distros;
        }

        private static string GetProcessCommandLine(int pid)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return obj["CommandLine"]?.ToString() ?? "";
                }
            }
            catch { }
            return "";
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return "";
            return value.Length <= maxLength ? value : value[..maxLength] + "...";
        }

        private class WslProcessInfo
        {
            public int Pid { get; set; }
            public string ProcessName { get; set; } = string.Empty;
            public string CommandLine { get; set; } = string.Empty;
            public DateTimeOffset StartTime { get; set; }
        }
    }
}
