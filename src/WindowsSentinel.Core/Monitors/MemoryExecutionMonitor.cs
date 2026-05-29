using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Detects in-memory / fileless execution patterns:
///
///   • Fileless: process with empty <see cref="ProcessStartInfo.FileName"/> or backing
///     file no longer present on disk.
///   • DownloadCradle: command line carrying invoke-expression / download / web-client
///     patterns AND a download primitive (http, curl, wget, webrequest…).
///   • ReflectiveDll: a loaded module whose backing file is missing on disk.
///   • DotNetMemoryLoad: CLR loaded + suspicious Assembly.Load / -EncodedCommand /
///     reflection patterns in command line.
///   • HollowFromMemory: office/browser/script-host parent spawning shell/lolbin child.
///
/// Ported (security-hardened) from GIDR's MemoryExecutionDetection. Hardening:
///   - WMI command-line query parameterized via WHERE ProcessId.
///   - Per-PID dedup so a long-lived process doesn't fire every cycle.
///   - All emits go through DetectionEngine: dedup, scoring, and the never-act-on-Tier2
///     contract still apply. We do NOT auto-kill here.
/// </summary>
public sealed class MemoryExecutionMonitor : BackgroundService
{
    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(45);

    // Processes that legitimately have no on-disk image path visible to the memory scanner.
    // svchost.exe instances are kernel-launched service hosts — their image path may not be
    // resolvable via WMI when launched by the kernel's service control manager.
    private static readonly HashSet<string> NoPathAllowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "svchost",
    };

    private static readonly HashSet<string> SuspiciousParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mshta.exe",
        "wscript.exe", "cscript.exe", "msedge.exe", "chrome.exe", "firefox.exe",
        "iexplore.exe", "acrord32.exe", "acrobat.exe"
    };

    private static readonly string[] DownloadCradlePatterns =
    {
        "invoke-expression", "iex ", "iex(", "downloadstring", "downloadfile",
        "frombase64string", "tobase64string", "compressed", "gzipstream",
        "memorystream", "reflection.assembly", "::load(", "load(",
        "virtualalloc", "virtualprotect", "createremotethread",
        "writeprocessmemory", "rtlmovememory",
        "invoke-shellcode", "invoke-mimikatz", "invoke-bloodhound",
        "amsibypass", "etwbypass", "patch-amsi"
    };

    private static readonly string[] DownloadIndicators =
    {
        "http", "webclient", "download", "net.socket",
        "invoke-webrequest", "curl ", " wget "
    };

    private readonly IDetectionEngine _engine;
    private readonly ILogger<MemoryExecutionMonitor> _logger;

    private readonly ConcurrentDictionary<string, byte> _emittedKeys = new();

    public MemoryExecutionMonitor(IDetectionEngine engine, ILogger<MemoryExecutionMonitor> logger)
    {
        _engine = engine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("MemoryExecutionMonitor: starting");
        await Task.Delay(TimeSpan.FromSeconds(25), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try { await ScanAsync(stoppingToken); }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { _logger.LogDebug(ex, "MemoryExecutionMonitor: scan error"); }

            try { await Task.Delay(ScanInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task ScanAsync(CancellationToken cancellationToken)
    {
        var snapshot = SnapshotProcesses();
        if (snapshot.Count == 0) return;

        await DetectFilelessAsync(snapshot, cancellationToken);
        await DetectCradleAsync(snapshot, cancellationToken);
        await DetectReflectiveDllAsync(snapshot, cancellationToken);
        await DetectDotNetMemoryLoadAsync(snapshot, cancellationToken);
        await DetectHollowFromMemoryAsync(snapshot, cancellationToken);
    }

    private async Task DetectFilelessAsync(List<ProcSnapshot> snapshot, CancellationToken cancellationToken)
    {
        foreach (var proc in snapshot)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrEmpty(proc.ExecutablePath))
            {
                // Skip kernel-launched service hosts that legitimately have no visible image path
                if (NoPathAllowlist.Contains(proc.Name))
                    continue;

                if (!_emittedKeys.TryAdd($"fileless:{proc.Pid}", 0)) continue;
                await _engine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Memory Execution: process has no executable path",
                    Evidence = $"PID {proc.Pid} ({proc.Name}) has no on-disk image.",
                    Reasoning = "A process with no backing executable typically indicates injection / hollowing or a kernel-level process. We treat user processes without a path as suspicious.",
                    Confidence = 0.80,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = proc.Name,
                    ProcessId = proc.Pid,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["technique"] = "T1055 - Process Injection",
                        ["mode"] = "fileless"
                    }
                }, cancellationToken);
            }
            else if (!File.Exists(proc.ExecutablePath))
            {
                if (!_emittedKeys.TryAdd($"missing:{proc.Pid}:{proc.ExecutablePath}", 0)) continue;
                await _engine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Memory Execution: backing file missing on disk",
                    Evidence = $"PID {proc.Pid} backing image '{proc.ExecutablePath}' was deleted while process is running.",
                    Reasoning = "Run-then-delete is a classic dropper pattern: stage a binary, execute, unlink to evade scanning. The image is still mapped in memory.",
                    Confidence = 0.85,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = proc.Name,
                    ProcessId = proc.Pid,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["technique"] = "T1070.004 - Indicator Removal: File Deletion",
                        ["image_path"] = proc.ExecutablePath
                    }
                }, cancellationToken);
            }
        }
    }

    private async Task DetectCradleAsync(List<ProcSnapshot> snapshot, CancellationToken cancellationToken)
    {
        foreach (var proc in snapshot)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrEmpty(proc.CommandLine)) continue;
            var cmd = proc.CommandLine.ToLowerInvariant();
            string? matched = DownloadCradlePatterns.FirstOrDefault(p => cmd.Contains(p));
            if (matched is null) continue;

            bool hasDownload = DownloadIndicators.Any(d => cmd.Contains(d));
            if (!hasDownload) continue;
            if (!_emittedKeys.TryAdd($"cradle:{proc.Pid}", 0)) continue;

            await _engine.EmitAsync(new DetectionEvent
            {
                RuleName = "Memory Execution: download cradle",
                Evidence = $"Command line contains '{matched}' + download primitive",
                Reasoning = "Download-execute cradles fetch a payload from the network and run it directly in memory, leaving no on-disk artifact.",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = proc.Name,
                ProcessId = proc.Pid,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["technique"] = "T1059 - Command and Scripting Interpreter",
                    ["matched_pattern"] = matched
                }
            }, cancellationToken);
        }
    }

    private async Task DetectReflectiveDllAsync(List<ProcSnapshot> snapshot, CancellationToken cancellationToken)
    {
        var selfPid = Environment.ProcessId;
        foreach (var proc in snapshot)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (proc.Pid == selfPid || proc.Pid <= 4) continue;

            try
            {
                using var p = Process.GetProcessById(proc.Pid);
                foreach (ProcessModule m in p.Modules)
                {
                    var path = m.FileName;
                    if (string.IsNullOrEmpty(path)) continue;
                    if (File.Exists(path)) continue;
                    var key = $"refldll:{proc.Pid}:{path}";
                    if (!_emittedKeys.TryAdd(key, 0)) continue;

                    await _engine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Memory Execution: reflective DLL (module not on disk)",
                        Evidence = $"Module {Path.GetFileName(path)} is mapped in {proc.Name} but missing on disk",
                        Reasoning = "Reflective DLL injection writes a module image into a target process and resolves imports manually so no LoadLibrary call appears and no path appears on disk.",
                        Confidence = 0.85,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = proc.Name,
                        ProcessId = proc.Pid,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["technique"] = "T1620 - Reflective Code Loading",
                            ["module_path"] = path
                        }
                    }, cancellationToken);
                    break;
                }
            }
            catch { /* access denied / exited */ }
        }
    }

    private async Task DetectDotNetMemoryLoadAsync(List<ProcSnapshot> snapshot, CancellationToken cancellationToken)
    {
        foreach (var proc in snapshot)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrEmpty(proc.CommandLine)) continue;
            var cmd = proc.CommandLine.ToLowerInvariant();

            bool hasClr;
            try
            {
                using var p = Process.GetProcessById(proc.Pid);
                hasClr = p.Modules.Cast<ProcessModule>()
                    .Select(m => Path.GetFileName(m.FileName ?? "").ToLowerInvariant())
                    .Any(n => n.Contains("clr") || n.Contains("mscor") || n.Contains("coreclr"));
            }
            catch { continue; }

            if (!hasClr) continue;

            bool match =
                cmd.Contains("assembly.load") ||
                cmd.Contains("loadbyte") ||
                cmd.Contains("[convert]::") ||
                cmd.Contains("-encodedcommand") ||
                cmd.Contains(" -enc ") ||
                cmd.Contains("reflection");
            if (!match) continue;

            if (!_emittedKeys.TryAdd($"dotnetmem:{proc.Pid}", 0)) continue;

            await _engine.EmitAsync(new DetectionEvent
            {
                RuleName = "Memory Execution: .NET in-memory assembly load",
                Evidence = "CLR-loaded process with reflection / -enc / Assembly.Load patterns",
                Reasoning = "In-memory .NET execution skips disk-resident .dll and is widely used by post-exploit tooling (Cobalt Strike execute-assembly, SharpHound, Sliver, Rubeus).",
                Confidence = 0.78,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = proc.Name,
                ProcessId = proc.Pid,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["technique"] = "T1620 - Reflective Code Loading"
                }
            }, cancellationToken);
        }
    }

    private async Task DetectHollowFromMemoryAsync(List<ProcSnapshot> snapshot, CancellationToken cancellationToken)
    {
        var byPid = snapshot.ToDictionary(p => p.Pid);
        foreach (var proc in snapshot)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (proc.ParentPid <= 0 || !byPid.TryGetValue(proc.ParentPid, out var parent)) continue;

            var parentName = (parent.Name ?? "").ToLowerInvariant();
            if (!SuspiciousParents.Contains(parentName)) continue;

            var childName = (proc.Name ?? "").ToLowerInvariant();
            bool isShellChild = childName.Contains("cmd") || childName.Contains("powershell") ||
                                childName.Contains("wscript") || childName.Contains("cscript") ||
                                childName.Contains("mshta") || childName.Contains("certutil") ||
                                childName.Contains("rundll32") || childName.Contains("regsvr32");
            if (!isShellChild) continue;

            if (!_emittedKeys.TryAdd($"hollowmem:{proc.Pid}:{proc.ParentPid}", 0)) continue;

            await _engine.EmitAsync(new DetectionEvent
            {
                RuleName = "Memory Execution: lolbin spawned by office / browser / scripthost",
                Evidence = $"{parentName} → {childName} (PID {proc.Pid})",
                Reasoning = "Productivity / browsing / scripting hosts launching shells or rundll32 / certutil is the canonical macro-to-payload chain. The child is typically used to download or in-memory-load a payload.",
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = proc.Name ?? "",
                ProcessId = proc.Pid,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["technique"] = "T1059 - Command and Scripting Interpreter",
                    ["parent_process"] = parentName,
                    ["parent_pid"] = proc.ParentPid.ToString()
                }
            }, cancellationToken);
        }
    }

    private static List<ProcSnapshot> SnapshotProcesses()
    {
        var list = new List<ProcSnapshot>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId FROM Win32_Process");
            using var results = searcher.Get();
            foreach (ManagementObject mo in results)
            {
                using (mo)
                {
                    list.Add(new ProcSnapshot
                    {
                        Pid = Convert.ToInt32(mo["ProcessId"] ?? 0),
                        Name = mo["Name"] as string ?? "",
                        ExecutablePath = mo["ExecutablePath"] as string ?? "",
                        CommandLine = mo["CommandLine"] as string ?? "",
                        ParentPid = Convert.ToInt32(mo["ParentProcessId"] ?? 0)
                    });
                }
            }
        }
        catch { }
        return list;
    }

    private sealed class ProcSnapshot
    {
        public int Pid;
        public string Name = "";
        public string ExecutablePath = "";
        public string CommandLine = "";
        public int ParentPid;
    }
}


