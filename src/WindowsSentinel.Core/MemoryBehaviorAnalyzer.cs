using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    public class MemoryBehaviorAnalyzer : IDisposable
    {
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<MemoryBehaviorAnalyzer> _logger;
        private readonly System.Threading.Timer _timer;

        private readonly ConcurrentDictionary<int, ProcessMemoryProfile> _profiles = new();
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(90);

        private static readonly byte[][] ShellcodePrologues = new byte[][]
        {
            new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 },  // CLD; AND RSP, -10h (Metasploit)
            new byte[] { 0xFC, 0xE8, 0x82, 0x00, 0x00 },  // CLD; CALL +82h (Cobalt Strike)
            new byte[] { 0x48, 0x31, 0xC9, 0x48, 0x81 },  // XOR RCX,RCX; ...
            new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03 },  // MZ header (reflective PE)
            new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00 },  // CALL $+5
        };

        private static readonly HashSet<string> JitProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "java.exe", "javaw.exe", "node.exe", "python.exe", "python3.exe",
            "ruby.exe", "dotnet.exe", "pwsh.exe", "powershell.exe",
            "deno.exe", "bun.exe",
            "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
            "vivaldi.exe", "arc.exe", "thorium.exe",
            "devenv.exe", "code.exe", "rider64.exe", "idea64.exe",
            "pycharm64.exe", "webstorm64.exe", "goland64.exe", "clion64.exe",
            "cursor.exe", "Cursor.exe", "zed.exe",
            "Kiro.exe", "discord.exe", "Discord.exe",
            "slack.exe", "Slack.exe",
            "teams.exe", "Teams.exe", "ms-teams.exe",
            "signal.exe", "Signal.exe",
            "notion.exe", "Notion.exe",
            "obsidian.exe", "Obsidian.exe",
            "figma.exe", "Figma.exe",
            "postman.exe", "Postman.exe",
            "bitwarden.exe", "Bitwarden.exe",
            "1password.exe", "1Password.exe",
            "spotify.exe", "Spotify.exe",
            "whatsapp.exe", "WhatsApp.exe",
            "telegram.exe", "Telegram.exe",
            "gitkraken.exe", "GitKraken.exe",
            "insomnia.exe", "Insomnia.exe",
            "loom.exe", "Loom.exe",
            "linear.exe", "Linear.exe",
            "todoist.exe", "Todoist.exe",
            "clickup.exe", "ClickUp.exe",
            "trello.exe", "Trello.exe",
            "mongodb-compass.exe",
            "hyper.exe", "Hyper.exe",
            "warp.exe",
            "msedgewebview2.exe", "msedgewebview2",
            "steam.exe", "steamwebhelper.exe",
            "epicgameslauncher.exe", "EpicWebHelper.exe",
            "v8_shell.exe",
            "TmsaInstance64.exe", "TmsaInstance64",
            "coreServiceShell.exe", "coreServiceShell",
            "coreFrameworkHost.exe", "coreFrameworkHost",
            "PtSessionAgent.exe", "PtSessionAgent",
            "uiSeAgnt.exe", "uiSeAgnt",
            "PtSvcHost.exe", "PtSvcHost",
            "AMSPTelemetryService.exe", "AMSPTelemetryService",
            "msmpeng.exe", "MsMpEng.exe",
            "mssense.exe", "MsSense.exe",
            "mainProcess.exe", "mainProcess",
            "ASCService.exe", "ASCService",
            "DriverBooster.exe", "DriverBooster",
            "LiveTuner3.exe", "LiveTuner3",
            "NVDisplay.Container.exe", "NVDisplay.Container",
            "nvcontainer.exe", "nvcontainer"
        };

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        private static extern nint VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer, nint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;

        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE = 0x10;

        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_PRIVATE = 0x20000;

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public nuint RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public MemoryBehaviorAnalyzer(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            ILogger<MemoryBehaviorAnalyzer> logger)
        {
            _fusionEngine = fusionEngine;
            _detectionEngine = detectionEngine;
            _logger = logger;
            // Scan memory spaces periodically
            _timer = new System.Threading.Timer(ScanProcesses, null, TimeSpan.FromSeconds(15), ScanInterval);
        }

        private void ScanProcesses(object? state)
        {
            try
            {
                var selfPid = Environment.ProcessId;
                var processes = Process.GetProcesses();

                foreach (var process in processes)
                {
                    try
                    {
                        var pid = process.Id;
                        if (pid <= 4 || pid == selfPid) continue;

                        if (JitProcesses.Contains(process.ProcessName + ".exe"))
                            continue;

                        if (_profiles.TryGetValue(pid, out var profile) &&
                            profile.IsClean && profile.ScanCount > 3)
                            continue;

                        ScanProcessMemory(pid, process.ProcessName);
                    }
                    catch (System.ComponentModel.Win32Exception) { }
                    catch (InvalidOperationException) { }
                    catch (Exception ex)
                    {
                        _logger.LogDebug($"MemoryBehaviorAnalyzer scan error for process: {ex.Message}");
                    }
                    finally
                    {
                        process.Dispose();
                    }
                }

                CleanupProfiles();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"MemoryBehaviorAnalyzer scan logic error: {ex.Message}");
            }
        }

        private void ScanProcessMemory(int pid, string processName)
        {
            var hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (hProcess == IntPtr.Zero) return;

            try
            {
                var findings = new List<MemoryFinding>();
                var address = IntPtr.Zero;
                int rwxRegionCount = 0;
                int unbackedExecCount = 0;
                long totalRwxSize = 0;

                while (true)
                {
                    var result = VirtualQueryEx(hProcess, address,
                        out MEMORY_BASIC_INFORMATION mbi,
                        (nint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());

                    if (result == 0) break;

                    if (mbi.State == MEM_COMMIT)
                    {
                        var isExecutable = (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0 ||
                                          (mbi.Protect & PAGE_EXECUTE_WRITECOPY) != 0;
                        var isExecRead = (mbi.Protect & PAGE_EXECUTE_READ) != 0 ||
                                        (mbi.Protect & PAGE_EXECUTE) != 0;
                        var isUnbacked = mbi.Type == MEM_PRIVATE;

                        if (isExecutable)
                        {
                            rwxRegionCount++;
                            totalRwxSize += (long)mbi.RegionSize;

                            if ((long)mbi.RegionSize > 4096)
                            {
                                findings.Add(new MemoryFinding
                                {
                                    Kind = MemoryBehaviorKind.RwxAllocation,
                                    Address = mbi.BaseAddress,
                                    Size = (long)mbi.RegionSize,
                                    Protection = mbi.Protect,
                                    IsBacked = mbi.Type != MEM_PRIVATE,
                                    Details = $"RWX region at 0x{mbi.BaseAddress:X}: {(long)mbi.RegionSize / 1024}KB"
                                });
                            }
                        }

                        if ((isExecutable || isExecRead) && isUnbacked && (long)mbi.RegionSize > 8192)
                        {
                            unbackedExecCount++;

                            findings.Add(new MemoryFinding
                            {
                                Kind = MemoryBehaviorKind.UnbackedExecutable,
                                Address = mbi.BaseAddress,
                                Size = (long)mbi.RegionSize,
                                Protection = mbi.Protect,
                                IsBacked = false,
                                Details = $"Unbacked executable at 0x{mbi.BaseAddress:X}: {(long)mbi.RegionSize / 1024}KB"
                            });

                            if ((long)mbi.RegionSize >= 64 && (long)mbi.RegionSize <= 10 * 1024 * 1024)
                            {
                                if (CheckForShellcodePatterns(hProcess, mbi.BaseAddress, Math.Min((int)(long)mbi.RegionSize, 4096)))
                                {
                                    findings.Add(new MemoryFinding
                                    {
                                        Kind = MemoryBehaviorKind.ShellcodePattern,
                                        Address = mbi.BaseAddress,
                                        Size = (long)mbi.RegionSize,
                                        Protection = mbi.Protect,
                                        IsBacked = false,
                                        Details = $"Shellcode prologue detected at 0x{mbi.BaseAddress:X}"
                                    });
                                }
                            }
                        }
                    }

                    address = (IntPtr)((long)mbi.BaseAddress + (long)mbi.RegionSize);
                    if ((long)address < 0) break;
                    if ((ulong)(long)address > 0x7FFFFFFEFFFF) break;
                }

                var memProfile = _profiles.GetOrAdd(pid, _ => new ProcessMemoryProfile
                {
                    ProcessId = pid,
                    ProcessName = processName
                });

                memProfile.ScanCount++;
                memProfile.LastScan = DateTimeOffset.UtcNow;
                memProfile.RwxRegionCount = rwxRegionCount;
                memProfile.UnbackedExecCount = unbackedExecCount;
                memProfile.TotalRwxSize = totalRwxSize;

                var suspiciousFindings = findings
                    .Where(f => f.Kind == MemoryBehaviorKind.ShellcodePattern || f.Kind == MemoryBehaviorKind.ReflectiveLoad)
                    .ToList();

                if (rwxRegionCount > 5 || totalRwxSize > 1024 * 1024)
                {
                    suspiciousFindings.AddRange(findings.Where(f => f.Kind == MemoryBehaviorKind.RwxAllocation).Take(3));
                }

                if (unbackedExecCount > 3)
                {
                    suspiciousFindings.AddRange(findings.Where(f => f.Kind == MemoryBehaviorKind.UnbackedExecutable).Take(3));
                }

                if (suspiciousFindings.Count == 0)
                {
                    memProfile.IsClean = true;
                    return;
                }

                memProfile.IsClean = false;

                var worstFinding = suspiciousFindings
                    .OrderByDescending(f => f.Kind switch
                    {
                        MemoryBehaviorKind.ShellcodePattern => 3,
                        MemoryBehaviorKind.ReflectiveLoad => 2,
                        MemoryBehaviorKind.UnbackedExecutable => 1,
                        _ => 0
                    })
                    .First();

                var telemetry = new MemoryBehaviorTelemetry
                {
                    Type = "memory",
                    Timestamp = DateTime.UtcNow,
                    ProcessId = pid,
                    ProcessName = processName,
                    Kind = worstFinding.Kind,
                    Details = worstFinding.Details
                };

                var context = _fusionEngine.FeedEvent(telemetry);
                _detectionEngine.SubmitTelemetry(context);

                double confidence = worstFinding.Kind switch
                {
                    MemoryBehaviorKind.ShellcodePattern => 0.88,
                    MemoryBehaviorKind.ReflectiveLoad => 0.82,
                    MemoryBehaviorKind.UnbackedExecutable => 0.72,
                    MemoryBehaviorKind.RwxAllocation => 0.65,
                    _ => 0.60
                };

                var alert = new DetectionEvent
                {
                    RuleName = $"Memory Behavior: {worstFinding.Kind}",
                    ProcessName = processName + ".exe",
                    ProcessId = pid,
                    Confidence = confidence,
                    Tier = confidence >= 0.80 ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                    Evidence = $"Process '{processName}' (PID {pid}) has suspicious memory layout: {worstFinding.Details}. Total: {suspiciousFindings.Count} suspicious regions, {rwxRegionCount} RWX regions ({totalRwxSize / 1024}KB total), {unbackedExecCount} unbacked executable regions.",
                    Reasoning = worstFinding.Kind switch
                    {
                        MemoryBehaviorKind.ShellcodePattern => "Shellcode prologue patterns detected in unbacked executable memory. This is a strong indicator of injected shellcode (Cobalt Strike, Metasploit).",
                        MemoryBehaviorKind.UnbackedExecutable => "Multiple unbacked executable memory regions detected. Private executable memory not backed by any file on disk indicates reflective DLL loading or manual PE mapping.",
                        MemoryBehaviorKind.RwxAllocation => "Excessive RWX (read-write-execute) memory regions detected. Large or numerous RWX regions in a non-JIT process indicate shellcode staging or unpacking.",
                        _ => "Suspicious memory behavior detected."
                    },
                    Timestamp = DateTime.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        { "memory_kind", worstFinding.Kind.ToString() },
                        { "rwx_regions", rwxRegionCount.ToString() },
                        { "rwx_total_kb", (totalRwxSize / 1024).ToString() },
                        { "unbacked_exec", unbackedExecCount.ToString() },
                        { "finding_count", suspiciousFindings.Count.ToString() },
                        { "address", $"0x{worstFinding.Address:X}" },
                        { "region_size_kb", (worstFinding.Size / 1024).ToString() },
                        { "technique", "T1055 - Process Injection" }
                    }
                };

                _ = _detectionEngine.EmitAsync(alert);
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }

        private bool CheckForShellcodePatterns(IntPtr hProcess, IntPtr baseAddress, int readSize)
        {
            var buffer = new byte[Math.Min(readSize, 4096)];

            if (!ReadProcessMemory(hProcess, baseAddress, buffer, buffer.Length, out int bytesRead))
                return false;

            if (bytesRead < 5) return false;

            foreach (var prologue in ShellcodePrologues)
            {
                if (bytesRead >= prologue.Length)
                {
                    bool match = true;
                    for (int i = 0; i < prologue.Length; i++)
                    {
                        if (buffer[i] != prologue[i])
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match) return true;
                }
            }

            int nopCount = 0;
            int checkLen = Math.Min(bytesRead, 64);
            for (int i = 0; i < checkLen; i++)
            {
                if (buffer[i] == 0x90) nopCount++;
            }
            if (nopCount > checkLen / 3) return true;

            return false;
        }

        private void CleanupProfiles()
        {
            var cutoff = DateTime.UtcNow - TimeSpan.FromMinutes(5);
            var staleKeys = _profiles
                .Where(kv => kv.Value.LastScan < cutoff)
                .Select(kv => kv.Key)
                .ToList();

            foreach (var key in staleKeys)
                _profiles.TryRemove(key, out _);
        }

        public void Dispose()
        {
            _timer.Dispose();
            GC.SuppressFinalize(this);
        }

        private class MemoryFinding
        {
            public MemoryBehaviorKind Kind { get; set; }
            public IntPtr Address { get; set; }
            public long Size { get; set; }
            public uint Protection { get; set; }
            public bool IsBacked { get; set; }
            public string Details { get; set; } = string.Empty;
        }

        private class ProcessMemoryProfile
        {
            public int ProcessId { get; set; }
            public string ProcessName { get; set; } = string.Empty;
            public int ScanCount { get; set; }
            public DateTimeOffset LastScan { get; set; }
            public bool IsClean { get; set; }
            public int RwxRegionCount { get; set; }
            public int UnbackedExecCount { get; set; }
            public long TotalRwxSize { get; set; }
        }
    }
}
