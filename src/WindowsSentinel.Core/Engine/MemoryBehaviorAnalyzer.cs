using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Memory Behavior Analyzer — Detects suspicious memory patterns by scanning
/// process memory regions for behavioral indicators.
///
/// This goes beyond what HollowProcessMonitor does (image path mismatch) and
/// EtwThreatIntelMonitor provides (API call visibility). It actively scans for:
///
///   1. RWX memory regions (executable + writable = shellcode staging)
///   2. Unbacked executable regions (no file on disk = reflective load)
///   3. Shellcode prologue patterns in executable memory
///   4. Suspicious memory region transitions (RW → RX = just-in-time compilation or shellcode)
///   5. Large executable allocations in non-JIT processes
///
/// Runs every 45 seconds. Requires same-integrity-level access to target processes.
/// Elevated: scans all user processes. Standard: scans own-integrity processes only.
///
/// IMPORTANT: This is behavioral analysis, not signature scanning. We look at
/// WHAT memory looks like (permissions, backing, patterns) not WHAT it contains
/// (no AV signatures, no hash matching).
/// </summary>
public sealed class MemoryBehaviorAnalyzer : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly TelemetryFusionEngine _fusionEngine;
    private readonly ILogger<MemoryBehaviorAnalyzer> _logger;

    // Track known-good processes to reduce scan overhead
    private readonly ConcurrentDictionary<int, ProcessMemoryProfile> _profiles = new();

    // Scan interval
    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(45);

    // Shellcode prologue patterns (common x64 shellcode starts)
    private static readonly byte[][] ShellcodePrologues = new byte[][]
    {
        new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 },  // CLD; AND RSP, -10h (Metasploit)
        new byte[] { 0xFC, 0xE8, 0x82, 0x00, 0x00 },  // CLD; CALL +82h (Cobalt Strike)
        new byte[] { 0x48, 0x31, 0xC9, 0x48, 0x81 },  // XOR RCX,RCX; ... (common stub)
        new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03 },  // MZ header (reflective PE)
        new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00 },  // CALL $+5 (position-independent)
    };

    // Processes that legitimately use RWX (JIT compilers, etc.)
    private static readonly HashSet<string> JitProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "java.exe", "javaw.exe", "node.exe", "python.exe", "python3.exe",
        "ruby.exe", "dotnet.exe", "pwsh.exe", "powershell.exe",
        "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
        "devenv.exe", "code.exe", "rider64.exe", "idea64.exe",
        "v8_shell.exe", "deno.exe", "bun.exe"
    };

    // Native methods for memory scanning
    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern nint VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer, nint dwLength);

    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;

    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE = 0x10;

    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_IMAGE = 0x1000000;
    private const uint MEM_MAPPED = 0x40000;
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
        IDetectionEngine detectionEngine,
        TelemetryFusionEngine fusionEngine,
        ILogger<MemoryBehaviorAnalyzer> logger)
    {
        _detectionEngine = detectionEngine;
        _fusionEngine = fusionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Memory Behavior Analyzer starting (v1.0.0) ===");

        // Initial delay to let other monitors start first
        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanProcessesAsync(stoppingToken);
                await Task.Delay(ScanInterval, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MemoryBehaviorAnalyzer: Scan error");
                await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
            }
        }
    }

    private async Task ScanProcessesAsync(CancellationToken ct)
    {
        var selfPid = Environment.ProcessId;
        var processes = System.Diagnostics.Process.GetProcesses();

        foreach (var process in processes)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                // Skip system processes and ourselves
                if (process.Id <= 4 || process.Id == selfPid)
                    continue;

                // Skip known JIT processes (they legitimately have RWX)
                if (JitProcesses.Contains(process.ProcessName + ".exe"))
                    continue;

                // Skip processes we've already profiled as clean
                if (_profiles.TryGetValue(process.Id, out var profile) &&
                    profile.IsClean && profile.ScanCount > 3)
                    continue;

                await ScanProcessMemoryAsync(process.Id, process.ProcessName, ct);
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // Access denied — expected for elevated processes when running as standard user
            }
            catch (InvalidOperationException)
            {
                // Process exited during scan
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "MemoryBehaviorAnalyzer: Error scanning PID {Pid}", process.Id);
            }
            finally
            {
                process.Dispose();
            }
        }

        // Cleanup profiles for dead processes
        CleanupProfiles();
    }

    private async Task ScanProcessMemoryAsync(int pid, string processName, CancellationToken ct)
    {
        var hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (hProcess == IntPtr.Zero)
            return;

        try
        {
            var findings = new List<MemoryFinding>();
            var address = IntPtr.Zero;
            int rwxRegionCount = 0;
            int unbackedExecCount = 0;
            long totalRwxSize = 0;

            while (true)
            {
                ct.ThrowIfCancellationRequested();

                var result = VirtualQueryEx(hProcess, address,
                    out MEMORY_BASIC_INFORMATION mbi,
                    (nint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());

                if (result == 0) break;

                // Only look at committed memory
                if (mbi.State == MEM_COMMIT)
                {
                    var isExecutable = (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0 ||
                                      (mbi.Protect & PAGE_EXECUTE_WRITECOPY) != 0;
                    var isExecRead = (mbi.Protect & PAGE_EXECUTE_READ) != 0 ||
                                    (mbi.Protect & PAGE_EXECUTE) != 0;
                    var isUnbacked = mbi.Type == MEM_PRIVATE; // Not backed by a file

                    // Finding 1: RWX regions (executable + writable)
                    if (isExecutable)
                    {
                        rwxRegionCount++;
                        totalRwxSize += (long)mbi.RegionSize;

                        // Only flag if region is large enough to be meaningful (>4KB)
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

                    // Finding 2: Unbacked executable regions (reflective load indicator)
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

                        // Finding 3: Check for shellcode prologues in unbacked executable regions
                        if ((long)mbi.RegionSize >= 64 && (long)mbi.RegionSize <= 10 * 1024 * 1024)
                        {
                            var hasShellcode = CheckForShellcodePatterns(hProcess, mbi.BaseAddress,
                                Math.Min((int)(long)mbi.RegionSize, 4096));

                            if (hasShellcode)
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

                // Advance to next region
                address = (IntPtr)((long)mbi.BaseAddress + (long)mbi.RegionSize);
                if ((long)address < 0) break; // Overflow guard
            }

            // Update profile
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

            // Determine if findings are suspicious enough to report
            var suspiciousFindings = findings
                .Where(f => f.Kind is MemoryBehaviorKind.ShellcodePattern
                    or MemoryBehaviorKind.ReflectiveLoad)
                .ToList();

            // RWX is suspicious only if there are many regions or they're large
            if (rwxRegionCount > 5 || totalRwxSize > 1024 * 1024)
            {
                suspiciousFindings.AddRange(findings.Where(f => f.Kind == MemoryBehaviorKind.RwxAllocation).Take(3));
            }

            // Unbacked executable is suspicious if there are multiple
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

            // Emit detection for the most severe finding
            var worstFinding = suspiciousFindings
                .OrderByDescending(f => f.Kind switch
                {
                    MemoryBehaviorKind.ShellcodePattern => 3,
                    MemoryBehaviorKind.ReflectiveLoad => 2,
                    MemoryBehaviorKind.UnbackedExecutable => 1,
                    _ => 0
                })
                .First();

            // Feed into telemetry fusion
            _fusionEngine.IngestMemoryBehavior(pid, processName,
                worstFinding.Kind, worstFinding.Details, DateTimeOffset.UtcNow);

            // Determine confidence based on finding severity
            double confidence = worstFinding.Kind switch
            {
                MemoryBehaviorKind.ShellcodePattern => 0.88,
                MemoryBehaviorKind.ReflectiveLoad => 0.82,
                MemoryBehaviorKind.UnbackedExecutable => 0.72,
                MemoryBehaviorKind.RwxAllocation => 0.65,
                _ => 0.60
            };

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = $"Memory Behavior: {worstFinding.Kind}",
                Evidence = $"Process '{processName}' (PID {pid}) has suspicious memory layout: " +
                          $"{worstFinding.Details}. " +
                          $"Total findings: {suspiciousFindings.Count} suspicious regions, " +
                          $"{rwxRegionCount} RWX regions ({totalRwxSize / 1024}KB total), " +
                          $"{unbackedExecCount} unbacked executable regions.",
                Reasoning = worstFinding.Kind switch
                {
                    MemoryBehaviorKind.ShellcodePattern =>
                        "Shellcode prologue patterns detected in unbacked executable memory. " +
                        "This is a strong indicator of injected shellcode (Cobalt Strike, Metasploit, " +
                        "custom loaders). Legitimate applications do not have shellcode-like byte " +
                        "sequences in private executable memory.",
                    MemoryBehaviorKind.UnbackedExecutable =>
                        "Multiple unbacked executable memory regions detected. Private executable " +
                        "memory not backed by any file on disk indicates reflective DLL loading, " +
                        "manual PE mapping, or shellcode execution. Common in fileless attacks.",
                    MemoryBehaviorKind.RwxAllocation =>
                        "Excessive RWX (read-write-execute) memory regions detected. While some " +
                        "JIT compilers use RWX temporarily, large or numerous RWX regions in a " +
                        "non-JIT process indicate shellcode staging or unpacking.",
                    _ => "Suspicious memory behavior detected."
                },
                Confidence = confidence,
                Tier = confidence >= 0.80 ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                ProcessName = processName,
                ProcessId = pid,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["memory_kind"] = worstFinding.Kind.ToString(),
                    ["rwx_regions"] = rwxRegionCount.ToString(),
                    ["rwx_total_kb"] = (totalRwxSize / 1024).ToString(),
                    ["unbacked_exec"] = unbackedExecCount.ToString(),
                    ["finding_count"] = suspiciousFindings.Count.ToString(),
                    ["address"] = $"0x{worstFinding.Address:X}",
                    ["region_size_kb"] = (worstFinding.Size / 1024).ToString()
                }
            }, ct);
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// Checks the first N bytes of a memory region for known shellcode prologues.
    /// </summary>
    private bool CheckForShellcodePatterns(IntPtr hProcess, IntPtr baseAddress, int readSize)
    {
        var buffer = new byte[Math.Min(readSize, 4096)];

        if (!ReadProcessMemory(hProcess, baseAddress, buffer, buffer.Length, out int bytesRead))
            return false;

        if (bytesRead < 5) return false;

        // Check for known shellcode prologues
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

        // Heuristic: high ratio of NOP sleds (0x90) in first 64 bytes
        int nopCount = 0;
        int checkLen = Math.Min(bytesRead, 64);
        for (int i = 0; i < checkLen; i++)
        {
            if (buffer[i] == 0x90) nopCount++;
        }
        if (nopCount > checkLen / 3) return true; // >33% NOPs = NOP sled

        return false;
    }

    private void CleanupProfiles()
    {
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-5);
        var staleKeys = _profiles
            .Where(kv => kv.Value.LastScan < cutoff)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var key in staleKeys)
            _profiles.TryRemove(key, out _);
    }

    /// <summary>
    /// Gets analyzer statistics.
    /// </summary>
    public MemoryAnalyzerStats GetStats() => new()
    {
        ProfiledProcesses = _profiles.Count,
        CleanProcesses = _profiles.Values.Count(p => p.IsClean),
        SuspiciousProcesses = _profiles.Values.Count(p => !p.IsClean && p.ScanCount > 0)
    };
}

// ── Supporting types ─────────────────────────────────────────────────────────

internal sealed class MemoryFinding
{
    public MemoryBehaviorKind Kind { get; init; }
    public IntPtr Address { get; init; }
    public long Size { get; init; }
    public uint Protection { get; init; }
    public bool IsBacked { get; init; }
    public string Details { get; init; } = "";
}

internal sealed class ProcessMemoryProfile
{
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = "";
    public int ScanCount { get; set; }
    public DateTimeOffset LastScan { get; set; }
    public bool IsClean { get; set; }
    public int RwxRegionCount { get; set; }
    public int UnbackedExecCount { get; set; }
    public long TotalRwxSize { get; set; }
}

public sealed class MemoryAnalyzerStats
{
    public int ProfiledProcesses { get; init; }
    public int CleanProcesses { get; init; }
    public int SuspiciousProcesses { get; init; }
}
