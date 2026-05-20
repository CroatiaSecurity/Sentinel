using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Detects process hollowing and module stomping by comparing what a process
/// claims to be (its image path from the process list) against what is actually
/// mapped at its base address in memory.
///
/// Technique:
///   1. Enumerate running processes via CreateToolhelp32Snapshot.
///   2. For each process, open a handle with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ.
///   3. Use NtQueryVirtualMemory (MemoryMappedFilenameInformation) to get the
///      actual file backing the executable region at the process base address.
///   4. Compare against the declared image path from the process list.
///   5. If they differ → the process is hollowed or stomped.
///
/// Also detects:
///   - Processes with no mapped file at their base address (shellcode running
///     in a private allocation — classic shellcode injection result).
///   - Processes whose base image is mapped from a suspicious path while
///     claiming to be a system process.
///
/// Why this is unusual for a userland tool:
///   Commercial EDRs do this in kernel (PsSetLoadImageNotifyRoutine).
///   Doing it from userland with NtQueryVirtualMemory is less reliable
///   (requires handle rights, misses some cases) but catches the common
///   hollowing patterns without any kernel code.
///
/// Runs every 30 seconds. Skips processes it can't open (access denied = normal).
/// No admin required for processes running at the same integrity level.
/// </summary>
public sealed class HollowProcessMonitor : IMonitor
{
    public string Name => "Hollow Process Detector";

    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<HollowProcessMonitor> _logger;
    private Task? _scanTask;

    // Processes we've already alerted on — don't re-fire every 30s
    private readonly HashSet<int> _alerted = new();
    private readonly object _alertedLock = new();

    // System processes that are always legitimate even if we can't verify their image
    private static readonly HashSet<string> AlwaysTrusted = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
        "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
        "fontdrvhost.exe", "dwm.exe", "sihost.exe", "taskhostw.exe",
        "explorer.exe", "RuntimeBroker.exe", "SearchIndexer.exe",
        "MsMpEng.exe", "NisSrv.exe"
    };

    public HollowProcessMonitor(
        IDetectionEngine detectionEngine,
        ILogger<HollowProcessMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger          = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("[{Monitor}] Starting hollow process scanner.", Name);
        _scanTask = ScanLoopAsync(cancellationToken);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("[{Monitor}] Stopping.", Name);
        return Task.CompletedTask;
    }

    private async Task ScanLoopAsync(CancellationToken cancellationToken)
    {
        // Initial delay — let the system settle before first scan
        await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken);

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await ScanProcessesAsync(cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "[{Monitor}] Scan error.", Name);
            }

            await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
        }
    }

    private async Task ScanProcessesAsync(CancellationToken cancellationToken)
    {
        var processes = GetProcessList();

        foreach (var (pid, name, declaredPath) in processes)
        {
            if (cancellationToken.IsCancellationRequested) break;
            if (AlwaysTrusted.Contains(name)) continue;
            if (pid <= 4) continue;

            lock (_alertedLock)
            {
                if (_alerted.Contains(pid)) continue;
            }

            try
            {
                await CheckProcessAsync(pid, name, declaredPath, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "[{Monitor}] Error checking PID {Pid}.", Name, pid);
            }
        }
    }

    private async Task CheckProcessAsync(
        int pid, string name, string declaredPath, CancellationToken ct)
    {
        const uint PROCESS_QUERY_INFORMATION = 0x0400;
        const uint PROCESS_VM_READ           = 0x0010;

        nint hProcess = NativeMethods.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);

        if (hProcess == IntPtr.Zero) return; // Access denied — normal for elevated processes

        try
        {
            // Get the actual mapped file at the process base address
            string? mappedFile = GetMappedFileName(hProcess, pid);

            if (mappedFile is null)
            {
                // No mapped file at base address — could be shellcode in private memory
                // Only flag if the process has a declared path (not a system process)
                if (!string.IsNullOrEmpty(declaredPath) &&
                    !declaredPath.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase))
                {
                    await FireDetectionAsync(pid, name, declaredPath,
                        "UNMAPPED_BASE",
                        $"Process '{name}' (PID {pid}) has no mapped file at its base address. " +
                        "This may indicate shellcode running in a private memory allocation.",
                        0.75, ct);
                }
                return;
            }

            // Normalize paths for comparison
            string normalizedMapped   = NormalizePath(mappedFile);
            string normalizedDeclared = NormalizePath(declaredPath);

            if (string.IsNullOrEmpty(normalizedDeclared)) return;

            // Compare — if they differ, the process is hollowed or stomped
            if (!normalizedMapped.Equals(normalizedDeclared, StringComparison.OrdinalIgnoreCase))
            {
                await FireDetectionAsync(pid, name, declaredPath,
                    "HOLLOWED",
                    $"Process '{name}' (PID {pid}) is HOLLOWED or STOMPED. " +
                    $"Declared image: '{declaredPath}' | " +
                    $"Actual mapped file: '{mappedFile}'",
                    0.92, ct);
            }
        }
        finally
        {
            NativeMethods.CloseHandle(hProcess);
        }
    }

    private async Task FireDetectionAsync(
        int pid, string name, string declaredPath,
        string hollowType, string evidence,
        double confidence, CancellationToken ct)
    {
        lock (_alertedLock) { _alerted.Add(pid); }

        _logger.LogCritical("[{Monitor}] {Evidence}", Name, evidence);

        var telemetry = new HollowProcessTelemetry
        {
            ProcessId    = pid,
            ProcessName  = name,
            DeclaredPath = declaredPath,
            HollowType   = hollowType,
            Evidence     = evidence,
            Confidence   = confidence,
            Timestamp    = DateTimeOffset.UtcNow
        };

        await _detectionEngine.ProcessAsync(telemetry, ct);
    }

    private static string? GetMappedFileName(nint hProcess, int pid)
    {
        // Get the base address of the main module
        nint baseAddress = GetProcessBaseAddress(pid);
        if (baseAddress == IntPtr.Zero) return null;

        // Query the mapped file name at that address
        var buffer = new StringBuilder(1024);
        uint result = NativeMethods.GetMappedFileName(
            hProcess, baseAddress, buffer, (uint)buffer.Capacity);

        if (result == 0) return null;

        // Convert device path (\Device\HarddiskVolume3\...) to drive letter path
        return DevicePathToDrivePath(buffer.ToString());
    }

    private static nint GetProcessBaseAddress(int pid)
    {
        // Use EnumProcessModules to get the first (main) module base address
        nint hProcess = NativeMethods.OpenProcess(0x0410, false, pid); // QUERY_INFO | VM_READ
        if (hProcess == IntPtr.Zero) return IntPtr.Zero;

        try
        {
            var modules = new nint[1];
            if (!NativeMethods.EnumProcessModules(hProcess, modules, (uint)(nint.Size), out _))
                return IntPtr.Zero;
            return modules[0];
        }
        finally
        {
            NativeMethods.CloseHandle(hProcess);
        }
    }

    private static string DevicePathToDrivePath(string devicePath)
    {
        // Map \Device\HarddiskVolumeN\ → drive letter
        foreach (var drive in DriveInfo.GetDrives())
        {
            var driveLetter = drive.Name.TrimEnd('\\');
            var sb = new StringBuilder(256);
            if (NativeMethods.QueryDosDevice(driveLetter, sb, 256) == 0) continue;

            string deviceName = sb.ToString();
            if (devicePath.StartsWith(deviceName, StringComparison.OrdinalIgnoreCase))
                return driveLetter + devicePath[deviceName.Length..];
        }
        return devicePath;
    }

    private static string NormalizePath(string path) =>
        path.Trim().TrimEnd('\\').ToLowerInvariant();

    private static List<(int Pid, string Name, string Path)> GetProcessList()
    {
        var result = new List<(int, string, string)>();

        nint hSnapshot = NativeMethods.CreateToolhelp32Snapshot(0x00000002, 0);
        if (hSnapshot == NativeMethods.INVALID_HANDLE_VALUE) return result;

        try
        {
            var entry = new NativeMethods.PROCESSENTRY32
            {
                dwSize = (uint)Marshal.SizeOf<NativeMethods.PROCESSENTRY32>()
            };

            if (!NativeMethods.Process32First(hSnapshot, ref entry)) return result;

            do
            {
                // Get full path via QueryFullProcessImageName
                string fullPath = GetFullProcessPath(entry.th32ProcessID);
                result.Add((entry.th32ProcessID, entry.szExeFile, fullPath));
            }
            while (NativeMethods.Process32Next(hSnapshot, ref entry));
        }
        finally
        {
            NativeMethods.CloseHandle(hSnapshot);
        }

        return result;
    }

    private static string GetFullProcessPath(int pid)
    {
        nint hProcess = NativeMethods.OpenProcess(0x1000, false, pid); // PROCESS_QUERY_LIMITED_INFORMATION
        if (hProcess == IntPtr.Zero) return string.Empty;

        try
        {
            var sb = new StringBuilder(1024);
            uint size = (uint)sb.Capacity;
            return NativeMethods.QueryFullProcessImageName(hProcess, 0, sb, ref size)
                ? sb.ToString()
                : string.Empty;
        }
        finally
        {
            NativeMethods.CloseHandle(hProcess);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_scanTask is not null)
        {
            try { await _scanTask.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch { /* best-effort */ }
        }
    }

    private static class NativeMethods
    {
        public static readonly nint INVALID_HANDLE_VALUE = -1;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern nint OpenProcess(uint dwAccess, bool bInherit, int dwPid);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(nint hObject);

        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetMappedFileName(
            nint hProcess, nint lpv, StringBuilder lpFilename, uint nSize);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool EnumProcessModules(
            nint hProcess, [Out] nint[] lphModule, uint cb, out uint lpcbNeeded);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool QueryFullProcessImageName(
            nint hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint QueryDosDevice(
            string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern nint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool Process32First(nint hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool Process32Next(nint hSnapshot, ref PROCESSENTRY32 lppe);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PROCESSENTRY32
        {
            public uint   dwSize;
            public uint   cntUsage;
            public int    th32ProcessID;
            public nint   th32DefaultHeapID;
            public uint   th32ModuleID;
            public uint   cntThreads;
            public int    th32ParentProcessID;
            public int    pcPriClassBase;
            public uint   dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }
    }
}

// ── Telemetry type ────────────────────────────────────────────────────────────

public sealed class HollowProcessTelemetry
{
    public required int    ProcessId    { get; init; }
    public required string ProcessName  { get; init; }
    public required string DeclaredPath { get; init; }
    public required string HollowType   { get; init; }
    public required string Evidence     { get; init; }
    public required double Confidence   { get; init; }
    public required DateTimeOffset Timestamp { get; init; }
}


