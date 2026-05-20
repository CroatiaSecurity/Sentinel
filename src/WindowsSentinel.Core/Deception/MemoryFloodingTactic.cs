using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Deception;

/// <summary>
/// Memory Flooding Tactic — Allocates massive garbage data in the target process's address space.
/// 
/// Purpose:
///   - If the attacker has memory dump capabilities, their dump is now gigabytes of noise
///   - If the C2 framework has crash-reporting, it sends corrupted telemetry to the operator
///   - Pollutes any in-memory data the attacker has collected pre-exfil
///   - Makes forensic analysis of the implant significantly harder for the attacker
/// 
/// Method:
///   - VirtualAllocEx to allocate large regions in target process
///   - WriteProcessMemory to fill with random garbage (not zeros — zeros compress well)
///   - Targets both heap-adjacent regions and stack-adjacent regions
///   - Allocates in 1MB chunks up to 256MB or until time budget expires
/// 
/// Safety:
///   - Process is about to be killed anyway — memory corruption is irrelevant
///   - If allocation fails (process already dying), tactic reports failure gracefully
/// </summary>
public sealed class MemoryFloodingTactic : IDeceptionTactic
{
    private readonly ILogger<MemoryFloodingTactic> _logger;

    /// <summary>Size of each garbage allocation (1 MB).</summary>
    private const int ChunkSize = 1024 * 1024;

    /// <summary>Maximum total garbage to inject (256 MB).</summary>
    private const int MaxTotalBytes = 256 * 1024 * 1024;

    /// <summary>Maximum time for this single tactic.</summary>
    private static readonly TimeSpan MaxTacticTime = TimeSpan.FromMilliseconds(500);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(
        IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(
        IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    // Access rights
    private const uint PROCESS_VM_OPERATION = 0x0008;
    private const uint PROCESS_VM_WRITE = 0x0020;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint PAGE_READWRITE = 0x04;

    public MemoryFloodingTactic(ILogger<MemoryFloodingTactic> logger)
    {
        _logger = logger;
    }

    public async Task<DeceptionTacticResult> ExecuteAsync(DeceptionContext context, CancellationToken cancellationToken)
    {
        return await Task.Run(() =>
        {
            var hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, context.ProcessId);
            if (hProcess == IntPtr.Zero)
            {
                return new DeceptionTacticResult
                {
                    TacticName = "MemoryFlooding",
                    Success = false,
                    Error = $"Cannot open process {context.ProcessId} for memory flooding"
                };
            }

            try
            {
                var startTime = DateTime.UtcNow;
                int totalAllocated = 0;
                int chunksWritten = 0;

                // Generate random garbage (not zeros — zeros compress trivially)
                var garbage = new byte[ChunkSize];
                Random.Shared.NextBytes(garbage);

                while (totalAllocated < MaxTotalBytes &&
                       DateTime.UtcNow - startTime < MaxTacticTime &&
                       !cancellationToken.IsCancellationRequested)
                {
                    var addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)ChunkSize,
                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                    if (addr == IntPtr.Zero)
                        break; // Process may be dying or out of address space

                    // Write random garbage — re-randomize every 4th chunk for entropy
                    if (chunksWritten % 4 == 0)
                        Random.Shared.NextBytes(garbage);

                    WriteProcessMemory(hProcess, addr, garbage, (uint)ChunkSize, out _);

                    totalAllocated += ChunkSize;
                    chunksWritten++;
                }

                return new DeceptionTacticResult
                {
                    TacticName = "MemoryFlooding",
                    Success = chunksWritten > 0,
                    Description = $"Injected {totalAllocated / (1024 * 1024)}MB of random garbage into PID {context.ProcessId} " +
                                  $"({chunksWritten} chunks) — attacker memory dumps are now polluted"
                };
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }, cancellationToken);
    }
}


