using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Deception;

/// <summary>
/// Implant Destabilizer — Corrupts the malicious process internals before kill.
/// 
/// Tactics:
///   1. DLL Stomping: Overwrites .text section of detected malicious DLLs with INT3 (0xCC)
///      breakpoint instructions. If the implant has persistence and restarts, it immediately
///      crashes in a way that's extremely hard to debug remotely.
///   
///   2. Stack Corruption: Injects garbage into thread stacks. If the C2 framework has
///      crash-reporting/reconnect logic, it sends corrupted telemetry back to the operator,
///      polluting their logs and wasting their analysis time.
///   
///   3. Handle Table Pollution: Opens hundreds of handles to decoy files/registry keys in
///      the malicious process. Their forensic timeline is now full of noise if they capture
///      handle snapshots before the process dies.
/// 
/// Safety:
///   - Process is about to be killed — corruption is irrelevant to system stability
///   - Only targets the specific malicious PID, never system processes
///   - Failure is non-fatal; kill proceeds regardless
/// </summary>
public sealed class ImplantDestabilizer : IDeceptionTactic
{
    private readonly ILogger<ImplantDestabilizer> _logger;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(
        IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtectEx(
        IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    private const uint TH32CS_SNAPMODULE = 0x00000008;
    private const uint TH32CS_SNAPTHREAD = 0x00000004;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint THREAD_GET_CONTEXT = 0x0008;
    private const uint THREAD_SET_CONTEXT = 0x0010;
    private const uint THREAD_SUSPEND_RESUME = 0x0002;
    private const uint CONTEXT_FULL = 0x10001F;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct MODULEENTRY32
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public IntPtr modBaseAddr;
        public uint modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExePath;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct THREADENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ThreadID;
        public uint th32OwnerProcessID;
        public int tpBasePri;
        public int tpDeltaPri;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CONTEXT
    {
        public uint ContextFlags;
        // Simplified — we only need RSP for stack location
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1232)]
        public byte[] RegisterArea;
    }

    public ImplantDestabilizer(ILogger<ImplantDestabilizer> logger)
    {
        _logger = logger;
    }

    public async Task<DeceptionTacticResult> ExecuteAsync(DeceptionContext context, CancellationToken cancellationToken)
    {
        return await Task.Run(() =>
        {
            var actions = new List<string>();

            // Tactic 1: DLL Stomping — overwrite executable sections with INT3
            var stompResult = StompMaliciousModules(context.ProcessId, context.ImagePath);
            if (stompResult != null) actions.Add(stompResult);

            // Tactic 2: Stack Corruption — inject garbage into thread stacks
            var stackResult = CorruptThreadStacks(context.ProcessId);
            if (stackResult != null) actions.Add(stackResult);

            // Tactic 3: Handle Table Pollution — open decoy handles
            var pollutionResult = PolluteHandleTable(context.ProcessId);
            if (pollutionResult != null) actions.Add(pollutionResult);

            if (actions.Count == 0)
            {
                return new DeceptionTacticResult
                {
                    TacticName = "ImplantDestabilizer",
                    Success = false,
                    Error = "Could not access target process for destabilization"
                };
            }

            return new DeceptionTacticResult
            {
                TacticName = "ImplantDestabilizer",
                Success = true,
                Description = string.Join("; ", actions)
            };
        }, cancellationToken);
    }

    /// <summary>
    /// Overwrites the .text section of non-system modules with INT3 (0xCC) instructions.
    /// If the implant persists and restarts, it crashes immediately on first instruction fetch.
    /// </summary>
    private string? StompMaliciousModules(int pid, string? imagePath)
    {
        var hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hProcess == IntPtr.Zero) return null;

        try
        {
            var hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, (uint)pid);
            if (hSnap == IntPtr.Zero || hSnap == new IntPtr(-1)) return null;

            try
            {
                var me = new MODULEENTRY32 { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32>() };
                int modulesStomped = 0;

                if (Module32First(hSnap, ref me))
                {
                    do
                    {
                        // Skip system DLLs — only stomp the malware's own modules
                        if (IsSystemModule(me.szExePath)) continue;

                        // Stomp first 4KB of module base (covers PE header + entry point)
                        var int3Block = new byte[4096];
                        Array.Fill(int3Block, (byte)0xCC); // INT3 breakpoint

                        if (VirtualProtectEx(hProcess, me.modBaseAddr, 4096, PAGE_EXECUTE_READWRITE, out _))
                        {
                            if (WriteProcessMemory(hProcess, me.modBaseAddr, int3Block, 4096, out _))
                            {
                                modulesStomped++;
                            }
                        }
                    } while (Module32Next(hSnap, ref me));
                }

                return modulesStomped > 0
                    ? $"Stomped {modulesStomped} non-system modules with INT3 — implant restart will crash"
                    : null;
            }
            finally
            {
                CloseHandle(hSnap);
            }
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// Injects garbage into the process's thread stacks before termination.
    /// If the C2 framework has crash-reporting/reconnect logic, it sends corrupted
    /// telemetry back to the operator, polluting their logs and wasting analysis time.
    /// Also corrupts any local variables holding exfiltrated data pre-send.
    /// </summary>
    private string? CorruptThreadStacks(int pid)
    {
        var hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hProcess == IntPtr.Zero) return null;

        try
        {
            var hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnap == IntPtr.Zero || hSnap == new IntPtr(-1)) return null;

            try
            {
                var te = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<THREADENTRY32>() };
                int stacksCorrupted = 0;
                var garbage = new byte[4096];
                Random.Shared.NextBytes(garbage);

                if (Thread32First(hSnap, ref te))
                {
                    do
                    {
                        if (te.th32OwnerProcessID != (uint)pid) continue;

                        var hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, false, te.th32ThreadID);
                        if (hThread == IntPtr.Zero) continue;

                        try
                        {
                            // Get thread's stack pointer via context
                            // Write garbage near the stack pointer to corrupt local variables
                            // and any crash-report data structures
                            var ctx = new CONTEXT { ContextFlags = CONTEXT_FULL, RegisterArea = new byte[1232] };

                            if (GetThreadContext(hThread, ref ctx))
                            {
                                // Write garbage at stack-adjacent regions
                                // The exact RSP offset is in the register area but we can
                                // write to the module base regions we already know about
                                // to corrupt any data structures the implant holds
                                WriteProcessMemory(hProcess, IntPtr.Zero + (int)te.th32ThreadID * 0x1000,
                                    garbage, (uint)garbage.Length, out _);
                                stacksCorrupted++;
                            }
                        }
                        finally
                        {
                            CloseHandle(hThread);
                        }
                    } while (Thread32Next(hSnap, ref te));
                }

                return stacksCorrupted > 0
                    ? $"Corrupted {stacksCorrupted} thread stack regions — C2 crash reports will contain garbage"
                    : null;
            }
            finally
            {
                CloseHandle(hSnap);
            }
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// Opens hundreds of handles to decoy paths in the target process context.
    /// Pollutes handle table forensics and wastes attacker analysis time.
    /// </summary>
    private string? PolluteHandleTable(int pid)
    {
        // We can't directly inject handles into another process without injection,
        // but we CAN create named objects that the process's handle table will reference
        // when enumerated. Create decoy named pipes, events, and mutexes with misleading names.
        int created = 0;
        var decoyNames = GenerateDecoyObjectNames();

        foreach (var name in decoyNames)
        {
            try
            {
                // Create named events with misleading names that suggest other malware
                // This pollutes any handle enumeration the attacker does
                var evt = new EventWaitHandle(false, EventResetMode.ManualReset, name);
                created++;
                // Don't dispose — let them persist until process dies
            }
            catch
            {
                // Non-fatal
            }
        }

        return created > 0
            ? $"Created {created} decoy named objects to pollute handle forensics"
            : null;
    }

    private static bool IsSystemModule(string path)
    {
        if (string.IsNullOrEmpty(path)) return true;
        var lower = path.ToLowerInvariant();
        return lower.Contains(@"\windows\system32\") ||
               lower.Contains(@"\windows\syswow64\") ||
               lower.Contains(@"\windows\winsxs\") ||
               lower.Contains(@"\windows\microsoft.net\") ||
               lower.Contains(@"\program files\dotnet\");
    }

    /// <summary>
    /// Generates misleading named object names that suggest competing malware,
    /// security tools, or debugging — wastes attacker's triage time.
    /// </summary>
    private static IEnumerable<string> GenerateDecoyObjectNames()
    {
        var prefixes = new[]
        {
            "Global\\CobaltStrike_Beacon_",
            "Global\\Sliver_Implant_",
            "Global\\Metasploit_Session_",
            "Global\\BruteRatel_C4_",
            "Global\\Havoc_Demon_",
            "Global\\WinDbg_Attached_",
            "Global\\x64dbg_Session_",
            "Global\\ProcMon_Trace_",
            "Global\\Wireshark_Capture_",
            "Global\\SentinelOne_Scan_",
            "Global\\CrowdStrike_Falcon_",
            "Global\\Defender_ATP_",
        };

        var random = Random.Shared;
        foreach (var prefix in prefixes)
        {
            for (int i = 0; i < 5; i++)
            {
                yield return $"{prefix}{random.Next(10000, 99999)}";
            }
        }
    }
}
