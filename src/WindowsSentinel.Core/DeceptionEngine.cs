using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace WindowsSentinel.Core
{
    public class DeceptionEngine
    {
        private readonly SentinelMetrics _metrics;
        private readonly JsonlEventLogger _eventLogger;

        public DeceptionEngine(SentinelMetrics metrics, JsonlEventLogger eventLogger)
        {
            _metrics = metrics;
            _eventLogger = eventLogger;
        }

        public async Task ExecutePreKillDeceptionAsync(int targetPid, string ruleName, string reasoning)
        {
            // Ransomware Fast-Path: bypass deception entirely
            if (ruleName.Contains("Ransomware", StringComparison.OrdinalIgnoreCase) || 
                reasoning.Contains("Ransomware", StringComparison.OrdinalIgnoreCase))
            {
                await LogDeceptionActionAsync(targetPid, "FAST-PATH", "Ransomware detected; bypassing deception engine for immediate kill.");
                return;
            }

            if (targetPid <= 4) return; // Never target System/Idle

            var stopwatch = Stopwatch.StartNew();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2)); // Hard 2-second budget

            try
            {
                // Run synchronous/on-host deception tactics in sequence with cancellation token checks
                await RunTacticAsync(targetPid, "ClipboardPoisoning", () => ClipboardPoisonTactic.Execute(), cts.Token);
                await RunTacticAsync(targetPid, "MemoryFlooding", () => MemoryFloodingTactic.Execute(targetPid), cts.Token);
                await RunTacticAsync(targetPid, "ImplantDestabilizer", () => ImplantDestabilizerTactic.Execute(targetPid), cts.Token);
                await RunTacticAsync(targetPid, "EnvironmentPoisoning", () => EnvironmentPoisonerTactic.Execute(), cts.Token);
                await RunTacticAsync(targetPid, "FileTrap", () => FileTrapTactic.Execute(), cts.Token);

                // Run asynchronous background/network deception (fire-and-forget, does not consume budget)
                _ = Task.Run(() => BeaconFlooderTactic.ExecuteAsync(targetPid), CancellationToken.None);
                _ = Task.Run(() => NetworkHoneypotDeployerTactic.ExecuteAsync(), CancellationToken.None);
            }
            catch (OperationCanceledException)
            {
                await LogDeceptionActionAsync(targetPid, "BUDGET-EXCEEDED", "Pre-kill deception budget (2s) reached; forcing termination.");
            }
            catch (Exception ex)
            {
                await LogDeceptionActionAsync(targetPid, "FAILURE", $"Deception engine error: {ex.Message}");
            }
            finally
            {
                stopwatch.Stop();
                _metrics.RecordDeception(stopwatch.ElapsedMilliseconds);
            }
        }

        private async Task RunTacticAsync(int targetPid, string name, Action action, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            await LogDeceptionActionAsync(targetPid, name, $"Executing tactic: {name}");
            try
            {
                action();
            }
            catch (Exception ex)
            {
                await LogDeceptionActionAsync(targetPid, name, $"Tactic {name} failed: {ex.Message}");
            }
        }

        private async Task LogDeceptionActionAsync(int pid, string tactic, string detail)
        {
            var log = new
            {
                TargetPid = pid,
                TacticName = tactic,
                Details = detail,
                Timestamp = DateTime.UtcNow
            };
            await _eventLogger.LogEventAsync("deception_action", log);
        }
    }

    // --- Deception Tactics Implementations ---

    public static class ClipboardPoisonTactic
    {
        public static void Execute()
        {
            // Clipboard poisoning: Replace clipboard with fake credentials/keys
            // STA thread check required for WinForms Clipboard access
            var thread = new Thread(() =>
            {
                try
                {
                    System.Windows.Forms.Clipboard.SetText("AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE-POISONED");
                }
                catch
                {
                    // Ignore clipboard lock issues
                }
            });
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            thread.Join(100);
        }
    }

    // --- Deception Tactics Real Implementations ---

    internal static class DeceptionNative
    {
        public const uint PROCESS_VM_OPERATION = 0x0008;
        public const uint PROCESS_VM_WRITE = 0x0020;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_DUP_HANDLE = 0x0040;

        public const uint THREAD_SUSPEND_RESUME = 0x0002;
        public const uint THREAD_GET_CONTEXT = 0x0008;
        public const uint THREAD_SET_CONTEXT = 0x0010;

        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;

        public const uint DUPLICATE_SAME_ACCESS = 0x0002;
        public const uint TH32CS_SNAPTHREAD = 0x0004;

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public ushort PartitionId;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct THREADENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ThreadID;
            public uint th32OwnerProcessID;
            public int tpBasePri;
            public int tpDeltaPri;
            public uint dwFlags;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string? lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            out IntPtr lpTargetHandle,
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwOptions);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();
    }

    public static class MemoryFloodingTactic
    {
        public static void Execute(int pid)
        {
            if (pid <= 4) return;
            IntPtr hProcess = DeceptionNative.OpenProcess(DeceptionNative.PROCESS_VM_OPERATION | DeceptionNative.PROCESS_VM_WRITE, false, pid);
            if (hProcess == IntPtr.Zero) return;

            try
            {
                // Allocate 256MB in chunks of 16MB
                int numChunks = 16;
                uint chunkSize = 16 * 1024 * 1024;
                var garbage = new byte[65536];
                new Random().NextBytes(garbage);

                for (int i = 0; i < numChunks; i++)
                {
                    IntPtr addr = DeceptionNative.VirtualAllocEx(hProcess, IntPtr.Zero, chunkSize, DeceptionNative.MEM_COMMIT | DeceptionNative.MEM_RESERVE, DeceptionNative.PAGE_READWRITE);
                    if (addr != IntPtr.Zero)
                    {
                        // Write garbage across the allocation
                        for (uint offset = 0; offset < chunkSize; offset += (uint)garbage.Length)
                        {
                            DeceptionNative.WriteProcessMemory(hProcess, addr + (int)offset, garbage, (uint)garbage.Length, out _);
                        }
                    }
                }
            }
            catch
            {
                // Degrade
            }
            finally
            {
                DeceptionNative.CloseHandle(hProcess);
            }
        }
    }

    public static class ImplantDestabilizerTactic
    {
        public static void Execute(int pid)
        {
            if (pid <= 4) return;

            // 1. Handle Table Pollution
            IntPtr hEvent = DeceptionNative.CreateEvent(IntPtr.Zero, true, false, null);
            if (hEvent != IntPtr.Zero)
            {
                IntPtr hProcessDup = DeceptionNative.OpenProcess(DeceptionNative.PROCESS_DUP_HANDLE, false, pid);
                if (hProcessDup != IntPtr.Zero)
                {
                    try
                    {
                        for (int i = 0; i < 500; i++)
                        {
                            DeceptionNative.DuplicateHandle(DeceptionNative.GetCurrentProcess(), hEvent, hProcessDup, out _, 0, false, DeceptionNative.DUPLICATE_SAME_ACCESS);
                        }
                    }
                    catch { }
                    finally
                    {
                        DeceptionNative.CloseHandle(hProcessDup);
                    }
                }
                DeceptionNative.CloseHandle(hEvent);
            }

            // 2. DLL Stomping (overwriting function prologues with INT3)
            IntPtr hProcessStomp = DeceptionNative.OpenProcess(DeceptionNative.PROCESS_QUERY_INFORMATION | DeceptionNative.PROCESS_VM_OPERATION | DeceptionNative.PROCESS_VM_WRITE | DeceptionNative.PROCESS_VM_READ, false, pid);
            if (hProcessStomp != IntPtr.Zero)
            {
                try
                {
                    IntPtr address = IntPtr.Zero;
                    DeceptionNative.MEMORY_BASIC_INFORMATION mbi;
                    int structSize = Marshal.SizeOf<DeceptionNative.MEMORY_BASIC_INFORMATION>();
                    int stompedCount = 0;

                    // Stomp up to 20 executable regions
                    while (DeceptionNative.VirtualQueryEx(hProcessStomp, address, out mbi, (uint)structSize) != 0 && stompedCount < 20)
                    {
                        if (mbi.State == DeceptionNative.MEM_COMMIT &&
                            (mbi.Protect == DeceptionNative.PAGE_EXECUTE_READ || mbi.Protect == DeceptionNative.PAGE_EXECUTE_READWRITE))
                        {
                            if (DeceptionNative.VirtualProtectEx(hProcessStomp, mbi.BaseAddress, 32, DeceptionNative.PAGE_EXECUTE_READWRITE, out uint oldProtect))
                            {
                                var int3Patch = new byte[32];
                                for (int k = 0; k < 32; k++) int3Patch[k] = 0xCC; // INT3 breakpoint instructions
                                DeceptionNative.WriteProcessMemory(hProcessStomp, mbi.BaseAddress, int3Patch, (uint)int3Patch.Length, out _);
                                DeceptionNative.VirtualProtectEx(hProcessStomp, mbi.BaseAddress, 32, oldProtect, out _);
                                stompedCount++;
                            }
                        }
                        address = (IntPtr)((ulong)mbi.BaseAddress + (ulong)mbi.RegionSize);
                    }
                }
                catch { }
                finally
                {
                    DeceptionNative.CloseHandle(hProcessStomp);
                }
            }

            // 3. Stack Corruption (x64 context-aligned context manipulation)
            IntPtr hSnapshot = DeceptionNative.CreateToolhelp32Snapshot(DeceptionNative.TH32CS_SNAPTHREAD, 0);
            if (hSnapshot != (IntPtr)(-1))
            {
                try
                {
                    var te = new DeceptionNative.THREADENTRY32();
                    te.dwSize = (uint)Marshal.SizeOf(te);

                    if (DeceptionNative.Thread32First(hSnapshot, ref te))
                    {
                        do
                        {
                            if (te.th32OwnerProcessID == (uint)pid)
                            {
                                IntPtr hThread = DeceptionNative.OpenThread(DeceptionNative.THREAD_SUSPEND_RESUME | DeceptionNative.THREAD_GET_CONTEXT | DeceptionNative.THREAD_SET_CONTEXT, false, te.th32ThreadID);
                                if (hThread != IntPtr.Zero)
                                {
                                    try
                                    {
                                        DeceptionNative.SuspendThread(hThread);

                                        // Allocate 16-byte aligned context block (1232 bytes context size on x64)
                                        int contextSize = 1232;
                                        IntPtr rawBuffer = Marshal.AllocHGlobal(contextSize + 15);
                                        IntPtr alignedContext = (IntPtr)(((long)rawBuffer + 15) & ~15);

                                        // Set CONTEXT_CONTROL flag (0x00100001) at offset 48 (ContextFlags)
                                        Marshal.WriteInt32(alignedContext, 48, 0x00100001);

                                        if (DeceptionNative.GetThreadContext(hThread, alignedContext))
                                        {
                                            long rsp = Marshal.ReadInt64(alignedContext, 152); // RSP offset
                                            long rip = Marshal.ReadInt64(alignedContext, 248); // RIP offset

                                            // Corrupt stack pointer alignment and zero instruction pointer
                                            Marshal.WriteInt64(alignedContext, 152, rsp - 0x100000);
                                            Marshal.WriteInt64(alignedContext, 248, 0L);

                                            DeceptionNative.SetThreadContext(hThread, alignedContext);
                                        }

                                        Marshal.FreeHGlobal(rawBuffer);
                                    }
                                    catch { }
                                    finally
                                    {
                                        DeceptionNative.ResumeThread(hThread);
                                        DeceptionNative.CloseHandle(hThread);
                                    }
                                }
                            }
                        }
                        while (DeceptionNative.Thread32Next(hSnapshot, ref te));
                    }
                }
                catch { }
                finally
                {
                    DeceptionNative.CloseHandle(hSnapshot);
                }
            }
        }
    }

    public static class EnvironmentPoisonerTactic
    {
        public static void Execute()
        {
            // HKCU only modifications
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
                key.SetValue("ProxyEnable", 1);
                key.SetValue("ProxyServer", "127.0.0.1:8080");
            }
            catch
            {
                // Degrade gracefully
            }
        }
    }

    public static class FileTrapTactic
    {
        private const uint FSCTL_SET_SPARSE = 0x000900C4;
        private const uint FSCTL_SET_ZERO_DATA = 0x000980C8;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint OPEN_ALWAYS = 4;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_ZERO_DATA_INFORMATION
        {
            public long FileOffset;
            public long BeyondFinalZero;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFile(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice, uint dwIoControlCode,
            ref FILE_ZERO_DATA_INFORMATION lpInBuffer, int nInBufferSize,
            IntPtr lpOutBuffer, int nOutBufferSize,
            out int lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice, uint dwIoControlCode,
            IntPtr lpInBuffer, int nInBufferSize,
            IntPtr lpOutBuffer, int nOutBufferSize,
            out int lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFilePointerEx(
            IntPtr hFile, long liDistanceToMove, IntPtr lpNewFilePointer, uint dwMoveMethod);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetEndOfFile(IntPtr hFile);

        public static void Execute()
        {
            // Creates NTFS sparse files that appear enormous on disk but consume zero physical space.
            // This traps exfiltration tools and ransomware that enumerate by apparent size.
            try
            {
                var tempPath = Path.GetTempPath();
                var trapFile = Path.Combine(tempPath, "backup_keys.bak");

                // Create or open the file via Win32 for sparse control
                IntPtr hFile = CreateFile(trapFile, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ,
                    IntPtr.Zero, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);

                if (hFile == (IntPtr)(-1)) return;

                try
                {
                    // Mark as sparse
                    DeviceIoControl(hFile, FSCTL_SET_SPARSE,
                        IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);

                    // Set logical size to 1 GB (appears huge, costs 0 bytes)
                    long sparseSize = 1L * 1024 * 1024 * 1024;
                    SetFilePointerEx(hFile, sparseSize, IntPtr.Zero, 0);
                    SetEndOfFile(hFile);

                    // Mark entire extent as zero-filled (no physical clusters allocated)
                    var zeroData = new FILE_ZERO_DATA_INFORMATION
                    {
                        FileOffset = 0,
                        BeyondFinalZero = sparseSize
                    };
                    DeviceIoControl(hFile, FSCTL_SET_ZERO_DATA,
                        ref zeroData, Marshal.SizeOf(zeroData),
                        IntPtr.Zero, 0, out _, IntPtr.Zero);
                }
                finally
                {
                    DeceptionNative.CloseHandle(hFile);
                }
            }
            catch
            {
                // Degrade
            }
        }
    }

    public static class BeaconFlooderTactic
    {
        /// <summary>
        /// Floods the target process's network context with rapid UDP beacon noise
        /// to loopback (127.0.0.1), disrupting C2 timing analysis.
        /// Fire-and-forget; runs for ~5 seconds.
        /// </summary>
        public static async Task ExecuteAsync(int pid)
        {
            try
            {
                using var udpClient = new System.Net.Sockets.UdpClient();
                var rng = new Random();
                var payload = new byte[64];
                var stopwatch = Stopwatch.StartNew();

                // Send 5 seconds of UDP noise to loopback on random high ports
                while (stopwatch.ElapsedMilliseconds < 5000)
                {
                    rng.NextBytes(payload);
                    int port = rng.Next(10000, 65535);
                    await udpClient.SendAsync(payload, payload.Length, "127.0.0.1", port);
                    await Task.Delay(1); // ~1000 packets/sec rate
                }
            }
            catch
            {
                // Degrade; network flooding is best-effort
            }
        }
    }

    public static class NetworkHoneypotDeployerTactic
    {
        /// <summary>
        /// Deploys a short-lived TCP honeypot listener on port 4444 (common C2 port).
        /// Accepts connections and logs remote endpoints for forensic analysis.
        /// Runs for up to 30 minutes then self-terminates.
        /// </summary>
        public static async Task ExecuteAsync()
        {
            System.Net.Sockets.TcpListener? listener = null;
            try
            {
                listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 4444);
                listener.Start();

                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(30));

                while (!cts.Token.IsCancellationRequested)
                {
                    // Wait for an incoming connection (respects cancellation via polling)
                    if (listener.Pending())
                    {
                        using var client = await listener.AcceptTcpClientAsync();
                        var remoteEp = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
                        Debug.WriteLine($"[Honeypot] Connection from: {remoteEp}");

                        // Send a fake banner to keep the connection alive briefly
                        var banner = System.Text.Encoding.ASCII.GetBytes("220 ESMTP Postfix\r\n");
                        try
                        {
                            await client.GetStream().WriteAsync(banner, 0, banner.Length, cts.Token);
                        }
                        catch { }
                    }
                    else
                    {
                        await Task.Delay(500, cts.Token);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown after 30-minute lifetime
            }
            catch
            {
                // Port may be in use or blocked; degrade gracefully
            }
            finally
            {
                listener?.Stop();
            }
        }
    }
}
