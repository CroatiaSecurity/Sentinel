using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    /// <summary>
    /// Remote process inspection and response primitives used by the EDR engine.
    /// All Win32 API calls use direct P/Invoke declarations — transparent to AV scanners,
    /// identical in behavior to any legitimate security product.
    /// </summary>
    internal static class NativeProcessMemory
    {
        public const uint AccessQuery = 0x0400;
        public const uint AccessQueryLimited = 0x1000;
        public const uint AccessVmRead = 0x0010;
        public const uint AccessVmOp = 0x0008;
        public const uint AccessThreadCtx = 0x0010;
        public const uint StateCommit = 0x1000;
        public const uint TypeImage = 0x1000000;
        public const uint ProtX = 0x10;
        public const uint ProtRX = 0x20;
        public const uint ProtRWX = 0x40;
        public const uint ProtXwc = 0x80;

        // Legacy aliases used by call sites
        public const uint PROCESS_QUERY_INFORMATION = AccessQuery;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = AccessQueryLimited;
        public const uint PROCESS_VM_READ = AccessVmRead;
        public const uint THREAD_SET_CONTEXT = AccessThreadCtx;
        public const uint MEM_COMMIT = StateCommit;
        public const uint MEM_IMAGE = TypeImage;
        public const uint PAGE_EXECUTE = ProtX;
        public const uint PAGE_EXECUTE_READ = ProtRX;
        public const uint PAGE_EXECUTE_READWRITE = ProtRWX;
        public const uint PAGE_EXECUTE_WRITECOPY = ProtXwc;

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        // ── Direct P/Invoke declarations ─────────────────────────────────────
        // Standard EDR practice: declare imports explicitly so the intent is
        // auditable and AV heuristics can correctly classify the binary.

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
            UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
            int dwDesiredAccess, bool bInheritHandle, int dwOptions);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryW(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int SystemInformationClass,
            IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr SetWindowsHookExW(int idHook, IntPtr lpfn,
            IntPtr hmod, uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        public static bool CanInspect(int pid, string? imagePath = null)
        {
            if (pid <= 4) return false;
            // Name-first: Denuvo titles self-terminate on VM_READ even when path resolve races.
            if (SecurityValidation.IsGameOrAntiCheatProcess(pid, imagePath))
                return false;
            imagePath ??= SecurityValidation.GetProcessImagePath(pid);
            // Fail closed: unresolved path → no VM_READ (PPL / anti-cheat / startup race).
            // Prefer missing a scan over killing interactive games.
            if (string.IsNullOrEmpty(imagePath))
                return false;
            return !SecurityValidation.IsGameOrAntiCheatPath(imagePath);
        }

        public static IntPtr OpenRemoteHandle(uint access, int pid)
        {
            // Central gate: never grant VM_READ to game / unresolved PIDs.
            if ((access & AccessVmRead) != 0 && !CanInspect(pid))
                return IntPtr.Zero;
            return OpenProcess(access, false, pid);
        }

        public static bool CopyRemote(IntPtr hProcess, IntPtr address, byte[] buffer, out int bytesRead)
        {
            bytesRead = 0;
            if (hProcess == IntPtr.Zero) return false;
            return ReadProcessMemory(hProcess, address, buffer, buffer.Length, out bytesRead);
        }

        public static int QueryRemoteRegion(IntPtr hProcess, IntPtr address, out MEMORY_BASIC_INFORMATION mbi)
        {
            mbi = default;
            if (hProcess == IntPtr.Zero) return 0;
            return VirtualQueryEx(hProcess, address, out mbi, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
        }

        public static bool IsExecutableProtection(uint protect) =>
            protect is ProtX or ProtRX or ProtRWX or ProtXwc;

        /// <summary>
        /// Strip execute from a remote region (reflective PE / shellcode).
        /// Games are refused by CanInspect. Does not unmap — PAGE_READONLY.
        /// </summary>
        public static bool TryStripExecute(int processId, IntPtr address, IntPtr size)
        {
            if (!CanInspect(processId) || address == IntPtr.Zero || size == IntPtr.Zero)
                return false;
            IntPtr h = OpenRemoteHandle(AccessQuery | AccessVmOp | AccessVmRead, processId);
            if (h == IntPtr.Zero) return false;
            try
            {
                return VirtualProtectEx(h, address, (UIntPtr)(ulong)size.ToInt64(), 0x02 /* PAGE_READONLY */, out _);
            }
            catch { return false; }
            finally { CloseHandle(h); }
        }

        /// <summary>
        /// Neuters a mapped module in place by stripping EXECUTE from every committed, executable
        /// page belonging to its image (walked from <paramref name="moduleBase"/> via VirtualQueryEx,
        /// bounded by <paramref name="moduleSize"/>). Used as an escalation when FreeLibrary-by-APC
        /// cannot be verified: the DLL stays mapped but its code can no longer run, so hooks and
        /// DllMain-installed callbacks are defanged without killing the (possibly legitimate) host.
        /// Games are refused by CanInspect. Returns true if at least one executable region was flipped.
        /// </summary>
        public static bool TryStripModuleExecute(int processId, IntPtr moduleBase, int moduleSize)
        {
            if (!CanInspect(processId) || moduleBase == IntPtr.Zero || moduleSize <= 0) return false;

            IntPtr h = OpenRemoteHandle(AccessQuery | AccessVmOp | AccessVmRead, processId);
            if (h == IntPtr.Zero) return false;
            try
            {
                bool any = false;
                long start = moduleBase.ToInt64();
                long end = start + moduleSize;
                long cursor = start;
                int guard = 0;
                while (cursor < end && guard++ < 4096)
                {
                    var addr = new IntPtr(cursor);
                    int n = VirtualQueryEx(h, addr, out var mbi, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
                    if (n == 0) break;

                    long regionSize = mbi.RegionSize.ToInt64();
                    if (regionSize <= 0) break;

                    if (mbi.State == StateCommit && IsExecutableProtection(mbi.Protect))
                    {
                        // Flip execute → PAGE_READONLY. Leave the bytes intact (analysts can still
                        // read them); only remove the ability to execute.
                        if (VirtualProtectEx(h, mbi.BaseAddress, (UIntPtr)(ulong)regionSize, 0x02 /* PAGE_READONLY */, out _))
                            any = true;
                    }
                    cursor += regionSize;
                }
                return any;
            }
            catch { return false; }
            finally { CloseHandle(h); }
        }

        public static bool LooksLikeMzPe(int processId, IntPtr address)
        {
            if (!CanInspect(processId) || address == IntPtr.Zero) return false;
            var buf = new byte[2];
            IntPtr h = OpenRemoteHandle(AccessQuery | AccessVmRead, processId);
            if (h == IntPtr.Zero) return false;
            try
            {
                if (!CopyRemote(h, address, buf, out int n) || n < 2) return false;
                return buf[0] == (byte)'M' && buf[1] == (byte)'Z';
            }
            catch { return false; }
            finally { CloseHandle(h); }
        }

        public static bool TryQueueFreeLibrary(int processId, IntPtr moduleBase)
        {
            if (!CanInspect(processId)) return false;

            // Get FreeLibrary's raw function pointer via GetProcAddress.
            // kernel32 is always mapped at the same base address across processes in the
            // same session (known-DLL), so this pointer is valid as an APC target.
            IntPtr hKernel = LoadLibraryW("kernel32.dll");
            if (hKernel == IntPtr.Zero) return false;
            IntPtr freeLibraryPtr = GetProcAddress(hKernel, "FreeLibrary");
            if (freeLibraryPtr == IntPtr.Zero) return false;

            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById(processId);
                foreach (System.Diagnostics.ProcessThread thread in proc.Threads)
                {
                    IntPtr hThread = OpenThread(AccessThreadCtx, false, (uint)thread.Id);
                    if (hThread == IntPtr.Zero) continue;
                    try
                    {
                        if (QueueUserAPC(freeLibraryPtr, hThread, moduleBase) != 0)
                            return true;
                    }
                    finally { CloseHandle(hThread); }
                }
            }
            catch { return false; }
            return false;
        }

        public static int QuerySystemInfo(int infoClass, IntPtr buffer, int size, out int returnLength)
        {
            return NtQuerySystemInformation(infoClass, buffer, size, out returnLength);
        }

        public static bool DupHandle(IntPtr srcProc, IntPtr src, IntPtr dstProc, out IntPtr dst, int access, bool inherit, int options)
        {
            return DuplicateHandle(srcProc, src, dstProc, out dst, access, inherit, options);
        }

        public static IntPtr InstallLowLevelHook(int idHook, Delegate callback, IntPtr module, uint threadId)
        {
            if (callback == null) return IntPtr.Zero;
            // Keep the delegate rooted by caller; convert to unmanaged pointer for the hook API.
            IntPtr cb = Marshal.GetFunctionPointerForDelegate(callback);
            return SetWindowsHookExW(idHook, cb, module, threadId);
        }

        public static bool RemoveHook(IntPtr handle)
        {
            return handle != IntPtr.Zero && UnhookWindowsHookEx(handle);
        }

        public static List<(string Name, string Path, IntPtr Base, int Size)> EnumModules(int pid)
        {
            var list = new List<(string, string, IntPtr, int)>();
            if (!CanInspect(pid)) return list;
            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById(pid);
                foreach (System.Diagnostics.ProcessModule mod in proc.Modules)
                {
                    list.Add((
                        mod.ModuleName ?? "",
                        mod.FileName ?? "",
                        mod.BaseAddress,
                        mod.ModuleMemorySize));
                }
            }
            catch { }
            return list;
        }
    }
}
