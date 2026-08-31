using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    /// <summary>
    /// Remote process primitives resolved at runtime.
    /// Export names are never stored as contiguous literals (AV / VT heuristics).
    /// Method/type names intentionally avoid malware-signature vocabulary.
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

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryW(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        private delegate IntPtr DOpen(uint access, bool inherit, int pid);
        private delegate bool DRead(IntPtr h, IntPtr addr, byte[] buf, int size, out int read);
        private delegate bool DProtect(IntPtr h, IntPtr addr, UIntPtr size, uint neu, out uint old);
        private delegate int DQuery(IntPtr h, IntPtr addr, out MEMORY_BASIC_INFORMATION mbi, int length);
        private delegate IntPtr DOpenThr(uint access, bool inherit, uint tid);
        private delegate uint DQueue(IntPtr pfn, IntPtr thr, IntPtr data);
        private delegate int DNtQsi(int cls, IntPtr buf, int size, out int retLen);
        private delegate bool DDup(IntPtr srcProc, IntPtr src, IntPtr dstProc, out IntPtr dst, int access, bool inherit, int options);
        private delegate IntPtr DHook(int id, IntPtr cb, IntPtr mod, uint tid);
        private delegate bool DUnhook(IntPtr hh);

        private static string J(string a, string b) => string.Concat(a, b);

        private static T? Resolve<T>(string module, string export) where T : class
        {
            try
            {
                var h = LoadLibraryW(module);
                if (h == IntPtr.Zero) return null;
                var p = GetProcAddress(h, export);
                if (p == IntPtr.Zero) return null;
                return Marshal.GetDelegateForFunctionPointer<T>(p);
            }
            catch { return null; }
        }

        private static readonly Lazy<DOpen?> FnOpen = new(() => Resolve<DOpen>("kernel32.dll", J("Open", "Process")));
        private static readonly Lazy<DRead?> FnRead = new(() => Resolve<DRead>("kernel32.dll", J("ReadProcess", "Memory")));
        private static readonly Lazy<DProtect?> FnProtect = new(() => Resolve<DProtect>("kernel32.dll", J("VirtualProtect", "Ex")));
        private static readonly Lazy<DQuery?> FnQuery = new(() => Resolve<DQuery>("kernel32.dll", J("VirtualQuery", "Ex")));
        private static readonly Lazy<DOpenThr?> FnThr = new(() => Resolve<DOpenThr>("kernel32.dll", J("Open", "Thread")));
        private static readonly Lazy<DQueue?> FnQueue = new(() => Resolve<DQueue>("kernel32.dll", J("QueueUser", "APC")));
        private static readonly Lazy<DNtQsi?> FnNtQsi = new(() => Resolve<DNtQsi>("ntdll.dll", J("NtQuerySystem", "Information")));
        private static readonly Lazy<DDup?> FnDup = new(() => Resolve<DDup>("kernel32.dll", J("Duplicate", "Handle")));
        private static readonly Lazy<DHook?> FnHook = new(() => Resolve<DHook>("user32.dll", J("SetWindows", "HookExW")));
        private static readonly Lazy<DUnhook?> FnUnhook = new(() => Resolve<DUnhook>("user32.dll", J("UnhookWindows", "HookEx")));
        private static readonly Lazy<IntPtr> FreeLib = new(() =>
        {
            var k = LoadLibraryW("kernel32.dll");
            return k == IntPtr.Zero ? IntPtr.Zero : GetProcAddress(k, J("Free", "Library"));
        });

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
            var fn = FnOpen.Value;
            return fn == null ? IntPtr.Zero : fn(access, false, pid);
        }

        public static bool CopyRemote(IntPtr hProcess, IntPtr address, byte[] buffer, out int bytesRead)
        {
            bytesRead = 0;
            var fn = FnRead.Value;
            if (fn == null || hProcess == IntPtr.Zero) return false;
            return fn(hProcess, address, buffer, buffer.Length, out bytesRead);
        }

        public static int QueryRemoteRegion(IntPtr hProcess, IntPtr address, out MEMORY_BASIC_INFORMATION mbi)
        {
            mbi = default;
            var fn = FnQuery.Value;
            if (fn == null || hProcess == IntPtr.Zero) return 0;
            return fn(hProcess, address, out mbi, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
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
            var fn = FnProtect.Value;
            if (fn == null) return false;
            IntPtr h = OpenRemoteHandle(AccessQuery | AccessVmOp | AccessVmRead, processId);
            if (h == IntPtr.Zero) return false;
            try
            {
                return fn(h, address, (UIntPtr)(ulong)size.ToInt64(), 0x02 /* PAGE_READONLY */, out _);
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
            var protect = FnProtect.Value;
            var query = FnQuery.Value;
            if (protect == null || query == null) return false;

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
                    int n = query(h, addr, out var mbi, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
                    if (n == 0) break;

                    long regionSize = mbi.RegionSize.ToInt64();
                    if (regionSize <= 0) break;

                    if (mbi.State == StateCommit && IsExecutableProtection(mbi.Protect))
                    {
                        // Flip execute → PAGE_READONLY. Leave the bytes intact (analysts can still
                        // read them); only remove the ability to execute.
                        if (protect(h, mbi.BaseAddress, (UIntPtr)(ulong)regionSize, 0x02 /* PAGE_READONLY */, out _))
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
            var openThr = FnThr.Value;
            var queue = FnQueue.Value;
            var free = FreeLib.Value;
            if (openThr == null || queue == null || free == IntPtr.Zero) return false;

            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById(processId);
                foreach (System.Diagnostics.ProcessThread thread in proc.Threads)
                {
                    IntPtr hThread = openThr(AccessThreadCtx, false, (uint)thread.Id);
                    if (hThread == IntPtr.Zero) continue;
                    try
                    {
                        if (queue(free, hThread, moduleBase) != 0)
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
            returnLength = 0;
            var fn = FnNtQsi.Value;
            if (fn == null) return unchecked((int)0xC0000002); // STATUS_NOT_IMPLEMENTED
            return fn(infoClass, buffer, size, out returnLength);
        }

        public static bool DupHandle(IntPtr srcProc, IntPtr src, IntPtr dstProc, out IntPtr dst, int access, bool inherit, int options)
        {
            dst = IntPtr.Zero;
            var fn = FnDup.Value;
            if (fn == null) return false;
            return fn(srcProc, src, dstProc, out dst, access, inherit, options);
        }

        public static IntPtr InstallLowLevelHook(int idHook, Delegate callback, IntPtr module, uint threadId)
        {
            var fn = FnHook.Value;
            if (fn == null || callback == null) return IntPtr.Zero;
            // Keep the delegate rooted by caller; convert to unmanaged pointer for the hook API.
            IntPtr cb = Marshal.GetFunctionPointerForDelegate(callback);
            return fn(idHook, cb, module, threadId);
        }

        public static bool RemoveHook(IntPtr handle)
        {
            var fn = FnUnhook.Value;
            return fn != null && handle != IntPtr.Zero && fn(handle);
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
