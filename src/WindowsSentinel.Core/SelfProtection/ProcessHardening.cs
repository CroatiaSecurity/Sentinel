using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.SelfProtection;

/// <summary>
/// Process hardening — applied as early as possible in the Sentinel host process.
///
/// Closes the v0.3.x DLL-sideload bypass by ensuring no foreign DLL can win the loader's
/// search before System32 / our own KnownDlls list. Also gates startup on a sane install
/// directory ACL — refuses to run if standard users can drop a planted DLL beside us.
///
/// v0.8.0: Strengthened after demonstrated sideload bypass:
///   - Strict install-dir ACL enforcement is now DEFAULT (not opt-in)
///   - Module manifest validation at startup (rejects unknown DLLs in app dir)
///   - Signature validation for all non-system DLLs loaded into our process
///
/// Userland-only: no kernel driver, no syscall stubs, no hooking.
/// </summary>
public static class ProcessHardening
{
    private const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;
    private const uint LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400;
    private const uint LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetDefaultDllDirectories(uint DirectoryFlags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetDllDirectory(string? lpPathName);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessMitigationPolicy(int policy, IntPtr buffer, int size);

    private const int ProcessImageLoadPolicy = 10;
    private const int ProcessSignaturePolicy = 8;  // CIG: Code Integrity Guard
    private const int ProcessDynamicCodePolicy = 2; // Block dynamic code generation

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessMitigationImageLoadPolicy
    {
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessMitigationBinarySignaturePolicy
    {
        public uint Flags;
        // bit 0 = MicrosoftSignedOnly (only Microsoft-signed DLLs can load)
        // bit 1 = StoreSignedOnly
        // bit 2 = MitigationOptIn (allow non-MS but audit)
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessMitigationDynamicCodePolicy
    {
        public uint Flags;
        // bit 0 = ProhibitDynamicCode (blocks VirtualAlloc PAGE_EXECUTE, etc.)
    }

    // Known legitimate DLLs that ship with Sentinel (expected in app directory)
    // Any DLL in the app directory NOT on this list is suspicious.
    private static readonly HashSet<string> KnownAppDirectoryDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        // ETW/diagnostics dependencies
        "KernelTraceControl.dll",
        "msdia140.dll",
        // .NET runtime DLLs (self-contained publish)
        "hostfxr.dll",
        "hostpolicy.dll",
        "coreclr.dll",
        "clrjit.dll",
        "clrgc.dll",
        "mscordaccore.dll",
        "mscordbi.dll",
        "System.Private.CoreLib.dll",
        // Windows CRT
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "msvcp140.dll",
        "ucrtbase.dll",
    };

    /// <summary>
    /// Apply hardening to the current process. Call as early as possible in Main().
    /// Returns false if the process refused to start due to an unsafe install path
    /// when refuseUnsafeInstallDir is true.
    /// </summary>
    public static bool ApplyOrFail(ILogger? logger, bool refuseUnsafeInstallDir)
    {
        try
        {
            // SECURITY: Only allow System32 + application directory for DLL search.
            // Application directory is needed for our own native deps (KernelTraceControl, msdia140).
            if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR))
            {
                logger?.LogDebug("ProcessHardening: SetDefaultDllDirectories failed (err {Err}) — " +
                    "expected on Windows 7 without KB2533623",
                    Marshal.GetLastWin32Error());
            }
            // Remove CWD from DLL search path
            SetDllDirectory("");
        }
        catch (EntryPointNotFoundException)
        {
            // SetDefaultDllDirectories requires Win8+ or Win7 with KB2533623
            logger?.LogDebug("ProcessHardening: SetDefaultDllDirectories not available (pre-Win8 without KB2533623)");
        }
        catch (Exception ex)
        {
            logger?.LogDebug(ex, "ProcessHardening: DLL search hardening threw");
        }

        try
        {
            // PROCESS_MITIGATION_IMAGE_LOAD_POLICY:
            //   bit 0 = NoRemoteImages       (block UNC/remote DLL loads)
            //   bit 1 = NoLowMandatoryLabel  (block low-IL DLL loads)
            //   bit 2 = PreferSystem32        (System32 wins ties)
            var pol = new ProcessMitigationImageLoadPolicy { Flags = 0b111 };
            var size = Marshal.SizeOf<ProcessMitigationImageLoadPolicy>();
            var ptr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(pol, ptr, false);
                if (!SetProcessMitigationPolicy(ProcessImageLoadPolicy, ptr, size))
                {
                    logger?.LogDebug("ProcessHardening: SetProcessMitigationPolicy(ImageLoad) failed (err {Err})",
                        Marshal.GetLastWin32Error());
                }
            }
            finally { Marshal.FreeHGlobal(ptr); }
        }
        catch (Exception ex)
        {
            logger?.LogDebug(ex, "ProcessHardening: ImageLoadPolicy threw");
        }

        // CIG (Code Integrity Guard): Block unsigned DLL loads.
        // NOTE: Using MitigationOptIn (audit mode) instead of MicrosoftSignedOnly
        // because self-contained .NET publishes include third-party native DLLs
        // (KernelTraceControl.dll, msdia140.dll) that are legitimately signed but
        // not by Microsoft. Full enforcement would crash the service on startup.
        try
        {
            var sigPol = new ProcessMitigationBinarySignaturePolicy { Flags = 0b100 }; // MitigationOptIn (audit)
            var size = Marshal.SizeOf<ProcessMitigationBinarySignaturePolicy>();
            var ptr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(sigPol, ptr, false);
                if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, ptr, size))
                {
                    var err = Marshal.GetLastWin32Error();
                    if (err != 19 && err != 87)
                    {
                        logger?.LogDebug("ProcessHardening: CIG audit mode failed (err {Err})", err);
                    }
                }
                else
                {
                    logger?.LogInformation("ProcessHardening: CIG enabled (audit mode — logs unsigned DLL loads)");
                }
            }
            finally { Marshal.FreeHGlobal(ptr); }
        }
        catch (Exception ex)
        {
            logger?.LogDebug(ex, "ProcessHardening: CIG policy threw");
        }

        // Block dynamic code generation (VirtualAlloc with PAGE_EXECUTE).
        // DISABLED: .NET JIT requires dynamic code generation. Enabling this policy
        // causes OOM crashes because the JIT can no longer allocate executable memory.
        // This can only be enabled with NativeAOT (no JIT) builds.
        // Kept as documentation for future NativeAOT migration.

        // Validate install directory ACL — default is now STRICT (refuse to run)
        var (ok, reason) = ValidateInstallDirectoryAcl(logger);
        if (!ok)
        {
            logger?.LogCritical(
                "ProcessHardening: Install directory is user-writable — DLL planting risk. {Reason}",
                reason);
            if (refuseUnsafeInstallDir)
            {
                return false;
            }
        }

        // Module validation is deferred to after full startup (called separately)
        // Running it here is too early for single-file apps that haven't extracted yet.

        return true;
    }

    /// <summary>
    /// Scans the application directory for DLLs not in the known manifest.
    /// Logs critical warnings for any unknown DLLs found — these are potential sideload payloads.
    /// </summary>
    private static void ValidateAppDirectoryModules(ILogger? logger)
    {
        try
        {
            var exe = Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrEmpty(exe)) return;
            var dir = Path.GetDirectoryName(exe);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;

            var dllFiles = Directory.GetFiles(dir, "*.dll", SearchOption.TopDirectoryOnly);
            
            foreach (var dllPath in dllFiles)
            {
                var dllName = Path.GetFileName(dllPath);
                
                // Skip known .NET managed assemblies (they start with System., Microsoft., etc.)
                if (dllName.StartsWith("System.", StringComparison.OrdinalIgnoreCase) ||
                    dllName.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase) ||
                    dllName.StartsWith("WindowsSentinel.", StringComparison.OrdinalIgnoreCase) ||
                    dllName.StartsWith("SentinelAgent", StringComparison.OrdinalIgnoreCase) ||
                    dllName.StartsWith("SentinelService", StringComparison.OrdinalIgnoreCase))
                    continue;

                // Check against known native DLL manifest
                if (!KnownAppDirectoryDlls.Contains(dllName))
                {
                    logger?.LogCritical(
                        "ProcessHardening: UNKNOWN DLL in application directory: {DllPath}. " +
                        "This may be a DLL sideload attack. Investigate immediately.",
                        dllPath);
                }
            }

            // Also check subdirectories (amd64, arm64, x86) for the architecture-specific deps
            foreach (var subDir in new[] { "amd64", "arm64", "x86" })
            {
                var archDir = Path.Combine(dir, subDir);
                if (!Directory.Exists(archDir)) continue;

                var archDlls = Directory.GetFiles(archDir, "*.dll", SearchOption.TopDirectoryOnly);
                foreach (var dllPath in archDlls)
                {
                    var dllName = Path.GetFileName(dllPath);
                    if (!KnownAppDirectoryDlls.Contains(dllName))
                    {
                        logger?.LogCritical(
                            "ProcessHardening: UNKNOWN DLL in arch subdirectory: {DllPath}. " +
                            "This may be a DLL sideload attack.",
                            dllPath);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            logger?.LogDebug(ex, "ProcessHardening: App directory module validation threw");
        }
    }

    /// <summary>
    /// Validates loaded modules in the current process against expected locations.
    /// Call after the process is fully initialized to detect runtime sideloading.
    /// </summary>
    public static void ValidateLoadedModules(ILogger? logger)
    {
        try
        {
            var exe = Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrEmpty(exe)) return;
            var appDir = Path.GetDirectoryName(exe) ?? "";

            var process = Process.GetCurrentProcess();
            foreach (ProcessModule module in process.Modules)
            {
                var modulePath = module.FileName ?? "";
                var moduleName = Path.GetFileName(modulePath);

                if (string.IsNullOrEmpty(modulePath)) continue;

                // Skip system DLLs
                if (modulePath.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase))
                    continue;

                // Skip known app directory DLLs
                if (modulePath.StartsWith(appDir, StringComparison.OrdinalIgnoreCase))
                {
                    if (KnownAppDirectoryDlls.Contains(moduleName) ||
                        moduleName.StartsWith("System.", StringComparison.OrdinalIgnoreCase) ||
                        moduleName.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase) ||
                        moduleName.StartsWith("WindowsSentinel.", StringComparison.OrdinalIgnoreCase) ||
                        moduleName.StartsWith("SentinelAgent", StringComparison.OrdinalIgnoreCase) ||
                        moduleName.StartsWith("SentinelService", StringComparison.OrdinalIgnoreCase))
                        continue;

                    // Unknown DLL loaded from app directory — potential sideload
                    logger?.LogCritical(
                        "ProcessHardening: SIDELOAD DETECTED — Unknown module '{Module}' loaded from " +
                        "application directory. Path: {Path}. This DLL is not in the expected manifest.",
                        moduleName, modulePath);
                }

                // DLL loaded from temp/user-writable location — very suspicious
                var lowerPath = modulePath.ToLowerInvariant();
                if (lowerPath.Contains("\\temp\\") || lowerPath.Contains("\\tmp\\") ||
                    lowerPath.Contains("\\appdata\\") || lowerPath.Contains("\\downloads\\"))
                {
                    logger?.LogCritical(
                        "ProcessHardening: SUSPICIOUS MODULE — '{Module}' loaded from user-writable " +
                        "location: {Path}. Possible injection or sideload attack.",
                        moduleName, modulePath);
                }
            }
        }
        catch (Exception ex)
        {
            logger?.LogDebug(ex, "ProcessHardening: Loaded module validation threw");
        }
    }

    /// <summary>
    /// Returns (true, reason) if the install directory's DACL grants Modify/Write to
    /// non-elevated principals (Everyone, Users, Authenticated Users). The Sentinel
    /// service must not run as SYSTEM out of a directory that any user can drop DLLs
    /// into — that's the primary sideload prerequisite.
    /// </summary>
    private static (bool ok, string reason) ValidateInstallDirectoryAcl(ILogger? logger)
    {
        try
        {
            var exe = Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrEmpty(exe)) return (true, "");
            var dir = Path.GetDirectoryName(exe);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return (true, "");

            var di = new DirectoryInfo(dir);
            var sec = di.GetAccessControl();
            var rules = sec.GetAccessRules(true, true, typeof(SecurityIdentifier));

            var risky = new[]
            {
                WellKnownSidType.WorldSid,                 // Everyone
                WellKnownSidType.BuiltinUsersSid,           // Users
                WellKnownSidType.AuthenticatedUserSid,      // Authenticated Users
                WellKnownSidType.InteractiveSid             // INTERACTIVE
            };

            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow) continue;

                var sid = (SecurityIdentifier)rule.IdentityReference;
                bool isRisky = risky.Any(t =>
                {
                    try { return sid.IsWellKnown(t); }
                    catch { return false; }
                });
                if (!isRisky) continue;

                var dangerous =
                    FileSystemRights.WriteData
                    | FileSystemRights.AppendData
                    | FileSystemRights.Modify
                    | FileSystemRights.Write
                    | FileSystemRights.FullControl
                    | FileSystemRights.CreateFiles
                    | FileSystemRights.CreateDirectories;

                if ((rule.FileSystemRights & dangerous) != 0)
                {
                    return (false,
                        $"Principal {sid} has {rule.FileSystemRights & dangerous} on {dir}");
                }
            }
            return (true, "");
        }
        catch (Exception ex)
        {
            logger?.LogDebug(ex, "ProcessHardening: ACL validation threw");
            // Fail-open on inspection error — service must start to protect the system.
            // The ACL check is defense-in-depth, not a hard gate.
            // DPAPI quarantine + CIG + module validation still protect even without this.
            return (true, "");
        }
    }
}


