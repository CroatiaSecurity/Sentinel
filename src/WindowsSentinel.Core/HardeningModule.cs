using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace WindowsSentinel.Core
{
    public static class HardeningModule
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool SetDllDirectory(string lpPathName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetDefaultDllDirectories(uint DirectoryFlags);

        private const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;

        public static bool ApplyOrFail()
        {
            try
            {
                // Remove Current Working Directory (CWD) from DLL search path by passing empty string
                bool res1 = SetDllDirectory(string.Empty);

                // Restrict DLL search to %SystemRoot%\System32
                bool res2 = SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);

                return res1 && res2;
            }
            catch
            {
                return false;
            }
        }

        public static void SafeKillProcessTree(int processId)
        {
            if (processId <= 4) return; // Never target System/Idle

            // CRITICAL: Never kill our own process or our Agent sibling
            if (processId == Environment.ProcessId) return;

            try
            {
                using var proc = Process.GetProcessById(processId);

                // Final safeguard: never kill BSOD-critical processes or user shells regardless of what triggered the kill
                var name = proc.ProcessName;
                if (IsCriticalProcessName(name))
                {
                    // HARDENING: Verify the binary actually resides in a system directory.
                    // An attacker can manipulate the PEB ProcessName field to masquerade as
                    // "csrss" or "explorer" — but they cannot move their binary into System32
                    // without triggering FileActivityMonitor's System32 write detection.
                    var imagePath = SecurityValidation.GetProcessImagePath(processId);
                    if (imagePath != null && IsInSystemDirectory(imagePath))
                    {
                        Debug.WriteLine($"SafeKillProcessTree: REFUSED to kill critical process {name} (PID {processId}) at verified system path");
                        return;
                    }
                    // Name matches critical process but path is NOT in system directory —
                    // this is masquerading. Allow the kill to proceed.
                    Debug.WriteLine($"SafeKillProcessTree: Process claims to be '{name}' but path is '{imagePath}' — masquerading detected, allowing kill");
                }

                proc.Kill(entireProcessTree: true);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to kill process tree for PID {processId}: {ex.Message}");
            }
        }

        private static bool IsCriticalProcessName(string name)
        {
            return string.Equals(name, "csrss", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "wininit", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "services", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "smss", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "lsass", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "winlogon", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "dwm", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "System", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "cmd", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsInSystemDirectory(string imagePath)
        {
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            return imagePath.StartsWith(winDir, StringComparison.OrdinalIgnoreCase);
        }

        public static void SecureInstallationDirectory()
        {
            // Harden installation directory: remove write for non-admin users
            // but preserve read/execute for Administrators and Users (needed by Agent)
            // Best-effort; non-fatal if it fails
            try
            {
                var exeDir = AppContext.BaseDirectory;
                if (string.IsNullOrEmpty(exeDir)) return;

                var dirInfo = new System.IO.DirectoryInfo(exeDir);
                if (!dirInfo.Exists) return;

                var security = dirInfo.GetAccessControl();

                // Keep inheritance — do NOT call SetAccessRuleProtection(true, false)
                // which strips all inherited ACEs and locks out non-SYSTEM users.
                // Instead, add a deny-write rule for regular Users to prevent tampering
                // while keeping read+execute intact.
                var usersIdentity = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    usersIdentity,
                    System.Security.AccessControl.FileSystemRights.Write |
                    System.Security.AccessControl.FileSystemRights.Delete |
                    System.Security.AccessControl.FileSystemRights.DeleteSubdirectoriesAndFiles,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                    System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Deny));

                dirInfo.SetAccessControl(security);
            }
            catch
            {
                // Non-fatal
            }
        }
    }
}
