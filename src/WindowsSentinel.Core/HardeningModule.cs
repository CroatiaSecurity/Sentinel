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

            try
            {
                using var proc = Process.GetProcessById(processId);
                proc.Kill(entireProcessTree: true);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to kill process tree for PID {processId}: {ex.Message}");
            }
        }

        public static void SecureInstallationDirectory()
        {
            try
            {
                var appDir = AppContext.BaseDirectory;
                if (appDir.Contains(@"\Program Files\", StringComparison.OrdinalIgnoreCase))
                {
                    var dInfo = new DirectoryInfo(appDir);
                    var dSecurity = dInfo.GetAccessControl();
                    
                    // Disable inheritance and copy existing rules
                    dSecurity.SetAccessRuleProtection(true, false);

                    // Allow Full Control to SYSTEM
                    dSecurity.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                        new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null),
                        System.Security.AccessControl.FileSystemRights.FullControl,
                        System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                        System.Security.AccessControl.PropagationFlags.None,
                        System.Security.AccessControl.AccessControlType.Allow));

                    // Allow Full Control to Administrators
                    dSecurity.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                        new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null),
                        System.Security.AccessControl.FileSystemRights.FullControl,
                        System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                        System.Security.AccessControl.PropagationFlags.None,
                        System.Security.AccessControl.AccessControlType.Allow));

                    // Allow Read & Execute to Users (required so Agent can launch under user context)
                    dSecurity.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                        new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null),
                        System.Security.AccessControl.FileSystemRights.ReadAndExecute,
                        System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                        System.Security.AccessControl.PropagationFlags.None,
                        System.Security.AccessControl.AccessControlType.Allow));

                    dInfo.SetAccessControl(dSecurity);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to secure installation directory natively: {ex.Message}");
            }
        }
    }
}
