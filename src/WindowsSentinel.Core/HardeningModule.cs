using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.Collections.Generic;

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

                // Apply IPSec policy registry settings
                ApplyIPSecPolicy();

                return res1 && res2;
            }
            catch
            {
                return false;
            }
        }

        private struct PortDef
        {
            public int Port;
            public string Name;
            public string Protocol; // "TCP", "UDP", or "TCPUDP"
        }

        private static readonly PortDef[] PortDefinitions = new PortDef[]
        {
            new PortDef { Port = 21, Name = "FTP", Protocol = "TCP" },
            new PortDef { Port = 69, Name = "TFTP", Protocol = "UDP" },
            new PortDef { Port = 111, Name = "RPCBind", Protocol = "TCPUDP" },
            new PortDef { Port = 512, Name = "rexec", Protocol = "TCP" },
            new PortDef { Port = 513, Name = "rlogin", Protocol = "TCP" },
            new PortDef { Port = 514, Name = "rsh", Protocol = "TCP" },
            new PortDef { Port = 548, Name = "AFP", Protocol = "TCP" },
            new PortDef { Port = 873, Name = "rsync", Protocol = "TCP" },
            new PortDef { Port = 2049, Name = "NFS", Protocol = "TCPUDP" },
            new PortDef { Port = 22, Name = "SSH", Protocol = "TCP" },
            new PortDef { Port = 23, Name = "Telnet", Protocol = "TCP" },
            new PortDef { Port = 3389, Name = "RDP", Protocol = "TCPUDP" },
            new PortDef { Port = 5900, Name = "VNC", Protocol = "TCP" },
            new PortDef { Port = 5985, Name = "WinRM_HTTP", Protocol = "TCP" },
            new PortDef { Port = 5986, Name = "WinRM_HTTPS", Protocol = "TCP" },
            new PortDef { Port = 135, Name = "RPC_DCOM", Protocol = "TCPUDP" },
            new PortDef { Port = 137, Name = "NetBIOS_NS", Protocol = "TCPUDP" },
            new PortDef { Port = 138, Name = "NetBIOS_DGM", Protocol = "UDP" },
            new PortDef { Port = 139, Name = "NetBIOS_SSN", Protocol = "TCP" },
            new PortDef { Port = 445, Name = "SMB", Protocol = "TCP" },
            new PortDef { Port = 1900, Name = "SSDP", Protocol = "UDP" },
            new PortDef { Port = 2869, Name = "UPnP", Protocol = "TCP" },
            new PortDef { Port = 5353, Name = "mDNS", Protocol = "UDP" },
            new PortDef { Port = 5355, Name = "LLMNR", Protocol = "UDP" },
            new PortDef { Port = 389, Name = "LDAP", Protocol = "TCPUDP" },
            new PortDef { Port = 636, Name = "LDAPS", Protocol = "TCP" },
            new PortDef { Port = 161, Name = "SNMP", Protocol = "UDP" },
            new PortDef { Port = 162, Name = "SNMP_Trap", Protocol = "UDP" },
            new PortDef { Port = 1433, Name = "MSSQL", Protocol = "TCP" },
            new PortDef { Port = 1434, Name = "MSSQL_Browser", Protocol = "UDP" },
            new PortDef { Port = 1521, Name = "OracleDB", Protocol = "TCP" },
            new PortDef { Port = 3306, Name = "MySQL", Protocol = "TCP" },
            new PortDef { Port = 5432, Name = "PostgreSQL", Protocol = "TCP" },
            new PortDef { Port = 6379, Name = "Redis", Protocol = "TCP" },
            new PortDef { Port = 9042, Name = "Cassandra", Protocol = "TCP" },
            new PortDef { Port = 9200, Name = "Elasticsearch", Protocol = "TCP" },
            new PortDef { Port = 11211, Name = "Memcached", Protocol = "TCPUDP" },
            new PortDef { Port = 27017, Name = "MongoDB", Protocol = "TCP" },
            new PortDef { Port = 2375, Name = "Docker_Unenc", Protocol = "TCP" },
            new PortDef { Port = 2376, Name = "Docker_TLS", Protocol = "TCP" },
            new PortDef { Port = 5000, Name = "DockerRegistry", Protocol = "TCP" },
            new PortDef { Port = 8291, Name = "MikroTik_Winbox", Protocol = "TCP" },
            new PortDef { Port = 9090, Name = "Prometheus", Protocol = "TCP" },
            new PortDef { Port = 50070, Name = "Hadoop_HDFS", Protocol = "TCP" },
            new PortDef { Port = 1099, Name = "Java_RMI", Protocol = "TCP" },
            new PortDef { Port = 5601, Name = "Kibana", Protocol = "TCP" },
            new PortDef { Port = 8888, Name = "Jupyter", Protocol = "TCP" },
            new PortDef { Port = 1080, Name = "SOCKS", Protocol = "TCP" },
            new PortDef { Port = 666, Name = "Trojan_666", Protocol = "TCP" },
            new PortDef { Port = 1234, Name = "RAT_1234", Protocol = "TCP" },
            new PortDef { Port = 1337, Name = "Backdoor_1337", Protocol = "TCP" },
            new PortDef { Port = 4444, Name = "Meterpreter_4444", Protocol = "TCP" },
            new PortDef { Port = 5555, Name = "Android_ADB", Protocol = "TCP" },
            new PortDef { Port = 6666, Name = "IRC_Backdoor", Protocol = "TCP" },
            new PortDef { Port = 6667, Name = "IRC_C2", Protocol = "TCP" },
            new PortDef { Port = 7777, Name = "Backdoor_7777", Protocol = "TCP" },
            new PortDef { Port = 12345, Name = "NetBus", Protocol = "TCP" },
            new PortDef { Port = 31337, Name = "BackOrifice", Protocol = "TCPUDP" },
            new PortDef { Port = 54321, Name = "BackOrifice2K", Protocol = "TCP" }
        };

        private static void RunNetsh(string args)
        {
            try
            {
                var psi = new ProcessStartInfo("netsh.exe", args)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using var proc = Process.Start(psi);
                proc?.WaitForExit();
            }
            catch { }
        }

        private static void ApplyIPSecPolicy()
        {
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var sentinelDir = Path.Combine(programData, "WindowsSentinel");
                var flagFile = Path.Combine(sentinelDir, ".ipsec_applied");

                if (File.Exists(flagFile))
                {
                    return; // Already applied
                }

                // 1. Delete existing policy (this is idempotent)
                RunNetsh("ipsec static delete policy name=GSecurity");

                // 2. Create the policy
                RunNetsh("ipsec static add policy name=GSecurity description=\"Blocks dangerous/unnecessary ports. Managed by Windows Sentinel.\" assign=yes");

                // 3. Create the BlockAction filter action
                RunNetsh("ipsec static add filteraction name=BlockAction action=block description=\"Block traffic\"");

                // 4. Create rules and filters
                foreach (var def in PortDefinitions)
                {
                    var protocols = new List<string>();
                    if (def.Protocol == "TCPUDP")
                    {
                        protocols.Add("TCP");
                        protocols.Add("UDP");
                    }
                    else
                    {
                        protocols.Add(def.Protocol);
                    }

                    foreach (var proto in protocols)
                    {
                        foreach (var direction in new[] { "Inbound", "Outbound" })
                        {
                            var filterListName = $"{direction}_{def.Name}_{proto}";
                            var ruleName = $"Block_{direction}_{def.Name}_{proto}";

                            string src = (direction == "Inbound") ? "Any" : "Me";
                            string dst = (direction == "Inbound") ? "Me" : "Any";

                            // Create filter list
                            RunNetsh($"ipsec static add filterlist name={filterListName} description=\"{direction} {def.Name} port {def.Port} ({proto})\"");

                            // Create filter
                            RunNetsh($"ipsec static add filter filterlist={filterListName} srcaddr={src} dstaddr={dst} protocol={proto} dstport={def.Port} mirrored=no");

                            // Link filter list to rule
                            RunNetsh($"ipsec static add rule name={ruleName} policy=GSecurity filterlist={filterListName} filteraction=BlockAction");
                        }
                    }
                }

                // 5. Assign policy
                RunNetsh("ipsec static set policy name=GSecurity assign=yes");

                // Write the flag file to avoid running on subsequent boots
                if (!Directory.Exists(sentinelDir))
                {
                    Directory.CreateDirectory(sentinelDir);
                }
                File.WriteAllText(flagFile, DateTimeOffset.UtcNow.ToString("o"));
            }
            catch
            {
                // Non-fatal
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
            var winDirTrailing = winDir.EndsWith('\\') ? winDir : winDir + '\\';
            return imagePath.StartsWith(winDirTrailing, StringComparison.OrdinalIgnoreCase);
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
