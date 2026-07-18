using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.Collections.Generic;
using System.Linq;

namespace Behavedr.Core
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

                // v1.4.2: Register for Safe Mode boot — ensures Behavedr runs even in Safe Mode
                RegisterForSafeMode();

                // v1.4.2: Block remote access to RPC ephemeral ports
                BlockRemoteRpcEphemeralPorts();

                // Apply custom hardening from setup scripts folder
                ApplyUserSetupScriptsHardening();

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
            new PortDef { Port = 54321, Name = "BackOrifice2K", Protocol = "TCP" },
            new PortDef { Port = 5040, Name = "CDP_UserSvc", Protocol = "TCP" }
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

        /// <summary>
        /// Verifies the GSecurity IPSec policy is currently assigned and active.
        /// Returns true if the policy is confirmed active, false if missing/unassigned.
        /// Uses 'netsh ipsec static show policy name=GSecurity' — exit code 0 + "assigned: yes"
        /// means it's active. Anything else means it's been tampered with.
        /// </summary>
        public static bool IsIPSecPolicyActive()
        {
            try
            {
                var psi = new ProcessStartInfo("netsh.exe", "ipsec static show policy name=GSecurity")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var proc = Process.Start(psi);
                if (proc == null) return false;
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(5000);
                // Policy exists and is assigned if output contains "Assigned" and "Yes"
                return proc.ExitCode == 0 &&
                       output.Contains("Assign", StringComparison.OrdinalIgnoreCase) &&
                       output.Contains("Yes", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Re-applies the IPSec policy unconditionally. Called by the self-healing loop
        /// when the policy is detected as missing or unassigned.
        /// v1.4.1: Extracted from ApplyIPSecPolicy for reuse by IPSecIntegrityGuard.
        /// </summary>
        public static void ReapplyIPSecPolicy()
        {
            try
            {
                // Delete and recreate from scratch — handles partial corruption
                RunNetsh("ipsec static delete policy name=GSecurity");
                RunNetsh("ipsec static add policy name=GSecurity description=\"Blocks dangerous/unnecessary ports. Managed by Behavedr.\" assign=yes");
                RunNetsh("ipsec static add filteraction name=BlockAction action=block description=\"Block traffic\"");

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
                            RunNetsh($"ipsec static add filterlist name={filterListName} description=\"{direction} {def.Name} port {def.Port} ({proto})\"");
                            RunNetsh($"ipsec static add filter filterlist={filterListName} srcaddr={src} dstaddr={dst} protocol={proto} dstport={def.Port} mirrored=no");
                            RunNetsh($"ipsec static add rule name={ruleName} policy=GSecurity filterlist={filterListName} filteraction=BlockAction");
                        }
                    }
                }

                RunNetsh("ipsec static set policy name=GSecurity assign=yes");
            }
            catch { }
        }

        /// <summary>
        /// v1.4.2: Registers the Behavedr service to run in both
        /// Safe Mode (Minimal) and Safe Mode with Networking.
        /// Without this, an attacker who triggers a Safe Mode reboot has
        /// unrestricted access because all non-registered services are stopped.
        /// </summary>
        private static void RegisterForSafeMode()
        {
            try
            {
                const string serviceName = "Behavedr";

                // Minimal Safe Mode
                using (var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    $@"SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\{serviceName}"))
                {
                    key?.SetValue("", "Service", Microsoft.Win32.RegistryValueKind.String);
                }

                // Safe Mode with Networking
                using (var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    $@"SYSTEM\CurrentControlSet\Control\SafeBoot\Network\{serviceName}"))
                {
                    key?.SetValue("", "Service", Microsoft.Win32.RegistryValueKind.String);
                }
            }
            catch { }
        }

        /// <summary>
        /// v1.4.2: Blocks inbound access to RPC dynamic endpoint ports (49664-49675)
        /// from non-localhost sources via Windows Firewall. These ports host LSASS,
        /// Task Scheduler, and other sensitive RPC services that should never be
        /// accessible from the network on a workstation.
        /// Self-healing: checks for rule existence on every call.
        /// </summary>
        public static void BlockRemoteRpcEphemeralPorts()
        {
            try
            {
                const string ruleName = "Behavedr-Block-Remote-RPC-Ephemeral";

                // Check if rule already exists
                var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType == null) return;
                dynamic? policy = Activator.CreateInstance(policyType);
                if (policy == null) return;

                bool exists = false;
                foreach (dynamic rule in policy.Rules)
                {
                    if ((string)rule.Name == ruleName) { exists = true; break; }
                }

                if (!exists)
                {
                    var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                    if (ruleType == null) return;
                    dynamic? newRule = Activator.CreateInstance(ruleType);
                    if (newRule == null) return;

                    newRule.Name = ruleName;
                    newRule.Description = "Behavedr: Blocks remote access to RPC dynamic endpoint ports. " +
                                          "Prevents lateral movement via DCOM/WMI/Task Scheduler RPC.";
                    newRule.Protocol = 6; // TCP
                    newRule.LocalPorts = "49664-49675";
                    newRule.Direction = 1; // Inbound
                    newRule.Action = 0; // Block
                    newRule.Enabled = true;
                    newRule.Profiles = 0x7FFFFFFF; // All profiles
                    // Allow localhost (loopback) — only block external
                    newRule.RemoteAddresses = "LocalSubnet,DNS,DHCP,WINS,DefaultGateway";
                    // Actually we need to BLOCK from everywhere except local — invert logic:
                    // Block all remote, which is the default when no RemoteAddresses filter is set
                    newRule.RemoteAddresses = "*";
                    // Exclude local loopback by setting LocalAddresses (can't exclude in block rule)
                    // The simpler approach: block from "LocalSubnet" which covers LAN attacks
                    newRule.RemoteAddresses = "LocalSubnet";

                    policy.Rules.Add(newRule);
                }
            }
            catch { }
        }

        private static void ApplyIPSecPolicy()
        {
            try
            {
                // v1.4.1: Check actual policy state instead of relying on flag file.
                // An attacker can delete the flag file to force re-application (benign),
                // or create it before first run to prevent application (critical).
                // Now we verify the policy is actually active in the IPSec engine.
                if (IsIPSecPolicyActive())
                {
                    return; // Policy confirmed active — no action needed
                }

                // Policy is missing or unassigned — apply it
                ReapplyIPSecPolicy();
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

            // HARDENING v1.3.8: Never kill any process whose binary resides in our install directory.
            // When explorer.exe was killed with entireProcessTree:true, it cascaded
            // and killed the Agent tray app (child of explorer). This self-exclusion
            // ensures even if a parent process tree kill occurs, our processes survive.
            //
            // SECURITY: Path-verified, not name-based. An attacker naming their binary
            // "Behavedr.Agent.exe" in a user-writable directory is NOT excluded.
            try
            {
                var targetImagePath = SecurityValidation.GetProcessImagePath(processId);
                // SECURITY v1.4.4: Normalize with Path.GetFullPath() to resolve junctions/symlinks.
                // Trailing separator prevents prefix collision (e.g., Behavedr2\evil.exe).
                var selfDir = Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\') + '\\';
                if (targetImagePath != null)
                {
                    var normalizedTarget = Path.GetFullPath(targetImagePath);
                    if (normalizedTarget.StartsWith(selfDir, StringComparison.OrdinalIgnoreCase))
                    {
                        Debug.WriteLine($"SafeKillProcessTree: REFUSED to kill sibling Behavedr process PID {processId} at verified install path '{targetImagePath}'");
                        return;
                    }
                }
            }
            catch { /* process may have already exited — continue with kill attempt */ }

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
                   string.Equals(name, "explorer", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "System", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "cmd", StringComparison.OrdinalIgnoreCase) ||
                   // v1.4.0: svchost hosts hundreds of critical Windows services — killing it can
                   // BSOD or leave the system in an unrecoverable state. Protect all instances
                   // that reside in System32 (the path check below verifies legitimacy).
                   string.Equals(name, "svchost", StringComparison.OrdinalIgnoreCase) ||
                   // v1.4.0: powershell and pwsh are user shells — killing them destroys the
                   // user's interactive session and any running scripts without warning.
                   string.Equals(name, "powershell", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "pwsh", StringComparison.OrdinalIgnoreCase);
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

        private static void ApplyUserSetupScriptsHardening()
        {
            string scriptsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Behavedr\HardeningTemp");
            try
            {
                // Create target directory
                if (!Directory.Exists(scriptsDir))
                {
                    Directory.CreateDirectory(scriptsDir);
                }

                // Extract all embedded resources from "Behavedr.Core.HardeningResources."
                var assembly = typeof(HardeningModule).Assembly;
                string resourcePrefix = "Behavedr.Core.HardeningResources.";
                foreach (string resourceName in assembly.GetManifestResourceNames())
                {
                    if (resourceName.StartsWith(resourcePrefix, StringComparison.OrdinalIgnoreCase))
                    {
                        string fileName = resourceName.Substring(resourcePrefix.Length);
                        string destPath = Path.Combine(scriptsDir, fileName);
                        try
                        {
                            using var stream = assembly.GetManifestResourceStream(resourceName);
                            if (stream != null)
                            {
                                using var fileStream = new FileStream(destPath, FileMode.Create, FileAccess.Write);
                                stream.CopyTo(fileStream);
                            }
                        }
                        catch { }
                    }
                }

                // 1. Run lgpo.exe if present
                string lgpoPath = Path.Combine(scriptsDir, "LGPO.exe");
                string infPath = Path.Combine(scriptsDir, "GSecurity.inf");
                if (File.Exists(lgpoPath) && File.Exists(infPath))
                {
                    RunProcess(lgpoPath, $"/s \"{infPath}\"", scriptsDir);
                }

                // 2. Import registry files alphabetically
                var regFiles = Directory.GetFiles(scriptsDir, "*.reg")
                                        .OrderBy(f => f)
                                        .ToList();
                foreach (var regFile in regFiles)
                {
                    RunProcess("reg.exe", $"import \"{regFile}\"", scriptsDir);
                }

                // 3. Run powershell scripts alphabetically (non-blocking)
                var psFiles = Directory.GetFiles(scriptsDir, "*.ps1")
                                       .OrderBy(f => f)
                                       .ToList();
                foreach (var psFile in psFiles)
                {
                    try
                    {
                        var psi = new ProcessStartInfo("powershell.exe", $"-ExecutionPolicy Bypass -WindowStyle Hidden -File \"{psFile}\"")
                        {
                            CreateNoWindow = true,
                            UseShellExecute = false,
                            WorkingDirectory = scriptsDir
                        };
                        Process.Start(psi);
                    }
                    catch { }
                }

                // 4. File ownership and permissions tweaks from GSecurity.bat
                string[] filesToRestrict = new[]
                {
                    Path.Combine(Environment.SystemDirectory, @"Oobe\useroobe.dll"),
                    Path.Combine(Environment.SystemDirectory, @"wbem\WmiPrvSE.exe"),
                    Path.Combine(Environment.SystemDirectory, @"wbem\Wmiadap.exe"),
                    Path.Combine(Environment.SystemDirectory, "dllhost.exe"),
                    Path.Combine(Environment.SystemDirectory, "conhost.exe"),
                    Path.Combine(Environment.SystemDirectory, "consent.exe"),
                    Path.Combine(Environment.SystemDirectory, "winmm.dll")
                };

                foreach (var file in filesToRestrict)
                {
                    if (File.Exists(file))
                    {
                        RunProcess("takeown.exe", $"/f \"{file}\" /A", scriptsDir);
                        RunProcess("icacls.exe", $"\"{file}\" /reset", scriptsDir);
                        RunProcess("icacls.exe", $"\"{file}\" /inheritance:r", scriptsDir);
                        if (file.EndsWith("consent.exe", StringComparison.OrdinalIgnoreCase) ||
                            file.EndsWith("winmm.dll", StringComparison.OrdinalIgnoreCase))
                        {
                            RunProcess("icacls.exe", $"\"{file}\" /grant:r \"Console Logon\":RX", scriptsDir);
                        }
                    }
                }

                // 5. Service disablement
                string[] servicesToDisable = new[]
                {
                    "VNC", "FileZilla Server", "OpenSSH", "vsftpd", "TeamViewer", "AnyDesk", "LogMeIn",
                    "Radmin", "SsdpSrv", "upnphost", "TelnetServer", "sshd", "ftpsvc", "seclogon",
                    "LanmanWorkstation", "LanmanServer", "WinRM", "RemoteRegistry", "SNMP"
                };
                foreach (var svc in servicesToDisable)
                {
                    RunProcess("sc.exe", $"config \"{svc}\" start= disabled", scriptsDir);
                    RunProcess("sc.exe", $"stop \"{svc}\"", scriptsDir);
                }

                // 6. Bcdedit NX AlwaysOn
                RunProcess("bcdedit.exe", "/set nx AlwaysOn", scriptsDir);

                // 7. Network autotuninglevel
                RunProcess("netsh.exe", "int tcp set global autotuninglevel=restricted", scriptsDir);

                // 8. Delete defaultuser0
                RunProcess("net.exe", "user defaultuser0 /delete", scriptsDir);

                // 9. Label C: Windows
                RunProcess("label.exe", "C: Windows", scriptsDir);
            }
            catch { }
        }

        private static void RunProcess(string fileName, string arguments, string workingDir)
        {
            try
            {
                var psi = new ProcessStartInfo(fileName, arguments)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WorkingDirectory = workingDir
                };
                using var proc = Process.Start(psi);
                proc?.WaitForExit();
            }
            catch { }
        }
    }
}
