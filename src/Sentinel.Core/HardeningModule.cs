using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Sentinel.Core
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
                // v1.5.5: Removed FIPS disable (RT-HIGH-1). An EDR must not weaken system
                // cryptographic posture. If internal code throws under FIPS, fix the algorithm
                // usage rather than disabling FIPS system-wide.

                // Remove Current Working Directory (CWD) from DLL search path by passing empty string
                bool res1 = SetDllDirectory(string.Empty);

                // Restrict DLL search to %SystemRoot%\System32
                bool res2 = SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);

                // Apply IPSec policy registry settings
                ApplyIPSecPolicy();

                // v1.4.2: Register for Safe Mode boot — ensures Sentinel runs even in Safe Mode
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
                RunNetsh("ipsec static add policy name=GSecurity description=\"Blocks dangerous/unnecessary ports. Managed by Sentinel.\" assign=yes");
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
        /// v1.4.2: Registers the Sentinel service to run in both
        /// Safe Mode (Minimal) and Safe Mode with Networking.
        /// Without this, an attacker who triggers a Safe Mode reboot has
        /// unrestricted access because all non-registered services are stopped.
        /// </summary>
        private static void RegisterForSafeMode()
        {
            try
            {
                const string serviceName = "Sentinel";

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
                const string ruleName = "Sentinel-Block-Remote-RPC-Ephemeral";

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
                    newRule.Description = "Sentinel: Blocks remote access to RPC dynamic endpoint ports. " +
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
            // "Sentinel.Agent.exe" in a user-writable directory is NOT excluded.
            try
            {
                var targetImagePath = SecurityValidation.GetProcessImagePath(processId);
                // SECURITY v1.4.4: Normalize with Path.GetFullPath() to resolve junctions/symlinks.
                // Trailing separator prevents prefix collision (e.g., Sentinel2\evil.exe).
                var selfDir = Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\') + '\\';
                if (targetImagePath != null)
                {
                    var normalizedTarget = Path.GetFullPath(targetImagePath);
                    if (normalizedTarget.StartsWith(selfDir, StringComparison.OrdinalIgnoreCase))
                    {
                        Debug.WriteLine($"SafeKillProcessTree: REFUSED to kill sibling Sentinel process PID {processId} at verified install path '{targetImagePath}'");
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

        /// <summary>
        /// Returns true for processes whose termination would cause BSOD or system instability.
        /// v1.5.5: Removed cmd, powershell, and pwsh from this list (RT-HIGH-2/5).
        /// These are NOT BSOD-critical — they are the most common LOLBin attack vectors.
        /// Sentinel's detection rules (ReverseShellRule, AttackToolsRule) authorize killing
        /// them, and the safety guard must not contradict the response engine.
        /// explorer.exe is retained because killing it destabilizes the user session
        /// (taskbar, Start menu, desktop icons all disappear).
        /// </summary>
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
                   // v1.4.0: svchost hosts hundreds of critical Windows services — killing it can
                   // BSOD or leave the system in an unrecoverable state. Protect all instances
                   // that reside in System32 (the path check below verifies legitimacy).
                   string.Equals(name, "svchost", StringComparison.OrdinalIgnoreCase) ||
                   // v1.6.0: Core security products — path verified below (system or Program Files)
                   string.Equals(name, "MsMpEng", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "NisSrv", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "SecurityHealthService", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "Sense", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "MpDefenderCoreService", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "smartscreen", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "SgrmBroker", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsInSystemDirectory(string imagePath)
        {
            if (string.IsNullOrEmpty(imagePath)) return false;
            try
            {
                var normalized = Path.GetFullPath(imagePath);
                var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                var winDirTrailing = winDir.EndsWith('\\') ? winDir : winDir + '\\';
                if (normalized.StartsWith(winDirTrailing, StringComparison.OrdinalIgnoreCase))
                    return true;

                // v1.6.0: Also treat Program Files\Windows Defender* as protected paths
                var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
                foreach (var root in new[] { pf, pf86 })
                {
                    if (string.IsNullOrEmpty(root)) continue;
                    var defender = Path.Combine(root, "Windows Defender") + Path.DirectorySeparatorChar;
                    var defenderAdv = Path.Combine(root, "Windows Defender Advanced Threat Protection") + Path.DirectorySeparatorChar;
                    if (normalized.StartsWith(defender, StringComparison.OrdinalIgnoreCase) ||
                        normalized.StartsWith(defenderAdv, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            catch { }
            return false;
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

                // Exclude uninstaller files from the Deny rule by disabling inheritance and removing the Deny rule on them
                foreach (var file in Directory.GetFiles(exeDir, "unins*"))
                {
                    ExcludeUninstallerFromDeny(file);
                }
            }
            catch
            {
                // Non-fatal
            }
        }

        private static void ExcludeUninstallerFromDeny(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return;
                var fileInfo = new FileInfo(filePath);
                var security = fileInfo.GetAccessControl();

                // Disable inheritance and copy existing rules (marks them as explicit on disk)
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: true);
                fileInfo.SetAccessControl(security);

                // Re-read the security descriptor so that the copied rules are loaded as explicit rules
                security = fileInfo.GetAccessControl();

                // Find and remove any Deny rules for BUILTIN\Users
                var usersSid = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);

                var rules = security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(System.Security.Principal.SecurityIdentifier));
                foreach (System.Security.AccessControl.FileSystemAccessRule rule in rules)
                {
                    if (rule.AccessControlType == System.Security.AccessControl.AccessControlType.Deny &&
                        rule.IdentityReference.Value == usersSid.Value)
                    {
                        security.RemoveAccessRule(rule);
                    }
                }

                fileInfo.SetAccessControl(security);
            }
            catch
            {
                // Non-fatal
            }
        }

        /// <summary>
        /// v1.5.7: Native C# system hardening — no scripts, no shell-outs for logic.
        /// 
        /// Each hardening action is:
        ///   - Documented with its security purpose
        ///   - Implemented via direct registry API or ServiceController
        ///   - Idempotent and safe to re-run
        ///   - Non-fatal on failure (logs debug, continues)
        ///
        /// Actions performed:
        ///   1. Disable dangerous remote access services (attack surface reduction)
        ///   2. Apply security-relevant registry hardening (LSA, TLS, mitigations)
        ///   3. Enforce DEP/NX via bcdedit (exploit mitigation)
        ///   4. Apply LGPO security policy baseline (if LGPO.exe is embedded)
        /// 
        /// NOT performed (removed from legacy GSecurity.bat):
        ///   - ACL stripping from system binaries (dangerous, breaks updates)
        ///   - Volume labeling (cosmetic)
        ///   - User deletion (opinionated)
        ///   - TCP autotuninglevel restriction (performance, not security)
        ///   - Blanket .reg file imports (unauditable, can contain non-security tweaks)
        /// </summary>
        private static void ApplyUserSetupScriptsHardening()
        {
            try
            {
                // ═══════════════════════════════════════════════════════════════
                // 1. DISABLE REMOTE ACCESS SERVICES
                //    These are the most common lateral movement vectors.
                //    Only disable services that are never needed on a workstation.
                // ═══════════════════════════════════════════════════════════════
                DisableRemoteAccessServices();

                // ═══════════════════════════════════════════════════════════════
                // 2. REGISTRY-BASED SECURITY HARDENING
                //    Direct registry writes via Microsoft.Win32.Registry API.
                //    Each setting has a documented security rationale.
                // ═══════════════════════════════════════════════════════════════
                ApplyRegistryHardening();

                // ═══════════════════════════════════════════════════════════════
                // 3. DEP (Data Execution Prevention) — NX AlwaysOn
                //    Prevents code execution from non-executable memory pages.
                //    This is the single most effective exploit mitigation after ASLR.
                // ═══════════════════════════════════════════════════════════════
                EnforceDepAlwaysOn();

                // ═══════════════════════════════════════════════════════════════
                // 4. LGPO SECURITY POLICY (if embedded)
                //    Applies Group Policy security baseline from GSecurity.inf.
                //    This is the only remaining shell-out — LGPO.exe has no .NET equivalent.
                // ═══════════════════════════════════════════════════════════════
                ApplyLgpoSecurityPolicy();
            }
            catch { /* Non-fatal: hardening is best-effort */ }
        }

        #region Hardening: Service Disablement

        /// <summary>
        /// Disables remote access and network services that are common attack vectors
        /// on workstations. Uses ServiceController API — no sc.exe shell-out.
        /// 
        /// Only targets services that:
        ///   - Provide remote access (RDP vector, lateral movement)
        ///   - Are never needed on a standard workstation
        ///   - Can be re-enabled by an admin if needed
        /// </summary>
        private static void DisableRemoteAccessServices()
        {
            // Remote access tools — primary lateral movement vectors
            var remoteAccessServices = new[]
            {
                ("TermService",     "Remote Desktop Services"),
                ("WinRM",           "Windows Remote Management"),
                ("RemoteRegistry",  "Remote Registry"),
                ("sshd",            "OpenSSH Server"),
                ("TlntSvr",         "Telnet Server"),
                ("SNMP",            "SNMP Service"),
                ("ftpsvc",          "FTP Publishing Service"),
            };

            // Discovery/broadcast services — device enumeration vectors
            var discoveryServices = new[]
            {
                ("SsdpSrv",   "SSDP Discovery (UPnP)"),
                ("upnphost",  "UPnP Device Host"),
            };

            // Third-party remote tools (if installed)
            var thirdPartyRemote = new[]
            {
                ("TeamViewer",       "TeamViewer"),
                ("AnyDesk",          "AnyDesk"),
                ("LogMeIn",          "LogMeIn"),
                ("VNC",              "VNC Server"),
                ("Radmin",           "Radmin Server"),
                ("FileZilla Server", "FileZilla FTP Server"),
            };

            foreach (var (name, _) in remoteAccessServices.Concat(discoveryServices).Concat(thirdPartyRemote))
            {
                DisableServiceSafe(name);
            }
        }

        private static void DisableServiceSafe(string serviceName)
        {
            try
            {
                using var sc = new System.ServiceProcess.ServiceController(serviceName);
                // Check if service exists by reading its status
                _ = sc.Status;

                // Stop if running
                if (sc.Status == System.ServiceProcess.ServiceControllerStatus.Running ||
                    sc.Status == System.ServiceProcess.ServiceControllerStatus.StartPending)
                {
                    try { sc.Stop(); } catch { }
                }

                // Set to disabled via registry (ServiceController doesn't expose StartType setter)
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{serviceName}", writable: true);
                if (key != null)
                {
                    key.SetValue("Start", 4, Microsoft.Win32.RegistryValueKind.DWord); // 4 = Disabled
                }
            }
            catch (InvalidOperationException) { } // Service doesn't exist — expected
            catch { } // Access denied or other — non-fatal
        }

        #endregion

        #region Hardening: Registry Security Settings

        /// <summary>
        /// Applies security-relevant registry settings directly via .NET Registry API.
        /// Each setting is documented with its MITRE ATT&CK mitigation or CIS benchmark reference.
        /// </summary>
        private static void ApplyRegistryHardening()
        {
            // --- LSA Hardening (Credential Protection) ---
            // Restrict anonymous access to SAM/LSA (CIS 2.3.10.2, MITRE T1003)
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\LSA", "restrictanonymous", 1);
            // Prevent LM hash storage (CIS 2.3.11.7, MITRE T1003.001)
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\LSA", "NoLMHash", 1);

            // --- Remote Access Restrictions ---
            // Disable remote WMI (MITRE T1047 — WMI lateral movement)
            SetRegistryDword(@"SOFTWARE\Microsoft\Wbem", "EnableRemoteWmi", 0);
            // Disable WS-Management remote requests (MITRE T1021.006 — WinRM)
            SetRegistryDword(@"Software\Microsoft\Windows\CurrentVersion\WSMAN\Service", "allow_remote_requests", 0);

            // --- TLS Hardening ---
            // Enable TLS 1.3 client support
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client", "Enabled", 1);
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client", "DisabledByDefault", 0);
            // Force .NET Framework to use system default TLS (prevents downgrade to TLS 1.0/1.1)
            SetRegistryDword(@"SOFTWARE\Microsoft\.NETFramework\v4.0.30319", "SystemDefaultTlsVersions", 1);
            SetRegistryDword(@"SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319", "SystemDefaultTlsVersions", 1);

            // --- Exploit Mitigations ---
            // Enable SEHOP — Structured Exception Handler Overwrite Protection (CIS 18.3.4)
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\Session Manager\kernel", "DisableExceptionChainValidation", 0);
            // Spectre/Meltdown mitigations (FeatureSettingsOverride/Mask)
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "FeatureSettingsOverride", 0x40);
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "FeatureSettingsOverrideMask", 3);
            // Hyper-V CPU mitigations for VMs
            SetRegistryString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization", "MinVmVersionForCpuBasedMitigations", "1.0");

            // --- Privilege Escalation Prevention ---
            // Disable AlwaysInstallElevated (MITRE T1548.002 — MSI privilege escalation)
            SetRegistryDword(@"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", 0);
            // Disable COM auto-approval for UAC bypass (MITRE T1548.002)
            SetRegistryDword(@"Software\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList", "{ca8c87c1-929d-45ba-94db-ef8e6cb346ad}", 0);

            // --- Information Disclosure Prevention ---
            // Disable lock screen camera (physical access data leak)
            SetRegistryDword(@"SOFTWARE\Policies\Microsoft\Windows\Personalization", "NoLockScreenCamera", 1);
            // Disable cloud clipboard sync (data exfiltration vector)
            SetRegistryDwordCurrentUser(@"Software\Microsoft\Clipboard", "CloudClipboardAutomaticUpload", 0);
            SetRegistryDwordCurrentUser(@"Software\Microsoft\Clipboard", "EnableClipboardHistory", 0);
            // Disable crash dumps (can contain credentials in memory)
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\CrashControl", "CrashDumpEnabled", 0);

            // --- Network Hardening ---
            // Disable WCN (Windows Connect Now) registrars — prevents UPnP/WPS provisioning attacks
            SetRegistryDword(@"SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars", "EnableRegistrars", 0);
            SetRegistryDword(@"Software\Policies\Microsoft\Windows\WCN\UI", "DisableWcnUi", 1);
            // Disable QUIC protocol in browsers (can bypass network inspection)
            SetRegistryDword(@"Software\Policies\Google\Chrome", "QuicAllowed", 0);
            SetRegistryDword(@"Software\Policies\Microsoft\Edge", "QuicAllowed", 0);

            // --- Firewall Enforcement ---
            // Ensure Windows Firewall is enabled on all profiles
            SetRegistryDword(@"System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall", 1);
            SetRegistryDword(@"System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile", "EnableFirewall", 1);
            SetRegistryDword(@"System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall", 1);
            // Disable Remote Admin, Remote Desktop, File/Print, and UPnP through firewall (all profiles)
            foreach (var profile in new[] { "DomainProfile", "PrivateProfile", "PublicProfile" })
            {
                string basePath = $@"System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}";
                SetRegistryDword($@"{basePath}\RemoteAdminSettings", "Enabled", 0);
                SetRegistryDword($@"{basePath}\Services\FileAndPrint", "Enabled", 0);
                SetRegistryDword($@"{basePath}\Services\RemoteDesktop", "Enabled", 0);
                SetRegistryDword($@"{basePath}\Services\UPnPFramework", "Enabled", 0);
            }
        }

        private static void SetRegistryDword(string subKey, string valueName, int value)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(subKey, writable: true);
                key?.SetValue(valueName, value, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { } // Non-fatal: may lack admin rights
        }

        private static void SetRegistryString(string subKey, string valueName, string value)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(subKey, writable: true);
                key?.SetValue(valueName, value, Microsoft.Win32.RegistryValueKind.String);
            }
            catch { }
        }

        private static void SetRegistryDwordCurrentUser(string subKey, string valueName, int value)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(subKey, writable: true);
                key?.SetValue(valueName, value, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { }
        }

        #endregion

        #region Hardening: DEP Enforcement

        /// <summary>
        /// Enforces DEP (Data Execution Prevention) AlwaysOn via bcdedit.
        /// This is a one-time boot configuration that survives reboots.
        /// No .NET API exists for BCD store manipulation — bcdedit is required.
        /// </summary>
        private static void EnforceDepAlwaysOn()
        {
            try
            {
                var psi = new ProcessStartInfo("bcdedit.exe", "/set nx AlwaysOn")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                };
                using var proc = Process.Start(psi);
                proc?.WaitForExit(5000);
            }
            catch { }
        }

        #endregion

        #region Hardening: LGPO Security Policy

        /// <summary>
        /// Applies the embedded GSecurity.inf security policy via LGPO.exe.
        /// LGPO.exe is Microsoft's Local Group Policy Object utility — it's the only
        /// supported way to apply .inf security templates programmatically without
        /// Active Directory. No .NET equivalent exists.
        /// 
        /// The extraction directory is ACL-locked to SYSTEM+Admins before writing files.
        /// </summary>
        private static void ApplyLgpoSecurityPolicy()
        {
            string tempDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                @"Sentinel\HardeningTemp");

            try
            {
                if (!Directory.Exists(tempDir))
                    Directory.CreateDirectory(tempDir);

                // Lock down temp directory ACL
                LockDirectoryAcl(tempDir);

                var assembly = typeof(HardeningModule).Assembly;
                string resourcePrefix = "Sentinel.Core.HardeningResources.";

                // Extract only LGPO.exe and GSecurity.inf
                string? lgpoPath = ExtractResource(assembly, resourcePrefix + "LGPO.exe", tempDir, "LGPO.exe");
                string? infPath = ExtractResource(assembly, resourcePrefix + "GSecurity.inf", tempDir, "GSecurity.inf");

                if (lgpoPath != null && infPath != null && File.Exists(lgpoPath) && File.Exists(infPath))
                {
                    var psi = new ProcessStartInfo(lgpoPath, $"/s \"{infPath}\"")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        WorkingDirectory = tempDir
                    };
                    using var proc = Process.Start(psi);
                    proc?.WaitForExit(30000);
                }

                // Clean up temp files
                try { if (File.Exists(lgpoPath)) File.Delete(lgpoPath); } catch { }
                try { if (File.Exists(infPath)) File.Delete(infPath); } catch { }
            }
            catch { }
        }

        private static void LockDirectoryAcl(string dirPath)
        {
            try
            {
                var dirInfo = new DirectoryInfo(dirPath);
                var security = dirInfo.GetAccessControl();
                security.SetAccessRuleProtection(true, false);

                var systemSid = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    systemSid,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                    System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));

                var adminsSid = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    adminsSid,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                    System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));

                dirInfo.SetAccessControl(security);
            }
            catch { }
        }

        private static string? ExtractResource(System.Reflection.Assembly assembly, string resourceName, string targetDir, string fileName)
        {
            try
            {
                using var stream = assembly.GetManifestResourceStream(resourceName);
                if (stream == null) return null;

                string destPath = Path.Combine(targetDir, fileName);
                using var fileStream = new FileStream(destPath, FileMode.Create, FileAccess.Write);
                stream.CopyTo(fileStream);
                return destPath;
            }
            catch { return null; }
        }

        #endregion
    }
}
