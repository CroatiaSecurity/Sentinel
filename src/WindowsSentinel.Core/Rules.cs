using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace WindowsSentinel.Core
{
    public class LsassAccessRule : IDetectionRule
    {
        public string Name => "LsassAccessRule";

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var cmd = pt.CommandLine;
                if (cmd.Contains("lsass", StringComparison.OrdinalIgnoreCase) && 
                    (cmd.Contains("dumptool", StringComparison.OrdinalIgnoreCase) || 
                     cmd.Contains("minidump", StringComparison.OrdinalIgnoreCase) || 
                     cmd.Contains("procdump", StringComparison.OrdinalIgnoreCase)))
                {
                    return new DetectionEvent
                    {
                        RuleName = Name,
                        ProcessName = pt.ProcessName,
                        ProcessId = pt.ProcessId,
                        Confidence = 0.90,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        Evidence = $"LSASS dumping command pattern: {cmd}",
                        Reasoning = "Process invoked utility targeting the Local Security Authority Subsystem Service (LSASS) memory space."
                    };
                }
            }
            return null;
        }
    }

    public class RansomwareDetectionRule : IDetectionRule
    {
        public string Name => "RansomwareDetectionRule";

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var cmd = pt.CommandLine;
                if (cmd.Contains("vssadmin", StringComparison.OrdinalIgnoreCase) && 
                    cmd.Contains("delete", StringComparison.OrdinalIgnoreCase) && 
                    cmd.Contains("shadows", StringComparison.OrdinalIgnoreCase))
                {
                    return new DetectionEvent
                    {
                        RuleName = Name,
                        ProcessName = pt.ProcessName,
                        ProcessId = pt.ProcessId,
                        Confidence = 0.98,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        Evidence = $"Volume shadow copy deletion command: {cmd}",
                        Reasoning = "Process attempted to delete volume shadow copies, which is a classic ransomware technique to prevent file recovery."
                    };
                }
            }

            if (context.TriggeringEvent is FileActivityTelemetry ft)
            {
                if (ft.OperationType == "RENAME" && ft.TargetPath != null)
                {
                    var ext = Path.GetExtension(ft.TargetPath).ToLowerInvariant();
                    if (ext == ".locked" || ext == ".enc" || ext == ".crypto")
                    {
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = ft.ProcessName,
                            ProcessId = ft.ProcessId,
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"File renamed to suspected ransomware extension: {ft.TargetPath}",
                            Reasoning = "Process renamed a file to an extension associated with cryptographic locker ransomware."
                        };
                    }
                }
            }

            return null;
        }
    }

    public class ReverseShellRule : IDetectionRule
    {
        public string Name => "ReverseShellRule";

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var cmd = pt.CommandLine;
                if (pt.ProcessName.Contains("powershell", StringComparison.OrdinalIgnoreCase) && 
                    (cmd.Contains("-enc", StringComparison.OrdinalIgnoreCase) || 
                     cmd.Contains("-encodedcommand", StringComparison.OrdinalIgnoreCase)))
                {
                    return new DetectionEvent
                    {
                        RuleName = Name,
                        ProcessName = pt.ProcessName,
                        ProcessId = pt.ProcessId,
                        Confidence = 0.85,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        Evidence = $"Encoded PowerShell execution command: {cmd}",
                        Reasoning = "Process launched an obfuscated PowerShell session, commonly used to execute downloader cradles or C2 shell callbacks."
                    };
                }
            }
            return null;
        }
    }

    public class ThreatIntelInjectionRule : IDetectionRule
    {
        public string Name => "ThreatIntelInjectionRule";

        // Suspicious API patterns from EtwThreatIntelMonitor kernel callbacks
        private static readonly string[] InjectionAPIs = new[]
        {
            "NtAllocateVirtualMemory", "VirtualAllocEx", "NtWriteVirtualMemory",
            "WriteProcessMemory", "NtMapViewOfSection", "MapViewOfSection",
            "QueueUserAPC", "NtQueueApcThread", "SetThreadContext",
            "NtSetContextThread", "RtlCreateUserThread", "CreateRemoteThread"
        };

        // Browsers legitimately use cross-process memory APIs for their sandbox model
        // (broker process allocates memory in renderer/tab processes). Skip to avoid FP kills.
        private static readonly HashSet<string> KnownBrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "iexplore",
            "msedgewebview2", "electron"
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ThreatIntelTelemetry tit)
            {
                // Skip browsers — they legitimately use injection APIs for sandboxing
                if (KnownBrowserProcesses.Contains(tit.ProcessName))
                    return null;

                foreach (var api in InjectionAPIs)
                {
                    if (tit.ApiName.Contains(api, StringComparison.OrdinalIgnoreCase))
                    {
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = tit.ProcessName,
                            ProcessId = tit.ProcessId,
                            Confidence = 0.90,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.QuarantineAndKill,
                            Evidence = $"Injection API invoked: {tit.ApiName} by {tit.ProcessName} (PID {tit.ProcessId}) targeting process PID {tit.TargetProcessId}",
                            Reasoning = "Process invoked a kernel-observed memory injection API targeting another process, indicating code injection (T1055).",
                            Metadata = new Dictionary<string, string>
                            {
                                { "TargetProcessId", tit.TargetProcessId.ToString() },
                                { "ApiName", tit.ApiName }
                            }
                        };
                    }
                }
            }
            return null;
        }
    }

    public class PrivilegeEscalationRule : IDetectionRule
    {
        public string Name => "PrivilegeEscalationRule";

        private static readonly string[] UacBypassPatterns = new[]
        {
            "fodhelper.exe", "computerdefaults.exe", "sdclt.exe",
            "eventvwr.exe", "slui.exe", "cmstp.exe",
            // Token manipulation
            "tokenvator", "incognito", "getsystem",
            // Named pipe impersonation
            "\\pipe\\", "ImpersonateNamedPipeClient",
            // DLL hijack indicators
            "\\syswow64\\version.dll", "\\temp\\version.dll", "\\temp\\winmm.dll"
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var cmd = pt.CommandLine.ToLowerInvariant();
                var image = pt.ImagePath.ToLowerInvariant();

                foreach (var pattern in UacBypassPatterns)
                {
                    if (cmd.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
                        image.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        // Skip legitimate uses — these only trigger when spawned by non-explorer parents
                        if (pattern.EndsWith(".exe") && pt.ParentProcessName?.Equals("explorer", StringComparison.OrdinalIgnoreCase) == true)
                            continue;

                        // Skip COM auto-elevation: when auto-elevate binaries are launched with
                        // "-Embedding" by the COM runtime (svchost/DcomLaunch), it's legitimate.
                        // This prevents false positives on FodHelper.exe, eventvwr.exe, etc.
                        if (pattern.EndsWith(".exe") && cmd.Contains("-embedding"))
                            continue;

                        // Skip false positives on legitimate named pipes used for IPC by development/IDE tools or other applications
                        if (pattern.Equals("\\pipe\\", StringComparison.OrdinalIgnoreCase))
                        {
                            var procName = pt.ProcessName.ToLowerInvariant();
                            bool isShell = procName == "cmd" || procName == "cmd.exe" ||
                                           procName == "powershell" || procName == "powershell.exe" ||
                                           procName == "pwsh" || procName == "pwsh.exe";
                            if (!isShell)
                                continue;

                            // Exclude common IPC parameters to prevent false positives on shell IPC
                            if (cmd.Contains("parent_pipe") || cmd.Contains("parent-pipe") || cmd.Contains("pipe-name") || cmd.Contains("chrome-signaling"))
                                continue;
                        }

                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            Confidence = 0.85,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"Privilege escalation pattern detected: '{pattern}' in {pt.ProcessName} (PID {pt.ProcessId}) cmd: {pt.CommandLine}",
                            Reasoning = "Process matches a known UAC bypass vector, token manipulation tool, or DLL hijacking pattern indicating privilege escalation."
                        };
                    }
                }
            }
            return null;
        }
    }

    public class AttackToolsRule : IDetectionRule
    {
        public string Name => "AttackToolsRule";

        private static readonly (string Pattern, string Category)[] ToolSignatures = new[]
        {
            // C2 frameworks
            ("cobalt", "CobaltStrike"), ("cobeacon", "CobaltStrike"), ("beacon.dll", "CobaltStrike"),
            ("meterpreter", "Metasploit"), ("msfvenom", "Metasploit"), ("msfconsole", "Metasploit"),
            ("sliver", "Sliver"), ("havoc", "Havoc"),

            // Credential tools
            ("mimikatz", "Mimikatz"), ("sekurlsa", "Mimikatz"), ("kerberos::list", "Mimikatz"),
            ("lazagne", "LaZagne"), ("pypykatz", "Pypykatz"),
            ("rubeus", "Rubeus"), ("asreproast", "Rubeus"), ("kerberoast", "Rubeus"),

            // AD attack tools
            ("bloodhound", "BloodHound"), ("sharphound", "BloodHound"),
            ("crackmapexec", "CrackMapExec"), ("impacket", "Impacket"),
            ("psexec", "PsExec"), ("wmiexec", "WMIExec"),

            // LOLBin abuse patterns
            ("certutil -urlcache", "LOLBin"), ("certutil -decode", "LOLBin"),
            ("bitsadmin /transfer", "LOLBin"), ("mshta vbscript", "LOLBin"),
            ("regsvr32 /s /n /u /i:", "LOLBin"), ("rundll32 javascript:", "LOLBin"),
            ("wmic process call create", "LOLBin"),
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var cmd = pt.CommandLine;
                var image = pt.ImagePath;

                foreach (var (pattern, category) in ToolSignatures)
                {
                    if (cmd.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
                        image.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"Attack tool detected: {category} (pattern: '{pattern}') in {pt.ProcessName} (PID {pt.ProcessId})",
                            Reasoning = $"Process command line or image path matches a known offensive security tool ({category}). Kill authorized."
                        };
                    }
                }
            }
            return null;
        }
    }

    public class CampaignIocRule : IDetectionRule
    {
        public string Name => "CampaignIocRule";

        // Known malicious filename patterns from tracked campaigns
        private static readonly string[] MaliciousFilenames = new[]
        {
            "svchosts.exe", "svchost.exe.exe", "csrss.exe.exe",
            "lsass.exe.exe", "explorer.exe.exe",
            "windowsupdate.exe", "windowsdefender.exe",
            "chrome_update.exe", "firefox_update.exe",
            "system32.exe", "kernel32.exe",
        };

        // Known C2 domain substrings
        private static readonly string[] MaliciousDomainPatterns = new[]
        {
            "pastebin.com/raw", "hastebin.com/raw",
            "discord.com/api/webhooks", "telegram-bot",
            ".onion.", ".tor2web.",
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var filename = Path.GetFileName(pt.ImagePath).ToLowerInvariant();

                foreach (var mal in MaliciousFilenames)
                {
                    if (filename.Equals(mal, StringComparison.OrdinalIgnoreCase))
                    {
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            Confidence = 0.80,
                            Tier = DetectionTier.Tier2Indicator,
                            Evidence = $"Known malicious filename executed: {pt.ImagePath}",
                            Reasoning = $"Process filename '{filename}' matches a known IoC from tracked malware campaigns."
                        };
                    }
                }

                var cmd = pt.CommandLine;
                foreach (var domain in MaliciousDomainPatterns)
                {
                    if (cmd.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            Confidence = 0.85,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"Known malicious C2 domain in command line: {domain}",
                            Reasoning = $"Command line contains a known C2 exfiltration endpoint ({domain}), indicating active malware communication."
                        };
                    }
                }
            }
            return null;
        }
    }

    public class UnsignedBinaryRule : IDetectionRule
    {
        public string Name => "UnsignedBinaryRule";

        // Standard user-mode install paths that are NOT suspicious
        private static readonly string[] TrustedAppDataPaths = new[]
        {
            "\\appdata\\local\\programs\\",
            "\\appdata\\local\\microsoft\\",
            "\\appdata\\local\\google\\",
            "\\appdata\\local\\mozilla\\",
            "\\appdata\\local\\slack\\",
            "\\appdata\\local\\discord\\",
            "\\appdata\\local\\spotify\\",
            "\\appdata\\local\\steam\\",
            "\\appdata\\local\\brave software\\",
            "\\appdata\\local\\1password\\",
            "\\appdata\\local\\gitkraken\\",
            "\\appdata\\local\\postman\\",
        };

        private static readonly string[] TrustedTempInstallerPatterns = new[]
        {
            "devinusersetup-",
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                // Skip checking if it lacks path separator (as per v4.1.0 fix)
                if (!pt.ImagePath.Contains('\\')) return null;

                var path = pt.ImagePath.ToLowerInvariant();

                // Only flag truly suspicious locations (Temp, Downloads, raw AppData outside program installs)
                bool isSuspicious = path.Contains("\\temp\\") || path.Contains("\\downloads\\");
                if (isSuspicious && TrustedTempInstallerPatterns.Any(pattern => path.Contains(pattern)))
                    isSuspicious = false;

                if (!isSuspicious && path.Contains("\\appdata\\"))
                {
                    // AppData is suspicious UNLESS it's a known app install path
                    isSuspicious = true;
                    foreach (var trusted in TrustedAppDataPaths)
                    {
                        if (path.Contains(trusted))
                        {
                            isSuspicious = false;
                            break;
                        }
                    }
                }

                if (isSuspicious)
                {
                    return new DetectionEvent
                    {
                        RuleName = Name,
                        ProcessName = pt.ProcessName,
                        ProcessId = pt.ProcessId,
                        Confidence = 0.60,
                        Tier = DetectionTier.Tier2Indicator, // Tier 2 - Log only
                        Evidence = $"Binary executed from user-writeable path: {pt.ImagePath}",
                        Reasoning = "Execution of a binary from temporary or user-profile directory. Feeds the correlation engine."
                    };
                }
            }
            return null;
        }
    }

    public class VerdictGateRule : IDetectionRule
    {
        public string Name => "VerdictGateRule";

        private readonly FileVerdictAds _verdictAds;
        private readonly SafeProcessExemptionRegistry _exemptionRegistry;

        public VerdictGateRule(FileVerdictAds verdictAds, SafeProcessExemptionRegistry exemptionRegistry)
        {
            _verdictAds = verdictAds;
            _exemptionRegistry = exemptionRegistry;
        }

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var imagePath = pt.ImagePath;
                if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath))
                {
                    return null;
                }

                // Compute file hash
                string hash = string.Empty;
                try
                {
                    using var sha = System.Security.Cryptography.SHA256.Create();
                    using var fs = File.OpenRead(imagePath);
                    var hashBytes = sha.ComputeHash(fs);
                    hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
                }
                catch
                {
                    return null;
                }

                // Check Alternate Data Stream verdict
                var verdict = _verdictAds.GetVerdict(imagePath, hash);

                if (verdict == HashVerdict.Unsafe)
                {
                    return new DetectionEvent
                    {
                        RuleName = Name,
                        ProcessName = pt.ProcessName,
                        ProcessId = pt.ProcessId,
                        Confidence = 0.99,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        Evidence = $"Process '{pt.ProcessName}' (PID {pt.ProcessId}) has signed 'unsafe' ADS reputation consensus verdict.",
                        Reasoning = "Process image was marked as malicious/unsafe by reputation consensus check and signed locally. Execution prevented.",
                        Metadata = new Dictionary<string, string> { { "SHA256", hash }, { "Verdict", "Unsafe" } }
                    };
                }
                else if (verdict == HashVerdict.Safe)
                {
                    _exemptionRegistry.RegisterSafeProcess(pt.ProcessId);
                }
            }

            return null;
        }
    }
}
