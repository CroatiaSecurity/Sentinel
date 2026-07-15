using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace WindowsSentinel.Core
{
    [RuleCategory(DetectionCategory.CredentialDump)]
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
                        SignalType = SignalType.LsassAccess,
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

    [RuleCategory(DetectionCategory.Ransomware)]
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
                        SignalType = SignalType.Ransomware,
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
                            SignalType = SignalType.Ransomware,
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

    [RuleCategory(DetectionCategory.ReverseShell)]
    public class ReverseShellRule : IDetectionRule
    {
        public string Name => "ReverseShellRule";

        private static readonly string[] EscalationIndicators = new[]
        {
            "-nop", "-w hidden", "-windowstyle hidden", "-sta", "-noni",
            "net.webclient", "downloadstring", "invoke-expression", "iex",
            "net.sockets", "tcpclient", "system.net"
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var cmd = pt.CommandLine;
                if (pt.ProcessName.Contains("powershell", StringComparison.OrdinalIgnoreCase) && 
                    (cmd.Contains("-enc", StringComparison.OrdinalIgnoreCase) || 
                     cmd.Contains("-encodedcommand", StringComparison.OrdinalIgnoreCase)))
                {
                    // Check for escalation indicators that suggest malicious use
                    bool hasEscalationIndicator = EscalationIndicators.Any(
                        indicator => cmd.Contains(indicator, StringComparison.OrdinalIgnoreCase));

                    if (hasEscalationIndicator)
                    {
                        // Combined with evasion flags or network indicators → Tier1 + Kill
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            SignalType = SignalType.ReverseShell,
                            Confidence = 0.85,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"Encoded PowerShell with evasion/network indicators: {cmd}",
                            Reasoning = "Process launched an obfuscated PowerShell session combined with evasion flags or network indicators, commonly used to execute downloader cradles or C2 shell callbacks."
                        };
                    }
                    else
                    {
                        // Encoded command alone → Tier2 (log only, no kill)
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            SignalType = SignalType.ReverseShell,
                            Confidence = 0.50,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            Evidence = $"Encoded PowerShell execution (no evasion indicators): {cmd}",
                            Reasoning = "Process launched PowerShell with an encoded command. Without additional evasion or network indicators this may be legitimate automation. Logged for correlation."
                        };
                    }
                }
            }
            return null;
        }
    }

    [RuleCategory(DetectionCategory.ProcessInjection)]
    public class ThreatIntelInjectionRule : IDetectionRule
    {
        public string Name => "ThreatIntelInjectionRule";

        // Suspicious API patterns from EtwThreatIntelMonitor kernel callbacks
        // Split at runtime to prevent AV heuristic matching on injection API name strings
        private static string S(string a, string b) => string.Concat(a, b);
        private static readonly string[] InjectionAPIs = new[]
        {
            S("NtAllocateVirtual","Memory"), S("Virtual","AllocEx"), S("NtWriteVirtual","Memory"),
            S("WriteProcess","Memory"), S("NtMapViewOf","Section"), S("MapViewOf","Section"),
            S("QueueUser","APC"), S("NtQueueApc","Thread"), S("SetThread","Context"),
            S("NtSetContext","Thread"), S("RtlCreateUser","Thread"), S("CreateRemote","Thread")
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
                            SignalType = SignalType.ProcessInjection,
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

    [RuleCategory(DetectionCategory.PrivilegeEscalation)]
    public class PrivilegeEscalationRule : IDetectionRule
    {
        public string Name => "PrivilegeEscalationRule";

        private static readonly string[] UacBypassPatterns = new[]
        {
            "fodhelper.exe", "computerdefaults.exe", "sdclt.exe",
            "eventvwr.exe", "slui.exe", "cmstp.exe",
            // Token manipulation
            "tokenvator", "incognito", "getsystem",
            // Privilege escalation exploits (GodPotato, JuicyPotato, PrintSpoofer, etc.)
            "potato", "printspoof",
            // Defense evasion: Clearing Windows Application, System, or Security event logs
            "wevtutil cl ", "wevtutil.exe cl ", "wevtutil clear-log",
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
                            SignalType = SignalType.SecurityEvasion,
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

    [RuleCategory(DetectionCategory.SecurityEvasion)]
    public class AttackToolsRule : IDetectionRule
    {
        public string Name => "AttackToolsRule";

        // Runtime string builder — prevents static string signatures in compiled IL
        // AV scanners match literal strings like "mimikatz" in the binary. Splitting
        // and joining at runtime makes the pattern invisible to static analysis.
        private static string S(string a, string b) => string.Concat(a, b);

        private static readonly (string Pattern, string Category)[] ToolSignatures = new[]
        {
            // C2 frameworks
            (S("cob","alt"), "C2"), (S("cobe","acon"), "C2"), (S("beac","on.dll"), "C2"),
            (S("meter","preter"), "C2"), (S("msf","venom"), "C2"), (S("msf","console"), "C2"),
            (S("sli","ver"), "C2"), (S("hav","oc"), "C2"),

            // Credential tools — patterns split to avoid static string signature matches
            (S("mimi","katz"), "CredTool"), (S("seku","rlsa"), "CredTool"), (S("kerber","os::list"), "CredTool"),
            (S("laz","agne"), "CredTool"), (S("pypy","katz"), "CredTool"),
            (S("rub","eus"), "CredTool"), (S("asrep","roast"), "CredTool"), (S("kerber","oast"), "CredTool"),

            // AD attack tools
            (S("blood","hound"), "ADTool"), (S("sharp","hound"), "ADTool"),
            (S("crackmap","exec"), "ADTool"), (S("impa","cket"), "ADTool"),
            (S("pse","xec"), "ADTool"), (S("wmie","xec"), "ADTool"),

            // === LOLBin abuse (behavioral: binary + suspicious arguments) ===
            // All patterns split via S() to prevent AV scanners from flagging source code
            // Download/execute
            (S("certutil"," -urlcache"), "LOLBin:certutil"), (S("certutil"," -decode"), "LOLBin:certutil"),
            (S("certutil"," -encode"), "LOLBin:certutil"), (S("certutil"," -verifyctl"), "LOLBin:certutil"),
            (S("bitsadmin"," /transfer"), "LOLBin:bitsadmin"), (S("bitsadmin"," /create"), "LOLBin:bitsadmin"),
            (S("msiexec /q"," /i http"), "LOLBin:msiexec"), (S("msiexec /q"," /i \\\\"), "LOLBin:msiexec"),
            // Script execution via proxy
            (S("mshta"," vbscript"), "LOLBin:mshta"), (S("mshta"," javascript"), "LOLBin:mshta"),
            (S("mshta"," http"), "LOLBin:mshta"), (S("mshta"," \\\\"), "LOLBin:mshta"),
            (S("regsvr32 /s"," /n /u /i:"), "LOLBin:regsvr32"), (S("regsvr32 /s"," /n /i:"), "LOLBin:regsvr32"),
            (S("regsvr32"," /i:http"), "LOLBin:regsvr32"),
            (S("rundll32"," javascript:"), "LOLBin:rundll32"), (S("rundll32"," vbscript:"), "LOLBin:rundll32"),
            (S("rundll32.exe"," shell32.dll,control_rundll"), "LOLBin:rundll32"),
            // WMI lateral movement
            (S("wmic process"," call create"), "LOLBin:wmic"), (S("wmic"," /node:"), "LOLBin:wmic"),
            // MSBuild inline task execution (T1127.001)
            (S("msbuild.exe"," /p:"), "LOLBin:msbuild"),
            // InstallUtil bypass (T1218.004)
            (S("installutil"," /logfile= /logtoconsole=false"), "LOLBin:installutil"),
            // Compiler abuse (drop & compile on target)
            (S("csc.exe"," /target:library /out:"), "LOLBin:csc"),
            // Forfiles proxy execution
            (S("forfiles"," /p c:\\windows"), "LOLBin:forfiles"),
            // SyncAppvPublishingServer (PowerShell execution proxy)
            (S("syncappv","publishingserver"), "LOLBin:syncappv"),
            // PresentationHost (XAML execution)
            (S("presentation","host.exe"), "LOLBin:presentationhost"),
            // CMSTP INF-based execution
            (S("cmstp.exe"," /s /ns"), "LOLBin:cmstp"), (S("cmstp.exe"," /ni"), "LOLBin:cmstp"),

            // === LOLScripts (suspicious interpreter usage) ===
            (S("powershell"," -enc"), "LOLScript:PowerShell"), (S("powershell"," -e "), "LOLScript:PowerShell"),
            (S("powershell -nop"," -w hidden"), "LOLScript:PowerShell"),
            (S("powershell -nop"," -exec bypass"), "LOLScript:PowerShell"),
            (S("powershell"," iex("), "LOLScript:PowerShell"), (S("powershell"," iex ("), "LOLScript:PowerShell"),
            (S("powershell -command"," \"iex"), "LOLScript:PowerShell"),
            (S("powershell"," downloadstring"), "LOLScript:PowerShell"),
            (S("pwsh"," -enc"), "LOLScript:PowerShell"), (S("pwsh"," -e "), "LOLScript:PowerShell"),
            (S("cscript //nologo"," //e:jscript"), "LOLScript:cscript"),
            (S("wscript //nologo"," //e:jscript"), "LOLScript:wscript"),
            (S("cscript //b"," //nologo"), "LOLScript:cscript"),

            // === LOLLibs (DLL abuse via rundll32 or direct load) ===
            (S("comsvcs.dll",",minidump"), "LOLLib:comsvcs"), (S("comsvcs.dll",",#24"), "LOLLib:comsvcs"),
            (S("comsvcs.dll",",minitump"), "LOLLib:comsvcs"),
            ("dbgcore.dll", "LOLLib:dbgcore"),
            (S("pcwutl.dll",",launchapplication"), "LOLLib:pcwutl"),
            (S("advpack.dll",",launchinfection"), "LOLLib:advpack"),
            (S("advpack.dll",",registerocx"), "LOLLib:advpack"),
            (S("zipfldr.dll",",routethepackage"), "LOLLib:zipfldr"),
            (S("url.dll",",filereprotocolhandler"), "LOLLib:url"),
            (S("url.dll",",openurl"), "LOLLib:url"),
            (S("ieadvpack.dll",",registerocx"), "LOLLib:ieadvpack"),
            (S("shdocvw.dll",",openurl"), "LOLLib:shdocvw"),
            (S("shell32.dll",",shellexec_rundll"), "LOLLib:shell32"),
            // === Chinese APT / Earth Lamia / StrikeShark Toolsets ===
            // Short names require exact filename or word-boundary matching to avoid
            // false positives from substring matches (e.g. "fscan" in "filesystem_scanner")
            ("fscan", "APTTool:fscan"),
            ("kscan", "APTTool:kscan"),
            ("stowaway", "APTTool:stowaway"),
            ("rakshasa", "APTTool:rakshasa"),
            ("supershell", "APTTool:supershell"),
            ("pillager", "APTTool:pillager"),
            ("searchall", "APTTool:searchall"),
            ("ntdsutil", "APTTool:ntdsutil"),
            ("ntds.dit", "APTTool:ntds.dit"),

            // === Exfiltration endpoints ===
            ("pastebin.com/raw", "Exfil:Pastebin"),
            ("discord.com/api/webhooks", "Exfil:Discord"),
            (".onion.", "Exfil:Tor"),
            ("tor2web", "Exfil:Tor"),
        };

        /// <summary>
        /// Checks if a pattern appears in the text at a word boundary (preceded/followed by
        /// non-alphanumeric characters or string start/end). Prevents substring false positives
        /// where e.g. "fscan" matches inside "filesystem_scanner.exe".
        /// </summary>
        private static bool HasWordBoundaryMatch(string text, string pattern)
        {
            int idx = -1;
            while ((idx = text.IndexOf(pattern, idx + 1, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                bool leftBound = idx == 0 || !char.IsLetterOrDigit(text[idx - 1]);
                int endIdx = idx + pattern.Length;
                bool rightBound = endIdx >= text.Length || !char.IsLetterOrDigit(text[endIdx]);
                if (leftBound && rightBound) return true;
            }
            return false;
        }

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var cmd = pt.CommandLine;
                var image = pt.ImagePath;

                // Custom check for symlink/junction abuse targeting system folders (BlueHammer, etc.)
                if ((cmd.Contains("mklink", StringComparison.OrdinalIgnoreCase) || 
                     cmd.Contains("junction", StringComparison.OrdinalIgnoreCase)) &&
                    (cmd.Contains(@"\system32\config", StringComparison.OrdinalIgnoreCase) ||
                     cmd.Contains(@"\windows defender", StringComparison.OrdinalIgnoreCase) ||
                     cmd.Contains(@"\config\system", StringComparison.OrdinalIgnoreCase) ||
                     cmd.Contains(@"\config\sam", StringComparison.OrdinalIgnoreCase) ||
                     cmd.Contains(@"\config\security", StringComparison.OrdinalIgnoreCase)))
                {
                    return new DetectionEvent
                    {
                        RuleName = Name,
                        ProcessName = pt.ProcessName,
                        ProcessId = pt.ProcessId,
                        SignalType = SignalType.SuspiciousProcess,
                        Confidence = 0.98,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        Evidence = $"Junction LPE attempt detected: '{cmd}'",
                        Reasoning = "Process attempted to create an NTFS directory junction or symlink targeting sensitive Windows configuration or Defender update directories. " +
                                    "This is a signature pattern of local privilege escalation exploits like BlueHammer."
                    };
                }

                foreach (var (pattern, category) in ToolSignatures)
                {
                    if (cmd.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
                        image.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        // For short APT tool names, require word-boundary or filename-exact match
                        // to avoid false positives from substring matches
                        if (category.StartsWith("APTTool:", StringComparison.OrdinalIgnoreCase))
                        {
                            var fileName = Path.GetFileNameWithoutExtension(pt.ImagePath).ToLowerInvariant();
                            bool isExactFilename = fileName.Equals(pattern, StringComparison.OrdinalIgnoreCase);
                            // Check for word boundary in command line: pattern preceded/followed by non-alphanumeric
                            bool hasWordBoundary = HasWordBoundaryMatch(cmd, pattern);
                            if (!isExactFilename && !hasWordBoundary)
                                continue; // Substring match without boundary — skip
                        }

                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            SignalType = category.Equals("C2", StringComparison.OrdinalIgnoreCase) ? SignalType.NetworkC2 : SignalType.SuspiciousProcess,
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

    [RuleCategory(DetectionCategory.CampaignIoC)]
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
                            SignalType = SignalType.SuspiciousProcess,
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
                            SignalType = SignalType.NetworkC2,
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

    [RuleCategory(DetectionCategory.UnsignedBinary)]
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
                        SignalType = SignalType.SuspiciousProcess,
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

    [RuleCategory(DetectionCategory.AntiTamper)]
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
                        SignalType = SignalType.SuspiciousProcess,
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

    [RuleCategory(DetectionCategory.ReverseShell)]
    public class ClickFixDetectionRule : IDetectionRule
    {
        public string Name => "ClickFixDetectionRule";

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var cmd = pt.CommandLine.ToLowerInvariant();
                var parent = pt.ParentProcessName?.ToLowerInvariant() ?? "";

                // Check if powershell/cmd is launched from explorer (Run dialog Win+R) or from a browser
                bool isExplorerOrBrowserParent = parent == "explorer" || parent == "explorer.exe" ||
                                                 parent == "chrome" || parent == "chrome.exe" ||
                                                 parent == "msedge" || parent == "msedge.exe" ||
                                                 parent == "firefox" || parent == "firefox.exe" ||
                                                 parent == "brave" || parent == "brave.exe";

                if (isExplorerOrBrowserParent)
                {
                    bool isSuspiciousShell = pt.ProcessName.Contains("powershell", StringComparison.OrdinalIgnoreCase) || 
                                             pt.ProcessName.Contains("cmd", StringComparison.OrdinalIgnoreCase) ||
                                             pt.ProcessName.Contains("mshta", StringComparison.OrdinalIgnoreCase);

                    if (isSuspiciousShell)
                    {
                        bool isClickFixPayload = cmd.Contains("frombase64string") || 
                                                 cmd.Contains("downloadstring") || 
                                                 cmd.Contains("iex ") || 
                                                 cmd.Contains("invoke-expression") ||
                                                 cmd.Contains("certutil -urlcache") ||
                                                 cmd.Contains("http") && pt.ProcessName.Contains("mshta", StringComparison.OrdinalIgnoreCase);

                        if (isClickFixPayload)
                        {
                            return new DetectionEvent
                            {
                                RuleName = Name,
                                ProcessName = pt.ProcessName,
                                ProcessId = pt.ProcessId,
                                SignalType = SignalType.ReverseShell,
                                Confidence = 0.95,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                Evidence = $"Click-Fix / Run-Dialog downloader execution detected: {pt.CommandLine}",
                                Reasoning = "Process spawned directly from explorer or a browser executed commands associated with social engineering paste-and-run payloads (ClickFix)."
                            };
                        }
                    }
                }
            }
            return null;
        }
    }

    [RuleCategory(DetectionCategory.CredentialDump)]
    public class ChromeRemoteDebuggingRule : IDetectionRule
    {
        public string Name => "ChromeRemoteDebuggingRule";

        private static readonly HashSet<string> BrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "brave", "vivaldi", "opera", "chromium"
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                // Detect browser launched with --remote-debugging-port which enables
                // full session/cookie access via Chrome DevTools Protocol (CDP)
                var procName = pt.ProcessName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase);
                if (!BrowserProcesses.Contains(procName)) return null;

                var cmd = pt.CommandLine;
                if (cmd.Contains("--remote-debugging-port", StringComparison.OrdinalIgnoreCase))
                {
                    // Check who launched it — if parent is a known browser (self-spawn), skip
                    if (!string.IsNullOrEmpty(pt.ParentProcessName))
                    {
                        var parentName = pt.ParentProcessName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase);
                        if (BrowserProcesses.Contains(parentName))
                            return null; // Browser spawning its own subprocess with debug port — normal
                    }

                    return new DetectionEvent
                    {
                        RuleName = Name,
                        ProcessName = pt.ProcessName,
                        ProcessId = pt.ProcessId,
                        SignalType = SignalType.CredentialTheft,
                        Confidence = 0.90,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        Evidence = $"Browser '{pt.ProcessName}' (PID {pt.ProcessId}) launched with --remote-debugging-port: {cmd}",
                        Reasoning = "A browser was launched with the Chrome DevTools Protocol remote debugging port enabled by a non-browser parent process. " +
                                    "This allows full programmatic access to all open tabs, cookies, session tokens, and saved passwords " +
                                    "without touching any credential file on disk. Common technique in session hijacking attacks."
                    };
                }
            }
            return null;
        }
    }

    [RuleCategory(DetectionCategory.ProcessInjection)]
    public class DllSideloadingDetectionRule : IDetectionRule
    {
        public string Name => "DllSideloadingDetectionRule";

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var path = pt.ImagePath.ToLowerInvariant();
                
                // Check if process runs out of user-writeable paths
                bool isUserWriteablePath = path.Contains(@"\users\") || 
                                           path.Contains(@"\appdata\") || 
                                           path.Contains(@"\temp\");

                if (isUserWriteablePath)
                {
                    // Check if it is a signed Microsoft utility (e.g. system tools or OneDrive)
                    // that should normally reside in System32 or Program Files
                    var procName = pt.ProcessName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase);
                    bool isSystemToolName = procName.Equals("onedrive", StringComparison.OrdinalIgnoreCase) ||
                                            procName.Equals("msoju", StringComparison.OrdinalIgnoreCase) ||
                                            procName.Equals("winword", StringComparison.OrdinalIgnoreCase) ||
                                            procName.Equals("excel", StringComparison.OrdinalIgnoreCase) ||
                                            procName.Equals("powershell", StringComparison.OrdinalIgnoreCase) ||
                                            procName.Equals("cmd", StringComparison.OrdinalIgnoreCase);

                    // Exclude developer build environments to avoid developer false positives
                    if (path.Contains(@"\bin\debug") || path.Contains(@"\bin\release") || path.Contains(@".nuget"))
                    {
                        return null;
                    }

                    if (isSystemToolName)
                    {
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            SignalType = SignalType.SuspiciousProcess,
                            Confidence = 0.85,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"Signed Microsoft tool running out of user writeable path: {pt.ImagePath}",
                            Reasoning = "A signed Microsoft utility was executed from an untrusted user-writeable directory. This is highly indicative of DLL Sideloading (T1574.002)."
                        };
                    }
                }
            }
            return null;
        }
    }
}

