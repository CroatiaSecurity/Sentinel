using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Detects common persistence mechanisms on Windows.
///
/// Detection vectors:
///   1. Registry Run/RunOnce keys modified by suspicious processes.
///   2. Scheduled task creation with suspicious command lines.
///   3. WMI event subscription persistence patterns.
///   4. Startup folder executables from suspicious paths.
///   5. Service creation with unusual binary paths.
///
/// Note: This rule focuses on process behavior indicating persistence setup.
/// For file-based detection of persisted payloads, see UnsignedBinaryRule.
/// </summary>
public sealed class PersistenceRule : IDetectionRule
{
    public string Name => "Persistence Mechanism Detected";
    public DetectionTier Tier => DetectionTier.Tier2Indicator; // Demoted: too many FPs from installers/updaters; use as signal only

    // Registry persistence keys that should not be written by user processes.
    private static readonly string[] RegistryPersistencePatterns =
    {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Appinit_Dlls",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load",
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute",
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Authentication Packages",
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages",
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages",
        "SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors",
        "SYSTEM\\CurrentControlSet\\Control\\Print\\Providers",
    };

    // Command-line patterns indicating scheduled task creation.
    private static readonly string[] ScheduledTaskPatterns =
    {
        "schtasks.exe /create",
        "schtasks /create",
        "Register-ScheduledTask",
        "New-ScheduledTask",
        "schtasks /change",
    };

    // WMI persistence command-line indicators.
    private static readonly string[] WmiPersistencePatterns =
    {
        "__EventToConsumerBinding",
        "__EventFilter",
        "__EventConsumer",
        "ActiveScriptEventConsumer",
        "CommandLineEventConsumer",
        "LogFileEventConsumer",
        "wmiobject -class", "Set-WmiInstance",
        "Register-WmiEvent",
    };

    // Service creation command-line patterns.
    private static readonly string[] ServiceCreationPatterns =
    {
        "sc.exe create",
        "sc create",
        "New-Service",
        "InstallUtil.exe",
        "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services",
    };

    // Legitimate installers/updaters that commonly create persistence.
    private static readonly HashSet<string> AllowedInstallers = new(StringComparer.OrdinalIgnoreCase)
    {
        "msiexec", "trustedinstaller", "tiworker", "msoidsvc",
        "googleupdate", "update.exe", "setup.exe", "install.exe",
        "vs_installer", "dotnet", "nuget", "winget",
        "steam", "epicgameslauncher", "galaxyclient", "origin",
        "battle.net", "riotclientservices", "xbox",
    };

    // Suspicious persistence payloads.
    private static readonly string[] SuspiciousPayloadPatterns =
    {
        "powershell", "pwsh", "cmd.exe", "wscript", "cscript",
        "mshta", "regsvr32", "rundll32", "certutil",
        "bitsadmin", "wmic", "http://", "https://",
        "-encodedcommand", "-enc ", "iex", "invoke-expression",
        "downloadstring", "downloadfile", "frombase64string",
    };

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;
        if (proc.EventType != "ProcessStart") return null;

        var cmdLower = proc.CommandLine.ToLowerInvariant();
        var nameLower = proc.ProcessName.ToLowerInvariant();
        var imgLower = proc.ImagePath.ToLowerInvariant();

        // Skip legitimate installers
        var nameStem = Path.GetFileNameWithoutExtension(proc.ProcessName);
        if (AllowedInstallers.Contains(nameStem)) return null;

        // 1. Registry persistence via command line (reg add)
        if (cmdLower.Contains("reg add") || cmdLower.Contains("reg.exe add"))
        {
            foreach (var pattern in RegistryPersistencePatterns)
            {
                if (cmdLower.Contains(pattern.ToLowerInvariant()))
                {
                    var payloadMatch = SuspiciousPayloadPatterns.FirstOrDefault(p =>
                        cmdLower.Contains(p.ToLowerInvariant()));

                    return new DetectionEvent
                    {
                        RuleName    = Name,
                        Evidence    = $"Registry persistence key modification detected. " +
                                      $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) " +
                                      $"attempting to modify '{pattern}'" +
                                      (payloadMatch is not null ? $" with suspicious payload '{payloadMatch}'." : ".") +
                                      $" CommandLine: {proc.CommandLine}",
                        Reasoning   = "Registry Run keys and Winlogon notify packages are the most common " +
                                      "persistence mechanisms. Attackers use them to survive reboots and " +
                                      "maintain access (T1547.001, T1547.012). " +
                                      "User processes should not modify these keys directly.",
                        Confidence  = payloadMatch is not null ? 0.92 : 0.85,
                        Tier        = Tier,
                        ProcessName = proc.ProcessName,
                        ProcessId   = proc.ProcessId,
                        Timestamp   = proc.Timestamp,
                        Metadata    = new()
                        {
                            ["PersistenceType"] = "Registry",
                            ["TargetKey"]       = pattern,
                            ["SuspiciousPayload"] = payloadMatch ?? "none",
                            ["CommandLine"]     = proc.CommandLine
                        }
                    };
                }
            }
        }

        // 2. Scheduled task creation with suspicious payload
        foreach (var taskPattern in ScheduledTaskPatterns)
        {
            if (cmdLower.Contains(taskPattern.ToLowerInvariant()))
            {
                var payloadMatch = SuspiciousPayloadPatterns.FirstOrDefault(p =>
                    cmdLower.Contains(p.ToLowerInvariant()));

                if (payloadMatch is not null)
                {
                    return new DetectionEvent
                    {
                        RuleName    = Name,
                        Evidence    = $"Scheduled task creation with suspicious payload detected. " +
                                      $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) " +
                                      $"creating task with payload containing '{payloadMatch}'. " +
                                      $"CommandLine: {proc.CommandLine}",
                        Reasoning   = "Scheduled tasks are a primary persistence mechanism (T1053.005). " +
                                      "Attackers create tasks to execute payloads at login, on schedule, " +
                                      "or as cleanup mechanisms. Shell/interpreter payloads in task commands " +
                                      "are high-confidence indicators of malicious persistence.",
                        Confidence  = 0.90,
                        Tier        = Tier,
                        ProcessName = proc.ProcessName,
                        ProcessId   = proc.ProcessId,
                        Timestamp   = proc.Timestamp,
                        Metadata    = new()
                        {
                            ["PersistenceType"] = "ScheduledTask",
                            ["SuspiciousPayload"] = payloadMatch,
                            ["CommandLine"]     = proc.CommandLine
                        }
                    };
                }
            }
        }

        // 3. WMI event subscription persistence
        foreach (var wmiPattern in WmiPersistencePatterns)
        {
            if (cmdLower.Contains(wmiPattern.ToLowerInvariant()))
            {
                return new DetectionEvent
                {
                    RuleName    = Name,
                    Evidence    = $"WMI persistence detected. Process '{proc.ProcessName}' (PID {proc.ProcessId}) " +
                                  $"using WMI event consumer pattern '{wmiPattern}'. " +
                                  $"CommandLine: {proc.CommandLine}",
                    Reasoning   = "WMI event subscriptions are a stealthy persistence mechanism (T1546.003). " +
                                  "ActiveScriptEventConsumer and CommandLineEventConsumer allow arbitrary " +
                                  "code execution triggered by system events. This technique is favored by " +
                                  "advanced attackers and fileless malware.",
                    Confidence  = 0.88,
                    Tier        = Tier,
                    ProcessName = proc.ProcessName,
                    ProcessId   = proc.ProcessId,
                    Timestamp   = proc.Timestamp,
                    Metadata    = new()
                    {
                        ["PersistenceType"] = "WMIEventSubscription",
                        ["WmiPattern"]      = wmiPattern,
                        ["CommandLine"]     = proc.CommandLine
                    }
                };
            }
        }

        // 4. Service creation with suspicious binary path
        foreach (var svcPattern in ServiceCreationPatterns)
        {
            if (cmdLower.Contains(svcPattern.ToLowerInvariant()))
            {
                // Check for suspicious binary path
                var hasSuspiciousPath = imgLower.Contains("\\temp\\") ||
                                        imgLower.Contains("\\appdata\\") ||
                                        imgLower.Contains("\\downloads\\") ||
                                        cmdLower.Contains("\\temp\\") ||
                                        cmdLower.Contains("\\appdata\\") ||
                                        cmdLower.Contains("\\users\\");

                var payloadMatch = SuspiciousPayloadPatterns.FirstOrDefault(p =>
                    cmdLower.Contains(p.ToLowerInvariant()));

                if (hasSuspiciousPath || payloadMatch is not null)
                {
                    return new DetectionEvent
                    {
                        RuleName    = Name,
                        Evidence    = $"Suspicious service creation detected. " +
                                      $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) " +
                                      $"creating service" +
                                      (payloadMatch is not null ? $" with payload '{payloadMatch}'" : "") +
                                      (hasSuspiciousPath ? " from user-writable path" : "") + ". " +
                                      $"CommandLine: {proc.CommandLine}",
                        Reasoning   = "Service creation is a privileged persistence mechanism (T1543.003). " +
                                      "Services run as SYSTEM and start automatically. Attackers create " +
                                      "services with binaries in user-writable paths or with shell commands " +
                                      "to maintain persistent SYSTEM-level access.",
                        Confidence  = 0.87,
                        Tier        = Tier,
                        ProcessName = proc.ProcessName,
                        ProcessId   = proc.ProcessId,
                        Timestamp   = proc.Timestamp,
                        Metadata    = new()
                        {
                            ["PersistenceType"] = "ServiceCreation",
                            ["SuspiciousPath"]  = hasSuspiciousPath.ToString(),
                            ["SuspiciousPayload"] = payloadMatch ?? "none",
                            ["CommandLine"]     = proc.CommandLine
                        }
                    };
                }
            }
        }

        return null;
    }
}

