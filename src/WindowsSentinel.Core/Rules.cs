using System;
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
                        Evidence = $"Encoded PowerShell execution command: {cmd}",
                        Reasoning = "Process launched an obfuscated PowerShell session, commonly used to execute downloader cradles or C2 shell callbacks."
                    };
                }
            }
            return null;
        }
    }

    public class UnsignedBinaryRule : IDetectionRule
    {
        public string Name => "UnsignedBinaryRule";

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                // Skip checking if it lacks path separator (as per v4.1.0 fix)
                if (!pt.ImagePath.Contains('\\')) return null;

                var path = pt.ImagePath.ToLowerInvariant();
                // Flag unsigned processes running outside trusted directories (Temp / AppData / Downloads)
                if (path.Contains("\\temp\\") || path.Contains("\\appdata\\") || path.Contains("\\downloads\\"))
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
}
