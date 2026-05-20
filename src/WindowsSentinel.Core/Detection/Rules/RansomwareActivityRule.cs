using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Detects ransomware-like file activity and pre-encryption preparation.
///
/// Detection vectors:
///   1. Rename to a known ransomware extension.
///   2. Bulk file renames within a short sliding window.
///   3. Shadow copy deletion commands (pre-encryption step used by virtually all ransomware).
///   4. Backup catalog deletion / bcdedit recovery disable.
/// </summary>
public sealed class RansomwareActivityRule : IDetectionRule
{
    public string Name => "Ransomware-Like Activity";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    // Shadow copy / backup destruction — used by virtually every ransomware family
    // before encryption begins. This alone is near-certain ransomware behavior.
    private static readonly (string Process, string Pattern)[] ShadowDeletePatterns =
    {
        // vssadmin
        ("vssadmin.exe",  "delete shadows"),
        ("vssadmin.exe",  "resize shadowstorage"),
        // wmic
        ("wmic.exe",      "shadowcopy delete"),
        ("wmic.exe",      "shadowcopy where"),
        // PowerShell via WMI
        ("powershell.exe","Get-WmiObject Win32_ShadowCopy"),
        ("powershell.exe","Win32_ShadowCopy"),
        ("powershell.exe","shadowcopy"),
        // wbadmin
        ("wbadmin.exe",   "delete catalog"),
        ("wbadmin.exe",   "delete systemstatebackup"),
        // bcdedit — disables Windows Recovery Environment
        ("bcdedit.exe",   "recoveryenabled no"),
        ("bcdedit.exe",   "bootstatuspolicy ignoreallfailures"),
        // diskshadow
        ("diskshadow.exe","delete shadows"),
        // net stop backup services
        ("net.exe",       "stop vss"),
        ("net.exe",       "stop \"volume shadow copy\""),
        ("net1.exe",      "stop vss"),
        // taskkill of backup agents
        ("taskkill.exe",  "veeam"),
        ("taskkill.exe",  "backup"),
        ("taskkill.exe",  "sql"),
    };

    public DetectionEvent? Evaluate(object telemetry)
    {
        // ── File-system telemetry ────────────────────────────────────────────
        if (telemetry is FileActivityTelemetry file)
        {
            if (!file.IsSuspiciousExtension && !file.IsBulkRename) return null;

            var evidence = file.IsSuspiciousExtension
                ? $"File renamed to ransomware extension: '{file.OldPath}' → '{file.NewPath}'"
                : $"Bulk rename: {file.RenameCount} renames in 10 s. Latest: '{file.OldPath}' → '{file.NewPath}'";

            double confidence = file.IsSuspiciousExtension && file.IsBulkRename ? 0.97
                              : file.IsSuspiciousExtension                       ? 0.82
                              : 0.68;

            return new DetectionEvent
            {
                RuleName    = Name,
                Evidence    = evidence,
                Reasoning   = "Ransomware renames or re-encrypts files in bulk, appending a custom extension. " +
                              "Bulk renames combined with known ransomware extensions are a near-certain indicator. " +
                              "Families covered include WannaCry, Locky, Cerber, REvil, LockBit, and many others.",
                Confidence  = confidence,
                Tier        = Tier,
                ProcessName = "FileSystem",
                ProcessId   = 0,
                Timestamp   = file.Timestamp,
                Metadata    = new()
                {
                    ["OldPath"]     = file.OldPath,
                    ["NewPath"]     = file.NewPath,
                    ["RenameCount"] = file.RenameCount.ToString()
                }
            };
        }

        // ── Process telemetry — shadow copy / backup destruction ─────────────
        if (telemetry is ProcessTelemetry proc)
        {
            var nameLower = proc.ProcessName.ToLowerInvariant();
            var cmdLower  = proc.CommandLine.ToLowerInvariant();

            foreach (var (shadowProcess, shadowPattern) in ShadowDeletePatterns)
            {
                if ((nameLower == shadowProcess.ToLowerInvariant() ||
                     proc.ImagePath.EndsWith(shadowProcess, StringComparison.OrdinalIgnoreCase)) &&
                    cmdLower.Contains(shadowPattern.ToLowerInvariant()))
                {
                    return new DetectionEvent
                    {
                        RuleName    = Name,
                        Evidence    = $"Shadow copy / backup destruction: '{proc.ProcessName}' (PID {proc.ProcessId}) " +
                                      $"with pattern '{shadowPattern}'. CommandLine: {proc.CommandLine}",
                        Reasoning   = "Deleting shadow copies and disabling Windows Recovery is the standard " +
                                      "pre-encryption step performed by ransomware (WannaCry, REvil, LockBit, " +
                                      "BlackCat, Conti, etc.) to prevent file recovery. This is one of the " +
                                      "highest-confidence ransomware indicators available in userland.",
                        Confidence  = 0.96,
                        Tier        = Tier,
                        ProcessName = proc.ProcessName,
                        ProcessId   = proc.ProcessId,
                        Timestamp   = proc.Timestamp,
                        Metadata    = new()
                        {
                            ["CommandLine"]    = proc.CommandLine,
                            ["MatchedPattern"] = shadowPattern,
                            ["ParentPid"]      = proc.ParentProcessId.ToString()
                        }
                    };
                }
            }
        }

        return null;
    }
}

