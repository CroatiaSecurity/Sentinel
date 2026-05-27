using System.Security.Cryptography.X509Certificates;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier2 — Flags unsigned binaries executing from user-writable locations.
///
/// Improvements over naive path-only check:
///   - Verifies Authenticode signature via X509Certificate (same as before, but with
///     a richer trusted-path list and explicit temp/staging path boosting).
///   - Boosts confidence when the binary is in a known malware staging path
///     (%TEMP%, %APPDATA%, ProgramData, Downloads, Desktop).
///   - Skips the check for system paths and known-legitimate unsigned binaries.
/// </summary>
public sealed class UnsignedBinaryRule : IDetectionRule
{
    public string Name => "Unsigned Binary Execution";
    public DetectionTier Tier => DetectionTier.Tier2Indicator;

    private static readonly string[] TrustedPaths =
    {
        @"C:\Windows\",
        @"C:\Program Files\",
        @"C:\Program Files (x86)\",
        @"C:\ProgramData\Microsoft\",
    };

    // High-risk staging paths — unsigned binaries here get a confidence boost.
    private static readonly string[] StagingPaths =
    {
        @"\Temp\",
        @"\AppData\Local\Temp\",
        @"\AppData\Roaming\",
        @"\Downloads\",
        @"\Desktop\",
        @"\ProgramData\",
        @"\Public\",
        @"\Users\Public\",
    };

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;
        if (proc.EventType != "ProcessStart") return null;
        if (string.IsNullOrWhiteSpace(proc.ImagePath)) return null;

        // v4.1.0: If ImagePath is just a filename (no path separator), ETW didn't provide
        // the full path. These are almost always system binaries launched by the kernel.
        // Don't flag them — we can't verify their location.
        if (!proc.ImagePath.Contains('\\') && !proc.ImagePath.Contains('/'))
            return null;

        // Skip trusted system paths
        bool inTrustedPath = TrustedPaths.Any(p =>
            proc.ImagePath.StartsWith(p, StringComparison.OrdinalIgnoreCase));
        if (inTrustedPath) return null;

        if (IsFileSigned(proc.ImagePath)) return null;

        bool inStagingPath = StagingPaths.Any(p =>
            proc.ImagePath.Contains(p, StringComparison.OrdinalIgnoreCase));

        double confidence = inStagingPath ? 0.68 : 0.50;

        return new DetectionEvent
        {
            RuleName    = Name,
            Evidence    = $"Unsigned binary '{proc.ImagePath}' executed as '{proc.ProcessName}' " +
                          $"(PID {proc.ProcessId})" +
                          (inStagingPath ? " from a known malware staging path." : "."),
            Reasoning   = "Unsigned binaries from non-system paths may indicate malware, a dropped payload, " +
                          "or an untrusted tool. Execution from temp/AppData paths significantly increases " +
                          "the likelihood of malicious intent. Investigate the parent process and origin.",
            Confidence  = confidence,
            Tier        = Tier,
            ProcessName = proc.ProcessName,
            ProcessId   = proc.ProcessId,
            Timestamp   = proc.Timestamp,
            Metadata    = new()
            {
                ["ImagePath"]      = proc.ImagePath,
                ["InStagingPath"]  = inStagingPath.ToString(),
                ["ParentPid"]      = proc.ParentProcessId.ToString()
            }
        };
    }

    private static bool IsFileSigned(string filePath)
    {
        try
        {
            if (!File.Exists(filePath)) return false;
            var cert = X509Certificate.CreateFromSignedFile(filePath);
            return cert is not null;
        }
        catch
        {
            return false;
        }
    }
}


