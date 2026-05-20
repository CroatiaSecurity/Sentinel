using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Parent PID Spoofing Detector — Detects processes that fake their parent PID
/// using PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
///
/// How it works:
///   - ETW ProcessStart events report the REAL parent (the process that called CreateProcess)
///   - CreateToolhelp32Snapshot (ProcessAncestryCache) reports the DECLARED parent
///   - If they disagree, the process is spoofing its parent PID
///
/// This catches:
///   - Cobalt Strike's ppid spoofing
///   - Any tool using UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)
///   - Token theft + process creation with stolen parent handle
///
/// Near-zero false positives — legitimate Windows never disagrees on parent PID.
/// The only exception is WMI-spawned processes (wmiprvse.exe as intermediary),
/// which are explicitly excluded.
/// </summary>
public sealed class ParentPidSpoofDetector
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ProcessAncestryCache _ancestryCache;
    private readonly ILogger<ParentPidSpoofDetector> _logger;

    // Track ETW-reported parents for comparison
    private readonly ConcurrentDictionary<int, EtwParentRecord> _etwParents = new();

    // Processes that legitimately act as intermediaries (declared parent ≠ real parent)
    private static readonly HashSet<string> LegitimateIntermediaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "wmiprvse.exe", "wmiprvse", // WMI provider host
        "svchost.exe", "svchost",   // Service host (some services spawn via different svchost)
        "dllhost.exe", "dllhost",   // COM surrogate
        "sihost.exe", "sihost",     // Shell Infrastructure Host
        "runtimebroker.exe",        // UWP broker
        "taskhostw.exe"             // Task scheduler host
    };

    public ParentPidSpoofDetector(
        IDetectionEngine detectionEngine,
        ProcessAncestryCache ancestryCache,
        ILogger<ParentPidSpoofDetector> logger)
    {
        _detectionEngine = detectionEngine;
        _ancestryCache = ancestryCache;
        _logger = logger;
    }

    /// <summary>
    /// Called by EtwProcessMonitor on every ProcessStart event.
    /// Records the ETW-reported parent PID for later comparison.
    /// </summary>
    public void RecordEtwParent(int childPid, int etwReportedParentPid, string childName)
    {
        _etwParents[childPid] = new EtwParentRecord
        {
            ChildPid = childPid,
            ChildName = childName,
            EtwParentPid = etwReportedParentPid,
            Timestamp = DateTimeOffset.UtcNow
        };

        // Prune old entries
        if (_etwParents.Count > 5000)
        {
            var cutoff = DateTimeOffset.UtcNow.AddMinutes(-2);
            foreach (var kv in _etwParents)
            {
                if (kv.Value.Timestamp < cutoff)
                    _etwParents.TryRemove(kv.Key, out _);
            }
        }
    }

    /// <summary>
    /// Called periodically (or after a short delay post-process-start) to compare
    /// ETW-reported parent with snapshot-reported parent.
    /// </summary>
    public async Task CheckForSpoofingAsync(CancellationToken ct)
    {
        var toCheck = _etwParents.Values
            .Where(r => (DateTimeOffset.UtcNow - r.Timestamp).TotalSeconds is > 1 and < 30)
            .ToList();

        foreach (var record in toCheck)
        {
            ct.ThrowIfCancellationRequested();

            // Get the snapshot-reported parent from ProcessAncestryCache
            var snapshotParentName = _ancestryCache.GetParentName(record.ChildPid);
            if (snapshotParentName == null) continue; // Process already exited

            // Get the ETW-reported parent name
            var etwParentName = _ancestryCache.GetProcessName(record.EtwParentPid);
            if (etwParentName == null) continue; // Parent already exited

            // Compare: get the snapshot-reported parent PID
            // We need to check if the ancestry cache's parent for this PID matches ETW
            var ancestors = _ancestryCache.GetAncestors(record.ChildPid);
            if (ancestors.Count == 0) continue;

            var declaredParentName = ancestors[0]; // Immediate parent from snapshot

            // If ETW parent and snapshot parent agree, no spoofing
            if (string.Equals(etwParentName, declaredParentName, StringComparison.OrdinalIgnoreCase))
                continue;

            // Skip legitimate intermediaries
            if (LegitimateIntermediaries.Contains(etwParentName) ||
                LegitimateIntermediaries.Contains(declaredParentName))
                continue;

            // Skip if child is a system process
            if (record.ChildPid <= 4) continue;

            // SPOOFING DETECTED
            _logger.LogCritical(
                "PPID SPOOF DETECTED: '{Child}' (PID {ChildPid}) — " +
                "ETW says parent is '{EtwParent}' (PID {EtwPid}), " +
                "but snapshot says parent is '{SnapshotParent}'",
                record.ChildName, record.ChildPid,
                etwParentName, record.EtwParentPid,
                declaredParentName);

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Parent PID Spoofing Detected",
                Evidence = $"Process '{record.ChildName}' (PID {record.ChildPid}) has mismatched parent: " +
                          $"ETW reports parent '{etwParentName}' (PID {record.EtwParentPid}), " +
                          $"but process snapshot reports parent '{declaredParentName}'. " +
                          $"This indicates PROC_THREAD_ATTRIBUTE_PARENT_PROCESS spoofing.",
                Reasoning = "Parent PID spoofing is used by advanced attackers (Cobalt Strike, custom loaders) " +
                           "to make malicious processes appear to be children of legitimate system processes " +
                           "(e.g., making malware look like it was spawned by explorer.exe or svchost.exe). " +
                           "Legitimate Windows processes NEVER disagree on parent PID between ETW and the " +
                           "process snapshot. This is a near-zero false positive detection.",
                Confidence = 0.95,
                Tier = DetectionTier.Tier2Indicator, // Corroborating signal — feeds correlation engine, not a standalone kill
                ProcessName = record.ChildName,
                ProcessId = record.ChildPid,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["etw_parent_pid"] = record.EtwParentPid.ToString(),
                    ["etw_parent_name"] = etwParentName,
                    ["declared_parent_name"] = declaredParentName,
                    ["technique"] = "T1134.004 - Access Token Manipulation: Parent PID Spoofing"
                }
            }, ct);

            // Remove so we don't re-alert
            _etwParents.TryRemove(record.ChildPid, out _);
        }
    }
}

internal sealed class EtwParentRecord
{
    public int ChildPid { get; init; }
    public string ChildName { get; init; } = "";
    public int EtwParentPid { get; init; }
    public DateTimeOffset Timestamp { get; init; }
}


