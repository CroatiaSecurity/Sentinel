using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Tails JSONL files dropped by PowerShell-based Councilor consultants
/// and emits their signals as Tier2 DetectionEvents into the DetectionEngine.
/// 
/// Consultants write one JSON object per line to:
///   %ProgramData%\WindowsSentinel\consultants\{name}.jsonl
/// 
/// Schema per line:
/// {
///   "consultant": "RansomwareScarewareDetection",
///   "timestamp": "ISO-8601 UTC",
///   "signal": "short identifier",
///   "evidence": "human-readable observation",
///   "process_id": int|null,
///   "process_name": "string|null",
///   "image_path": "string|null",
///   "confidence": 0.0-1.0,
///   "metadata": { "key": "string", ... }
/// }
/// </summary>
public sealed class ConsultantSignalIngestor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<ConsultantSignalIngestor> _logger;
    private readonly string _consultantDir;
    private readonly TimeSpan _pollInterval = TimeSpan.FromSeconds(5);
    private readonly ConcurrentDictionary<string, long> _filePositions = new(StringComparer.OrdinalIgnoreCase);

    public ConsultantSignalIngestor(
        IDetectionEngine detectionEngine,
        ILogger<ConsultantSignalIngestor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _consultantDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "WindowsSentinel", "consultants");
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("ConsultantSignalIngestor starting. Watching: {Dir}", _consultantDir);

        // Ensure the directory exists with restrictive ACL (Admin + SYSTEM only)
        // This prevents non-admin users from injecting signals into the correlator.
        EnsureSecureDirectory(_consultantDir);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ProcessConsultantFilesAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "ConsultantSignalIngestor: error processing files");
            }

            try { await Task.Delay(_pollInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task ProcessConsultantFilesAsync(CancellationToken ct)
    {
        if (!Directory.Exists(_consultantDir)) return;

        var files = Directory.GetFiles(_consultantDir, "*.jsonl");
        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                await ProcessFileAsync(file, ct);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "ConsultantSignalIngestor: error processing {File}", Path.GetFileName(file));
            }
        }
    }

    private async Task ProcessFileAsync(string filePath, CancellationToken ct)
    {
        var fileInfo = new FileInfo(filePath);
        if (!fileInfo.Exists || fileInfo.Length == 0) return;

        long lastPosition = _filePositions.GetOrAdd(filePath, 0);

        // If file was truncated/rotated, reset position
        if (lastPosition > fileInfo.Length)
        {
            lastPosition = 0;
            _filePositions[filePath] = 0;
        }

        if (lastPosition >= fileInfo.Length) return;

        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        stream.Seek(lastPosition, SeekOrigin.Begin);

        using var reader = new StreamReader(stream);
        string? line;
        while ((line = await reader.ReadLineAsync(ct)) != null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            await ProcessLineAsync(line, Path.GetFileNameWithoutExtension(filePath), ct);
        }

        _filePositions[filePath] = stream.Position;
    }

    private async Task ProcessLineAsync(string line, string consultantName, CancellationToken ct)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;

            var signal = GetStringProperty(root, "signal") ?? "unknown_signal";
            var evidence = GetStringProperty(root, "evidence") ?? line;
            var processName = GetStringProperty(root, "process_name") ?? "unknown";
            var imagePath = GetStringProperty(root, "image_path");
            var processId = GetIntProperty(root, "process_id") ?? 0;
            var confidence = GetDoubleProperty(root, "confidence") ?? 0.5;

            // Build metadata from the consultant's extra fields
            var metadata = new Dictionary<string, string>
            {
                ["consultant"] = consultantName,
                ["signal"] = signal
            };

            if (root.TryGetProperty("metadata", out var metaElement) && metaElement.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in metaElement.EnumerateObject())
                {
                    metadata[$"consultant_{prop.Name}"] = prop.Value.ToString();
                }
            }

            if (!string.IsNullOrEmpty(imagePath))
                metadata["image_path"] = imagePath;

            var detection = new DetectionEvent
            {
                RuleName = $"Councilor: {consultantName} — {signal}",
                Evidence = evidence,
                Reasoning = $"Signal from Council of Elders consultant '{consultantName}'. " +
                           "Consultant signals are advisory only — they never trigger kills on their own. " +
                           "Multiple correlating consultant signals may produce a composite kill via BehavioralCorrelationEngine.",
                Confidence = confidence,
                Tier = DetectionTier.Tier2Indicator, // Consultants are always Tier2
                ProcessName = processName,
                ProcessId = processId,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = metadata
            };

            await _detectionEngine.EmitAsync(detection, ct);
            _logger.LogDebug("Councilor signal: {Consultant}/{Signal} | {Process} (PID {Pid})",
                consultantName, signal, processName, processId);
        }
        catch (JsonException ex)
        {
            _logger.LogDebug(ex, "ConsultantSignalIngestor: invalid JSON from {Consultant}", consultantName);
        }
    }

    private static string? GetStringProperty(JsonElement element, string name)
    {
        if (element.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.String)
            return prop.GetString();
        return null;
    }

    private static int? GetIntProperty(JsonElement element, string name)
    {
        if (element.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.Number && prop.TryGetInt32(out var val))
            return val;
        return null;
    }

    private static double? GetDoubleProperty(JsonElement element, string name)
    {
        if (element.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.Number && prop.TryGetDouble(out var val))
            return val;
        return null;
    }

    /// <summary>
    /// Creates the consultant directory with restrictive ACL (SYSTEM + Administrators only).
    /// Prevents non-admin users from injecting signals into the detection correlator.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private void EnsureSecureDirectory(string dir)
    {
        if (!Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        try
        {
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            var dirInfo = new DirectoryInfo(dir);
            var sec = dirInfo.GetAccessControl();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            // Remove all existing rules
            foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                sec.RemoveAccessRule(rule);

            // Grant SYSTEM full control
            sec.AddAccessRule(new FileSystemAccessRule(
                systemSid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));

            // Grant Administrators full control
            sec.AddAccessRule(new FileSystemAccessRule(
                adminsSid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));

            dirInfo.SetAccessControl(sec);
            _logger.LogInformation("ConsultantSignalIngestor: ACL hardened on {Dir}", dir);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "ConsultantSignalIngestor: Failed to apply restrictive ACL to {Dir}. " +
                "Non-admin users may be able to inject signals.", dir);
        }
    }
}

