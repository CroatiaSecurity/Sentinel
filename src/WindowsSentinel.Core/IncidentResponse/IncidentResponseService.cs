using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Response;

namespace WindowsSentinel.Core.IncidentResponse;

/// <summary>
/// Incident Response Service - Collects forensic evidence and generates incident tickets.
/// </summary>
public sealed class IncidentResponseService
{
    private readonly ILogger<IncidentResponseService> _logger;
    private readonly string _evidenceBasePath;

    // Native methods for memory dump
    [DllImport("dbghelp.dll")]
    private static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        int ProcessId,
        IntPtr hFile,
        MINIDUMP_TYPE DumpType,
        IntPtr ExceptionParam,
        IntPtr UserStreamParam,
        IntPtr CallbackParam);

    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint GENERIC_WRITE = 0x40000000;
    private const uint CREATE_ALWAYS = 2;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;

    private enum MINIDUMP_TYPE
    {
        MiniDumpNormal = 0x00000000,
        MiniDumpWithDataSegs = 0x00000001,
        MiniDumpWithFullMemory = 0x00000002,
        MiniDumpWithHandleData = 0x00000004,
    }

    public IncidentResponseService(ILogger<IncidentResponseService> logger)
    {
        _logger = logger;
        _evidenceBasePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WindowsSentinel", "Evidence");
        Directory.CreateDirectory(_evidenceBasePath);
        ApplyRestrictiveAcl(_evidenceBasePath);
    }

    /// <summary>
    /// Collects comprehensive forensic evidence for an incident.
    /// </summary>
    public async Task<IncidentEvidence> CollectEvidenceAsync(
        DetectionEvent detection,
        ChainTraceResult? chainTrace = null,
        bool collectMemoryDump = true,
        CancellationToken cancellationToken = default)
    {
        var caseId = $"CASE_{detection.ProcessId}_{DateTime.Now:yyyyMMdd_HHmmss}";
        var casePath = Path.Combine(_evidenceBasePath, caseId);
        Directory.CreateDirectory(casePath);

        _logger.LogCritical(
            "IncidentResponse: Collecting evidence for Case {CaseId} - {Rule}",
            caseId, detection.RuleName);

        var evidence = new IncidentEvidence
        {
            CaseId = caseId,
            CasePath = casePath,
            Detection = detection,
            CollectionStartTime = DateTimeOffset.UtcNow
        };

        try
        {
            // 1. Memory dump of offending process
            if (collectMemoryDump && detection.ProcessId > 0)
            {
                try
                {
                    var dumpPath = await CollectMemoryDumpAsync(detection.ProcessId, casePath, cancellationToken);
                    if (dumpPath != null)
                    {
                        evidence.MemoryDumpPath = dumpPath;
                        _logger.LogInformation("IncidentResponse: Memory dump collected: {Path}", dumpPath);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "IncidentResponse: Failed to collect memory dump");
                }
            }

            // 2. Module inventory
            if (detection.ProcessId > 0)
            {
                try
                {
                    var modulesPath = await CollectModuleInventoryAsync(detection.ProcessId, casePath, cancellationToken);
                    evidence.ModuleInventoryPath = modulesPath;
                    _logger.LogInformation("IncidentResponse: Module inventory collected");
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "IncidentResponse: Failed to collect module inventory");
                }
            }

            // 3. Network snapshot
            try
            {
                var networkPath = await CollectNetworkSnapshotAsync(casePath, cancellationToken);
                evidence.NetworkSnapshotPath = networkPath;
                _logger.LogInformation("IncidentResponse: Network snapshot collected");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "IncidentResponse: Failed to collect network snapshot");
            }

            // 4. Binary copy (if chain trace available)
            if (chainTrace?.QuarantinedFiles.Any() == true)
            {
                try
                {
                    var binaryPath = await CopyAttackerBinariesAsync(
                        chainTrace.QuarantinedFiles, casePath, cancellationToken);
                    evidence.BinaryCopiesPath = binaryPath;
                    _logger.LogInformation("IncidentResponse: Binary copies saved");
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "IncidentResponse: Failed to copy binaries");
                }
            }

            // 5. Process tree snapshot
            try
            {
                var treePath = await CollectProcessTreeSnapshotAsync(detection.ProcessId, casePath, cancellationToken);
                evidence.ProcessTreePath = treePath;
                _logger.LogInformation("IncidentResponse: Process tree snapshot collected");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "IncidentResponse: Failed to collect process tree");
            }

            // 6. Generate incident ticket
            var ticketPath = await GenerateIncidentTicketAsync(evidence, chainTrace, casePath, cancellationToken);
            evidence.IncidentTicketPath = ticketPath;

            evidence.CollectionEndTime = DateTimeOffset.UtcNow;
            evidence.Success = true;

            _logger.LogCritical(
                "IncidentResponse: Evidence collection complete for Case {CaseId}. " +
                "Duration: {Duration}s, Files: {Files}",
                caseId,
                (evidence.CollectionEndTime - evidence.CollectionStartTime).TotalSeconds,
                Directory.GetFiles(casePath, "*", SearchOption.AllDirectories).Length);
        }
        catch (Exception ex)
        {
            evidence.Success = false;
            evidence.ErrorMessage = ex.Message;
            _logger.LogError(ex, "IncidentResponse: Evidence collection failed");
        }

        return evidence;
    }

    /// <summary>
    /// Generates an incident ticket with full details.
    /// </summary>
    private async Task<string> GenerateIncidentTicketAsync(
        IncidentEvidence evidence,
        ChainTraceResult? chainTrace,
        string casePath,
        CancellationToken cancellationToken)
    {
        var ticket = new IncidentTicket
        {
            CaseId = evidence.CaseId,
            GeneratedAt = DateTimeOffset.UtcNow,
            Detection = evidence.Detection,
            Evidence = evidence,
            ChainTrace = chainTrace,
            Severity = CalculateSeverity(evidence.Detection),
            RecommendedActions = GetRecommendedActions(evidence.Detection, chainTrace),
            IndicatorsOfCompromise = ExtractIOCs(evidence, chainTrace)
        };

        var ticketPath = Path.Combine(casePath, "incident_ticket.json");
        var json = JsonSerializer.Serialize(ticket, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });

        await File.WriteAllTextAsync(ticketPath, json, cancellationToken);

        // Also create a human-readable summary
        var summaryPath = Path.Combine(casePath, "incident_summary.txt");
        var summary = GenerateHumanReadableSummary(ticket);
        await File.WriteAllTextAsync(summaryPath, summary, cancellationToken);

        return ticketPath;
    }

    /// <summary>
    /// Collects a minidump of the target process.
    /// </summary>
    private async Task<string?> CollectMemoryDumpAsync(int processId, string casePath, CancellationToken cancellationToken)
    {
        var dumpPath = Path.Combine(casePath, $"process_{processId}_dump.dmp");

        try
        {
            using var process = Process.GetProcessById(processId);
            if (process.HasExited)
                return null;

            _logger.LogInformation("IncidentResponse: Creating memory dump for PID {Pid} at {Path}", processId, dumpPath);

            // Use MiniDumpWriteDump via P/Invoke for a real memory dump
            var fileHandle = CreateFile(
                dumpPath,
                GENERIC_WRITE,
                0, // No sharing
                IntPtr.Zero,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero);

            if (fileHandle == IntPtr.Zero || fileHandle == new IntPtr(-1))
            {
                _logger.LogWarning("IncidentResponse: Failed to create dump file handle");
                return null;
            }

            try
            {
                bool success = MiniDumpWriteDump(
                    process.Handle,
                    processId,
                    fileHandle,
                    MINIDUMP_TYPE.MiniDumpWithFullMemory,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero);

                if (!success)
                {
                    var error = Marshal.GetLastWin32Error();
                    _logger.LogWarning("IncidentResponse: MiniDumpWriteDump failed (error {Error}). " +
                                      "This requires elevation (SYSTEM or Admin).", error);

                    // Write metadata file as fallback
                    var metadata = new Dictionary<string, object>
                    {
                        ["process_id"] = processId,
                        ["process_name"] = process.ProcessName,
                        ["dump_requested"] = DateTimeOffset.UtcNow,
                        ["error"] = $"MiniDumpWriteDump failed with Win32 error {error}",
                        ["note"] = "Full dump requires SeDebugPrivilege (run as SYSTEM or Admin)"
                    };

                    await File.WriteAllTextAsync(
                        dumpPath + ".metadata.json",
                        JsonSerializer.Serialize(metadata, new JsonSerializerOptions { WriteIndented = true }),
                        cancellationToken);

                    // Clean up the empty/partial dump file
                    try { File.Delete(dumpPath); } catch { }
                    return dumpPath + ".metadata.json";
                }
            }
            finally
            {
                CloseHandle(fileHandle);
            }

            _logger.LogInformation("IncidentResponse: Memory dump created successfully ({Size} bytes)",
                new FileInfo(dumpPath).Length);
            return dumpPath;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "IncidentResponse: Memory dump collection failed");
            return null;
        }
    }

    /// <summary>
    /// Collects module inventory for the target process.
    /// </summary>
    private async Task<string> CollectModuleInventoryAsync(int processId, string casePath, CancellationToken cancellationToken)
    {
        var inventoryPath = Path.Combine(casePath, $"process_{processId}_modules.json");
        var modules = new List<ModuleInfo>();

        try
        {
            using var process = Process.GetProcessById(processId);
            foreach (ProcessModule module in process.Modules)
            {
                string? hash = null;
                try
                {
                    if (File.Exists(module.FileName))
                    {
                        using var sha256 = SHA256.Create();
                        await using var stream = File.OpenRead(module.FileName);
                        var hashBytes = await sha256.ComputeHashAsync(stream, cancellationToken);
                        hash = Convert.ToHexString(hashBytes);
                    }
                }
                catch { /* Ignore hash errors */ }

                modules.Add(new ModuleInfo
                {
                    ModuleName = module.ModuleName,
                    FileName = module.FileName,
                    BaseAddress = module.BaseAddress.ToString(),
                    ModuleMemorySize = module.ModuleMemorySize,
                    FileVersion = module.FileVersionInfo?.FileVersion,
                    ProductName = module.FileVersionInfo?.ProductName,
                    CompanyName = module.FileVersionInfo?.CompanyName,
                    Sha256Hash = hash
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "IncidentResponse: Module inventory collection failed");
        }

        var json = JsonSerializer.Serialize(modules, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(inventoryPath, json, cancellationToken);

        return inventoryPath;
    }

    /// <summary>
    /// Collects network connection snapshot.
    /// </summary>
    private async Task<string> CollectNetworkSnapshotAsync(string casePath, CancellationToken cancellationToken)
    {
        var snapshotPath = Path.Combine(casePath, "network_snapshot.json");
        var connections = new List<NetworkConnectionInfo>();

        try
        {
            var tcpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
            foreach (var conn in tcpConnections)
            {
                connections.Add(new NetworkConnectionInfo
                {
                    Protocol = "TCP",
                    LocalEndPoint = conn.LocalEndPoint.ToString(),
                    RemoteEndPoint = conn.RemoteEndPoint.ToString(),
                    State = conn.State.ToString(),
                    Timestamp = DateTimeOffset.UtcNow
                });
            }

            var tcpListeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
            foreach (var listener in tcpListeners)
            {
                connections.Add(new NetworkConnectionInfo
                {
                    Protocol = "TCP",
                    LocalEndPoint = listener.ToString(),
                    State = "LISTENING",
                    Timestamp = DateTimeOffset.UtcNow
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "IncidentResponse: Network snapshot collection failed");
        }

        var json = JsonSerializer.Serialize(connections, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(snapshotPath, json, cancellationToken);

        return snapshotPath;
    }

    /// <summary>
    /// Copies attacker binaries to evidence folder.
    /// </summary>
    private Task<string> CopyAttackerBinariesAsync(
        List<QuarantinedFileInfo> quarantinedFiles,
        string casePath,
        CancellationToken cancellationToken)
    {
        var binariesPath = Path.Combine(casePath, "binaries");
        Directory.CreateDirectory(binariesPath);

        foreach (var file in quarantinedFiles)
        {
            try
            {
                if (File.Exists(file.QuarantinePath))
                {
                    var destPath = Path.Combine(binariesPath, Path.GetFileName(file.QuarantinePath));
                    File.Copy(file.QuarantinePath, destPath, true);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "IncidentResponse: Failed to copy binary {File}", file.QuarantinePath);
            }
        }

        return Task.FromResult(binariesPath);
    }

    /// <summary>
    /// Collects process tree snapshot.
    /// </summary>
    private async Task<string> CollectProcessTreeSnapshotAsync(int rootPid, string casePath, CancellationToken cancellationToken)
    {
        var treePath = Path.Combine(casePath, "process_tree.json");
        var processes = new List<ProcessSnapshot>();

        try
        {
            var allProcesses = Process.GetProcesses();
            foreach (var proc in allProcesses)
            {
                try
                {
                    int parentPid = GetParentProcessId(proc.Id);
                    string? imagePath = null;
                    try { imagePath = proc.MainModule?.FileName; } catch { }

                    processes.Add(new ProcessSnapshot
                    {
                        ProcessId = proc.Id,
                        ProcessName = proc.ProcessName,
                        ParentProcessId = parentPid,
                        ImagePath = imagePath,
                        StartTime = proc.StartTime,
                        CommandLine = GetCommandLine(proc.Id)
                    });
                }
                catch { /* Process may have exited */ }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "IncidentResponse: Process tree collection failed");
        }

        var json = JsonSerializer.Serialize(processes, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(treePath, json, cancellationToken);

        return treePath;
    }

    private string CalculateSeverity(DetectionEvent detection)
    {
        return detection.Confidence switch
        {
            >= 0.95 => "CRITICAL",
            >= 0.85 => "HIGH",
            >= 0.70 => "MEDIUM",
            _ => "LOW"
        };
    }

    private List<string> GetRecommendedActions(DetectionEvent detection, ChainTraceResult? chainTrace)
    {
        var actions = new List<string>();

        if (detection.RuleName.Contains("credential", StringComparison.OrdinalIgnoreCase))
        {
            actions.Add("Reset credentials for affected accounts immediately");
            actions.Add("Review authentication logs for lateral movement");
            actions.Add("Consider forcing password reset for all domain users");
        }

        if (detection.RuleName.Contains("ransomware", StringComparison.OrdinalIgnoreCase))
        {
            actions.Add("ISOLATE AFFECTED SYSTEMS IMMEDIATELY");
            actions.Add("Check backup integrity and restore if needed");
            actions.Add("Review file share access logs");
        }

        if (detection.RuleName.Contains("c2", StringComparison.OrdinalIgnoreCase) ||
            detection.RuleName.Contains("beacon", StringComparison.OrdinalIgnoreCase))
        {
            actions.Add("Block identified C2 IPs at firewall");
            actions.Add("Review proxy and DNS logs for additional C2 channels");
            actions.Add("Check for additional compromised hosts communicating with same C2");
        }

        if (chainTrace != null)
        {
            actions.Add($"Review quarantined files in: {chainTrace.QuarantinedFiles.Count} files captured");
            actions.Add($"Review process tree: {chainTrace.AllChainProcesses.Count} processes in chain");
        }

        actions.Add("Preserve all evidence in the case folder");
        actions.Add("Review full event timeline for additional indicators");

        return actions;
    }

    private List<IndicatorOfCompromise> ExtractIOCs(IncidentEvidence evidence, ChainTraceResult? chainTrace)
    {
        var iocs = new List<IndicatorOfCompromise>();

        // File hash
        if (chainTrace?.QuarantinedFiles.FirstOrDefault() is {} quarantinedFile)
        {
            iocs.Add(new IndicatorOfCompromise
            {
                Type = "FileHash_SHA256",
                Value = quarantinedFile.FileHash,
                Context = "Quarantined attacker executable"
            });
        }

        // Network indicators from detection metadata
        if (evidence.Detection.Metadata.TryGetValue("RemoteAddress", out var remoteAddr))
        {
            iocs.Add(new IndicatorOfCompromise
            {
                Type = "IP_Address",
                Value = remoteAddr,
                Context = "C2 communication endpoint"
            });
        }

        if (evidence.Detection.Metadata.TryGetValue("domain", out var domain))
        {
            iocs.Add(new IndicatorOfCompromise
            {
                Type = "Domain",
                Value = domain,
                Context = "C2 domain"
            });
        }

        // Process names
        iocs.Add(new IndicatorOfCompromise
        {
            Type = "Process_Name",
            Value = evidence.Detection.ProcessName,
            Context = "Malicious process name"
        });

        // Technique
        if (evidence.Detection.Metadata.TryGetValue("technique", out var technique))
        {
            iocs.Add(new IndicatorOfCompromise
            {
                Type = "MITRE_ATT&CK",
                Value = technique,
                Context = "Attack technique"
            });
        }

        return iocs;
    }

    private string GenerateHumanReadableSummary(IncidentTicket ticket)
    {
        var sb = new StringBuilder();

        sb.AppendLine("═══════════════════════════════════════════════════════════════");
        sb.AppendLine("                    INCIDENT RESPONSE TICKET");
        sb.AppendLine("═══════════════════════════════════════════════════════════════");
        sb.AppendLine();
        sb.AppendLine($"Case ID:        {ticket.CaseId}");
        sb.AppendLine($"Generated:      {ticket.GeneratedAt:yyyy-MM-dd HH:mm:ss UTC}");
        sb.AppendLine($"Severity:       {ticket.Severity}");
        sb.AppendLine();
        sb.AppendLine("───────────────────────────────────────────────────────────────");
        sb.AppendLine("DETECTION DETAILS");
        sb.AppendLine("───────────────────────────────────────────────────────────────");
        sb.AppendLine($"Rule:           {ticket.Detection.RuleName}");
        sb.AppendLine($"Process:        {ticket.Detection.ProcessName} (PID {ticket.Detection.ProcessId})");
        sb.AppendLine($"Confidence:      {ticket.Detection.Confidence:P0}");
        sb.AppendLine($"Tier:            {ticket.Detection.Tier}");
        sb.AppendLine($"Timestamp:       {ticket.Detection.Timestamp:yyyy-MM-dd HH:mm:ss UTC}");
        sb.AppendLine();
        sb.AppendLine("Evidence:");
        sb.AppendLine($"  {ticket.Detection.Evidence}");
        sb.AppendLine();
        sb.AppendLine("Reasoning:");
        sb.AppendLine($"  {ticket.Detection.Reasoning}");
        sb.AppendLine();

        if (ticket.ChainTrace != null)
        {
            sb.AppendLine("───────────────────────────────────────────────────────────────");
            sb.AppendLine("CHAIN TRACE RESULTS");
            sb.AppendLine("───────────────────────────────────────────────────────────────");
            sb.AppendLine($"Attack Root:     {ticket.ChainTrace.AttackRoot?.ProcessName} (PID {ticket.ChainTrace.AttackRoot?.ProcessId})");
            sb.AppendLine($"Chain Length:    {ticket.ChainTrace.AllChainProcesses.Count} processes");
            sb.AppendLine($"Killed:          {ticket.ChainTrace.KilledProcesses.Count} processes");
            sb.AppendLine($"Quarantined:     {ticket.ChainTrace.QuarantinedFiles.Count} files");
            sb.AppendLine($"Persistence:     {ticket.ChainTrace.PersistenceRemoved.Count} items removed");
            sb.AppendLine($"Blocked IPs:     {ticket.ChainTrace.BlockedIps.Count} firewall rules");
            sb.AppendLine();
        }

        sb.AppendLine("───────────────────────────────────────────────────────────────");
        sb.AppendLine("INDICATORS OF COMPROMISE (IOCs)");
        sb.AppendLine("───────────────────────────────────────────────────────────────");
        foreach (var ioc in ticket.IndicatorsOfCompromise)
        {
            sb.AppendLine($"  [{ioc.Type}] {ioc.Value}");
            sb.AppendLine($"    Context: {ioc.Context}");
        }
        sb.AppendLine();

        sb.AppendLine("───────────────────────────────────────────────────────────────");
        sb.AppendLine("RECOMMENDED ACTIONS");
        sb.AppendLine("───────────────────────────────────────────────────────────────");
        for (int i = 0; i < ticket.RecommendedActions.Count; i++)
        {
            sb.AppendLine($"  {i + 1}. {ticket.RecommendedActions[i]}");
        }
        sb.AppendLine();

        sb.AppendLine("───────────────────────────────────────────────────────────────");
        sb.AppendLine("EVIDENCE COLLECTED");
        sb.AppendLine("───────────────────────────────────────────────────────────────");
        sb.AppendLine($"  Case Folder:      {ticket.Evidence.CasePath}");
        if (ticket.Evidence.MemoryDumpPath != null)
            sb.AppendLine($"  Memory Dump:      {Path.GetFileName(ticket.Evidence.MemoryDumpPath)}");
        if (ticket.Evidence.ModuleInventoryPath != null)
            sb.AppendLine($"  Module Inventory: {Path.GetFileName(ticket.Evidence.ModuleInventoryPath)}");
        if (ticket.Evidence.NetworkSnapshotPath != null)
            sb.AppendLine($"  Network Snapshot: {Path.GetFileName(ticket.Evidence.NetworkSnapshotPath)}");
        if (ticket.Evidence.BinaryCopiesPath != null)
            sb.AppendLine($"  Binary Copies:    {ticket.Evidence.BinaryCopiesPath}");
        if (ticket.Evidence.ProcessTreePath != null)
            sb.AppendLine($"  Process Tree:     {Path.GetFileName(ticket.Evidence.ProcessTreePath)}");
        sb.AppendLine();

        sb.AppendLine("───────────────────────────────────────────────────────────────");
        sb.AppendLine($"Collection Duration: {(ticket.Evidence.CollectionEndTime - ticket.Evidence.CollectionStartTime).TotalSeconds:F1} seconds");
        sb.AppendLine($"Status:              {(ticket.Evidence.Success ? "SUCCESS" : "PARTIAL/FAILED")}");
        sb.AppendLine("═══════════════════════════════════════════════════════════════");

        return sb.ToString();
    }

    // Helper methods
    private int GetParentProcessId(int pid)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (var obj in searcher.Get())
            {
                return Convert.ToInt32(obj["ParentProcessId"]);
            }
        }
        catch { }
        return 0;
    }

    private string GetCommandLine(int pid)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (var obj in searcher.Get())
            {
                return obj["CommandLine"]?.ToString() ?? "";
            }
        }
        catch { }
        return "";
    }

    /// <summary>
    /// Applies restrictive ACL to a directory (SYSTEM + Administrators only).
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private void ApplyRestrictiveAcl(string path)
    {
        try
        {
            var systemSid = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
            var adminsSid = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);

            var dirInfo = new DirectoryInfo(path);
            var sec = dirInfo.GetAccessControl();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            foreach (System.Security.AccessControl.FileSystemAccessRule rule in
                sec.GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier)))
                sec.RemoveAccessRule(rule);

            sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                systemSid, System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                System.Security.AccessControl.PropagationFlags.None,
                System.Security.AccessControl.AccessControlType.Allow));

            sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                adminsSid, System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                System.Security.AccessControl.PropagationFlags.None,
                System.Security.AccessControl.AccessControlType.Allow));

            dirInfo.SetAccessControl(sec);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "IncidentResponse: Failed to apply restrictive ACL to {Path}", path);
        }
    }
}

/// <summary>
/// Represents collected incident evidence.
/// </summary>
public sealed class IncidentEvidence
{
    public string CaseId { get; set; } = "";
    public string CasePath { get; set; } = "";
    public DetectionEvent Detection { get; set; } = null!;
    public DateTimeOffset CollectionStartTime { get; set; }
    public DateTimeOffset CollectionEndTime { get; set; }
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }

    // Evidence files
    public string? MemoryDumpPath { get; set; }
    public string? ModuleInventoryPath { get; set; }
    public string? NetworkSnapshotPath { get; set; }
    public string? BinaryCopiesPath { get; set; }
    public string? ProcessTreePath { get; set; }
    public string? IncidentTicketPath { get; set; }
}

/// <summary>
/// Represents an incident ticket.
/// </summary>
public sealed class IncidentTicket
{
    public string CaseId { get; set; } = "";
    public DateTimeOffset GeneratedAt { get; set; }
    public DetectionEvent Detection { get; set; } = null!;
    public IncidentEvidence Evidence { get; set; } = null!;
    public ChainTraceResult? ChainTrace { get; set; }
    public string Severity { get; set; } = "";
    public List<string> RecommendedActions { get; set; } = new();
    public List<IndicatorOfCompromise> IndicatorsOfCompromise { get; set; } = new();
}

/// <summary>
/// Represents an indicator of compromise.
/// </summary>
public sealed class IndicatorOfCompromise
{
    public string Type { get; set; } = "";
    public string Value { get; set; } = "";
    public string Context { get; set; } = "";
}

/// <summary>
/// Module information for inventory.
/// </summary>
public sealed class ModuleInfo
{
    public string? ModuleName { get; set; }
    public string? FileName { get; set; }
    public string? BaseAddress { get; set; }
    public int ModuleMemorySize { get; set; }
    public string? FileVersion { get; set; }
    public string? ProductName { get; set; }
    public string? CompanyName { get; set; }
    public string? Sha256Hash { get; set; }
}

/// <summary>
/// Network connection information.
/// </summary>
public sealed class NetworkConnectionInfo
{
    public string? Protocol { get; set; }
    public string? LocalEndPoint { get; set; }
    public string? RemoteEndPoint { get; set; }
    public string? State { get; set; }
    public DateTimeOffset Timestamp { get; set; }
}

/// <summary>
/// Process snapshot information.
/// </summary>
public sealed class ProcessSnapshot
{
    public int ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public int ParentProcessId { get; set; }
    public string? ImagePath { get; set; }
    public DateTime StartTime { get; set; }
    public string? CommandLine { get; set; }
}

