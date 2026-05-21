using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Logging;

/// <summary>
/// Structured logging extensions for consistent operation context tracking.
///
/// Usage:
///   using (_logger.BeginDetectionScope("LsassAccessRule", processId: 1234))
///   {
///       // All logs in this scope include detection context
///   }
///
///   using (_logger.BeginResponseScope("Kill", processId: 1234, ruleName: "LsassAccessRule"))
///   {
///       // All logs in this scope include response context
///   }
/// </summary>
public static class StructuredLoggingExtensions
{
    /// <summary>
    /// Creates a logging scope for detection operations.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    /// <param name="ruleName">The detection rule name.</param>
    /// <param name="processId">The target process ID.</param>
    /// <param name="processName">The target process name.</param>
    /// <returns>A disposable scope.</returns>
    public static IDisposable? BeginDetectionScope(this ILogger logger, string ruleName, 
        int processId = 0, string? processName = null)
    {
        return logger.BeginScope(new Dictionary<string, object?>
        {
            ["Operation"] = "Detection",
            ["RuleName"] = ruleName,
            ["ProcessId"] = processId,
            ["ProcessName"] = processName
        });
    }

    /// <summary>
    /// Creates a logging scope for response operations.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    /// <param name="action">The response action (Kill, Quarantine, Block, etc.).</param>
    /// <param name="processId">The target process ID.</param>
    /// <param name="ruleName">The triggering rule name.</param>
    /// <returns>A disposable scope.</returns>
    public static IDisposable? BeginResponseScope(this ILogger logger, string action, 
        int processId = 0, string? ruleName = null)
    {
        return logger.BeginScope(new Dictionary<string, object?>
        {
            ["Operation"] = "Response",
            ["Action"] = action,
            ["ProcessId"] = processId,
            ["TriggerRule"] = ruleName
        });
    }

    /// <summary>
    /// Creates a logging scope for deception operations.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    /// <param name="tacticName">The deception tactic name.</param>
    /// <param name="processId">The target process ID.</param>
    /// <param name="category">The attack category.</param>
    /// <returns>A disposable scope.</returns>
    public static IDisposable? BeginDeceptionScope(this ILogger logger, string tacticName, 
        int processId = 0, string? category = null)
    {
        return logger.BeginScope(new Dictionary<string, object?>
        {
            ["Operation"] = "Deception",
            ["Tactic"] = tacticName,
            ["ProcessId"] = processId,
            ["Category"] = category
        });
    }

    /// <summary>
    /// Creates a logging scope for monitor operations.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    /// <param name="monitorName">The monitor name.</param>
    /// <param name="scanCycle">The current scan cycle number.</param>
    /// <returns>A disposable scope.</returns>
    public static IDisposable? BeginMonitorScope(this ILogger logger, string monitorName, 
        int scanCycle = 0)
    {
        return logger.BeginScope(new Dictionary<string, object?>
        {
            ["Operation"] = "Monitor",
            ["Monitor"] = monitorName,
            ["ScanCycle"] = scanCycle
        });
    }

    /// <summary>
    /// Creates a logging scope for quarantine operations.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    /// <param name="action">The quarantine action (Quarantine, Restore, Purge).</param>
    /// <param name="filePath">The file path being operated on.</param>
    /// <returns>A disposable scope.</returns>
    public static IDisposable? BeginQuarantineScope(this ILogger logger, string action, 
        string? filePath = null)
    {
        return logger.BeginScope(new Dictionary<string, object?>
        {
            ["Operation"] = "Quarantine",
            ["Action"] = action,
            ["FilePath"] = filePath
        });
    }

    /// <summary>
    /// Creates a logging scope for threat intelligence reporting.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    /// <param name="platform">The reporting platform (AbuseIPDB, URLhaus, MalwareBazaar).</param>
    /// <param name="indicator">The indicator being reported (IP, hash, URL).</param>
    /// <returns>A disposable scope.</returns>
    public static IDisposable? BeginThreatReportScope(this ILogger logger, string platform, 
        string? indicator = null)
    {
        return logger.BeginScope(new Dictionary<string, object?>
        {
            ["Operation"] = "ThreatReport",
            ["Platform"] = platform,
            ["Indicator"] = indicator
        });
    }

    /// <summary>
    /// Creates a logging scope for self-protection operations.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    /// <param name="check">The self-protection check being performed.</param>
    /// <returns>A disposable scope.</returns>
    public static IDisposable? BeginSelfProtectionScope(this ILogger logger, string check)
    {
        return logger.BeginScope(new Dictionary<string, object?>
        {
            ["Operation"] = "SelfProtection",
            ["Check"] = check
        });
    }

    /// <summary>
    /// Creates a logging scope for DLL unload operations.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    /// <param name="processId">The target process ID.</param>
    /// <param name="dllName">The DLL being unloaded.</param>
    /// <param name="reason">The reason for unloading.</param>
    /// <returns>A disposable scope.</returns>
    public static IDisposable? BeginDllUnloadScope(this ILogger logger, int processId, 
        string dllName, string? reason = null)
    {
        return logger.BeginScope(new Dictionary<string, object?>
        {
            ["Operation"] = "DllUnload",
            ["ProcessId"] = processId,
            ["DllName"] = dllName,
            ["Reason"] = reason
        });
    }

    /// <summary>
    /// Creates a logging scope for health check operations.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    /// <param name="component">The component being checked.</param>
    /// <returns>A disposable scope.</returns>
    public static IDisposable? BeginHealthCheckScope(this ILogger logger, string component)
    {
        return logger.BeginScope(new Dictionary<string, object?>
        {
            ["Operation"] = "HealthCheck",
            ["Component"] = component
        });
    }
}