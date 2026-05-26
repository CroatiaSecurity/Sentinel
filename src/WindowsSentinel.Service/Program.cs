using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core;
using WindowsSentinel.Core.Deception;
using WindowsSentinel.Core.Monitors;
using WindowsSentinel.Core.SelfProtection;

// ─────────────────────────────────────────────────────────────────────────────
//  Windows Sentinel — Windows Service (SYSTEM)
//  Runs as LocalSystem and launches Agent into user session.
//  Logs to Windows Event Log and the JSONL file.
//  Author : Gorstak | gorstak.eu | github.com/CroatiaSecurity/Sentinel
//
//  RESPONSE MODES:
//    ActiveResponse: false  → Monitor-only. All detections are logged; nothing is killed.
//                             Use this during initial deployment to tune false positives.
//    ActiveResponse: true   → Active response. Malicious/Critical verdicts trigger
//                             process termination + quarantine + persistence removal.
//                             Only fires when confidence ≥ 0.90 OR 2+ corroborating sources.
//
//  Set "Sentinel:ActiveResponse" in appsettings.json to control the mode.
// ─────────────────────────────────────────────────────────────────────────────

// Apply DLL-search-order + image-load hardening BEFORE we touch any managed code
// path that might trigger a delay-loaded native dependency. This closes the
// SYSTEM-context DLL sideload bypass demonstrated against 0.3.x.
//
// Strict mode (refuse to start when install dir is user-writable) is opt-in.
// Set SENTINEL_STRICT_INSTALL_DIR=1 to enable (recommended for production).
// Default is to log a warning and continue — service availability takes priority.
{
    var strict = string.Equals(
        Environment.GetEnvironmentVariable("SENTINEL_STRICT_INSTALL_DIR"),
        "1", StringComparison.Ordinal);
    if (!ProcessHardening.ApplyOrFail(logger: null, refuseUnsafeInstallDir: strict))
    {
        try
        {
            using var bootLog = new System.Diagnostics.EventLog("Application");
            bootLog.Source = "Windows Sentinel";
            bootLog.WriteEntry(
                "Refusing to start: install directory is user-writable (SENTINEL_STRICT_INSTALL_DIR=1).",
                System.Diagnostics.EventLogEntryType.Error, 1003);
        }
        catch { }
        return;
    }
}

try
{
    var builder = Host.CreateApplicationBuilder(args);

    // ── Data directory - use CommonApplicationData for SYSTEM service ───────────
    var dataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WindowsSentinel");

    Directory.CreateDirectory(dataDir);

    // ── Logging: Event Log + Debug output ────────────────────────────────────────
    // v1.4.0: Reduced Event Log flooding by raising EventLog minimum to Warning.
    // Information-level telemetry still goes to the JSONL event log file.
    // Only Warning/Error/Critical reach Windows Event Viewer now.
    builder.Logging.ClearProviders();
    builder.Logging.AddEventLog(settings =>
    {
        settings.SourceName = "Windows Sentinel";
        settings.LogName    = "Application";
        settings.Filter = (category, level) => level >= LogLevel.Warning;
    });

    // ── Read active response setting from configuration ──────────────────────────
    // Default is false (monitor-only) — set to true in appsettings.json to enable.
    // ACTIVE RESPONSE: default ON. Sentinel ships in killing mode now; only
    // explicit "ActiveResponse: false" in appsettings.json puts it back into
    // monitor-only mode (for FP-tuning during initial deployment).
    var activeResponse = builder.Configuration.GetValue<bool>("Sentinel:ActiveResponse", defaultValue: true);

    // ── Sentinel services ────────────────────────────────────────────────────────
    string logPath = Path.Combine(dataDir, "events.jsonl");

    builder.Services.AddWindowsSentinel(
        logPath: logPath,
        activeResponseEnabled: activeResponse,
        watchPath: null);

    // ── Windows Service host ─────────────────────────────────────────────────────
    builder.Services.AddWindowsService(options =>
    {
        options.ServiceName = "Windows Sentinel";
    });

    // Increase service startup timeout — Sentinel has 50+ services to initialize
    // and ETW session creation can be slow on first boot.
    builder.Services.Configure<Microsoft.Extensions.Hosting.HostOptions>(options =>
    {
        options.StartupTimeout = TimeSpan.FromSeconds(120);
    });

    var host = builder.Build();

    // Re-run hardening with the real logger so any non-fatal warnings reach EventLog.
    var startupLogger = host.Services.GetRequiredService<ILoggerFactory>()
        .CreateLogger("WindowsSentinel.ProcessHardening");
    ProcessHardening.ApplyOrFail(startupLogger, refuseUnsafeInstallDir: false);

    // v3.9.0: Clean up any leftover sparse file bombs from previous runs or older versions.
    // These 500GB sparse files were deployed during pre-kill deception but never cleaned up
    // in versions prior to 3.9.0. They consume zero actual disk space but confuse users
    // when they see "500GB" files in Explorer.
    var cleanupLogger = host.Services.GetRequiredService<ILoggerFactory>()
        .CreateLogger("WindowsSentinel.DeceptionCleanup");
    FileTrapTactic.CleanupSparseFileBombs(cleanupLogger);

    // v4.0.0: Clean up pre-existing malicious persistent routes on startup.
    // Addresses the attack pattern where hundreds of /32 host routes are planted
    // to redirect traffic through a local MITM interceptor.
    var routeLogger = host.Services.GetRequiredService<ILoggerFactory>()
        .CreateLogger("WindowsSentinel.RouteCleanup");
    try
    {
        var routeMonitor = host.Services.GetRequiredService<WindowsSentinel.Core.Monitors.RouteTableMonitor>();
        var removedRoutes = routeMonitor.CleanupExistingMaliciousRoutes();
        if (removedRoutes > 0)
        {
            routeLogger.LogCritical(
                "[STARTUP] v4.0.0: Removed {Count} malicious persistent /32 host routes " +
                "that were planted for traffic interception.", removedRoutes);
        }
    }
    catch (Exception ex)
    {
        routeLogger.LogWarning(ex, "[STARTUP] Route cleanup failed (non-fatal)");
    }

    await host.RunAsync();
}
catch (Exception ex)
{
    // Log to Event Log directly if service fails to start
    try
    {
        using var eventLog = new System.Diagnostics.EventLog("Application");
        eventLog.Source = "Windows Sentinel";
        eventLog.WriteEntry($"Service failed to start: {ex}", System.Diagnostics.EventLogEntryType.Error, 1001);
    }
    catch { /* Last resort - can't do anything */ }
    throw;
}


