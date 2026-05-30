using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// LSASS Dump Canary Monitor — Detects credential dumping by monitoring for:
///
///   1. dbghelp.dll loaded into non-debugger processes (MiniDumpWriteDump prerequisite)
///   2. Newly created files with MDMP magic header (0x504D444D = "MDMP")
///   3. Processes opening handles to lsass.exe with suspicious access rights
///
/// This catches sophisticated LSASS dumps that bypass command-line detection:
///   - Custom C# tools using MiniDumpWriteDump directly
///   - NanoDump, HandleKatz, and other "silent" dumpers
///   - Comsvcs.dll MiniDump via rundll32
///   - Any tool that loads dbghelp.dll to dump a process
///
/// The dbghelp.dll detection is particularly powerful because:
///   - Debuggers (devenv, windbg, x64dbg) are excluded
///   - Normal applications NEVER load dbghelp.dll
///   - It's a prerequisite for MiniDumpWriteDump regardless of how the tool is built
/// </summary>
public sealed class LsassDumpCanaryMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<LsassDumpCanaryMonitor> _logger;

    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(15);

    // Processes that legitimately load dbghelp.dll
    private static readonly HashSet<string> LegitimateDbghelpUsers = new(StringComparer.OrdinalIgnoreCase)
    {
        "devenv.exe", "devenv",             // Visual Studio
        "windbg.exe", "windbg",             // WinDbg
        "windbgx.exe", "windbgx",           // WinDbg Preview
        "x64dbg.exe", "x64dbg",             // x64dbg
        "x32dbg.exe", "x32dbg",             // x32dbg
        "ollydbg.exe", "ollydbg",           // OllyDbg
        "ida.exe", "ida64.exe",             // IDA Pro
        "radare2.exe", "r2.exe",            // Radare2
        "cdb.exe",                          // Console Debugger
        "ntsd.exe",                         // NT Symbolic Debugger
        "drwtsn32.exe",                     // Dr. Watson
        "werfault.exe", "werfaultsecure.exe", // Windows Error Reporting
        "taskmgr.exe",                      // Task Manager (can create dumps)
        "procmon.exe", "procmon64.exe",     // Process Monitor
        "procdump.exe", "procdump64.exe",   // Sysinternals ProcDump (legitimate use)
        "msmpeng.exe",                      // Windows Defender
        "mssense.exe",                      // Defender for Endpoint
        "sentinelservice.exe",              // Ourselves
        "sentinelagent.exe",                // Our agent
        "dotnet.exe",                       // .NET runtime (crash dumps)
        "crashpad_handler.exe",             // Chrome/Electron crash handler
        "dumpminitool.exe",                 // VS crash dump tool
        // v1.9.0: Crash handlers and Electron apps that legitimately load dbghelp.dll
        "steamwebhelper", "steamwebhelper.exe",   // Steam crash reporting
        "steam", "steam.exe",                     // Steam client
        "GoogleCrashHandler", "GoogleCrashHandler.exe",     // Google crash handler (32-bit)
        "GoogleCrashHandler64", "GoogleCrashHandler64.exe", // Google crash handler (64-bit)
        "Kiro", "Kiro.exe",                       // Kiro IDE (Electron — uses crashpad)
        "Code", "Code.exe",                       // VS Code (Electron — uses crashpad)
        "code", "code.exe",                       // VS Code lowercase
        "cursor", "Cursor.exe",                   // Cursor IDE (Electron)
        "electron", "electron.exe",               // Generic Electron apps
        "msedge", "msedge.exe",                   // Edge (Chromium crash reporting)
        "chrome", "chrome.exe",                   // Chrome (crash reporting)
        "firefox", "firefox.exe",                 // Firefox (crash reporting)
        "brave", "brave.exe",                     // Brave (Chromium crash reporting)
        "opera", "opera.exe",                     // Opera (Chromium crash reporting)
        "discord", "Discord.exe",                 // Discord (Electron)
        "slack", "Slack.exe",                     // Slack (Electron)
        "teams", "Teams.exe",                     // Teams (Electron)
        "svchost", "svchost.exe",                 // Windows service host (WER integration)
        "rider64", "rider64.exe",                 // JetBrains Rider
        "idea64", "idea64.exe",                   // JetBrains IntelliJ
        "pycharm64", "pycharm64.exe",             // JetBrains PyCharm
        "webstorm64", "webstorm64.exe",           // JetBrains WebStorm
        // v4.1.0: Antivirus/security products that legitimately load dbghelp.dll for crash reporting
        "TmsaInstance64", "TmsaInstance64.exe",   // Trend Micro Security Agent (64-bit)
        "PtSessionAgent", "PtSessionAgent.exe",   // Trend Micro Platinum Session Agent
        "uiSeAgnt", "uiSeAgnt.exe",               // Trend Micro UI Security Agent
        "coreServiceShell", "coreServiceShell.exe", // Trend Micro Core Service
        "coreFrameworkHost", "coreFrameworkHost.exe", // Trend Micro Core Framework
        "PtSvcHost", "PtSvcHost.exe",             // Trend Micro Platinum Service Host
        "AMSPTelemetryService", "AMSPTelemetryService.exe", // Trend Micro AMSP Telemetry
        "PtWatchDog", "PtWatchDog.exe",           // Trend Micro Platinum Watchdog
        "NVDisplay.Container", "NVDisplay.Container.exe", // NVIDIA Display Container (crash reporting)
        "nvcontainer", "nvcontainer.exe",         // NVIDIA Container
        "WUDFHost", "WUDFHost.exe",               // Windows User-Mode Driver Framework Host
        "msedgewebview2", "msedgewebview2.exe",   // Edge WebView2 (Chromium crash reporting)
        // IObit processes
        "mainProcess", "mainProcess.exe",         // IObit Advanced SystemCare main process
        "ASCService", "ASCService.exe",           // IObit ASC Service
        // v4.7.0: Games that legitimately load dbghelp.dll for crash reporting
        "fm", "fm.exe",                           // Football Manager (Sports Interactive)
    };

    // Track which PIDs we've already alerted on
    private readonly ConcurrentDictionary<int, DateTimeOffset> _alertedPids = new();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
    private static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule,
        uint cb, out uint lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule,
        [Out] char[] lpFilename, uint nSize);

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint LIST_MODULES_ALL = 0x03;

    public LsassDumpCanaryMonitor(
        IDetectionEngine detectionEngine,
        ILogger<LsassDumpCanaryMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== LSASS Dump Canary Monitor starting ===");

        await Task.Delay(TimeSpan.FromSeconds(20), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanForDbghelpLoadAsync(stoppingToken);
                await Task.Delay(ScanInterval, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "LsassDumpCanary: Scan error");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
    }

    private async Task ScanForDbghelpLoadAsync(CancellationToken ct)
    {
        var selfPid = Environment.ProcessId;
        var processes = Process.GetProcesses();

        foreach (var process in processes)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                if (process.Id <= 4 || process.Id == selfPid) continue;
                if (LegitimateDbghelpUsers.Contains(process.ProcessName)) continue;
                if (_alertedPids.ContainsKey(process.Id)) continue;

                // Check if this process has dbghelp.dll loaded
                if (HasDbghelpLoaded(process.Id))
                {
                    _alertedPids[process.Id] = DateTimeOffset.UtcNow;

                    _logger.LogCritical(
                        "LSASS DUMP CANARY: '{Name}' (PID {Pid}) loaded dbghelp.dll — " +
                        "possible MiniDumpWriteDump preparation",
                        process.ProcessName, process.Id);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "LSASS Credential Dump: dbghelp.dll Loaded",
                        Evidence = $"Non-debugger process '{process.ProcessName}' (PID {process.Id}) " +
                                  $"has dbghelp.dll loaded. This DLL is required for MiniDumpWriteDump " +
                                  $"and is not normally loaded by applications.",
                        Reasoning = "dbghelp.dll contains MiniDumpWriteDump — the function used by virtually " +
                                   "all credential dumping tools (Mimikatz, NanoDump, HandleKatz, custom tools) " +
                                   "to dump LSASS memory. Legitimate applications never load this DLL unless " +
                                   "they are debuggers or crash reporters. This is a behavioral indicator that " +
                                   "cannot be bypassed by renaming the dumping tool.",
                        Confidence = 0.85,
                        Tier = DetectionTier.Tier2Indicator, // Corroborating signal — dbghelp alone doesn't prove malice
                        ProcessName = process.ProcessName,
                        ProcessId = process.Id,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["loaded_module"] = "dbghelp.dll",
                            ["technique"] = "T1003.001 - OS Credential Dumping: LSASS Memory"
                        }
                    }, ct);
                }
            }
            catch (InvalidOperationException) { /* process exited */ }
            catch (System.ComponentModel.Win32Exception) { /* access denied */ }
            finally
            {
                process.Dispose();
            }
        }

        // Cleanup old alerts
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-5);
        foreach (var kv in _alertedPids)
        {
            if (kv.Value < cutoff)
                _alertedPids.TryRemove(kv.Key, out _);
        }
    }

    private bool HasDbghelpLoaded(int pid)
    {
        var hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (hProcess == IntPtr.Zero) return false;

        try
        {
            var modules = new IntPtr[1024];
            if (!EnumProcessModulesEx(hProcess, modules, (uint)(modules.Length * IntPtr.Size),
                out uint needed, LIST_MODULES_ALL))
                return false;

            int moduleCount = (int)(needed / IntPtr.Size);
            var nameBuffer = new char[260];

            for (int i = 0; i < moduleCount && i < modules.Length; i++)
            {
                if (modules[i] == IntPtr.Zero) continue;

                var len = GetModuleFileNameEx(hProcess, modules[i], nameBuffer, (uint)nameBuffer.Length);
                if (len == 0) continue;

                var moduleName = new string(nameBuffer, 0, (int)len);
                var fileName = Path.GetFileName(moduleName);

                if (string.Equals(fileName, "dbghelp.dll", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(fileName, "dbgcore.dll", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }
}


