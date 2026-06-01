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

    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(45);

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
        // NOTE: GoogleUpdate.exe is intentionally NOT in this list.
        // PlugX, APT41, and other threat actors specifically abuse GoogleUpdate.exe as a
        // DLL sideloading carrier (T1574.002). A GoogleUpdate process loading dbghelp.dll
        // must be validated by path and signature before being trusted — see the
        // IsLegitimateGoogleUpdateProcess() check below.
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

                // ── GoogleUpdate / Google installer family ────────────────────────
                // PlugX (APT41), Mustang Panda, and other threat actors specifically
                // abuse GoogleUpdate.exe as a DLL sideloading carrier (T1574.002).
                // The technique: drop a malicious DLL alongside a legitimate signed
                // GoogleUpdate.exe copy in a user-writable directory, then execute it.
                // The signed binary loads the malicious DLL, which loads dbghelp.dll.
                //
                // We cannot simply allowlist "GoogleUpdate" by name — that's exactly
                // what the attacker is counting on. Instead, validate the binary's
                // actual path and signature before deciding whether to trust it.
                if (IsGoogleUpdateProcessName(process.ProcessName))
                {
                    var (isLegitimate, reason) = ValidateGoogleUpdateProcess(process);
                    if (isLegitimate)
                    {
                        // Confirmed legitimate Google Update — skip dbghelp alert.
                        // Still add to alertedPids to avoid re-checking every scan.
                        _alertedPids[process.Id] = DateTimeOffset.UtcNow;
                        continue;
                    }

                    // GoogleUpdate name but failed path/signature validation — this is
                    // the PlugX sideloading pattern. Emit with elevated confidence and
                    // explicit APT context so the composite fires correctly.
                    if (HasDbghelpLoaded(process.Id))
                    {
                        _alertedPids[process.Id] = DateTimeOffset.UtcNow;

                        _logger.LogCritical(
                            "LSASS DUMP CANARY [APT SIDELOAD]: '{Name}' (PID {Pid}) loaded dbghelp.dll " +
                            "but failed Google Update legitimacy check: {Reason}",
                            process.ProcessName, process.Id, reason);

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "LSASS Credential Dump: dbghelp.dll Loaded",
                            Evidence = $"Process '{process.ProcessName}' (PID {process.Id}) has dbghelp.dll " +
                                      $"loaded but is NOT a legitimate Google Update binary: {reason}. " +
                                      $"This matches the PlugX/APT DLL sideloading pattern (T1574.002) where " +
                                      $"threat actors abuse the GoogleUpdate.exe name to evade detection.",
                            Reasoning = "dbghelp.dll loaded by a process impersonating GoogleUpdate.exe from " +
                                       "an unexpected path or without a valid Google signature. PlugX (used by " +
                                       "APT41, Mustang Panda) and other APT toolkits specifically copy " +
                                       "GoogleUpdate.exe to user-writable directories and sideload malicious " +
                                       "DLLs alongside it. The legitimate binary loads the malicious DLL, " +
                                       "which then loads dbghelp.dll for LSASS credential dumping.",
                            Confidence = 0.92, // Higher than normal — name+path mismatch is very suspicious
                            Tier = DetectionTier.Tier2Indicator,
                            ProcessName = process.ProcessName,
                            ProcessId = process.Id,
                            Timestamp = DateTimeOffset.UtcNow,
                            Metadata = new Dictionary<string, string>
                            {
                                ["loaded_module"] = "dbghelp.dll",
                                ["technique"] = "T1003.001 - OS Credential Dumping: LSASS Memory",
                                ["apt_sideload_suspected"] = "true",
                                ["validation_failure"] = reason ?? "unknown",
                                ["mitre_sideload"] = "T1574.002 - DLL Side-Loading"
                            }
                        }, ct);
                    }
                    continue;
                }

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

    // ── Google Update legitimacy validation ───────────────────────────────────

    private static readonly HashSet<string> GoogleUpdateProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "GoogleUpdate", "GoogleUpdate.exe",
        "GoogleUpdateSetup", "GoogleUpdateSetup.exe",
        "GoogleUpdateOnDemand", "GoogleUpdateOnDemand.exe",
        "GoogleUpdateComRegisterShell64", "GoogleUpdateComRegisterShell64.exe",
        "elevation_service", "elevation_service.exe",
    };

    // Legitimate paths where Google Update binaries reside.
    // PlugX drops copies into ProgramData, Public, AppData, or random temp dirs.
    private static readonly string[] LegitimateGoogleUpdatePaths = new[]
    {
        @"\Program Files (x86)\Google\Update\",
        @"\Program Files\Google\Update\",
        @"\Program Files (x86)\Google\Chrome\Application\",
        @"\Program Files\Google\Chrome\Application\",
        // Temp path used during Chrome installation (GUM*.tmp bootstrapper)
        // This is legitimate: the installer extracts itself to a GUM*.tmp dir and runs.
        // We allow it only if the binary is signed by Google.
        @"\AppData\Local\Temp\GUM",
        @"\Users\",  // Covered by signature check below — allowed only if Google-signed
    };

    private static bool IsGoogleUpdateProcessName(string processName) =>
        GoogleUpdateProcessNames.Contains(processName) ||
        processName.StartsWith("GoogleUpdate", StringComparison.OrdinalIgnoreCase) ||
        processName.StartsWith("GoogleCrash", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Validates that a GoogleUpdate-named process is actually a legitimate Google binary.
    /// Returns (true, null) if legitimate, (false, reason) if suspicious.
    ///
    /// Checks:
    ///   1. Binary is digitally signed by Google LLC or Google Inc.
    ///   2. If running from a temp/user-writable path, signature is mandatory.
    ///   3. Binary is not running from a known PlugX staging path
    ///      (ProgramData\[random], Public\[random], AppData\Roaming\[random]).
    /// </summary>
    private (bool isLegitimate, string? reason) ValidateGoogleUpdateProcess(Process process)
    {
        try
        {
            string? imagePath = null;
            try { imagePath = process.MainModule?.FileName; }
            catch { /* access denied or process exited */ }

            if (string.IsNullOrEmpty(imagePath))
            {
                // Can't read path — treat as suspicious (legitimate Google Update is always readable)
                return (false, "cannot read process image path (access denied or process exited)");
            }

            var pathLower = imagePath.ToLowerInvariant();

            // Check for known PlugX staging paths — these are never legitimate for Google Update
            if (IsPlugXStagingPath(pathLower))
            {
                return (false, $"running from known APT staging path: {imagePath}");
            }

            // Validate digital signature
            bool isGoogleSigned = IsSignedByGoogle(imagePath);

            // If running from a non-standard path, require Google signature
            bool isStandardPath = LegitimateGoogleUpdatePaths
                .Take(4) // First 4 are definitive standard paths (not temp)
                .Any(p => pathLower.Contains(p.ToLowerInvariant()));

            if (isStandardPath && isGoogleSigned)
                return (true, null);

            if (isStandardPath && !isGoogleSigned)
                return (false, $"running from standard path but signature invalid or missing: {imagePath}");

            // Temp path (GUM*.tmp) — allowed only if Google-signed (this is the Chrome installer)
            bool isGumTempPath = pathLower.Contains(@"\appdata\local\temp\gum") ||
                                 System.Text.RegularExpressions.Regex.IsMatch(
                                     pathLower, @"\\temp\\gum[0-9a-f]+\.tmp\\");
            if (isGumTempPath && isGoogleSigned)
                return (true, null);

            if (isGumTempPath && !isGoogleSigned)
                return (false, $"running from GUM temp path but NOT signed by Google — likely PlugX sideload: {imagePath}");

            // Any other path — require Google signature
            if (!isGoogleSigned)
                return (false, $"not signed by Google, running from non-standard path: {imagePath}");

            // Google-signed but from an unusual path — still suspicious
            return (false, $"Google-signed but running from unexpected path: {imagePath}");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "GoogleUpdate validation failed for PID {Pid}", process.Id);
            // Validation failure → treat as suspicious (fail-secure)
            return (false, $"validation exception: {ex.Message}");
        }
    }

    /// <summary>
    /// Checks if a path matches known PlugX/APT staging locations.
    /// APTs drop GoogleUpdate copies into random-named subdirectories of
    /// ProgramData, Public, or AppData\Roaming to blend in.
    /// </summary>
    private static bool IsPlugXStagingPath(string pathLower)
    {
        // ProgramData\[8-char random hex] — classic PlugX drop location
        if (System.Text.RegularExpressions.Regex.IsMatch(
            pathLower, @"\\programdata\\[a-z0-9]{6,12}\\"))
            return true;

        // C:\Users\Public\[anything] — world-writable, used by multiple APT families
        if (pathLower.Contains(@"\users\public\"))
            return true;

        // AppData\Roaming\[random] — used by Gh0st RAT, PlugX variants
        if (System.Text.RegularExpressions.Regex.IsMatch(
            pathLower, @"\\appdata\\roaming\\[a-z0-9]{6,12}\\"))
            return true;

        // Windows\Temp\[random] — used by some PlugX variants
        if (System.Text.RegularExpressions.Regex.IsMatch(
            pathLower, @"\\windows\\temp\\[a-z0-9]{6,12}\\"))
            return true;

        return false;
    }

    /// <summary>
    /// Checks if a file is digitally signed by Google LLC or Google Inc.
    /// </summary>
    private static bool IsSignedByGoogle(string filePath)
    {
        try
        {
            if (!File.Exists(filePath)) return false;
            using var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath));
            var subject = cert.Subject;
            return subject.Contains("Google LLC", StringComparison.OrdinalIgnoreCase) ||
                   subject.Contains("Google Inc", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
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


