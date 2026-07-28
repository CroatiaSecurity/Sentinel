using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Service-side watchdog that keeps Sentinel.Agent.exe alive in the user's
    /// interactive session.
    ///
    /// Problem: The Agent is a user-session process launched via the HKLM Run key.
    /// Unlike the Service (which has SCM failure-restart configured), the Agent has no
    /// automatic recovery — if it crashes or is killed it stays dead until the next login.
    /// The Service runs as SYSTEM and has no direct visibility into the user session,
    /// so a simple Process.Start won't land in the correct session.
    ///
    /// Solution:
    ///   1. Poll for the Agent process every 10 seconds.
    ///   2. If absent, launch it in the active console session via CreateProcessAsUser
    ///      (WTSQueryUserToken → CreateEnvironmentBlock → CreateProcessAsUser).
    ///   3. Rate-limit relaunches (max 1 per 15s, 5 in 5 minutes before backing off)
    ///      to avoid restart storms on systematic crash loops.
    ///   4. Fire a Tier1 detection if the Agent is killed more than 3 times in 5 minutes
    ///      (anti-tamper signal — attacker is trying to blind the user-facing monitor).
    ///
    /// Security note: CreateProcessAsUser requires SE_ASSIGNPRIMARYTOKEN_NAME and
    /// SE_INCREASE_QUOTA_NAME privileges. The Service already runs as LocalSystem which
    /// holds both. The Agent token obtained from WTSQueryUserToken is a restricted user
    /// token (not elevated), so the relaunched agent runs as the logged-in user — identical
    /// to what the HKLM Run key produces.
    /// </summary>
    public sealed class AgentWatchdog : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<AgentWatchdog> _logger;

        private const string AgentProcessName = "Sentinel.Agent";
        private const string AgentExeName = "Sentinel.Agent.exe";

        private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(10);
        private static readonly TimeSpan RelaunchCooldown = TimeSpan.FromSeconds(15);
        private static readonly TimeSpan KillWindowDuration = TimeSpan.FromMinutes(5);
        private const int KillThresholdForAlert = 3;
        private const int MaxRelaunchesInWindow = 5;

        // How long to wait after service start before first check.
        // Gives the Run key a chance to launch the agent during login before we
        // step in — avoids a dual-launch race at session start.
        private static readonly TimeSpan StartupGrace = TimeSpan.FromSeconds(20);

        private DateTimeOffset _lastRelaunchTime = DateTimeOffset.MinValue;
        private int _killCount;
        private DateTimeOffset _firstKillInWindow = DateTimeOffset.MinValue;
        private bool _alertFired;

        public AgentWatchdog(
            DetectionEngine detectionEngine,
            JsonlEventLogger eventLogger,
            ILogger<AgentWatchdog> logger)
        {
            _detectionEngine = detectionEngine;
            _eventLogger = eventLogger;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[AgentWatchdog] Started — will monitor {Agent} liveness", AgentProcessName);

            // Startup grace — let the HKLM Run key do its job first
            await Task.Delay(StartupGrace, stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(PollInterval, stoppingToken);
                    await CheckAgentAsync(stoppingToken);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[AgentWatchdog] Unexpected error during agent check");
                }
            }
        }

        private async Task CheckAgentAsync(CancellationToken ct)
        {
            // Is the agent already running in ANY session?
            if (IsAgentRunning())
                return;

            // Agent is gone — track kills for anti-tamper alerting
            var now = DateTimeOffset.UtcNow;
            if (now - _firstKillInWindow > KillWindowDuration)
            {
                // Reset window
                _killCount = 0;
                _firstKillInWindow = now;
                _alertFired = false;
            }

            _killCount++;
            _logger.LogWarning("[AgentWatchdog] Agent not running — kill #{Count} in current window", _killCount);

            if (_killCount >= KillThresholdForAlert && !_alertFired)
            {
                _alertFired = true;
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Anti-Tamper: Agent Process Repeatedly Killed",
                    Evidence = $"Sentinel.Agent.exe has been absent {_killCount} times in the last " +
                               $"{KillWindowDuration.TotalMinutes:F0} minutes. Watchdog is relaunching it.",
                    Reasoning = "The Sentinel user-session agent keeps dying. This may indicate an attacker " +
                                "is repeatedly terminating the agent to suppress tray notifications and prevent " +
                                "the user from seeing active threat alerts. Could also be an AV/EDR product " +
                                "incorrectly blocking the agent binary.",
                    Confidence = _killCount >= KillThresholdForAlert + 2 ? 0.90 : 0.70,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = AgentProcessName,
                    ProcessId = 0,
                    SignalType = SignalType.AntiTamper,
                    Metadata = new System.Collections.Generic.Dictionary<string, string>
                    {
                        ["KillCount"] = _killCount.ToString(),
                        ["WindowMinutes"] = KillWindowDuration.TotalMinutes.ToString("F0")
                    }
                });
            }

            // Enforce relaunch cooldown to avoid storm on systematic crash
            if (now - _lastRelaunchTime < RelaunchCooldown)
            {
                _logger.LogDebug("[AgentWatchdog] Relaunch cooldown active — skipping");
                return;
            }

            if (_killCount > MaxRelaunchesInWindow)
            {
                _logger.LogWarning("[AgentWatchdog] Relaunch rate limit reached ({Count}/{Max}) — backing off",
                    _killCount, MaxRelaunchesInWindow);
                return;
            }

            await RelaunchAgentAsync(ct);
        }

        private async Task RelaunchAgentAsync(CancellationToken ct)
        {
            // Locate the agent binary next to the service binary
            var selfDir = AppContext.BaseDirectory;
            var agentPath = Path.Combine(selfDir, AgentExeName);

            if (!File.Exists(agentPath))
            {
                _logger.LogError("[AgentWatchdog] Agent binary not found at {Path} — cannot relaunch", agentPath);
                return;
            }

            _lastRelaunchTime = DateTimeOffset.UtcNow;

            // Try privileged launch (SYSTEM service → user session) first
            bool launched = TryLaunchInUserSession(agentPath);

            if (!launched)
            {
                // Fallback: simple Process.Start (works if the Service happens to share a session,
                // e.g., on a non-Server SKU where session 0 isolation is partial, or under a test runner)
                launched = TryFallbackLaunch(agentPath);
            }

            if (launched)
            {
                _logger.LogWarning("[AgentWatchdog] Relaunched {Agent}", AgentProcessName);
                await _eventLogger.LogEventAsync("agent_relaunched", new
                {
                    KillCount = _killCount,
                    AgentPath = agentPath,
                    Timestamp = DateTimeOffset.UtcNow
                }, ct);
            }
            else
            {
                _logger.LogError("[AgentWatchdog] All relaunch attempts failed for {Agent}", AgentProcessName);
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // Process Detection
        // ═══════════════════════════════════════════════════════════════

        private static bool IsAgentRunning()
        {
            try
            {
                var procs = Process.GetProcessesByName(AgentProcessName);
                var found = procs.Length > 0;
                foreach (var p in procs) p.Dispose();
                return found;
            }
            catch
            {
                return false;
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // User-Session Launch (SYSTEM → console user)
        // ═══════════════════════════════════════════════════════════════

        /// <summary>
        /// Launches the agent in the active console user's session using
        /// WTSQueryUserToken → CreateEnvironmentBlock → CreateProcessAsUser.
        ///
        /// This is the standard Windows pattern for services that need to spawn
        /// processes visible to the logged-in user (e.g., Task Scheduler "run in user context").
        /// </summary>
        private bool TryLaunchInUserSession(string agentPath)
        {
            var sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == 0xFFFFFFFF)
            {
                _logger.LogDebug("[AgentWatchdog] No active console session — skipping user-session launch");
                return false;
            }

            var userToken = IntPtr.Zero;
            var envBlock = IntPtr.Zero;
            var procInfo = new PROCESS_INFORMATION();

            try
            {
                // Obtain the primary token of the logged-in console user
                if (!WTSQueryUserToken(sessionId, out userToken))
                {
                    var err = Marshal.GetLastWin32Error();
                    _logger.LogDebug("[AgentWatchdog] WTSQueryUserToken failed (err={Err}) — user may not be logged in", err);
                    return false;
                }

                // Build the environment block for the user (inherits their PATH, APPDATA, etc.)
                if (!CreateEnvironmentBlock(out envBlock, userToken, false))
                    envBlock = IntPtr.Zero; // Non-fatal; proceed without custom env block

                var si = new STARTUPINFO
                {
                    cb = Marshal.SizeOf<STARTUPINFO>(),
                    dwFlags = STARTF_USESHOWWINDOW,
                    wShowWindow = SW_HIDE
                };

                var commandLine = $"\"{agentPath}\"";
                var workDir = Path.GetDirectoryName(agentPath) ?? selfDir;

                const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
                const uint CREATE_NO_WINDOW = 0x08000000;
                const uint NORMAL_PRIORITY_CLASS = 0x00000020;

                bool created = CreateProcessAsUser(
                    userToken,
                    null,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW | (envBlock != IntPtr.Zero ? CREATE_UNICODE_ENVIRONMENT : 0),
                    envBlock,
                    workDir,
                    ref si,
                    out procInfo);

                if (!created)
                {
                    var err = Marshal.GetLastWin32Error();
                    _logger.LogWarning("[AgentWatchdog] CreateProcessAsUser failed (err={Err})", err);
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AgentWatchdog] Exception during user-session launch");
                return false;
            }
            finally
            {
                if (procInfo.hProcess != IntPtr.Zero) CloseHandle(procInfo.hProcess);
                if (procInfo.hThread != IntPtr.Zero) CloseHandle(procInfo.hThread);
                if (userToken != IntPtr.Zero) CloseHandle(userToken);
                if (envBlock != IntPtr.Zero) DestroyEnvironmentBlock(envBlock);
            }
        }

        // Stored for use inside TryLaunchInUserSession without capturing 'this'
        private static readonly string selfDir = AppContext.BaseDirectory;

        private static bool TryFallbackLaunch(string agentPath)
        {
            try
            {
                var psi = new ProcessStartInfo(agentPath)
                {
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                using var p = Process.Start(psi);
                return p != null;
            }
            catch
            {
                return false;
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // P/Invoke
        // ═══════════════════════════════════════════════════════════════

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr phToken);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string? lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string? lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string? lpReserved;
            public string? lpDesktop;
            public string? lpTitle;
            public uint dwX, dwY, dwXSize, dwYSize;
            public uint dwXCountChars, dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private const uint STARTF_USESHOWWINDOW = 0x00000001;
        private const ushort SW_HIDE = 0;
    }
}
