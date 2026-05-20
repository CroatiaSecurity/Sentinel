using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Session;

/// <summary>
/// Launches the user-mode agent into the active user session.
/// Uses WTS APIs to create a process as the logged-in user from the SYSTEM service.
/// </summary>
public sealed class UserSessionLauncher : BackgroundService
{
    private readonly ILogger<UserSessionLauncher> _logger;
    private readonly string _agentPath;
    private int _currentSessionId = -1;

    // WTS API imports
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(int sessionId, out IntPtr phToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string? lpApplicationName,
        string? lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandle,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int ImpersonationLevel,
        int TokenType,
        out IntPtr phNewToken);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint CREATE_NEW_CONSOLE = 0x00000010;
    private const uint MAXIMUM_ALLOWED = 0x02000000;
    private const int SecurityImpersonation = 2;
    private const int TokenPrimary = 1;

    public UserSessionLauncher(ILogger<UserSessionLauncher> logger)
    {
        _logger = logger;
        _agentPath = Path.Combine(AppContext.BaseDirectory, "SentinelAgent.exe");
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("User Session Launcher: Starting...");

        // Test if WTS APIs are available on this system
        try
        {
            _ = WTSGetActiveConsoleSessionId();
        }
        catch (EntryPointNotFoundException)
        {
            _logger.LogWarning(
                "User Session Launcher: WTSGetActiveConsoleSessionId not available on this OS. " +
                "Agent will not be auto-launched into user session. " +
                "This is expected on Windows Server Core or minimal installations.");
            return; // Exit gracefully — don't spam errors every 30s
        }
        catch (DllNotFoundException)
        {
            _logger.LogWarning(
                "User Session Launcher: kernel32.dll WTS function not found. " +
                "Agent will not be auto-launched.");
            return;
        }

        // Initial launch
        LaunchAgent();

        // Monitor for session changes and relaunch if needed
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);

                var activeSession = WTSGetActiveConsoleSessionId();
                if (activeSession != _currentSessionId && activeSession >= 0)
                {
                    _logger.LogInformation("User Session Launcher: Session changed from {Old} to {New}, relaunching agent",
                        _currentSessionId, activeSession);
                    LaunchAgent();
                }

                // Check if agent is still running
                if (!IsAgentRunning())
                {
                    _logger.LogWarning("User Session Launcher: Agent not running, restarting...");
                    LaunchAgent();
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (EntryPointNotFoundException)
            {
                // API became unavailable mid-run (shouldn't happen, but be safe)
                _logger.LogWarning("User Session Launcher: WTS API no longer available, stopping monitor.");
                return;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "User Session Launcher: Error during monitoring");
            }
        }

        _logger.LogInformation("User Session Launcher: Stopped");
    }

    private void LaunchAgent()
    {
        IntPtr userToken = IntPtr.Zero;
        IntPtr duplicatedToken = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;

        try
        {
            var sessionId = WTSGetActiveConsoleSessionId();

            if (sessionId < 0)
            {
                _logger.LogDebug("User Session Launcher: No active console session");
                return;
            }

            // Get the user token for the active session
            if (!WTSQueryUserToken(sessionId, out userToken))
            {
                var error = Marshal.GetLastWin32Error();
                _logger.LogWarning("User Session Launcher: WTSQueryUserToken failed (error {Error}). Is a user logged in?", error);
                return;
            }

            // Duplicate the token
            if (!DuplicateTokenEx(userToken, MAXIMUM_ALLOWED, IntPtr.Zero,
                SecurityImpersonation, TokenPrimary, out duplicatedToken))
            {
                _logger.LogError("User Session Launcher: DuplicateTokenEx failed");
                return;
            }

            // Create environment block for the user
            if (!CreateEnvironmentBlock(out environment, duplicatedToken, false))
            {
                _logger.LogError("User Session Launcher: CreateEnvironmentBlock failed");
                return;
            }

            var startupInfo = new STARTUPINFO
            {
                cb = Marshal.SizeOf<STARTUPINFO>(),
                lpDesktop = "winsta0\\default",
                dwFlags = 0,
                wShowWindow = 1 // SW_SHOWNORMAL
            };

            var creationFlags = CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE;

            if (!CreateProcessAsUser(
                duplicatedToken,
                _agentPath,
                null,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                creationFlags,
                environment,
                Path.GetDirectoryName(_agentPath),
                ref startupInfo,
                out var processInfo))
            {
                var error = Marshal.GetLastWin32Error();
                _logger.LogError("User Session Launcher: CreateProcessAsUser failed (error {Error})", error);
                return;
            }

            _currentSessionId = sessionId;
            _logger.LogInformation("User Session Launcher: Agent launched successfully (PID {Pid}) in session {Session}",
                processInfo.dwProcessId, sessionId);

            // Close process handles
            CloseHandle(processInfo.hProcess);
            CloseHandle(processInfo.hThread);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "User Session Launcher: Failed to launch agent");
        }
        finally
        {
            if (environment != IntPtr.Zero)
                DestroyEnvironmentBlock(environment);
            if (duplicatedToken != IntPtr.Zero)
                CloseHandle(duplicatedToken);
            if (userToken != IntPtr.Zero)
                CloseHandle(userToken);
        }
    }

    private bool IsAgentRunning()
    {
        try
        {
            var processes = Process.GetProcessesByName("SentinelAgent");
            return processes.Length > 0;
        }
        catch
        {
            return false;
        }
    }
}

