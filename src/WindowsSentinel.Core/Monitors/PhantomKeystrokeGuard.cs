using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

public sealed class PhantomKeystrokeGuard : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<PhantomKeystrokeGuard> _logger;
    private IntPtr _hookId = IntPtr.Zero;
    private NativeMethods.LowLevelKeyboardProc _proc;

    private DateTimeOffset _lastAlertTime = DateTimeOffset.MinValue;
    private int _blockedCount = 0;

    public PhantomKeystrokeGuard(
        IDetectionEngine detectionEngine,
        ILogger<PhantomKeystrokeGuard> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _proc = HookCallback;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== PhantomKeystrokeGuard starting ===");

        // We run the hook installation on a dedicated STA thread so it has a message loop
        var thread = new Thread(() => RunMessageLoop(stoppingToken))
        {
            IsBackground = true,
            Name = "PhantomKeystrokeGuardThread"
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();

        return Task.CompletedTask;
    }

    private void RunMessageLoop(CancellationToken stoppingToken)
    {
        _hookId = SetHook(_proc);
        if (_hookId == IntPtr.Zero)
        {
            _logger.LogError("PhantomKeystrokeGuard: Failed to install WH_KEYBOARD_LL hook. Error: {Error}", Marshal.GetLastWin32Error());
            return;
        }

        _logger.LogInformation("PhantomKeystrokeGuard: WH_KEYBOARD_LL hook installed.");

        try
        {
            // Pumping messages is required for WH_KEYBOARD_LL to receive events
            while (!stoppingToken.IsCancellationRequested)
            {
                if (NativeMethods.MsgWaitForMultipleObjectsEx(0, IntPtr.Zero, 250, NativeMethods.QS_ALLINPUT, NativeMethods.MWMO_ALERTABLE) == NativeMethods.WAIT_OBJECT_0)
                {
                    while (NativeMethods.PeekMessage(out var msg, IntPtr.Zero, 0, 0, NativeMethods.PM_REMOVE))
                    {
                        if (msg.message == NativeMethods.WM_QUIT)
                        {
                            return;
                        }

                        NativeMethods.TranslateMessage(ref msg);
                        NativeMethods.DispatchMessage(ref msg);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PhantomKeystrokeGuard: Error in message loop");
        }
        finally
        {
            NativeMethods.UnhookWindowsHookEx(_hookId);
            _hookId = IntPtr.Zero;
            _logger.LogInformation("PhantomKeystrokeGuard: WH_KEYBOARD_LL hook removed.");
        }
    }

    private IntPtr SetHook(NativeMethods.LowLevelKeyboardProc proc)
    {
        using var curProcess = Process.GetCurrentProcess();
        using var curModule = curProcess.MainModule;
        if (curModule?.ModuleName == null) return IntPtr.Zero;

        return NativeMethods.SetWindowsHookEx(NativeMethods.WH_KEYBOARD_LL, proc,
            NativeMethods.GetModuleHandle(curModule.ModuleName), 0);
    }

    private IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0)
        {
            var kbdStruct = Marshal.PtrToStructure<NativeMethods.KBDLLHOOKSTRUCT>(lParam);

            // LLKHF_INJECTED (0x10) indicates the event was injected from a process using SendInput
            if ((kbdStruct.flags & NativeMethods.LLKHF_INJECTED) != 0)
            {
                _blockedCount++;
                
                // Fire and forget
                _ = EmitDetectionAsync();

                // Return non-zero to block the event from reaching other hooks or the target application
                return new IntPtr(1);
            }
        }

        return NativeMethods.CallNextHookEx(_hookId, nCode, wParam, lParam);
    }

    private async Task EmitDetectionAsync()
    {
        var now = DateTimeOffset.UtcNow;
        if (now - _lastAlertTime < TimeSpan.FromSeconds(10))
        {
            return;
        }

        _lastAlertTime = now;
        var blocked = _blockedCount;
        _blockedCount = 0;

        try
        {
            _logger.LogWarning("PhantomKeystrokeGuard: Blocked {Count} injected keystrokes.", blocked);

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Input Injection: Phantom Keystrokes Blocked",
                Evidence = $"Blocked {blocked} software-injected keystroke(s).",
                Reasoning = "Software-injected keystrokes were detected via the LLKHF_INJECTED flag. " +
                            "This is a common technique used by malware (such as credential stealers or remote access trojans) " +
                            "to automate typing, corrupt user input, or interact with applications without user consent.",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = "Unknown (Injected)",
                ProcessId = 0,
                Timestamp = now,
                Metadata = new Dictionary<string, string>
                {
                    ["blocked_count"] = blocked.ToString(),
                    ["technique"] = "T1056 - Input Capture / Injection"
                }
            }, CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PhantomKeystrokeGuard: Failed to emit detection event.");
        }
    }

    private static class NativeMethods
    {
        public const int WH_KEYBOARD_LL = 13;
        public const int LLKHF_INJECTED = 0x00000010;
        public const int QS_ALLINPUT = 0x04FF;
        public const int MWMO_ALERTABLE = 0x0002;
        public const uint WAIT_OBJECT_0 = 0x00000000;
        public const uint PM_REMOVE = 0x0001;
        public const uint WM_QUIT = 0x0012;

        public delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        [StructLayout(LayoutKind.Sequential)]
        public struct KBDLLHOOKSTRUCT
        {
            public uint vkCode;
            public uint scanCode;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public int pt_x;
            public int pt_y;
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint MsgWaitForMultipleObjectsEx(uint nCount, IntPtr pHandles, uint dwMilliseconds, uint dwWakeMask, uint dwFlags);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool PeekMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax, uint wRemoveMsg);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool TranslateMessage(ref MSG lpMsg);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr DispatchMessage(ref MSG lpMsg);
    }
}
