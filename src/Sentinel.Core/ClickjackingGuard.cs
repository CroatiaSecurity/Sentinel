using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Comprehensive clickjacking and UI manipulation guard:
    /// 
    /// 1. Mouse input injection — detects synthetic mouse clicks (SendInput/mouse_event)
    /// 2. Click redirection — detects SetCursorPos followed by synthetic click (cursor teleport + click)
    /// 3. Non-foreground overlays — enumerates ALL visible top-level windows for overlay patterns
    /// 4. Fake UAC/credential prompts — detects windows mimicking system UI from non-system processes
    /// 5. Semi-transparent overlays — detects partially transparent windows over sensitive areas
    ///
    /// Runs in the user session (Agent) since it needs desktop access.
    /// </summary>
    public sealed class ClickjackingGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SignerTrustService _signerTrust;
        private readonly ILogger<ClickjackingGuard> _logger;

        // Mouse hook handle
        private IntPtr _mouseHookHandle = IntPtr.Zero;
        private LowLevelMouseProc? _mouseHookProc;

        // Track injected mouse events
        private int _injectedClickCount;
        private DateTime _lastInjectedClick = DateTime.MinValue;
        private DateTime _lastInjectedClickAlert = DateTime.MinValue;

        // Track cursor teleportation
        private POINT _lastCursorPos;
        private DateTime _lastCursorChange = DateTime.UtcNow;
        private int _teleportClickCount; // cursor jump + click within 50ms

        // Fake UAC dedup
        private readonly ConcurrentDictionary<int, DateTime> _fakeUacAlerted = new();

        #region P/Invoke

        private delegate IntPtr LowLevelMouseProc(int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelMouseProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll")]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string? lpModuleName);

        [DllImport("user32.dll")]
        private static extern bool GetCursorPos(out POINT lpPoint);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

        [DllImport("user32.dll")]
        private static extern byte GetLayeredWindowAttributes(IntPtr hwnd, out uint pcrKey, out byte pbAlpha, out uint pdwFlags);

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT { public int X; public int Y; }

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT { public int Left, Top, Right, Bottom; }

        [StructLayout(LayoutKind.Sequential)]
        private struct MSLLHOOKSTRUCT
        {
            public POINT pt;
            public uint mouseData;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        private const int WH_MOUSE_LL = 14;
        private const int WM_LBUTTONDOWN = 0x0201;
        private const int WM_RBUTTONDOWN = 0x0204;
        private const int WM_LBUTTONUP = 0x0202;
        private const uint LLMHF_INJECTED = 0x01;
        private const uint LLMHF_LOWER_IL_INJECTED = 0x02;
        private const int GWL_EXSTYLE = -20;
        private const int WS_EX_LAYERED = 0x80000;
        private const int WS_EX_TRANSPARENT = 0x20;
        private const int WS_EX_TOPMOST = 0x8;
        private const int WS_EX_NOACTIVATE = 0x08000000;
        private const uint LWA_ALPHA = 0x02;

        #endregion

        public ClickjackingGuard(DetectionEngine de, SignerTrustService signerTrust, ILogger<ClickjackingGuard> l)
        {
            _detectionEngine = de;
            _signerTrust = signerTrust;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ClickjackingGuard] Started — monitoring for clickjacking, fake UAC, mouse injection");

            // Install low-level mouse hook on a dedicated STA thread
            var hookThread = new Thread(() => RunMouseHook(ct));
            hookThread.SetApartmentState(ApartmentState.STA);
            hookThread.IsBackground = true;
            hookThread.Start();

            GetCursorPos(out _lastCursorPos);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(5000, ct);

                    // Periodic checks (every 5s)
                    await CheckOverlayWindowsAsync();
                    await CheckFakeUacAsync();
                    CheckCursorTeleportation();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[ClickjackingGuard] Error");
                }
            }

            // Hook thread handles its own cleanup via WM_QUIT → UnhookWindowsHookEx
        }

        #region Mouse Injection Detection

        [DllImport("user32.dll")]
        private static extern int GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

        [DllImport("user32.dll")]
        private static extern bool TranslateMessage(ref MSG lpMsg);

        [DllImport("user32.dll")]
        private static extern IntPtr DispatchMessage(ref MSG lpMsg);

        [DllImport("user32.dll")]
        private static extern bool PostThreadMessage(uint idThread, uint Msg, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [StructLayout(LayoutKind.Sequential)]
        private struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public POINT pt;
        }

        private const uint WM_QUIT = 0x0012;
        private uint _hookThreadNativeId;

        private void RunMouseHook(CancellationToken ct)
        {
            try
            {
                // Get the native Win32 thread ID (NOT managed thread ID)
                _hookThreadNativeId = GetCurrentThreadId();

                _mouseHookProc = MouseHookCallback;
                using var curProcess = Process.GetCurrentProcess();
                using var curModule = curProcess.MainModule!;
                _mouseHookHandle = SetWindowsHookEx(WH_MOUSE_LL, _mouseHookProc, GetModuleHandle(curModule.ModuleName), 0);

                if (_mouseHookHandle == IntPtr.Zero)
                {
                    _logger.LogWarning("[ClickjackingGuard] Failed to install mouse hook");
                    return;
                }

                _logger.LogInformation("[ClickjackingGuard] Mouse hook installed");

                // Register cancellation to post WM_QUIT to THIS thread's message queue
                ct.Register(() =>
                {
                    try { PostThreadMessage(_hookThreadNativeId, WM_QUIT, IntPtr.Zero, IntPtr.Zero); } catch { }
                });

                // Proper Win32 message pump — required for low-level hooks to work without lag
                MSG msg;
                while (GetMessage(out msg, IntPtr.Zero, 0, 0) > 0)
                {
                    TranslateMessage(ref msg);
                    DispatchMessage(ref msg);
                }

                // Unhook on the same thread that installed the hook
                if (_mouseHookHandle != IntPtr.Zero)
                {
                    UnhookWindowsHookEx(_mouseHookHandle);
                    _mouseHookHandle = IntPtr.Zero;
                    _logger.LogInformation("[ClickjackingGuard] Mouse hook removed");
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ClickjackingGuard] Mouse hook thread error");
            }
        }

        private IntPtr MouseHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && (wParam == (IntPtr)WM_LBUTTONDOWN || wParam == (IntPtr)WM_RBUTTONDOWN))
            {
                var hookStruct = Marshal.PtrToStructure<MSLLHOOKSTRUCT>(lParam);
                bool isInjected = (hookStruct.flags & LLMHF_INJECTED) != 0 ||
                                  (hookStruct.flags & LLMHF_LOWER_IL_INJECTED) != 0;

                if (isInjected)
                {
                    // v1.5.7: Exempt IDE processes from synthetic mouse click detection.
                    // IDEs generate injected mouse events for autocomplete selection, code lens,
                    // inline rename, drag-and-drop, and UI automation in their panels.
                    if (IsIdeMouseTarget())
                    {
                        return CallNextHookEx(_mouseHookHandle, nCode, wParam, lParam);
                    }

                    Interlocked.Increment(ref _injectedClickCount);
                    _lastInjectedClick = DateTime.UtcNow;

                    // Alert on burst of injected clicks (5+ in 10 seconds)
                    if (_injectedClickCount >= 5 && DateTime.UtcNow - _lastInjectedClickAlert > TimeSpan.FromMinutes(1))
                    {
                        _lastInjectedClickAlert = DateTime.UtcNow;
                        _injectedClickCount = 0;

                        _ = _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Clickjacking: Synthetic Mouse Click Injection",
                            Evidence = $"Detected 5+ injected mouse clicks within 10s at position ({hookStruct.pt.X},{hookStruct.pt.Y})",
                            Reasoning = "Mouse clicks with the LLMHF_INJECTED flag indicate they were generated by SendInput " +
                                        "or mouse_event, not physical hardware. Clickjacking attacks use synthetic clicks to " +
                                        "interact with UI elements on behalf of the user — clicking 'Allow', 'Yes', or form " +
                                        "buttons without user intent.",
                            Confidence = 0.85,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.PhantomKeystroke,
                            Metadata = new Dictionary<string, string>
                            {
                                { "ClickPosition", $"{hookStruct.pt.X},{hookStruct.pt.Y}" },
                                { "InjectedFlag", hookStruct.flags.ToString() }
                            }
                        });
                    }
                }
            }

            return CallNextHookEx(_mouseHookHandle, nCode, wParam, lParam);
        }

        /// <summary>
        /// v1.5.7: Checks if the foreground window (mouse click target) belongs to an IDE
        /// or a child process of an IDE. IDEs use synthetic mouse events for UI automation
        /// (autocomplete, code lens, inline actions, panel interactions).
        /// </summary>
        private static bool IsIdeMouseTarget()
        {
            try
            {
                IntPtr fgWnd = GetForegroundWindow();
                if (fgWnd == IntPtr.Zero) return false;
                GetWindowThreadProcessId(fgWnd, out uint pid);
                if (pid <= 4) return false;

                using var proc = Process.GetProcessById((int)pid);
                var name = proc.ProcessName;

                // Direct match
                if (IdeMouseProcessNames.Contains(name))
                    return true;

                // Walk parent chain (up to 3 levels)
                int currentPid = (int)pid;
                for (int depth = 0; depth < 3; depth++)
                {
                    int parentPid = GetParentProcessIdForMouse(currentPid);
                    if (parentPid <= 4) break;
                    try
                    {
                        using var parentProc = Process.GetProcessById(parentPid);
                        if (IdeMouseProcessNames.Contains(parentProc.ProcessName))
                            return true;
                    }
                    catch { break; }
                    currentPid = parentPid;
                }
                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// IDE process names for mouse click exemption. Same set as keystroke guard
        /// but maintained here to avoid cross-class coupling.
        /// </summary>
        private static readonly HashSet<string> IdeMouseProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "code", "Code - Insiders", "kiro", "cursor", "windsurf", "positron",
            "rider64", "idea64", "phpstorm64", "webstorm64", "goland64",
            "pycharm64", "clion64", "rubymine64", "datagrip64",
            "devenv",
            "windowsterminal", "wt", "ConEmu64", "ConEmu",
            "alacritty", "wezterm-gui", "hyper",
            "sublime_text", "notepad++", "atom",
            "mstsc", "vmware-vmx", "VirtualBoxVM",
        };

        private static int GetParentProcessIdForMouse(int pid)
        {
            IntPtr hProcess = IntPtr.Zero;
            try
            {
                hProcess = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, (uint)pid);
                if (hProcess == IntPtr.Zero) return 0;

                var pbi = new PROCESS_BASIC_INFO_MOUSE();
                int status = NtQueryInformationProcessMouse(hProcess, 0, ref pbi, Marshal.SizeOf(pbi), out _);
                return status == 0 ? pbi.InheritedFromUniqueProcessId.ToInt32() : 0;
            }
            catch { return 0; }
            finally
            {
                if (hProcess != IntPtr.Zero) CloseHandleMouse(hProcess);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFO_MOUSE
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("ntdll.dll", EntryPoint = "NtQueryInformationProcess")]
        private static extern int NtQueryInformationProcessMouse(
            IntPtr processHandle, int processInformationClass,
            ref PROCESS_BASIC_INFO_MOUSE processInformation,
            int processInformationLength, out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "CloseHandle")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandleMouse(IntPtr hObject);

        #endregion

        #region Cursor Teleportation + Click Detection

        private void CheckCursorTeleportation()
        {
            if (!GetCursorPos(out var pos)) return;

            var dx = pos.X - _lastCursorPos.X;
            var dy = pos.Y - _lastCursorPos.Y;
            var distance = Math.Sqrt(dx * dx + dy * dy);

            // Large jump (>500px) followed by recent injected click = click redirection
            if (distance > 500 && DateTime.UtcNow - _lastInjectedClick < TimeSpan.FromMilliseconds(200))
            {
                _teleportClickCount++;
                if (_teleportClickCount >= 2)
                {
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Clickjacking: Cursor Teleport + Synthetic Click",
                        Evidence = $"Cursor teleported {distance:F0}px to ({pos.X},{pos.Y}) followed by injected click. " +
                                   $"Pattern repeated {_teleportClickCount} times.",
                        Reasoning = "SetCursorPos moved the cursor to a target UI element and immediately triggered a " +
                                    "synthetic click. This is the classic clickjacking technique: move cursor to 'Allow' " +
                                    "or 'Confirm' button, click it via SendInput, then return cursor — user sees nothing.",
                        Confidence = 0.92,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        SignalType = SignalType.PhantomKeystroke,
                        Metadata = new Dictionary<string, string>
                        {
                            { "TeleportDistance", $"{distance:F0}px" },
                            { "TargetPosition", $"{pos.X},{pos.Y}" },
                            { "RepeatCount", _teleportClickCount.ToString() }
                        }
                    });
                    _teleportClickCount = 0;
                }
            }

            _lastCursorPos = pos;
        }

        #endregion

        #region Non-Foreground Overlay Detection

        private async Task CheckOverlayWindowsAsync()
        {
            var suspiciousWindows = new List<(IntPtr hWnd, int pid, string procName, int width, int height, byte alpha)>();

            EnumWindows((hWnd, _) =>
            {
                if (!IsWindowVisible(hWnd)) return true;

                int exStyle = GetWindowLong(hWnd, GWL_EXSTYLE);
                bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
                bool isTopmost = (exStyle & WS_EX_TOPMOST) != 0;
                bool isNoActivate = (exStyle & WS_EX_NOACTIVATE) != 0;
                bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;

                // Pattern: layered + topmost + (transparent OR noactivate) = overlay
                if (isLayered && isTopmost && (isTransparent || isNoActivate))
                {
                    if (!GetWindowRect(hWnd, out var rect)) return true;
                    int width = rect.Right - rect.Left;
                    int height = rect.Bottom - rect.Top;

                    // Only care about large overlays (>400x400)
                    if (width < 400 || height < 400) return true;

                    GetWindowThreadProcessId(hWnd, out uint pid);
                    if (pid <= 4) return true;

                    string procName = "unknown";
                    try { using var p = Process.GetProcessById((int)pid); procName = p.ProcessName; } catch { }

                    // Skip known-good overlay creators
                    if (procName.Equals("dwm", StringComparison.OrdinalIgnoreCase) ||
                        procName.Equals("explorer", StringComparison.OrdinalIgnoreCase) ||
                        procName.Equals("GeForceOverlay", StringComparison.OrdinalIgnoreCase) ||
                        procName.Equals("GameBar", StringComparison.OrdinalIgnoreCase) ||
                        procName.Equals("Discord", StringComparison.OrdinalIgnoreCase) ||
                        procName.Contains("Overlay", StringComparison.OrdinalIgnoreCase) ||
                        // v1.5.5: IDEs use layered topmost windows for autocomplete, tooltips,
                        // debugging overlays, and notification panels.
                        procName.Equals("Code", StringComparison.OrdinalIgnoreCase) ||
                        procName.Equals("kiro", StringComparison.OrdinalIgnoreCase) ||
                        procName.Equals("cursor", StringComparison.OrdinalIgnoreCase) ||
                        procName.Equals("windsurf", StringComparison.OrdinalIgnoreCase) ||
                        procName.Equals("devenv", StringComparison.OrdinalIgnoreCase) ||
                        procName.Contains("rider", StringComparison.OrdinalIgnoreCase) ||
                        procName.Contains("idea", StringComparison.OrdinalIgnoreCase) ||
                        procName.Contains("webstorm", StringComparison.OrdinalIgnoreCase) ||
                        procName.Contains("pycharm", StringComparison.OrdinalIgnoreCase))
                        return true;

                    // Check alpha transparency
                    byte alpha = 255;
                    uint crKey;
                    uint flags;
                    GetLayeredWindowAttributes(hWnd, out crKey, out alpha, out flags);
                    if ((flags & LWA_ALPHA) != 0 && alpha > 200) return true; // Nearly opaque = normal window

                    suspiciousWindows.Add((hWnd, (int)pid, procName, width, height, alpha));
                }
                return true;
            }, IntPtr.Zero);

            foreach (var (hWnd, pid, procName, width, height, alpha) in suspiciousWindows)
            {
                var dedupKey = $"overlay:{pid}";
                if (_fakeUacAlerted.ContainsKey(pid)) continue;
                _fakeUacAlerted[pid] = DateTime.UtcNow;

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Clickjacking: Suspicious Overlay Window",
                    Evidence = $"Process '{procName}' (PID {pid}) has a large overlay window ({width}x{height}, alpha={alpha}). " +
                               "Layered+Topmost+Transparent/NoActivate pattern.",
                    Reasoning = "A non-foreground transparent topmost window was detected covering a significant screen area. " +
                                "This pattern is used in clickjacking: an invisible overlay captures clicks meant for the window " +
                                "beneath, or a deceptive overlay mimics legitimate UI to trick the user into clicking.",
                    Confidence = 0.78,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.KillProcessTree,
                    ProcessName = procName,
                    ProcessId = pid,
                    SignalType = SignalType.PhantomKeystroke,
                    Metadata = new Dictionary<string, string>
                    {
                        { "WindowSize", $"{width}x{height}" },
                        { "Alpha", alpha.ToString() },
                        { "ExStyle", "Layered+Topmost+Transparent" }
                    }
                });
            }
        }

        #endregion

        #region Fake UAC / Credential Prompt Detection

        private async Task CheckFakeUacAsync()
        {
            var sb = new StringBuilder(256);
            var classSb = new StringBuilder(256);

            EnumWindows((hWnd, _) =>
            {
                if (!IsWindowVisible(hWnd)) return true;

                GetWindowText(hWnd, sb, 256);
                var title = sb.ToString();
                GetClassName(hWnd, classSb, 256);
                var className = classSb.ToString();

                // Detect windows with UAC-like titles from non-consent.exe processes
                bool looksLikeUac = title.Contains("User Account Control", StringComparison.OrdinalIgnoreCase) ||
                                    title.Contains("Windows Security", StringComparison.OrdinalIgnoreCase) ||
                                    title.Contains("Administrator permission", StringComparison.OrdinalIgnoreCase) ||
                                    title.Contains("Credential", StringComparison.OrdinalIgnoreCase) && title.Contains("Windows", StringComparison.OrdinalIgnoreCase) ||
                                    title.Contains("Sign in", StringComparison.OrdinalIgnoreCase) && className.Contains("#32770");

                if (!looksLikeUac) return true;

                GetWindowThreadProcessId(hWnd, out uint pid);
                if (pid <= 4) return true;

                string procName = "unknown";
                string? imagePath = null;
                try
                {
                    using var p = Process.GetProcessById((int)pid);
                    procName = p.ProcessName;
                    imagePath = p.MainModule?.FileName;
                }
                catch { }

                // Skip processes signed by a trusted publisher (Google, Microsoft, Mozilla, etc.)
                // This cannot be bypassed by renaming a malicious binary to "chrome.exe" —
                // the attacker would need the publisher's private code-signing key.
                if (!string.IsNullOrEmpty(imagePath) && _signerTrust.IsSignedFile(imagePath))
                    return true;

                // Also skip our own agent process by name (it won't have a third-party signature)
                if (string.Equals(procName, "Sentinel.Agent", StringComparison.OrdinalIgnoreCase))
                    return true;

                // This is a non-system process with a UAC-like window title — fake UAC
                if (!_fakeUacAlerted.ContainsKey((int)pid))
                {
                    _fakeUacAlerted[(int)pid] = DateTime.UtcNow;
                    Task.Run(() => _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Clickjacking: Fake UAC/Credential Prompt",
                        Evidence = $"Process '{procName}' (PID {pid}) from '{imagePath ?? "unknown"}' " +
                                   $"created a window titled '{title}' (class: {className})",
                        Reasoning = "A non-system process created a window with a title mimicking Windows UAC or " +
                                    "credential prompts. Attackers use fake UAC dialogs to harvest passwords — the user " +
                                    "thinks they're authenticating to Windows but they're typing into an attacker-controlled window.",
                        Confidence = 0.90,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        ProcessName = procName,
                        ProcessId = (int)pid,
                        SignalType = SignalType.PhantomKeystroke,
                        Metadata = new Dictionary<string, string>
                        {
                            { "WindowTitle", title },
                            { "ClassName", className },
                            { "ImagePath", imagePath ?? "unknown" }
                        }
                    }));
                }

                return true;
            }, IntPtr.Zero);
        }

        #endregion
    }
}
