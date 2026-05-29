using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Notifications;

/// <summary>
/// Toast Notification Service - Windows native toast notifications for threat alerts.
/// 
/// v2.0.0: Fully defensive against missing WinRT APIs (Server Core, IoT, stripped builds).
/// If Windows.UI.Notifications is unavailable, all methods become no-ops.
///
/// v4.2.0: ARCHITECTURE FIX — Toast notifications from SYSTEM services are invisible
/// (session 0 isolation). Added WTSSendMessage fallback that CAN show alerts to the
/// user desktop from a SYSTEM service. WinRT toasts only work when called from the
/// Agent (user session). The Service uses WTSSendMessage for critical alerts.
/// </summary>
public sealed class ToastNotificationService
{
    private readonly ILogger<ToastNotificationService> _logger;
    private readonly string _appId = "WindowsSentinel.EDR";
    private readonly bool _toastsAvailable;
    private readonly bool _isUserSession;

    // WTS API for showing messages from SYSTEM service to user desktop
    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool WTSSendMessage(
        IntPtr hServer, int sessionId,
        string title, int titleLength,
        string message, int messageLength,
        uint style, int timeout,
        out int response, bool wait);

    [DllImport("kernel32.dll")]
    private static extern int WTSGetActiveConsoleSessionId();

    private const uint MB_OK = 0x00000000;
    private const uint MB_ICONWARNING = 0x00000030;
    private const uint MB_ICONERROR = 0x00000010;
    private const uint MB_TOPMOST = 0x00040000;
    private const uint MB_SETFOREGROUND = 0x00010000;

    // Rate limiting: don't spam the user with message boxes
    private DateTimeOffset _lastWtsMessage = DateTimeOffset.MinValue;
    private static readonly TimeSpan WtsMessageCooldown = TimeSpan.FromMinutes(2);

    public ToastNotificationService(ILogger<ToastNotificationService> logger)
    {
        _logger = logger;
        _isUserSession = !IsRunningAsSystem();
        _toastsAvailable = _isUserSession && CheckToastAvailability();

        if (_isUserSession)
        {
            if (_toastsAvailable)
                _logger.LogDebug("Toast: WinRT notifications available (user session)");
            else
                _logger.LogInformation("Toast: WinRT not available, using fallback");
        }
        else
        {
            _logger.LogInformation(
                "Toast: Running as SYSTEM service — notifications delegated to Agent tray icon. " +
                "WTSSendMessage popups disabled (v4.3.0).");
        }
    }

    public void ShowThreatDetected(string ruleName, string processName, int pid, string verdict, string? actionTaken = null)
    {
        string title = $"\u26a0 {verdict} Threat Detected";
        string detail = $"{ruleName}\nProcess: {processName} (PID {pid})";
        if (!string.IsNullOrEmpty(actionTaken)) detail += $"\nAction: {actionTaken}";

        if (_toastsAvailable)
        {
            ShowWinRtToast(title, ruleName, detail, "threat");
        }
        // v4.3.0: WTSSendMessage popups removed — Agent tray icon handles user notifications
    }

    public void ShowQuarantine(string fileName, string threatName, bool successful)
    {
        string title = successful ? "\u2713 Threat Quarantined" : "\u26a0 Quarantine Failed";
        string message = successful
            ? $"{fileName} - {threatName}"
            : $"{fileName} - Manual action required";

        if (_toastsAvailable)
            ShowWinRtToast(title, message, null, "quarantine");
        // v4.3.0: WTSSendMessage popups removed — Agent tray icon handles user notifications
    }

    public void ShowProcessTerminated(string processName, int pid, string reason)
    {
        string title = "\U0001f6e1 Process Terminated";
        string message = $"{processName} (PID {pid}) - {reason}";

        if (_toastsAvailable)
            ShowWinRtToast(title, message, null, "terminated");
        // v4.3.0: WTSSendMessage popups removed — Agent tray icon handles user notifications
    }

    public void ShowSelfProtectionAlert(string threat, string action)
    {
        string title = "\U0001f512 Sentinel Self-Protection";
        string message = $"{threat} - {action}";

        if (_toastsAvailable)
            ShowWinRtToast(title, message, null, "selfprotection");
        // v4.3.0: WTSSendMessage popups removed — Agent tray icon handles user notifications
    }

    public void ShowInfo(string title, string message)
    {
        if (_toastsAvailable)
            ShowWinRtToast(title, message, null, "info");
        // Don't use WTS for info-level — too intrusive
    }

    public void ClearAllNotifications()
    {
        if (!_toastsAvailable) return;
        try { Windows.UI.Notifications.ToastNotificationManager.History.Clear(_appId); }
        catch { /* best-effort */ }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // WinRT Toast (only works from user session / Agent)
    // ═══════════════════════════════════════════════════════════════════════════

    private void ShowWinRtToast(string line1, string line2, string? line3, string tag)
    {
        try
        {
            var toastXml = Windows.UI.Notifications.ToastNotificationManager
                .GetTemplateContent(Windows.UI.Notifications.ToastTemplateType.ToastText04);
            var textElements = toastXml.GetElementsByTagName("text");
            var n = textElements.Count;
            if (n > 0) textElements[0].AppendChild(toastXml.CreateTextNode(line1));
            if (n > 1) textElements[1].AppendChild(toastXml.CreateTextNode(line2));
            if (n > 2 && !string.IsNullOrEmpty(line3))
                textElements[2].AppendChild(toastXml.CreateTextNode(line3));
            var toast = new Windows.UI.Notifications.ToastNotification(toastXml)
            {
                Tag = tag,
                Group = "sentinel"
            };
            Windows.UI.Notifications.ToastNotificationManager.CreateToastNotifier(_appId).Show(toast);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Toast: WinRT show failed");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // WTSSendMessage fallback (works from SYSTEM service → user desktop)
    // ═══════════════════════════════════════════════════════════════════════════

    private void ShowWtsMessage(string title, string message)
    {
        // Rate limit — don't spam modal dialogs
        if (DateTimeOffset.UtcNow - _lastWtsMessage < WtsMessageCooldown)
            return;

        try
        {
            int sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId < 0) return;

            // Non-blocking (wait=false) so the service doesn't hang
            bool result = WTSSendMessage(
                IntPtr.Zero, // Local server
                sessionId,
                title, title.Length * 2,
                message, message.Length * 2,
                MB_OK | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND,
                30, // Auto-dismiss after 30 seconds
                out _,
                false); // Don't wait for user response

            if (result)
            {
                _lastWtsMessage = DateTimeOffset.UtcNow;
                _logger.LogDebug("Toast: WTSSendMessage shown to session {Session}", sessionId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Toast: WTSSendMessage failed");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════

    private bool CheckToastAvailability()
    {
        try
        {
            _ = Windows.UI.Notifications.ToastNotificationManager.History;
            return true;
        }
        catch (TypeLoadException) { return false; }
        catch (FileNotFoundException) { return false; }
        catch (COMException) { return false; }
        catch (Exception) { return false; }
    }

    private static bool IsRunningAsSystem()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return identity.IsSystem;
        }
        catch
        {
            // If we can't determine, assume service context
            return true;
        }
    }
}

/// <summary>
/// Toast notification configuration.
/// </summary>
public sealed class ToastConfig
{
    public bool EnableThreatToasts { get; set; } = true;
    public bool EnableQuarantineToasts { get; set; } = true;
    public bool EnableTerminationToasts { get; set; } = true;
    public bool EnableSelfProtectionToasts { get; set; } = true;
    public bool EnableInfoToasts { get; set; } = false;
}


