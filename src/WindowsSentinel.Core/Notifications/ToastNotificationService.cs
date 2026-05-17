using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Notifications;

/// <summary>
/// Toast Notification Service - Windows native toast notifications for threat alerts.
/// 
/// v2.0.0: Fully defensive against missing WinRT APIs (Server Core, IoT, stripped builds).
/// If Windows.UI.Notifications is unavailable, all methods become no-ops.
/// </summary>
public sealed class ToastNotificationService
{
    private readonly ILogger<ToastNotificationService> _logger;
    private readonly string _appId = "WindowsSentinel.EDR";
    private readonly bool _toastsAvailable;

    public ToastNotificationService(ILogger<ToastNotificationService> logger)
    {
        _logger = logger;
        _toastsAvailable = CheckToastAvailability();

        if (!_toastsAvailable)
        {
            _logger.LogInformation(
                "Toast: WinRT notification APIs not available (Server Core / minimal install). " +
                "Notifications disabled — detections still logged to event log and JSONL.");
        }
        else
        {
            _logger.LogDebug("Toast: Notification service initialized");
        }
    }

    public void ShowThreatDetected(string ruleName, string processName, int pid, string verdict, string? actionTaken = null)
    {
        if (!_toastsAvailable) return;
        try
        {
            var toastXml = Windows.UI.Notifications.ToastNotificationManager
                .GetTemplateContent(Windows.UI.Notifications.ToastTemplateType.ToastText04);
            var textElements = toastXml.GetElementsByTagName("text");
            var n = textElements.Count;
            if (n > 0) textElements[0].AppendChild(toastXml.CreateTextNode($"\u26a0 {verdict} Threat Detected"));
            if (n > 1) textElements[1].AppendChild(toastXml.CreateTextNode(ruleName));
            if (n > 2)
            {
                var detail = $"Process: {processName} (PID {pid})";
                if (!string.IsNullOrEmpty(actionTaken)) detail += $" | Action: {actionTaken}";
                textElements[2].AppendChild(toastXml.CreateTextNode(detail));
            }
            var toast = new Windows.UI.Notifications.ToastNotification(toastXml) { Tag = "threat", Group = "sentinel" };
            Windows.UI.Notifications.ToastNotificationManager.CreateToastNotifier(_appId).Show(toast);
        }
        catch (Exception ex) { _logger.LogDebug(ex, "Toast: show failed (non-critical)"); }
    }

    public void ShowQuarantine(string fileName, string threatName, bool successful)
    {
        if (!_toastsAvailable) return;
        try
        {
            var toastXml = Windows.UI.Notifications.ToastNotificationManager
                .GetTemplateContent(Windows.UI.Notifications.ToastTemplateType.ToastText02);
            var textElements = toastXml.GetElementsByTagName("text");
            var n = textElements.Count;
            if (successful)
            {
                if (n > 0) textElements[0].AppendChild(toastXml.CreateTextNode("\u2713 Threat Quarantined"));
                if (n > 1) textElements[1].AppendChild(toastXml.CreateTextNode($"{fileName} - {threatName}"));
            }
            else
            {
                if (n > 0) textElements[0].AppendChild(toastXml.CreateTextNode("\u26a0 Quarantine Failed"));
                if (n > 1) textElements[1].AppendChild(toastXml.CreateTextNode($"{fileName} - Manual action required"));
            }
            var toast = new Windows.UI.Notifications.ToastNotification(toastXml) { Tag = "quarantine", Group = "sentinel" };
            Windows.UI.Notifications.ToastNotificationManager.CreateToastNotifier(_appId).Show(toast);
        }
        catch (Exception ex) { _logger.LogDebug(ex, "Toast: show failed (non-critical)"); }
    }

    public void ShowProcessTerminated(string processName, int pid, string reason)
    {
        if (!_toastsAvailable) return;
        try
        {
            var toastXml = Windows.UI.Notifications.ToastNotificationManager
                .GetTemplateContent(Windows.UI.Notifications.ToastTemplateType.ToastText02);
            var textElements = toastXml.GetElementsByTagName("text");
            var n = textElements.Count;
            if (n > 0) textElements[0].AppendChild(toastXml.CreateTextNode("\U0001f6e1 Process Terminated"));
            if (n > 1) textElements[1].AppendChild(toastXml.CreateTextNode($"{processName} (PID {pid}) - {reason}"));
            var toast = new Windows.UI.Notifications.ToastNotification(toastXml) { Tag = "terminated", Group = "sentinel" };
            Windows.UI.Notifications.ToastNotificationManager.CreateToastNotifier(_appId).Show(toast);
        }
        catch (Exception ex) { _logger.LogDebug(ex, "Toast: show failed (non-critical)"); }
    }

    public void ShowSelfProtectionAlert(string threat, string action)
    {
        if (!_toastsAvailable) return;
        try
        {
            var toastXml = Windows.UI.Notifications.ToastNotificationManager
                .GetTemplateContent(Windows.UI.Notifications.ToastTemplateType.ToastText02);
            var textElements = toastXml.GetElementsByTagName("text");
            var n = textElements.Count;
            if (n > 0) textElements[0].AppendChild(toastXml.CreateTextNode("\U0001f512 Sentinel Self-Protection"));
            if (n > 1) textElements[1].AppendChild(toastXml.CreateTextNode($"{threat} - {action}"));
            var toast = new Windows.UI.Notifications.ToastNotification(toastXml) { Tag = "selfprotection", Group = "sentinel" };
            Windows.UI.Notifications.ToastNotificationManager.CreateToastNotifier(_appId).Show(toast);
        }
        catch (Exception ex) { _logger.LogDebug(ex, "Toast: show failed (non-critical)"); }
    }

    public void ShowInfo(string title, string message)
    {
        if (!_toastsAvailable) return;
        try
        {
            var toastXml = Windows.UI.Notifications.ToastNotificationManager
                .GetTemplateContent(Windows.UI.Notifications.ToastTemplateType.ToastText02);
            var textElements = toastXml.GetElementsByTagName("text");
            var n = textElements.Count;
            if (n > 0) textElements[0].AppendChild(toastXml.CreateTextNode(title));
            if (n > 1) textElements[1].AppendChild(toastXml.CreateTextNode(message));
            var toast = new Windows.UI.Notifications.ToastNotification(toastXml) { Tag = "info", Group = "sentinel" };
            Windows.UI.Notifications.ToastNotificationManager.CreateToastNotifier(_appId).Show(toast);
        }
        catch (Exception ex) { _logger.LogDebug(ex, "Toast: show failed (non-critical)"); }
    }

    public void ClearAllNotifications()
    {
        if (!_toastsAvailable) return;
        try { Windows.UI.Notifications.ToastNotificationManager.History.Clear(_appId); }
        catch { /* best-effort */ }
    }

    /// <summary>
    /// Checks if WinRT toast notification APIs are available on this system.
    /// Returns false on Server Core, IoT Enterprise LTSC without shell, or stripped builds.
    /// </summary>
    private bool CheckToastAvailability()
    {
        try
        {
            // Probe: access ToastNotificationManager — throws on systems without WinRT shell
            _ = Windows.UI.Notifications.ToastNotificationManager.History;
            return true;
        }
        catch (TypeLoadException) { return false; }
        catch (FileNotFoundException) { return false; }
        catch (COMException) { return false; }
        catch (Exception) { return false; }
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
