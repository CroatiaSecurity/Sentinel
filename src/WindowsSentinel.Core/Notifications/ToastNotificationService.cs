using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Xml;
using Microsoft.Extensions.Logging;
using Windows.Data.Xml.Dom;
using Windows.UI.Notifications;

namespace WindowsSentinel.Core.Notifications;

/// <summary>
/// Toast Notification Service - Windows native toast notifications for threat alerts.
/// </summary>
public sealed class ToastNotificationService
{
    private readonly ILogger<ToastNotificationService> _logger;
    private readonly string _appId = "WindowsSentinel.EDR";

    public ToastNotificationService(ILogger<ToastNotificationService> logger)
    {
        _logger = logger;
        
        // Register notification app if not already registered
        RegisterAppForNotification();
    }

    /// <summary>
    /// Shows a threat detected toast notification.
    /// </summary>
    public void ShowThreatDetected(string ruleName, string processName, int pid, string verdict, string? actionTaken = null)
    {
        try
        {
            var toastXml = ToastNotificationManager.GetTemplateContent(ToastTemplateType.ToastImageAndText04);
            
            var textElements = toastXml.GetElementsByTagName("text");
            textElements[0].AppendChild(toastXml.CreateTextNode($"⚠ {verdict} Threat Detected"));
            textElements[1].AppendChild(toastXml.CreateTextNode($"{ruleName}"));
            textElements[2].AppendChild(toastXml.CreateTextNode($"Process: {processName} (PID {pid})"));
            
            if (!string.IsNullOrEmpty(actionTaken))
            {
                textElements[3]?.AppendChild(toastXml.CreateTextNode($"Action: {actionTaken}"));
            }

            var toast = new ToastNotification(toastXml);
            toast.Tag = "threat";
            toast.Group = "sentinel";
            
            ToastNotificationManager.CreateToastNotifier(_appId).Show(toast);
            
            _logger.LogDebug("Toast: Threat notification shown for {Process}", processName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Toast: Failed to show threat notification");
        }
    }

    /// <summary>
    /// Shows a quarantine notification.
    /// </summary>
    public void ShowQuarantine(string fileName, string threatName, bool successful)
    {
        try
        {
            var toastXml = ToastNotificationManager.GetTemplateContent(ToastTemplateType.ToastText02);
            
            var textElements = toastXml.GetElementsByTagName("text");
            if (successful)
            {
                textElements[0].AppendChild(toastXml.CreateTextNode($"✓ Threat Quarantined"));
                textElements[1].AppendChild(toastXml.CreateTextNode($"{fileName} - {threatName}"));
            }
            else
            {
                textElements[0].AppendChild(toastXml.CreateTextNode($"⚠ Quarantine Failed"));
                textElements[1].AppendChild(toastXml.CreateTextNode($"{fileName} - Manual action required"));
            }

            var toast = new ToastNotification(toastXml);
            toast.Tag = "quarantine";
            toast.Group = "sentinel";
            
            ToastNotificationManager.CreateToastNotifier(_appId).Show(toast);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Toast: Failed to show quarantine notification");
        }
    }

    /// <summary>
    /// Shows a process termination notification.
    /// </summary>
    public void ShowProcessTerminated(string processName, int pid, string reason)
    {
        try
        {
            var toastXml = ToastNotificationManager.GetTemplateContent(ToastTemplateType.ToastText02);
            
            var textElements = toastXml.GetElementsByTagName("text");
            textElements[0].AppendChild(toastXml.CreateTextNode($"🛡 Process Terminated"));
            textElements[1].AppendChild(toastXml.CreateTextNode($"{processName} (PID {pid}) - {reason}"));

            var toast = new ToastNotification(toastXml);
            toast.Tag = "terminated";
            toast.Group = "sentinel";
            
            ToastNotificationManager.CreateToastNotifier(_appId).Show(toast);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Toast: Failed to show termination notification");
        }
    }

    /// <summary>
    /// Shows a self-protection alert.
    /// </summary>
    public void ShowSelfProtectionAlert(string threat, string action)
    {
        try
        {
            var toastXml = ToastNotificationManager.GetTemplateContent(ToastTemplateType.ToastText02);
            
            var textElements = toastXml.GetElementsByTagName("text");
            textElements[0].AppendChild(toastXml.CreateTextNode($"🔒 Sentinel Self-Protection"));
            textElements[1].AppendChild(toastXml.CreateTextNode($"{threat} - {action}"));

            var toast = new ToastNotification(toastXml);
            toast.Tag = "selfprotection";
            toast.Group = "sentinel";
            
            ToastNotificationManager.CreateToastNotifier(_appId).Show(toast);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Toast: Failed to show self-protection notification");
        }
    }

    /// <summary>
    /// Shows a general info notification.
    /// </summary>
    public void ShowInfo(string title, string message)
    {
        try
        {
            var toastXml = ToastNotificationManager.GetTemplateContent(ToastTemplateType.ToastText02);
            
            var textElements = toastXml.GetElementsByTagName("text");
            textElements[0].AppendChild(toastXml.CreateTextNode(title));
            textElements[1].AppendChild(toastXml.CreateTextNode(message));

            var toast = new ToastNotification(toastXml);
            toast.Tag = "info";
            toast.Group = "sentinel";
            
            ToastNotificationManager.CreateToastNotifier(_appId).Show(toast);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Toast: Failed to show info notification");
        }
    }

    /// <summary>
    /// Clears all Sentinel notifications.
    /// </summary>
    public void ClearAllNotifications()
    {
        try
        {
            ToastNotificationManager.History.Clear(_appId);
            _logger.LogDebug("Toast: All notifications cleared");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Toast: Failed to clear notifications");
        }
    }

    private void RegisterAppForNotification()
    {
        try
        {
            // In a real implementation, this would register with the Windows notification system
            // For now, we rely on the standard ToastNotifier which works for desktop apps
            _logger.LogDebug("Toast: Notification service initialized");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Toast: Failed to register for notifications");
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
    public bool EnableInfoToasts { get; set; } = false; // Off by default
}
