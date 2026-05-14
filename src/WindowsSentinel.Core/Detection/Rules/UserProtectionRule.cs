using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — User-facing threat detection: scareware windows, fake UAC dialogs,
/// RAT cursor takeover, and malicious LNK shortcuts.
///
/// Ported from standalone Gorstak PowerShell consultants:
///   - RansomwareScarewareDetection.ps1
///   - FakeUacDetection.ps1
///   - CursorTakeoverDetection.ps1
///   - LNKProtection.ps1
///
/// These run as periodic checks via the detection job scheduler rather than
/// per-telemetry-event evaluation.
/// </summary>
public sealed class UserProtectionRule : IDetectionRule
{
    public string Name => "User Protection (Scareware/FakeUAC/RAT)";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    private readonly ILogger<UserProtectionRule> _logger;

    // Scareware/ransom window title keywords (2+ matches = suspicious)
    private static readonly string[] RansomKeywords =
    {
        "encrypted", "bitcoin", "decrypt", "ransom", "pay to unlock",
        "your files have been", "restore your files", "microsoft support",
        "pay fine", "your computer has been locked", "call this number",
        "virus detected", "trojan detected", "send bitcoin",
        "files are encrypted", "recovery key", "wallet address"
    };

    // Fake UAC dialog keywords
    private static readonly string[] FakeUacKeywords =
    {
        "user account control", "windows security", "administrator permission",
        "do you want to allow", "requires elevation", "run as administrator"
    };

    // Processes that legitimately show these window titles
    private static readonly HashSet<string> AllowedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "logonui", "lockapp", "consent", "applicationframehost",
        "steam", "epicgameslauncher", "shellexperiencehost", "searchhost",
        "systemsettings", "securityhealthsystray", "windowsdefender"
    };

    // Known remote access tools (not inherently malicious but high-risk)
    private static readonly Dictionary<string, string> RemoteAccessTools = new(StringComparer.OrdinalIgnoreCase)
    {
        ["teamviewer"] = "TeamViewer",
        ["anydesk"] = "AnyDesk",
        ["logmein"] = "LogMeIn",
        ["supremoservice"] = "Supremo",
        ["supremo"] = "Supremo",
        ["rustdesk"] = "RustDesk",
        ["ammyy"] = "Ammyy Admin",
        ["ultraviewer"] = "UltraViewer",
        ["remotepc"] = "RemotePC",
        ["connectwise"] = "ConnectWise",
        ["screenconnect"] = "ScreenConnect",
        ["bomgar"] = "BeyondTrust (Bomgar)",
        ["splashtop"] = "Splashtop",
    };

    public UserProtectionRule(ILogger<UserProtectionRule> logger)
    {
        _logger = logger;
    }

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;
        if (proc.EventType != "ProcessStart") return null;

        // Check for known remote access tools launching
        if (RemoteAccessTools.TryGetValue(proc.ProcessName, out var toolName))
        {
            return new DetectionEvent
            {
                RuleName = "Remote Access Tool Detected",
                Evidence = $"Remote access tool '{toolName}' ({proc.ProcessName}.exe) started. " +
                          $"PID {proc.ProcessId}. Path: {proc.ImagePath}",
                Reasoning = "Remote access tools can be used legitimately but are also commonly " +
                    "abused by attackers for persistent access, data exfiltration, and social " +
                    "engineering attacks. Their presence should be monitored and verified.",
                Confidence = 0.65,
                Tier = DetectionTier.Tier2Indicator,
                ProcessName = proc.ProcessName,
                ProcessId = proc.ProcessId,
                Timestamp = proc.Timestamp,
                Metadata = new()
                {
                    ["tool_name"] = toolName,
                    ["image_path"] = proc.ImagePath,
                    ["technique"] = "T1219 - Remote Access Software"
                }
            };
        }

        return null;
    }

    /// <summary>
    /// Scans running processes for scareware/ransomware window titles.
    /// Called periodically by the detection job scheduler.
    /// </summary>
    public List<DetectionEvent> ScanForScarewareWindows()
    {
        var detections = new List<DetectionEvent>();

        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    if (string.IsNullOrEmpty(proc.MainWindowTitle)) continue;
                    if (AllowedProcesses.Contains(proc.ProcessName)) continue;

                    var title = proc.MainWindowTitle.ToLowerInvariant();
                    int hits = 0;

                    foreach (var keyword in RansomKeywords)
                    {
                        if (title.Contains(keyword)) hits++;
                    }

                    if (hits >= 2)
                    {
                        detections.Add(new DetectionEvent
                        {
                            RuleName = "Scareware/Ransomware Window Detected",
                            Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) has suspicious " +
                                      $"window title matching {hits} ransom keywords: \"{proc.MainWindowTitle}\"",
                            Reasoning = "Scareware and ransomware display threatening messages to users " +
                                "demanding payment. Multiple ransom-related keywords in a window title " +
                                "strongly indicate a scareware/ransomware screen. Legitimate software " +
                                "does not display messages about encrypted files or bitcoin payments.",
                            Confidence = hits >= 3 ? 0.92 : 0.78,
                            Tier = DetectionTier.Tier1Behavioral,
                            ProcessName = proc.ProcessName,
                            ProcessId = proc.Id,
                            Timestamp = DateTimeOffset.UtcNow,
                            Metadata = new()
                            {
                                ["window_title"] = proc.MainWindowTitle[..Math.Min(200, proc.MainWindowTitle.Length)],
                                ["keyword_hits"] = hits.ToString(),
                                ["technique"] = "T1491 - Defacement"
                            }
                        });
                    }

                    // Fake UAC detection: non-consent.exe showing UAC-like titles
                    if (!proc.ProcessName.Equals("consent", StringComparison.OrdinalIgnoreCase))
                    {
                        int uacHits = 0;
                        foreach (var keyword in FakeUacKeywords)
                        {
                            if (title.Contains(keyword)) uacHits++;
                        }

                        if (uacHits >= 2)
                        {
                            detections.Add(new DetectionEvent
                            {
                                RuleName = "Fake UAC Dialog Detected",
                                Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) displays " +
                                          $"UAC-like dialog: \"{proc.MainWindowTitle}\". " +
                                          "Only consent.exe should show UAC prompts.",
                                Reasoning = "Fake UAC dialogs are used by malware to trick users into " +
                                    "entering credentials or approving elevation. The real UAC prompt " +
                                    "only comes from consent.exe on the secure desktop. Any other process " +
                                    "showing UAC-like UI is attempting social engineering.",
                                Confidence = 0.85,
                                Tier = DetectionTier.Tier1Behavioral,
                                ProcessName = proc.ProcessName,
                                ProcessId = proc.Id,
                                Timestamp = DateTimeOffset.UtcNow,
                                Metadata = new()
                                {
                                    ["window_title"] = proc.MainWindowTitle[..Math.Min(200, proc.MainWindowTitle.Length)],
                                    ["technique"] = "T1056.002 - Input Capture: GUI Input Capture"
                                }
                            });
                        }
                    }
                }
                catch { /* Process may have exited */ }
                finally { proc.Dispose(); }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "UserProtection: Window scan error");
        }

        return detections;
    }

    /// <summary>
    /// Scans for malicious LNK shortcuts pointing to UNC paths.
    /// UNC-targeted shortcuts can steal NTLM hashes or execute remote payloads.
    /// Called periodically by the detection job scheduler.
    /// </summary>
    public List<DetectionEvent> ScanForMaliciousShortcuts()
    {
        var detections = new List<DetectionEvent>();

        try
        {
            var searchPaths = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Microsoft", "Internet Explorer", "Quick Launch", "User Pinned", "TaskBar")
            };

            foreach (var searchPath in searchPaths)
            {
                if (!Directory.Exists(searchPath)) continue;

                foreach (var lnkFile in Directory.GetFiles(searchPath, "*.lnk", SearchOption.AllDirectories))
                {
                    try
                    {
                        // Read LNK raw bytes and look for UNC paths
                        var bytes = File.ReadAllBytes(lnkFile);
                        var ascii = System.Text.Encoding.ASCII.GetString(bytes);
                        var unicode = System.Text.Encoding.Unicode.GetString(bytes);

                        bool hasUnc = ContainsUncPath(ascii) || ContainsUncPath(unicode);

                        if (hasUnc)
                        {
                            detections.Add(new DetectionEvent
                            {
                                RuleName = "Malicious LNK Shortcut (UNC Path)",
                                Evidence = $"Shortcut '{Path.GetFileName(lnkFile)}' points to a UNC path. " +
                                          $"Location: {lnkFile}. This can steal NTLM hashes or execute remote payloads.",
                                Reasoning = "LNK files targeting UNC paths (\\\\server\\share) are used in " +
                                    "NTLM relay attacks and forced authentication. When a user clicks the shortcut, " +
                                    "Windows automatically sends NTLM credentials to the remote server. " +
                                    "Attackers place these on desktops or taskbars for credential theft.",
                                Confidence = 0.82,
                                Tier = DetectionTier.Tier1Behavioral,
                                ProcessName = "Explorer",
                                ProcessId = 0,
                                Timestamp = DateTimeOffset.UtcNow,
                                Metadata = new()
                                {
                                    ["lnk_path"] = lnkFile,
                                    ["technique"] = "T1187 - Forced Authentication"
                                }
                            });
                        }
                    }
                    catch { /* Skip unreadable files */ }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "UserProtection: LNK scan error");
        }

        return detections;
    }

    private static bool ContainsUncPath(string content)
    {
        // Look for \\hostname\ pattern (UNC path)
        int idx = 0;
        while ((idx = content.IndexOf(@"\\", idx, StringComparison.Ordinal)) >= 0)
        {
            // Check it's not just escaped backslashes in a local path
            if (idx + 3 < content.Length && content[idx + 2] != '\\' && char.IsLetterOrDigit(content[idx + 2]))
            {
                return true;
            }
            idx += 2;
        }
        return false;
    }
}
