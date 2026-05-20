using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Clipboard Security Monitor — Detects unauthorized clipboard access and exfiltration.
///
/// Monitors for:
///   1. Processes that repeatedly read/own the clipboard without user interaction
///   2. Clipboard content changes not initiated by foreground window (clipboard hijacking)
///   3. Rapid clipboard sequence number changes indicating automated scraping
///   4. Background processes (no visible window) taking clipboard ownership
///
/// This catches:
///   - Clipboard-stealing malware (infostealers, keyloggers)
///   - Crypto address swappers (replace copied wallet addresses)
///   - Clipboard exfiltration tools
///   - Unauthorized clipboard monitoring/logging
///
/// Detection philosophy:
///   - Foreground window owning clipboard = normal (user copied something)
///   - Background process owning clipboard without user action = suspicious
///   - Rapid clipboard changes from same process = highly suspicious
///   - Process with no window taking ownership repeatedly = malicious pattern
/// </summary>
public sealed class ClipboardMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<ClipboardMonitor> _logger;
    private readonly TelemetryFusionEngine? _fusionEngine;

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan RapidChangeWindow = TimeSpan.FromSeconds(10);
    private const int RapidChangeThreshold = 5; // 5+ changes in 10s = suspicious
    private const int BackgroundOwnershipThreshold = 3; // 3+ times bg process owns clipboard

    // Track clipboard sequence changes
    private uint _lastSequenceNumber;
    private readonly ConcurrentDictionary<int, ClipboardAccessRecord> _processAccessHistory = new();
    private readonly ConcurrentDictionary<int, DateTimeOffset> _alertedPids = new();

    // Allowlist: processes that legitimately access clipboard
    private static readonly HashSet<string> AllowedClipboardProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "explorer.exe",
        "svchost", "svchost.exe",
        "dwm", "dwm.exe",
        "csrss", "csrss.exe",
        "conhost", "conhost.exe",
        "ctfmon", "ctfmon.exe",             // Text input framework
        "textinputhost", "textinputhost.exe",
        "searchhost", "searchhost.exe",
        "shellexperiencehost", "shellexperiencehost.exe",
        "runtimebroker", "runtimebroker.exe",
        "applicationframehost", "applicationframehost.exe",
        "sentinelservice", "sentinelservice.exe",
        "sentinelagent", "sentinelagent.exe",
        "powershell", "powershell.exe",
        "pwsh", "pwsh.exe",
        "cmd", "cmd.exe",
        // Clipboard managers (legitimate)
        "ditto", "ditto.exe",
        "clipx", "clipx.exe",
        "copyq", "copyq.exe",
        // Remote desktop
        "rdpclip", "rdpclip.exe",
        "mstsc", "mstsc.exe",
        // Password managers
        "1password", "1password.exe",
        "keepass", "keepass.exe",
        "keepassxc", "keepassxc.exe",
        "bitwarden", "bitwarden.exe",
        "lastpass", "lastpass.exe",
    };

    // Browsers are allowed to own clipboard (user copies from web pages)
    private static readonly HashSet<string> BrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "msedge", "msedge.exe",
        "chrome", "chrome.exe",
        "firefox", "firefox.exe",
        "brave", "brave.exe",
        "opera", "opera.exe",
        "vivaldi", "vivaldi.exe",
        "iexplore", "iexplore.exe",
    };

    // IDE/editors that legitimately use clipboard
    private static readonly HashSet<string> EditorProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "code", "code.exe",                 // VS Code
        "kiro", "kiro.exe",                 // Kiro
        "devenv", "devenv.exe",             // Visual Studio
        "notepad", "notepad.exe",
        "notepad++", "notepad++.exe",
        "sublime_text", "sublime_text.exe",
        "idea64", "idea64.exe",             // IntelliJ
        "rider64", "rider64.exe",           // JetBrains Rider
        "winword", "winword.exe",           // Word
        "excel", "excel.exe",
        "powerpnt", "powerpnt.exe",
        "outlook", "outlook.exe",
        "teams", "teams.exe",
        "slack", "slack.exe",
        "discord", "discord.exe",
        "telegram", "telegram.exe",
    };

    [DllImport("user32.dll")]
    private static extern IntPtr GetClipboardOwner();

    [DllImport("user32.dll")]
    private static extern IntPtr GetOpenClipboardWindow();

    [DllImport("user32.dll")]
    private static extern int GetWindowThreadProcessId(IntPtr hWnd, out int processId);

    [DllImport("user32.dll")]
    private static extern uint GetClipboardSequenceNumber();

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern int GetWindowText(IntPtr hWnd, char[] text, int count);

    public ClipboardMonitor(
        IDetectionEngine detectionEngine,
        ILogger<ClipboardMonitor> logger,
        TelemetryFusionEngine? fusionEngine = null)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _fusionEngine = fusionEngine;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Clipboard Security Monitor starting ===");

        // Initial delay to let system stabilize
        await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);

        _lastSequenceNumber = GetClipboardSequenceNumber();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await MonitorClipboardAsync(stoppingToken);
                await Task.Delay(PollInterval, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ClipboardMonitor: Scan error");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
    }

    private async Task MonitorClipboardAsync(CancellationToken ct)
    {
        var currentSequence = GetClipboardSequenceNumber();
        var now = DateTimeOffset.UtcNow;

        // Check if clipboard was modified
        if (currentSequence != _lastSequenceNumber)
        {
            var ownerHwnd = GetClipboardOwner();
            if (ownerHwnd != IntPtr.Zero)
            {
                GetWindowThreadProcessId(ownerHwnd, out int ownerPid);
                if (ownerPid > 0)
                {
                    await AnalyzeClipboardOwner(ownerPid, currentSequence, now, ct);
                }
            }

            _lastSequenceNumber = currentSequence;
        }

        // Check if any process currently has clipboard locked (open)
        var openHwnd = GetOpenClipboardWindow();
        if (openHwnd != IntPtr.Zero)
        {
            GetWindowThreadProcessId(openHwnd, out int lockingPid);
            if (lockingPid > 0)
            {
                await CheckClipboardLock(lockingPid, now, ct);
            }
        }

        // Prune old records
        PruneHistory(now);
    }

    private async Task AnalyzeClipboardOwner(int pid, uint sequence, DateTimeOffset now, CancellationToken ct)
    {
        System.Diagnostics.Process? process = null;
        try
        {
            process = System.Diagnostics.Process.GetProcessById(pid);
        }
        catch { return; } // Process exited

        var processName = process.ProcessName;

        // Track access history for ALL processes (even allowed ones) to detect hijacking
        var record = _processAccessHistory.GetOrAdd(pid, _ => new ClipboardAccessRecord
        {
            ProcessName = processName,
            FirstSeen = now
        });

        record.AccessCount++;
        record.LastSeen = now;
        record.SequenceChanges.Add(now);

        // Remove old sequence changes outside the window
        record.SequenceChanges.RemoveAll(t => now - t > RapidChangeWindow);

        // For allowed processes: only alert on extreme abuse patterns (hijacked process)
        if (IsAllowedProcess(processName))
        {
            // Even legitimate processes shouldn't be changing clipboard 10+ times in 10s
            // from the background — that indicates DLL injection or COM hijack
            var foregroundHwnd = GetForegroundWindow();
            GetWindowThreadProcessId(foregroundHwnd, out int foregroundPid);

            if (foregroundPid != pid && record.SequenceChanges.Count >= RapidChangeThreshold * 2)
            {
                await EmitHijackedProcessClipboardAbuse(process, record, ct);
            }

            process.Dispose();
            return;
        }

        // Check for rapid clipboard changes (automated scraping)
        if (record.SequenceChanges.Count >= RapidChangeThreshold)
        {
            await EmitRapidClipboardAccess(process, record, ct);
        }

        // Check if this is a background process (no visible window) taking ownership
        {
            var foregroundHwnd = GetForegroundWindow();
            GetWindowThreadProcessId(foregroundHwnd, out int foregroundPid);

            if (foregroundPid != pid && !HasVisibleWindow(process))
            {
                record.BackgroundOwnershipCount++;

                if (record.BackgroundOwnershipCount >= BackgroundOwnershipThreshold)
                {
                    await EmitBackgroundClipboardHijack(process, record, ct);
                }
            }
        }

        process.Dispose();
    }

    private async Task CheckClipboardLock(int pid, DateTimeOffset now, CancellationToken ct)
    {
        System.Diagnostics.Process? process = null;
        try
        {
            process = System.Diagnostics.Process.GetProcessById(pid);
        }
        catch { return; }

        var processName = process.ProcessName;

        // Skip allowed processes
        if (IsAllowedProcess(processName))
        {
            process.Dispose();
            return;
        }

        // A process holding clipboard open for extended time is suspicious
        // (we poll every 3s, so if we catch it locked twice in a row, it's been held 3+ seconds)
        var record = _processAccessHistory.GetOrAdd(pid, _ => new ClipboardAccessRecord
        {
            ProcessName = processName,
            FirstSeen = now
        });

        record.LockCount++;
        record.LastSeen = now;

        // If a process has held clipboard locked across multiple polls, it's blocking other apps
        if (record.LockCount >= 3 && !_alertedPids.ContainsKey(pid))
        {
            _alertedPids[pid] = now;

            _logger.LogWarning(
                "Clipboard Lock: '{Name}' (PID {Pid}) holding clipboard locked for extended period — " +
                "blocking copy/paste for other applications",
                processName, pid);

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Clipboard Lock: Extended Hold",
                Evidence = $"Process '{processName}' (PID {pid}) has held the clipboard locked " +
                          $"for {record.LockCount * PollInterval.TotalSeconds:F0}+ seconds, " +
                          $"preventing other applications from copying/pasting.",
                Reasoning = "A process holding the clipboard open for extended periods blocks all other " +
                           "applications from using copy/paste. This can be a denial-of-service attack, " +
                           "a buggy application, or malware preventing the user from copying sensitive data " +
                           "to move it to a secure location.",
                Confidence = 0.70,
                Tier = DetectionTier.Tier2Indicator,
                ProcessName = processName,
                ProcessId = pid,
                Timestamp = now,
                Metadata = new Dictionary<string, string>
                {
                    ["lock_duration_seconds"] = (record.LockCount * PollInterval.TotalSeconds).ToString("F0"),
                    ["technique"] = "T1115 - Clipboard Data"
                }
            }, ct);
        }

        process.Dispose();
    }

    private async Task EmitRapidClipboardAccess(System.Diagnostics.Process process, ClipboardAccessRecord record, CancellationToken ct)
    {
        if (_alertedPids.ContainsKey(process.Id)) return;
        _alertedPids[process.Id] = DateTimeOffset.UtcNow;

        string? processPath = null;
        try { processPath = process.MainModule?.FileName; } catch { }

        _logger.LogWarning(
            "Clipboard Scraping: '{Name}' (PID {Pid}) made {Count} clipboard changes in {Window}s — " +
            "possible clipboard stealing/crypto swapper",
            process.ProcessName, process.Id, record.SequenceChanges.Count,
            RapidChangeWindow.TotalSeconds);

        await _detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = "Clipboard Scraping: Rapid Automated Access",
            Evidence = $"Process '{process.ProcessName}' (PID {process.Id}) caused " +
                      $"{record.SequenceChanges.Count} clipboard changes within " +
                      $"{RapidChangeWindow.TotalSeconds}s. Path: {processPath ?? "unknown"}. " +
                      $"Total accesses since first seen: {record.AccessCount}.",
            Reasoning = "Rapid clipboard modifications from a single process indicate automated clipboard " +
                       "manipulation. Common in: crypto address swappers (replace wallet addresses), " +
                       "clipboard stealers (harvest copied passwords/data), and clipboard injection attacks. " +
                       "Normal user clipboard usage is 1-2 copies per minute, not 5+ in 10 seconds.",
            Confidence = 0.85,
            Tier = DetectionTier.Tier1Behavioral,
            ProcessName = process.ProcessName,
            ProcessId = process.Id,
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["changes_in_window"] = record.SequenceChanges.Count.ToString(),
                ["window_seconds"] = RapidChangeWindow.TotalSeconds.ToString(),
                ["total_accesses"] = record.AccessCount.ToString(),
                ["process_path"] = processPath ?? "unknown",
                ["technique"] = "T1115 - Clipboard Data"
            }
        }, ct);

        // Feed telemetry fusion
        _fusionEngine?.IngestFileActivity(process.Id, process.ProcessName,
            "clipboard_scraping", FileActivityKind.Read, DateTimeOffset.UtcNow);
    }

    private async Task EmitBackgroundClipboardHijack(System.Diagnostics.Process process, ClipboardAccessRecord record, CancellationToken ct)
    {
        if (_alertedPids.ContainsKey(process.Id)) return;
        _alertedPids[process.Id] = DateTimeOffset.UtcNow;

        string? processPath = null;
        try { processPath = process.MainModule?.FileName; } catch { }

        _logger.LogWarning(
            "Clipboard Hijack: Background process '{Name}' (PID {Pid}) took clipboard ownership " +
            "{Count} times without being foreground — possible clipboard stealer/swapper",
            process.ProcessName, process.Id, record.BackgroundOwnershipCount);

        await _detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = "Clipboard Hijack: Background Process Ownership",
            Evidence = $"Background process '{process.ProcessName}' (PID {process.Id}) took clipboard " +
                      $"ownership {record.BackgroundOwnershipCount} times without being the foreground " +
                      $"window. Path: {processPath ?? "unknown"}. " +
                      $"This process has no visible window and is modifying clipboard content silently.",
            Reasoning = "Background processes that repeatedly take clipboard ownership without user " +
                       "interaction are a strong indicator of clipboard hijacking malware. Legitimate " +
                       "clipboard usage comes from the foreground application (user explicitly copies). " +
                       "Background clipboard writes indicate: crypto address swappers, clipboard stealers, " +
                       "or data exfiltration tools that replace clipboard content.",
            Confidence = 0.88,
            Tier = DetectionTier.Tier1Behavioral,
            ProcessName = process.ProcessName,
            ProcessId = process.Id,
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["background_ownership_count"] = record.BackgroundOwnershipCount.ToString(),
                ["total_accesses"] = record.AccessCount.ToString(),
                ["process_path"] = processPath ?? "unknown",
                ["has_visible_window"] = "false",
                ["technique"] = "T1115 - Clipboard Data"
            }
        }, ct);

        // Feed telemetry fusion
        _fusionEngine?.IngestFileActivity(process.Id, process.ProcessName,
            "clipboard_hijack", FileActivityKind.Write, DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Detects when a normally-allowed process (explorer, svchost, browser) is exhibiting
    /// abnormal clipboard behavior — strong indicator of DLL injection or COM hijack
    /// using the legitimate process as a proxy for clipboard exfiltration.
    /// </summary>
    private async Task EmitHijackedProcessClipboardAbuse(System.Diagnostics.Process process, ClipboardAccessRecord record, CancellationToken ct)
    {
        if (_alertedPids.ContainsKey(process.Id)) return;
        _alertedPids[process.Id] = DateTimeOffset.UtcNow;

        string? processPath = null;
        try { processPath = process.MainModule?.FileName; } catch { }

        _logger.LogWarning(
            "Clipboard Abuse via Trusted Process: '{Name}' (PID {Pid}) made {Count} clipboard changes " +
            "in {Window}s from background — possible DLL injection/COM hijack using trusted process as proxy",
            process.ProcessName, process.Id, record.SequenceChanges.Count,
            RapidChangeWindow.TotalSeconds);

        await _detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = "Clipboard Abuse: Trusted Process Hijacked",
            Evidence = $"Trusted process '{process.ProcessName}' (PID {process.Id}) caused " +
                      $"{record.SequenceChanges.Count} clipboard changes within " +
                      $"{RapidChangeWindow.TotalSeconds}s while NOT being the foreground window. " +
                      $"Path: {processPath ?? "unknown"}. " +
                      $"Normal behavior for this process is 0-2 clipboard accesses per minute.",
            Reasoning = "A normally-trusted process (browser, explorer, system service) is exhibiting " +
                       "abnormal clipboard behavior at a rate far exceeding normal usage, and it's doing " +
                       "so from the background. This strongly indicates the process has been compromised " +
                       "via DLL injection, browser extension, COM hijack, or similar technique, and is " +
                       "being used as a proxy to scrape/modify clipboard content while evading detection " +
                       "by hiding behind a trusted process name.",
            Confidence = 0.82,
            Tier = DetectionTier.Tier1Behavioral,
            ProcessName = process.ProcessName,
            ProcessId = process.Id,
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["changes_in_window"] = record.SequenceChanges.Count.ToString(),
                ["window_seconds"] = RapidChangeWindow.TotalSeconds.ToString(),
                ["total_accesses"] = record.AccessCount.ToString(),
                ["process_path"] = processPath ?? "unknown",
                ["is_trusted_process"] = "true",
                ["technique"] = "T1115 - Clipboard Data"
            }
        }, ct);

        // Feed telemetry fusion — this will correlate with network signals
        _fusionEngine?.IngestFileActivity(process.Id, process.ProcessName,
            "clipboard_hijack_trusted", FileActivityKind.Read, DateTimeOffset.UtcNow);
    }

    private bool IsAllowedProcess(string processName)
    {
        return AllowedClipboardProcesses.Contains(processName) ||
               BrowserProcesses.Contains(processName) ||
               EditorProcesses.Contains(processName);
    }

    private static bool HasVisibleWindow(System.Diagnostics.Process process)
    {
        try
        {
            return process.MainWindowHandle != IntPtr.Zero &&
                   IsWindowVisible(process.MainWindowHandle);
        }
        catch
        {
            return false;
        }
    }

    private void PruneHistory(DateTimeOffset now)
    {
        var cutoff = now.AddMinutes(-5);

        foreach (var kv in _processAccessHistory)
        {
            if (kv.Value.LastSeen < cutoff)
                _processAccessHistory.TryRemove(kv.Key, out _);
        }

        foreach (var kv in _alertedPids)
        {
            if (kv.Value < cutoff)
                _alertedPids.TryRemove(kv.Key, out _);
        }
    }

    private sealed class ClipboardAccessRecord
    {
        public required string ProcessName { get; init; }
        public required DateTimeOffset FirstSeen { get; init; }
        public DateTimeOffset LastSeen { get; set; }
        public int AccessCount { get; set; }
        public int BackgroundOwnershipCount { get; set; }
        public int LockCount { get; set; }
        public List<DateTimeOffset> SequenceChanges { get; } = new();
    }
}

