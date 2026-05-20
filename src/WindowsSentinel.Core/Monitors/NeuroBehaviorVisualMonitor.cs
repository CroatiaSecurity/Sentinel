using System.Collections.Concurrent;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// NeuroBehavior Visual Monitor — Detects visual/input manipulation attacks.
///
/// Ported from Antivirus.ps1 Invoke-NeuroBehaviorMonitor. Detects:
///   1. Focus abuse — process stealing focus rapidly (>8 times in 10s)
///   2. Flash stimulus — rapid brightness changes (strobing/flashing)
///   3. Topmost abuse — non-allowlisted process forcing WS_EX_TOPMOST
///   4. Cursor jitter — rapid programmatic cursor movement
///   5. Color distortion/inversion — screen colors being manipulated
///
/// These are Tier2 advisory signals that feed into the BehavioralCorrelationEngine.
/// They NEVER kill independently. Combined with other signals (mic session, network,
/// injection), they can produce composite kills.
///
/// Why Tier2: Games, video players, and browsers can legitimately cause rapid
/// brightness changes, topmost windows, and cursor movement. Killing on these
/// alone would destroy the user experience. But a HIDDEN background process
/// causing screen flashes while also holding a mic session? That's a composite kill.
///
/// Runs in Agent (user session) because it needs:
///   - Screen capture (CopyFromScreen)
///   - Foreground window enumeration
///   - Cursor position access
///
/// IMPORTANT: The Pre-Kill Validation Gate (v2.2.0) provides additional safety —
/// even if a composite fires, user-interactive foreground apps running stably
/// for 5+ minutes are never killed.
/// </summary>
public sealed class NeuroBehaviorVisualMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<NeuroBehaviorVisualMonitor> _logger;
    private readonly TelemetryFusionEngine? _fusionEngine;

    // Scan interval — 1 second (matches original PS1 behavior)
    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(1);

    // ── Focus abuse tracking ─────────────────────────────────────────────────
    private readonly ConcurrentDictionary<int, FocusEntry> _focusHistory = new();

    // ── Flash/brightness tracking ────────────────────────────────────────────
    private long _lastBrightness = -1;
    private int _flashScore;
    private const int FlashThreshold = 6;        // 6 rapid brightness changes = flash attack
    private const long BrightnessDelta = 40000;  // Minimum brightness change to count

    // ── Cursor jitter tracking ───────────────────────────────────────────────
    private Point _lastCursorPos;
    private DateTimeOffset _cursorFirstSeen = DateTimeOffset.MinValue;
    private int _cursorJitterCount;
    private const int CursorJitterThreshold = 6;  // 6 large jumps in 10s
    private const int CursorJitterDistance = 60;   // Minimum pixel distance to count as jitter

    // ── Color distortion tracking ────────────────────────────────────────────
    private double _lastAvgR = -1, _lastAvgG = -1, _lastAvgB = -1;
    private int _distortScore;
    private const int DistortThreshold = 5;       // 5 rapid color shifts = distortion attack
    private const double ColorInversionTolerance = 25.0;
    private const double ColorShiftThreshold = 70.0;

    // ── Deduplication (report each process only once per type) ────────────────
    private readonly ConcurrentDictionary<string, DateTimeOffset> _reportedItems = new();
    private static readonly TimeSpan ReportCooldown = TimeSpan.FromMinutes(5);

    // ── Topmost allowlist (legitimate always-on-top processes) ────────────────
    private static readonly HashSet<string> TopmostAllowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "taskmgr", "dwm", "systemsettings", "applicationframehost",
        "shellexperiencehost", "searchapp", "startmenuexperiencehost",
        "msedge", "chrome", "firefox", "brave", "opera", "vivaldi",
        "discord", "steam", "steamwebhelper", "obs64", "obs",
        "vlc", "mpc-hc64", "mpc-hc", "mpv",
        // Games commonly go topmost
        "gamebar", "gamebarftserver", "gamebarpresencewriter",
        // Sentinel itself
        "sentinelservice", "sentinelagent",
        // Media players
        "spotify", "wmplayer", "groove",
        // System tray / notifications
        "textinputhost", "lockapp", "logonui"
    };

    // ── Win32 imports ─────────────────────────────────────────────────────────

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int pid);

    [DllImport("user32.dll")]
    private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetCursorPos(out POINT lpPoint);

    private const int GWL_EXSTYLE = -20;
    private const int WS_EX_TOPMOST = 0x00000008;

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    public NeuroBehaviorVisualMonitor(
        IDetectionEngine detectionEngine,
        ILogger<NeuroBehaviorVisualMonitor> logger,
        TelemetryFusionEngine? fusionEngine = null)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
        _fusionEngine = fusionEngine;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== NeuroBehavior Visual Monitor starting (ported from Antivirus.ps1) ===");

        // Initial delay — let desktop stabilize after login
        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "NeuroBehaviorVisual: scan error");
            }

            try { await Task.Delay(ScanInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task ScanAsync(CancellationToken ct)
    {
        // Get foreground window and owning process
        var hWnd = GetForegroundWindow();
        if (hWnd == IntPtr.Zero) return;

        GetWindowThreadProcessId(hWnd, out int fgPid);
        if (fgPid <= 4) return;

        string processName;
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(fgPid);
            processName = proc.ProcessName;
        }
        catch { return; } // Process exited

        // Skip self
        if (fgPid == Environment.ProcessId) return;

        // ── Screen sample (64x64 from top-left corner) ───────────────────────
        double avgR = 0, avgG = 0, avgB = 0;
        long brightness = 0;
        bool screenSampled = false;

        try
        {
            using var bmp = new Bitmap(64, 64, PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(bmp))
            {
                g.CopyFromScreen(0, 0, 0, 0, new Size(64, 64));
            }

            long sumR = 0, sumG = 0, sumB = 0;
            int samples = 0;

            // Sample every 4th pixel for performance
            for (int x = 0; x < 64; x += 4)
            {
                for (int y = 0; y < 64; y += 4)
                {
                    var c = bmp.GetPixel(x, y);
                    sumR += c.R;
                    sumG += c.G;
                    sumB += c.B;
                    brightness += c.R + c.G + c.B;
                    samples++;
                }
            }

            if (samples > 0)
            {
                avgR = (double)sumR / samples;
                avgG = (double)sumG / samples;
                avgB = (double)sumB / samples;
                screenSampled = true;
            }
        }
        catch
        {
            // Screen capture may fail (locked screen, secure desktop, etc.)
        }

        // ── 1. Focus abuse detection ─────────────────────────────────────────
        await DetectFocusAbuse(fgPid, processName, ct);

        // ── 2. Flash stimulus detection ──────────────────────────────────────
        if (screenSampled)
            await DetectFlashStimulus(brightness, fgPid, processName, ct);

        // ── 3. Topmost abuse detection ───────────────────────────────────────
        await DetectTopmostAbuse(hWnd, fgPid, processName, ct);

        // ── 4. Cursor jitter detection ───────────────────────────────────────
        await DetectCursorJitter(fgPid, processName, ct);

        // ── 5. Color distortion/inversion detection ──────────────────────────
        if (screenSampled)
            await DetectColorDistortion(avgR, avgG, avgB, fgPid, processName, ct);

        // Update last values
        if (screenSampled)
        {
            _lastBrightness = brightness;
            _lastAvgR = avgR;
            _lastAvgG = avgG;
            _lastAvgB = avgB;
        }

        // Cleanup old dedup entries
        CleanupReportedItems();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DETECTION 1: Focus Abuse
    // A process rapidly stealing focus (>8 times in 10 seconds) indicates
    // programmatic focus manipulation — used to force user attention or
    // prevent interaction with other windows.
    // ═══════════════════════════════════════════════════════════════════════════

    private async Task DetectFocusAbuse(int pid, string processName, CancellationToken ct)
    {
        var entry = _focusHistory.GetOrAdd(pid, _ => new FocusEntry());
        var elapsed = (DateTimeOffset.UtcNow - entry.FirstSeen).TotalSeconds;

        if (elapsed > 10)
        {
            // Reset window
            entry.Count = 1;
            entry.FirstSeen = DateTimeOffset.UtcNow;
        }
        else
        {
            entry.Count++;
        }

        if (elapsed < 10 && entry.Count > 8)
        {
            if (ShouldReport($"NBM_FocusAbuse:{processName}"))
            {
                _logger.LogWarning(
                    "NeuroBehaviorVisual: Focus abuse by {Process} (PID {Pid}) — {Count} focus steals in {Elapsed:F1}s",
                    processName, pid, entry.Count, elapsed);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "NeuroBehavior: Focus Abuse",
                    Evidence = $"Process '{processName}' (PID {pid}) stole focus {entry.Count} times " +
                              $"in {elapsed:F1} seconds. Threshold: 8 in 10s.",
                    Reasoning = "Rapid programmatic focus stealing is used to force user attention, " +
                               "prevent interaction with security tools, or create disorientation. " +
                               "Normal applications do not steal focus more than 8 times in 10 seconds. " +
                               "This is a Tier2 advisory signal — it feeds composite correlation but " +
                               "does not kill independently (games/installers may legitimately refocus).",
                    Confidence = 0.60,
                    Tier = DetectionTier.Tier2Indicator,
                    ProcessName = processName,
                    ProcessId = pid,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["technique"] = "T1056 - Input Capture / Focus Manipulation",
                        ["focus_count"] = entry.Count.ToString(),
                        ["window_seconds"] = elapsed.ToString("F1"),
                        ["neuro_signal"] = "focus_abuse"
                    }
                }, ct);

                _fusionEngine?.IngestFileActivity(pid, processName,
                    "neuro_focus_abuse", FileActivityKind.Read, DateTimeOffset.UtcNow);
            }

            // Reset after reporting
            entry.Count = 0;
            entry.FirstSeen = DateTimeOffset.UtcNow;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DETECTION 2: Flash Stimulus
    // Rapid brightness oscillation (strobing) can cause disorientation,
    // seizures, or be used as a subliminal influence technique.
    // ═══════════════════════════════════════════════════════════════════════════

    private async Task DetectFlashStimulus(long brightness, int pid, string processName, CancellationToken ct)
    {
        if (_lastBrightness < 0) return; // First sample, no comparison

        var delta = Math.Abs(brightness - _lastBrightness);

        if (delta > BrightnessDelta)
        {
            _flashScore++;
        }
        else
        {
            _flashScore = Math.Max(0, _flashScore - 1);
        }

        if (_flashScore >= FlashThreshold)
        {
            if (ShouldReport($"NBM_Flash:{processName}"))
            {
                _logger.LogWarning(
                    "NeuroBehaviorVisual: Flash stimulus detected from {Process} (PID {Pid}) — score {Score}",
                    processName, pid, _flashScore);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "NeuroBehavior: Flash Stimulus",
                    Evidence = $"Rapid brightness oscillation detected while '{processName}' (PID {pid}) " +
                              $"is in foreground. Flash score: {_flashScore}/{FlashThreshold}. " +
                              $"Last delta: {delta} (threshold: {BrightnessDelta}).",
                    Reasoning = "Rapid screen brightness changes (strobing/flashing) can cause " +
                               "disorientation, photosensitive seizures, or be used as a subliminal " +
                               "influence technique. This is a Tier2 advisory signal — video content " +
                               "and games can legitimately cause brightness changes. Combined with " +
                               "other neuro signals or mic/network activity, it becomes a composite kill.",
                    Confidence = 0.55,
                    Tier = DetectionTier.Tier2Indicator,
                    ProcessName = processName,
                    ProcessId = pid,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["technique"] = "T1499 - Endpoint Denial of Service / Visual Manipulation",
                        ["flash_score"] = _flashScore.ToString(),
                        ["brightness_delta"] = delta.ToString(),
                        ["neuro_signal"] = "flash_stimulus"
                    }
                }, ct);

                _fusionEngine?.IngestFileActivity(pid, processName,
                    "neuro_flash_stimulus", FileActivityKind.Read, DateTimeOffset.UtcNow);
            }

            _flashScore = 0; // Reset after reporting
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DETECTION 3: Topmost Abuse
    // Non-allowlisted process forcing WS_EX_TOPMOST to overlay all windows.
    // Used for phishing overlays, attention forcing, or blocking security UI.
    // ═══════════════════════════════════════════════════════════════════════════

    private async Task DetectTopmostAbuse(IntPtr hWnd, int pid, string processName, CancellationToken ct)
    {
        var exStyle = GetWindowLong(hWnd, GWL_EXSTYLE);
        if ((exStyle & WS_EX_TOPMOST) == 0) return; // Not topmost

        if (TopmostAllowlist.Contains(processName)) return; // Allowlisted

        if (ShouldReport($"NBM_Topmost:{processName}"))
        {
            _logger.LogWarning(
                "NeuroBehaviorVisual: Topmost abuse by {Process} (PID {Pid})",
                processName, pid);

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "NeuroBehavior: Topmost Abuse",
                Evidence = $"Process '{processName}' (PID {pid}) has WS_EX_TOPMOST style set " +
                          $"and is not in the allowlist of known legitimate topmost applications.",
                Reasoning = "A non-allowlisted process forcing itself to always-on-top can be used " +
                           "for transparent overlay phishing, blocking access to security tools, " +
                           "or forcing user attention. This is a Tier2 advisory signal — some " +
                           "legitimate apps use topmost (media players, sticky notes). Combined " +
                           "with injection or network signals, it becomes a composite kill.",
                Confidence = 0.50,
                Tier = DetectionTier.Tier2Indicator,
                ProcessName = processName,
                ProcessId = pid,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["technique"] = "T1036 - Masquerading / Overlay",
                    ["window_style"] = $"0x{exStyle:X8}",
                    ["neuro_signal"] = "topmost_abuse"
                }
            }, ct);

            _fusionEngine?.IngestFileActivity(pid, processName,
                "neuro_topmost_abuse", FileActivityKind.Read, DateTimeOffset.UtcNow);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DETECTION 4: Cursor Jitter
    // Rapid programmatic cursor movement (>6 large jumps in 10s) indicates
    // cursor manipulation — used to disorient or prevent user interaction.
    // ═══════════════════════════════════════════════════════════════════════════

    private async Task DetectCursorJitter(int pid, string processName, CancellationToken ct)
    {
        if (!GetCursorPos(out POINT pos)) return;

        var dx = Math.Abs(pos.X - _lastCursorPos.X);
        var dy = Math.Abs(pos.Y - _lastCursorPos.Y);
        _lastCursorPos = new Point(pos.X, pos.Y);

        if (_cursorFirstSeen == DateTimeOffset.MinValue)
        {
            _cursorFirstSeen = DateTimeOffset.UtcNow;
            return;
        }

        var elapsed = (DateTimeOffset.UtcNow - _cursorFirstSeen).TotalSeconds;

        if (elapsed > 10)
        {
            // Reset window
            _cursorJitterCount = 0;
            _cursorFirstSeen = DateTimeOffset.UtcNow;
            return;
        }

        if (dx + dy > CursorJitterDistance)
        {
            _cursorJitterCount++;
        }

        if (elapsed < 10 && _cursorJitterCount > CursorJitterThreshold)
        {
            if (ShouldReport($"NBM_Cursor:{processName}"))
            {
                _logger.LogWarning(
                    "NeuroBehaviorVisual: Cursor jitter abuse from {Process} (PID {Pid}) — {Count} jumps in {Elapsed:F1}s",
                    processName, pid, _cursorJitterCount, elapsed);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "NeuroBehavior: Cursor Jitter",
                    Evidence = $"Rapid cursor movement detected while '{processName}' (PID {pid}) " +
                              $"is in foreground. {_cursorJitterCount} large jumps (>{CursorJitterDistance}px) " +
                              $"in {elapsed:F1} seconds. Threshold: {CursorJitterThreshold} in 10s.",
                    Reasoning = "Rapid programmatic cursor movement can be used to disorient the user, " +
                               "prevent interaction with security dialogs, or indicate a remote access " +
                               "tool actively controlling the mouse. This is a Tier2 advisory signal — " +
                               "FPS games and drawing apps cause rapid cursor movement legitimately. " +
                               "Combined with injection or network signals, it becomes a composite kill.",
                    Confidence = 0.50,
                    Tier = DetectionTier.Tier2Indicator,
                    ProcessName = processName,
                    ProcessId = pid,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["technique"] = "T1056 - Input Capture / Cursor Manipulation",
                        ["jitter_count"] = _cursorJitterCount.ToString(),
                        ["window_seconds"] = elapsed.ToString("F1"),
                        ["neuro_signal"] = "cursor_jitter"
                    }
                }, ct);

                _fusionEngine?.IngestFileActivity(pid, processName,
                    "neuro_cursor_jitter", FileActivityKind.Read, DateTimeOffset.UtcNow);
            }

            // Reset after reporting
            _cursorJitterCount = 0;
            _cursorFirstSeen = DateTimeOffset.UtcNow;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DETECTION 5: Color Distortion / Inversion
    // Screen colors being inverted or rapidly shifted indicates visual
    // manipulation — used for disorientation or subliminal influence.
    // ═══════════════════════════════════════════════════════════════════════════

    private async Task DetectColorDistortion(double avgR, double avgG, double avgB,
        int pid, string processName, CancellationToken ct)
    {
        if (_lastAvgR < 0) return; // First sample

        // Check for color inversion (current ≈ inverse of previous)
        double invR = 255 - _lastAvgR;
        double invG = 255 - _lastAvgG;
        double invB = 255 - _lastAvgB;

        bool isInversion = Math.Abs(avgR - invR) < ColorInversionTolerance &&
                          Math.Abs(avgG - invG) < ColorInversionTolerance &&
                          Math.Abs(avgB - invB) < ColorInversionTolerance;

        if (isInversion)
        {
            if (ShouldReport($"NBM_Color:{processName}"))
            {
                _logger.LogWarning(
                    "NeuroBehaviorVisual: Color inversion detected from {Process} (PID {Pid})",
                    processName, pid);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "NeuroBehavior: Color Inversion",
                    Evidence = $"Screen color inversion detected while '{processName}' (PID {pid}) " +
                              $"is in foreground. Current RGB ({avgR:F0},{avgG:F0},{avgB:F0}) ≈ " +
                              $"inverse of previous ({_lastAvgR:F0},{_lastAvgG:F0},{_lastAvgB:F0}).",
                    Reasoning = "Screen color inversion is a visual manipulation technique that can " +
                               "cause disorientation or be used as a subliminal influence method. " +
                               "Normal applications do not invert screen colors. This is a Tier2 " +
                               "advisory signal — accessibility features (high contrast) can trigger " +
                               "this. Combined with other neuro signals, it becomes a composite kill.",
                    Confidence = 0.65,
                    Tier = DetectionTier.Tier2Indicator,
                    ProcessName = processName,
                    ProcessId = pid,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["technique"] = "T1499 - Visual Manipulation / Color Inversion",
                        ["current_rgb"] = $"{avgR:F0},{avgG:F0},{avgB:F0}",
                        ["previous_rgb"] = $"{_lastAvgR:F0},{_lastAvgG:F0},{_lastAvgB:F0}",
                        ["neuro_signal"] = "color_inversion"
                    }
                }, ct);

                _fusionEngine?.IngestFileActivity(pid, processName,
                    "neuro_color_inversion", FileActivityKind.Read, DateTimeOffset.UtcNow);
            }
        }
        else
        {
            // Check for rapid color distortion (large shift without inversion)
            double dR = Math.Abs(avgR - _lastAvgR);
            double dG = Math.Abs(avgG - _lastAvgG);
            double dB = Math.Abs(avgB - _lastAvgB);
            double maxDelta = Math.Max(dR, Math.Max(dG, dB));

            if (maxDelta > ColorShiftThreshold)
            {
                _distortScore++;
            }
            else
            {
                _distortScore = Math.Max(0, _distortScore - 1);
            }

            if (_distortScore >= DistortThreshold)
            {
                if (ShouldReport($"NBM_Distort:{processName}"))
                {
                    _logger.LogWarning(
                        "NeuroBehaviorVisual: Screen distortion from {Process} (PID {Pid}) — score {Score}",
                        processName, pid, _distortScore);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "NeuroBehavior: Screen Distortion",
                        Evidence = $"Rapid screen color distortion detected while '{processName}' " +
                                  $"(PID {pid}) is in foreground. Distortion score: " +
                                  $"{_distortScore}/{DistortThreshold}. Max channel delta: {maxDelta:F0}.",
                        Reasoning = "Rapid color shifts without inversion indicate screen manipulation " +
                                   "— potentially subliminal color cycling or visual disorientation. " +
                                   "This is a Tier2 advisory signal — video content and games cause " +
                                   "rapid color changes legitimately. Combined with mic/network signals, " +
                                   "it becomes a composite kill.",
                        Confidence = 0.55,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = processName,
                        ProcessId = pid,
                        Timestamp = DateTimeOffset.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            ["technique"] = "T1499 - Visual Manipulation / Color Distortion",
                            ["distort_score"] = _distortScore.ToString(),
                            ["max_channel_delta"] = maxDelta.ToString("F0"),
                            ["neuro_signal"] = "color_distortion"
                        }
                    }, ct);

                    _fusionEngine?.IngestFileActivity(pid, processName,
                        "neuro_color_distortion", FileActivityKind.Read, DateTimeOffset.UtcNow);
                }

                _distortScore = 0; // Reset after reporting
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private bool ShouldReport(string key)
    {
        if (_reportedItems.TryGetValue(key, out var lastReport))
        {
            if (DateTimeOffset.UtcNow - lastReport < ReportCooldown)
                return false;
        }
        _reportedItems[key] = DateTimeOffset.UtcNow;
        return true;
    }

    private void CleanupReportedItems()
    {
        var cutoff = DateTimeOffset.UtcNow - ReportCooldown;
        foreach (var kv in _reportedItems)
        {
            if (kv.Value < cutoff)
                _reportedItems.TryRemove(kv.Key, out _);
        }

        // Cleanup old focus entries
        foreach (var kv in _focusHistory)
        {
            if ((DateTimeOffset.UtcNow - kv.Value.FirstSeen).TotalMinutes > 5)
                _focusHistory.TryRemove(kv.Key, out _);
        }
    }

    private sealed class FocusEntry
    {
        public int Count;
        public DateTimeOffset FirstSeen = DateTimeOffset.UtcNow;
    }
}


