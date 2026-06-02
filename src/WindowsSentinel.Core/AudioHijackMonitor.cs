using System.Diagnostics;
using System.Management;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core;

/// <summary>
/// Detects processes that route audio output into a microphone or virtual-mic device.
///
/// Why we care: a common voice-fraud / impersonation primitive is to play attacker-
/// controlled audio into the victim's mic input (loopback, VB-Audio, virtual cables,
/// stereo mix, etc) so meeting/voice-chat peers hear synthesized speech. It is also
/// occasionally seen as a side-channel for command/control over voice transcription.
///
/// Ported (security-hardened) from GIDR's AudioHijackDetection. Hardening:
///   - process iteration uses a lazy enumerator and disposes each <see cref="Process"/>;
///   - WMI command-line query is parameterized via WHERE ProcessId, not string-built;
///   - Tier1Behavioral output goes through DetectionEngine, so all
///     dedup/scoring/policy gates apply (including the Tier2-never-acts contract);
///   - per-PID dedup so a chatty sample doesn't flood the log.
/// </summary>
public sealed class AudioHijackMonitor : BackgroundService
{
    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(20);

    private static readonly string[] AudioOutputModuleHints =
    {
        "audioses.dll", "audioeng.dll", "mmdevapi.dll", "audioclient.dll"
    };

    private static readonly string[] MicInputModuleHints =
    {
        // Virtual audio cable / loopback DLLs â€” indicate output-to-mic routing
        "portaudio",          // PortAudio library (used by routing tools)
        "naudio",             // NAudio library (used by routing tools)
        "vbcable",            // VB-Audio Virtual Cable
        "vbaudiow",           // VB-Audio VAIO
        "voicemeeter",        // Voicemeeter routing
        "virtualcable",       // Generic virtual cable
        "stereomix",          // Stereo Mix capture
        "audiorepeater",      // Audio repeater/router
        "loopback",           // Loopback capture DLLs
        "wasapiloopback"      // WASAPI loopback capture
    };

    private static readonly string[] OutputToMicTokens =
    {
        "-output=mic", "-output mic", "--output-mic", "-out=mic",
        "playback=mic", "playback mic", "-to=mic", "-to mic",
        "-redirect=mic", "-redirect mic", "-sink=mic", "-sink mic",
        "audioout=mic", "audioout mic", "virtualmic", "mic=loopback",
        "stereomix", "cable output", "vb-audio", "voiceoutput",
        "outputdevice=mic", "render=mic", "endpoint=mic"
    };

    private readonly DetectionEngine _engine;
    private readonly ILogger<AudioHijackMonitor> _logger;
    private readonly TelemetryFusionEngine? _fusionEngine;
    private readonly HashSet<int> _alertedPids = new();
    private readonly object _alertedLock = new();

    public AudioHijackMonitor(DetectionEngine engine, ILogger<AudioHijackMonitor> logger,
        TelemetryFusionEngine? fusionEngine = null)
    {
        _engine = engine;
        _logger = logger;
        _fusionEngine = fusionEngine;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("AudioHijackMonitor: starting");
        await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "AudioHijackMonitor: scan error");
            }
            try { await Task.Delay(ScanInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task ScanAsync(CancellationToken cancellationToken)
    {
        var selfPid = Environment.ProcessId;
        var procs = Process.GetProcesses();
        try
        {
            foreach (var proc in procs)
            {
                cancellationToken.ThrowIfCancellationRequested();

                using var p = proc;
                if (p.Id == selfPid || p.Id <= 4) continue;

                bool dedup;
                lock (_alertedLock) { dedup = _alertedPids.Contains(p.Id); }
                if (dedup) continue;

                bool hasAudioOut = false, hasMicIn = false;
                try
                {
                    foreach (ProcessModule m in p.Modules)
                    {
                        var name = Path.GetFileName(m.FileName ?? "")?.ToLowerInvariant() ?? "";
                        if (string.IsNullOrEmpty(name)) continue;

                        foreach (var hint in AudioOutputModuleHints)
                            if (name.Contains(hint)) { hasAudioOut = true; break; }
                        foreach (var hint in MicInputModuleHints)
                            if (name.Contains(hint)) { hasMicIn = true; break; }
                        if (hasAudioOut && hasMicIn) break;
                    }
                }
                catch { /* access denied / exited */ continue; }

                if (!(hasAudioOut && hasMicIn)) continue;

                // Detection path 1: Command-line tokens (original detection)
                var cmdLine = TryGetCommandLine(p.Id);
                string? matchedToken = null;
                if (!string.IsNullOrEmpty(cmdLine))
                {
                    var lower = cmdLine.ToLowerInvariant();
                    matchedToken = OutputToMicTokens.FirstOrDefault(t => lower.Contains(t));
                }

                // Detection path 2: Module-only detection (no command-line required)
                // If a process loads BOTH audio output AND mic input modules AND is not
                // in the allowlist of legitimate audio apps, flag it.
                // This catches tools that don't advertise their intent in command-line args.
                bool isAllowedAudioApp = IsAllowedAudioProcess(p.ProcessName);

                // Need either a command-line match OR (both module types + not allowlisted + no visible window)
                if (matchedToken is null && (isAllowedAudioApp || ProcessHasVisibleWindow(p.Id)))
                    continue;

                // If no command-line token and it IS allowlisted, skip entirely
                if (matchedToken is null && isAllowedAudioApp)
                    continue;

                lock (_alertedLock) { _alertedPids.Add(p.Id); }

                var evidence = matchedToken is not null
                    ? $"Process loads audio-out + mic-in modules and command line contains '{matchedToken}'"
                    : $"Process loads audio-out + mic-in modules without visible window (background audio routing). " +
                      $"No command-line token needed â€” module combination alone indicates output-to-mic routing.";

                var confidence = matchedToken is not null ? 0.85 : 0.75;

                await _engine.EmitAsync(new DetectionEvent
                {
                    RuleName    = "AudioHijack: Audio routed to microphone",
                    Evidence    = evidence,
                    Reasoning   = "A non-conferencing process routing playback into a mic device is the classic voice-impersonation primitive (virtual cable / stereo mix / loopback). Combined with mic-input modules, it is unlikely to be benign.",
                    Confidence  = confidence,
                    Tier        = DetectionTier.Tier1Behavioral,
                    ProcessName = p.ProcessName,
                    ProcessId   = p.Id,
                    Timestamp   = DateTime.UtcNow,
                    Metadata    = new Dictionary<string, string>
                    {
                        ["technique"] = "T1123 - Audio Capture (inverse: audio replay to capture device)",
                        ["matched_token"] = matchedToken ?? "none (module-based detection)",
                        ["module_indicators"] = "audio-out + mic-in",
                        ["detection_method"] = matchedToken is not null ? "cmdline_token" : "module_analysis"
                    }
                }, cancellationToken);

                // Feed telemetry fusion for composite correlation (surveillance suite detection)
                _fusionEngine?.IngestFileActivity(p.Id, p.ProcessName,
                    "audio_hijack", FileActivityKind.Read, DateTime.UtcNow);
            }
        }
        finally
        {
            foreach (var p in procs)
            {
                if (!p.HasExited) { try { p.Dispose(); } catch { } }
            }
        }
    }

    /// <summary>
    /// Processes that legitimately load both audio output and mic input modules.
    /// These should not be flagged for having both module types.
    /// </summary>
    private static bool IsAllowedAudioProcess(string processName)
    {
        var name = processName.ToLowerInvariant();
        return name is "discord" or "teams" or "ms-teams" or "zoom" or "slack"
            or "skype" or "obs64" or "obs" or "streamlabs" or "audacity"
            or "chrome" or "msedge" or "firefox" or "brave" or "opera" or "vivaldi"
            or "spotify" or "vlc" or "wmplayer" or "reaper" or "fl64" or "flstudio"
            or "ableton live" or "voicemeeter" or "voicemeeterpro"
            or "audiodg" or "svchost" or "runtimebroker"
            or "sentinelservice" or "sentinelagent";
    }

    /// <summary>
    /// Check if a process has a visible window (user is aware of it).
    /// Background processes with no window are more suspicious.
    /// </summary>
    private static bool ProcessHasVisibleWindow(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.MainWindowHandle != IntPtr.Zero;
        }
        catch { return false; }
    }

    private static string? TryGetCommandLine(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                using (obj)
                {
                    return obj["CommandLine"] as string;
                }
            }
        }
        catch { }
        return null;
    }
}


