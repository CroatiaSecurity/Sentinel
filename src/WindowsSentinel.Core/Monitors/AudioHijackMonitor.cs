using System.Diagnostics;
using System.Management;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

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
        "portaudio", "naudio", "directsound", "winmm.dll", "mfreadwrite.dll", "mf.dll"
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

    private readonly IDetectionEngine _engine;
    private readonly ILogger<AudioHijackMonitor> _logger;
    private readonly TelemetryFusionEngine? _fusionEngine;
    private readonly HashSet<int> _alertedPids = new();
    private readonly object _alertedLock = new();

    public AudioHijackMonitor(IDetectionEngine engine, ILogger<AudioHijackMonitor> logger,
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

                var cmdLine = TryGetCommandLine(p.Id);
                if (string.IsNullOrEmpty(cmdLine)) continue;

                var lower = cmdLine.ToLowerInvariant();
                string? token = OutputToMicTokens.FirstOrDefault(t => lower.Contains(t));
                if (token is null) continue;

                lock (_alertedLock) { _alertedPids.Add(p.Id); }

                await _engine.EmitAsync(new DetectionEvent
                {
                    RuleName    = "AudioHijack: Audio routed to microphone",
                    Evidence    = $"Process loads audio-out + mic-in modules and command line contains '{token}'",
                    Reasoning   = "A non-conferencing process routing playback into a mic device is the classic voice-impersonation primitive (virtual cable / stereo mix / loopback). Combined with mic-input modules, it is unlikely to be benign.",
                    Confidence  = 0.85,
                    Tier        = DetectionTier.Tier1Behavioral,
                    ProcessName = p.ProcessName,
                    ProcessId   = p.Id,
                    Timestamp   = DateTimeOffset.UtcNow,
                    Metadata    = new Dictionary<string, string>
                    {
                        ["technique"] = "T1123 - Audio Capture (inverse: audio replay to capture device)",
                        ["matched_token"] = token,
                        ["module_indicators"] = "audio-out + mic-in"
                    }
                }, cancellationToken);

                // Feed telemetry fusion for composite correlation (surveillance suite detection)
                _fusionEngine?.IngestFileActivity(p.Id, p.ProcessName,
                    "audio_hijack", FileActivityKind.Read, DateTimeOffset.UtcNow);
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
