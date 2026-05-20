using System.Diagnostics;
using System.Management;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Detects audio output redirection to microphone devices.
/// Ported from GIDR's AudioHijackDetection with security hardening.
/// 
/// Detects spyware/audio recorders that redirect system audio to virtual
/// microphones for stealthy recording (e.g., " Stereo Mix", "What U Hear", 
/// VB-Audio virtual cables).
/// </summary>
public sealed class AudioHijackRule : IDetectionRule
{
    public string Name => "Audio Hijack / Mic Redirection";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    private readonly ILogger<AudioHijackRule> _logger;
    private readonly ProcessValidator _processValidator;
    
    // Rate limiting: max 1 detection per process per hour
    private readonly Dictionary<string, DateTime> _lastDetection = new();
    private readonly object _lock = new();

    // Audio DLL indicators - loaded when process uses audio
    private static readonly HashSet<string> AudioOutputDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "audioses.dll", "audioeng.dll", "mmdevapi.dll", "audioclient.dll"
    };

    private static readonly HashSet<string> MicInputDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "portaudio.dll", "naudio.dll", "directsound.dll", "winmm.dll",
        "mfreadwrite.dll", "mf.dll", "wmcodecdsp.dll"
    };

    // Command-line patterns indicating mic redirection
    // SECURITY: These are checked against validated command-line strings only
    private static readonly string[] MicRedirectionPatterns = new[]
    {
        "-output=mic", "-output mic", "--output-mic", "-out=mic",
        "playback=mic", "playback mic", "-to=mic", "-to mic",
        "-redirect=mic", "-redirect mic", "-sink=mic", "-sink mic",
        "audioout=mic", "audioout mic", "virtualmic", "mic=loopback",
        "stereomix", "stereo mix", "whatuh", "what u hear",
        "cable output", "vb-audio", "voiceoutput", "outputdevice=mic",
        "render=mic", "endpoint=mic", "loopback=mic", "listen=mic"
    };

    // Whitelisted audio applications that legitimately use both input/output
    private static readonly HashSet<string> WhitelistedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "teams", "zoom", "slack", "discord", "skype",
        "obs", "obs64", "streamlabs obs", "xsplit",
        "audacity", "adobe audition", "reaper", "ableton",
        "voicemeeter", "voicemeeter8", "voice_meeter",
        "steam", "steamwebhelper", "chrome", "firefox", "edge",
        "spotify", "itunes", "vlc", "wmplayer"
    };

    public AudioHijackRule(ILogger<AudioHijackRule> logger, ProcessValidator processValidator)
    {
        _logger = logger;
        _processValidator = processValidator;
    }

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;
        if (proc.EventType != "ProcessStart") return null;

        // Skip whitelisted legitimate audio applications
        if (WhitelistedProcesses.Contains(proc.ProcessName))
            return null;

        // Skip system processes
        if (proc.ProcessId <= 4) return null;

        // Rate limit: one detection per unique process per hour
        string cacheKey = $"{proc.ProcessName}:{proc.ProcessId}";
        lock (_lock)
        {
            if (_lastDetection.TryGetValue(cacheKey, out var lastTime))
            {
                if ((DateTime.UtcNow - lastTime).TotalHours < 1)
                    return null;
            }
        }

        try
        {
            // SECURITY: Validate PID before querying
            if (!_processValidator.IsValidPid(proc.ProcessId))
            {
                _logger.LogDebug("Skipping audio check for invalid PID {Pid}", proc.ProcessId);
                return null;
            }

            // Check process modules for audio DLLs
            bool hasAudioOutput = false;
            bool hasMicInput = false;

            try
            {
                using var process = Process.GetProcessById(proc.ProcessId);
                foreach (ProcessModule module in process.Modules)
                {
                    string modName = Path.GetFileName(module.FileName ?? "").ToLowerInvariant();
                    
                    if (AudioOutputDlls.Contains(modName))
                        hasAudioOutput = true;
                    if (MicInputDlls.Contains(modName))
                        hasMicInput = true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not enumerate modules for PID {Pid}", proc.ProcessId);
                // Continue - command-line check may still detect
            }

            // Check command line for mic redirection patterns
            // SECURITY: Command line is already validated by ProcessValidator before reaching here
            bool hasMicRedirection = false;
            string cmdLine = (proc.CommandLine ?? "").ToLowerInvariant();
            
            foreach (var pattern in MicRedirectionPatterns)
            {
                if (cmdLine.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    hasMicRedirection = true;
                    break;
                }
            }

            // Detection logic: must have both audio output AND mic input indicators
            // AND show mic redirection patterns in command line
            if ((hasAudioOutput && hasMicInput && hasMicRedirection) ||
                // OR: explicit mic redirection command WITH virtual audio indicators
                (hasMicRedirection && (cmdLine.Contains("virtual") || cmdLine.Contains("loopback") || cmdLine.Contains("stereomix"))))
            {
                // Rate limit update
                lock (_lock)
                {
                    _lastDetection[cacheKey] = DateTime.UtcNow;
                }

                string evidence = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) " +
                    $"detected with audio output-to-microphone redirection. " +
                    $"Audio DLLs present: {(hasAudioOutput ? "Output" : "")} {(hasMicInput ? "Input" : "")}. " +
                    $"Command line indicates mic redirection.";

                return new DetectionEvent
                {
                    RuleName = Name,
                    Evidence = evidence,
                    Reasoning = "Audio output redirected to microphone device is a technique used by spyware " +
                        "and audio recording malware to capture system audio (microphone hijacking). " +
                        "Common tools include Virtual Audio Cable, Stereo Mix, and custom redirection utilities. " +
                        "This detection identifies processes combining audio I/O capabilities with explicit " +
                        "mic redirection command-line arguments.",
                    Confidence = (hasAudioOutput && hasMicInput) ? 0.92 : 0.78,
                    Tier = Tier,
                    ProcessName = proc.ProcessName,
                    ProcessId = proc.ProcessId,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new()
                    {
                        ["HasAudioOutput"] = hasAudioOutput.ToString(),
                        ["HasMicInput"] = hasMicInput.ToString(),
                        ["HasMicRedirection"] = hasMicRedirection.ToString(),
                        ["CommandLine"] = proc.CommandLine?.Substring(0, Math.Min(proc.CommandLine?.Length ?? 0, 500)) ?? "",
                        ["AudioDlls"] = string.Join(",", AudioOutputDlls.Intersect(GetLoadedDllsSafe(proc.ProcessId))),
                        ["MicDlls"] = string.Join(",", MicInputDlls.Intersect(GetLoadedDllsSafe(proc.ProcessId)))
                    }
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Audio hijack detection failed for {Process} PID {Pid}", 
                proc.ProcessName, proc.ProcessId);
        }

        return null;
    }

    /// <summary>
    /// SECURITY: Safely get loaded DLLs with exception handling
    /// </summary>
    private HashSet<string> GetLoadedDllsSafe(int pid)
    {
        var dlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var process = Process.GetProcessById(pid);
            foreach (ProcessModule module in process.Modules)
            {
                dlls.Add(Path.GetFileName(module.FileName ?? "").ToLowerInvariant());
            }
        }
        catch { }
        return dlls;
    }
}

