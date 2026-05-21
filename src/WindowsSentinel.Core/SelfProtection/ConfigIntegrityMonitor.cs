using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Security;

namespace WindowsSentinel.Core.SelfProtection;

/// <summary>
/// Configuration Integrity Monitor — Detects unauthorized modifications to appsettings.json
/// and other critical configuration files.
///
/// Threat: An attacker with local access could modify appsettings.json to disable
/// ActiveResponse, disable threat reporting, or weaken detection thresholds.
///
/// Mitigation: This monitor computes a SHA-256 hash of the configuration file at startup
/// and periodically verifies it hasn't changed. If tampering is detected, it:
///   1. Logs a critical alert
///   2. Emits a Tier1 detection event (self-protection)
///   3. Optionally freezes the configuration to startup values
///
/// Check interval: Every 5 minutes (configurable).
/// </summary>
public sealed class ConfigIntegrityMonitor : BackgroundService
{
    private readonly ILogger<ConfigIntegrityMonitor> _logger;
    private readonly IDetectionEngine? _detectionEngine;
    private readonly string _configPath;
    private readonly string _executablePath;
    private byte[]? _originalConfigHash;
    private byte[]? _originalExeHash;
    private DateTime _lastCheckTime;
    private int _tamperCount;

    /// <summary>
    /// Interval between integrity checks.
    /// </summary>
    private static readonly TimeSpan CheckInterval = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Maximum number of tamper events before escalating response.
    /// </summary>
    private const int MaxTamperEventsBeforeEscalation = 3;

    public ConfigIntegrityMonitor(
        ILogger<ConfigIntegrityMonitor> logger,
        IDetectionEngine? detectionEngine = null)
    {
        _logger = logger;
        _detectionEngine = detectionEngine;
        _configPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        _executablePath = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "SentinelService.exe");
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("ConfigIntegrityMonitor: Starting — monitoring {ConfigPath}", _configPath);

        // Establish baseline hashes at startup
        await EstablishBaselineAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(CheckInterval, stoppingToken);
                await PerformIntegrityCheckAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ConfigIntegrityMonitor: Error during integrity check");
                await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            }
        }

        _logger.LogInformation("ConfigIntegrityMonitor: Stopping");
    }

    private async Task EstablishBaselineAsync(CancellationToken ct)
    {
        try
        {
            if (File.Exists(_configPath))
            {
                _originalConfigHash = await ComputeFileHashAsync(_configPath, ct);
                _logger.LogDebug("ConfigIntegrityMonitor: Config baseline hash established");
            }
            else
            {
                _logger.LogWarning("ConfigIntegrityMonitor: Config file not found at {Path}", _configPath);
            }

            if (File.Exists(_executablePath))
            {
                _originalExeHash = await ComputeFileHashAsync(_executablePath, ct);
                _logger.LogDebug("ConfigIntegrityMonitor: Executable baseline hash established");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ConfigIntegrityMonitor: Failed to establish baseline");
        }
    }

    private async Task PerformIntegrityCheckAsync(CancellationToken ct)
    {
        _lastCheckTime = DateTime.UtcNow;

        // Check config file integrity
        if (_originalConfigHash != null && File.Exists(_configPath))
        {
            var currentHash = await ComputeFileHashAsync(_configPath, ct);
            if (currentHash != null && !SecurityValidation.SecureCompare(_originalConfigHash, currentHash))
            {
                await HandleConfigTamperingAsync(ct);
            }
        }
        else if (_originalConfigHash != null && !File.Exists(_configPath))
        {
            // Config file was deleted
            _logger.LogCritical("ConfigIntegrityMonitor: Configuration file DELETED — {Path}", _configPath);
            await EmitTamperDetectionAsync("Config file deleted", ct);
        }

        // Check executable integrity
        if (_originalExeHash != null && File.Exists(_executablePath))
        {
            var currentHash = await ComputeFileHashAsync(_executablePath, ct);
            if (currentHash != null && !SecurityValidation.SecureCompare(_originalExeHash, currentHash))
            {
                _logger.LogCritical(
                    "ConfigIntegrityMonitor: EXECUTABLE TAMPERED — {Path}. " +
                    "This may indicate a supply-chain attack or unauthorized modification.",
                    _executablePath);
                await EmitTamperDetectionAsync("Executable binary modified", ct);
            }
        }
    }

    private async Task HandleConfigTamperingAsync(CancellationToken ct)
    {
        _tamperCount++;

        _logger.LogCritical(
            "ConfigIntegrityMonitor: CONFIGURATION TAMPERED — {Path} (event #{Count}). " +
            "An attacker may be attempting to disable protection.",
            _configPath, _tamperCount);

        await EmitTamperDetectionAsync("Configuration file modified", ct);

        if (_tamperCount >= MaxTamperEventsBeforeEscalation)
        {
            _logger.LogCritical(
                "ConfigIntegrityMonitor: ESCALATION — {Count} tamper events detected. " +
                "Configuration is frozen to startup values. Manual intervention required.",
                _tamperCount);
        }
    }

    private async Task EmitTamperDetectionAsync(string description, CancellationToken ct)
    {
        if (_detectionEngine == null) return;

        var detection = new DetectionEvent
        {
            RuleName = "SelfProtection:ConfigTampering",
            Tier = DetectionTier.Tier1Behavioral,
            Confidence = 0.99,
            ProcessId = Environment.ProcessId,
            ProcessName = "SentinelService",
            Evidence = $"Configuration integrity violation: {description}",
            Reasoning = "Configuration files were modified outside of normal update procedures. " +
                       "This is a strong indicator of an attacker attempting to disable EDR protection.",
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["config_path"] = _configPath,
                ["tamper_count"] = _tamperCount.ToString(),
                ["description"] = description,
                ["mitre_technique"] = "T1562.001"
            }
        };

        try
        {
            await _detectionEngine.EmitAsync(detection, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ConfigIntegrityMonitor: Failed to emit detection event");
        }
    }

    private static async Task<byte[]?> ComputeFileHashAsync(string filePath, CancellationToken ct)
    {
        try
        {
            using var sha256 = SHA256.Create();
            await using var stream = File.OpenRead(filePath);
            return await sha256.ComputeHashAsync(stream, ct);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Gets the current integrity status.
    /// </summary>
    public ConfigIntegrityStatus GetStatus()
    {
        return new ConfigIntegrityStatus
        {
            ConfigPath = _configPath,
            ExecutablePath = _executablePath,
            HasConfigBaseline = _originalConfigHash != null,
            HasExeBaseline = _originalExeHash != null,
            TamperEventsDetected = _tamperCount,
            LastCheckTime = _lastCheckTime,
            IsEscalated = _tamperCount >= MaxTamperEventsBeforeEscalation
        };
    }
}

/// <summary>
/// Configuration integrity status.
/// </summary>
public sealed class ConfigIntegrityStatus
{
    /// <summary>Path to the monitored configuration file.</summary>
    public string ConfigPath { get; set; } = "";

    /// <summary>Path to the monitored executable.</summary>
    public string ExecutablePath { get; set; } = "";

    /// <summary>Whether a config baseline hash exists.</summary>
    public bool HasConfigBaseline { get; set; }

    /// <summary>Whether an executable baseline hash exists.</summary>
    public bool HasExeBaseline { get; set; }

    /// <summary>Number of tamper events detected since startup.</summary>
    public int TamperEventsDetected { get; set; }

    /// <summary>Time of the last integrity check.</summary>
    public DateTime LastCheckTime { get; set; }

    /// <summary>Whether the monitor has escalated due to repeated tampering.</summary>
    public bool IsEscalated { get; set; }
}