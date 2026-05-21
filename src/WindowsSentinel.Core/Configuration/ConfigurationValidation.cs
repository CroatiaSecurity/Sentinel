using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WindowsSentinel.Core.Response;

namespace WindowsSentinel.Core.Configuration;

/// <summary>
/// Configuration validation result.
/// </summary>
public sealed class ConfigurationValidationResult
{
    /// <summary>
    /// Gets a value indicating whether the configuration is valid.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets the validation errors, if any.
    /// </summary>
    public IReadOnlyList<string> Errors { get; }

    /// <summary>
    /// Gets the validation warnings, if any.
    /// </summary>
    public IReadOnlyList<string> Warnings { get; }

    private ConfigurationValidationResult(bool isValid, IEnumerable<string>? errors = null, IEnumerable<string>? warnings = null)
    {
        IsValid = isValid;
        Errors = errors?.ToList() ?? new List<string>();
        Warnings = warnings?.ToList() ?? new List<string>();
    }

    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    public static ConfigurationValidationResult Success() => new(true);

    /// <summary>
    /// Creates a successful validation result with warnings.
    /// </summary>
    public static ConfigurationValidationResult SuccessWithWarnings(IEnumerable<string> warnings) => 
        new(true, warnings: warnings);

    /// <summary>
    /// Creates a failed validation result.
    /// </summary>
    public static ConfigurationValidationResult Failure(IEnumerable<string> errors) => 
        new(false, errors: errors);

    /// <summary>
    /// Creates a failed validation result with warnings.
    /// </summary>
    public static ConfigurationValidationResult Failure(IEnumerable<string> errors, IEnumerable<string> warnings) => 
        new(false, errors: errors, warnings: warnings);
}

/// <summary>
/// Base class for configuration validators.
/// </summary>
public abstract class ConfigurationValidator
{
    /// <summary>
    /// Validates the configuration.
    /// </summary>
    /// <param name="configuration">The configuration to validate.</param>
    /// <returns>The validation result.</returns>
    public abstract ConfigurationValidationResult Validate(IConfiguration configuration);
}

/// <summary>
/// Sentinel-specific configuration validator.
/// </summary>
public sealed class SentinelConfigurationValidator : ConfigurationValidator
{
    /// <inheritdoc/>
    public override ConfigurationValidationResult Validate(IConfiguration configuration)
    {
        var errors = new List<string>();
        var warnings = new List<string>();

        // Validate Sentinel section
        var sentinelSection = configuration.GetSection("Sentinel");
        if (sentinelSection.Exists())
        {
            ValidateSentinelSection(sentinelSection, errors, warnings);
        }
        else
        {
            warnings.Add("Sentinel configuration section not found. Using defaults.");
        }

        // Validate ThreatReporting section
        var threatReportingSection = configuration.GetSection("ThreatReporting");
        if (threatReportingSection.Exists())
        {
            ValidateThreatReportingSection(threatReportingSection, errors, warnings);
        }

        // Validate Logging section
        var loggingSection = configuration.GetSection("Logging");
        if (loggingSection.Exists())
        {
            ValidateLoggingSection(loggingSection, errors, warnings);
        }

        if (errors.Count > 0)
            return ConfigurationValidationResult.Failure(errors, warnings);
        
        if (warnings.Count > 0)
            return ConfigurationValidationResult.SuccessWithWarnings(warnings);
        
        return ConfigurationValidationResult.Success();
    }

    private void ValidateSentinelSection(IConfigurationSection section, List<string> errors, List<string> warnings)
    {
        // Validate ActiveResponse
        var activeResponse = section["ActiveResponse"];
        if (!string.IsNullOrEmpty(activeResponse) && !bool.TryParse(activeResponse, out _))
        {
            errors.Add("Sentinel:ActiveResponse must be 'true' or 'false'.");
        }

        // Validate LogPath
        var logPath = section["LogPath"];
        if (!string.IsNullOrEmpty(logPath))
        {
            try
            {
                // Just check if it's a valid path format
                var _ = Path.GetFullPath(logPath);
            }
            catch
            {
                errors.Add($"Sentinel:LogPath '{logPath}' is not a valid path.");
            }
        }

        // Validate WatchPath
        var watchPath = section["WatchPath"];
        if (!string.IsNullOrEmpty(watchPath))
        {
            try
            {
                var _ = Path.GetFullPath(watchPath);
            }
            catch
            {
                errors.Add($"Sentinel:WatchPath '{watchPath}' is not a valid path.");
            }
        }

        // Validate MaxLogSizeMb
        var maxLogSizeStr = section["MaxLogSizeMb"];
        if (!string.IsNullOrEmpty(maxLogSizeStr))
        {
            if (!int.TryParse(maxLogSizeStr, out var maxLogSize) || maxLogSize < 1 || maxLogSize > 1024)
            {
                errors.Add("Sentinel:MaxLogSizeMb must be between 1 and 1024.");
            }
        }

        // Validate MaxRotatedFiles
        var maxRotatedFilesStr = section["MaxRotatedFiles"];
        if (!string.IsNullOrEmpty(maxRotatedFilesStr))
        {
            if (!int.TryParse(maxRotatedFilesStr, out var maxRotatedFiles) || maxRotatedFiles < 1 || maxRotatedFiles > 20)
            {
                errors.Add("Sentinel:MaxRotatedFiles must be between 1 and 20.");
            }
        }
    }

    private void ValidateThreatReportingSection(IConfigurationSection section, List<string> errors, List<string> warnings)
    {
        // Validate Enabled
        var enabled = section["Enabled"];
        if (!string.IsNullOrEmpty(enabled) && !bool.TryParse(enabled, out _))
        {
            errors.Add("ThreatReporting:Enabled must be 'true' or 'false'.");
        }

        // Validate ReportToMalwareBazaar
        var reportToMalwareBazaar = section["ReportToMalwareBazaar"];
        if (!string.IsNullOrEmpty(reportToMalwareBazaar) && !bool.TryParse(reportToMalwareBazaar, out _))
        {
            errors.Add("ThreatReporting:ReportToMalwareBazaar must be 'true' or 'false'.");
        }

        // Validate ReportToUrlhaus
        var reportToUrlhaus = section["ReportToUrlhaus"];
        if (!string.IsNullOrEmpty(reportToUrlhaus) && !bool.TryParse(reportToUrlhaus, out _))
        {
            errors.Add("ThreatReporting:ReportToUrlhaus must be 'true' or 'false'.");
        }

        // Validate MaxReportsPerHour
        var maxReportsPerHourStr = section["MaxReportsPerHour"];
        if (!string.IsNullOrEmpty(maxReportsPerHourStr))
        {
            if (!int.TryParse(maxReportsPerHourStr, out var maxReportsPerHour) || maxReportsPerHour < 1 || maxReportsPerHour > 100)
            {
                errors.Add("ThreatReporting:MaxReportsPerHour must be between 1 and 100.");
            }
        }

        // Warn about API keys in plaintext (they should be encrypted)
        var abuseIpDbApiKey = section["AbuseIpDbApiKey"];
        var urlhausAuthToken = section["UrlhausAuthToken"];
        
        if (!string.IsNullOrEmpty(abuseIpDbApiKey) && abuseIpDbApiKey.Length < 32)
        {
            warnings.Add("ThreatReporting:AbuseIpDbApiKey appears to be a placeholder or invalid key.");
        }
        
        if (!string.IsNullOrEmpty(urlhausAuthToken) && urlhausAuthToken.Length < 32)
        {
            warnings.Add("ThreatReporting:UrlhausAuthToken appears to be a placeholder or invalid token.");
        }
    }

    private void ValidateLoggingSection(IConfigurationSection section, List<string> errors, List<string> warnings)
    {
        // Validate LogLevel
        var logLevelSection = section.GetSection("LogLevel");
        if (logLevelSection.Exists())
        {
            foreach (var entry in logLevelSection.GetChildren())
            {
                var level = entry.Value;
                if (!string.IsNullOrEmpty(level))
                {
                    var validLevels = new[] { "Trace", "Debug", "Information", "Warning", "Error", "Critical", "None" };
                    if (!validLevels.Contains(level, StringComparer.OrdinalIgnoreCase))
                    {
                        errors.Add($"Logging:LogLevel:{entry.Key} has invalid value '{level}'. Must be one of: {string.Join(", ", validLevels)}");
                    }
                }
            }
        }

        // Validate EventLog settings
        var eventLogSection = section.GetSection("EventLog");
        if (eventLogSection.Exists())
        {
            var logName = eventLogSection["LogName"];
            if (!string.IsNullOrEmpty(logName))
            {
                var validLogNames = new[] { "Application", "System", "Security", "Setup" };
                if (!validLogNames.Contains(logName, StringComparer.OrdinalIgnoreCase))
                {
                    warnings.Add($"Logging:EventLog:LogName '{logName}' may not exist on this system.");
                }
            }

            var sourceName = eventLogSection["SourceName"];
            if (string.IsNullOrEmpty(sourceName))
            {
                warnings.Add("Logging:EventLog:SourceName is not set. Using default 'Windows Sentinel'.");
            }
        }
    }
}

/// <summary>
/// Options validator for ThreatReportingConfig.
/// </summary>
public sealed class ThreatReportingConfigValidator : IValidateOptions<ThreatReportingConfig>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, ThreatReportingConfig options)
    {
        var errors = new List<string>();

        if (options.MaxReportsPerHour < 1)
            errors.Add($"ThreatReportingConfig.MaxReportsPerHour ({options.MaxReportsPerHour}) must be at least 1.");

        if (options.MaxReportsPerHour > 100)
            errors.Add($"ThreatReportingConfig.MaxReportsPerHour ({options.MaxReportsPerHour}) is too high. Maximum is 100.");

        if (options.DeduplicationWindow < TimeSpan.FromHours(1))
            errors.Add($"ThreatReportingConfig.DeduplicationWindow ({options.DeduplicationWindow}) is too short. Minimum is 1 hour.");

        if (options.DeduplicationWindow > TimeSpan.FromDays(30))
            errors.Add($"ThreatReportingConfig.DeduplicationWindow ({options.DeduplicationWindow}) is too long. Maximum is 30 days.");

        if (!string.IsNullOrEmpty(options.AbuseIpDbApiKey) && options.AbuseIpDbApiKey.Length < 32)
            errors.Add("ThreatReportingConfig.AbuseIpDbApiKey appears to be invalid (too short).");

        if (!string.IsNullOrEmpty(options.UrlhausAuthToken) && options.UrlhausAuthToken.Length < 32)
            errors.Add("ThreatReportingConfig.UrlhausAuthToken appears to be invalid (too short).");

        if (errors.Count > 0)
            return ValidateOptionsResult.Fail(string.Join("; ", errors));

        return ValidateOptionsResult.Success;
    }
}

/// <summary>
/// Centralized configuration validation service.
/// </summary>
public sealed class ConfigurationValidationService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<ConfigurationValidationService> _logger;
    private readonly List<ConfigurationValidator> _validators;

    /// <summary>
    /// Initializes a new instance of the <see cref="ConfigurationValidationService"/> class.
    /// </summary>
    public ConfigurationValidationService(IConfiguration configuration, ILogger<ConfigurationValidationService> logger)
    {
        _configuration = configuration;
        _logger = logger;
        _validators = new List<ConfigurationValidator>
        {
            new SentinelConfigurationValidator()
        };
    }

    /// <summary>
    /// Validates all configuration sections.
    /// </summary>
    /// <returns>True if configuration is valid, false otherwise.</returns>
    public bool ValidateAll()
    {
        _logger.LogInformation("Starting configuration validation...");

        var allErrors = new List<string>();
        var allWarnings = new List<string>();
        var hasErrors = false;

        foreach (var validator in _validators)
        {
            try
            {
                var result = validator.Validate(_configuration);
                
                if (!result.IsValid)
                {
                    hasErrors = true;
                    allErrors.AddRange(result.Errors);
                }
                
                allWarnings.AddRange(result.Warnings);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Configuration validator failed.");
                hasErrors = true;
                allErrors.Add($"Validator failed: {ex.Message}");
            }
        }

        // Log warnings
        foreach (var warning in allWarnings)
        {
            _logger.LogWarning("Configuration warning: {Warning}", warning);
        }

        // Log errors
        if (hasErrors)
        {
            _logger.LogError("Configuration validation failed with {Count} error(s):", allErrors.Count);
            foreach (var error in allErrors)
            {
                _logger.LogError("  - {Error}", error);
            }
            return false;
        }

        _logger.LogInformation("Configuration validation passed with {WarningCount} warning(s).", allWarnings.Count);
        return true;
    }

    /// <summary>
    /// Gets a summary of configuration validation results.
    /// </summary>
    public ConfigurationValidationResult GetValidationResult()
    {
        var allErrors = new List<string>();
        var allWarnings = new List<string>();
        var hasErrors = false;

        foreach (var validator in _validators)
        {
            try
            {
                var result = validator.Validate(_configuration);
                
                if (!result.IsValid)
                {
                    hasErrors = true;
                    allErrors.AddRange(result.Errors);
                }
                
                allWarnings.AddRange(result.Warnings);
            }
            catch (Exception ex)
            {
                hasErrors = true;
                allErrors.Add($"Validator failed: {ex.Message}");
            }
        }

        if (hasErrors)
            return ConfigurationValidationResult.Failure(allErrors, allWarnings);
        
        if (allWarnings.Count > 0)
            return ConfigurationValidationResult.SuccessWithWarnings(allWarnings);
        
        return ConfigurationValidationResult.Success();
    }
}

