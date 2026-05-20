using System.Net.NetworkInformation;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// ShadowProxy Detector - Detects proxy manipulation and traffic interception attempts.
/// Monitors system proxy settings for unauthorized changes.
/// </summary>
public sealed class ShadowProxyDetector : BackgroundService
{
    private readonly ILogger<ShadowProxyDetector> _logger;
    
    private string? _lastKnownProxy;
    private int? _lastKnownProxyPort;
    private bool _lastKnownProxyEnabled;
    
    private readonly TimeSpan _checkInterval = TimeSpan.FromMinutes(1);

    public ShadowProxyDetector(ILogger<ShadowProxyDetector> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== ShadowProxy Detector starting ===");

        // Capture baseline
        CaptureBaseline();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_checkInterval, stoppingToken);
                
                // Check for proxy changes
                CheckForProxyChanges();
                
                // Check for suspicious proxy settings
                CheckForSuspiciousProxies();
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ShadowProxy: Error in main loop");
            }
        }
    }

    private void CaptureBaseline()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            
            if (key != null)
            {
                _lastKnownProxy = key.GetValue("ProxyServer") as string;
                _lastKnownProxyEnabled = (key.GetValue("ProxyEnable") as int?) == 1;
                
                // Parse port if present
                if (!string.IsNullOrEmpty(_lastKnownProxy) && _lastKnownProxy.Contains(':'))
                {
                    var parts = _lastKnownProxy.Split(':');
                    if (parts.Length == 2 && int.TryParse(parts[1], out var port))
                    {
                        _lastKnownProxyPort = port;
                    }
                }

                _logger.LogInformation(
                    "ShadowProxy: Baseline captured - Proxy: {Proxy}, Enabled: {Enabled}",
                    _lastKnownProxy ?? "None",
                    _lastKnownProxyEnabled);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ShadowProxy: Error capturing baseline");
        }
    }

    private void CheckForProxyChanges()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            
            if (key == null) return;

            var currentProxy = key.GetValue("ProxyServer") as string;
            var currentEnabled = (key.GetValue("ProxyEnable") as int?) == 1;

            // Check if proxy changed
            if (currentProxy != _lastKnownProxy || currentEnabled != _lastKnownProxyEnabled)
            {
                var action = currentEnabled ? "ENABLED" : "DISABLED";
                var proxyInfo = currentEnabled ? $" -> {currentProxy}" : "";
                
                _logger.LogCritical(
                    "SHADOWPROXY ALERT: System proxy changed - was {OldEnabled} ({OldProxy}), now {NewEnabled}{NewProxy}",
                    _lastKnownProxyEnabled ? "ENABLED" : "DISABLED",
                    _lastKnownProxy ?? "None",
                    action,
                    proxyInfo);

                // Check if new proxy is suspicious
                if (currentEnabled && IsSuspiciousProxy(currentProxy))
                {
                    _logger.LogCritical(
                        "SHADOWPROXY CRITICAL: Suspicious proxy detected - {Proxy}",
                        currentProxy);
                }

                // Update baseline
                _lastKnownProxy = currentProxy;
                _lastKnownProxyEnabled = currentEnabled;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ShadowProxy: Error checking for changes");
        }
    }

    private void CheckForSuspiciousProxies()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            
            if (key == null) return;

            var currentProxy = key.GetValue("ProxyServer") as string;
            var currentEnabled = (key.GetValue("ProxyEnable") as int?) == 1;

            if (!currentEnabled || string.IsNullOrEmpty(currentProxy))
                return;

            // Check for suspicious patterns
            var suspicions = new List<string>();

            // Localhost proxy (common in attacks)
            if (currentProxy.Contains("127.0.0.1") || currentProxy.Contains("localhost"))
            {
                suspicions.Add("Localhost proxy (possible traffic interception)");
            }

            // Unusual ports
            if (currentProxy.Contains(":8080") || currentProxy.Contains(":3128") ||
                currentProxy.Contains(":8888") || currentProxy.Contains(":8081"))
            {
                suspicions.Add("Common proxy port (8080/3128/8888/8081)");
            }

            // Non-standard ports
            var portMatch = System.Text.RegularExpressions.Regex.Match(currentProxy, @":(\d+)");
            if (portMatch.Success)
            {
                var port = int.Parse(portMatch.Groups[1].Value);
                if (port > 10000)
                {
                    suspicions.Add($"High ephemeral port ({port})");
                }
            }

            // HTTP proxy (not HTTPS)
            if (currentProxy.StartsWith("http://") || 
                (!currentProxy.StartsWith("https://") && !currentProxy.Contains("https://")))
            {
                suspicions.Add("Unencrypted HTTP proxy");
            }

            if (suspicions.Count > 0)
            {
                _logger.LogWarning(
                    "ShadowProxy: Proxy {Proxy} has {Count} suspicious indicators: {Indicators}",
                    currentProxy,
                    suspicions.Count,
                    string.Join(", ", suspicions));
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ShadowProxy: Error checking suspicious proxies");
        }
    }

    private bool IsSuspiciousProxy(string? proxy)
    {
        if (string.IsNullOrEmpty(proxy))
            return false;

        var lowerProxy = proxy.ToLowerInvariant();

        // Known suspicious patterns
        var suspiciousPatterns = new[]
        {
            "127.0.0.1",
            "localhost",
            "0.0.0.0",
            ":8080",
            ":3128",
            "proxy.php",
            "proxy.cgi",
            "proxypac",
            "wpad.",
            "autoproxy",
            "proxy.pac"
        };

        foreach (var pattern in suspiciousPatterns)
        {
            if (lowerProxy.Contains(pattern))
                return true;
        }

        // Check for PAC file URLs that aren't from trusted sources
        if (lowerProxy.Contains(".pac") && 
            !lowerProxy.Contains("microsoft") &&
            !lowerProxy.Contains("mozilla"))
        {
            return true;
        }

        return false;
    }

    /// <summary>
    /// Gets current proxy configuration.
    /// </summary>
    public ProxyConfiguration GetCurrentConfiguration()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            
            if (key == null)
                return new ProxyConfiguration { Error = "Registry key not found" };

            var proxy = key.GetValue("ProxyServer") as string;
            var enabled = (key.GetValue("ProxyEnable") as int?) == 1;
            var autoConfigUrl = key.GetValue("AutoConfigURL") as string;

            return new ProxyConfiguration
            {
                ProxyServer = proxy,
                ProxyEnabled = enabled,
                AutoConfigUrl = autoConfigUrl,
                IsSuspicious = enabled && IsSuspiciousProxy(proxy)
            };
        }
        catch (Exception ex)
        {
            return new ProxyConfiguration { Error = ex.Message };
        }
    }

    /// <summary>
    /// Resets proxy to system defaults.
    /// </summary>
    public void ResetToDefaults()
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            
            if (key != null)
            {
                key.SetValue("ProxyEnable", 0);
                key.DeleteValue("ProxyServer", false);
                key.DeleteValue("AutoConfigURL", false);
                
                _logger.LogInformation("ShadowProxy: Proxy settings reset to defaults");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ShadowProxy: Error resetting proxy");
        }
    }
}

/// <summary>
/// Current proxy configuration.
/// </summary>
public sealed class ProxyConfiguration
{
    public string? ProxyServer { get; set; }
    public bool ProxyEnabled { get; set; }
    public string? AutoConfigUrl { get; set; }
    public bool IsSuspicious { get; set; }
    public string? Error { get; set; }

    public string Summary => ProxyEnabled
        ? $"Proxy enabled: {ProxyServer} {(IsSuspicious ? "[SUSPICIOUS]" : "")}"
        : "No proxy configured";
}

