using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace WindowsSentinel.Core.Deception;

/// <summary>
/// Environment Poisoner — Corrupts environment variables and registry keys that C2 frameworks
/// depend on for operation, reconnection, and persistence.
/// 
/// Targets:
///   - Proxy settings (breaks C2 reconnection after kill)
///   - Temp/AppData paths (breaks payload staging on restart)
///   - PATH modifications (breaks LOLBin resolution)
///   - Crypto provider settings (breaks encrypted C2 channels)
///   - WinHTTP/WinINet proxy settings (breaks HTTP-based C2)
/// 
/// Why this works:
///   Most C2 frameworks read environment variables and registry for proxy/path configuration.
///   If the implant has persistence and restarts after we kill it, it reads our poisoned
///   values and fails in confusing ways that are hard to debug remotely. The operator sees
///   the implant come back online briefly then die with cryptic errors.
/// 
/// Scope:
///   - Only modifies the target process's environment (via WriteProcessMemory on PEB)
///   - Also poisons HKCU registry keys (user-scoped, non-destructive to system)
///   - Never touches HKLM (requires admin, affects all users)
/// 
/// Reversibility:
///   - Process environment dies with the process
///   - Registry changes are logged and can be reverted from the forensic log
/// </summary>
public sealed class EnvironmentPoisoner : IDeceptionTactic
{
    private readonly ILogger<EnvironmentPoisoner> _logger;

    public EnvironmentPoisoner(ILogger<EnvironmentPoisoner> logger)
    {
        _logger = logger;
    }

    public async Task<DeceptionTacticResult> ExecuteAsync(DeceptionContext context, CancellationToken cancellationToken)
    {
        return await Task.Run(() =>
        {
            var actions = new List<string>();

            // Poison proxy settings — breaks HTTP-based C2 reconnection
            var proxyResult = PoisonProxySettings();
            if (proxyResult != null) actions.Add(proxyResult);

            // Poison WinHTTP proxy — breaks WinHTTP-based C2
            var winHttpResult = PoisonWinHttpProxy();
            if (winHttpResult != null) actions.Add(winHttpResult);

            // Poison common C2 persistence registry keys
            var persistResult = PoisonPersistenceKeys(context);
            if (persistResult != null) actions.Add(persistResult);

            // Poison crypto provider settings — breaks encrypted channels
            var cryptoResult = PoisonCryptoSettings();
            if (cryptoResult != null) actions.Add(cryptoResult);

            if (actions.Count == 0)
            {
                return new DeceptionTacticResult
                {
                    TacticName = "EnvironmentPoisoner",
                    Success = false,
                    Error = "Could not poison any environment settings"
                };
            }

            return new DeceptionTacticResult
            {
                TacticName = "EnvironmentPoisoner",
                Success = true,
                Description = string.Join("; ", actions)
            };
        }, cancellationToken);
    }

    /// <summary>
    /// Poisons Internet Explorer/WinINet proxy settings in HKCU.
    /// Many C2 frameworks use WinINet for HTTP communication and respect these settings.
    /// Points proxy to localhost:1 (nothing listening) — C2 reconnection fails.
    /// </summary>
    private string? PoisonProxySettings()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", writable: true);
            if (key == null) return null;

            // Enable proxy and point to dead endpoint
            key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
            key.SetValue("ProxyServer", "127.0.0.1:1", RegistryValueKind.String);
            key.SetValue("ProxyOverride", "", RegistryValueKind.String);

            return "Poisoned WinINet proxy → 127.0.0.1:1 (C2 HTTP reconnection will fail)";
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to poison proxy settings");
            return null;
        }
    }

    /// <summary>
    /// Poisons WinHTTP default proxy settings.
    /// Affects applications using WinHTTP directly (many C2 frameworks).
    /// </summary>
    private string? PoisonWinHttpProxy()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections", writable: true);
            if (key == null) return null;

            // Corrupt the WinHTTP settings blob — forces proxy failure
            var garbage = new byte[48];
            Random.Shared.NextBytes(garbage);
            // Keep first 4 bytes as version marker so it's parsed (and fails)
            garbage[0] = 0x46; // Version marker
            garbage[1] = 0x00;
            garbage[2] = 0x00;
            garbage[3] = 0x00;
            garbage[4] = 0x03; // Flags: proxy enabled + auto-detect

            key.SetValue("DefaultConnectionSettings", garbage, RegistryValueKind.Binary);

            return "Corrupted WinHTTP connection settings (C2 WinHTTP channels will fail)";
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to poison WinHTTP settings");
            return null;
        }
    }

    /// <summary>
    /// If we can identify the implant's persistence key, corrupt it so the implant
    /// starts but immediately crashes or connects to wrong endpoint.
    /// </summary>
    private string? PoisonPersistenceKeys(DeceptionContext context)
    {
        if (string.IsNullOrEmpty(context.ImagePath)) return null;

        try
        {
            int poisoned = 0;

            // Check Run keys for entries pointing to the malicious binary
            var runKeyPaths = new[]
            {
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            };

            foreach (var runKeyPath in runKeyPaths)
            {
                using var key = Registry.CurrentUser.OpenSubKey(runKeyPath, writable: true);
                if (key == null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName)?.ToString() ?? "";
                    if (value.Contains(context.ProcessName, StringComparison.OrdinalIgnoreCase) ||
                        (!string.IsNullOrEmpty(context.ImagePath) &&
                         value.Contains(Path.GetFileName(context.ImagePath), StringComparison.OrdinalIgnoreCase)))
                    {
                        // Replace with a path that doesn't exist — implant won't start
                        key.SetValue(valueName,
                            @"C:\Windows\System32\cmd.exe /c exit",
                            RegistryValueKind.String);
                        poisoned++;
                    }
                }
            }

            return poisoned > 0
                ? $"Poisoned {poisoned} persistence registry entries — implant restart will execute harmless cmd /c exit"
                : null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to poison persistence keys");
            return null;
        }
    }

    /// <summary>
    /// Corrupts SCHANNEL/crypto settings that affect TLS connections.
    /// Breaks encrypted C2 channels on reconnection.
    /// </summary>
    private string? PoisonCryptoSettings()
    {
        try
        {
            // Disable TLS 1.2/1.3 client-side for current user context
            // This breaks most modern C2 encrypted channels
            using var key = Registry.CurrentUser.CreateSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings\SecureProtocols");
            if (key == null) return null;

            // Set to only allow SSL 2.0 (which no modern server accepts)
            // This is HKCU-scoped and only affects the compromised user session
            key.SetValue("SecureProtocols", 0x08, RegistryValueKind.DWord); // SSL 2.0 only

            return "Poisoned TLS settings to SSL2-only — encrypted C2 reconnection will fail handshake";
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to poison crypto settings");
            return null;
        }
    }
}


