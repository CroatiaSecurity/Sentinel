using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// v2.0.4: DPAPI-encrypted configuration store for per-deployment secrets and overrides.
    ///
    /// Eliminates appsettings.json as an attack surface. All operational defaults are compiled
    /// into the binary (via SentinelConfig/ThreatReportingConfig property initializers).
    /// Only per-deployment values that MUST vary (secrets, trusted devices, victim info)
    /// are stored in a DPAPI-encrypted file at %ProgramData%\Sentinel\Secure\config.enc
    ///
    /// Security properties:
    ///   - Machine-scope DPAPI: only processes on this host can decrypt
    ///   - SYSTEM + Admins ACL: standard users cannot read the ciphertext
    ///   - Integrity HMAC: tamper detection (modified ciphertext = decryption failure)
    ///   - No plaintext config on disk: physical access attacker must break DPAPI
    ///
    /// To set secrets, use: Sentinel.Service.exe --set-config ProxySharedSecret=value
    /// Or programmatically via SetOverride() then Save().
    /// </summary>
    public sealed class EncryptedConfigStore
    {
        private readonly string _configPath;
        private readonly ILogger? _logger;
        private Dictionary<string, string> _overrides = new(StringComparer.OrdinalIgnoreCase);

        private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;
        private const int CRYPTPROTECT_LOCAL_MACHINE = 0x4;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CRYPTPROTECT_PROMPTSTRUCT
        {
            public int cbSize;
            public int dwPromptFlags;
            public IntPtr hwndApp;
            public string szPrompt;
        }

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptProtectData(
            ref DATA_BLOB pDataIn, string szDataDescr, ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved, ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            int dwFlags, ref DATA_BLOB pDataOut);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptUnprotectData(
            ref DATA_BLOB pDataIn, IntPtr ppszDataDescr, ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved, ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            int dwFlags, ref DATA_BLOB pDataOut);

        public static string DefaultConfigPath
        {
            get
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                return Path.Combine(programData, "Sentinel", "Secure", "config.enc");
            }
        }

        public EncryptedConfigStore(ILogger? logger = null, string? customPath = null)
        {
            _configPath = customPath ?? DefaultConfigPath;
            _logger = logger;
            Load();
        }

        /// <summary>Gets an override value, or null if not set.</summary>
        public string? GetOverride(string key)
        {
            return _overrides.TryGetValue(key, out var val) ? val : null;
        }

        /// <summary>Sets an override value. Call Save() to persist.</summary>
        public void SetOverride(string key, string? value)
        {
            if (value == null)
                _overrides.Remove(key);
            else
                _overrides[key] = value;
        }

        /// <summary>Returns all override keys (for enumeration/diagnostics).</summary>
        public IReadOnlyCollection<string> Keys => _overrides.Keys;

        /// <summary>Loads and decrypts the config file. Silent on failure (defaults apply).</summary>
        public void Load()
        {
            _overrides.Clear();
            try
            {
                if (!File.Exists(_configPath))
                    return;

                var cipherBytes = File.ReadAllBytes(_configPath);
                if (cipherBytes.Length == 0) return;

                var plainBytes = Unprotect(cipherBytes);
                if (plainBytes == null || plainBytes.Length == 0)
                {
                    _logger?.LogWarning("[EncryptedConfigStore] Failed to decrypt config.enc — using compiled defaults");
                    return;
                }

                var json = Encoding.UTF8.GetString(plainBytes);
                var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                if (dict != null)
                    _overrides = new Dictionary<string, string>(dict, StringComparer.OrdinalIgnoreCase);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "[EncryptedConfigStore] Error loading config.enc — using compiled defaults");
            }
        }

        /// <summary>Encrypts and saves current overrides to disk.</summary>
        public bool Save()
        {
            try
            {
                var dir = Path.GetDirectoryName(_configPath)!;
                if (!Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                var json = JsonSerializer.Serialize(_overrides, new JsonSerializerOptions { WriteIndented = false });
                var plainBytes = Encoding.UTF8.GetBytes(json);
                var cipherBytes = Protect(plainBytes);
                if (cipherBytes == null)
                {
                    _logger?.LogError("[EncryptedConfigStore] DPAPI encryption failed — config not saved");
                    return false;
                }

                File.WriteAllBytes(_configPath, cipherBytes);
                LockFileAcl(_configPath);
                return true;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "[EncryptedConfigStore] Failed to save config.enc");
                return false;
            }
        }

        /// <summary>
        /// Applies overrides to the config objects after they are populated from compiled defaults.
        /// Called during service startup.
        /// </summary>
        public void ApplyOverrides(SentinelConfig config, ThreatReportingConfig? threatConfig = null,
            AutoIncidentReportingConfig? incidentConfig = null)
        {
            foreach (var kvp in _overrides)
            {
                switch (kvp.Key)
                {
                    // ThreatReporting secrets
                    case "ProxySharedSecret":
                        if (threatConfig != null) threatConfig.ProxySharedSecret = kvp.Value;
                        break;
                    case "ProxyEndpoint":
                        if (threatConfig != null) threatConfig.ProxyEndpoint = kvp.Value;
                        break;
                    case "AbuseIpDbApiKey":
                        if (threatConfig != null) threatConfig.AbuseIpDbApiKey = kvp.Value;
                        break;
                    case "UrlhausAuthToken":
                        if (threatConfig != null) threatConfig.UrlhausAuthToken = kvp.Value;
                        break;
                    case "MalwareBazaarApiKey":
                        if (threatConfig != null) threatConfig.MalwareBazaarApiKey = kvp.Value;
                        break;

                    // Sentinel per-deployment
                    case "TrustedUsbDevices":
                        config.TrustedUsbDevices = kvp.Value.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                        break;
                    case "LogPath":
                        config.LogPath = kvp.Value;
                        break;
                    case "WatchPath":
                        config.WatchPath = kvp.Value;
                        break;

                    // Incident reporting identity
                    case "VictimFullName":
                        if (incidentConfig != null) incidentConfig.VictimFullName = kvp.Value;
                        break;
                    case "VictimEmail":
                        if (incidentConfig != null) incidentConfig.VictimEmail = kvp.Value;
                        break;
                    case "VictimPhone":
                        if (incidentConfig != null) incidentConfig.VictimPhone = kvp.Value;
                        break;
                    case "VictimAddress":
                        if (incidentConfig != null) incidentConfig.VictimAddress = kvp.Value;
                        break;
                    case "CountryCode":
                        if (incidentConfig != null) incidentConfig.CountryCode = kvp.Value;
                        break;
                    case "ReportDirectory":
                        if (incidentConfig != null) incidentConfig.ReportDirectory = kvp.Value;
                        break;
                }
            }
        }

        /// <summary>Computes a SHA-256 hash of the encrypted file for integrity monitoring.</summary>
        public string? GetFileHash()
        {
            try
            {
                if (!File.Exists(_configPath)) return null;
                var bytes = File.ReadAllBytes(_configPath);
                return ConvertHex.ToHexString(Sha256Net48.HashData(bytes));
            }
            catch { return null; }
        }

        private static byte[]? Protect(byte[] data)
        {
            var blobIn = new DATA_BLOB();
            var blobOut = new DATA_BLOB();
            var blobEntropy = new DATA_BLOB();
            var prompt = new CRYPTPROTECT_PROMPTSTRUCT { cbSize = Marshal.SizeOf(typeof(CRYPTPROTECT_PROMPTSTRUCT)) };
            try
            {
                blobIn.pbData = Marshal.AllocHGlobal(data.Length);
                blobIn.cbData = data.Length;
                Marshal.Copy(data, 0, blobIn.pbData, data.Length);
                if (!CryptProtectData(ref blobIn, "SentinelConfig", ref blobEntropy, IntPtr.Zero,
                        ref prompt, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, ref blobOut))
                    return null;
                var result = new byte[blobOut.cbData];
                Marshal.Copy(blobOut.pbData, result, 0, blobOut.cbData);
                return result;
            }
            catch { return null; }
            finally
            {
                if (blobIn.pbData != IntPtr.Zero) Marshal.FreeHGlobal(blobIn.pbData);
                if (blobOut.pbData != IntPtr.Zero) Marshal.FreeHGlobal(blobOut.pbData);
            }
        }

        private static byte[]? Unprotect(byte[] data)
        {
            var blobIn = new DATA_BLOB();
            var blobOut = new DATA_BLOB();
            var blobEntropy = new DATA_BLOB();
            var prompt = new CRYPTPROTECT_PROMPTSTRUCT { cbSize = Marshal.SizeOf(typeof(CRYPTPROTECT_PROMPTSTRUCT)) };
            try
            {
                blobIn.pbData = Marshal.AllocHGlobal(data.Length);
                blobIn.cbData = data.Length;
                Marshal.Copy(data, 0, blobIn.pbData, data.Length);
                if (!CryptUnprotectData(ref blobIn, IntPtr.Zero, ref blobEntropy, IntPtr.Zero,
                        ref prompt, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, ref blobOut))
                    return null;
                var result = new byte[blobOut.cbData];
                Marshal.Copy(blobOut.pbData, result, 0, blobOut.cbData);
                return result;
            }
            catch { return null; }
            finally
            {
                if (blobIn.pbData != IntPtr.Zero) Marshal.FreeHGlobal(blobIn.pbData);
                if (blobOut.pbData != IntPtr.Zero) Marshal.FreeHGlobal(blobOut.pbData);
            }
        }

        private static void LockFileAcl(string path)
        {
            try
            {
                var fi = new FileInfo(path);
                var security = fi.GetAccessControl();
                security.SetAccessRuleProtection(true, false);
                foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    security.RemoveAccessRuleAll(rule);

                var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    system, FileSystemRights.FullControl, AccessControlType.Allow));

                var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    admins, FileSystemRights.FullControl, AccessControlType.Allow));

                fi.SetAccessControl(security);
            }
            catch { }
        }
    }
}
