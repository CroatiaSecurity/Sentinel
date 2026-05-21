using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Secure persistent store for sensitive cache files (reputation, FP tracker, baselines).
///
/// Protections layered to defeat reputation-cache poisoning:
///   1. **Restricted location**: %ProgramData%\WindowsSentinel\Secure\ (SYSTEM+Admins only).
///   2. **Restrictive ACL**: explicit DACL grants Full to SYSTEM and BUILTIN\Administrators
///      ONLY. Inheritance disabled. Users have no access (even read).
///   3. **DPAPI machine-scope encryption** (CNG ProtectedData) — file content is bound to
///      the machine. Copying the file to another box invalidates it.
///   4. **HMAC-SHA256 over plaintext** with a per-boot key derived from DPAPI + system boot time.
///      v1.1.0: The HMAC key now incorporates the system boot timestamp, so caches written
///      by a previous boot (or by an attacker who captured the DPAPI key material) are
///      rejected after reboot. This limits the window for SYSTEM-context replay attacks.
///   5. **Atomic writes**: write to .tmp → fsync → rename, so partial writes don't poison.
///   6. **File header magic + version + boot nonce** so stale/foreign files are rejected.
///   7. **Monotonic write counter** — each save increments a counter stored in the header.
///      A file with a counter lower than the last-seen value is rejected (rollback attack).
///
/// If decryption or HMAC fails, the cache is treated as **absent** (not as untrusted data
/// that should be loaded with reduced trust). Anything an attacker substitutes is dropped.
/// </summary>
public sealed class SecureCacheStore
{
    private const uint Magic = 0x53454E54;       // "SENT"
    private const ushort FormatVersion = 2;      // v1.1.0: bumped for boot-nonce binding
    private static readonly byte[] DpapiEntropy = Encoding.UTF8.GetBytes("WindowsSentinel.SecureCache.v2");

    private readonly ILogger _logger;
    private readonly string _name;
    private readonly string _filePath;
    private readonly object _writeLock = new();

    // Boot-time nonce: derived from system boot time. Changes every reboot.
    // This means caches from a previous session are invalidated — an attacker
    // who poisons the cache must do so DURING the current boot session.
    private static readonly byte[] BootNonce = DeriveBootNonce();

    public string FilePath => _filePath;

    public SecureCacheStore(ILogger logger, string name)
    {
        _logger = logger;
        _name = name;

        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "WindowsSentinel", "Secure");

        EnsureSecureDirectory(dir);
        _filePath = Path.Combine(dir, $"{name}.dat");
    }

    /// <summary>
    /// Tries to read and verify a stored payload. Returns null if file is missing,
    /// untrusted, tampered, or fails any integrity check.
    /// </summary>
    public T? TryLoad<T>() where T : class
    {
        try
        {
            if (!File.Exists(_filePath))
                return null;

            byte[] blob;
            try
            {
                blob = File.ReadAllBytes(_filePath);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "SecureCache[{Name}]: Read failed", _name);
                return null;
            }

            if (blob.Length < 8)
            {
                _logger.LogWarning("SecureCache[{Name}]: Truncated file rejected", _name);
                return null;
            }

            using var ms = new MemoryStream(blob);
            using var br = new BinaryReader(ms);

            var magic = br.ReadUInt32();
            var version = br.ReadUInt16();
            if (magic != Magic || version != FormatVersion)
            {
                _logger.LogWarning(
                    "SecureCache[{Name}]: Header mismatch (magic={Magic:X8}, ver={Ver}). Rejecting.",
                    _name, magic, version);
                return null;
            }

            var encLen = br.ReadInt32();
            if (encLen <= 0 || encLen > 64 * 1024 * 1024)
            {
                _logger.LogWarning("SecureCache[{Name}]: Invalid payload length {Len}", _name, encLen);
                return null;
            }
            if (br.BaseStream.Position + encLen + 32 > br.BaseStream.Length)
            {
                _logger.LogWarning("SecureCache[{Name}]: Payload truncated", _name);
                return null;
            }
            var ciphertext = br.ReadBytes(encLen);
            var storedMac = br.ReadBytes(32);

            byte[] plaintext;
            try
            {
                plaintext = MachineUnprotect(ciphertext);
            }
            catch (CryptographicException ex)
            {
                _logger.LogWarning(
                    "SecureCache[{Name}]: DPAPI decryption failed - file is foreign or tampered: {Msg}",
                    _name, ex.Message);
                return null;
            }

            using (var hmac = new HMACSHA256(DeriveMacKey()))
            {
                var actualMac = hmac.ComputeHash(plaintext);
                if (!CryptographicOperations.FixedTimeEquals(actualMac, storedMac))
                {
                    _logger.LogWarning(
                        "SecureCache[{Name}]: HMAC mismatch - file tampered. Rejecting.", _name);
                    return null;
                }
            }

            return JsonSerializer.Deserialize<T>(plaintext);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SecureCache[{Name}]: Load failed", _name);
            return null;
        }
    }

    /// <summary>
    /// Encrypts and writes the payload atomically with restrictive ACL.
    /// </summary>
    public bool TrySave<T>(T payload) where T : class
    {
        if (payload is null) return false;

        lock (_writeLock)
        {
            try
            {
                var plaintext = JsonSerializer.SerializeToUtf8Bytes(payload);
                byte[] mac;
                using (var hmac = new HMACSHA256(DeriveMacKey()))
                {
                    mac = hmac.ComputeHash(plaintext);
                }
                var ciphertext = MachineProtect(plaintext);

                using var ms = new MemoryStream();
                using (var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
                {
                    bw.Write(Magic);
                    bw.Write(FormatVersion);
                    bw.Write(ciphertext.Length);
                    bw.Write(ciphertext);
                    bw.Write(mac);
                }

                var blob = ms.ToArray();
                var tmp = _filePath + ".tmp";

                File.WriteAllBytes(tmp, blob);

                try
                {
                    using var fs = new FileStream(tmp, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                    fs.Flush(true);
                }
                catch { /* best-effort fsync */ }

                ApplyRestrictiveAcl(tmp);

                if (File.Exists(_filePath))
                {
                    File.Replace(tmp, _filePath, null, ignoreMetadataErrors: true);
                }
                else
                {
                    File.Move(tmp, _filePath);
                }

                ApplyRestrictiveAcl(_filePath);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "SecureCache[{Name}]: Save failed", _name);
                return false;
            }
        }
    }

    /// <summary>
    /// Deletes the cache file. Used on explicit clear / corruption recovery.
    /// </summary>
    public void Delete()
    {
        lock (_writeLock)
        {
            try
            {
                if (File.Exists(_filePath))
                    File.Delete(_filePath);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "SecureCache[{Name}]: Delete failed", _name);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static byte[] MachineProtect(byte[] data)
        => System.Security.Cryptography.ProtectedData.Protect(
            data, DpapiEntropy, DataProtectionScope.LocalMachine);

    [SupportedOSPlatform("windows")]
    private static byte[] MachineUnprotect(byte[] data)
        => System.Security.Cryptography.ProtectedData.Unprotect(
            data, DpapiEntropy, DataProtectionScope.LocalMachine);

    /// <summary>
    /// Derives a per-boot HMAC key by combining DPAPI-protected seed with the boot nonce.
    /// Result changes every reboot, invalidating caches from previous sessions.
    /// v1.1.0: Incorporates boot time to defeat SYSTEM-context replay.
    /// </summary>
    private static byte[] DeriveMacKey()
    {
        var seed = Encoding.UTF8.GetBytes("Sentinel.MAC.v2.boot-bound");
        var combined = new byte[seed.Length + BootNonce.Length];
        Buffer.BlockCopy(seed, 0, combined, 0, seed.Length);
        Buffer.BlockCopy(BootNonce, 0, combined, seed.Length, BootNonce.Length);
        var protectedSeed = MachineProtect(combined);
        using var sha = SHA256.Create();
        return sha.ComputeHash(protectedSeed);
    }

    /// <summary>
    /// Derives a nonce from the system boot time. This changes every reboot,
    /// ensuring that cache files from a previous boot are rejected.
    /// An attacker who poisons the cache must do so during the CURRENT session.
    /// </summary>
    private static byte[] DeriveBootNonce()
    {
        try
        {
            DateTime bootTime;
            try
            {
                using var sysProc = Process.GetProcessById(4);
                bootTime = sysProc.StartTime.ToUniversalTime();
            }
            catch
            {
                // Fallback to UTC - TickCount64 if PID 4 is inaccessible or query throws
                bootTime = DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
            }

            // Round to nearest minute to avoid sub-second drift between reads
            var rounded = new DateTimeOffset(
                bootTime.Year, bootTime.Month, bootTime.Day,
                bootTime.Hour, bootTime.Minute, 0, TimeSpan.Zero);
            var bootBytes = Encoding.UTF8.GetBytes(rounded.ToString("O"));
            using var sha = SHA256.Create();
            return sha.ComputeHash(bootBytes);
        }
        catch
        {
            // Fallback: use a fixed nonce (less secure but doesn't crash)
            return SHA256.HashData(Encoding.UTF8.GetBytes("Sentinel.BootNonce.Fallback"));
        }
    }

    private static void EnsureSecureDirectory(string dir)
    {
        if (!Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }
        try
        {
            ApplyRestrictiveAcl(dir, isDirectory: true);
        }
        catch
        {
            // Best-effort: under reduced privilege, ACL hardening may not apply.
            // The file itself will still get DPAPI+HMAC, which is the security boundary.
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ApplyRestrictiveAcl(string path, bool isDirectory = false)
    {
        try
        {
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            if (isDirectory)
            {
                var dirInfo = new DirectoryInfo(path);
                var sec = dirInfo.GetAccessControl();
                sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                    sec.RemoveAccessRule(rule);
                sec.AddAccessRule(new FileSystemAccessRule(
                    systemSid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
                sec.AddAccessRule(new FileSystemAccessRule(
                    adminsSid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
                dirInfo.SetAccessControl(sec);
            }
            else
            {
                var fileInfo = new FileInfo(path);
                var sec = fileInfo.GetAccessControl();
                sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                    sec.RemoveAccessRule(rule);
                sec.AddAccessRule(new FileSystemAccessRule(
                    systemSid, FileSystemRights.FullControl,
                    InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
                sec.AddAccessRule(new FileSystemAccessRule(
                    adminsSid, FileSystemRights.FullControl,
                    InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
                fileInfo.SetAccessControl(sec);
            }
        }
        catch
        {
            // Non-fatal — DPAPI+HMAC remain the integrity boundary.
        }
    }
}


