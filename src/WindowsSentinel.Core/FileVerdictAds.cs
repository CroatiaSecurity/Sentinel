using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace WindowsSentinel.Core
{
    public class FileVerdictAds
    {
        private readonly byte[] _hmacKey;
        private readonly string _secureDir;
        private readonly bool _isCustomDir;

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
            ref DATA_BLOB pDataIn,
            string szDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            int dwFlags,
            ref DATA_BLOB pDataOut);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptUnprotectData(
            ref DATA_BLOB pDataIn,
            IntPtr ppszDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            int dwFlags,
            ref DATA_BLOB pDataOut);

        private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;
        private const int CRYPTPROTECT_LOCAL_MACHINE = 0x4;

        public FileVerdictAds(string? customSecureDir = null)
        {
            if (!string.IsNullOrWhiteSpace(customSecureDir))
            {
                _secureDir = customSecureDir;
                _isCustomDir = true;
            }
            else
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                _secureDir = Path.Combine(programData, "WindowsSentinel", "Secure");
                _isCustomDir = false;
            }

            _hmacKey = GetOrCreateHmacKey();
        }

        private byte[] GetOrCreateHmacKey()
        {
            var keyFilePath = Path.Combine(_secureDir, "ads_hmac.key");
            try
            {
                var dirInfo = new DirectoryInfo(_secureDir);
                if (!dirInfo.Exists)
                {
                    dirInfo.Create();
                }

                // Apply secure ACLs to restrict access to local SYSTEM and Administrators only
                var security = dirInfo.GetAccessControl();
                security.SetAccessRuleProtection(true, false);

                var systemSid = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    systemSid,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));

                var adminsSid = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    adminsSid,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));

                if (_isCustomDir)
                {
                    var currentUserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User;
                    if (currentUserSid != null)
                    {
                        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                            currentUserSid,
                            System.Security.AccessControl.FileSystemRights.FullControl,
                            System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                            System.Security.AccessControl.PropagationFlags.None,
                            System.Security.AccessControl.AccessControlType.Allow));
                    }
                }

                dirInfo.SetAccessControl(security);
            }
            catch { }

            try
            {
                if (File.Exists(keyFilePath))
                {
                    var encryptedBytes = File.ReadAllBytes(keyFilePath);
                    var rawKey = Unprotect(encryptedBytes);
                    if (rawKey != null && rawKey.Length == 32)
                    {
                        return rawKey;
                    }
                }
            }
            catch { }

            // Create new key
            var newKey = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(newKey);
            }

            try
            {
                var encryptedBytes = Protect(newKey);
                File.WriteAllBytes(keyFilePath, encryptedBytes);
            }
            catch { }

            return newKey;
        }

        private static byte[] Protect(byte[] data)
        {
            var dataIn = new DATA_BLOB { cbData = data.Length, pbData = Marshal.AllocHGlobal(data.Length) };
            Marshal.Copy(data, 0, dataIn.pbData, data.Length);

            var dataOut = new DATA_BLOB();
            var entropy = new DATA_BLOB();
            var prompt = new CRYPTPROTECT_PROMPTSTRUCT();

            try
            {
                // Remove CRYPTPROTECT_LOCAL_MACHINE to restrict decryption to the current user (SYSTEM in service context)
                if (CryptProtectData(ref dataIn, "SentinelAdsKey", ref entropy, IntPtr.Zero, ref prompt, CRYPTPROTECT_UI_FORBIDDEN, ref dataOut))
                {
                    var result = new byte[dataOut.cbData];
                    Marshal.Copy(dataOut.pbData, result, 0, dataOut.cbData);
                    return result;
                }
                throw new CryptographicException("DPAPI encryption failed");
            }
            finally
            {
                Marshal.FreeHGlobal(dataIn.pbData);
                if (dataOut.pbData != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(dataOut.pbData);
                }
            }
        }

        private static byte[]? Unprotect(byte[] data)
        {
            var dataIn = new DATA_BLOB { cbData = data.Length, pbData = Marshal.AllocHGlobal(data.Length) };
            Marshal.Copy(data, 0, dataIn.pbData, data.Length);

            var dataOut = new DATA_BLOB();
            var entropy = new DATA_BLOB();
            var prompt = new CRYPTPROTECT_PROMPTSTRUCT();

            try
            {
                // Remove CRYPTPROTECT_LOCAL_MACHINE to restrict decryption to the current user (SYSTEM in service context)
                if (CryptUnprotectData(ref dataIn, IntPtr.Zero, ref entropy, IntPtr.Zero, ref prompt, CRYPTPROTECT_UI_FORBIDDEN, ref dataOut))
                {
                    var result = new byte[dataOut.cbData];
                    Marshal.Copy(dataOut.pbData, result, 0, dataOut.cbData);
                    return result;
                }
                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(dataIn.pbData);
                if (dataOut.pbData != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(dataOut.pbData);
                }
            }
        }

        public HashVerdict GetVerdict(string filePath, string expectedSha256)
        {
            var adsPath = $"{filePath}:sentinel_verdict";
            try
            {
                if (!File.Exists(adsPath))
                {
                    return HashVerdict.Unknown;
                }

                var text = File.ReadAllText(adsPath, Encoding.UTF8);
                if (string.IsNullOrWhiteSpace(text)) return HashVerdict.Unknown;

                var parts = text.Split('|');
                if (parts.Length != 4) return HashVerdict.Unknown;

                var verdictStr = parts[0];
                var timestampStr = parts[1];
                var sha256 = parts[2];
                var signatureHex = parts[3];

                // Verify file hash match
                if (!expectedSha256.Equals(sha256, StringComparison.OrdinalIgnoreCase))
                {
                    return HashVerdict.Unknown;
                }

                // Verify signature
                var payloadStr = $"{verdictStr}|{timestampStr}|{sha256}";
                var payloadBytes = Encoding.UTF8.GetBytes(payloadStr);

                byte[] computedSignature;
                using (var hmac = new HMACSHA256(_hmacKey))
                {
                    computedSignature = hmac.ComputeHash(payloadBytes);
                }
                var signatureBytes = Convert.FromHexString(signatureHex);

                if (!SecurityValidation.SecureCompare(computedSignature, signatureBytes))
                {
                    return HashVerdict.Unknown;
                }

                // Check key expiry or timestamp sanity (within last 365 days)
                if (long.TryParse(timestampStr, out var ticks))
                {
                    var signedAt = new DateTime(ticks, DateTimeKind.Utc);
                    if (DateTime.UtcNow - signedAt > TimeSpan.FromDays(365) || signedAt > DateTime.UtcNow.AddHours(1))
                    {
                        return HashVerdict.Unknown;
                    }
                }
                else
                {
                    return HashVerdict.Unknown;
                }

                if (Enum.TryParse<HashVerdict>(verdictStr, out var verdict))
                {
                    return verdict;
                }
            }
            catch
            {
                // Degrade gracefully
            }
            return HashVerdict.Unknown;
        }

        public void SetVerdict(string filePath, string fileSha256, HashVerdict verdict)
        {
            var adsPath = $"{filePath}:sentinel_verdict";
            try
            {
                var timestampTicks = DateTime.UtcNow.Ticks;
                var payloadStr = $"{verdict}|{timestampTicks}|{fileSha256.ToLowerInvariant()}";
                var payloadBytes = Encoding.UTF8.GetBytes(payloadStr);

                byte[] signature;
                using (var hmac = new HMACSHA256(_hmacKey))
                {
                    signature = hmac.ComputeHash(payloadBytes);
                }
                var signatureHex = Convert.ToHexString(signature);

                var finalPayload = $"{payloadStr}|{signatureHex}";
                File.WriteAllText(adsPath, finalPayload, Encoding.UTF8);
            }
            catch
            {
                // Degrade gracefully
            }
        }
    }
}
