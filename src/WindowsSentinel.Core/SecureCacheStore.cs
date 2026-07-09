using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace WindowsSentinel.Core
{
    public class SecureCacheStore
    {
        private readonly string _secureDir;
        private readonly byte[] _hmacKey;

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

        public SecureCacheStore(string? customPath = null)
        {
            bool isDefaultPath = string.IsNullOrWhiteSpace(customPath);
            if (!isDefaultPath)
            {
                _secureDir = customPath!;
            }
            else
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                _secureDir = Path.Combine(programData, "WindowsSentinel", "Secure");
            }

            try
            {
                if (!Directory.Exists(_secureDir))
                {
                    Directory.CreateDirectory(_secureDir);
                }
                
                // Only lock ACLs to SYSTEM + Administrators in production (default path)
                if (isDefaultPath)
                {
                    LockDirectoryAcl(_secureDir);
                }
            }
            catch
            {
                // Degrade gracefully
            }

            // Generate a boot-nonce-bound HMAC key
            _hmacKey = GenerateBootBoundKey();
        }

        private static byte[] GenerateBootBoundKey()
        {
            using var ms = new MemoryStream();

            // 1. Boot time (publicly readable, but adds temporal binding)
            long bootTimeTicks;
            try
            {
                using var systemProc = Process.GetProcessById(4);
                bootTimeTicks = systemProc.StartTime.Ticks;
            }
            catch
            {
                bootTimeTicks = DateTime.UtcNow.Date.Ticks; // Fallback
            }
            ms.Write(BitConverter.GetBytes(bootTimeTicks));

            // 2. HARDENING: Machine GUID (requires registry access — standard users can read,
            // but combined with other entropy provides defense in depth)
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Cryptography");
                var machineGuid = key?.GetValue("MachineGuid")?.ToString() ?? "";
                if (!string.IsNullOrEmpty(machineGuid))
                {
                    ms.Write(Encoding.UTF8.GetBytes(machineGuid));
                }
            }
            catch { }

            // 3. HARDENING: Installation-specific random entropy stored in our ACL-locked directory.
            // An attacker would need SYSTEM/Admin access to read this file, and if they have that,
            // they already have broader access. This raises the bar for baseline poisoning from
            // "read System process start time" to "read a SYSTEM-ACL-protected file."
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var entropyFile = Path.Combine(programData, "WindowsSentinel", "Secure", ".install_entropy");
                if (File.Exists(entropyFile))
                {
                    var entropy = File.ReadAllBytes(entropyFile);
                    if (entropy.Length == 32)
                    {
                        ms.Write(entropy);
                    }
                }
                else
                {
                    // First run: generate and persist random entropy
                    var entropy = new byte[32];
                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(entropy);
                    }
                    var dir = Path.GetDirectoryName(entropyFile)!;
                    if (!Directory.Exists(dir))
                        Directory.CreateDirectory(dir);
                    File.WriteAllBytes(entropyFile, entropy);
                    ms.Write(entropy);
                }
            }
            catch { }

            // 4. HARDENING: Process ID of Sentinel itself (changes per boot, not predictable)
            ms.Write(BitConverter.GetBytes(Environment.ProcessId));

            return SHA256.HashData(ms.ToArray());
        }

        public void Save(string cacheName, string key, string value)
        {
            try
            {
                var cacheFilePath = Path.Combine(_secureDir, $"{cacheName}.cache");
                var rawData = $"{key}:{value}";
                var rawBytes = Encoding.UTF8.GetBytes(rawData);

                // Compute HMAC
                byte[] hash;
                using (var hmac = new HMACSHA256(_hmacKey))
                {
                    hash = hmac.ComputeHash(rawBytes);
                }

                // Payload: [HMAC 32 bytes] + [Raw Data]
                var payload = new byte[hash.Length + rawBytes.Length];
                Buffer.BlockCopy(hash, 0, payload, 0, hash.Length);
                Buffer.BlockCopy(rawBytes, 0, payload, hash.Length, rawBytes.Length);

                // DPAPI Encrypt
                var encryptedBytes = Protect(payload);
                File.WriteAllBytes(cacheFilePath, encryptedBytes);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"SecureCacheStore Save error: {ex.Message}");
            }
        }

        public string? Load(string cacheName, string key)
        {
            try
            {
                var cacheFilePath = Path.Combine(_secureDir, $"{cacheName}.cache");
                if (!File.Exists(cacheFilePath)) return null;

                var encryptedBytes = File.ReadAllBytes(cacheFilePath);
                var payload = Unprotect(encryptedBytes);
                if (payload == null || payload.Length <= 32) return null;

                // Extract HMAC and Data
                var hmacHash = new byte[32];
                var rawBytes = new byte[payload.Length - 32];
                Buffer.BlockCopy(payload, 0, hmacHash, 0, 32);
                Buffer.BlockCopy(payload, 32, rawBytes, 0, rawBytes.Length);

                // Verify HMAC
                byte[] computedHash;
                using (var hmac = new HMACSHA256(_hmacKey))
                {
                    computedHash = hmac.ComputeHash(rawBytes);
                }

                if (!SecurityValidation.SecureCompare(hmacHash, computedHash))
                {
                    // Tampered or old boot session cache file
                    File.Delete(cacheFilePath);
                    return null;
                }

                var rawData = Encoding.UTF8.GetString(rawBytes);
                var splitIdx = rawData.IndexOf(':');
                if (splitIdx == -1) return null;

                var loadedKey = rawData[..splitIdx];
                var loadedValue = rawData[(splitIdx + 1)..];

                if (loadedKey == key)
                {
                    return loadedValue;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"SecureCacheStore Load error: {ex.Message}");
            }
            return null;
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
                if (CryptProtectData(ref dataIn, "SentinelCache", ref entropy, IntPtr.Zero, ref prompt, CRYPTPROTECT_UI_FORBIDDEN, ref dataOut))
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

        /// <summary>
        /// Locks the directory ACL to SYSTEM and Administrators only, removing inherited ACEs.
        /// </summary>
        private static void LockDirectoryAcl(string directoryPath)
        {
            try
            {
                var dirInfo = new DirectoryInfo(directoryPath);
                var security = dirInfo.GetAccessControl();

                // Disable inheritance and remove all inherited ACEs
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

                // Remove all existing access rules
                var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
                foreach (FileSystemAccessRule rule in rules)
                {
                    security.RemoveAccessRuleAll(rule);
                }

                // Grant SYSTEM full control
                var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    systemSid,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                // Grant Administrators full control
                var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    adminSid,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                dirInfo.SetAccessControl(security);
            }
            catch
            {
                // Best effort — may fail if process is not elevated
            }
        }
    }
}
