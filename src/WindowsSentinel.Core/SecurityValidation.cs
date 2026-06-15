using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    public static class SecurityValidation
    {
        private static readonly Regex SafePathRegex = new(@"^[a-zA-Z]:\\[a-zA-Z0-9_\-\s\\\.%()\[\]]*$", RegexOptions.Compiled);
        private static readonly Regex SafeFileNameRegex = new(@"^[a-zA-Z0-9_\-\s\.]+\.[a-zA-Z0-9]+$", RegexOptions.Compiled);

        public static bool ValidatePath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            try
            {
                // Prevent path traversal
                if (path.Contains("..")) return false;
                
                // Absolute path check
                if (!Path.IsPathRooted(path)) return false;
                
                // Format check
                return SafePathRegex.IsMatch(path);
            }
            catch
            {
                return false;
            }
        }

        public static bool ValidateFileName(string? fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName)) return false;
            return SafeFileNameRegex.IsMatch(fileName) && !fileName.Contains("..");
        }

        public static bool ValidateIpAddress(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            return IPAddress.TryParse(ip, out _);
        }

        public static bool ValidatePid(int pid)
        {
            return pid >= 0 && pid <= 4194304; // Max PID limit in Windows/Linux
        }

        public static bool ValidatePort(int port)
        {
            return port >= 0 && port <= 65535;
        }

        public static bool ValidateTimestamp(DateTime timestamp)
        {
            // Within reasonable limits (not years in the past or future)
            var diff = (DateTime.UtcNow - timestamp.ToUniversalTime()).Duration();
            return diff.TotalDays < 365;
        }

        private static readonly HashSet<string> WindowsReservedNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "CON", "PRN", "AUX", "NUL",
            "COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9",
            "LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9"
        };

        /// <summary>
        /// Validates a filename is safe: no path separators, no traversal, no reserved names,
        /// no null bytes, no dangerous characters.
        /// </summary>
        public static bool IsSafeFilename(string? filename)
        {
            if (string.IsNullOrWhiteSpace(filename)) return false;
            if (filename.Contains('\0')) return false;
            if (filename.Contains('/') || filename.Contains('\\')) return false;
            if (filename.Contains("..")) return false;

            // Dangerous characters
            foreach (var c in new[] { '<', '>', '|', '*', '?', '"', ':' })
                if (filename.Contains(c)) return false;

            // Windows reserved names
            var nameOnly = Path.GetFileNameWithoutExtension(filename);
            if (WindowsReservedNames.Contains(nameOnly)) return false;

            return true;
        }

        /// <summary>
        /// Checks if a full path is within the expected directory (prevents path traversal).
        /// </summary>
        public static bool IsPathWithinDirectory(string? fullPath, string? expectedDir)
        {
            if (string.IsNullOrWhiteSpace(fullPath) || string.IsNullOrWhiteSpace(expectedDir))
                return false;
            try
            {
                var normalizedPath = Path.GetFullPath(fullPath);
                var normalizedDir = Path.GetFullPath(expectedDir);
                if (!normalizedDir.EndsWith(Path.DirectorySeparatorChar.ToString()))
                    normalizedDir += Path.DirectorySeparatorChar;
                return normalizedPath.StartsWith(normalizedDir, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        /// <summary>
        /// Returns true if the IP is a private/reserved address (loopback, RFC1918, link-local).
        /// Treats null/empty as private (safe default).
        /// </summary>
        public static bool IsPrivateIpAddress(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return true;
            if (ip == "localhost" || ip == "::1") return true;
            if (!IPAddress.TryParse(ip, out var addr)) return true; // Unparseable = treat as private
            var bytes = addr.GetAddressBytes();
            if (bytes.Length == 4)
            {
                if (bytes[0] == 127) return true;                                          // 127.x.x.x
                if (bytes[0] == 10) return true;                                            // 10.x.x.x
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;       // 172.16-31.x.x
                if (bytes[0] == 192 && bytes[1] == 168) return true;                        // 192.168.x.x
                if (bytes[0] == 169 && bytes[1] == 254) return true;                        // 169.254.x.x
            }
            return false;
        }

        /// <summary>Validates a process ID is within a reasonable range.</summary>
        public static bool IsValidProcessId(int pid) => pid >= 1 && pid <= 999999;

        /// <summary>Validates a port number (1-65535).</summary>
        public static bool IsValidPort(int port) => port >= 1 && port <= 65535;

        /// <summary>Validates a timestamp is within a reasonable range (not far past or future).</summary>
        public static bool IsValidTimestamp(DateTime timestamp)
        {
            var utc = timestamp.ToUniversalTime();
            var now = DateTime.UtcNow;
            // Reject timestamps more than 365 days in the past
            if ((now - utc).TotalDays > 365) return false;
            // Reject timestamps more than 1 day in the future (clock skew tolerance)
            if ((utc - now).TotalDays > 1) return false;
            return true;
        }

        /// <summary>Checks if a string is safe (no injection characters).</summary>
        public static bool IsSafeString(string? input)
        {
            if (input == null) return false;
            if (string.IsNullOrEmpty(input)) return true;
            foreach (var c in new[] { '<', '>', '\'', '`', '$' })
                if (input.Contains(c)) return false;
            return true;
        }

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        public static bool SecureCompare(byte[]? a, byte[]? b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;

            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
            new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public int cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public int cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public int dwUIChoice;
            public int fdwRevocationChecks;
            public int dwUnionChoice;
            public IntPtr pFile;
            public int dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public int dwProvFlags;
            public int dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

        private const int WTD_UI_NONE = 2;
        private const int WTD_REVOKE_NONE = 0;
        private const int WTD_CHOICE_FILE = 1;
        private const int WTD_STATEACTION_VERIFY = 1;
        private const int WTD_STATEACTION_CLOSE = 2;
        private const int WTD_REVOCATION_CHECK_NONE = 0x00000010;
        private const int WTD_LIFETIME_SIGNING_FLAG = 0x00000800;

        /// <summary>
        /// Verifies the Authenticode signature of a PE file using WinVerifyTrust.
        /// Returns true only if the signature is valid AND chains to a trusted root.
        /// </summary>
        public static bool VerifyAuthenticodeSignature(string filePath, Microsoft.Extensions.Logging.ILogger? logger = null)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return false;

            IntPtr fileInfoPtr = IntPtr.Zero;
            try
            {
                var fileInfo = new WINTRUST_FILE_INFO
                {
                    cbStruct = Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                    pcwszFilePath = filePath,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };

                fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

                var trustData = new WINTRUST_DATA
                {
                    cbStruct = Marshal.SizeOf<WINTRUST_DATA>(),
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice = WTD_CHOICE_FILE,
                    pFile = fileInfoPtr,
                    dwStateAction = WTD_STATEACTION_VERIFY,
                    dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_LIFETIME_SIGNING_FLAG
                };

                var actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                int result = WinVerifyTrust(IntPtr.Zero, ref actionId, ref trustData);

                // Close the state handle
                trustData.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(IntPtr.Zero, ref actionId, ref trustData);

                return result == 0;
            }
            catch (Exception ex)
            {
                logger?.LogDebug(ex, "[SecurityValidation] Authenticode verification failed for '{Path}'", filePath);
                return false;
            }
            finally
            {
                if (fileInfoPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(fileInfoPtr);
            }
        }
    }
}
