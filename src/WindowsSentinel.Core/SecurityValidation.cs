using System;
using System.IO;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

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

        /// <summary>Alias for ValidatePid â€” used by DllUnloadEngine.</summary>
        public static bool IsValidProcessId(int pid) => ValidatePid(pid);

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
    }
}
