using System;
using System.IO;
using System.Text.RegularExpressions;

namespace Sentinel.Core
{
    /// <summary>
    /// Shared installer / packager heuristics used by PPID spoof, ransomware IO,
    /// ephemeral process, and token monitors to avoid treating official installs as malware.
    /// Name patterns alone are never sufficient for kill decisions — callers must also
    /// require Authenticode or path context where trust is granted.
    /// </summary>
    public static class InstallerHeuristics
    {
        /// <summary>
        /// Git-2.47.0-64-bit, ChromeSetup, VSCodeUserSetup, python-3.12.0-amd64, etc.
        /// </summary>
        public static bool LooksLikeInstallerName(string? processName, string? imagePath = null)
        {
            var n = (processName ?? "").Replace(".exe", "", StringComparison.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(n) && !string.IsNullOrEmpty(imagePath))
                n = Path.GetFileNameWithoutExtension(imagePath) ?? "";

            if (string.IsNullOrEmpty(n)) return false;

            if (n.Contains("setup", StringComparison.OrdinalIgnoreCase) ||
                n.Contains("install", StringComparison.OrdinalIgnoreCase) ||
                n.Contains("update", StringComparison.OrdinalIgnoreCase) ||
                n.Contains("unins", StringComparison.OrdinalIgnoreCase) ||
                n.StartsWith("git-", StringComparison.OrdinalIgnoreCase) ||
                n.StartsWith("git_", StringComparison.OrdinalIgnoreCase) ||
                n.Equals("git", StringComparison.OrdinalIgnoreCase) ||
                n.StartsWith("node-v", StringComparison.OrdinalIgnoreCase) ||
                n.StartsWith("python-", StringComparison.OrdinalIgnoreCase) ||
                (n.StartsWith("go", StringComparison.OrdinalIgnoreCase) && n.Contains("windows", StringComparison.OrdinalIgnoreCase)) ||
                n.Contains("vscode", StringComparison.OrdinalIgnoreCase) ||
                n.Contains("docker", StringComparison.OrdinalIgnoreCase) ||
                n.Contains("chrome", StringComparison.OrdinalIgnoreCase) ||
                n.Contains("firefox", StringComparison.OrdinalIgnoreCase) ||
                n.Contains("edge", StringComparison.OrdinalIgnoreCase) ||
                n.Contains("brave", StringComparison.OrdinalIgnoreCase) ||
                n.Contains("dotnet", StringComparison.OrdinalIgnoreCase) ||
                n.Contains("jdk", StringComparison.OrdinalIgnoreCase) ||
                n.Contains("jre", StringComparison.OrdinalIgnoreCase) ||
                n.Contains("msiexec", StringComparison.OrdinalIgnoreCase) ||
                n.Contains("windowsdesktop-runtime", StringComparison.OrdinalIgnoreCase) ||
                n.Contains("vcredist", StringComparison.OrdinalIgnoreCase) ||
                n.Contains("sentinelsetup", StringComparison.OrdinalIgnoreCase) ||
                n.Contains("finalizer", StringComparison.OrdinalIgnoreCase)) // WiX burn
                return true;

            // Product-1.2.3-64-bit / Product-x64 / Product-amd64
            if (Regex.IsMatch(n, @"-\d+(\.\d+)+", RegexOptions.CultureInvariant) &&
                (n.Contains("64", StringComparison.OrdinalIgnoreCase) ||
                 n.Contains("86", StringComparison.OrdinalIgnoreCase) ||
                 n.Contains("arm", StringComparison.OrdinalIgnoreCase) ||
                 n.Contains("bit", StringComparison.OrdinalIgnoreCase) ||
                 n.Contains("amd64", StringComparison.OrdinalIgnoreCase) ||
                 n.Contains("x64", StringComparison.OrdinalIgnoreCase)))
                return true;

            if (!string.IsNullOrEmpty(imagePath))
            {
                var file = Path.GetFileNameWithoutExtension(imagePath);
                if (!string.IsNullOrEmpty(file) &&
                    !file.Equals(n, StringComparison.OrdinalIgnoreCase) &&
                    LooksLikeInstallerName(file, null))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Inno Setup extracts innosetup-*.tmp / is-XXXXX stubs; NSIS uses nst/nsm/nsu temp dirs.
        /// These cause PPID ancestry races and ephemeral "self-delete" false positives.
        /// </summary>
        public static bool IsInstallerExtractor(string? processName, string? imagePath = null)
        {
            var n = (processName ?? "").ToLowerInvariant().Replace(".exe", "");
            if (n.StartsWith("innosetup") || n.Contains("innosetup")) return true;
            if (n.StartsWith("is-") && n.Length <= 16) return true;
            if (n.Contains("nsis") || n.Contains("_setup.tmp")) return true;
            if (n.EndsWith(".tmp") && n.Contains("setup")) return true;
            if (n is "iside" or "issetup" or "setup.tmp") return true;

            if (!string.IsNullOrEmpty(imagePath))
            {
                var file = Path.GetFileName(imagePath).ToLowerInvariant();
                if (file.StartsWith("innosetup") || file.StartsWith("is-")) return true;
                if (file.Contains("innosetup") && file.EndsWith(".tmp")) return true;

                var lower = imagePath.ToLowerInvariant();
                if (lower.Contains(@"\temp\is-") || lower.Contains(@"\temp\nst") ||
                    lower.Contains(@"\temp\nsm") || lower.Contains(@"\temp\nsu") ||
                    lower.Contains(@"\temp\7zs") || lower.Contains(@"\.be\")) // WiX burn extract
                    return true;
            }

            return false;
        }

        /// <summary>
        /// v1.8.1 RT-LOW-2: Path must look like a real install/download location before
        /// HighRisk→Tier2 demotion applies. Blocks evasion via ChromeSetup.exe in
        /// AppData\Roaming or arbitrary Temp without installer-extractor context.
        /// </summary>
        public static bool IsLikelyInstallerPath(string? imagePath)
        {
            if (string.IsNullOrWhiteSpace(imagePath))
                return false;

            string full;
            try { full = Path.GetFullPath(imagePath); }
            catch { return false; }

            var lower = full.ToLowerInvariant();

            // Explicit deny: classic malware staging locations (name-only installer spoof)
            if (lower.Contains(@"\appdata\roaming\") ||
                lower.Contains(@"\appdata\local\programs\") ||
                lower.Contains(@"\appdata\local\microsoft\windows\inetcache\") ||
                lower.Contains(@"\appdata\local\microsoft\windows\inetcookies\"))
                return false;

            // Trusted install roots
            if (lower.Contains(@"\program files\") ||
                lower.Contains(@"\program files (x86)\") ||
                lower.Contains(@"\windows\installer\") ||
                lower.Contains(@"\package cache\") ||
                lower.Contains(@"\programdata\package cache\"))
                return true;

            // User download / desktop drop of official installers
            if (lower.Contains(@"\downloads\") ||
                lower.Contains(@"\desktop\"))
                return true;

            // Temp only when path matches known extractor layout (Inno/NSIS/7z/WiX)
            if (IsInstallerExtractor(null, full))
                return true;

            return false;
        }

        /// <summary>
        /// Prefetch basenames that are normal short-lived install activity, not droppers.
        /// </summary>
        public static bool IsBenignEphemeralPrefetchName(string? exeOrPrefetchStem)
        {
            if (string.IsNullOrEmpty(exeOrPrefetchStem)) return false;
            var n = Path.GetFileNameWithoutExtension(exeOrPrefetchStem)
                .Replace(".tmp", "", StringComparison.OrdinalIgnoreCase);

            if (IsInstallerExtractor(n, null) || LooksLikeInstallerName(n, null))
                return true;

            // Prefetch often uppercases and truncates
            var u = n.ToUpperInvariant();
            if (u.StartsWith("GIT-") || u.StartsWith("INNOSETUP") || u.StartsWith("DOTNET") ||
                u.StartsWith("PYTHON-") || u.StartsWith("NODE-V") || u.Contains("SETUP") ||
                u.Contains("INSTALL") || u.StartsWith("ISIDE") || u.StartsWith("FINALIZER") ||
                u.Contains("CHROME") || u.Contains("VSCODE") || u.Contains("VCREDIST") ||
                u.Contains("SENTINELSETUP") || u.Contains("GOOGLEUPDATE"))
                return true;

            return false;
        }
    }
}
