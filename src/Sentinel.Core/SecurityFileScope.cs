using System;
using System.Collections.Generic;
using System.IO;

namespace Sentinel.Core
{
    /// <summary>
    /// Kernel-File ETW is a firehose (every temp/cache create). Fusion only needs
    /// loadable modules, scripts, and installer/disk-image droppers. Filtering
    /// before <c>FeedEvent</c> stops the allocation churn that pages the service.
    /// </summary>
    internal static class SecurityFileScope
    {
        private static readonly HashSet<string> RelevantExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv", ".efi",
            ".com", ".pif", ".msc",
            ".ps1", ".psm1", ".psd1", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
            ".hta", ".bat", ".cmd", ".lnk", ".url",
            ".msi", ".msp", ".msix", ".appx", ".cab",
            ".iso", ".img", ".vhd", ".vhdx", ".wim",
            ".chm", ".reg", ".inf", ".job",
            ".winmd", ".node", ".ax", ".acm",
        };

        public const int MaxEtwPathChars = 520;

        public static bool IsEtwFileEventRelevant(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            if (path!.Length < 4 || path.Length > MaxEtwPathChars) return false;
            if (path.IndexOf('\\') < 0 && path.IndexOf('/') < 0) return false;

            string ext;
            try { ext = Path.GetExtension(path); }
            catch { return false; }
            return ext.Length > 0 && RelevantExtensions.Contains(ext);
        }
    }
}
