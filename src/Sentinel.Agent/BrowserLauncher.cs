using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace Sentinel.Agent
{
    /// <summary>
    /// v2.2.1: Open an http(s) URL by launching a real browser executable.
    ///
    /// <c>Process.Start(url, UseShellExecute=true)</c> asks Windows to resolve the
    /// <c>http</c> protocol. On machines with a broken/empty default-app association
    /// that "succeeds" and then shows: "We can't open this 'http' link".
    /// Catching exceptions never runs because there is no exception.
    /// </summary>
    internal static class BrowserLauncher
    {
        public static bool TryOpen(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return false;

            if (TryLaunchDefaultBrowser(url))
                return true;

            foreach (var exe in KnownBrowserExecutables())
            {
                if (File.Exists(exe) && TryStart(exe, Quote(url), useShell: false))
                    return true;
            }

            // Does not require a working http ProgId.
            if (TryStart("rundll32.exe", "url.dll,FileProtocolHandler " + url, useShell: false))
                return true;

            return false;
        }

        private static bool TryLaunchDefaultBrowser(string url)
        {
            try
            {
                var progId = Registry.GetValue(
                    @"HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice",
                    "ProgId",
                    null) as string;
                if (string.IsNullOrWhiteSpace(progId))
                    return false;

                var command = Registry.GetValue(
                    @"HKEY_CLASSES_ROOT\" + progId + @"\shell\open\command",
                    null,
                    null) as string;
                if (string.IsNullOrWhiteSpace(command))
                    return false;

                if (!TryParseCommand(command!, url, out var exe, out var args))
                    return false;
                if (string.IsNullOrEmpty(exe) || !File.Exists(exe))
                    return false;
                return TryStart(exe!, args ?? Quote(url), useShell: false);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Parse a shell open command like
        /// <c>"C:\...\chrome.exe" --single-argument %1</c> or <c>"...\msedge.exe" "%1"</c>.
        /// </summary>
        internal static bool TryParseCommand(string command, string url, out string? exe, out string? args)
        {
            exe = null;
            args = null;
            if (string.IsNullOrWhiteSpace(command))
                return false;

            command = command.Trim();
            if (command.StartsWith("\"", StringComparison.Ordinal))
            {
                var end = command.IndexOf('"', 1);
                if (end <= 1) return false;
                exe = command.Substring(1, end - 1);
                args = command.Substring(end + 1).Trim();
            }
            else
            {
                var space = command.IndexOf(' ');
                if (space < 0)
                {
                    exe = command;
                    args = Quote(url);
                    return true;
                }
                exe = command.Substring(0, space);
                args = command.Substring(space + 1).Trim();
            }

            if (string.IsNullOrWhiteSpace(args))
            {
                args = Quote(url);
                return true;
            }

            if (args.IndexOf("%1", StringComparison.Ordinal) >= 0)
                args = args.Replace("%1", url);
            else
                args = args + " " + Quote(url);

            return !string.IsNullOrEmpty(exe);
        }

        private static IEnumerable<string> KnownBrowserExecutables()
        {
            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            yield return Path.Combine(pf86, @"Microsoft\Edge\Application\msedge.exe");
            yield return Path.Combine(pf, @"Microsoft\Edge\Application\msedge.exe");
            yield return Path.Combine(pf, @"Google\Chrome\Application\chrome.exe");
            yield return Path.Combine(pf86, @"Google\Chrome\Application\chrome.exe");
            yield return Path.Combine(local, @"Google\Chrome\Application\chrome.exe");
            yield return Path.Combine(pf, @"Mozilla Firefox\firefox.exe");
            yield return Path.Combine(pf86, @"Mozilla Firefox\firefox.exe");
            yield return Path.Combine(local, @"Mozilla Firefox\firefox.exe");
            yield return Path.Combine(local, @"BraveSoftware\Brave-Browser\Application\brave.exe");
        }

        private static bool TryStart(string fileName, string arguments, bool useShell)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = useShell,
                    CreateNoWindow = !useShell
                };
                using var p = Process.Start(psi);
                return p != null || useShell;
            }
            catch
            {
                return false;
            }
        }

        private static string Quote(string value) => "\"" + value.Replace("\"", "%22") + "\"";
    }
}
