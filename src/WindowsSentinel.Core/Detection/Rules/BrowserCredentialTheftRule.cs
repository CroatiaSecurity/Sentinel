using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Detection.Rules;

/// <summary>
/// Tier1 — Detects process-start patterns associated with browser credential theft.
///
/// Detection vectors:
///   1. Processes referencing Chrome/Edge/Firefox credential file paths in command line
///   2. Known browser credential theft tools (SharpChromium, ChromePass, HackBrowserData, LaZagne)
///   3. Python/PowerShell scripts targeting browser data directories
///   4. DPAPI CryptUnprotectData calls from non-browser processes (via command-line indicators)
///   5. SQLite operations on browser database files from suspicious processes
///   6. Microsoft account / Azure AD token theft tools (ROADtools, AADInternals, TokenTactics)
///   7. Firefox NSS key extraction (key4.db + logins.json)
///
/// This rule complements ChromeCredentialGuardMonitor, FirefoxCredentialGuardMonitor,
/// and MicrosoftAccountGuardMonitor by catching the process-start event before the
/// stealer even opens the file.
///
/// MITRE ATT&amp;CK:
///   T1555.003 — Credentials from Password Stores: Credentials from Web Browsers
///   T1539     — Steal Web Session Cookie
///   T1528     — Steal Application Access Token
/// </summary>
public sealed class BrowserCredentialTheftRule : IDetectionRule
{
    public string Name => "Browser Credential Theft";
    public DetectionTier Tier => DetectionTier.Tier1Behavioral;

    // Known browser credential theft tools
    private static readonly HashSet<string> KnownStealerTools = new(StringComparer.OrdinalIgnoreCase)
    {
        // Chromium stealers
        "sharpchromium", "chromepass", "hackbrowserdata",
        "browserghost", "sharpweb", "chlonern",
        "chromecookiesview", "webcookiessniffer",
        "chrome-passwords", "cookie-stealer",
        "browserstealer", "dumpchrome",
        // Firefox stealers
        "lazagne", "firepwd", "firefox_decrypt",
        "passfox", "firefoxdecrypt", "ffpassdecrypt",
        "dumpzilla", "foxstealer",
        // Microsoft account / Azure AD tools
        "roadtx", "roadrecon", "aadinternals",
        "tokentacticsv2", "tokentactics",
        "azurehound", "graphrunner", "teamfiltration",
        "msolspray", "o365spray", "trevorspray",
        // Multi-browser stealers
        "stealc", "redline", "raccoon", "vidar",
        "mars", "aurora", "risepro", "mystic", "lumma",
    };

    // Command-line patterns that indicate browser credential targeting
    private static readonly string[] BrowserTargetPatterns =
    {
        // ── Chromium browser paths ───────────────────────────────────────────
        "login data",
        "local state",
        "\\user data\\default\\cookies",
        "\\user data\\default\\login",
        "\\user data\\default\\web data",
        "google\\chrome\\user data",
        "microsoft\\edge\\user data",
        "bravesoftware\\brave-browser\\user data",
        // ── Firefox / Gecko paths ────────────────────────────────────────────
        "key4.db",
        "key3.db",
        "logins.json",
        "cookies.sqlite",
        "signons.sqlite",
        "cert9.db",
        "mozilla\\firefox\\profiles",
        "thunderbird\\profiles",
        // ── Microsoft account / Azure AD tokens ──────────────────────────────
        "tokenbroker\\cache",
        ".tbres",
        "primaryrefreshtoken",
        "x-ms-refreshtokencredential",
        "get-prttoken",
        "browsercore.exe",
        "microsoft.aad.brokerplugin",
        "roadtx",
        "aadinternals",
        "get-aadintaccesstoken",
        "invoke-aadintuserenum",
        "export-aadintadfstoken",
        // ── DPAPI decryption patterns ────────────────────────────────────────
        "cryptunprotectdata",
        "dpapi::chrome",
        "dpapi::masterkey",
        "sekurlsa::dpapi",
        // ── SQLite operations on browser DBs ─────────────────────────────────
        "sqlite3.*login",
        "sqlite.*cookies",
        "sqlite.*key4",
        // ── Python stealer patterns ──────────────────────────────────────────
        "import sqlite3.*chrome",
        "win32crypt",
        "cryptography.hazmat",
        "browser_cookie3",
        "pycookiecheat",
        // ── PowerShell patterns ──────────────────────────────────────────────
        "get-chromecredentials",
        "get-chromepasswords",
        "invoke-chromedump",
        "convertfrom-securestring.*chrome",
        "[system.security.cryptography.protecteddata]",
    };

    // Processes that legitimately reference browser paths
    private static readonly HashSet<string> AllowedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Chromium browsers
        "chrome", "msedge", "brave", "opera", "vivaldi", "arc", "chromium",
        // Firefox / Gecko browsers
        "firefox", "waterfox", "palemoon", "thunderbird",
        // Microsoft account processes
        "RuntimeBroker", "TokenBroker", "Microsoft.AAD.BrokerPlugin",
        "OneDrive", "OUTLOOK", "Teams",
        // AV / Security
        "MsMpEng", "MsSense",
        "SentinelService", "SentinelAgent",
        "SearchIndexer",
    };

    public DetectionEvent? Evaluate(object telemetry)
    {
        if (telemetry is not ProcessTelemetry proc) return null;
        if (proc.EventType != "ProcessStart") return null;
        if (AllowedProcesses.Contains(proc.ProcessName)) return null;

        var cmdLower = (proc.CommandLine ?? "").ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(cmdLower)) return null;

        var nameLower = proc.ProcessName.ToLowerInvariant();
        var nameStem = Path.GetFileNameWithoutExtension(proc.ProcessName).ToLowerInvariant();

        // Check 1: Known stealer tool names
        if (KnownStealerTools.Contains(nameStem) || KnownStealerTools.Contains(proc.ProcessName))
        {
            return new DetectionEvent
            {
                RuleName = Name,
                Evidence = $"Known browser credential theft tool '{proc.ProcessName}' (PID {proc.ProcessId}) launched. " +
                          $"CommandLine: {proc.CommandLine}",
                Reasoning = "This process matches a known browser credential stealing tool. These tools extract " +
                           "saved passwords, cookies, and session tokens from Chrome/Edge/Firefox and Microsoft " +
                           "accounts by reading their databases and decrypting stored credentials. This enables " +
                           "Google/Microsoft account takeover via stolen session cookies (T1555.003, T1528).",
                Confidence = 0.93,
                Tier = Tier,
                ProcessName = proc.ProcessName,
                ProcessId = proc.ProcessId,
                Timestamp = proc.Timestamp,
                Metadata = new()
                {
                    ["tool_name"] = proc.ProcessName,
                    ["command_line"] = proc.CommandLine,
                    ["technique"] = "T1555.003 - Credentials from Web Browsers"
                }
            };
        }

        // Check 2: Command-line patterns targeting browser credentials
        string? matchedPattern = null;
        foreach (var pattern in BrowserTargetPatterns)
        {
            if (cmdLower.Contains(pattern))
            {
                matchedPattern = pattern;
                break;
            }
        }

        if (matchedPattern != null)
        {
            // Higher confidence if it's a scripting engine (python, powershell)
            var isScriptEngine = nameLower is "python" or "python3" or "pythonw" or "py"
                or "powershell" or "pwsh" or "cmd" or "wscript" or "cscript"
                or "node" or "ruby";

            var confidence = isScriptEngine ? 0.88 : 0.85;

            return new DetectionEvent
            {
                RuleName = Name,
                Evidence = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) targets browser credentials " +
                          $"with pattern '{matchedPattern}'. CommandLine: {proc.CommandLine}",
                Reasoning = "Command-line arguments reference browser credential stores or DPAPI decryption " +
                           "functions. This is the operational pattern of infostealers that extract saved " +
                           "passwords and session cookies from Chromium-based browsers. Stolen cookies enable " +
                           "immediate Google account access without needing the password (T1539).",
                Confidence = confidence,
                Tier = Tier,
                ProcessName = proc.ProcessName,
                ProcessId = proc.ProcessId,
                Timestamp = proc.Timestamp,
                Metadata = new()
                {
                    ["matched_pattern"] = matchedPattern ?? "",
                    ["is_script_engine"] = isScriptEngine.ToString(),
                    ["command_line"] = proc.CommandLine,
                    ["technique"] = "T1555.003 - Credentials from Web Browsers"
                }
            };
        }

        return null;
    }
}
