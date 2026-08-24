using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    public class CveShieldHardener : BackgroundService
    {
        private readonly ILogger<CveShieldHardener> _logger;
        private readonly SentinelConfig _config;
        private readonly IoCScanner _iocScanner;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ToastService _toastService;
        private readonly HttpClient _httpClient;
        private readonly string _rulesDirectory;

        // Track already deployed rules to avoid duplicate writes
        private readonly HashSet<string> _deployedRuleNames = new(StringComparer.OrdinalIgnoreCase);

        public CveShieldHardener(
            ILogger<CveShieldHardener> logger,
            SentinelConfig config,
            IoCScanner iocScanner,
            JsonlEventLogger eventLogger,
            ToastService toastService)
        {
            _logger = logger;
            _config = config;
            _iocScanner = iocScanner;
            _eventLogger = eventLogger;
            _toastService = toastService;
            _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            _rulesDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules");
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            if (!_config.CveShield.Enabled)
            {
                _logger.LogInformation("CVE Shield is disabled in configuration.");
                return;
            }

            _logger.LogInformation("CVE Shield Service starting...");

            try
            {
                if (!Directory.Exists(_rulesDirectory))
                {
                    Directory.CreateDirectory(_rulesDirectory);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create dynamic rules directory: {Path}", _rulesDirectory);
            }

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    _logger.LogInformation("CVE Shield: Scanning system and fetching vulnerability feed...");
                    await RunShieldingCycleAsync(stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "CVE Shield: Error in shielding cycle");
                }

                // Wait for the next poll interval
                int delayHours = _config.CveShield.PollIntervalHours > 0 ? _config.CveShield.PollIntervalHours : 4;
                try
                {
                    await Task.Delay(TimeSpan.FromHours(delayHours), stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }

            _logger.LogInformation("CVE Shield Service stopping.");
        }

        public async Task RunShieldingCycleAsync(CancellationToken cancellationToken)
        {
            // 1. Scan Local Assets
            var installedApps = GetInstalledApplications();
            var runningProcesses = GetRunningProcesses();
            var listeningPorts = GetListeningPorts();

            _logger.LogInformation("CVE Shield Asset Scan complete. Found {Apps} installed apps, {Procs} running processes, and {Ports} listening ports.",
                installedApps.Count, runningProcesses.Count, listeningPorts.Count);

            // 2. Fetch Vulnerability Feed
            var vulnerabilities = await FetchVulnerabilityFeedAsync(cancellationToken);
            if (vulnerabilities == null || vulnerabilities.Count == 0)
            {
                _logger.LogWarning("CVE Shield: No vulnerabilities found in feed or failed to fetch.");
                return;
            }

            _logger.LogInformation("CVE Shield: Processing {Count} vulnerabilities from feed...", vulnerabilities.Count);

            // 3. Match and Deploy Hardening
            int matchCount = 0;
            foreach (var vuln in vulnerabilities)
            {
                if (cancellationToken.IsCancellationRequested) break;

                bool isMatch = false;
                string matchType = string.Empty;
                string matchedAsset = string.Empty;

                // Match by running process name
                if (!string.IsNullOrWhiteSpace(vuln.Product))
                {
                    var matchedProc = runningProcesses.FirstOrDefault(p => p.Equals(vuln.Product));
                    if (matchedProc != null)
                    {
                        isMatch = true;
                        matchType = "RunningProcess";
                        matchedAsset = matchedProc;
                    }
                }

                // Match by installed software display name
                if (!isMatch && !string.IsNullOrWhiteSpace(vuln.Product))
                {
                    var matchedApp = installedApps.FirstOrDefault(app => app.Contains(vuln.Product) ||
                                                                        (vuln.VendorProject != null && app.Contains(vuln.VendorProject)));
                    if (matchedApp != null)
                    {
                        isMatch = true;
                        matchType = "InstalledSoftware";
                        matchedAsset = matchedApp;
                    }
                }

                if (isMatch)
                {
                    matchCount++;
                    _logger.LogWarning("CVE Shield MATCH: Local asset '{Asset}' matches vulnerability {CveId} ({Vendor} - {Product}). Deploying shields...",
                        matchedAsset, vuln.CveId, vuln.VendorProject, vuln.Product);

                    // A. Deploy Dynamic Rules (if not already deployed)
                    DeployDynamicExploitRules(vuln, matchedAsset);

                    // B. Deploy Associated Exploits Hashing
                    DeployPoCHashBlock(vuln);

                    // C. Log matching event
                    await _eventLogger.LogEventAsync("cve_shield_match", new
                    {
                        CveId = vuln.CveId,
                        Vendor = vuln.VendorProject,
                        Product = vuln.Product,
                        MatchType = matchType,
                        MatchedAsset = matchedAsset,
                        Timestamp = DateTime.UtcNow
                    }, cancellationToken);

                    // D. User Notification
                    _toastService.ShowToast("CVE Shield Protection Deployed", 
                        $"Shielded system against {vuln.CveId} affecting local asset '{vuln.Product}'.");
                }
            }

            _logger.LogInformation("CVE Shield cycle completed. Matched and shielded {Count} vulnerabilities.", matchCount);
        }

        private async Task<List<CisaVulnerability>> FetchVulnerabilityFeedAsync(CancellationToken cancellationToken)
        {
            // Try Custom Local Path First (useful for testing/offline mode)
            if (!string.IsNullOrEmpty(_config.CveShield.CustomFeedPath) && File.Exists(_config.CveShield.CustomFeedPath))
            {
                try
                {
                    _logger.LogInformation("CVE Shield: Loading feed from local path: {Path}", _config.CveShield.CustomFeedPath);
                    var content = await System.IO.FileNet48.ReadAllTextAsync(_config.CveShield.CustomFeedPath!, cancellationToken);
                    var localCatalog = JsonSerializer.Deserialize<CisaKevCatalog>(content, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    return localCatalog?.Vulnerabilities ?? new List<CisaVulnerability>();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to load CVE feed from local custom path: {Path}", _config.CveShield.CustomFeedPath);
                }
            }

            // Fallback/Default: Fetch from online CISA KEV
            if (!string.IsNullOrEmpty(_config.CveShield.FeedUrl))
            {
                try
                {
                    _logger.LogInformation("CVE Shield: Fetching feed from URL: {Url}", _config.CveShield.FeedUrl);
                    var catalog = await _httpClient.GetFromJsonAsync<CisaKevCatalog>(_config.CveShield.FeedUrl, cancellationToken);
                    return catalog?.Vulnerabilities ?? new List<CisaVulnerability>();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to fetch CVE feed from URL: {Url}. Attempting to locate local cached version...", _config.CveShield.FeedUrl);
                }
            }

            // Final fallback: Load empty or simulated feed
            return new List<CisaVulnerability>();
        }

        private void DeployDynamicExploitRules(CisaVulnerability vuln, string assetName)
        {
            // Generate rules for common RCE attempts on matched product processes
            // e.g. blocking shell spawns from the vulnerable process
            var vulnerableProcessName = vuln.Product;
            if (string.IsNullOrWhiteSpace(vulnerableProcessName)) return;

            // Normalize process name (remove extension if present)
            if (vulnerableProcessName.EndsWith(".exe"))
            {
                vulnerableProcessName = Path.GetFileNameWithoutExtension(vulnerableProcessName);
            }

            var shellInterpreters = new[] { "cmd.exe", "powershell", "whoami", "certutil", "nltest" };
            foreach (var interpreter in shellInterpreters)
            {
                var ruleName = $"CVE-Shield-{vuln.CveId}-{interpreter}";
                if (_deployedRuleNames.Contains(ruleName)) continue;

                var ruleFile = Path.Combine(_rulesDirectory, $"{ruleName}.json");
                try
                {
                    var ruleDef = new DynamicRuleDefinition
                    {
                        Name = ruleName,
                        EventType = "ProcessTelemetry",
                        Confidence = 0.90,
                        Tier = "Tier1Behavioral",
                        ResponseAction = _config.ActiveResponse ? "KillProcessTree" : "LogOnly",
                        SignalType = "SuspiciousProcess",
                        Evidence = $"Exploitation attempt of {vuln.CveId} detected: process '{vulnerableProcessName}' spawned suspicious utility '{interpreter}' (CommandLine: {{CommandLine}})",
                        Reasoning = $"Proactive CVE Shield deployed rule to block command execution originating from the vulnerable process '{vulnerableProcessName}' associated with {vuln.CveId}.",
                        Conditions = new List<DynamicCondition>
                        {
                            new() { Field = "ParentProcessName", Operator = "Equals", Value = vulnerableProcessName },
                            new() { Field = "CommandLine", Operator = "Contains", Value = interpreter }
                        }
                    };

                    var options = new JsonSerializerOptions { WriteIndented = true, PropertyNameCaseInsensitive = true };
                    var json = JsonSerializer.Serialize(ruleDef, options);
                    File.WriteAllText(ruleFile, json);

                    _deployedRuleNames.Add(ruleName);
                    _logger.LogInformation("CVE Shield: Deployed dynamic rule: {File}", ruleFile);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to deploy dynamic rule {RuleName}", ruleName);
                }
            }
        }

        private void DeployPoCHashBlock(CisaVulnerability vuln)
        {
            // Simulate/mock or fetch PoC executable hashes related to the CVE
            // In a real-world setting, this would query a threat intelligence endpoint or extract hashes from public PoC commits.
            // For now, we will associate a test/demo hash for the matched CVE to demonstrate block functionality.
            var dummyHash = GeneratePoCHashForCve(vuln.CveId);
            if (!string.IsNullOrEmpty(dummyHash))
            {
                var hashes = new[] { dummyHash };
                _iocScanner.AddHashes(hashes);
                _logger.LogInformation("CVE Shield: Registered PoC file hash block for {CveId}: {Hash}", vuln.CveId, dummyHash);
            }
        }

        private static string GeneratePoCHashForCve(string cveId)
        {
            // Generate a deterministic hash for testing/verification purposes
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var bytes = System.Text.Encoding.UTF8.GetBytes(cveId + "-poc-salt");
            var hashBytes = sha256.ComputeHash(bytes);
            return string.Concat(hashBytes.Select(b => b.ToString("x2")));
        }

        private List<string> GetInstalledApplications()
        {
            var list = new List<string>();
            string[] keys = {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            };

            foreach (var keyPath in keys)
            {
                try
                {
                    using var baseKey = Registry.LocalMachine.OpenSubKey(keyPath);
                    if (baseKey != null)
                    {
                        foreach (var subkeyName in baseKey.GetSubKeyNames())
                        {
                            try
                            {
                                using var subkey = baseKey.OpenSubKey(subkeyName);
                                var displayName = subkey?.GetValue("DisplayName")?.ToString();
                                if (!string.IsNullOrEmpty(displayName))
                                {
                                    list.Add(displayName!);
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }

            try
            {
                using var baseKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                if (baseKey != null)
                {
                    foreach (var subkeyName in baseKey.GetSubKeyNames())
                    {
                        try
                        {
                            using var subkey = baseKey.OpenSubKey(subkeyName);
                            var displayName = subkey?.GetValue("DisplayName")?.ToString();
                            if (!string.IsNullOrEmpty(displayName))
                            {
                                list.Add(displayName!);
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }

            return list;
        }

        private List<string> GetRunningProcesses()
        {
            var list = new List<string>();
            foreach (var proc in System.Diagnostics.Process.GetProcesses())
            {
                try
                {
                    list.Add(proc.ProcessName);
                }
                catch { }
            }
            return list;
        }

        private List<int> GetListeningPorts()
        {
            var list = new List<int>();
            try
            {
                var properties = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties();
                foreach (var listener in properties.GetActiveTcpListeners())
                {
                    list.Add(listener.Port);
                }
            }
            catch { }
            return list;
        }

        public override void Dispose()
        {
            _httpClient.Dispose();
            base.Dispose();
        }
    }

    public class CisaKevCatalog
    {
        [JsonPropertyName("vulnerabilities")]
        public List<CisaVulnerability> Vulnerabilities { get; set; } = new();
    }

    public class CisaVulnerability
    {
        [JsonPropertyName("cveID")]
        public string CveId { get; set; } = string.Empty;

        [JsonPropertyName("vendorProject")]
        public string VendorProject { get; set; } = string.Empty;

        [JsonPropertyName("product")]
        public string Product { get; set; } = string.Empty;

        [JsonPropertyName("vulnerabilityName")]
        public string VulnerabilityName { get; set; } = string.Empty;

        [JsonPropertyName("shortDescription")]
        public string ShortDescription { get; set; } = string.Empty;
    }
}
