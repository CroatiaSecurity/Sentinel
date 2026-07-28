using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Tests
{
    public class CveShieldHardenerTests : IDisposable
    {
        private readonly string _tempTestDir;
        private readonly string _rulesDir;
        private readonly string _logPath;
        private readonly string _feedPath;

        public CveShieldHardenerTests()
        {
            _tempTestDir = Path.Combine(Path.GetTempPath(), "cve_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_tempTestDir);
            _rulesDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules");
            if (!Directory.Exists(_rulesDir))
            {
                Directory.CreateDirectory(_rulesDir);
            }
            _logPath = Path.Combine(_tempTestDir, "sentinel.log");
            _feedPath = Path.Combine(_tempTestDir, "cisa_kev.json");
        }

        [Fact]
        public async Task RunShieldingCycle_DeploysRulesAndHashes_WhenVulnerabilityMatched()
        {
            // Arrange
            var config = new SentinelConfig();
            config.CveShield.Enabled = true;
            config.CveShield.CustomFeedPath = _feedPath;
            config.ActiveResponse = false; // LogOnly mode for testing

            // Mock a catalog that matches a process we know is running: "dotnet" (the test execution host)
            var mockCatalog = new CisaKevCatalog
            {
                Vulnerabilities = new System.Collections.Generic.List<CisaVulnerability>
                {
                    new()
                    {
                        CveId = "CVE-2026-9999",
                        VendorProject = "Microsoft",
                        Product = "dotnet",
                        VulnerabilityName = "Mock .NET Core Vulnerability",
                        ShortDescription = "A mock vulnerability for unit testing."
                    }
                }
            };

            var json = JsonSerializer.Serialize(mockCatalog);
            await File.WriteAllTextAsync(_feedPath, json);

            var cache = new SecureCacheStore(_tempTestDir);
            var iocScanner = new IoCScanner(cache);
            var eventLogger = new JsonlEventLogger(_logPath);
            var toastLogger = NullLogger<ToastService>.Instance;
            var toastService = new ToastService(toastLogger);
            var hardenerLogger = NullLogger<CveShieldHardener>.Instance;

            var hardener = new CveShieldHardener(hardenerLogger, config, iocScanner, eventLogger, toastService);

            // Act
            await hardener.RunShieldingCycleAsync(CancellationToken.None);

            // Assert
            // 1. Verify dynamic rules were written to the rules directory
            var cmdRuleFile = Path.Combine(_rulesDir, "CVE-Shield-CVE-2026-9999-cmd.exe.json");
            var psRuleFile = Path.Combine(_rulesDir, "CVE-Shield-CVE-2026-9999-powershell.json");
            
            Assert.True(File.Exists(cmdRuleFile), $"Expected rule file not found: {cmdRuleFile}");
            Assert.True(File.Exists(psRuleFile), $"Expected rule file not found: {psRuleFile}");

            // 2. Verify PoC hash was added to IoCScanner
            // Determinsitic hash generated for "CVE-2026-9999" is 1544c8c7c980997193b22cf331d279cf04b11fcfcdfae9c0cae6cf4a40d5e1cf
            // Let's compute it deterministically
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var bytes = System.Text.Encoding.UTF8.GetBytes("CVE-2026-9999-poc-salt");
            var hashBytes = sha256.ComputeHash(bytes);
            var expectedHash = string.Concat(System.Linq.Enumerable.Select(hashBytes, b => b.ToString("x2")));

            Assert.True(iocScanner.IsKnownBadHash(expectedHash), "PoC hash not registered in IoCScanner.");

            // 3. Verify event was logged to jsonl
            Assert.True(File.Exists(_logPath), "Log file was not created.");
            await eventLogger.DisposeAsync(); // Release lock on sentinel.log
            var logs = await File.ReadAllTextAsync(_logPath);
            Assert.Contains("cve_shield_match", logs);
            Assert.Contains("CVE-2026-9999", logs);

            // Clean up rule files created by this test
            try { File.Delete(cmdRuleFile); } catch { }
            try { File.Delete(psRuleFile); } catch { }
            foreach (var interpreter in new[] { "whoami", "certutil", "nltest" })
            {
                try { File.Delete(Path.Combine(_rulesDir, $"CVE-Shield-CVE-2026-9999-{interpreter}.json")); } catch { }
            }
        }

        [Fact]
        public async Task RunShieldingCycle_DoesNotDeploy_WhenNoMatchFound()
        {
            // Arrange
            var config = new SentinelConfig();
            config.CveShield.Enabled = true;
            config.CveShield.CustomFeedPath = _feedPath;

            // Mock a catalog that matches nothing
            var mockCatalog = new CisaKevCatalog
            {
                Vulnerabilities = new System.Collections.Generic.List<CisaVulnerability>
                {
                    new()
                    {
                        CveId = "CVE-2026-8888",
                        VendorProject = "NonExistentVendor",
                        Product = "NonExistentProductXYZ",
                        VulnerabilityName = "Mock Nonexistent Vulnerability",
                        ShortDescription = "A mock vulnerability that matches no local asset."
                    }
                }
            };

            var json = JsonSerializer.Serialize(mockCatalog);
            await File.WriteAllTextAsync(_feedPath, json);

            var cache = new SecureCacheStore(_tempTestDir);
            var iocScanner = new IoCScanner(cache);
            var eventLogger = new JsonlEventLogger(_logPath);
            var toastService = new ToastService(NullLogger<ToastService>.Instance);
            var hardener = new CveShieldHardener(NullLogger<CveShieldHardener>.Instance, config, iocScanner, eventLogger, toastService);

            // Act
            await hardener.RunShieldingCycleAsync(CancellationToken.None);

            // Assert
            var cmdRuleFile = Path.Combine(_rulesDir, "CVE-Shield-CVE-2026-8888-cmd.exe.json");
            Assert.False(File.Exists(cmdRuleFile), "Rule should not be written for non-matched CVE.");

            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var bytes = System.Text.Encoding.UTF8.GetBytes("CVE-2026-8888-poc-salt");
            var hashBytes = sha256.ComputeHash(bytes);
            var expectedHash = string.Concat(System.Linq.Enumerable.Select(hashBytes, b => b.ToString("x2")));
            Assert.False(iocScanner.IsKnownBadHash(expectedHash), "PoC hash should not be registered.");
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_tempTestDir))
                {
                    Directory.Delete(_tempTestDir, true);
                }
            }
            catch { }
        }
    }
}
