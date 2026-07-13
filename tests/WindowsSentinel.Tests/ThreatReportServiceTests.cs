using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using WindowsSentinel.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace WindowsSentinel.Tests
{
    public class ThreatReportServiceTests
    {
        [Fact]
        public void ThreatReportService_ConstructsSuccessfully()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "rep_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                var config = new ThreatReportingConfig
                {
                    Enabled = true,
                    ProxyEndpoint = "https://localhost:8080",
                    ProxySharedSecret = "test-secret"
                };

                var service = new ThreatReportService(config, NullLogger<ThreatReportService>.Instance, cache);
                Assert.NotNull(service);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }
    }
}
