using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Reports detected threats to threat intelligence platforms via the Cloudflare Worker proxy.
    /// The proxy holds API keys server-side so they never appear in the open-source repo.
    /// 
    /// If ProxyEndpoint is null, reporting is silently skipped (lookups still work via HashReputationService).
    /// </summary>
    public class ThreatReportService
    {
        private readonly ThreatReportingConfig _config;
        private readonly ILogger<ThreatReportService> _logger;
        private readonly HttpClient _httpClient;

        public ThreatReportService(ThreatReportingConfig config, ILogger<ThreatReportService> logger)
        {
            _config = config;
            _logger = logger;
            _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        }

        /// <summary>
        /// Reports a malicious file hash (SHA256) to MalwareBazaar via proxy.
        /// </summary>
        public async Task ReportHashAsync(string sha256, string[] tags, string comment)
        {
            if (!CanReport()) return;

            await SendReportAsync("/report/hash", new
            {
                type = "hash",
                value = sha256,
                tags,
                comment
            });
        }

        /// <summary>
        /// Reports a malicious URL to URLhaus via proxy.
        /// </summary>
        public async Task ReportUrlAsync(string url, string threat, string[] tags)
        {
            if (!CanReport()) return;

            await SendReportAsync("/report/url", new
            {
                type = "url",
                value = url,
                threat,
                tags
            });
        }

        /// <summary>
        /// Reports a malicious IP to AbuseIPDB via proxy.
        /// Categories: https://www.abuseipdb.com/categories
        /// </summary>
        public async Task ReportIpAsync(string ip, int[] categories, string comment)
        {
            if (!CanReport()) return;

            await SendReportAsync("/report/ip", new
            {
                type = "ip",
                value = ip,
                categories,
                comment
            });
        }

        private bool CanReport()
        {
            if (!_config.Enabled) return false;
            if (string.IsNullOrWhiteSpace(_config.ProxyEndpoint)) return false;
            return true;
        }

        private async Task SendReportAsync(string path, object payload)
        {
            try
            {
                var url = _config.ProxyEndpoint!.TrimEnd('/') + path;
                var json = JsonSerializer.Serialize(payload);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync(url, content);

                if (response.IsSuccessStatusCode)
                {
                    _logger.LogDebug("Threat report submitted: {Path}", path);
                }
                else
                {
                    _logger.LogWarning("Threat report failed ({Status}): {Path}", (int)response.StatusCode, path);
                }
            }
            catch (Exception ex)
            {
                // Never crash on reporting failure — detection/response is more important
                _logger.LogDebug("Threat report error: {Message}", ex.Message);
            }
        }
    }
}
