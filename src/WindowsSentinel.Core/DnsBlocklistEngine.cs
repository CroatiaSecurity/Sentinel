using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace WindowsSentinel.Core
{
    public class DnsBlocklistEngine
    {
        private readonly HashSet<string> _maliciousDomains = new(StringComparer.OrdinalIgnoreCase);
        private readonly DetectionEngine _detectionEngine;

        public DnsBlocklistEngine(DetectionEngine detectionEngine)
        {
            _detectionEngine = detectionEngine;
            _maliciousDomains.Add("c2.malicious-domain.com");
            _maliciousDomains.Add("malware-exfil.xyz");
        }

        public async Task EvaluateQueryAsync(int pid, string processName, string domain)
        {
            if (string.IsNullOrWhiteSpace(domain)) return;

            if (_maliciousDomains.Contains(domain))
            {
                var detection = new DetectionEvent
                {
                    RuleName = "DNS Blocklist Match",
                    ProcessName = processName,
                    ProcessId = pid,
                    Confidence = 0.90,
                    Tier = DetectionTier.Tier1Behavioral,
                    Evidence = $"Process '{processName}' resolved a known malicious domain: {domain}",
                    Reasoning = "Outbound DNS query matches threat intelligence blocklist for active malware or C2 infrastructure.",
                    Metadata = new Dictionary<string, string> { { "Domain", domain } }
                };

                await _detectionEngine.EmitAsync(detection);
            }
        }

        /// <summary>2-arg synchronous check — used internally.</summary>
        public bool IsBlocked(string domain, out BlocklistCategory category)
        {
            category = BlocklistCategory.Malware;
            if (string.IsNullOrWhiteSpace(domain)) return false;
            if (_maliciousDomains.Contains(domain))
            {
                category = BlocklistCategory.Malware;
                return true;
            }
            return false;
        }

        /// <summary>3-arg overload — used by DnsQueryMonitor (includes blockReason).</summary>
        public bool IsBlocked(string domain, out BlocklistCategory category, out string blockReason)
        {
            blockReason = string.Empty;
            category = BlocklistCategory.Malware;
            if (string.IsNullOrWhiteSpace(domain)) return false;
            if (_maliciousDomains.Contains(domain))
            {
                category = BlocklistCategory.Malware;
                blockReason = "Matched internal malicious domain list";
                return true;
            }
            return false;
        }

        /// <summary>Adds a domain to the runtime blocklist.</summary>
        public void AddDomain(string domain) => _maliciousDomains.Add(domain);
    }

    /// <summary>Category of a blocked domain.</summary>
    public enum BlocklistCategory
    {
        Malware,
        Phishing,
        C2,
        Adware,
        Tracking
    }
}
