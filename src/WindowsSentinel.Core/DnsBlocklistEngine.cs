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
            // Baseline some known domains
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
                    Tier = DetectionTier.Tier1Behavioral, // President's Law can kill on DNS blocklist / campaign
                    Evidence = $"Process '{processName}' resolved a known malicious domain: {domain}",
                    Reasoning = "Outbound DNS query matches threat intelligence blocklist for active malware or C2 infrastructure.",
                    Metadata = new Dictionary<string, string>
                    {
                        { "Domain", domain }
                    }
                };

                await _detectionEngine.EmitAsync(detection);
            }
        }
    }
}
