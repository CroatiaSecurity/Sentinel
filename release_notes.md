## What's New in v1.3.1

### Multi-Signal File Reputation Engine

Sentinel now evaluates every binary with a composite trust score (0-100) derived from 4 independent signal sources — matching how enterprise EDRs like CrowdStrike and SentinelOne assess file risk.

#### How It Works

Every file scanned on disk or executed as a process receives a composite score:

| Score | Verdict | Action |
|-------|---------|--------|
| 0-20 | Trusted | No action |
| 21-40 | Low Risk | No action |
| 41-60 | Suspicious | Logged for review, feeds correlation engine |
| 61-80 | High Risk | Kill process, deny execution ACL |
| 81-100 | Malicious | Kill process tree, deny execution, quarantine |

#### Signal Sources

1. **Hash Reputation Consensus** (weight: 40%) — Parallel queries to CIRCL, MalwareBazaar, and VirusTotal with weighted voting
2. **Static PE Analysis** (weight: 25%) — Entropy, suspicious imports, packer detection, section anomalies
3. **Signer Trust** (weight: 20%) — Authenticode verification as continuous trust signal
4. **Contextual Risk** (weight: 15%) — File path, age on disk, prevalence across system

#### Rate Limiting & Efficiency

- 4 concurrent CIRCL lookups, 2 MalwareBazaar, 1 VirusTotal (4/min)
- In-flight deduplication: same hash queried by multiple threads = single API call
- Intelligent caching: Safe=7d TTL, Unknown=24h (retry), Malicious=permanent
- Prevalence map: widely-seen files get lower risk scores automatically

**Full Changelog**: https://github.com/CroatiaSecurity/Sentinel/compare/v1.3.0...v1.3.1
