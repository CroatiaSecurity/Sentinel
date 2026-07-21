# Sentinel Threat Report Proxy

Cloudflare Worker that receives threat reports from Sentinel agents and forwards them to threat intelligence platforms (MalwareBazaar, URLhaus, AbuseIPDB) using server-side API keys.

Users never need to configure API keys — the Worker holds them as encrypted secrets.

## Free Tier Limits

- 100,000 requests/day (Cloudflare Workers free plan)
- No credit card required
- No egress fees

## Setup

1. Create a free Cloudflare account at https://dash.cloudflare.com/sign-up
2. Install Wrangler CLI: `npm install -g wrangler`
3. Login: `wrangler login`
4. Set your account ID in `wrangler.toml`
5. Add your API keys as secrets:

```bash
wrangler secret put MALWAREBAZAAR_KEY
wrangler secret put URLHAUS_TOKEN
wrangler secret put ABUSEIPDB_KEY
```

6. Deploy: `wrangler deploy`

Your Worker will be available at: `https://sentinel-threat-proxy.<your-subdomain>.workers.dev`

## API Endpoints

### POST /report/hash
Report a malicious file hash to MalwareBazaar.
```json
{
  "type": "hash",
  "value": "sha256_hex_string",
  "tags": ["trojan", "rat"],
  "comment": "Detected by Sentinel - ransomware behavior"
}
```

### POST /report/url
Report a malicious URL to URLhaus.
```json
{
  "type": "url",
  "value": "http://evil.com/payload.exe",
  "threat": "malware_download",
  "tags": ["sentinel", "c2"]
}
```

### POST /report/ip
Report a malicious IP to AbuseIPDB.
```json
{
  "type": "ip",
  "value": "1.2.3.4",
  "categories": [14, 15],
  "comment": "Port scan and brute force detected"
}
```

### GET /health
Health check.

## Getting API Keys (Free)

- **MalwareBazaar**: https://auth.abuse.ch/ → sign up → get Auth-Key
- **URLhaus**: https://urlhaus.abuse.ch/api/ → sign up → get token
- **AbuseIPDB**: https://www.abuseipdb.com/register → get API key (free tier: 1000 reports/day)

## Sentinel Integration

In the Sentinel service appsettings.json, set:
```json
{
  "ThreatReporting": {
    "Enabled": true,
    "ProxyEndpoint": "https://sentinel-threat-proxy.your-subdomain.workers.dev"
  }
}
```

The Sentinel agent will POST reports to this endpoint instead of directly to abuse.ch.
