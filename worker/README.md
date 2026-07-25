# Sentinel Threat Report Proxy

Cloudflare Worker that receives threat reports from Sentinel agents and forwards them to threat intelligence platforms (MalwareBazaar, URLhaus, AbuseIPDB, VirusTotal) using server-side API keys.

**Version: 1.6.0** — authentication is mandatory.

## Auth model (v1.6.0)

| Header | Required | Purpose |
|--------|----------|---------|
| `X-Sentinel-Timestamp` | Yes | Unix seconds; must be within ±5 minutes |
| `X-Sentinel-Signature` | Yes | Hex HMAC-SHA256 of `{timestamp}.{path}.{rawBody}` |
| `X-Sentinel-Auth` | Optional | If present, must equal shared secret |

Signing key is the **server-side** `SENTINEL_SHARED_SECRET` (also configured on agents as `ThreatReporting:ProxySharedSecret`).  
**There is no client-supplied signing key.** Missing secret → Worker returns 503.

## Free Tier Limits

- 100,000 requests/day (Cloudflare Workers free plan)
- Worker enforces ~60 requests/IP/minute

## Setup

1. Create a free Cloudflare account at https://dash.cloudflare.com/sign-up
2. Install Wrangler CLI: `npm install -g wrangler`
3. Login: `wrangler login`
4. Set your account ID in `wrangler.toml`
5. Add secrets:

```bash
wrangler secret put SENTINEL_SHARED_SECRET   # required, ≥16 chars
wrangler secret put MALWAREBAZAAR_KEY
wrangler secret put URLHAUS_TOKEN
wrangler secret put ABUSEIPDB_KEY
wrangler secret put VIRUSTOTAL_KEY
```

6. Deploy: `wrangler deploy`

## Sentinel Integration

```json
{
  "ThreatReporting": {
    "Enabled": true,
    "ProxyEndpoint": "https://sentinel-threat-proxy.your-subdomain.workers.dev",
    "ProxySharedSecret": "same-value-as-SENTINEL_SHARED_SECRET"
  }
}
```

If `ProxySharedSecret` is null/short, agents **skip** reporting and VT proxy lookups (fail closed).

## API Endpoints

- `POST /report/hash` — MalwareBazaar
- `POST /report/url` — URLhaus
- `POST /report/ip` — AbuseIPDB
- `POST /lookup/vt` — VirusTotal hash lookup
- `GET /health` — unauthenticated health (no secrets)

## Getting API Keys (Free)

- **MalwareBazaar**: https://auth.abuse.ch/
- **URLhaus**: https://urlhaus.abuse.ch/api/
- **AbuseIPDB**: https://www.abuseipdb.com/register
- **VirusTotal**: https://www.virustotal.com/
