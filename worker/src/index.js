/**
 * Sentinel — Threat Report Proxy Worker (v2.0.8)
 *
 * Receives threat reports from Sentinel agents and forwards them to
 * abuse.ch (MalwareBazaar, URLhaus) using server-side API keys.
 *
 * SECURITY:
 *   - SENTINEL_SHARED_SECRET is REQUIRED (fail closed).
 *   - HMAC-SHA256 over `timestamp.nonce.path.body` using the shared secret
 *     as the key (never accept a client-provided signing key).
 *   - 60-second timestamp window (v2.0.8: was 5 minutes).
 *   - Server-side nonce replay cache (in-memory per isolate; CF Rate Limiting
 *     recommended as durable backstop).
 *   - No wildcard CORS (non-browser agents only).
 *
 * Endpoints:
 *   POST /report/hash    — Report a malicious hash to MalwareBazaar
 *   POST /report/url     — Report a malicious URL to URLhaus
 *   POST /report/ip      — Report a malicious IP to AbuseIPDB
 *   POST /lookup/vt      — Lookup a SHA-256 hash on VirusTotal (proxied)
 *   GET  /health         — Health check (unauthenticated)
 *
 * Deploy: wrangler deploy
 * Secrets: wrangler secret put SENTINEL_SHARED_SECRET
 *          wrangler secret put MALWAREBAZAAR_KEY
 *          wrangler secret put URLHAUS_TOKEN
 *          wrangler secret put ABUSEIPDB_KEY
 *          wrangler secret put VIRUSTOTAL_KEY
 */

// Per-isolate rate limit with sliding window.
// NOTE: Resets on cold start. Prefer Cloudflare Rate Limiting Rules in production.
const RATE_LIMIT_PER_MINUTE = 30;
const rateBuckets = new Map();

// v2.0.8: Nonce replay cache (timestamp.nonce → expiry unix sec)
const MAX_NONCE_ENTRIES = 4096;
const usedNonces = new Map();
const TIMESTAMP_WINDOW_SEC = 60;

function checkRateLimit(ip) {
  const now = Math.floor(Date.now() / 1000);
  const window = Math.floor(now / 60);
  const key = `${ip}:${window}`;
  const count = rateBuckets.get(key) || 0;
  if (count >= RATE_LIMIT_PER_MINUTE) return false;
  rateBuckets.set(key, count + 1);
  if (rateBuckets.size > 5000) {
    for (const k of rateBuckets.keys()) {
      if (!k.endsWith(`:${window}`) && !k.endsWith(`:${window - 1}`)) {
        rateBuckets.delete(k);
      }
    }
  }
  return true;
}

function consumeNonce(nonce, ts) {
  if (!nonce || typeof nonce !== 'string' || nonce.length < 16 || nonce.length > 64) {
    return false;
  }
  // Hex-ish only
  if (!/^[a-fA-F0-9]+$/.test(nonce)) return false;

  const key = `${ts}:${nonce.toLowerCase()}`;
  if (usedNonces.has(key)) return false;
  usedNonces.set(key, ts + TIMESTAMP_WINDOW_SEC);

  // Prune expired
  if (usedNonces.size > 64) {
    const now = Math.floor(Date.now() / 1000);
    for (const [k, exp] of usedNonces.entries()) {
      if (exp < now) usedNonces.delete(k);
    }
  }
  // Hard cap
  if (usedNonces.size > MAX_NONCE_ENTRIES) {
    const keys = [...usedNonces.keys()].slice(0, usedNonces.size - MAX_NONCE_ENTRIES);
    for (const k of keys) usedNonces.delete(k);
  }
  return true;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // No CORS for browser abuse surface
    const corsHeaders = {
      'Access-Control-Allow-Origin': '',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Sentinel-Signature, X-Sentinel-Timestamp, X-Sentinel-Nonce',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    if (url.pathname === '/health') {
      return new Response(JSON.stringify({
        status: 'ok',
        service: 'sentinel-threat-proxy',
        version: '2.0.8',
        timestamp: new Date().toISOString(),
        authRequired: true,
        nonceRequired: true,
        timestampWindowSec: TIMESTAMP_WINDOW_SEC
      }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
    }

    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'POST required' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    if (!env.SENTINEL_SHARED_SECRET || env.SENTINEL_SHARED_SECRET.length < 16) {
      return new Response(JSON.stringify({
        error: 'Service misconfigured: SENTINEL_SHARED_SECRET required'
      }), {
        status: 503,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    const clientIp = request.headers.get('CF-Connecting-IP')
      || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim()
      || 'unknown';
    if (!checkRateLimit(clientIp)) {
      return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
        status: 429,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    const signature = request.headers.get('X-Sentinel-Signature');
    const timestamp = request.headers.get('X-Sentinel-Timestamp');
    const nonce = request.headers.get('X-Sentinel-Nonce');

    if (!signature || !timestamp || !nonce) {
      return new Response(JSON.stringify({
        error: 'Bad Request: Missing X-Sentinel-Signature, X-Sentinel-Timestamp, or X-Sentinel-Nonce'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    const timestampVal = parseInt(timestamp, 10);
    const nowSec = Math.floor(Date.now() / 1000);
    if (isNaN(timestampVal) || Math.abs(nowSec - timestampVal) > TIMESTAMP_WINDOW_SEC) {
      return new Response(JSON.stringify({ error: 'Bad Request: Stale or invalid timestamp' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    if (!consumeNonce(nonce, timestampVal)) {
      return new Response(JSON.stringify({ error: 'Unauthorized: Replay or invalid nonce' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const rawBody = await request.text();

      // v2.0.8 payload: timestamp.nonce.path.body
      const signatureValid = await verifySignature(
        signature,
        env.SENTINEL_SHARED_SECRET,
        timestamp,
        nonce,
        url.pathname,
        rawBody
      );
      if (!signatureValid) {
        return new Response(JSON.stringify({ error: 'Unauthorized: HMAC signature verification failed' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      const body = JSON.parse(rawBody);

      if (!body.type || !body.value) {
        return new Response(JSON.stringify({ error: 'Missing type or value' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      let result;
      switch (url.pathname) {
        case '/report/hash':
          result = await reportHash(body, env);
          break;
        case '/report/url':
          result = await reportUrl(body, env);
          break;
        case '/report/ip':
          result = await reportIp(body, env);
          break;
        case '/lookup/vt':
          result = await lookupVirusTotal(body, env);
          break;
        default:
          return new Response(JSON.stringify({ error: 'Unknown endpoint' }), {
            status: 404,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
      }

      return new Response(JSON.stringify(result), {
        status: result.success ? 200 : 502,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: 'Invalid request', detail: err.message }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
};

async function reportHash(body, env) {
  if (!env.MALWAREBAZAAR_KEY) {
    return { success: false, error: 'MalwareBazaar key not configured' };
  }

  const formData = new URLSearchParams();
  formData.append('query', 'taginfo');
  formData.append('hash', body.value);
  formData.append('comment', body.comment || 'Reported by Sentinel');
  if (body.tags && body.tags.length > 0) {
    formData.append('tag', body.tags.join(','));
  }

  const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers: { 'Auth-Key': env.MALWAREBAZAAR_KEY },
    body: formData
  });

  const text = await response.text();
  return { success: response.ok, upstream: text.substring(0, 500) };
}

async function reportUrl(body, env) {
  if (!env.URLHAUS_TOKEN) {
    return { success: false, error: 'URLhaus token not configured' };
  }

  const formData = new URLSearchParams();
  formData.append('token', env.URLHAUS_TOKEN);
  formData.append('anonymous', '0');
  formData.append('submission', JSON.stringify([{
    url: body.value,
    threat: body.threat || 'malware_download',
    tags: body.tags || ['sentinel']
  }]));

  const response = await fetch('https://urlhaus-api.abuse.ch/v1/urls/add/', {
    method: 'POST',
    body: formData
  });

  const text = await response.text();
  return { success: response.ok, upstream: text.substring(0, 500) };
}

async function reportIp(body, env) {
  if (!env.ABUSEIPDB_KEY) {
    return { success: false, error: 'AbuseIPDB key not configured' };
  }

  const response = await fetch('https://api.abuseipdb.com/api/v2/report', {
    method: 'POST',
    headers: {
      'Key': env.ABUSEIPDB_KEY,
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      ip: body.value,
      categories: (body.categories || [14]).join(','),
      comment: body.comment || 'Malicious activity detected by Sentinel',
      timestamp: new Date().toISOString()
    })
  });

  const text = await response.text();
  return { success: response.ok, upstream: text.substring(0, 500) };
}

async function lookupVirusTotal(body, env) {
  if (!env.VIRUSTOTAL_KEY) {
    return { success: false, error: 'VirusTotal API key not configured' };
  }

  const hash = body.value;
  if (!hash || hash.length !== 64 || !/^[a-fA-F0-9]+$/.test(hash)) {
    return { success: false, error: 'Invalid SHA-256 hash' };
  }

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      method: 'GET',
      headers: {
        'x-apikey': env.VIRUSTOTAL_KEY,
        'Accept': 'application/json'
      }
    });

    if (response.status === 404) {
      return { success: true, verdict: 'not_found', detections: 0, engines: 0 };
    }

    if (!response.ok) {
      return { success: false, error: `VT API returned ${response.status}` };
    }

    const data = await response.json();
    const stats = data?.data?.attributes?.last_analysis_stats;
    if (!stats) {
      return { success: true, verdict: 'not_found', detections: 0, engines: 0 };
    }

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const undetected = stats.undetected || 0;
    const harmless = stats.harmless || 0;
    const totalEngines = malicious + suspicious + undetected + harmless;
    const detectionCount = malicious + suspicious;
    const detectionRate = totalEngines > 0 ? detectionCount / totalEngines : 0;

    let verdict = 'safe';
    if (detectionRate >= 0.25) verdict = 'malicious';
    else if (detectionRate >= 0.10) verdict = 'suspicious';
    else if (detectionCount >= 3) verdict = 'suspicious';

    return {
      success: true,
      verdict,
      detections: detectionCount,
      engines: totalEngines,
      detectionRate: Math.round(detectionRate * 100) / 100
    };
  } catch (err) {
    return { success: false, error: `VT lookup failed: ${err.message}` };
  }
}

function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) return new Uint8Array(0);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Verify HMAC-SHA256(secret, `${timestamp}.${nonce}.${path}.${body}`) against hex signature.
 */
async function verifySignature(signatureHex, sharedSecret, timestamp, nonce, path, bodyJson) {
  try {
    const encoder = new TextEncoder();
    const keyBytes = encoder.encode(sharedSecret);
    const sigBytes = hexToBytes(signatureHex);
    if (sigBytes.length !== 32) return false;

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const payloadStr = `${timestamp}.${nonce}.${path}.${bodyJson}`;
    const payloadBytes = encoder.encode(payloadStr);

    return await crypto.subtle.verify('HMAC', cryptoKey, sigBytes, payloadBytes);
  } catch {
    return false;
  }
}
