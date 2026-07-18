/**
 * Behavedr — Threat Report Proxy Worker
 * 
 * Receives threat reports from Behavedr agents and forwards them to
 * abuse.ch (MalwareBazaar, URLhaus) using server-side API keys.
 * 
 * Users never see or need API keys — this Worker holds them as secrets.
 * 
 * Endpoints:
 *   POST /report/hash    — Report a malicious hash to MalwareBazaar
 *   POST /report/url     — Report a malicious URL to URLhaus
 *   POST /report/ip      — Report a malicious IP to AbuseIPDB
 *   POST /lookup/vt      — Lookup a SHA-256 hash on VirusTotal (proxied)
 *   GET  /health         — Health check
 * 
 * Deploy: wrangler deploy
 * Secrets: wrangler secret put MALWAREBAZAAR_KEY
 *          wrangler secret put URLHAUS_TOKEN
 *          wrangler secret put ABUSEIPDB_KEY
 *          wrangler secret put VIRUSTOTAL_KEY
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS headers for browser-based tools (if ever needed)
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Behavedr-Auth, X-Behavedr-Signature, X-Behavedr-Timestamp, X-Behavedr-Key',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // Health check
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({
        status: 'ok',
        service: 'behavedr-threat-proxy',
        timestamp: new Date().toISOString()
      }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
    }

    // All report endpoints require POST
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'POST required' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    // Check shared secret authentication if configured on worker
    if (env.BEHAVEDR_SHARED_SECRET) {
      const authHeader = request.headers.get('X-Behavedr-Auth');
      if (!authHeader || authHeader !== env.BEHAVEDR_SHARED_SECRET) {
        return new Response(JSON.stringify({ error: 'Unauthorized: Invalid or missing X-Behavedr-Auth header' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
    }

    // Check signature and timestamp (required for all proxy requests to prevent replay and MITM)
    const signature = request.headers.get('X-Behavedr-Signature');
    const timestamp = request.headers.get('X-Behavedr-Timestamp');
    const clientKey = request.headers.get('X-Behavedr-Key');

    if (!signature || !timestamp || !clientKey) {
      return new Response(JSON.stringify({ error: 'Bad Request: Missing required X-Behavedr security headers' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    // Verify timestamp within 5 minutes (300 seconds) of worker time
    const timestampVal = parseInt(timestamp, 10);
    const nowSec = Math.floor(Date.now() / 1000);
    if (isNaN(timestampVal) || Math.abs(nowSec - timestampVal) > 300) {
      return new Response(JSON.stringify({ error: 'Bad Request: Stale or invalid timestamp' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const rawBody = await request.text();
      
      // Verify signature over the exact raw body payload
      const signatureValid = await verifySignature(signature, clientKey, timestamp, url.pathname, rawBody);
      if (!signatureValid) {
        return new Response(JSON.stringify({ error: 'Unauthorized: HMAC signature verification failed' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      const body = JSON.parse(rawBody);

      // Basic validation — require at minimum a type and value
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

/**
 * Report malicious hash to MalwareBazaar
 * Body: { type: "hash", value: "sha256hex", tags: ["trojan", "rat"], comment: "..." }
 */
async function reportHash(body, env) {
  if (!env.MALWAREBAZAAR_KEY) {
    return { success: false, error: 'MalwareBazaar key not configured' };
  }

  const formData = new URLSearchParams();
  formData.append('query', 'taginfo');
  formData.append('hash', body.value);
  formData.append('comment', body.comment || 'Reported by Behavedr');
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

/**
 * Report malicious URL to URLhaus
 * Body: { type: "url", value: "http://evil.com/malware.exe", threat: "malware_download", tags: [...] }
 */
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
    tags: body.tags || ['behavedr']
  }]));

  const response = await fetch('https://urlhaus-api.abuse.ch/v1/urls/add/', {
    method: 'POST',
    body: formData
  });

  const text = await response.text();
  return { success: response.ok, upstream: text.substring(0, 500) };
}

/**
 * Report malicious IP to AbuseIPDB
 * Body: { type: "ip", value: "1.2.3.4", categories: [14, 15], comment: "Port scan detected" }
 */
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
      comment: body.comment || 'Malicious activity detected by Behavedr',
      timestamp: new Date().toISOString()
    })
  });

  const text = await response.text();
  return { success: response.ok, upstream: text.substring(0, 500) };
}

/**
 * Lookup a SHA-256 hash on VirusTotal v3 API (proxied — API key held server-side).
 * Body: { type: "hash", value: "sha256hex" }
 * Returns: { success: true, verdict: "safe"|"suspicious"|"malicious"|"not_found", detections: N, engines: N }
 */
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

/**
 * Helper to convert hex string to Uint8Array
 */
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Cryptographically verify the HMAC-SHA256 signature
 */
async function verifySignature(signatureHex, keyHex, timestamp, path, bodyJson) {
  try {
    const keyBytes = hexToBytes(keyHex);
    const sigBytes = hexToBytes(signatureHex);
    
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    
    const payloadStr = `${timestamp}.${path}.${bodyJson}`;
    const encoder = new TextEncoder();
    const payloadBytes = encoder.encode(payloadStr);
    
    return await crypto.subtle.verify(
      "HMAC",
      cryptoKey,
      sigBytes,
      payloadBytes
    );
  } catch (err) {
    return false;
  }
}
