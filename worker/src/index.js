/**
 * Windows Sentinel — Threat Report Proxy Worker
 * 
 * Receives threat reports from Sentinel agents and forwards them to
 * abuse.ch (MalwareBazaar, URLhaus) using server-side API keys.
 * 
 * Users never see or need API keys — this Worker holds them as secrets.
 * 
 * Endpoints:
 *   POST /report/hash    — Report a malicious hash to MalwareBazaar
 *   POST /report/url     — Report a malicious URL to URLhaus
 *   POST /report/ip      — Report a malicious IP to AbuseIPDB
 *   GET  /health         — Health check
 * 
 * Deploy: wrangler deploy
 * Secrets: wrangler secret put MALWAREBAZAAR_KEY
 *          wrangler secret put URLHAUS_TOKEN
 *          wrangler secret put ABUSEIPDB_KEY
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS headers for browser-based tools (if ever needed)
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // Health check
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({
        status: 'ok',
        service: 'sentinel-threat-proxy',
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

    try {
      const body = await request.json();

      // Basic validation — require at minimum a type and value
      if (!body.type || !body.value) {
        return new Response(JSON.stringify({ error: 'Missing type or value' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // Rate limiting: simple per-IP throttle via CF headers
      // (Cloudflare's free plan includes basic rate limiting)

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
  formData.append('comment', body.comment || 'Reported by Windows Sentinel');
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
    tags: body.tags || ['sentinel']
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
      comment: body.comment || 'Malicious activity detected by Windows Sentinel',
      timestamp: new Date().toISOString()
    })
  });

  const text = await response.text();
  return { success: response.ok, upstream: text.substring(0, 500) };
}
