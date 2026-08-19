// Real client for the URLhaus (abuse.ch) URL lookup API.
// Verified contract (Phase 1 research): POST https://urlhaus-api.abuse.ch/v1/url/,
// body `url=<target>` (form-encoded), header `Auth-Key: <key>`.
// Response fields used: query_status, url_status, threat.

const ENDPOINT = 'https://urlhaus-api.abuse.ch/v1/url/';

/**
 * @param {string} targetUrl
 * @param {{ timeoutMs?: number, apiKey?: string }} [opts]
 * @returns {Promise<{source:string, available:boolean, malicious:boolean, suspicious:boolean, confidence:number, reason:string, latency_ms:number}>}
 */
export async function checkUrlhaus(targetUrl, opts = {}) {
  const { timeoutMs = 5000, apiKey = process.env.URLHAUS_AUTH_KEY } = opts;
  const start = Date.now();

  if (!apiKey) {
    return {
      source: 'urlhaus',
      available: false,
      malicious: false,
      suspicious: false,
      confidence: 0,
      reason: 'URLHAUS_AUTH_KEY not configured',
      latency_ms: Date.now() - start,
    };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(ENDPOINT, {
      method: 'POST',
      headers: {
        'Auth-Key': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ url: targetUrl }).toString(),
      signal: controller.signal,
    });

    if (!res.ok) {
      return {
        source: 'urlhaus',
        available: false,
        malicious: false,
        suspicious: false,
        confidence: 0,
        reason: `urlhaus http ${res.status}`,
        latency_ms: Date.now() - start,
      };
    }

    const data = await res.json();

    if (data.query_status === 'no_results') {
      return {
        source: 'urlhaus',
        available: true,
        malicious: false,
        suspicious: false,
        confidence: 0.2,
        reason: 'not listed in URLhaus',
        latency_ms: Date.now() - start,
      };
    }

    if (data.query_status === 'ok') {
      const isOnline = data.url_status === 'online';
      return {
        source: 'urlhaus',
        available: true,
        malicious: true,
        suspicious: false,
        confidence: isOnline ? 0.9 : 0.7,
        reason: `listed in URLhaus (status: ${data.url_status}, threat: ${data.threat || 'unspecified'})`,
        latency_ms: Date.now() - start,
      };
    }

    // invalid_url, http_post_expected, or any other status URLhaus defines
    return {
      source: 'urlhaus',
      available: false,
      malicious: false,
      suspicious: false,
      confidence: 0,
      reason: `urlhaus query_status: ${data.query_status}`,
      latency_ms: Date.now() - start,
    };
  } catch (err) {
    return {
      source: 'urlhaus',
      available: false,
      malicious: false,
      suspicious: false,
      confidence: 0,
      reason: `urlhaus request failed: ${err.message}`,
      latency_ms: Date.now() - start,
    };
  } finally {
    clearTimeout(timer);
  }
}
