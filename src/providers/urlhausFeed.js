// URLhaus feed-based provider — no Auth-Key required.
// Real, live, keyless bulk feeds (verified working 2026-08-18/19):
//   https://urlhaus.abuse.ch/downloads/csv_online/  — ~16k currently-online listed threats, ~3.9MB
// Too large to fetch per-request, so we pull it on an interval into an
// in-memory Set and match incoming URLs against that local snapshot.
// This is abuse.ch's own standard distribution mechanism, not a workaround
// of anything they intend to restrict — the Auth-Key-gated query API and
// this feed are two different, both-official access paths to the same data.
//
// Tradeoff vs the live query API (src/providers/urlhaus.js, currently
// blocked on an account-activation issue outside our control — see
// docs/url-scan-research.md conversation log): data is only as fresh as the
// last refresh cycle, not truly real-time. Refresh interval is deliberately
// short (5 min) to keep that gap small.

const FEED_URL = 'https://urlhaus.abuse.ch/downloads/csv_online/';
const REFRESH_INTERVAL_MS = 5 * 60 * 1000;
const RETRY_INTERVAL_MS = 30 * 1000; // faster retry after a failed refresh, instead of waiting a full cycle
const STALE_AFTER_MS = REFRESH_INTERVAL_MS * 3; // 3 missed cycles = something is actually wrong, not just one blip

let urlSet = new Set();
let lastRefreshed = null;
let lastRefreshError = null;
let consecutiveFailures = 0;
let isRefreshing = false;

// Minimal quoted-CSV line parser — URLhaus fields are double-quoted,
// comma-separated, with "" as the escape for a literal quote inside a field.
function parseCsvLine(line) {
  const fields = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQuotes) {
      if (c === '"') {
        if (line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        current += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ',') {
      fields.push(current);
      current = '';
    } else {
      current += c;
    }
  }
  fields.push(current);
  return fields;
}

async function refresh() {
  if (isRefreshing) {
    console.log(JSON.stringify({ ts: new Date().toISOString(), event: 'urlhaus_feed_refresh_skipped_overlap' }));
    return;
  }
  isRefreshing = true;
  const start = Date.now();
  try {
    const res = await fetch(FEED_URL, { signal: AbortSignal.timeout(20000) });
    if (!res.ok) throw new Error(`feed http ${res.status}`);
    const text = await res.text();
    const next = new Set();
    for (const line of text.split('\n')) {
      if (!line || line.startsWith('#')) continue;
      const fields = parseCsvLine(line);
      // columns: id, dateadded, url, url_status, threat, tags, urlhaus_link, reporter
      const url = fields[2];
      if (url) next.add(url);
    }
    // Guard against a truncated/empty response silently wiping out a good
    // cache — a real feed has thousands of entries; anything wildly smaller
    // is treated as a failed refresh that keeps the previous snapshot.
    if (next.size < 100) {
      throw new Error(`feed returned suspiciously few entries (${next.size}), keeping previous snapshot`);
    }

    urlSet = next;
    lastRefreshed = new Date();
    lastRefreshError = null;
    consecutiveFailures = 0;
    console.log(JSON.stringify({
      ts: new Date().toISOString(),
      event: 'urlhaus_feed_refreshed',
      entries: urlSet.size,
      duration_ms: Date.now() - start,
    }));
  } catch (err) {
    consecutiveFailures += 1;
    lastRefreshError = err.message;
    console.log(JSON.stringify({
      ts: new Date().toISOString(),
      event: 'urlhaus_feed_refresh_failed',
      error: err.message,
      consecutive_failures: consecutiveFailures,
      duration_ms: Date.now() - start,
    }));
  } finally {
    isRefreshing = false;
  }
}

function scheduleNext() {
  const delay = lastRefreshError ? RETRY_INTERVAL_MS : REFRESH_INTERVAL_MS;
  setTimeout(async () => {
    await refresh();
    scheduleNext();
  }, delay).unref();
}

export function startUrlhausFeedRefresh() {
  const initialLoad = refresh();
  initialLoad.then(scheduleNext);
  return initialLoad;
}

export function isFeedStale() {
  if (lastRefreshed === null) return false; // "never loaded" is a distinct state, not "stale"
  return Date.now() - lastRefreshed.getTime() > STALE_AFTER_MS;
}

export function getUrlhausFeedStatus() {
  return {
    loaded: lastRefreshed !== null,
    entries: urlSet.size,
    last_refreshed: lastRefreshed ? lastRefreshed.toISOString() : null,
    last_error: lastRefreshError,
    consecutive_failures: consecutiveFailures,
    stale: isFeedStale(),
  };
}

/**
 * @param {string} normalizedUrl
 * @returns {{source:string, available:boolean, malicious:boolean, suspicious:boolean, confidence:number, reason:string, latency_ms:number}}
 */
export function checkUrlhausFeed(normalizedUrl) {
  const start = Date.now();

  if (lastRefreshed === null) {
    return {
      source: 'urlhaus',
      available: false,
      malicious: false,
      suspicious: false,
      confidence: 0,
      reason: 'urlhaus feed not loaded yet',
      latency_ms: Date.now() - start,
    };
  }

  const hit = urlSet.has(normalizedUrl);
  return {
    source: 'urlhaus',
    available: true,
    malicious: hit,
    suspicious: false,
    confidence: hit ? 0.9 : 0.2,
    reason: hit
      ? `listed as an active online threat in URLhaus (feed snapshot ${lastRefreshed.toISOString()})`
      : `not found in URLhaus online-threat feed (${urlSet.size} entries, snapshot ${lastRefreshed.toISOString()})`,
    latency_ms: Date.now() - start,
  };
}
