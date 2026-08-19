import { normalizeUrl } from '../engine/normalizeUrl.js';
import { checkDns, checkTls, checkRedirectChain } from '../engine/nativeSignals.js';
import { checkUrlhausFeed, getUrlhausFeedStatus } from '../providers/urlhausFeed.js';
import { decideVerdict } from '../engine/verdictEngine.js';

const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS || 8000);
const STARTUP_GRACE_MS = 30 * 1000; // don't report degraded just because the feed's first load hasn't finished yet
const processStartedAt = Date.now();

function log(event, fields) {
  // Structured logging — one JSON line per event, per docs/url-scan-design.md.
  console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...fields }));
}

export function registerRoutes(app) {
  app.get('/health', (req, res) => {
    const feed = getUrlhausFeedStatus();
    const uptimeMs = Date.now() - processStartedAt;
    const pastGracePeriod = uptimeMs > STARTUP_GRACE_MS;

    let status = 'ok';
    if (!feed.loaded && pastGracePeriod) {
      status = 'degraded'; // still serves requests (native signals keep working), just missing urlhaus coverage
    } else if (feed.stale) {
      status = 'degraded';
    }

    // Always 200: "degraded" still means the miner is up and serving
    // requests (native DNS/TLS/redirect signals keep working regardless of
    // urlhaus feed state) — it's a diagnostic flag, not a liveness failure.
    res.status(200).json({
      status,
      uptime_ms: uptimeMs,
      urlhaus_feed: feed,
    });
  });

  app.post('/scan', async (req, res) => {
    const requestId = `req_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const startedAt = Date.now();
    const rawUrl = req.body && req.body.url;

    log('scan_received', { requestId, rawUrl });

    const normalized = normalizeUrl(rawUrl);
    if (!normalized.ok) {
      const verdict = { verdict: 'unknown', confidence: 0, reason: normalized.reason };
      log('scan_complete', { requestId, verdict: verdict.verdict, reason: verdict.reason, duration_ms: Date.now() - startedAt });
      return res.json(verdict);
    }

    const { url, normalized: normalizedUrl } = normalized;

    const overallController = new AbortController();
    const overallTimer = setTimeout(() => overallController.abort(), REQUEST_TIMEOUT_MS);

    try {
      const results = await Promise.allSettled([
        Promise.resolve(checkUrlhausFeed(normalizedUrl)),
        checkDns(url.hostname),
        checkTls(url.hostname),
        checkRedirectChain(normalizedUrl),
      ]);

      const evidence = results.map((r, i) => {
        if (r.status === 'fulfilled') return r.value;
        const sourceNames = ['urlhaus', 'dns', 'tls', 'redirect'];
        return {
          source: sourceNames[i],
          available: false,
          malicious: false,
          suspicious: false,
          confidence: 0,
          reason: `provider threw: ${r.reason && r.reason.message}`,
        };
      });

      const verdict = decideVerdict(evidence);
      log('scan_complete', {
        requestId,
        url: normalizedUrl,
        verdict: verdict.verdict,
        confidence: verdict.confidence,
        evidence_sources: evidence.map((e) => ({ source: e.source, available: e.available })),
        duration_ms: Date.now() - startedAt,
      });

      res.json(verdict);
    } catch (err) {
      log('scan_error', { requestId, error: err.message, duration_ms: Date.now() - startedAt });
      res.json({ verdict: 'unknown', confidence: 0, reason: 'internal error during scan' });
    } finally {
      clearTimeout(overallTimer);
    }
  });
}
