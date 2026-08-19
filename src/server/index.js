import 'dotenv/config';
import express from 'express';
import { registerRoutes } from './routes.js';
import { startUrlhausFeedRefresh } from '../providers/urlhausFeed.js';
import { loadConfig } from './config.js';

function log(event, fields = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...fields }));
}

let config;
try {
  config = loadConfig(process.env);
} catch (err) {
  // Fail fast and loud on bad config — do not start serving requests with
  // an unvalidated port/timeout that could silently misbehave.
  console.error(JSON.stringify({ ts: new Date().toISOString(), event: 'config_invalid', error: err.message }));
  process.exit(1);
}

log('config_loaded', {
  port: config.port,
  requestTimeoutMs: config.requestTimeoutMs,
  nodeEnv: config.nodeEnv,
  optionalProviders: config.optionalProviders,
});

const app = express();
app.use(express.json());

registerRoutes(app);

// Global error handler — catches express.json() parse errors and anything
// else thrown/passed to next(err) in a route. Must be registered last and
// take exactly 4 args for Express to treat it as an error handler.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  log('unhandled_route_error', { error: err.message, path: req.path });
  if (res.headersSent) return;
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ verdict: 'unknown', confidence: 0, reason: 'malformed json body' });
  }
  res.status(500).json({ verdict: 'unknown', confidence: 0, reason: 'internal server error' });
});

const server = app.listen(config.port, () => {
  log('server_started', { port: config.port });
});

// Kick off the first URLhaus feed load in the background — the server
// accepts requests immediately; /scan degrades gracefully (urlhaus
// unavailable) until the first load completes, same as any other
// provider failure per the verdict engine's design.
startUrlhausFeedRefresh();

// Process-level safety net. A miner that silently dies (and doesn't restart)
// is worse for leaderboard score than one that restarts cleanly — a crash
// here is intentional: log it plainly, then exit so the platform's process
// manager restarts us with a clean feed reload (~3s) rather than continuing
// in a possibly-corrupted state.
process.on('uncaughtException', (err) => {
  log('uncaught_exception', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  log('unhandled_rejection', { reason: reason instanceof Error ? reason.message : String(reason) });
  process.exit(1);
});

function shutdown(signal) {
  log('shutdown_signal_received', { signal });
  server.close(() => {
    log('shutdown_complete');
    process.exit(0);
  });
  // Force-exit if connections don't drain in time.
  setTimeout(() => process.exit(1), 5000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
