// Startup config validation — fail fast with a clear message rather than
// limping along on a bad value (e.g. a non-numeric PORT silently becoming
// NaN and Express binding to a nonsensical port).

function requireNumber(name, raw, { min = -Infinity, max = Infinity } = {}) {
  const n = Number(raw);
  if (!Number.isFinite(n) || n < min || n > max) {
    throw new Error(`invalid config: ${name}=${JSON.stringify(raw)} must be a number in [${min}, ${max}]`);
  }
  return n;
}

export function loadConfig(env = process.env) {
  const config = {
    port: requireNumber('PORT', env.PORT ?? 8080, { min: 1, max: 65535 }),
    requestTimeoutMs: requireNumber('REQUEST_TIMEOUT_MS', env.REQUEST_TIMEOUT_MS ?? 8000, { min: 1000, max: 60000 }),
    nodeEnv: env.NODE_ENV || 'development',
    logLevel: env.LOG_LEVEL || 'info',
    optionalProviders: {
      safeBrowsing: Boolean(env.SAFE_BROWSING_API_KEY),
      virusTotal: Boolean(env.VIRUSTOTAL_API_KEY),
      urlhausApiKey: Boolean(env.URLHAUS_AUTH_KEY),
    },
  };
  return config;
}
