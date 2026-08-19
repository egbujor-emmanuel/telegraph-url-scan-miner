// LOCAL TEST — pure config parsing logic, no server, no network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/server/config.js';

test('applies sensible defaults with empty env', () => {
  const config = loadConfig({});
  assert.equal(config.port, 8080);
  assert.equal(config.requestTimeoutMs, 8000);
  assert.equal(config.nodeEnv, 'development');
});

test('parses valid overrides', () => {
  const config = loadConfig({ PORT: '3000', REQUEST_TIMEOUT_MS: '5000', NODE_ENV: 'production' });
  assert.equal(config.port, 3000);
  assert.equal(config.requestTimeoutMs, 5000);
  assert.equal(config.nodeEnv, 'production');
});

test('rejects non-numeric PORT', () => {
  assert.throws(() => loadConfig({ PORT: 'not-a-number' }), /invalid config: PORT/);
});

test('rejects PORT out of valid range', () => {
  assert.throws(() => loadConfig({ PORT: '99999' }), /invalid config: PORT/);
  assert.throws(() => loadConfig({ PORT: '0' }), /invalid config: PORT/);
});

test('rejects unreasonably small REQUEST_TIMEOUT_MS', () => {
  assert.throws(() => loadConfig({ REQUEST_TIMEOUT_MS: '10' }), /invalid config: REQUEST_TIMEOUT_MS/);
});

test('reports optional providers as disabled when keys absent', () => {
  const config = loadConfig({});
  assert.equal(config.optionalProviders.safeBrowsing, false);
  assert.equal(config.optionalProviders.virusTotal, false);
});

test('reports optional providers as enabled when keys present', () => {
  const config = loadConfig({ SAFE_BROWSING_API_KEY: 'x' });
  assert.equal(config.optionalProviders.safeBrowsing, true);
});
