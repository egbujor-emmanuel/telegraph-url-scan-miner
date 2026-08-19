// REAL INTEGRATION TEST — spawns the actual server as a child process and
// hits it over real HTTP on localhost. Not a mock of the server; the real
// entrypoint (src/server/index.js), the real Express app, the real error
// handler. URLhaus feed calls are real network calls to the live feed.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';

const PORT = 8099;
const BASE = `http://localhost:${PORT}`;
let child;

before(async () => {
  child = spawn('node', ['src/server/index.js'], {
    env: { ...process.env, PORT: String(PORT) },
    stdio: 'pipe',
  });

  // Poll /health until the process is actually accepting connections,
  // rather than a fixed sleep (flaky under real, variable startup timing).
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE}/health`);
      if (res.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error('server did not become healthy within 15s');
});

after(() => {
  child.kill();
});

test('GET /health returns 200 with real status shape', async () => {
  const res = await fetch(`${BASE}/health`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(['ok', 'degraded'].includes(body.status));
  assert.equal(typeof body.uptime_ms, 'number');
  assert.equal(typeof body.urlhaus_feed.loaded, 'boolean');
});

test('malformed JSON body returns clean 400, not a stack trace', async () => {
  const res = await fetch(`${BASE}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{not valid json',
  });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.verdict, 'unknown');
  assert.equal(body.confidence, 0);
  assert.match(body.reason, /json/i);
});

test('missing Content-Type header does not crash the server', async () => {
  const res = await fetch(`${BASE}/scan`, {
    method: 'POST',
    body: JSON.stringify({ url: 'https://example.com' }),
  });
  // express.json() only parses application/json — without the header,
  // req.body is undefined. Must degrade to "unknown", not 500.
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.verdict, 'unknown');
});

test('valid real request against a real known-safe domain', async () => {
  const res = await fetch(`${BASE}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com' }),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(['safe', 'suspicious', 'unknown'].includes(body.verdict));
  assert.equal(typeof body.confidence, 'number');
});

test('server survives a burst of concurrent requests without crashing', async () => {
  const urls = ['https://example.com', 'https://wikipedia.org', 'not a url', 'https://github.com'];
  const results = await Promise.all(
    urls.map((url) =>
      fetch(`${BASE}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      }),
    ),
  );
  for (const res of results) assert.equal(res.status, 200);
  // health still responds after the burst — process didn't die
  const health = await fetch(`${BASE}/health`);
  assert.equal(health.status, 200);
});
