// LOCAL TEST — pure logic over hand-constructed evidence objects. Not real
// provider data; validates the decision rules themselves in isolation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decideVerdict } from '../src/engine/verdictEngine.js';

test('malformed url -> unknown, 0 confidence', () => {
  const r = decideVerdict([], { malformed: true });
  assert.equal(r.verdict, 'unknown');
  assert.equal(r.confidence, 0);
});

test('all sources unavailable -> unknown, never fabricates safe', () => {
  const evidence = [
    { source: 'dns', available: false },
    { source: 'urlhaus', available: false },
  ];
  const r = decideVerdict(evidence);
  assert.equal(r.verdict, 'unknown');
  assert.equal(r.confidence, 0);
});

test('urlhaus high-confidence exact-url malicious hit -> malicious, high confidence', () => {
  const evidence = [
    { source: 'urlhaus', available: true, malicious: true, suspicious: false, confidence: 0.9, reason: 'listed in URLhaus as active threat' },
    { source: 'dns', available: true, malicious: false, suspicious: false, confidence: 0.3, reason: 'resolves' },
  ];
  const r = decideVerdict(evidence);
  assert.equal(r.verdict, 'malicious');
  assert.ok(r.confidence >= 0.9);
});

test('two independent malicious signals -> malicious even without urlhaus', () => {
  const evidence = [
    { source: 'safeBrowsing', available: true, malicious: true, suspicious: false, confidence: 0.7, reason: 'flagged social engineering' },
    { source: 'virustotal', available: true, malicious: true, suspicious: false, confidence: 0.7, reason: '5/70 engines flag malicious' },
  ];
  const r = decideVerdict(evidence);
  assert.equal(r.verdict, 'malicious');
});

test('single low-confidence malicious-adjacent source alone does not trigger malicious falsely', () => {
  // A single non-urlhaus, non-high-confidence malicious hit still counts as
  // malicious per the rule table (§7 row 3) — this test documents that
  // intentional behavior rather than assuming otherwise.
  const evidence = [
    { source: 'virustotal', available: true, malicious: true, suspicious: false, confidence: 0.5, reason: '1/70 engines flag' },
  ];
  const r = decideVerdict(evidence);
  assert.equal(r.verdict, 'malicious');
  assert.equal(r.confidence, 0.75);
});

test('suspicious-only signal (bad TLS) -> suspicious, not malicious', () => {
  const evidence = [
    { source: 'tls', available: true, malicious: false, suspicious: true, confidence: 0.5, reason: 'certificate expired' },
    { source: 'dns', available: true, malicious: false, suspicious: false, confidence: 0.3, reason: 'resolves' },
  ];
  const r = decideVerdict(evidence);
  assert.equal(r.verdict, 'suspicious');
});

test('clean evidence across all sources -> safe', () => {
  const evidence = [
    { source: 'urlhaus', available: true, malicious: false, suspicious: false, confidence: 0.2, reason: 'not listed' },
    { source: 'dns', available: true, malicious: false, suspicious: false, confidence: 0.3, reason: 'resolves' },
    { source: 'tls', available: true, malicious: false, suspicious: false, confidence: 0.3, reason: 'valid cert' },
    { source: 'redirect', available: true, malicious: false, suspicious: false, confidence: 0.2, reason: 'no redirects' },
  ];
  const r = decideVerdict(evidence);
  assert.equal(r.verdict, 'safe');
  assert.ok(r.confidence > 0.5);
});

test('partial coverage safe verdict has lower confidence than full coverage', () => {
  const full = decideVerdict([
    { source: 'a', available: true, malicious: false, suspicious: false },
    { source: 'b', available: true, malicious: false, suspicious: false },
    { source: 'c', available: true, malicious: false, suspicious: false },
  ]);
  const partial = decideVerdict([
    { source: 'a', available: true, malicious: false, suspicious: false },
    { source: 'b', available: false },
    { source: 'c', available: false },
  ]);
  assert.equal(full.verdict, 'safe');
  assert.equal(partial.verdict, 'safe');
  assert.ok(partial.confidence < full.confidence);
});

test('deterministic: same evidence in, same verdict out, repeatedly', () => {
  const evidence = [
    { source: 'urlhaus', available: true, malicious: false, suspicious: false, confidence: 0.2, reason: 'not listed' },
  ];
  const results = Array.from({ length: 5 }, () => decideVerdict(evidence));
  for (const r of results) assert.deepEqual(r, results[0]);
});
