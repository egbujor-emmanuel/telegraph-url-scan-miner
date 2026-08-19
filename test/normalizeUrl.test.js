// LOCAL TEST — pure logic, no network calls, no external data.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeUrl, isPrivateIPv4 } from '../src/engine/normalizeUrl.js';

test('accepts a well-formed https url', () => {
  const r = normalizeUrl('https://example.com/path?x=1');
  assert.equal(r.ok, true);
  assert.equal(r.normalized, 'https://example.com/path?x=1');
});

test('lowercases the hostname', () => {
  const r = normalizeUrl('https://EXAMPLE.com/');
  assert.equal(r.ok, true);
  assert.equal(r.normalized, 'https://example.com/');
});

test('strips default https port', () => {
  const r = normalizeUrl('https://example.com:443/');
  assert.equal(r.ok, true);
  assert.equal(r.normalized, 'https://example.com/');
});

test('accepts a bare domain with no scheme', () => {
  const r = normalizeUrl('example.com');
  assert.equal(r.ok, true);
  assert.equal(r.normalized, 'https://example.com/');
});

test('rejects empty string', () => {
  const r = normalizeUrl('');
  assert.equal(r.ok, false);
});

test('rejects garbage input', () => {
  const r = normalizeUrl('not a url at all!!!');
  assert.equal(r.ok, false);
});

test('rejects javascript: scheme', () => {
  const r = normalizeUrl('javascript:alert(1)');
  assert.equal(r.ok, false);
});

test('rejects loopback IP (SSRF guard)', () => {
  const r = normalizeUrl('http://127.0.0.1/admin');
  assert.equal(r.ok, false);
  assert.match(r.reason, /private/);
});

test('rejects link-local / cloud metadata IP (SSRF guard)', () => {
  const r = normalizeUrl('http://169.254.169.254/latest/meta-data/');
  assert.equal(r.ok, false);
});

test('rejects localhost by name', () => {
  const r = normalizeUrl('http://localhost:8080/');
  assert.equal(r.ok, false);
});

test('rejects private 10.x range', () => {
  assert.equal(isPrivateIPv4('10.1.2.3'), true);
});

test('does not flag a real public IP as private', () => {
  assert.equal(isPrivateIPv4('8.8.8.8'), false);
});

test('same input produces identical output (determinism)', () => {
  const a = normalizeUrl('https://Example.com:443/Foo?b=1');
  const b = normalizeUrl('https://Example.com:443/Foo?b=1');
  assert.deepEqual(a, b);
});
