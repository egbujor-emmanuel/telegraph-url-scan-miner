// Protocol-level signals that need no third-party API key: DNS resolution,
// TLS certificate validity, and redirect-chain tracing. Each returns the
// common evidence shape used throughout the engine:
//   { source, available, malicious, suspicious, confidence, reason, latency_ms }
// These never set `malicious: true` on their own — they only ever raise
// `suspicious`, per docs/url-scan-design.md §7 (a bad cert or a weird
// redirect chain isn't proof of malice, just reduced trust).

import dns from 'node:dns/promises';
import tls from 'node:tls';
import { isPrivateHost } from './normalizeUrl.js';

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

export async function checkDns(hostname, { timeoutMs = 3000 } = {}) {
  const start = Date.now();
  try {
    const addresses = await withTimeout(dns.resolve(hostname), timeoutMs, 'dns');
    return {
      source: 'dns',
      available: true,
      malicious: false,
      suspicious: false,
      confidence: 0.3,
      reason: `resolves to ${addresses.length} address(es)`,
      latency_ms: Date.now() - start,
    };
  } catch (err) {
    return {
      source: 'dns',
      available: true, // the lookup itself completed — NXDOMAIN is a real answer
      malicious: false,
      suspicious: true,
      confidence: 0.4,
      reason: `dns resolution failed: ${err.code || err.message}`,
      latency_ms: Date.now() - start,
    };
  }
}

export async function checkTls(hostname, { timeoutMs = 4000 } = {}) {
  const start = Date.now();
  if (isPrivateHost(hostname)) {
    return {
      source: 'tls',
      available: false,
      malicious: false,
      suspicious: false,
      confidence: 0,
      reason: 'skipped: private host',
      latency_ms: Date.now() - start,
    };
  }
  const socketPromise = new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, timeout: timeoutMs },
      () => {
        const authorized = socket.authorized;
        const cert = socket.getPeerCertificate();
        const now = Date.now();
        const expired = cert && cert.valid_to ? new Date(cert.valid_to).getTime() < now : true;
        socket.end();
        if (authorized && !expired) {
          resolve({
            source: 'tls',
            available: true,
            malicious: false,
            suspicious: false,
            confidence: 0.3,
            reason: 'valid certificate chain',
            latency_ms: Date.now() - start,
          });
        } else {
          resolve({
            source: 'tls',
            available: true,
            malicious: false,
            suspicious: true,
            confidence: 0.5,
            reason: authorized ? 'certificate expired' : `certificate not trusted: ${socket.authorizationError}`,
            latency_ms: Date.now() - start,
          });
        }
      },
    );
    socket.on('error', (err) => {
      resolve({
        source: 'tls',
        available: true,
        malicious: false,
        suspicious: true,
        confidence: 0.3,
        reason: `tls connection failed: ${err.message}`,
        latency_ms: Date.now() - start,
      });
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        source: 'tls',
        available: false,
        malicious: false,
        suspicious: false,
        confidence: 0,
        reason: 'tls handshake timed out',
        latency_ms: Date.now() - start,
      });
    });
  });

  // Backstop: the socket promise is designed to always resolve via one of
  // its own handlers, but if the OS-level connection attempt hangs without
  // ever firing connect/error/timeout, withTimeout's race will reject —
  // caught here so checkTls always resolves, never throws.
  try {
    return await withTimeout(socketPromise, timeoutMs + 500, 'tls');
  } catch (err) {
    return {
      source: 'tls',
      available: false,
      malicious: false,
      suspicious: false,
      confidence: 0,
      reason: `tls check failed: ${err.message}`,
      latency_ms: Date.now() - start,
    };
  }
}

const MAX_REDIRECTS = 5;

export async function checkRedirectChain(startUrl, { timeoutMs = 5000 } = {}) {
  const start = Date.now();
  let current = startUrl;
  let hops = 0;
  let leftOriginalDomain = false;
  const originalHost = new URL(startUrl).hostname;

  try {
    while (hops < MAX_REDIRECTS) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      let res;
      try {
        res = await fetch(current, {
          method: 'HEAD',
          redirect: 'manual',
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timer);
      }

      if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
        const next = new URL(res.headers.get('location'), current).toString();
        if (isPrivateHost(new URL(next).hostname)) {
          return {
            source: 'redirect',
            available: true,
            malicious: false,
            suspicious: true,
            confidence: 0.6,
            reason: 'redirect chain targets a private/internal host',
            latency_ms: Date.now() - start,
          };
        }
        if (new URL(next).hostname !== originalHost) leftOriginalDomain = true;
        current = next;
        hops += 1;
        continue;
      }
      break;
    }

    return {
      source: 'redirect',
      available: true,
      malicious: false,
      suspicious: hops >= 2 && leftOriginalDomain,
      confidence: hops === 0 ? 0.2 : 0.4,
      reason: hops === 0 ? 'no redirects' : `${hops} redirect(s)${leftOriginalDomain ? ', left original domain' : ''}`,
      latency_ms: Date.now() - start,
    };
  } catch (err) {
    return {
      source: 'redirect',
      available: false,
      malicious: false,
      suspicious: false,
      confidence: 0,
      reason: `redirect trace failed: ${err.message}`,
      latency_ms: Date.now() - start,
    };
  }
}
