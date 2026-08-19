// REAL EXTERNAL NETWORK CALLS — not a local-only test. Hits real DNS, real
// TLS endpoints, and real HTTP servers on the live internet. Run manually
// (not part of `npm test`) since it depends on external hosts being up.
import { checkDns, checkTls, checkRedirectChain } from '../src/engine/nativeSignals.js';

const cases = [
  { label: 'example.com — known-good domain', host: 'example.com', url: 'https://example.com/' },
  { label: 'github.com — known http->https redirector', host: 'github.com', url: 'http://github.com/' },
  { label: 'nonexistent domain (real NXDOMAIN)', host: 'this-domain-should-not-exist-zzz98765.com', url: 'https://this-domain-should-not-exist-zzz98765.com/' },
];

for (const c of cases) {
  console.log(`\n=== ${c.label} ===`);
  const [dnsResult, tlsResult, redirectResult] = await Promise.all([
    checkDns(c.host),
    checkTls(c.host),
    checkRedirectChain(c.url),
  ]);
  console.log('dns:', JSON.stringify(dnsResult));
  console.log('tls:', JSON.stringify(tlsResult));
  console.log('redirect:', JSON.stringify(redirectResult));
}
