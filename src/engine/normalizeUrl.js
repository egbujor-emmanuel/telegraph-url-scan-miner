// Parses and validates a submitted URL, rejecting anything malformed or
// pointed at a private/internal network before any outbound call is made
// (SSRF guard — see docs/url-scan-design.md §10).

const PRIVATE_IPV4_RANGES = [
  { base: [10, 0, 0, 0], mask: 8 },
  { base: [172, 16, 0, 0], mask: 12 },
  { base: [192, 168, 0, 0], mask: 16 },
  { base: [127, 0, 0, 0], mask: 8 },
  { base: [169, 254, 0, 0], mask: 16 }, // link-local, incl. cloud metadata endpoints
  { base: [0, 0, 0, 0], mask: 8 },
];

function ipv4ToInt(parts) {
  return parts.reduce((acc, p) => (acc << 8) + p, 0) >>> 0;
}

export function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return false;
  }
  const ipInt = ipv4ToInt(parts);
  return PRIVATE_IPV4_RANGES.some(({ base, mask }) => {
    const baseInt = ipv4ToInt(base);
    const maskInt = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
    return (ipInt & maskInt) === (baseInt & maskInt);
  });
}

export function isPrivateIPv6(ip) {
  const lower = ip.toLowerCase();
  return (
    lower === '::1' ||
    lower.startsWith('fe80:') || // link-local
    lower.startsWith('fc') ||
    lower.startsWith('fd') // unique local
  );
}

export function isPrivateHost(hostname) {
  if (hostname === 'localhost') return true;
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    return isPrivateIPv4(hostname);
  }
  if (hostname.includes(':')) {
    return isPrivateIPv6(hostname);
  }
  return false;
}

/**
 * @param {string} rawUrl
 * @returns {{ ok: true, url: URL, normalized: string } | { ok: false, reason: string }}
 */
export function normalizeUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.trim().length === 0) {
    return { ok: false, reason: 'empty or non-string url' };
  }

  let parsed;
  try {
    // Bare "example.com" (no scheme) is a common real-world input — try as-is
    // first, then retry with an https:// prefix before giving up.
    parsed = new URL(rawUrl);
  } catch {
    try {
      parsed = new URL(`https://${rawUrl}`);
    } catch {
      return { ok: false, reason: 'unparseable url' };
    }
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { ok: false, reason: `unsupported scheme: ${parsed.protocol}` };
  }

  if (isPrivateHost(parsed.hostname)) {
    return { ok: false, reason: 'private/internal host not allowed' };
  }

  // Canonical form: lowercase host, strip default port, strip fragment.
  const port =
    (parsed.protocol === 'https:' && parsed.port === '443') ||
    (parsed.protocol === 'http:' && parsed.port === '80')
      ? ''
      : parsed.port;

  const normalized =
    `${parsed.protocol}//${parsed.hostname.toLowerCase()}` +
    (port ? `:${port}` : '') +
    parsed.pathname +
    parsed.search;

  return { ok: true, url: parsed, normalized };
}
