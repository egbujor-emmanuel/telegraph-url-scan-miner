// Deterministic decision engine — implements the exact rule table in
// docs/url-scan-design.md §7. Pure function: same evidence array in, same
// verdict out, every time. No LLM, no randomness, no I/O.

/**
 * @param {Array<{source:string, available:boolean, malicious:boolean, suspicious:boolean, confidence:number, reason:string}>} evidence
 * @param {{ malformed?: boolean }} [opts]
 * @returns {{ verdict: 'safe'|'suspicious'|'malicious'|'unknown', confidence: number, reason: string }}
 */
export function decideVerdict(evidence, opts = {}) {
  if (opts.malformed) {
    return { verdict: 'unknown', confidence: 0, reason: 'malformed or unparseable url' };
  }

  const responded = evidence.filter((e) => e.available);
  if (responded.length === 0) {
    return { verdict: 'unknown', confidence: 0, reason: 'no evidence available: all sources failed or timed out' };
  }

  const maliciousHits = responded.filter((e) => e.malicious);
  const suspiciousHits = responded.filter((e) => e.suspicious);

  // Exact-URL-match sources are stronger evidence than domain-level/heuristic
  // sources (see design §7) — URLhaus reporting the specific submitted URL
  // as an active listed threat is treated as high-confidence on its own.
  const highConfidenceMalicious = maliciousHits.find(
    (e) => e.source === 'urlhaus' && e.confidence >= 0.8,
  );

  if (maliciousHits.length >= 2) {
    const names = maliciousHits.map((e) => e.source).join(', ');
    return { verdict: 'malicious', confidence: 0.9, reason: `flagged malicious by multiple independent sources (${names})` };
  }

  if (highConfidenceMalicious) {
    return { verdict: 'malicious', confidence: 0.95, reason: highConfidenceMalicious.reason };
  }

  if (maliciousHits.length === 1) {
    return { verdict: 'malicious', confidence: 0.75, reason: maliciousHits[0].reason };
  }

  if (suspiciousHits.length > 0) {
    const names = suspiciousHits.map((e) => e.source).join(', ');
    return { verdict: 'suspicious', confidence: 0.6, reason: `elevated-risk signal from: ${names}` };
  }

  // No malicious/suspicious signals from anything that responded.
  const coverage = responded.length / evidence.length;
  const confidence = Math.min(0.9, 0.3 + coverage * 0.6);
  return {
    verdict: 'safe',
    confidence: Number(confidence.toFixed(2)),
    reason: `no malicious or suspicious signals across ${responded.length}/${evidence.length} responding source(s)`,
  };
}
