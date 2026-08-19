# URL_SCAN — Phase 1 Design

Builds on [`url-scan-research.md`](./url-scan-research.md) (Phase 0). Not repeating verified facts from there — read that first if anything here seems to assume prior context.

New verification done in Phase 1 (not in Phase 0):

- **Diamond contract address discrepancy resolved on-chain.** `telegraphprotocol/tg-miner-integration`'s README lists Diamond `0xac683bFa8F1C892E23e8300d14c20678C6FC0CA3`, which conflicts with `telegraph-docs`' `0x5a2324aA18613FAD4e44bDF0d6c73Ec1f6D87ff8`. I called both on the live Base Sepolia RPC (`sepolia.base.org`): `0x5a23...` returns `getTreasury()` = `0xffe89e1f0a77c600ad938b57180e5be3e3119f40` (matches the Treasury address independently confirmed via seed-miner fee addresses in Phase 0) and `getCanonicalIntents()` returning exactly 45 entries (matches the live intent count from Phase 0). `0xac68...` returns different values entirely for both calls. **`0x5a2324aA18613FAD4e44bDF0d6c73Ec1f6D87ff8` is confirmed correct; the other address is stale and must not be used.**
- **The `label_field`/`reason_field` → `miner_answer` question remains unresolved.** I checked `tg-miner-integration` (the `integrate.telegraphprotocol.com` source) on GitHub — it's a Next.js frontend whose YAML-validation logic proxies to a private backend (`VALIDATOR_BASE_URL` + `/miner-dispatcher/validate`, gated by an internal secret we don't have). That backend, and the actual node/validator scoring code, are not in any public Telegraph repo. This can only be resolved by observing real scored traffic after registration (Phase 4), not by source inspection or local experiment. Documented as an open risk below, designed around defensively.

---

## 1. Architecture

```
Telegraph node (HTTP call per our YAML endpoint declaration)
        ↓
POST /scan  { "url": "..." }
        ↓
[normalize] → canonicalize URL, reject malformed input early
        ↓
[gather]    → concurrent, independent, timeout-bounded:
                - URLhaus lookup (malware/phishing feed)
                - DNS resolution + basic domain signals
                - TLS certificate inspection
                - redirect-chain trace (bounded hops)
                - (optional, env-gated) Safe Browsing / VirusTotal
        ↓
[normalize evidence] → each signal source → common shape:
                { source, available, malicious, suspicious, confidence, reason, latency_ms }
        ↓
[verdict engine] → deterministic rules over normalized evidence → verdict + confidence + reason
        ↓
{ "verdict": "safe"|"suspicious"|"malicious"|"unknown", "confidence": 0-1, "reason": "..." }
        ↓
Telegraph validators (ground truth scraped independently, scored against our response)
```

Single HTTP service, no queue, no database required for correctness (only optional in-memory cache). This matches "keep the architecture simple enough to debug" — nothing here needs infrastructure beyond one deployable process.

## 2. Exact Telegraph interface

Per Phase 0 §2/3/4: there is no fixed schema Telegraph imposes — we define our own, declared in YAML, and Telegraph reads it via `signal_mapping`. Chosen:

- **Method/path:** `POST /scan`
- **Content-Type:** `application/json`
- **Auth:** none (open endpoint — matches the reference pattern in every existing URL_SCAN miner)

## 3. Request schema

```json
{ "url": "https://example.com/path" }
```

`url` is the only field, required, string. Matches what all three existing seed URL_SCAN miners expect and what the intent description itself implies ("Query supplies a URL").

## 4. Response schema

```json
{
  "verdict": "safe",
  "confidence": 0.92,
  "reason": "No malicious signals across 3 independent sources; valid TLS certificate; no redirect chain."
}
```

- `verdict`: exactly one of `"safe"`, `"suspicious"`, `"malicious"`, `"unknown"`. `"unknown"` is used, not fabricated as `"safe"`, when evidence is genuinely insufficient (e.g., every provider failed/timed out) — see §8.
- `confidence`: 0.0–1.0.
- `reason`: short, plain-text, human-readable. Deliberately concise (not a full evidence dump) given the unresolved risk that `reason_field` text might get concatenated into whatever string the scorer compares — a short, clean sentence is safer than a verbose evidence log under either possible scoring behavior.

`label_field: verdict`, `confidence_field: confidence`, `reason_field: reason` — chosen specifically so the single most important token (the verdict word) lives in its own field, isolated from prose, regardless of how the scorer assembles `miner_answer`.

## 5. YAML configuration design

Full draft written to [`config/miner.yaml`](../config/miner.yaml) — real file, schema-checked against `telegraph-docs/miners/yaml-config.md` field-by-field (every key used is in the verified field reference; nothing invented). Two things intentionally **not real yet**, called out in the file's header comment: `base_url` is a placeholder pending Phase 2 deployment, and `id: 5001` is a self-chosen value (per the docs, this field is ours to pick — it isn't issued by Telegraph — but it isn't a registration ID and doesn't mean anything until we actually register).

No `on_chain` block: that's only needed for ERC-8183 job routing / on-chain-triggered calls, which isn't required for a Miner to serve ordinary HTTP/x402 traffic. Adding it later is a non-breaking YAML update if we want on-chain-job compatibility after Track 1 is stable.

## 6. Provider selection

Real, current findings — not carried over from any prior assumption:

| Provider | Key required | Real limits (verified) | Verdict |
|---|---|---|---|
| **URLhaus** (abuse.ch) | Yes, free, self-serve at `auth.abuse.ch` — **registration currently open** | No documented rate limit found | **Use — primary provider** |
| **PhishTank** | Yes | N/A | **Excluded** — PhishTank (now Cisco Talos) closed new user registration in 2020 and it remains closed in 2026. We cannot obtain a key. The existing seed miner using it was presumably grandfathered in before 2020; we have no path to replicate that. |
| **Google Safe Browsing v4** | Yes, free | No cost, quota-based (exact numeric quota not published, adjustable in Google Cloud Console) | **Optional, gated** — see licensing note below |
| **VirusTotal Public API** | Yes, free | 4 requests/minute, 500/day (documented) | **Optional, gated** — same licensing note, and the existing seed miner's own description already flags this exact restriction |

**Real licensing tension, not hand-waved:** both Google Safe Browsing v4 ("for non-commercial use only") and VirusTotal's Public API ("must not be used in commercial products or services") explicitly restrict free-tier use to non-commercial purposes. A Telegraph Miner earns MACHINA per served request — whether that makes a hackathon URL_SCAN miner "commercial" under either provider's terms is a real, unresolved question, not something I'm going to silently decide for you. My recommendation: **build the engine so it works correctly on URLhaus + native signals alone**, and treat Safe Browsing/VirusTotal as optional, environment-gated bonus signals you can consciously choose to enable — the `.env.example` comments carry this same warning at the point where you'd add the key.

**No-key native signals** (no provider ToS risk at all, since they're just protocol-level lookups, not a vendor's proprietary database):
- **DNS resolution** — does the domain resolve at all; how many/which record types.
- **TLS certificate inspection** — valid cert, matches hostname, not expired, not self-signed.
- **Redirect-chain trace** — how many hops, whether it leaves the original domain, whether it terminates.

These three cost nothing, need no key, and can't hit a rate limit that matters at hackathon volume, so they're always-on.

## 7. Deterministic verdict logic

Explicit rule table, evaluated in this order (first match wins):

| Condition | Verdict | Confidence |
|---|---|---|
| URL fails to parse / is malformed | `unknown` | 0.0 |
| URLhaus reports the exact URL as an active, listed threat | `malicious` | 0.95 |
| ≥2 independent sources report malicious (from: URLhaus, Safe Browsing, VirusTotal-if-enabled) | `malicious` | 0.9 |
| Exactly 1 source reports malicious, and it's a high-confidence source (URLhaus exact-URL match, not just domain-level) | `malicious` | 0.75 |
| Any source reports suspicious (but none report malicious), OR redirect chain leaves the original domain ≥2 times, OR TLS certificate is invalid/expired/mismatched | `suspicious` | 0.6 |
| No malicious/suspicious signals from any source that responded, AND at least one source responded | `safe` | scaled by how many of the available sources actually responded (fewer responding sources → lower confidence, e.g. 1 of 3 responding caps confidence at ~0.5; all 3 responding allows up to ~0.9) |
| Every source failed/timed out — no evidence at all | `unknown` | 0.0 |

This directly targets the false-positive/false-negative concerns from your brief: a single low-confidence signal never triggers `malicious` on its own (avoids false positives from one flaky source), but any real listed-threat match from URLhaus is enough by itself (avoids false negatives on a known-bad URL just because other providers are disabled/down). `unknown` is a real, distinct output — used instead of silently defaulting to `safe`, which would be fabricating a positive result from missing evidence (explicitly forbidden in your brief).

**Explicitly not using an LLM anywhere in this decision.** The intent is Tier A/Deterministic; every rule above is a fixed, reproducible function of the normalized evidence. Given the same evidence, the same input always produces the same output — this matters for the spot-check mechanism in Phase 0 (§ scoring), which can revoke routing if a miner's score drops relative to its own history.

## 8. Error handling

- **Malformed URL** → `unknown`, 0.0 confidence, HTTP 200 (not a 4xx — Telegraph's node is calling our declared endpoint per our own schema; a scoring-relevant "I don't know" is a valid answer, not a protocol error).
- **One provider fails/times out** → excluded from evidence, verdict engine proceeds with whatever responded (§7's "safe" row explicitly scales confidence down as fewer sources respond, rather than either failing the whole request or silently treating a missing source as "clean").
- **All providers fail** → `unknown`, 0.0 confidence. Never fabricate `safe` from an absence of evidence.
- **Unexpected exception anywhere in the pipeline** → caught at the top level, logged with a request-scoped ID, responds `unknown`/0.0/"internal error" rather than crashing the process or hanging past the timeout.

## 9. Caching strategy

`cache_ttl_sec: 0` in the YAML draft — **no caching in the v1 design.** Reasoning: URL_SCAN is Tier A/Deterministic and the whole point is a fresh, current safety verdict; a URL can go from clean to actively malicious within minutes (that's exactly the case URLhaus exists to catch), and Telegraph's own spot-check mechanism re-queries miners continuously — serving a stale cached verdict risks being caught disagreeing with fresh ground truth on a spot check, which is scored against us. If latency becomes a measured problem after Phase 4 (real evidence, not a guess), a short (e.g. 60–120s) cache keyed on normalized URL is the first thing to add — deferred until there's a real number showing it's needed, per your Part 6 instruction not to optimize prematurely.

## 10. Security considerations

- No secrets in source or in the YAML — every provider key is `env_var`-referenced only, consistent with the verified auth block schema.
- Outbound requests to arbitrary user-supplied URLs are a real SSRF-adjacent risk (someone could ask us to "scan" `http://169.254.169.254/...` or an internal address) — the design must resolve and reject requests targeting private/link-local/loopback IP ranges before making any outbound connection tied to the submitted URL (applies to our own redirect-chain trace and TLS check, which are the two things in this design that actually connect to the target).
- Provider API keys are read from environment variables at process start, never logged.
- The two ToS-restricted providers (§6) are opt-in via presence of their env var, not on by default — reduces the chance of silently violating a provider's terms.

## 11. Local testing strategy

Distinguishing, per your explicit instruction, **local test cases** (inputs we chose, run against our own code and real provider APIs) from **real ground truth** (Telegraph's, which we don't have access to and can't fabricate). Corpus categories for local tests, each clearly labeled as a local test case, not a claim about what Telegraph will say:

1. Known-safe major domains (e.g. a handful of well-established sites) — expect `safe`.
2. A currently-listed URLhaus entry (pulled live from URLhaus's own recent-threats feed at test time, not hardcoded, since threat URLs age out) — expect `malicious`.
3. A domain with an expired/self-signed TLS cert — expect at least `suspicious`.
4. Malformed strings (`"not a url"`, empty string, `javascript:...`) — expect `unknown`, 0.0.
5. A URL with a multi-hop redirect chain leaving the original domain — expect `suspicious` or lower confidence.
6. Non-existent/NXDOMAIN domain — expect `unknown` or low-confidence `safe`/`suspicious` depending on whether "doesn't exist" itself is evidence (open design question, resolved in Phase 2 with a real rule, not guessed here).
7. Simulated provider timeout (achievable locally by pointing the provider client at an unroutable address/short timeout in a test harness — not by asserting against Telegraph) — expect graceful degradation, not a crash.
8. Internationalized domain name (IDN/punycode) — expect correct normalization, not a parse failure.
9. Same URL requested twice in a row — expect identical output (determinism check).

## 12. Telegraph integration testing strategy

Deferred to Phase 4 by design (Phase 1 explicitly forbids registering or deploying). What Phase 4 will actually check, using real evidence only:

1. Register the miner (real transaction, real `registrationId`, recorded — not invented).
2. Poll `GET /api/miners/<registrationId>` until `activation_status: active` (or capture and report the real rejection reason if not).
3. Confirm we appear in `GET /api/miners?intent=URL_SCAN`.
4. Attempt a real call — either by funding a wallet and using `POST /engine/v1/ask/{minerId}` (x402 payment required, per Phase 0 §5), or by waiting for organic routed traffic during the grace period.
5. Watch `"scored"` flip to `true` (or stay `false`, and report that plainly) and any leaderboard/score field that becomes visible.

**Part 10 (competitive testing against the existing seed miners over the live network) cannot be done right now.** Calling another miner through `/engine/v1/ask/{minerId}` requires a real x402 USDC payment on Base Sepolia, which requires a funded wallet — we don't have one yet (that's a Phase 2/4 prerequisite, not something Phase 1 design needs). Stating this plainly rather than skipping it silently or faking a comparison: **no competitive benchmarking against the seed miners has been performed.** If you want this done before Phase 2, it just needs a Base Sepolia wallet funded with testnet ETH + USDC (Circle faucet, per Phase 0's troubleshooting notes) — say the word and I'll do it as its own step.

## 13. Deployment architecture

Not finalized in Phase 1 (Phase 1 explicitly forbids deploying), but the constraint shaping Phase 2's choice: `base_url` in the YAML must be a **stable, public HTTPS URL** that stays reachable for the life of the registration (the node re-fetches YAML and calls our endpoint on-demand; an unreachable miner gets `activation_status: unreachable` and, per Phase 0's troubleshooting doc, is eventually deregistered/superseded). Any platform that gives us a persistent HTTPS URL without our own machine needing to stay on works (e.g., a small always-on container host or serverless platform with no cold-start-induced timeout risk, given URL_SCAN calls chain multiple outbound provider calls). Concrete platform choice deferred to Phase 2.

## 14. Environment variables required

All declared in [`.env.example`](../.env.example) — real file, no secrets:

| Variable | Required? | Source |
|---|---|---|
| `URLHAUS_AUTH_KEY` | Yes (primary provider) | Free, self-serve at `auth.abuse.ch` — registration currently open |
| `SAFE_BROWSING_API_KEY` | No — optional, gated | Google Cloud Console; non-commercial ToS caveat noted inline |
| `VIRUSTOTAL_API_KEY` | No — optional, gated | virustotal.com free signup; same ToS caveat |
| `PORT`, `NODE_ENV`, `LOG_LEVEL`, `REQUEST_TIMEOUT_MS` | Operational, have safe defaults | N/A |

**Stopping point, per your explicit instruction:** we do not yet have a real `URLHAUS_AUTH_KEY`. I have not fabricated one, and Phase 2 implementation of the URLhaus provider client cannot be *tested against the real API* until you (or I, with your go-ahead) register at `auth.abuse.ch` and put the real key in a local `.env`. Everything else in this design can proceed without it (verdict engine logic, native DNS/TLS/redirect signals, request/response handling, tests for the parts that don't need URLhaus specifically).

## 15. Remaining unknowns

Carried forward honestly, not resolved by guessing:

1. **How `label_field`/`reason_field` become the scorer's `miner_answer` string.** Unresolvable from any public source (§ above). Designed around by keeping `verdict` a single clean token and `reason` short.
2. **What ground-truth source is whitelisted for URL_SCAN**, and what the actual active (fallback/default) Canonical Script rewards. Only observable after real scored traffic.
3. **Whether seed miners count toward the "≥3 active miners" prize guardrail** the way the rules intend.
4. **No competitive benchmarking against the existing seed miners performed** — blocked on a funded wallet, not attempted, not faked (§12).
5. **NXDOMAIN handling** — is a non-existent domain itself evidence of maliciousness (many phishing domains are short-lived) or just "unknown"? Real design decision deferred to Phase 2 with an explicit, documented rule rather than an implicit guess here.

## 16. Exact Phase 2 implementation plan

1. `src/engine/normalizeUrl.js` — parsing, IDN/punycode handling, private-IP-range rejection (security requirement from §10).
2. `src/providers/urlhaus.js` — real client against `urlhaus-api.abuse.ch`, normalized to the common evidence shape. Blocked on real `URLHAUS_AUTH_KEY` for live testing (§14).
3. `src/engine/nativeSignals.js` — DNS resolution, TLS certificate check, redirect-chain trace. No external key needed; can be built and tested immediately.
4. `src/providers/safeBrowsing.js`, `src/providers/virustotal.js` — built but disabled unless their env var is present (§6/§10).
5. `src/engine/verdictEngine.js` — implements the exact rule table in §7, pure function over normalized evidence (easiest thing in this system to unit-test deterministically).
6. `src/server/routes.js` — the `POST /scan` handler: timeout-bound concurrent provider calls, error handling per §8, JSON response per §4.
7. `test/` — the local corpus from §11, clearly labeled as local, not Telegraph validation.
8. Health check endpoint (`GET /health`) for the deployment platform, not part of the Telegraph interface itself.

No Track 2 work, no registration, no deployment — all explicitly out of scope until Track 1 is real and stable, per your instructions.

---

## Open items needing your input before/during Phase 2

- Do you want me to set up and fund a Base Sepolia test wallet now, to unblock competitive testing (§12) before writing more code? Or proceed straight to Phase 2 implementation and revisit this at Phase 4 registration time?
- Register at `auth.abuse.ch` for the URLhaus key yourself, or do you want me to walk you through it live?
- Decision on Safe Browsing / VirusTotal: leave them off by default per this design's recommendation, or do you want to make an explicit call on the non-commercial ToS question first?
