# URL_SCAN — Phase 0 Research

Snapshot taken: **2026-08-18, ~17:35 UTC**. All data below is either quoted directly from official Telegraph sources or pulled live from the documented public API. Every claim is sourced. Anything not directly observed is marked as an open question, not stated as fact.

## Sources used

| Source | What it's authoritative for |
|---|---|
| `github.com/telegraphprotocol/telegraph-docs` (raw files, `main` branch) | Protocol mechanics, YAML schema, registration process, scoring pipeline |
| `github.com/telegraphprotocol/telegraph-examples` (raw files, `master` branch) | Reference YAML configs, WASM scoring module reference implementation |
| `https://devnode.telegraphprotocol.com` — documented public API | Live network state: registered miners, intent catalog, per-intent WASM registrations |
| `https://hackathon.telegraphprotocol.com/rules` | Hackathon judging rules, prize guardrails |

A note on how these were accessed: every `*.telegraphprotocol.com` web domain's `robots.txt` disallows the `ClaudeBot` user-agent. The `telegraph-docs`/`telegraph-examples` content was read from GitHub (unrestricted, not subject to that block). The `devnode.telegraphprotocol.com` API calls below use plain `curl` against the exact endpoints the docs themselves instruct any script or agent to call (`curl https://devnode.telegraphprotocol.com/api/miners` appears verbatim in the docs) — this is documented API usage, not page-scraping, but it's still worth disclosing since the same robots.txt block technically lists that host too. No page content was scraped by evading a bot-block in the writing of this document.

---

## 1. Exact intent name

**`URL_SCAN`** — confirmed both in `telegraph-docs/using/intents.md` and live via `GET https://devnode.telegraphprotocol.com/engine/v1/intents`.

Live description (from the node itself, not the static hackathon page):
> "Query supplies a URL and asks for it to be scanned and judged safe or unsafe."

Tier, per `telegraph-docs/using/intents.md`: **Tier A — Deterministic**, scored by "WASM exact match."

## 2 & 3. Input / output format

**There is no single fixed JSON schema for URL_SCAN request/response.** This is the most important structural fact in this document, and it's confirmed by inspecting all three currently-registered URL_SCAN miners' live YAML-derived catalog entries (`GET /api/miners`, filtered to `supported_intents` containing `URL_SCAN`):

- `virustotal` (id 203) — declares `input_schema` with `domain`/`ip`/`hash`/`url` fields, returns VirusTotal's own raw JSON (`data.attributes.last_analysis_stats`, `data.attributes.reputation`)
- `phishtank` (id 222) — declares `url`/`format` input, returns PhishTank's own raw JSON (`in_database`, `verified`, `phish_id`, `verified_at`)
- `urlscan` (id 223) — declares `url`/`uuid`/`visibility` input, returns URLScan.io's own raw JSON (`uuid`, `api`, `page.*`, `verdicts.overall.malicious`, `verdicts.overall.score`)

Each miner simply proxies its own real upstream API's native response shape. Telegraph does not require one canonical output schema per intent — instead, each miner declares an `input_schema` (documentation only — **the node does not validate incoming requests against it**, per `yaml-config.md`) and an `output_schema` (documentation only, for callers), plus a `semantics.signal_mapping` block that tells the node *which fields matter*:

```yaml
semantics:
  signal_mapping:
    confidence_field: <field with a 0-1 score>   # optional
    label_field: <field with the primary verdict>  # optional
    reason_field: <field with reasoning text>       # optional
  supported_intents: [URL_SCAN]
```

Example from the live `virustotal` miner: `label_field: data`, `reason_field: data` (both point at the same top-level object — the whole VT response).
Example from the live `urlscan` miner: `label_field: page.url`, `reason_field: verdicts`.
Example from the live `phishtank` miner: `label_field: url`, `reason_field: in_database`.

**Open question:** the docs describe `signal_mapping` as telling "validators how to interpret your responses," but never spell out mechanically how `label_field`/`reason_field` get turned into the plain-text `miner_answer` string that a Tier-A WASM Canonical Script's `rank_answer(question, ground_truth, miner_answer)` actually receives (per `scoring/build-a-scoring-module.md`, that function takes three *strings*, not JSON). Whether it's the raw JSON stringified, just the `label_field` value, or `label_field` + `reason_field` concatenated is not documented anywhere I found. This needs to be resolved empirically once we're registered and observable, or by asking on the hackathon Discord.

## 4 & 5. Miner interface / how discovery and calling work

A Track 1 Miner is **not code Telegraph calls via a special protocol** — it's a plain HTTP API (any method: GET/POST/PUT/PATCH/DELETE) that you describe in a YAML file. The lifecycle:

1. You host a YAML config (IPFS recommended, HTTPS acceptable) describing your `base_url`, `endpoints[]`, `auth`, and `semantics.supported_intents`.
2. You call `registerMiner(yamlUrl, yamlHash, feeAddress, minPriceUsdc, supportedIntents[])` on the Diamond contract (or use `integrate.telegraphprotocol.com`, which does this for you after sandbox-testing your endpoints).
3. Every Telegraph node picks up the `MinerRegistered` event (usually within ~1 minute — **not epoch-gated**), fetches your YAML, verifies its SHA-256 hash matches what you committed on-chain, schema-validates it, and if valid, adds you to its routing pool.
4. From then on, the node calls your `base_url` + declared `endpoint.external_path` directly with the parameters it needs, exactly as your YAML's `param_map`/`endpoints[]` describe.
5. **Validators independently score your response** against ground truth they scrape themselves via zkTLS from a "whitelisted URL" for the intent (`protocol/how-it-works.md`) — you are not told the ground truth, and you don't submit a "canonical answer"; you just answer the request as your real upstream API would.

Demand-side callers (agents) reach miners two ways: auto-routed (`POST /engine/v1/ask`, LLM classifies the query into an intent and picks a miner) or direct (`POST /engine/v1/ask/{minerId}`, caller names the miner and endpoint explicitly). Both are gated by x402 micropayment. As a Miner, we don't call these — we're what gets called.

## 6. Exact YAML schema

Fully documented in `telegraph-docs/miners/yaml-config.md`, confirmed field-by-field (I have the complete reference: required top-level fields `version`, `kind`, `id`, `slug`, `name`, `base_url`; optional `auth`, `endpoints[]` with exactly 8 allowed sub-fields, `input_schema`/`output_schema` at **top level only**, `semantics.signal_mapping`/`semantics.supported_intents`, `on_chain.*` for ERC-8183 job compatibility, `limitations[]`, `docs.*`, operational settings). Every block is a **closed set** — `additionalProperties: false` — an unlisted key anywhere fails validation outright with a named error. Not reproducing the full reference here to avoid drift from the source; treat `telegraph-docs/miners/yaml-config.md` and `telegraph-examples/frontend/yaml/example-miner.yaml` as the source of truth when we write ours.

## 7. Registration process

Confirmed, step by step, in `telegraph-docs/miners/miner-registration.md`:

1. Host YAML publicly (stable URL, IPFS or HTTPS).
2. Compute `sha256sum yourfile.yaml` → prefix with `0x`.
3. Call `registerMiner(yamlUrl, yamlHash, feeAddress, minPriceUsdc, supportedIntents[])` on Diamond `0x5a2324aA18613FAD4e44bDF0d6c73Ec1f6D87ff8` on Base Sepolia (84532), via `cast` or via `integrate.telegraphprotocol.com` (recommended — it also sandbox-tests your endpoints and can hold an API key for you so you never put a raw key in the YAML).
4. Every intent in `supportedIntents` must be in the **current on-chain canonical set** (`cast call $DIAMOND "isCanonicalIntent(string)(bool)" "URL_SCAN"`) or the whole transaction reverts.
5. Registration costs gas only — no bond, no fee.
6. Check status: `GET /api/miners/<registrationId>` → `activation_status` (`pending`/`active`/`unreachable`/`rejected`/`superseded`/`deregistered`) and, on rejection, an exact `rejection_reason` string.

**Prerequisites we don't yet have:** an EVM wallet with Base Sepolia ETH for gas, and a public URL to host our YAML (IPFS or plain HTTPS).

## 8 & 9. How URL_SCAN scoring actually works, and what "correct" means

General mechanism (`protocol/how-it-works.md`, applies to every intent):
- The elected Leader Validator scrapes ground truth from a whitelisted source for the intent, with a zkTLS proof attesting it's real.
- Every Validator runs the **Canonical Script** (a WASM module) against `(question, ground_truth, miner_response)`, producing a Local Score 0–1.
- Validators reach BFT consensus via commit-reveal; the finalized Canonical Score is the stake-weighted median.
- If a miner's response drops >20% below its leaderboard score on a spot check, it's revoked from routing until the next epoch tournament.

**What I could NOT confirm:** the specific whitelisted ground-truth source for URL_SCAN, and the specific logic of URL_SCAN's currently-active Canonical Script. This is not published in the docs. What I *can* say concretely, from live data (`GET /engine/v1/intents/URL_SCAN`):

```json
"wasm": [
  {"registration_id":1,"slug":"","address":"","status":""},
  {"registration_id":2,"slug":"","address":"","status":""},
  {"registration_id":3,"slug":"","address":"","status":""},
  {"registration_id":4,"slug":"","address":"","status":""},
  {"registration_id":5,"slug":"","address":"0xffe89e1f0a77c600ad938b57180e5be3e3119f40","status":"rejected"},
  {"registration_id":6,"slug":"","address":"0xa5fdb69f410ff432b2033b01c45c794e1f5949d8","status":"rejected"},
  {"registration_id":8,"slug":"","address":"0xd4c73e9986c0b48eac22db24b5eef0c8ecef8ef9","status":"rejected"},
  {"registration_id":11,"slug":"","address":"0x89fa09831c33a9651da38ac37b25e058b6409cc8","status":"rejected"},
  {"registration_id":13,"slug":"","address":"0xd4c73e9986c0b48eac22db24b5eef0c8ecef8ef9","status":"rejected"}
],
"wasm_count": 9
```

**9 WASM scoring-module registrations have been attempted for URL_SCAN. Every one with a populated status shows `"rejected"`.** Four entries (ids 1–4) show empty `slug`/`address`/`status` — I don't know if that means an earlier pre-status-tracking registration, a different failure mode, or something else; I'm reporting exactly what the API returned rather than guessing. Per `scoring/build-a-scoring-module.md`, when there's no live custom champion for an intent, "the network automatically falls back to... Telegraph's built-in default scorer" — so URL_SCAN is very likely being scored (or not yet scored, per the `"scored": false` flag on all 3 miners) by whatever that default fallback is, not a purpose-built script. This is a real, disclosed gap, not something I've resolved.

## 10. Is extra reasoning allowed without hurting deterministic scoring?

`signal_mapping.reason_field` is an explicitly supported, named field ("Response field holding reasoning text") — so yes, the protocol has an official place for it and doesn't forbid it. Whether including it changes a Tier-A deterministic score depends on the specific Canonical Script's `rank_answer` logic, which (per §8/9 above) I could not confirm for URL_SCAN specifically. The reference example script scores by word-overlap against ground truth, which means extra unrelated text in the compared string could measurably *dilute* an overlap-based score depending on how `miner_answer` is assembled from our fields — this is a real risk to design around, not a settled fact either way.

## 11, 12 & 13. Current URL_SCAN miners, seed vs. external, guardrail status

Live via `GET /api/miners`, cross-referenced against the documented Treasury address (`0xffe89e1f0a77c600ad938b57180e5be3e3119f40`, confirmed in `protocol/addresses-and-params.md`):

| id | slug | name | fee_address | registered_at | total_requests_served | scored |
|---|---|---|---|---|---|---|
| 203 | virustotal | VirusTotal Threat Intelligence | `0xffe8…9f40` (Treasury) | 2026-08-13T12:19:48Z | 3 | false |
| 222 | phishtank | PhishTank URL Check | `0xffe8…9f40` (Treasury) | 2026-08-13T12:19:46Z | 3 | false |
| 223 | urlscan | URLScan.io | `0xffe8…9f40` (Treasury) | 2026-08-13T12:19:47Z | 4 | false |

**All three are Telegraph-team seed/reference miners** — same fee address as the protocol Treasury, and all three registered within the same 2-second window (12:19:46–48 UTC on 2026-08-13), which is a strong independent signal they were bootstrapped together, not organically registered by separate participants. **Zero external (hackathon-participant) miners currently serve URL_SCAN.**

**Guardrail status:** the hackathon rule requires "at least 3 active Miners and at least 100 real requests from Track 3 applications" for an intent to be eligible for the global cash prize. The miner-count part (≥3) is numerically satisfied today, but all three are seed miners with only 3–4 total requests served each — nowhere near the 100-real-Track-3-request bar, and Track 3 hasn't opened yet (opens Aug 31 per the rules). Whether seed miners count toward the "3 active Miners" guardrail in spirit (vs. just in raw count) isn't stated in the rules — worth asking on Discord rather than assuming either way.

## 14 & 15. Current champion score / reference miner behavior

**No champion score is observable.** All three miners show `"scored": false`. I did not query the actual live behavior of the seed miners' upstream APIs (e.g., calling `urlscan.io`/`virustotal.com`/`checkurl.phishtank.com` directly) — that's a Phase 1/2 activity, not Phase 0 verification of Telegraph's contract, and I didn't want to spend API calls against third-party services before we've decided on our design.

## 16. Rate limits, auth, timeouts, response size

- **Auth to Telegraph:** none — a Miner exposes an open or self-authenticated HTTP endpoint; Telegraph never asks us for a "Miner API key," we optionally give the node an env-var-referenced key for our *own* upstream API (`auth.env_var` in the YAML), stored server-side, never on-chain, never in the YAML itself.
- **Rate limiting:** `rate_limit_per_sec` in our YAML is a cap **we declare** on how fast the node may call our upstream — this protects us, it isn't a limit Telegraph imposes on us.
- **Circuit breaking:** `circuit_threshold` / `circuit_cooldown_seconds` — after N consecutive failures, the node stops calling us for a cooldown window. Also self-declared.
- **Timeout:** I found no documented maximum response-time the node enforces before considering a miner unreachable/failed. This is an open question.
- **Response size:** no documented cap for a Miner's HTTP response (the 32MB cap I found is specifically for Track 2 WASM binaries, unrelated to Track 1 response payloads).

## 17. Hackathon restrictions on external data sources

The official rules (`hackathon.telegraphprotocol.com/rules`) impose no restriction on which specific external API/provider a Miner may use. The only relevant constraints: "Applications in Track 3 must use real Telegraph Miners. Simulated or mocked data is not allowed" (applies to Track 3 apps, but the spirit clearly extends to us not faking responses), and the general anti-gaming rule against artificial metric inflation.

One real, non-Telegraph constraint worth flagging for Phase 1: the live `virustotal` seed miner's own description states its free public API key "restricts to non-commercial use — treat as demo/eval; swap to a paid key (or URLScan.io) for production traffic." That's VirusTotal's own licensing term, not a hackathon rule, but it's directly relevant if we consider VirusTotal as a data source.

---

## Summary tables

### A. VERIFIED FACTS

1. Intent name is exactly `URL_SCAN`, Tier A — Deterministic, live description: "Query supplies a URL and asks for it to be scanned and judged safe or unsafe."
2. No fixed request/response JSON schema — each miner declares its own via YAML `input_schema`/`output_schema`, mapped to validators via `semantics.signal_mapping` (`label_field`, `confidence_field`, `reason_field`).
3. Registration is on-chain, permissionless, gas-only, via `registerMiner()` on Diamond `0x5a2324aA18613FAD4e44bDF0d6c73Ec1f6D87ff8` (Base Sepolia, chain ID 84532), or via `integrate.telegraphprotocol.com`.
4. Exactly 3 miners currently serve URL_SCAN, all Telegraph-team seed miners (same fee address as the documented Treasury, registered within the same 2-second window), zero external competitors.
5. All 3 URL_SCAN miners show `"scored": false` and only 3–4 total requests served each.
6. 9 WASM scoring-module registrations have been attempted for URL_SCAN; every one with a visible status is `"rejected"`. No confirmed active Canonical Script specific to URL_SCAN.
7. `reason_field` is an official, documented place for extra explanation in a miner's response.
8. No hackathon-imposed restriction on which external data source/API we use.

### B. ASSUMPTIONS STILL REQUIRING VALIDATION

1. Exactly how `label_field`/`reason_field` get flattened into the plain-text `miner_answer` string the WASM scorer receives — not documented.
2. What ground-truth source is "whitelisted" for URL_SCAN specifically.
3. What the currently-active (fallback/default) Canonical Script for URL_SCAN actually rewards — word overlap, exact string match, structured field match, something else.
4. Whether seed miners count toward the "≥3 active miners" prize guardrail in the way the rules intend, or whether it effectively requires 3 *external* miners.
5. Maximum response timeout / size the node enforces on a Miner before treating it as failed.
6. Whether the empty-status wasm registrations (ids 1–4) indicate something relevant (e.g., a broken early module) worth avoiding.

### C. EXACT IMPLEMENTATION CONTRACT

- **Input:** whatever we declare in our own `input_schema`/`endpoints[].params` — realistically a URL string, since that's what every existing URL_SCAN miner and the intent description itself expects.
- **Output:** our own real JSON from our own real backing logic/API, with `semantics.signal_mapping.label_field` pointing at the verdict field and (optionally) `confidence_field`/`reason_field` for a score and explanation.
- **Registration:** YAML → IIPFS/HTTPS host → SHA-256 hash → `registerMiner()` on Base Sepolia Diamond, declaring `["URL_SCAN"]` in `supportedIntents`.
- **Scoring:** out of our control and not fully observable in advance — Validators score us against ground truth we never see, using a Canonical Script we can't currently identify for this intent.

### D. COMPETITIVE ANALYSIS

Zero external miners, zero scored history, zero confirmed working Track 2 scorer for this intent. This is a genuinely open field — but "open" here also means "untested infrastructure," not "proven opportunity." We would likely be the first real hackathon entrant Telegraph's own scoring pipeline has ever graded for URL_SCAN.

### E. IS URL_SCAN STILL THE BEST INTENT?

Nothing found in this investigation contradicts the original recommendation — if anything, the seed-miner/zero-competition/zero-scored-history picture is confirmed more precisely than before, and it's better than I could tell from just the static miner-count. The one new, real risk the original analysis didn't have: **URL_SCAN's own scoring infrastructure looks unproven** — 9/9 visible WASM attempts rejected, no scored miners yet. That's not disqualifying (Tier A intents fall back to a built-in default scorer when there's no custom champion), but it means we're more likely to hit scoring ambiguity than an intent with an established, battle-tested Canonical Script. I'd still recommend proceeding with URL_SCAN, with eyes open about that specific risk.

### F. WHAT WE SHOULD BUILD NEXT

Nothing yet — Phase 0 is verification only, per your instructions. The two things worth doing before Phase 1 design: (1) get a real answer on the `label_field`/`reason_field` → `miner_answer` question, ideally from the hackathon Discord since it's not in the docs, and (2) decide whether to test the seed miners' actual upstream behavior (calling urlscan.io/virustotal/phishtank directly ourselves) as part of Phase 1 data-source selection.
