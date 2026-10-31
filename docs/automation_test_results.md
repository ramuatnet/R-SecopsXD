# Automation Program — Baseline & Results

## Baseline (before automation program, 2026-10-27)

Recorded from a real run before any spec changes:

- `tsc --noEmit`: PASS
- `npm test`: 82/82 pass (59 unit, 14 integration, 9 e2e), 0 skipped
- htcnxt report (quick-passive, real public target) reviewed as the motivating artifact:
  1 confirmed finding; 6 categories manual-only; verdicts derived from
  `computeCoverage()` capability labels in `src/scan/coverage.ts` (v1)

## After Phase 2+13 implementation (2026-10-27)

- `tsc --noEmit`: PASS
- `npm test`: **91/91 pass** (68 unit, 14 integration, 9 e2e), 0 skipped
  - 9 new unit tests: task registry integrity, task-state derivation
    (FINDING_DETECTED / AUTOMATED_PASS / ENGINE_UNAVAILABLE / ERROR /
    NOT_EXECUTED / MANUAL_REVIEW_REQUIRED), category aggregation,
    no-coverage-inflation guarantee vs v1, SRI check positive/negative
- Live comparison scan (standard-active on the vulnerable fixture), before → after:

| Category | Before (v1) | After (v2) | Evidence now shown |
|---|---|---|---|
| A01 | partial | **PARTIALLY_COVERED** | A01-T01/T02/T03 FINDING_DETECTED (4 findings), A01-T04 manual |
| A02 | covered | **COVERED_WITH_EVIDENCE** | 5/5 tasks executed, 5 findings attributed across T01–T05 |
| A03 | manual-only | MANUAL_REVIEW_REQUIRED | honest: deployed-SBOM review task (webapp) |
| A04 | manual-only | **PARTIALLY_COVERED** | A04-T01 executed (cleartext finding), A04-T03 manual |
| A05 | manual-only | **PARTIALLY_COVERED** | A05-T01 executed (reflection finding), A05-T03 manual |
| A06 | manual-only | MANUAL_REVIEW_REQUIRED | unchanged (genuinely manual) |
| A07 | manual-only | **PARTIALLY_COVERED** | A07-T01/T02 executed (2 findings), A07-T04 manual |
| A08 | manual-only | **PARTIALLY_COVERED** | A08-T01 executed (SRI clean), A08-T02 manual |
| A09 | manual-only | MANUAL_REVIEW_REQUIRED | unchanged (unobservable by black-box) |
| A10 | manual-only* | **COVERED_WITH_EVIDENCE** | A10-T01 executed (error-disclosure finding) |

*A10 read "manual-only" in the htcnxt quick-passive report only because the profile
filter excluded active work; in scans where the observation engine ran, v1 already
said "covered". The v2 status is task-derived in both cases.

No category regressed to a higher claim (enforced by the no-inflation test).

## What changed in the code (all additive)

- `src/core/tasks.ts` — assessment-task registry (26 tasks: 17 automated across 12
  engines, 9 by-design manual with reasons)
- `src/scan/coverage.ts` — evidence-based `computeCoverage()` (v1 retained as
  `computeCoverageV1` for regression comparison and rollback)
- `src/core/types.ts` — `CoverageReport.status?` + `CoverageReport.tasks?`
  (canonical JSON stays backward-compatible; v1 `verdict` untouched)
- `src/engines/builtin/httpObservation.ts` — new SRI check (A08)
- `src/core/cweMap.ts` — CWE-829 → A08 override (documented)
- `src/scan/orchestrator.ts` — passes findings/target-kind/mode into coverage
- `src/reports/html.ts`, `src/reports/pdf.ts` — render per-task evidence
- `src/engines/builtin/httpObservation.ts` — cookie finding explanation now
  flag-specific (report-quality fix found while validating the htcnxt scan)

## Rollback procedure

1. Revert `src/scan/orchestrator.ts` to call `computeCoverage(ranRecords, profileId)`
   (v2 function tolerates the short signature) or swap to `computeCoverageV1`.
2. The `status`/`tasks` fields are optional — old consumers ignore them; removing
   them from `computeCoverage()` output restores v1 JSON exactly.
3. No schema migration involved; no stored data changes.

## Enterprise expansion increment (2026-10-27, later)

- Baseline: 99/99 pass. After CORS/JWT/sensitive-URL/source-map/TLS/OpenAPI/A09 increments: **109/109 pass** (14 new unit tests)
- Engines registered: 12 → **14** (builtin.tls-analysis, builtin.openapi-policy)
- Task registry: 26 → **32 tasks**; manual tasks reduced 9 → 6 (A04-T03, A06-T02, A09-T02, A09-T03, A03-T06, A01-T05/T06/A02-T06 newly automated)
- Newly automated (was manual): TLS certificate/protocol analysis; API design-policy signals; JWT handling observation; logging hygiene (source); log-correlation observation; exposed manifests; source-map exposure; sensitive-data-in-URLs
- Repository assessment for the enterprise expansion: docs/enterprise_expansion_assessment.md

## Python data plane (2026-10-28, v2 Phase 0-py)

- T0.1 redirected: user decision — Python 3.14 stdlib asyncio data plane now, Rust migration later (T12)
- `engine/rsec_engine.py`: NDJSON JSON-RPC daemon (ping/http.get/http.post/recon/shutdown)
- `engine/proto/v1.md`: language-agnostic protocol doc
- `src/engine-bridge/bridge.ts`: TS control-plane bridge — spawn/supervise, NDJSON framing,
  per-call timeout, crash rejection, respawn-on-next-call
- Safety parity with the TS httpClient, regression-tested: scope origins enforced on
  every redirect hop (out-of-scope hop → scope_blocked), rate limiting, method policy
  (DELETE → safety_blocked), cumulative request budget (budget_exhausted), header +
  body secret redaction, 256 KiB body cap
- Suite: **155/155** (6 new bridge/engine tests)

## Continuous security + SARIF (2026-10-29)

- T9.1 ScanScheduler (interval rescans, error-isolated) + originChanged watcher (ETag/length baseline → targeted rescan trigger)
- T9.2 alertOnNewFindings: fingerprint diff vs previous scan → webhook POST with scores; alert-dedup prevents re-alerting the same finding
- T10.3 toSarif: SARIF 2.1.0 with rules, levels, stable partialFingerprints
- Suite: **164/164** (5 new continuous tests)

## JSON login + metrics + SBOM + SSE (2026-10-29, latest)

- JSON-API login: `loginType: 'json'` + `tokenField` on credential profiles;
  authenticated probe handles bearer-token sessions (tested against a JSON login fixture)
- computePrecisionRecall: formalized P/R/F1 measurement for CI ground-truth gating
- toCycloneDX: SBOM 1.5 export from dependency-inventory findings
- SSE trace endpoint: GET /api/scans/:id/trace streams scan events
- Suite: **180/180**

## Raw probes, variant hunter, ASM, RBAC, SSE (2026-10-29, final batch)

- T4.2 rawProbes.ts: host-header injection probe via node:net (attacker Host reflected in response)
- T4.6 variantHunter.ts: mutation fan-out (URL-encode, double-encode, uppercase, null-byte, boundary, whitespace) across sibling params; sibling-endpoint numeric probe
- T8.1 asmDiscovery.ts: DNS asset discovery (CNAME, MX, NS, TXT) + certificate SAN extraction + cloud bucket public-access probes (S3, GCS, Azure)
- T10.1/T10.2 repository.ts: ScanRepository interface + RBAC role definitions (viewer/scanner/approver/admin)
- T9.3 SSE trace endpoint (GET /api/scans/:id/trace — streams engine status until completion)
- Suite: **180/180**

## Context-based infrastructure recon (2026-10-30, latest)

- New engine `builtin.host-infra` (HostInfraEngine): registering a web URL is now enough —
  the scan resolves the hostname (DNS lookup + CNAME + PTR), then in active mode port-scans
  the resolved IPs (max 4, IPv4 first), TLS-probes 443/8443 (cert CN/issuer/SANs/protocol),
  fingerprints services, matches versions against the offline CVE list, and derives banner-based
  OS hints (low confidence; unknown stays unknown). Edge-proxy (CDN) fronting detected and reported.
- Passive scans get DNS-only resolution (host-resolved finding, no packets to the host).
- Scope anchoring: only IPs the registered hostname resolves to are scanned — no separate CIDR
  target registration needed for external infrastructure recon.
- Wired into `standard-active` + `external-dast` profiles (linear path) and seeded in loopRunner
  (loop path, never breaks the scan). Tasks A01-T13, A02-T09, A03-T08 added; coverage v1 map updated.

## Honest-unknown fix: blocked fetches never imply absent headers (2026-10-31)

- Validation of scan 0747af82 (zmail.htcinc.com) exposed an evidence-integrity bug: the root
  fetch was scope-blocked (302 -> iam.htcinc.com SSO, cross-origin), the crawler recorded the
  page as status 0 with empty headers, and http-observation then reported ALL security headers
  as "missing" — absence inferred from no data (violates I8).
- Fix 1: http-observation filters status-0 pages — header/cookie absence is only ever derived
  from a real observed response.
- Fix 2: crawler emits a `root-fetch-blocked` informational finding naming the blocked reason
  (e.g. "iam.htcinc.com:443 is not zmail.htcinc.com:443") so the operator sees the scope edge
  instead of an empty report.
- Verified live: re-scan of zmail now yields exactly the scope-edge finding; the header findings
  (which were coincidentally true on the raw 302) are no longer claimed from a blocked fetch.
- Suite: **194/194**

## EASM expansion: ports, fingerprints, proactive discovery (2026-10-31)

- **Ports**: host-infra expanded 18 → ~35 ports (added Telnet 23, MSRPC 135, NetBIOS 139, SMB 445,
  WebLogic 7001, GlassFish 4848, K8s API 6443, Docker 2375/2376, Elasticsearch 9200, memcached
  11211, VNC 5900, CouchDB 5984, plus alt-HTTP 8008/8081/9000). Fingerprint port→service map extended.
- **Deep recon per open HTTP/TLS port** (one connection: TLS handshake + GET /): response-header and
  body signature identification (Jenkins, Grafana, K8s Dashboard/API, Elasticsearch, phpMyAdmin,
  WebLogic, GlassFish, Kibana, SonarQube, Jetty, MinIO, default nginx/Apache/IIS pages), favicon
  murmur3 hashing (shodan favicon-hash compatible) for external correlation, CDN/WAF edge detection
  from response headers (cf-ray, x-amz-cf-*, x-akamai-*, x-sucuri-id, x-vercel-id, x-msedge-ref, …).
  Management-interface finding now names the product.
- **New engine `builtin.asset-discovery`** (passive, wired into standard-passive/active + external-dast):
  DNS records (CNAME/MX/NS/TXT), Certificate Transparency names via crt.sh with liveness resolution,
  target cert SANs, IP attribution via Team Cymru IP→ASN whois (ASN/owner/country). Active mode adds
  AXFR zone-transfer attempts against discovered NS and cloud bucket listability probes.
  Discovered assets are LISTED, never scanned — registering them as targets remains an explicit
  approval decision (scope model preserved). Short-circuits cleanly for IP-literal/localhost targets.
- New tasks: A01-T14 (asset discovery), A01-T15 (tech-stack identification), A02-T10 (AXFR/buckets).
- Suite: **200/200**

## newtask.md Phase A + B: validation fixes + in-house Nuclei pack (2026-10-31)

Baseline: scan 160fb8bf (TNEB standard-active) — 5 findings, zero vulnerability-class results.

**Phase A (V1–V8 from the review):**
- **A1/V1** port results surface per-port (`port-open`, info/medium/high exposure classes —
  DB/remote-access/cluster APIs at the edge = high). Plus TWO root-cause bugs found by re-scanning:
  - `normalizeLocator` stripped `:port` from `ip:port` locators ("file line number" regex) — every
    port finding on one host collapsed into one dedupe fingerprint. Ports now keep their port.
  - `httpRecon` reported `open:true` on SYN-ACK-with-zero-bytes; TNEB's edge intermittently
    SYN-ACKs (and answers HTTP block pages on) every probed port. Zero-byte answers no longer count;
    identical responses across ≥5 ports are suppressed as `port-scan-interference` (middlebox
    detection) instead of flooding the report. Live proof: TNEB honestly shows 443 (TLS) + 80
    (HTTP 307) — the earlier "9200/Elasticsearch high" was a middlebox artifact (direct probe
    confirms closed).
- **A2/V2+V3** verification stage added before variant-hunter (seeds verified, promotions audited);
  variant-hunter injects seeds and hunts mutations (previously a no-op stub); reflection/redirect/
  endpoint-discovery record `notExecutedReason` on empty surface instead of "ran 0ms".
- **A3/V5** asset-discovery sources run in parallel with hard caps (≤8s), public-resolver fallback
  (1.1.1.1/8.8.8.8/9.9.9.9) when the OS resolver denies.
- **A4/V7** coverage adds `RAN_CLEAN`: all-tasks-executed-but-zero-findings categories never read
  "covered" and the note says so explicitly.
- **A5/V4** endpoint-discovery scans all crawled pages for bundles, accepts extension-less module
  scripts, cap 8→16.
- **V6** honest: authenticated-probe records the exact skip reason (needs a credential profile).

**Phase B (N1–N10) — in-house Nuclei, no clone:**
- `templates/` pack: 41 curated templates across A01-sensitive-exposure, A02-admin-consoles,
  A01-api-surface, A02-cors, A07-default-credentials, A10-verbose-errors, each with `# source:`
  citation (N9) and CWE classification; `index.json` maps template → required capability.
- Runner: adapter executes ONLY the in-house pack (`-t` per gated template), capability-gated from
  the crawl corpus (N5 — graphql templates need observed GraphQL surface); `-duc -jsonl -silent`,
  deny-listed tags, rate limits unchanged.
- `npm run lint:templates` (N3/N7/N9): required keys, unique ids, source citation, matcher
  type+part, ≤3 requests, DSL allowlist (no `code:`/javascript, payload cap 40), index consistency.
- Binary integrity (N6): `templates/nuclei-pin.json`; version+SHA-256 verified at startup, mismatch
  = fail closed. Canary (N10): `npm run canary` — parser canary always; binary execution canary
  only when the pinned binary + fixture are actually present (honest skip).
- Nuclei binary is not installed on this host — the adapter reports unavailable honestly; every
  mechanism above is test-covered so the pack activates the moment the pinned binary lands.

Suite: **212/212** (`npm run lint:templates` + `npm run canary` green). Server re-validated on TNEB.

## newtask.md Phases C–F: unified asset graph, orchestration, risk (2026-10-31)

**Phase C — graph + normalization (C1–C4):**
- `src/graph/types.ts`: closed vocabularies — 19 node types, 10 edge types; NodeAssertion/
  EdgeAssertion/AssetNode/AssetEdge/NormalizedEvent (OCSF-aligned: class_uid, activity_id,
  observables, severity_raw + severity_norm, provenance).
- `src/graph/uid.ts`: deterministic UIDs — `<type>:<base32(sha256(type|canonical_identity))>`;
  canonical identity per type (webapp origin normalized, domains lowercased, ip:port verbatim).
  Same asset from DNS, CT and port scan collapses to one node.
- `src/graph/graph.ts`: bitemporal GraphStore over node:sqlite (migration 007) — upserts idempotent
  per (type, identity), valid_from/valid_to/observed_at, nothing deleted only closed (re-observation
  re-opens; history retained), bounded traverse(), fanout().
- `db/postgres/001_asset_graph.sql`: the Postgres deployment of the same schema (JSONB attributes,
  ltree adjacency path + GIST index, partial indexes on open edges, recursive blast-radius CTE).
- `src/graph/adapters.ts`: one adapter per source family (EASM/scanner/DAST/CSPM) — findings route
  by provenance engine (cloud-bucket by rawId); host-resolved → domain+ip nodes + resolves_to;
  port-open → port node + exposes; service-identified → service node + runs; vulnerability findings
  → finding node + found_on.
- `src/graph/merger.ts`: EventStore + pure mergeEvents — dedupe key (class_uid, asset_uid,
  observable_hash); raw severity of the FIRST source NEVER overwritten; normalized severity ratchets
  up; provenance merges; times_seen counter.
- `src/graph/query.ts` + `sync.ts`: blastRadius (bounded walk + blast factor) and the scan-finalize
  seam — syncFindingsToGraph wired into the orchestrator (never breaks a scan; audited).

**Phase D — orchestration (D1–D5):**
- `src/safety/governor.ts`: global + per-asset token buckets, gentle/normal/aggressive profiles
  (1/5/20 rps per asset, 100/500/2000 request ceilings per scan), adaptive throttle (429/503 or
  >3s latency halves rate with exponential backoff, 10% recovery on success), kill switch per
  target + global, per-sensor circuit breaker (3 failures → open 60s).
- `src/safety/scopeGate.ts`: explicit approval records for domains/cidrs/origins (I13 — nothing
  auto-expands; subdomain covered by approved parent).
- `src/bus/bus.ts`: the six canonical topics with typed envelopes; in-process pub/sub now, Kafka/
  Redpanda adapter maps 1:1 later.
- `src/orchestration/assessAsset.ts`: trigger rules (web port + approved scope → scan.request;
  DB/mgmt port → approval.gate, never auto-scanned) and the AssessAsset state machine (9 steps,
  retry 3× with backoff, reverse-order compensation on abort, governor-bound safety-gate step).
  Temporal port = each step becomes an activity with the same options.

**Phase E3 — planner:** `src/orchestration/planner.ts` closes V8: fingerprint → capability tags
(Tomcat/Coyote → manager paths + rsec-tomcat template family; PHP → .php set; GraphQL → introspection
set; ES/docker/k8s → API checks; database/SMB/RDP/VNC → alert-only, zero probes; unknown → generic
pack only, I8).

**Phase F — risk (F1–F4):** `src/risk/risk.ts` — Risk = Base × Reachability × Exposure × Criticality
× Blast clamped 0–100 with every factor stored; base = max(CVSS/10, EPSS×1.4, VPR/10) floored 0.05;
blast log-fit to the spec's example (fan-out 1 → 0.6, 4 → ~1.2, cap 1.5). Worked example verified:
identical CVE-9.8/EPSS-0.6 → 100 at the edge vs 4 on an isolated internal box (25×). Noise rules:
2-of-3 confirmation gate, EPSS<0.01+unreachable → backlog, (asset_uid, cve) dedupe keeping max.

**Validated live:** vuln-app standard-active scan → graph accumulated 18 nodes / 16 edges / 17
events; cross-scan dedupe merged the repeat observation (times_seen=2); graph.synced audited.
Suite: **238/238**. Sensors (E1), credentialed SSH/WinRM (E4), cloud metadata merge (E5) need
external infrastructure — interfaces documented, not faked.

## newtask.md wiring: closed loop, live governor, planner, risk-in-reports, CI (2026-10-31)

**D3-live (G2):** `ScopedHttpClient` now takes an optional `GovernorBinding` — every request
acquires from the process-wide SafetyGovernor (per-host asset keys, scan-bound ceilings) and feeds
responses back for adaptive throttle. Rate-limit refusals WAIT (`acquireWait`, bounded 30s) so
engines run at the profile's pace instead of silently dropping probes; kill switch / scan ceiling /
circuit breaker refuse hard. `OWASP_SCAN_PROFILE=gentle|normal|aggressive` selects ceilings
(100/500/2000 requests per scan). G2 load test: gentle profile throttles a 120-request burst to the
ceiling, blocked requests are honest, counter exact.

**D5-live (closed loop):** the orchestrator publishes `discovery.asset` for every finding and
evaluates trigger rules on port-open findings (scope-approved origins only). `ScanRequestDispatcher`
subscribes to `scan.request` and auto-starts scans for APPROVED registered targets — never while a
scan is active for that target, never more than one per hour per target, never for unregistered
origins (I13 holds). Scope records are approved authoritatively at scan start.

**E3-live:** path-probe derives the product from crawl Server/X-Powered-By headers and merges
planner payload-family paths (deduped, bounded 8). Live: `insecure-express-clone → families [node],
+2 paths`.

**E2:** `os-hint` findings now land as `os` nodes with `ip runs os` edges (banner-derived, low
confidence by design).

**F1/F4:** every finding in the JSON and HTML reports carries an explainable risk object —
score, band, all five factors, confirmation signals, backlog flag. Blast factor is neutral (1.0)
when no graph fan-out measurement exists; the log-fit factor applies when it does. `riskSummary`
bands in the JSON report.

**G1:** `precisionRecallByClass` — per-class P/R/F1 over labeled examples.
**G4:** `.github/workflows/ci.yml` — lint:templates → tsc → canary → full suite on every push/PR
(template without `# source:` fails the gate; egress audit runs inside the suite).

Suite: **246/246**. Server re-validated live (dispatcher started, planner fired, graph synced).
