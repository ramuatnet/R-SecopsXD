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
