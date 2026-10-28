# Worklog

Build journal, newest last. Every phase ended with a real test run; regressions were
fixed before moving on.

## 2026-10-25 — Phase 0: inspect, decide, design

- Inspected workspace (empty), toolchain (Node 24.18 w/ native TS + node:sqlite, npm
  11, git, Docker 29, Java 21; scanners absent, **grype present**), npm registry reach.
- Verified `node:sqlite` `DatabaseSync` and Node TS strip-only execution with probe
  scripts; npm ping OK.
- Knowledge research via a background agent verified against primary sources:
  OWASP Top 10:2025 **Final** category codes/names + official CWE lists + canonical
  URLs (top10.owasp.org/2025); tool licenses (semgrep LGPL-2.1, semgrep-rules
  custom internal-use license — NOT LGPL; trivy/grype Apache-2.0; nuclei+templates
  MIT; ZAP Apache-2.0); CLI facts (semgrep `--json`, trivy `fs --scanners
  vuln,secret,misconfig --format json`, nuclei `-passive/-etags`, ZAP
  `-cmd -quickurl -quickout` with extension-driven format); WSTG v4.2 section codes;
  ASVS 5.0.0 (V1–V17).
- Wrote docs: DECISIONS (D1–D9), ARCHITECTURE, THREAT-MODEL, ACCEPTANCE (27 criteria).
- Stack decision D1: Node 24 + strict TS, zero runtime deps (erasable-only syntax —
  this bit us twice later, see below).

## 2026-10-25 — Phase 1–2: core domain + safety layer

- Built `core/` (types, OWASP 2025 catalog with official CWE lists, CWE→category
  mapper with 2021→2025 tag translation, stable IDs/dedupe via sha256+base32, central
  redactor) and `safety/` (scope guard with per-hop redirect validation and
  public-target gate, token-bucket rate limiter, payload guard refusing destructive
  classes, global semaphore).
- Fixed: regex-literal bug in payloadGuard (unescaped `/`), exactOptionalPropertyTypes
  friction (adopted `| undefined` convention for optional fields), redactor replacer
  typing.
- Unit tests: 35 passing.

## 2026-10-25/26 — Phase 3–8: persistence, engines, adapters, orchestrator, reports

- `db/database.ts`: node:sqlite, versioned migrations, repositories (targets, scans,
  findings, fingerprint-scoped triages, append-only audit), sha256-stored bearer token
  with timing-safe compare.
- `scan/httpClient.ts`: the single egress point — payload guard → scope check →
  semaphore → rate limit → manual redirect hops (each re-validated) → capped body
  read → redacted evidence capture.
- Ground-truth fixtures: `fixtures/vuln-app` (12 planted issues, truth.json),
  `fixtures/hardened-app` (same surface hardened), `fixtures/source-project`
  (4 planted source issues + outdated lockfile for real SCA).
- Built-in engines: crawler-lite (bounded, robots-aware, captures error pages),
  http-observation (headers/cookies/banners/errors/comments/listings/cleartext),
  path-probe (calibrated not-found suppression + bounded object-access IDOR smoke
  probe), reflection-probe (marker-tag unencoded-output detection), auth-probe
  (enumeration differential + bounded 8-attempt rate-limit check), source-scan
  (6 rule patterns, probable-only), dep-manifest (inventory + lockfile check).
- Adapters: semgrep/trivy/grype/nuclei/zap — subprocess (no shell, PATH+PATHEXT
  resolution, taskkill tree-kill on Windows), pure `static parseReport` mappers,
  honest availability with install hints, nuclei hard deny-tags.
- Orchestrator: profile plans, per-engine availability/status records, normalize →
  dedupe → triage-inherit → persist → coverage verdicts.
- Reports: canonical JSON (+evidence re-redaction at render), self-contained HTML,
  dependency-free PDF 1.4 writer with format tests.
- Notable self-caught issues: an `Object.prototype` patch slipped into
  http-observation during drafting — removed immediately (global prototype pollution
  in a security tool is unacceptable); parameter-property syntax (unsupported by
  strip-only mode) found in 6 classes via runtime failures — replaced with explicit
  fields; base32 alphabet off-by-one produced `undefined` inside finding IDs — fixed
  with modulo by alphabet length; path-probe had an inverted status condition that
  skipped every probe — caught by the e2e truth assertions.

## 2026-10-26 — Phase 9–10: UI, CLI, samples, docs

- Web UI (vanilla TS-free ES module): token gate, targets (register→approve),
  scans (start/view with engines, coverage matrix, findings, triage, report
  downloads), engines with availability + install hints, OWASP catalog with honest
  automation notes, audit log. Verified in the in-app browser: all views render with
  live data from the running server; a DOM-structure check confirmed engines (12
  listed, 4 unavailable shown honestly) and audit entries (auth.failed recorded from
  an earlier bad-token test). Screenshot capture timed out in the browser harness —
  verification is DOM-level, noted here honestly.
- CLI: register/approve/scan(--wait)/report/findings/engines; ran a real
  `source-review` scan — 4 planted issues + 10 grype advisory findings, semgrep/trivy
  honestly `unavailable`.
- Sample reports generated from real scans into docs/samples/ (JSON/HTML/PDF for a
  webapp active scan and a source review).
- Final docs: CAPABILITY-MATRIX, SETUP, API, LICENSES, LIMITATIONS, BACKLOG,
  TEST-RESULTS (from the recorded run), README, LICENSE (MIT).
- Final recorded run: `tsc --noEmit` PASS; `npm test` → **82/82 PASS** (59 unit,
  14 integration, 9 e2e), 0 skipped.

## Verification summary (definition of done)

- Platform starts locally (`npm start`, loopback, token). ✔
- Scans an explicitly authorized test application end-to-end (API + UI + CLI). ✔
- Produces traceable findings (stable IDs, evidence, provenance) and useful reports
  (JSON/HTML/PDF). ✔
- Passes its documented tests (82/82, recorded in TEST-RESULTS.md). ✔
- Transparently reports detection gaps (coverage verdicts, unavailable engines,
  manual-only categories, LIMITATIONS.md). ✔

## 2026-10-28 — B1 completion + compounding batch

- **JS bundle endpoint discovery** (`builtin.endpoint-discovery`, passive): fetches crawled same-origin
  bundles, extracts fetch/axios/url route strings, feeds hidden API surface into path-probe and the
  authenticated surface map. Inventory finding (informational).
- **Cross-role authorization matrix** (B1 complete): credentials now support multiple roles per target
  (encrypted); the authenticated probe logs in as the secondary identity and re-requests primary-restricted
  pages — secondary access without redirect = broken function-level authorization (probable, CWE-285).
  Validated against vulnerable + hardened two-role fixtures.
- **Rescan diffing**: fingerprint-based new/fixed/persistent comparison. API
  `GET /api/targets/:id/diff`, CLI `diff <target>`, UI "Compare with previous scan" on scan detail.
- Client hardening retained: Set-Cookie carried across redirect hops within one chain.
- Suite: 139/139 (17 engines, 48 tasks). Manual residual: 6 documented entries.
