# Design Decision Record (ADR summary)

Each decision lists context → decision → consequences. Decisions are numbered and dated.

## D1 — Runtime: Node.js 24 + TypeScript, zero runtime npm dependencies
**Date:** 2026-10-25 · **Status:** accepted

**Context.** The platform itself assesses software supply-chain risk (OWASP A03). Every runtime
dependency we add is itself supply-chain surface. The build host is Windows with Node 24.18,
which natively executes TypeScript (type stripping) and ships an embedded SQLite engine
(`node:sqlite`), an HTTP server, `fetch`, and a test runner (`node:test`) in the standard library.

**Decision.** Implement in strict TypeScript executed directly by Node 24. The **only** npm
dependency is `typescript` (dev-only, used for `tsc --noEmit` type-gating). No bundler, no
transpiler, no framework.

**Consequences.**
- `npm ci` installs exactly one package; SBOM is trivially auditable; no postinstall scripts
  beyond typescript's.
- TypeScript must use *erasable-only* syntax (no `enum`, no namespaces, no parameter
  properties) because Node type-stripping does not transform code. We use union string-literal
  types and plain objects instead — this is also the more JSON-friendly style.
- Imports use explicit `.ts` extensions (`allowImportingTsExtensions`) which is required for
  direct execution.
- We write our own micro-router, PDF writer and test fixtures instead of pulling libraries.
  Each is small (< ~400 lines), fully typed, and covered by tests. If the project later needs
  more capability, each can be swapped for a library behind its module boundary.

## D2 — Persistence: embedded SQLite via `node:sqlite`
**Date:** 2026-10-25 · **Status:** accepted

**Context.** Scan history, findings, targets and audit logs need durable, queryable storage with
zero administration for a locally-run tool.

**Decision.** Use `node:sqlite` (`DatabaseSync`) with a versioned migration table, WAL mode, and
a single data directory (`./data`, git-ignored). Synchronous SQLite is acceptable because scan
work is bounded by network/engine latency, not DB throughput.

**Consequences.** No native module compilation (unlike `better-sqlite3`). `node:sqlite` is
flagged experimental by Node; the API we use (`DatabaseSync`, prepared statements) has been
stable across 22→24 and we pin `engines.node >= 24`. The data file is portable and easy to back
up. Concurrency is single-writer — fine for a single-operator tool; multi-user deployments
would move to a server DB (see BACKLOG).

## D3 — External scanners: subprocess adapters over JSON, never reimplemented
**Date:** 2026-10-25 · **Status:** accepted

**Context.** Semgrep (SAST), Trivy (SCA/misconfig), OWASP ZAP (DAST) and Nuclei (template
testing) are mature, community-audited scanners. Duplicating their detection logic would be
worse than reuse; wrapping them is the standard DevSecOps pattern.

**Decision.** Every external scanner is an *adapter* that: (1) detects the binary (or Docker
image) and version, (2) invokes it as a subprocess with explicit arguments and a timeout,
(3) parses its JSON/JSONL output, (4) normalizes findings into the platform finding model,
(5) reports "unavailable + install hint" when missing — never silently pretending to have run.
Grype is included as an additional SCA adapter because it is available on this host, proving
the adapter architecture end-to-end against a real external tool.

**Consequences.** Detection quality equals the wrapped tool at its installed version; upgrades
flow through automatically. Normalization code contains per-tool mappers with fixture-based
unit tests using captured sample outputs (no live tool needed for unit tests). Licensing of the
wrapped tools is documented in `docs/LICENSES.md`; the platform's own license is MIT.

## D4 — Built-in evidence modules complement (not replace) external scanners
**Date:** 2026-10-25 · **Status:** accepted

**Context.** With no scanners installed the platform must still demonstrate value; and some
checks (HTTP security-header observation, cookie flags, information disclosure in responses,
SRI verification) are simple, deterministic HTTP observations.

**Decision.** Ship built-in engines (`builtin.http-observation`, `builtin.crawler-lite`,
`builtin.path-probe`, `builtin.auth-probe`, `builtin.source-scan`, `builtin.dep-manifest`).
They produce *evidence-backed* findings only: every finding carries the request/response or
file/line evidence that a human can re-verify. Heuristic checks (e.g. source-code regex) are
labelled with low/medium confidence and `probable`/`informational` status — never `confirmed`
unless the observation itself is deterministic (e.g. a missing header observed on a live
response).

**Consequences.** The platform is useful out of the box and its demo/e2e tests do not depend on
external tools. The capability matrix states explicitly, per OWASP category, what built-in
checks can and cannot conclude, and marks the remainder "requires manual assessment / external
scanner".

## D5 — Safety model: registered-and-approved scope, passive by default
**Date:** 2026-10-25 · **Status:** accepted

**Context.** A vulnerability assessment platform is itself a dual-use tool. Unauthorized or
accidental scanning of third-party systems is the primary misuse risk.

**Decision.**
1. Targets must be **registered** (name + origin URL) and **explicitly approved** before any
   request is sent to them. Approval is a separate action from registration (two-step intent).
2. **Passive by default**: passive mode issues only plain GET requests to the registered
   origin (no injected payloads). **Active mode** (parameter markers, path probes, auth
   probes, Nuclei non-passive templates) must be explicitly requested per scan on an approved
   target and is recorded in the audit log.
3. URL guard: every request URL must match the approved origin (scheme+host+port); redirects
   are followed manually, hop-by-hop, and must stay in scope; private/loopback targets are
   allowed, **public internet targets require the operator to set `allowPublicTargets: true`**
   in addition to approval.
4. Destructive/dangerous payload classes are refused by a payload guard (see
   `src/safety/payloadGuard.ts`); Nuclei runs with a deny-list (`dos`, `fuzz`, `brute-force`
   tags) even in active mode.
5. Rate limiting (token bucket per target), request timeout, global concurrency semaphore,
   bounded crawl/page caps, and per-scan/per-engine timeouts.
6. All mutating API actions require a bearer token; server binds `127.0.0.1` by default and
   refuses to bind non-loopback without an explicitly generated token.
7. Secrets are redacted from stored evidence and logs by a central redactor.
8. An append-only audit log records target lifecycle, scans, exports and auth events.

**Consequences.** Some genuinely useful tests (e.g. authenticated deep-scanning) are out of
scope for v1 and listed in the backlog. The guard layer is unit-tested with positive and
negative cases, including redirect-based scope escape.

## D6 — Finding model: stable IDs, severity ⊥ confidence, explicit validation status
**Date:** 2026-10-25 · **Status:** accepted

**Decision.** Findings carry: a stable `id` (derived from a content hash — the same issue on the
same asset keeps its ID across rescans), a `fingerprint` used for cross-engine deduplication,
`severity` (impact: critical/high/medium/low/info) kept strictly separate from `confidence`
(engine certainty: high/medium/low), and a `validationStatus` lifecycle
(`untested → probable/confirmed` via evidence rules; `false_positive` via human triage;
`informational` for hygiene observations). Every finding includes CWE/CVE where applicable,
evidence (HTTP or file/line or process output), detection engine + version, explanation,
remediation, references, timestamps and provenance (including raw scanner IDs).

**Consequences.** Reports can honestly answer "what do we know vs believe". Deduplication
merges provenance from multiple engines instead of dropping evidence. No finding is ever
auto-invented: built-in findings always link to concrete evidence; adapters map their source
findings 1:1. Where the platform cannot detect something, the scan's *coverage report* says so
category by category.

## D7 — Reports: JSON (canonical), HTML (interactive/print), PDF (generated in-process)
**Date:** 2026-10-25 · **Status:** accepted

**Decision.** The JSON report is the canonical artifact (round-trips into the tool). HTML is a
self-contained styled document. PDF is produced by a small in-house PDF 1.4 writer (core
Helvetica fonts, no external dependency) that is format-tested (`%PDF` header, xref offsets,
marker strings) — we do not shell out to a browser.

**Consequences.** No headless-Chrome dependency; PDF layout is deliberately simple (cover,
executive summary, findings, coverage matrix). Complex graphics stay in HTML.

## D8 — Honesty constraints ("no fabrication")
**Date:** 2026-10-25 · **Status:** accepted

**Decision.** (1) A scan record lists engines that *ran*, engines that were *unavailable*, and
per-OWASP-category coverage (`covered` / `partial` / `manual-only`). (2) No test may assert a
capability without a reproducible test (this is enforced by the ground-truth fixture design).
(3) Docs never claim full automated coverage of any OWASP category — the capability matrix
states limits per category and per scan mode. (4) CI-equivalent (`npm test`) results in
`docs/TEST-RESULTS.md` are produced by actually running the suite.

## D9 — Test fixtures: purpose-built local apps with ground truth
**Date:** 2026-10-25 · **Status:** accepted

**Decision.** Ship `fixtures/vuln-app` (12 planted, documented vulnerabilities) and
`fixtures/hardened-app` (the same surface, hardened) plus `fixtures/source-project` (planted
source-level issues and a lockfile with known CVEs). Each planted issue has an ID recorded in
`fixtures/vuln-app/truth.json`; e2e tests assert detection (recall) and, on the hardened app,
absence of false positives (precision). Adapters for Juice Shop / WebGoat / crAPI are provided
as *target profiles + docs*, not required for the test suite (see `docs/SETUP.md`).

**Consequences.** The test suite runs offline in seconds. Demoing against real OWASP training
apps (Juuce Shop via Docker) is documented and scripted (`scripts/`) but optional.
