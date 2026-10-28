# Acceptance Criteria

Definition of done for v0.1 (tracked in WORKLOG.md; each criterion maps to an automated test
where feasible — the test name is given).

## A. Platform operation
- AC1 `npm install` + `npm start` boots the server on `127.0.0.1:7788` with a generated auth
  token; `GET /api/health` responds unauthenticated. *(manual + `test/e2e/platform.test.ts`)*
- AC2 All mutating API routes reject requests without a valid bearer token.
  *(`test/integration/api-auth.test.ts`)*
- AC3 Scanning an origin that was registered but not approved is refused.
  *(`test/integration/targets.test.ts`)*

## B. Safety controls (each positive + negative test)
- AC4 Out-of-scope URL (unregistered host, wrong port/scheme) blocked before any request.
  *(`test/unit/safety-guard.test.ts`)*
- AC5 Redirect to off-scope host blocked mid-hop. *(`test/unit/safety-guard.test.ts`)*
- AC6 Public-internet origin refused while `allowPublicTargets=false`.
  *(`test/unit/safety-guard.test.ts`)*
- AC7 Destructive payloads refused by payload guard; benign probes pass.
  *(`test/unit/payload-guard.test.ts`)*
- AC8 Rate limiter bounds request rate under burst.
  *(`test/unit/rate-limiter.test.ts`)*
- AC9 Secrets redacted in stored evidence (Authorization/Cookie/API-key/JWT/PEM cases).
  *(`test/unit/redact.test.ts`)*
- AC10 Target register/approve/scan/export actions present in audit log.
  *(`test/integration/audit.test.ts`)*

## C. Detection (ground-truthed, no unbacked claims)
- AC11 Passive scan of `fixtures/vuln-app` detects every ground-truth passive item in
  `truth.json` (V1,V2,V3,V5,V6,V8) with correct OWASP category. *(`test/e2e/scan-vulnapp.test.ts`)*
- AC12 Active scan additionally detects V4 (reflection), V7 (unauthenticated /admin),
  V9 (user enumeration), V10 (no rate limit). *(same file)*
- AC13 Scan of `fixtures/hardened-app` produces **zero** confirmed medium+ findings
  (false-positive suppression). *(`test/e2e/scan-cleanapp.test.ts`)*
- AC14 Source scan of `fixtures/source-project` detects planted hardcoded secret, weak hash,
  SQL string concat, disabled TLS verification with file+line evidence.
  *(`test/unit/engine-source.test.ts`)*
- AC15 Dependency inventory finding produced; CVE findings produced when grype is installed
  (test auto-skips with a visible reason otherwise). *(`test/e2e/adapters.test.ts`)*
- AC16 Every finding carries: stable id, category, severity, confidence, validation status,
  evidence, engine, remediation, references, timestamps. *(`test/unit/model.test.ts` invariant
  + e2e assertions)*
- AC17 Same vulnerability rescanned keeps its stable ID (fingerprint stability).
  *(`test/e2e/scan-vulnapp.test.ts`)*
- AC18 Findings from two engines on the same issue deduplicate into one finding with merged
  provenance. *(`test/unit/dedupe.test.ts`)*

## D. Scanner integration honesty
- AC19 Engine list reports availability + version or install hint for semgrep/trivy/grype/
  nuclei/zap without crashing when tools are missing. *(`test/unit/adapters.test.ts`)*
- AC20 A scan with a failing/unavailable engine completes, records the engine status, and the
  report shows it. *(`test/integration/scan-lifecycle.test.ts`)*
- AC21 Scan report includes per-OWASP-category coverage verdicts including "manual-only"
  categories — the platform never claims full automated coverage.
  *(`test/unit/coverage.test.ts`)*

## E. Reports
- AC22 JSON report round-trips (parses; contains all findings + coverage).
  *(`test/unit/report-json.test.ts`)*
- AC23 HTML report self-contained, contains findings and coverage.
  *(`test/unit/report-html.test.ts`)*
- AC24 PDF report is a valid PDF (header/xref/EOF) containing scan metadata.
  *(`test/unit/report-pdf.test.ts`)*

## F. Engineering
- AC25 `npm run typecheck` passes with `strict` TS.
- AC26 `npm test` runs the full suite green (skips explicitly reported).
- AC27 Docs complete: SETUP, API, CAPABILITY-MATRIX, LICENSES, LIMITATIONS, BACKLOG,
  TEST-RESULTS (generated from a real run).

Criteria intentionally **not** claimed: authenticated crawling, exploit verification, full A01
IDOR automation, TLS deep inspection — see CAPABILITY-MATRIX and LIMITATIONS.
