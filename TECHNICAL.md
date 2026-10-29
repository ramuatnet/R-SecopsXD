# R-SecopsXD — Technical Documentation

## 1. Overview

R-SecopsXD is an autonomous, evidence-driven vulnerability assessment and penetration testing (VA/PT) platform for web applications, APIs, and source code. It maps findings to the OWASP Top 10:2025 (Final), enforces strict safety invariants, and produces reproducible evidence for every claim.

**Stack:** TypeScript (control plane) + Python (data plane), Node.js 24 runtime, zero runtime npm dependencies, SQLite persistence, vanilla web UI + headless CLI.

**Repository:** https://github.com/ramuatnet/R-SecopsXD

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    CONTROL PLANE (TypeScript, Node 24)                │
│                                                                      │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────────┐    │
│  │ Target Model│  │ Probe Gate   │  │ Autonomous Loop           │    │
│  │ (tri-state  │  │ (capability  │  │ sense→model→decide→act    │    │
│  │  graph,     │  │  flips,      │  │   →verify→adapt           │    │
│  │  hash-chain │  │  absence=    │  │   closure or budget       │    │
│  │  deltas)    │  │  evidence)   │  │   deterministic trace     │    │
│  └──────┬──────┘  └──────┬───────┘  └────────────┬──────────────┘    │
│         │                │                       │                   │
│  ┌──────▼────────────────────────────────────────▼──────────────┐    │
│  │                    ENGINE REGISTRY (17 engines)               │    │
│  │  14 builtin + 4 adapters (Semgrep/Trivy/Grype/Nuclei/ZAP)    │    │
│  └──────┬───────────────────────────────────────────────────────┘    │
│         │                                                            │
│  ┌──────▼──────────┐  ┌──────────────┐  ┌────────────────────────┐   │
│  │ Scoped HTTP     │  │ Safety Layer │  │ Evidence Store (content│   │
│  │ Client (single  │  │ payload guard│  │ addressed, append-only)│   │
│  │ egress point)   │  │ scope guard  │  │ Corpus Store (replay)  │   │
│  └──────┬──────────┘  │ rate limiter │  └────────────────────────┘   │
│         │             │ redaction    │                                │
│  ┌──────▼──────┐      └──────────────┘  ┌────────────────────────┐   │
│  │ SQLite DB   │                       │ Reports (JSON/HTML/    │   │
│  │ (targets,   │                       │ PDF/SARIF/CycloneDX)   │   │
│  │ scans,finds,│                       │                        │   │
│  │ model,audit)│                       │                        │   │
│  └─────────────┘                       └────────────────────────┘   │
└──────────────────────────┬───────────────────────────────────────────┘
                           │ newline-delimited JSON-RPC (stdio)
┌──────────────────────────▼───────────────────────────────────────────┐
│                    DATA PLANE (Python 3.14, stdlib asyncio)           │
│  rsec_engine.py: http.get/post, recon, scope+rate+redaction          │
│  rsec_corpus.py: corpus store, replay+diff, recursive SPA crawler    │
└──────────────────────────────────────────────────────────────────────┘
```

### Key architectural decisions

| Decision | Rationale |
|---|---|
| Zero runtime npm dependencies | Supply-chain security: the assessor must not be vulnerable to its own scans |
| Single network egress point (`src/scan/httpClient.ts`) | All engine HTTP passes scope→guard→rate→redaction; grep-enforced |
| Tri-state model (`present/absent/unknown`) | Never assume; absence is evidence with the probe recorded |
| Evidence-based coverage (not capability-based) | Coverage verdicts derive from actual task execution, not labels |
| Content-addressed evidence store | Same content = same ref = no duplicate writes; reconstructible |
| Severity ⊥ confidence | Independent dimensions; a high-confidence low is possible |
| Python data plane (not Rust) | Python 3.14 stdlib asyncio; Rust migration deferred behind the same protocol |

---

## 3. Engines (19 registered)

### Built-in (14)

| Engine | ID | Capabilities | Mode |
|---|---|---|---|
| Bounded Crawler | `builtin.crawler-lite` | Same-origin BFS, href + fallback paths | passive/active |
| HTTP Security Observation | `builtin.http-observation` | Headers (incl. CSP quality), cookies, banners, listings, verbose errors, info exposure, SRI, JWT observation, mixed content, cleartext, correlation IDs, library version fingerprinting, bundle secrets | passive/active |
| Sensitive Path Probe | `builtin.path-probe` | Admin/config/backup paths, robots.txt entries, Tomcat paths (server-aware), source maps, manifests, 500 stack traces | active |
| Input Reflection Probe | `builtin.reflection-probe` | Unencoded reflection markers, bounded error-based SQLi differential | active |
| Authentication Probe | `builtin.auth-probe` | Username enumeration, missing rate limiting | active |
| Source Pattern Review | `builtin.source-scan` | Hardcoded credentials, weak crypto, SQL concat, eval, secrets in logs, log injection, TLS verify off | passive |
| Dependency Manifest Inventory | `builtin.dep-manifest` | Lockfile inventory, missing lockfile detection | passive |
| TLS Handshake Analysis | `builtin.tls-analysis` | Certificate expiry/self-signed/hostname, protocol version, legacy-TLS acceptance | passive |
| OpenAPI Design-Policy Review | `builtin.openapi-policy` | Spec exposure, operations without security requirements | passive |
| Authenticated Probe | `builtin.authenticated-probe` | Surface mapping, logout invalidation, JWT forgery, cross-role matrix | active |
| Open Redirect Probe | `builtin.redirect-probe` | Redirect parameter discovery, reserved marker host testing | active |
| GraphQL Probe | `builtin.graphql-probe` | Introspection exposure, playground discovery | active |
| JS Bundle Endpoint Discovery | `builtin.endpoint-discovery` | API route extraction from served bundles | passive |
| Variant Hunter | `builtin.variant-hunter` | Mutation fan-out from confirmed findings | active |

### Adapters (5)

| Engine | ID | License | Status |
|---|---|---|---|
| Semgrep (SAST) | `adapter.semgrep` | LGPL-2.1 | installed |
| Trivy (SCA) | `adapter.trivy` | Apache-2.0 | installed |
| Grype (SCA) | `adapter.grype` | Apache-2.0 | installed |
| Nuclei (templates) | `adapter.nuclei` | MIT | not installed |
| OWASP ZAP (DAST) | `adapter.zap` | Apache-2.0 | not installed |

### Python data plane

| Module | Purpose |
|---|---|
| `engine/rsec_engine.py` | JSON-RPC daemon: `http.get/post`, `recon`, `ping`, `shutdown` |
| `engine/rsec_corpus.py` | Corpus store, replay with diff, recursive SPA crawler |

---

## 4. Safety Invariants (I1–I10)

| # | Invariant | Enforcement |
|---|---|---|
| I1 | Single egress | All HTTP passes `httpClient.ts`; grep-enforced |
| I2 | Registered + approved scope | Scope guard on every request + redirect hop |
| I3 | Append-only audit | `audit_log` table; every state transition recorded |
| I4 | Evidence redaction | Headers + body patterns at capture and at render |
| I5 | No fabricated findings | Every finding = observation, advisory match, or labelled heuristic |
| I6 | Severity ⊥ confidence | Separate fields; confidence never adjusts severity |
| I7 | Stable fingerprint IDs | sha256(category|cwe|asset|locator) — stable across rescans |
| I8 | Unexecuted ≠ pass | `NOT_EXECUTED`, `ENGINE_UNAVAILABLE` states; never silently promoted |
| I9 | Reconstructible | Evidence + provenance on disk; JSON report round-trips |
| I10 | Loop terminates | Closure threshold + hard budget (iterations/requests/time) |

---

## 5. Autonomous Loop

```
for iteration in 1..maxIterations:
    if budget_exhausted or aborted: break
    candidates = planCandidates(model, mode, findings, executedSets)
    if candidates.empty: break (closure)
    action = decide(candidates)  # P(worth) × info_gain / cost
    result = act(action)         # engine call, probe, verify, or sub-scan
    verify(result)               # independent re-observation
    adapt(result)                # update model, dedupe by novelty
    audit(iteration, action, outcome)
```

**Closure:** no candidates exceed the novelty threshold.
**Budget:** maxIterations, maxRequests, maxMs — whichever hits first.
**Determinism:** fixed seed + budget ⇒ identical trace hash (tested).

### Capability Probe Gate

| Probe | Capability | Method |
|---|---|---|
| probe.http-server | `http.server` | corpus observation |
| probe.html-frontend | `frontend.html` | corpus observation |
| probe.spa-js | `frontend.spa` | corpus observation (scripts vs anchors) |
| probe.rest-openapi | `api.openapi` | GET /openapi.json |
| probe.graphql | `api.graphql` | GET /graphql?query={__typename} |
| probe.auth-form | `auth.form` | corpus observation |
| probe.session-cookie | `auth.session-cookie` | corpus observation |
| probe.cdn-waf | `edge.cdn-waf` | corpus header observation |
| probe.cloud-markers | `cloud.markers` | corpus observation |
| probe.websocket | `api.websocket` | corpus observation |
| probe.sitemap | `surface.sitemap` | GET /sitemap.xml |

---

## 6. Assessment Tasks (48 registered)

### A01 Broken Access Control (10 tasks)
| Task | Engine | Mode | Strength |
|---|---|---|---|
| T01 Sensitive info exposure | http-observation | passive | heuristic |
| T02 Admin/sensitive path exposure | path-probe | active | strong |
| T03 Object-access smoke probe (IDOR) | path-probe | active | heuristic |
| T04 Authenticated horizontal/vertical authz | manual | active | strong |
| T05 Sensitive data in URLs | http-observation | passive | heuristic |
| T06 Source map exposure | path-probe | active | strong |
| T07 Authenticated surface discovery | authenticated-probe | active | strong |
| T08 Open redirect probing | redirect-probe | active | strong |
| T09 GraphQL introspection exposure | graphql-probe | active | strong |
| T10 CSRF exposure (tokenless forms) | http-observation | passive | heuristic |
| T11 Cross-role authorization matrix | authenticated-probe | active | strong |
| T12 Undocumented endpoint discovery | endpoint-discovery | passive | strong |

### A02 Security Misconfiguration (8 tasks)
| Task | Engine | Mode | Strength |
|---|---|---|---|
| T01 Security headers | http-observation | passive | strong |
| T02 Cookie attributes | http-observation | passive | strong |
| T03 Software version disclosure | http-observation | passive | strong |
| T04 Directory listing | http-observation | passive | strong |
| T05 Exposed config/backup files | path-probe | active | strong |
| T06 CORS policy | http-observation | active | strong |
| T07 CSP quality analysis | http-observation | passive | strong |
| T08 GraphQL playground exposure | graphql-probe | active | strong |

### A03 Software Supply Chain Failures (7 tasks)
| Task | Engine | Mode | Strength |
|---|---|---|---|
| T01 Dependency inventory | dep-manifest | passive | strong |
| T02 CVE matching (Trivy) | trivy | passive | strong |
| T03 CVE matching (Grype) | grype | passive | strong |
| T04 Malicious package / pipeline review | manual | passive | strong |
| T05 SBOM review of deployed app | manual | passive | strong |
| T06 Exposed manifests on web target | path-probe | active | strong |
| T07 Vulnerable frontend library versions | http-observation | passive | strong |

### A04 Cryptographic Failures (7 tasks)
| Task | Engine | Mode | Strength |
|---|---|---|---|
| T01 Cleartext credential forms | http-observation | passive | strong |
| T02 Weak crypto in source | source-scan | passive | heuristic |
| T03 TLS certificate/protocol analysis | tls-analysis | passive | strong |
| T04 JWT handling observation | http-observation | passive | heuristic |
| T05 JWT forgery verification | authenticated-probe | active | strong |
| T06 HSTS absence | http-observation | passive | strong |
| T07 Mixed content | http-observation | passive | strong |

### A05 Injection (5 tasks)
| Task | Engine | Mode | Strength |
|---|---|---|---|
| T01 Unencoded reflection | reflection-probe | active | strong |
| T02 SQL concat / eval in source | source-scan | passive | heuristic |
| T03 Dynamic injection beyond bounded reflection | manual | active | strong |
| T04 GraphQL introspection | graphql-probe | active | strong |
| T05 Error-based SQLi differential | reflection-probe | active | heuristic |

### A06 Insecure Design (2 tasks)
| Task | Engine | Mode | Strength |
|---|---|---|---|
| T01 Design/threat-model review | manual | passive | strong |
| T02 OpenAPI design-policy signals | openapi-policy | passive | heuristic |

### A07 Authentication Failures (7 tasks)
| Task | Engine | Mode | Strength |
|---|---|---|---|
| T01 Username enumeration | auth-probe | active | strong |
| T02 Missing login rate limiting | auth-probe | active | strong |
| T03 Hardcoded credentials in source | source-scan | passive | heuristic |
| T04 Session lifecycle/MFA/password policy | manual | active | strong |
| T05 Session invalidation after logout | authenticated-probe | active | strong |
| T06 Secrets in exposed source maps | path-probe | active | heuristic |
| T07 Secrets in served JS bundles | http-observation | passive | heuristic |

### A08 Software/Data Integrity Failures (2 tasks)
| Task | Engine | Mode | Strength |
|---|---|---|---|
| T01 External scripts without SRI | http-observation | passive | strong |
| T02 Pipeline integrity (signing/provenance) | manual | passive | strong |

### A09 Logging & Alerting Failures (3 tasks)
| Task | Engine | Mode | Strength |
|---|---|---|---|
| T01 Server-side logging effectiveness | manual | passive | strong |
| T02 Logging hygiene in source | source-scan | passive | heuristic |
| T03 Log-correlation indicators on errors | http-observation | passive | heuristic |

### A10 Mishandling of Exceptional Conditions (1 task)
| Task | Engine | Mode | Strength |
|---|---|---|---|
| T01 Verbose error disclosure | http-observation | passive | strong |

---

## 7. Coverage Verdicts

Coverage is **evidence-based**, derived from task execution results — not labels:

| Status | Meaning |
|---|---|
| `COVERED_WITH_EVIDENCE` | All mandatory automated tasks for the profile executed successfully |
| `PARTIALLY_COVERED` | Some tasks executed, others pending/manual/unavailable |
| `MANUAL_REVIEW_REQUIRED` | All tasks are by-design manual |
| `NOT_ASSESSED` | Category has no tasks required by this profile |
| `ASSESSMENT_FAILED` | Required tasks attempted but all errored |

Legacy verdict mapping (backward-compatible): `covered`, `partial`, `manual-only`.

---

## 8. API Reference

All routes require `Authorization: Bearer <token>` except `/api/health`.

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Liveness + version |
| GET/POST | `/api/targets` | List/register targets |
| GET | `/api/targets/:id` | Target summary + latest scan |
| GET | `/api/targets/:id/model` | Tri-state model (nodes + deltas) |
| GET | `/api/targets/:id/diff` | Rescan diff (new/fixed/persistent) |
| POST | `/api/targets/:id/approve` | Approve target (audited) |
| POST | `/api/targets/:id/credentials` | Set test account (encrypted) |
| DELETE | `/api/targets/:id/credentials` | Remove test account |
| GET/POST | `/api/scans` | List/start scans |
| GET | `/api/scans/:id` | Scan detail + findings |
| GET | `/api/scans/:id/findings` | Findings only |
| GET | `/api/scans/:id/report?format=` | JSON/HTML/PDF report |
| GET | `/api/scans/:id/trace` | SSE live-trace stream |
| POST | `/api/scans/:id/cancel` | Cancel running scan |
| GET | `/api/profiles` | Available scan profiles |
| GET | `/api/engines` | Engine registry + availability |
| GET | `/api/owasp` | OWASP Top 10:2025 catalog |
| GET | `/api/audit` | Append-only audit log |

---

## 9. Scan Profiles

| Profile | Crawl Cap | Passive Engines | Active Engines | Target |
|---|---|---|---|---|
| `quick-passive` | 50 | crawler, observation, TLS, OpenAPI, endpoint-discovery | — | webapp |
| `standard-passive` | 200 | same | — | webapp |
| `standard-active` | 200 | same | path, reflection, auth, redirect, authenticated, graphql | webapp |
| `external-dast` | 200 | same | same + ZAP, Nuclei | webapp |
| `source-review` | — | source-scan, dep-manifest, semgrep, trivy, grype | — | source |

---

## 10. Testing

```bash
npm test                # 180/180 TS tests (unit + integration + e2e)
npx tsc --noEmit        # strict typecheck
python test/python/test_corpus.py  # 5/5 Python data-plane tests
```

### Test categories
| Type | Count | Coverage |
|---|---|---|
| Unit | 102 | Engines, safety, model, verify, evidence, scoring, continuous, coverage, adapters, reports |
| Integration | 14 | API auth, targets, scans, reports, engine failure, audit |
| E2E | 9 | Ground-truth recall/precision against vulnerable/hardened fixtures |
| Python | 5 | Corpus store, replay, recursive crawler, route extraction |

### Ground truth
`fixtures/vuln-app/truth.json` documents 12 planted vulnerabilities. The e2e suite asserts all 12 are detected (recall) and the hardened twin produces zero confirmed medium+ findings (precision).

---

## 11. Deployment

### Quick start
```bash
git clone https://github.com/ramuatnet/R-SecopsXD.git
cd R-SecopsXD
npm install
npm start                     # → http://127.0.0.1:7788
```

### Configuration
| Variable | Default | Purpose |
|---|---|---|
| `OWASP_HOST` | 127.0.0.1 | Bind address (non-loopback requires `OWASP_TOKEN`) |
| `OWASP_PORT` | 7788 | Listen port |
| `OWASP_TOKEN` | generated | Bearer token for API |
| `OWASP_ALLOW_PUBLIC_TARGETS` | false | Allow internet-facing targets |
| `OWASP_MAX_CRAWL_PAGES` | 30 | Override profile crawl caps |
| `OWASP_MAX_CRAWL_PAGES_EXPLICIT` | false | When set, overrides profile caps |
| `OWASP_RATE_RPS` | 5 | Per-target requests/second |
| `OWASP_DATA_DIR` | data | SQLite + evidence + tokens |
| `OWASP_LOG_LEVEL` | info | debug/info/warn/error |

### Optional external tools
| Tool | Install | Adds |
|---|---|---|
| Semgrep | `pip install semgrep` | SAST source analysis |
| Trivy | `winget install AquaSecurity.Trivy` | CVE advisory matching |
| Grype | `winget install anchore.grype` | CVE advisory matching (cross-verify) |
| Nuclei | Download from [releases](https://github.com/projectdiscovery/nuclei/releases) | Template-based scanning |
| OWASP ZAP | Download from [zaproxy.org](https://www.zaproxy.org/download/) | Full DAST active scanning |

---

## 12. Documentation Index

| Document | Content |
|---|---|
| `README.md` | Overview + quick start |
| `ARCHITECTURE.md` | Module map, data flow, invariants |
| `DECISIONS.md` | 9+ numbered ADRs with rationale |
| `THREAT-MODEL.md` | STRIDE + scan-abuse analysis |
| `CAPABILITY-MATRIX.md` | Per-category limits per engine/mode |
| `ACCEPTANCE.md` | 27 acceptance criteria mapped to tests |
| `TEST-RESULTS.md` | Recorded test runs (no fabricated claims) |
| `API.md` | REST API reference |
| `SETUP.md` | Installation, configuration, training-app demos |
| `LICENSES.md` | Dependency & content license inventory |
| `LIMITATIONS.md` | What the platform does NOT do |
| `BACKLOG.md` | Prioritized next steps |
| `automation_test_results.md` | Automation program test evidence |
| `manual_only_gap_analysis.md` | Gap analysis for automation program |
| `automation_architecture.md` | Autonomous loop architecture |
| `enterprise_expansion_assessment.md` | Enterprise expansion assessment |
| `remaining_manual_assessments.md` | What requires human review |
| `engine_coverage_matrix.csv` | All engines × tasks × statuses |
| `WORKLOG.md` | Build journal |

---

## 13. Known Limitations

1. **Automated scanning ≠ proof of safety.** A clean scan means "the executed engines found nothing they can see."
2. **Authenticated testing limited to 2 roles.** Deeper role matrices need additional test identities.
3. **No dataflow SAST.** `source-scan` is regex heuristics; real SAST requires the Semgrep adapter.
4. **Reflection ≠ XSS.** Marker reflection is the precondition; JS execution is not performed.
5. **No TLS cipher enumeration.** Handshake analysis covers certs/protocols; exhaustive ciphers need testssl.sh.
6. **A06/A09 manual-only for web targets.** Design and logging are not machine-observable.
7. **ZAP/Nuclei run outside the scoped client.** Scope enforced at entry URL; internal crawling trusted to ZAP.
8. **SPA crawling limited to JS bundle analysis.** No headless browser; DOM-rendered links not discovered.
9. **JSON login requires explicit configuration.** The platform doesn't auto-discover JSON login endpoints.
10. **Evidence redaction is pattern-based.** Unusual encoding could survive; review evidence before sharing reports.
