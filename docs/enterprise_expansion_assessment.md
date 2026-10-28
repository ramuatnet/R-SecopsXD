# Enterprise VA/PT Expansion — Repository Assessment & Coverage Matrix

Mandated pre-implementation assessment for the enterprise expansion program
(master development prompt). Scope: what the platform already implements vs what the
expansion spec requires, with honest status. **A capability is "implemented" only
when its execution path, evidence, and tests are demonstrated** (spec rule §2).

Assessment date: 2026-10-27. Baseline: 99/99 tests (76 unit, 14 integration, 9 e2e).

## Architecture summary (already inspected)

Entry: `src/server.ts` (composition root) + `src/cli/cli.ts`. Orchestration:
`src/scan/orchestrator.ts` → engine plan from `src/core/profiles.ts` → engines
(`src/engines/builtin/*`, `src/engines/adapters/*`) via single egress point
`src/scan/httpClient.ts` (scope guard, rate limiter, payload guard, redaction).
Persistence: `src/db/database.ts` (SQLite). Reports: `src/reports/*` (JSON canonical,
HTML, PDF). Coverage: `src/scan/coverage.ts` — evidence-based per-task statuses over
`src/core/tasks.ts` registry (26 tasks). Safety: `src/safety/*`.

## Spec-section → status matrix

Legend: ✅ implemented+tested · 🟡 partial (exists, gaps listed) · ❌ missing

| Spec section | Capability | Status | Where / gap |
|---|---|---|---|
| 3.1 Injection | SQLi/NoSQLi/commandi/SSTI/XXE dynamic probes | ❌ (by design) | destructive-risk payloads excluded by payload guard; reflection preconditions covered (A05-T01); expansion requires controlled safe probes |
| 3.1 Injection | SAST source patterns (SQL concat, eval, deserialization) | 🟡 | source-scan + semgrep adapter; no dataflow |
| 3.2 XSS/browser | Reflected XSS precondition (unencoded reflection) | ✅ | reflection-probe, e2e-verified |
| 3.2 XSS/browser | Clickjacking/framing controls | ✅ | X-Frame-Options header observation |
| 3.2 XSS/browser | CORS misconfiguration | ✅ (this increment) | http-observation active check: Origin reflection + credentials |
| 3.2 XSS/browser | Source-map exposure | ✅ (this increment) | path-probe: .js.map probing with sources-validation |
| 3.2 XSS/browser | Stored XSS, DOM XSS, postMessage, service-worker, browser storage | ❌ | needs JS execution/DOM analysis — manual or ZAP with DOM add-ons |
| 3.3 Server-side | SSRF (incl. CWE-918 task mapping) | 🟡 | unauthenticated surface probes only; blind SSRF needs callback infrastructure (backlog) |
| 3.3 Server-side | Open redirect | 🟡 | redirect hops validated for scanner scope; target-side open-redirect probing missing |
| 3.3 Server-side | Directory listing, backups, .env/.git, debug endpoints | ✅ | path-probe, e2e-verified |
| 3.3 Server-side | Request smuggling, cache poisoning, host-header injection | ❌ | requires crafted raw requests; not in safe default payload set |
| 4 Frontend secrets | Hardcoded credentials in source | ✅ | source-scan rule (CWE-798) |
| 4 Frontend secrets | Source-map secret/content analysis | 🟡 (this increment) | exposure detection now; content secret-scanning of fetched maps next |
| 4 Frontend secrets | Client-side authz decisions, bundled secret scanning | ❌ | needs JS bundle fetch+parse — backlog |
| 5 Authentication | Enumeration, login rate limiting, cookie flags, cleartext login | ✅ | auth-probe + http-observation, e2e-verified |
| 5.2 JWT | alg=none / missing-expiry observation | ✅ (this increment) | passive JWT header/payload decode on observed tokens |
| 5.2 JWT | Active signature/algorithm-confusion testing | ❌ (by design without creds) | requires authorized tokens; passive observation flags candidates |
| 5.3 Authenticated testing | Credential profiles, multi-role | ❌ | backlog B1 — the single largest gap |
| 6 IDOR/BOLA/BFLA | Object-access smoke probe | 🟡 | sibling-id probe (heuristic); full BOLA needs test identities |
| 7 API security | OpenAPI exposure + unauthenticated-operation signals | ✅ | openapi-policy engine |
| 7 API security | GraphQL/SOAP/WebSocket/gRPC adapters | ❌ | adapters sketched in BACKLOG |
| 8 Business logic | — | ❌ | human-in-the-loop by nature; workflow state machines are a backlog design item |
| 9 Infrastructure | TLS handshake analysis | ✅ | tls-analysis engine (this increment) |
| 9 Infrastructure | Cloud/IAM/container/K8s | ❌ | requires cloud credentials/infra access — correctly out of web-only scope (spec §9 agrees) |
| 10 Crypto/data | Weak primitives (source), cleartext transport, sensitive data in URLs | ✅/✅/✅ (this increment) | source-scan + http-observation |
| 11 DoS/resource | — | ❌ (by design) | destructive stress excluded; only rate-limit weakness observation exists |
| 12 Mobile | — | ❌ | optional module, backlog |
| 13 AI/LLM | — | ❌ | optional module, backlog; prompt-injection testing needs controlled harness |
| 14 Framework mapping | OWASP 2025 + CWE + WSTG refs per task/finding | ✅ | tasks.ts + findings references; ASVS/API-Top10/NIST layers sketched in backlog |
| 15 Evidence model | Stable IDs, provenance, severity⊥confidence, redaction, validation lifecycle | ✅ | core model + triage persistence |
| 15 Finding states | Task states incl. BLOCKED_BY_SAFETY, INCONCLUSIVE | 🟡 | registry defines them; BLOCKED_BY_SAFETY not yet emitted by any guard path |
| 16 FP reduction | Calibration (404 fingerprinting), flag-specific explanations, dedupe | ✅ | tested |
| 17 Safety | Scope guard, redirects, rate limits, payload guard, passive default, audit | ✅ | threat-model + tests |
| 18 Reporting | JSON/HTML/PDF with task-level evidence | ✅ | this increment extends task rendering |

## Increment implemented in this program step

1. CORS misconfiguration check (active: Origin reflection + credentials) — A02, CWE-942
2. JWT handling observation (passive: alg=none, missing expiry) — A04/A07, CWE-347/613
3. Sensitive data in URLs (passive) — A01, CWE-598
4. Source-map exposure probe (active) — A01, CWE-540

Each is registered as an assessment task, attributed by rawId, and unit-tested.
The remaining ❌ rows are NOT relabeled: they stay missing/manual until their
implementations exist and pass tests (spec rule §2, final acceptance condition).
