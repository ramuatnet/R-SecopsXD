# Manual-Only Gap Analysis

Phase 1 output of the automation program (see docs/automation_architecture.md for the
design that closes these gaps). Baseline for this analysis: 2026-10-27, commit state
after v0.1.0 delivery + flag-specific cookie explanation fix. Baseline test suite:
82/82 pass (59 unit, 14 integration, 9 e2e).

## 1. Where manual-only status is assigned (exact code)

| Concern | Location | Mechanism |
|---|---|---|
| Capability map | `src/scan/coverage.ts` → `capabilitiesFor(engineId)` | Hardcoded engine→category map with `strength: strong\|heuristic` |
| Verdict derivation | `src/scan/coverage.ts` → `computeCoverage()` | `strong>0 → covered; heuristic>0 → partial; else manual-only` |
| Which engines run | `src/core/profiles.ts` → `PROFILES`, `enginePlan()` | Profile declares passive/active engine lists |
| Engine-run records | `src/scan/orchestrator.ts` → `executeScan()` | `EngineRunRecord[]` with `ran/unavailable/failed/skipped/cancelled` |

The current verdict is **capability-based** (an engine that can speak to a category
ran), not **evidence-based** (which declared tasks ran, what they found, what was
inconclusive). That is the central defect the automation program fixes. It also
cannot distinguish "engine ran clean" from "engine unavailable" — both leave
manual-only as-is, but with different implications.

## 2. Category-by-category gap inventory

Categories were marked manual-only in the baseline report for `htcnxt` (quick-passive):
A03, A05, A06, A07, A08, A09. A01 partial. Ground truth per category:

| Category | Existing engines (unused by passive profiles) | Genuinely missing capabilities | Automatable now (safe) |
|---|---|---|---|
| A01 | path-probe (admin/paths, object-access smoke — active only), reflection-probe | authenticated multi-role IDOR testing; route-variant probing | no (needs credentials — B1); object-access smoke exists in active profiles |
| A03 | trivy/grype/dep-manifest (source targets only) | SBOM for DEPLOYED web targets; lockfile discovery over HTTP (false-positive prone) | source targets: already automated. Web targets: correctly manual unless source is provided |
| A05 | reflection-probe (active), semgrep (source) | dynamic SQLi/commandi/NoSQLi probes (destructive-risk), blind injection | reflected-XSS/reflection already active; add bounded error-based SQLi *probe* (single-quote error differential) — low risk; everything else stays manual |
| A06 | — | OpenAPI/design-policy analysis; route-level authz matrix | partial: parse `/openapi.json`/`swagger.json` when exposed, flag securitySchemes gaps + unauthenticated operations (heuristic) |
| A07 | auth-probe (active: enumeration + rate limit) | session-expiry/logout testing, MFA validation, lockout behavior (needs creds) | auth-probe tasks already exist — passive profiles just don't run them; register them as active-mode tasks |
| A08 | — | SRI verification (HTTP, deterministic), CI/CD pipeline analysis, artifact signing | **SRI check: fully automatable passively** (implement now); CI/CD analysis needs source targets (source-scan rule addition) |
| A09 | — | server-side log inspection (fundamentally unobservable) | source targets: add logging-pattern rules to source-scan (missing log statements near auth, secrets in logs, log injection). Web targets: correctly manual |
| A10 | http-observation (errors) | — | already covered passively when error paths are crawled; add active error-path probes (already implied by reflection probe 500s) |

## 3. Conclusion

- 4 of the 6 manual-only categories already have **existing engines that simply are
  not part of passive profiles** (A01 active probes, A05 reflection, A07 auth-probe,
  A03 source adapters). Their fix is mostly in the task registry + profiles, not new code.
- 2 new **safe, deterministic capabilities** close real gaps: A08 SRI (passive HTTP)
  and A06 OpenAPI policy review (passive HTTP, heuristic). A09 gains source-mode rules.
- The remainder (authenticated A01/A07, blind injection, SIEM validation, pipeline
  integrity) is genuinely manual or credential-gated and must keep its honest status.
