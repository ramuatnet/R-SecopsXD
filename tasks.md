R-SecopsXD v2 — Autonomous DAST + Cloud/ASM Assessment Platform
Master plan & agent build file. Target: convert R-SecopsXD (v0.1 linear VA/PT pipeline) into an autonomous, evidence-driven, black-box security assessment system with a Rust scan engine, recursive scans, corpus replay, variant hunting, finding verification, dynamic scoring, PoC/evidence, and internal + external attack-surface coverage.

Repo: https://github.com/ramuatnet/R-SecopsXD Plan date: 2026-10-28

0. How to use this file
This file is written for an agentic coder (opencode / zcode / Cursor-style). Place it at repo root as tasks.md (or PLAN.md).
Drive it with a system prompt such as:
"Execute tasks.md top to bottom. One task at a time. Run the task's acceptance test, then commit with message T<id>: <summary>. Never break the §1 invariants. Ask only when a decision is irreversible."

Order matters. Build the control loop (Phase 3) before the Rust port (Phase 4/12). The loop is the differentiator; Rust is the performance layer.
Status legend: [ ] todo · [~] in progress · [x] done · [!] blocked.
Progress log: 2026-10-29 — T9.1/T9.2 done (scheduler, origin change watcher, webhook delta alerting with alert-dedup). T10.3 done (SARIF 2.1.0 export). 2026-10-28 — T0.2 done (CI). T0.1 REDIRECTED: Python-first data plane (user decision — Python 3.14 stdlib asyncio; Rust migration deferred to T12). T1.1–T1.5 done. T2.1–T2.4 done. T3.1–T3.3, T3.5–T3.6 done. T3.4 partial. T0.4 done (TS EngineBridge + integration tests). T4.1-py done (Python HTTP parity: scope, per-hop redirects, rate limit, redaction, body cap, budget).
Every capability is "done" only when its execution path, evidence, and tests exist. No relabeling missing work as done.
1. Invariants (non-negotiable — regression-test these)
I1 Single egress. All engine HTTP passes one scoped client that consults: payload guard → scope check (every redirect hop) → rate limit → concurrency cap → redaction.
I2 Registered + approved scope before any packet to a webapp origin.
I3 Append-only audit of every state transition.
I4 Evidence redaction on capture AND at render.
I5 No fabricated findings. Every finding = deterministic observation, advisory match, or labelled heuristic, with re-verifiable evidence.
I6 Severity ⊥ confidence are separate fields.
I7 Stable fingerprint IDs across rescans (new/fixed/persistent diffing).
I8 An unexecuted check is never a pass; an unavailable engine never implies absence.
I9 Every finding is reconstructible from evidence + provenance on disk.
I10 The loop always terminates by closure or budget (no infinite loops).
2. Current-state analysis (what exists today)
R-SecopsXD v0.1 is a well-engineered, honest web-app VA/PT platform.

Stack: Node 24 + strict TypeScript, zero runtime deps, node:sqlite, loopback API + vanilla web UI + headless CLI. 17 engines (13 builtin + adapters for Semgrep/Trivy/Grype/Nuclei/ZAP), 48 evidence-based tasks, OWASP Top 10:2025 catalog with CWE mapping. 139–140 tests passing with ground-truth e2e against vulnerable/hardened fixture twins.

Genuine strengths to preserve:

Single network egress point; every finding reconstructible.
Severity/confidence separation; stable IDs; triage persistence.
Coverage verdicts that admit unavailability.
Explicit no-fabrication policy.
Self-declared limitations: no authenticated testing in v1; no dataflow SAST; no JS/DOM execution; no callbacks/OOB; no TLS protocol analysis; no cloud/ASM; capability-based (not result-based) coverage; single-operator.

3. Looping-structure review (exact, code-level)
Loop	Location	Type	Assessment
Engine plan	orchestrator.executeScan → for (const step of plan)	Linear single pass	Runs each engine once, sequentially. No re-planning, no feedback. A finding never changes what runs next.
Crawl	crawlerLite.run → while (queue.length > 0 …)	Bounded BFS	Safe (seen set, cap), but GET-only, href-only → blind to SPAs, POST-only flows, JS routes.
Redirects	httpClient.doRequest → recursive doRequest(hop+1)	Depth-bounded recursion	Clean; re-validates every hop; depth capped at 5.
Coverage	coverage.computeCoverage	Derivation loop	Observes engine records; no re-execution.
Missing loop types (the autonomy gap):

No control loop — no observe→orient→decide→act→verify→adapt cycle.
No fixpoint/closure loop — nothing repeats until new surface stops appearing.
No recursive scan — findings never spawn sub-scans.
No corpus replay — request/response pairs not persisted as replayable corpus.
No variant loop — a confirmed seed never fans out across siblings.
No verify loop — probable never promoted to confirmed by active re-test.
No continuous loop — manual one-shot scans; no scheduler/watcher.
Conclusion: the plumbing for a loop exists, but the loop itself does not. This is the single highest-value thing to build.

4. Gap analysis vs the target vision
Requirement	Current state	Severity
Autonomous assessment (decide next)	Linear plan	Critical
Understand observed architecture / evidence / exposure / context	Flat findings; no model	Critical
Don't assume API/browser/cloud/auth/stack; discover present/absent/unknown	Only target.kind	Critical
Dynamically adapt	Static profiles	High
Black-box testing	Shallow passive/active	Medium
Recursive scans	None	High
Corpus replay	None	High
Variant hunting	None	High
Rust scan engine	Node/TS only	High
Finding verification/validation	probable never confirmed	Critical
POC / evidence	HTTP excerpt only	High
Dynamic scoring	Static severity	High
Realtime security	No continuous mode	High
Cloud + internal/external ASM	Explicitly rejected	Critical
Enterprise (RBAC, multi-tenant, scale)	Single operator, SQLite	High
Improvement levers, ranked:

Build the agentic control loop + target knowledge graph.
Rust engine for concurrency, recursion, corpus, variants, verification.
A real verification stage: heuristics → confirmed findings with PoCs.
Break "webapp-only / registered-scope-only" into a discoverable capability matrix.
Continuous mode + dynamic scoring + cloud/internal surface.
5. Target architecture (v2)
┌──────────────────────────────────────────────────────────────┐
│  PLANNER / AGENT LOOP  (control plane, TS)                    │
│  Sense → Model → Decide(info_gain/budget) → Act               │
│       → Verify → Adapt  ↺ (fixpoint until closure or budget)  │
│  - Target Model (knowledge graph: assets, tech, caps, unknowns)│
│  - Capability Probe Gate (API? browser? auth? cloud?)          │
│  - Scheduler + budget governor + novelty/dedupe filter         │
└───────────────┬──────────────────────────────────────────────┘
                │ newline-delimited JSON-RPC (stdio or localhost)
┌───────────────▼──────────────────────────────────────────────┐
│  RUST SCAN ENGINE  (data plane)  engine/  →  rsec-engine      │
│  async HTTP/2 pool · raw sockets · recursion · corpus store    │
│  · mutation/variant fuzzer · OOB callback server · differ      │
│  · verification workers · evidence/PoC writer                  │
└───────────────┬──────────────────────────────────────────────┘
                │
   Evidence Store (append-only) · Target Model DB · Reports/API
Control plane (TS): planner, target model, capability gate, scheduler, reports, API/CLI/UI. Existing safety layer retained verbatim.
Data plane (Rust, engine/): rsec-engine daemon — the muscle.
Transport: versioned JSON-RPC over stdio (default) or localhost TCP; schema in engine/proto/.
Stores: Target Model DB (graph), Evidence Store (content-addressed, append-only), Corpus Store (replayable request/response pairs).
Compatibility: existing TS engines remain as legacy adapters behind the same Engine interface until ported (Phase 12), with parity tests.
6. The autonomous loop (spec)
loop:
  sense()        # recon + capability probes, update Target Model
  model()        # refresh graph: assets, tech, auth, caps, exposures, UNKNOWNS
  if closure() or budget_exhausted(): break
  action = decide()      # rank candidates by expected_info_gain / cost
  result = act(action)   # engine call; may enqueue recursive sub-scan
  verified = verify(result)   # active confirmation -> confirmed | rejected
  adapt(verified)        # update model, enqueue follow-ups, dedupe by novelty
Decision function: score = P(worth) * information_gain / estimated_cost, gated by safety + budget; deterministic tie-break.
Closure: stop when no action exceeds a novelty threshold, or N iterations, or budget (requests/time) is hit.
Every iteration emits an audit entry + model delta.
Determinism mode: fixed seed + fixed budget ⇒ reproducible loop trace (for CI and ground-truth scoring).
7. JSON-RPC protocol v1 (engine/proto/v1.md)
Transport: newline-delimited JSON, one object per line, over stdio (default) or localhost TCP. Every request carries id, method, params; every response carries id, result or error. All engine methods receive the same envelope:

{
  "id": "uuid",
  "method": "http.get",
  "params": {
    "scan_id": "uuid",
    "action_id": "uuid",
    "scope": { "origins": ["https://t.example"], "allow_public": false, "max_redirect_hops": 5 },
    "budget": { "max_requests": 500, "max_ms": 60000 },
    "safety": { "rate_per_sec": 10, "burst": 20, "max_concurrency": 8 },
    "args": { "url": "https://t.example/login" }
  }
}
Response:

{
  "id": "uuid",
  "result": {
    "findings": [ { "raw_id": "hdr.missing-hsts", "cwe": "CWE-319", "severity": "low", "confidence": "strong", "evidence_ref": "ev_01H…" } ],
    "model_deltas": [ { "op": "set", "node": "cap:api.rest", "value": "present", "provenance": "ev_01H…" } ],
    "evidence_refs": ["ev_01H…"],
    "stats": { "requests_sent": 1, "bytes_in": 842 }
  }
}
Methods:

ping
recon — passive surface discovery (headers, robots, sitemap, tech)
crawl — recursive crawl (HTML + JS routes + forms)
http.get / http.post / http.raw
probe — capability probe (single bounded request, flips unknown→present/absent)
fuzz.variants — mutation/variant fan-out from a seed
replay — deterministic corpus re-issue + diff
verify — independent confirmation of a candidate finding
oob.register / oob.poll — out-of-band callback tokens
tls — handshake/cert analysis
cloud.* — S3/GCS/Azure/IMDS/marker probes
shutdown
8. Task board
Phase 0 — Foundations
 [~] T0.1 Create engine/ workspace — REDIRECTED to Python (engine/rsec_engine.py); Rust port deferred to T12 (cargo new --lib rsec-engine; bins rsec-engine, rsec-probe). Crates: tokio, hyper + hyper-rustls, h2, reqwest (fallback), serde/serde_json, pest, regex, bytes, dashmap, tracing, anyhow/thiserror, clap, uuid, base64, sha2. Pin versions. Accept: cargo build clean; cargo clippy -D warnings clean.
 [x] T0.2 CI: GitHub Actions for TS (tsc --noEmit, npm test) + Rust (cargo test, clippy, fmt --check). Accept: green on PR.
 T0.3 engine/proto/v1.md (see §7) + serde structs. Accept: schema doc + structs compile.
 T0.4 TS EngineBridge: spawn/supervise rsec-engine, framed JSON-RPC, timeout, restart-on-crash. Accept: integration test round-trips ping + one http.get.
 T0.5 Trace correlation: scan_id + action_id propagated TS↔Rust. Accept: a scan yields one correlated trace.
Phase 1 — Target Model (understand present / absent / unknown)
 [x] T1.1 src/model/targetModel.ts: node/edge types — Asset, Endpoint, Param, Tech, AuthSurface, CloudHint, Capability, Unknown, Exposure. New versioned DB tables. Accept: CRUD + migration up/down tests.
 [x] T1.2 Tri-state knowledge: every capability field is present | absent | unknown (never assumed). Accept: fresh target has zero present, N unknown.
 [x] T1.3 src/model/merge.ts (mergeEvidence in targetModel.ts): idempotent evidence→model merge; conflict resolution (newer wins, provenance kept). Accept: replaying evidence twice = no diff.
 [x] T1.4 Delta emitter: each loop iteration writes a signed model delta. Accept: delta reconstructs model from empty.
 [x] T1.5 GET /api/targets/:id/model + UI view (graph + unknowns panel). Accept: API test; UI renders unknowns honestly.
Phase 2 — Capability Probe Gate (kill the "webapp assumed" bias)
 [x] T2.1 src/model/probeGate.ts: ordered, cheap, safe probes flipping unknown→present|absent for: HTTP server, HTML frontend, SPA/JS app, REST/OpenAPI, GraphQL, SOAP/WSDL, WebSocket, gRPC-web, auth (form/token/SSO), cookies/session, CDN/WAF, cloud markers (S3/GCS/Azure, IMDS, /.well-known), container/K8s markers. One bounded request each. Accept: fixture tests; a source-only target reports HTTP absent.
 [~] T2.2 Non-HTTP target kinds: api, source, cloud-account, cidr, container-image, k8s-cluster; extend TargetKind + gate branches. Accept: profile/target-kind matrix tests.
 [x] T2.3 "Absence is evidence" report section: what was probed-for and found absent, with the probe used. Accept: report snapshot test.
 [x] T2.4 Gate budget: max probes/iterations, all safety-gated. Accept: budget test.
Phase 3 — The Autonomous Loop (control plane)
 [x] T3.0 engine/proto/v1.md — protocol doc + implementation (v1 methods: ping/http.get/http.post/recon/shutdown) (§7). Accept: schema frozen + versioned.
 [x] T3.1 src/loop/planner.ts: candidate-action generation from the model (one generator per gap type). Accept: unit test per generator.
 [x] T3.2 src/loop/decide.ts: scoring P(worth)*info_gain/cost, safety + budget gated, deterministic tie-break. Accept: scoring unit tests.
 [x] T3.3 src/loop/loop.ts: sense→model→decide→act→verify→adapt with closure
budget governor + per-iteration audit + delta. Accept: e2e loop terminates by closure; asserts ≥1 adapt-driven follow-up.
 [~] T3.4 Recursion: act() may enqueue sub-scans (new scope roots) inheriting safety; depth + fan-out caps. Accept: nested-path fixture triggers sub-scan; caps enforced.
 [x] T3.5 Novelty filter: dedupe actions/results by fingerprint. Accept: repeated discovery doesn't re-queue.
 [x] T3.6 Determinism mode: fixed seed + budget ⇒ reproducible trace. Accept: two runs → identical trace hash.
Phase 4 — Rust Scan Engine (data plane)
 T4.1 Async HTTP client honoring I1: scope, per-hop redirect validation, rate limit, concurrency cap, redaction, capped body, raw evidence. Accept: Rust unit tests mirror TS httpClient tests 1:1.
 T4.2 Raw socket layer (smuggling, host-header, cache-poisoning primitives) behind http.raw. Accept: tests vs fixtures.
 T4.3 Corpus store: content-addressed req/resp pairs on disk, indexed by (method,url,param,hash). Accept: write/read + integrity test.
 T4.4 Replay: deterministic re-issue + status/header/body-hash diff. Accept: replay of vuln vs hardened fixtures flags the delta.
 T4.5 Recursive crawler (Rust): BFS + sitemap + JS-route extraction (regex + optional swc/oxc), form discovery, bounded. Accept: discovers routes a plain href crawl misses (SPA fixture).
 T4.6 Variant hunter: from a confirmed seed, fan out across sibling params/endpoints with mutation strategies (encoding, boundary, case, null/type). Accept: finds a variant where the base payload passes.
 T4.7 OOB callback server (oob.*): unique tokens, DNS + HTTP listener, correlate blind SSRF/injection/XXE. Accept: blind-SSRF fixture detected.
 T4.8 JS/DOM sandbox (headless) for DOM-XSS, postMessage, client authz. Accept: DOM-XSS fixture detected.
 T4.9 Resource governor: global semaphore + per-target token bucket in Rust, respecting control-plane budget. Accept: load test stays within caps.
Phase 5 — Verification & Validation (probable → confirmed)
 T5.1 src/verify/verify.ts: per-type validators; each actively re-tests with an independent method and emits confirmed | rejected | inconclusive + rationale. Accept: validator test per heuristic type.
 T5.2 Differential confirmation: baseline vs mutated, require causal delta (e.g., single-quote error differential for SQLi). Accept: FP fixture rejected, TP confirmed.
 T5.3 Promotion rules + audit; probable never silently becomes confirmed. Accept: promotion requires evidence ref.
 T5.4 FP-reduction: calibration, negative controls, multi-signal agreement. Accept: measured FP rate on hardened fixture < baseline.
Phase 6 — Evidence & PoC generation
 T6.1 Evidence Store (append-only, content-addressed, redacted) + refs on every finding. Accept: any finding reconstructs full request/response.
 T6.2 PoC writer: emit repro.sh / curl / raw HTTP for confirmed findings (deterministic, re-runnable). Accept: PoC reproduces in CI.
 T6.3 Minimal-reproducer minimization. Accept: minimized PoC reproduces; size reduced.
 T6.4 Attach model context to each finding (endpoint, tech, exposure, why it matters here). Accept: report shows context, not just payload.
Phase 7 — Dynamic Scoring
 T7.1 Scoring model: base severity × exploitability (verified? auth? reachable?) × exposure (internal/external) × context; keep raw fields. Accept: scoring unit tests; documented formula.
 T7.2 Risk trend over time from rescans; per-asset and per-category. Accept: trend test from seeded history.
 T7.3 Score explainability: every score lists its factors. Accept: report factor breakdown.
Phase 8 — Cloud + Internal/External Attack Surface
 T8.1 External ASM: subdomain/asset discovery (DNS, CT logs, cert SANs) feeding the model, with explicit scope-widening controls. Accept: fixture domain tree discovered.
 T8.2 Cloud provider probes: S3/GCS/Azure blob, IMDS, markers, misconfig. Accept: mock-cloud fixture checks.
 T8.3 Internal surface: CIDR target kind, host discovery, service/port fingerprint, HTTP upgrade. Accept: docker-compose internal fixture scanned.
 T8.4 Container/K8s: image scan (trivy/grype docker://), manifest misconfig, exposed K8s API. Accept: fixture manifests + image scanned.
 T8.5 Unified asset/identity graph across web + cloud + internal.
Phase 9 — Realtime / Continuous Security
 [x] T9.1 Scheduler: cron/interval + on-change (ETag/hash) watchers. Accept: scheduled scan fires; change triggers targeted rescan.
 [x] T9.2 Delta alerting: new finding → webhook/Slack/email with PoC + score. Accept: webhook test.
 [~] T9.3 Streaming scan progress (SSE/WS) to UI — trace available in loop result; SSE endpoint pending.
Phase 10 — Enterprise
 T10.1 Postgres driver behind repository interface (SQLite stays default).
 T10.2 RBAC + multi-tenancy (orgs, roles, per-target authz chains).
 [~] T10.3 SARIF export done (toSarif); CycloneDX SBOM + Dependency-Track push pending.
 T10.4 External KMS for credential profiles.
 T10.5 Horizontal scale: engine worker pool, job queue, resumable scans.
Phase 11 — Testing, Ground Truth, Benchmarks
 T11.1 Fixtures: SPA, GraphQL, cloud mock, internal net, blind-SSRF.
 T11.2 Precision/recall harness vs truth.json per profile; CI gate.
 T11.3 Fuzz redactor + parsers (proptest).
 T11.4 Loop-determinism CI gate (trace hash).
 T11.5 Benchmarks: requests/sec, loop iterations, coverage/time.
Phase 12 — Port & Retire
 T12.1 Port each builtin engine to Rust behind identical semantics; TS stays as reference oracle; parity tests must pass before retirement.
 T12.2 Retire TS engines only when parity + e2e are green.
9. Definition of done
All tasks [x] with passing acceptance tests; tsc, cargo test, clippy green.
No §1 invariant regressed (regression suite green).
Docs updated honestly: ARCHITECTURE, CAPABILITY-MATRIX, LIMITATIONS.
Every claim test-backed; unavailable paths visible in reports.
10. Anti-regression checklist (before every merge)
 Single egress enforced (grep for stray fetch/subprocess HTTP).
 Scope + payload guard on the hot path.
 Evidence redacted on capture AND render.
 Fingerprint IDs stable across a no-op rescan.
 Loop terminates by closure/budget.
 unknown never rendered as absent.
 PoC re-runs green in CI.
11. Ground truth & benchmarks
Extend fixtures/ with SPA, GraphQL, cloud mock, internal net, blind-SSRF, and a two-role auth fixture; each with a truth.json.
CI computes precision/recall per profile against truth; regressions fail the build.
Determinism gate: identical trace hash across two runs (fixed seed/budget).
Benchmarks tracked over time (requests/sec, iterations, coverage/time).
12. Risk register
Risk	Mitigation
Loop runs forever	closure threshold + hard budget + iteration cap (I10).
Autonomy fabricates findings	every action emits evidence; verify stage gates confirmation (I5).
Rust/TS drift	shared proto schema; parity tests before TS retirement.
Scope creep on external ASM	explicit scope-widening controls; per-origin approval.
FP explosion from variants	negative controls + multi-signal agreement (T5.4).
Safety regressions	invariant regression suite (I1–I10) as CI gate.
13. Suggested execution order
Phase 0 → Phase 1 → Phase 2 → Phase 3 (loop first) → Phase 4 → Phase 5 → Phase 6 → Phase 7 → Phase 8 → Phase 9 → Phase 10 → Phase 11 → Phase 12.

14. Appendix — crate & module map
Rust crates: tokio, hyper, hyper-rustls, h2, reqwest, serde/serde_json, pest, regex, bytes, dashmap, tracing, anyhow, thiserror, clap, uuid, base64, sha2, optionally swc_ecma_parser/oxc_parser, chromiumoxide (DOM sandbox).
TS new modules: src/model/*, src/loop/*, src/verify/*, src/engine-bridge/*, src/evidence/*.
Stores: Target Model DB (graph), Evidence Store (content-addressed), Corpus Store (replayable).
Preserved: src/safety/*, src/scan/httpClient.ts semantics, src/core/*, src/reports/* (extended with PoC + context + score factors).