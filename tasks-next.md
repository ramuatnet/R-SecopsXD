tasks-next.md — R-SecopsXD: wire the autonomy, close the gaps
Next-phase agent build file. This supersedes the remaining items of tasks.md. It is scoped to the verified state of the repo at commit b640223 (2026-10-29).

The single most important fact: the autonomous loop already exists and is unit-tested, but no real scan executes it. Phase W exists to fix that before any new capability is built. Do not add features on top of a dead code path.

0. How to use this file
Place at repo root as tasks-next.md. Drive with:
"Execute tasks-next.md top to bottom. One task at a time. Run the acceptance test, then commit T-<id>: <summary>. Never break the §2 invariants. If a wiring change makes a test fail, fix the test's premise before the code."

Phase W is strictly ordered. Do not start Phase X until W1–W5 are green.
Status legend: [ ] todo · [~] doing · [x] done · [!] blocked.
"Done" = execution path + evidence + passing acceptance test. A module that compiles but nothing calls it is not done.
1. Verified current state (read before coding)
Verified by reading source, not commit messages.

Built AND wired
Target model: src/model/targetModel.ts (tri-state, hash-chained deltas), migration 004.
Probe gate: src/model/probeGate.ts.
Loop, planner, decide, novelty, determinism: src/loop/loop.ts.
Verification: src/verify/verify.ts.
Evidence store, PoC writer, scoring, risk trend.
Scheduler, alerting, SARIF, CycloneDX, RBAC, SSE endpoint, ScanRepository.
180 TS tests + 5 Python tests.
Built but NOT wired (the dead-code ledger)
Module	Status	Evidence
src/loop/loop.ts (runLoop, planCandidates, decide, runSubscan)	orphaned	orchestrator.ts unchanged since initial commit; startScan → orchestrator.startScan → linear for (const step of plan); no import of runLoop anywhere in src/ except tests.
engine/rsec_engine.py + src/engine-bridge/bridge.ts	orphaned	registry.ts never instantiates the bridge; every engine uses the TS client.
probeHostHeaderInjection (rawProbes.ts)	imported, unused	imported in registry.ts, absent from create().
runLoop persistence	missing	loop returns findings in memory; never calls insertFindings, dedupeFindings, computeCoverage, or db.audit.
Loop budget config	missing	budget is a literal object in tests; no OWASP_LOOP_*.
Consequence
Every real scan still runs the v0.1 linear pipeline. Model, probe gate, verifier, and loop only run under unit test. Treat this as the primary defect.

2. Invariants (unchanged, regression-test)
I1 single egress · I2 approved scope every hop · I3 append-only audit · I4 redaction on capture+render · I5 no fabricated findings · I6 severity ⊥ confidence · I7 stable fingerprint IDs · I8 unexecuted ≠ pass · I9 reconstructible · I10 loop terminates by closure or budget.

Add:

I11 Linear fallback. If the loop throws, the scan must still complete via the linear path and record why, never fail silently.
I12 No orphan modules. Any module added to src/ must be reachable from server.ts or cli.ts; a dead import is a test failure.
3. PHASE W — Wiring (critical path)
T-W1 — Execute the loop from the scan lifecycle
 Add src/scan/loopRunner.ts: builds a LoopContext from the existing guard, client, stats, workDir, crawl, credentials; seeds a bounded crawl (reuse crawler-lite) so discoveredEndpoints is populated before iteration 1; calls runLoop; maps the trace to EngineRunRecord[]; runs dedupeFindings → insertFindings; computes coverage; audits every iteration.
 executeScan branches: use the loop when config.loopEnabled and target.kind === 'webapp'; otherwise the existing linear plan. Source targets keep the linear path.
 Wrap the loop in try/catch → on throw, run the linear plan and set scan.error = 'loop fell back: <reason>' (I11).
 runLoop must return enough for coverage: emit one record per executed action with ran|unavailable|failed|skipped; reuse computeCoverage unchanged.
Accept: e2e against fixtures/vuln-app with loop enabled shows a trace with ≥1 adapt-driven iteration, termination closure or budget, findings persisted, coverage non-empty. Forced loop throw falls back and completes.
T-W2 — Route the data plane through EngineBridge
 Instantiate EngineBridge in server.ts; add engine/rsec_engine.py methods crawl and replay if absent (corpus already exists in rsec_corpus.py).
 Add src/engines/adapters/dataPlane.ts implementing Engine over the bridge for crawl/corpus/replay; register as builtin.data-plane.
 runSubscan and the loop's crawl seed call the data plane, not the TS crawler, when the bridge is available; fall back to TS when not.
Accept: parity test — same fixture, bridge crawl and TS crawl return the same URL set; replay reproduces a stored response and diffs a mutated one.
T-W3 — Harden verifyFinding
 Replace excerpt-first-line matching with a per-type causal marker: header findings → the header name must be absent; cookie findings → cookie name; SRI/mixed-content → the integrity/http:// token; reflection → the marker; SQLi differential → the error signature.
 Return inconclusive when the finding has no type-specific marker (never promote on a body-line match alone).
 Append the re-check evidence ref on confirmed.
Accept: a header finding confirms only when the header reappears; a finding whose excerpt line is unrelated to its cause returns inconclusive.
T-W4 — Loop config + telemetry
 Add OWASP_LOOP_ENABLED (default 0), OWASP_LOOP_MAX_ITERATIONS (40), OWASP_LOOP_MAX_REQUESTS (800), OWASP_LOOP_MAX_MS (600000), OWASP_LOOP_SEED (0), OWASP_LOOP_SUBSCAN_FANOUT (3) to src/config.ts.
 Persist the trace incrementally to a scan_trace table (migration 005); write one row per iteration before the action runs.
 sseTrace reads scan_trace instead of diffing scan.engines.
Accept: SSE emits each action as it happens; budget values come from env.
T-W5 — Sub-scan and probe wiring fixes
 runSubscan uses the real triage map (pass it in, don't new Map()) and runs dedupeFindings over its findings before returning.
 Register probeHostHeaderInjection as a callable inside path-probe (or a builtin.raw-probe engine) and add it to the active plan.
Accept: duplicate sub-scan findings dedupe; host-header injection produces a finding on the fixture and is absent on the hardened twin.
4. PHASE X — Unbuilt plan items (only after W1–W5 green)
 T-X1 OOB callbacks (T4.7). DNS+HTTP listener, unique tokens, correlate blind SSRF/injection/XXE; oob.register/oob.poll. Accept: blind-SSRF fixture detected via callback.
 T-X2 DOM sandbox (T4.8). Headless execution for DOM-XSS, postMessage, client-side authz. Accept: DOM-XSS fixture detected.
 T-X3 Internal surface (T8.3). cidr target kind, host discovery, service fingerprint. Accept: compose fixture scanned.
 T-X4 Container/K8s (T8.4). Image scan, manifest misconfig, exposed API.
 T-X5 Unified asset graph (T8.5). Merge web + cloud + internal into the model.
 T-X6 KMS credential backend (T10.4).
 T-X7 Scale (T10.5). Job queue, worker pool, resumable scans.
 T-X8 Fixtures + benchmarks (T11.1–T11.5). SPA, GraphQL, cloud mock, internal net, blind-SSRF; precision/recall gate; loop-determinism gate.
 T-X9 Rust port (T12). Only after parity harness exists.
5. Definition of done
Every task [x] with its acceptance test green; tsc --noEmit + npm test green.
No invariant regressed; I11/I12 added and tested.
grep -r "runLoop\|EngineBridge" src/ shows the orchestrator and server, not only tests.
Docs updated: ARCHITECTURE, TECHNICAL, LIMITATIONS — loop is described as live.
6. Anti-regression checklist (before each merge)
 runLoop reachable from executeScan; linear fallback still works.
 Bridge failure degrades to the TS client, never crashes a scan.
 Verify never promotes on a non-causal marker.
 Loop terminates by closure/budget on every e2e run.
 unknown still never rendered as absent.
 No new orphan module (I12).
7. Sequencing
W1 → W2 → W3 → W4 → W5 → (gate: 180+ tests green, loop e2e deterministic) → X1 → X2 → X3 → X4 → X5 → X6 → X7 → X8 → X9.

8. Risk notes
Don't rewrite the orchestrator. Branch, don't replace — source scans and fallback depend on the linear path.
Don't delete the loop to "clean up." It is correct; it is just unplugged.
W2 before X1–X2. Callbacks and the DOM sandbox belong in the Python data plane, not the control plane.
Determinism is the gate. If W1's trace hash varies between identical runs, stop and fix before Phase X.