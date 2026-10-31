tasklist.md — validation, Nuclei build, and enterprise architecture
Scope: validate the current tool against a real scan, fix what the scan proves broken, build Nuclei template scanning in-house (no clone), and specify the production architecture for a unified EASM + CNAPP + DAST + active network platform.

Baseline evidence: scan 160fb8bf (TNEB, standard-active, 46 requests, 5 findings).

0. Validation — the scan is the proof
0.1 What the scan actually produced
46 requests. 5 findings. Of those: 1 confirmed (missing headers), 3 informational (CT names, SAN, IP resolve), 1 probable (rate limiting). Zero vulnerability-class findings. No open ports. No service versions. No CVEs. No OS.

This is the honest verdict: the tool is currently a header/hygiene checker with light recon, not a vulnerability assessment platform. Coverage says covered for A02 and A10, which flatters it.

0.2 Specific defects the run exposes
#	Defect	Evidence in the run
V1	Open ports discovered but never surfaced	builtin.host-infra: "scanned 33 ports/IP, 2 finding(s)" — no port finding appears in the table
V2	Engine ordering is wrong	variant-hunter: "no seed findings available (run verification first)" — it ran before verification produced seeds
V3	Probes run on empty input and burn 0 ms	reflection-probe 0 ms, redirect-probe 0 ms, endpoint-discovery 0 ms — no crawl surface reached them
V4	Endpoint discovery found nothing on a real site	"0 bundle(s) fetched; no API endpoints discovered"
V5	asset-discovery spends 30.7 s then reports failure of its own core function	"no DNS records enumerable (resolver denied or timed out); IP attribution unavailable; AXFR skipped" — 67% of total scan wall-clock for 2 info findings
V6	Auth-gated coverage silently skipped	authenticated-probe: skipped, no credential profile
V7	Coverage inflation	A02 "covered" with 10/10 tasks but only 1 finding; "covered" reads as done
V8	No fingerprint→exploit coupling	host-infra scanned ports but nothing consumed the result to select payloads
0.3 Root cause
The architecture is collect-then-report. Engines run a fixed list, findings land in a table, coverage is computed from engine labels. Nothing consumes an engine's output to change what runs next — except the loop, which only reorders pre-declared engines. Discovery has no downstream consumer, so port results die at the boundary.

That is the gap between "runs 17 engines" and "finds vulnerabilities."

1. Looping structure — current state
Loop	Where	Type	Verdict
Scan lifecycle	orchestrator.executeScan → runLoopScan | executeLinearScan	branch, single pass	wired, terminates correctly
Loop iterations	loop.runLoop for (iteration < maxIterations)	bounded, closure/budget	correct, deterministic
Crawl	crawlerLite while (queue)	bounded BFS	GET/href only
Redirect	httpClient.doRequest recursion	depth-bounded	fine
Port scan	internalScan.scanCidr nested for + batch	bounded	leaf node — feeds nothing
Missing loops:

Discovery→action loop. Ports/services must generate work items (DAST profile selection, template selection), not just findings.
Fingerprint→payload loop. Service/version must select the probe set.
Retry/backoff loop. asset-discovery timeouts should retry with a different resolver, not report failure once.
Cross-sensor loop. Internal sensor results must feed the external planner.
Until loop 1 exists, adding engines will not raise findings.

2. Nuclei — build fresh, no clone
2.1 Decision
Do not vendor or git clone nuclei-templates. Author a curated in-house template pack (templates/) plus our own runner integration. Reasons: clone drift, thousands of noisy/low-signal templates, uncontrolled code: templates executing on the scan host, and no review trail.

2.2 Build tasks
N1 templates/ tree by OWASP category + template.yaml schema (id, info, severity, tags, matchers, requires capability).
N2 Native runner: builtin.nuclei-engine invoking the pinned nuclei binary with -jsonl -duc -silent, -t templates/, per-template timeout, output parsed into RawFinding with rule id → CWE map.
N3 Template linter (npm run lint:templates): required keys, no duplicate id, matcher must have a part + condition, max 3 requests per template.
N4 Author 40 seed templates covering the gaps the scan shows: exposed .git/.env/backup variants, Tomcat/Spring/actuator defaults, GraphQL introspection, S3/GCS listing, default creds pages, CORS misconfig, source-map disclosure, verbose error signatures.
N5 Capability gating: template requires: [api.graphql] only runs when the probe gate marked that capability present (kills V3-class waste).
2.3 Backdoor / supply-chain validation
Threat: a template that exfiltrates, executes code, or a tampered binary.

N6 Binary integrity. Pin nuclei version + SHA-256; verify at startup; record version in every finding's provenance.
N7 DSL allowlist. Reject templates using code: unless reviewed; ban pre-condition with exec; cap payloads size.
N8 Egress audit. Test that a scan sends traffic only to the approved origin — capture with a sink and diff.
N9 Template review gate. Every template needs a # source: comment citing the public advisory/WSTG reference it derives from; CI fails without it.
N10 Canary scan. Nightly scan of a known-vulnerable fixture; a template that stops matching or starts matching everything is flagged.
3. Architecture — four dimensions
3.1 Unified asset graph + OCSF-style normalization
Store: Postgres with ltree + adjacency tables as the graph abstraction; Neo4j optional when traversal depth exceeds 4. Postgres first because it keeps one transactional store for assets, findings and evidence.

Node types: org, domain, subdomain, ip, host, port, service, os, webapp, api, endpoint, cloud_account, cloud_resource, iam_role, container_image, certificate, finding, evidence, sensor.

Edges: resolves_to, hosts, exposes, runs, member_of, assumes, trusts, reachable_from, derived_from, found_on.

UID scheme: deterministic, source-independent — sha256(type | canonical_identity) truncated + typed prefix (ip:, svc:, fnd:). Same asset from DNS, CT logs and a port scan collapses to one node.

Normalization (OCSF-aligned):

raw source record → adapter → NormalizedEvent {
  class_uid, activity_id, severity_id, time,
  asset_uid, source_uid, observables[], evidence_ref,
  confidence, first_seen, last_seen, provenance
}
Rules: one adapter per source (EASM, CSPM, DAST, scanner); adapters emit only NormalizedEvent; a merger dedupes by (class_uid, asset_uid, observable-hash) and merges provenance. Severity is stored raw and normalised — never overwrite the source value.

Bitemporal: every node and edge carries valid_from/valid_to and observed_at; nothing is deleted, only closed. Required for "was this exposed when we were breached".

3.2 Autonomous discovery & orchestration
Bus: Kafka (or Redpanda) topics: discovery.asset, scan.request, scan.result, finding.normalized, risk.changed, approval.gate.

Workflow: Temporal. Workflow AssessAsset — idempotent, replayable, resumable: resolve → fingerprint → classify exposure → select plan → safety gate → execute → normalize → score → notify. Each step has a retry policy and a compensation.

Trigger examples: new port edge → AssessService; new webapp node with exposure=edge → DAST plan; new iam_role with trusts: * → IAM review.

Safety guardrails (DoS / WAF):

Global + per-asset token buckets; separate budgets for discovery vs fuzzing.
Adaptive throttle: on 429/503 or latency p95 breach, halve rate and back off exponentially; never exceed the ceiling.
Scan profiles gentle / normal / aggressive with fixed request ceilings.
WAF detection → drop to gentle, cap concurrency 1, add jitter.
Scope gate: asset must be in an approved scope record; CIDR and domain expansions need explicit approval (I13).
Pre-flight: HEAD / + OPTIONS to confirm liveness before a full plan.
Kill switch per target and global; circuit breaker per sensor.
3.3 Scanning integration & fingerprinting
Sensors: stateless containers in three tiers — external (egress IPs), internal (one per VPC/subnet, no inbound), cloud-readonly (API credentials, no packets). All pull work from the bus; none hold credentials for targets except the scoped vault token.

Fingerprint pipeline (feeds payload selection):

TCP connect / SYN → TTL + window + options (stack profile) → banner per protocol → product/version → CPE → service node → capability tags

TTL and stack quirks give an OS hypothesis with a confidence; banner gives service/version. Output writes service and os nodes. The DAST planner reads those nodes to choose payload families (e.g. Tomcat → JSP/manager templates; PHP → .php traversal; GraphQL present → introspection set). This closes V8.

Credentialed vs uncredentialed: two distinct workflows. Uncredentialed = external view. Credentialed (SSH/WinRM/WMI) = read-only patch level, installed packages, local config; results merge into the same host node with provenance: credentialed. Cloud API metadata (image digest, patch baseline, IAM) merges by the same asset UID. Conflicts resolve to the credentialed value with the uncredentialed retained as history.

3.4 Context-aware risk prioritization
Formula (multiplicative, capped):

Risk = Base(CVSS, EPSS, VPR) × Reachability × Exposure × Criticality × Blast
Base — max(CVSS/10, EPSS×1.4, VPR/10), floored at 0.05
Reachability — 0.3 isolated · 0.7 same-VPC · 1.0 internet-reachable
Exposure — 1.0 edge/public ingress · 0.55 internal · 0.25 air-gapped
Criticality — asset tier 0.5–1.5
Blast — IAM/network fan-out from this node, capped 1.5
Final clamped 0–100; every factor stored and shown (explainability)
Worked example: identical CVE-2024-X, CVSS 9.8, EPSS 0.6.

Edge web server, public ingress, prod: 0.98 × 1.0 × 1.0 × 1.5 × 1.2 → ~98
Isolated internal CI box, no route, tier-2: 0.98 × 0.3 × 0.25 × 1.0 × 0.6 → ~4
Same CVE, 24× apart. That difference is the whole point of the graph — a flat CVSS list cannot express it, and that is why siloed scanners drown teams in noise.

Noise reduction: require 2 of 3 signals (advisory, banner-version, active confirmation) before confirmed; EPSS < 0.01 and unreachable ⇒ backlog; dedupe by (asset_uid, cve) keeping max score.

4. Task list
Phase A — stop the bleeding (fixes the observed scan)
 A1 Surface port results as findings (info for open, medium for risky-by-default ports, high for DB/management exposed to edge). Accept: fixture with open 22/3306 emits findings with asset linkage.
 A2 Fix engine ordering: variant-hunter after verification; probes require non-empty crawl surface or are recorded not-applicable not ran 0ms. Accept: trace shows order; empty-surface probes record a reason.
 A3 asset-discovery retry/backoff with resolver fallback; hard timeout below 8 s. Accept: resolver failure no longer costs 30 s.
 A4 Coverage honesty: covered requires ≥1 finding or explicit clean-evidence note; add ran-but-empty state. Accept: A02 no longer reads covered on headers alone.
 A5 endpoint-discovery: fetch scripts from all crawled pages, not just first; report bundles fetched. Accept: fixture SPA yields endpoints.
Phase B — Nuclei, in-house
 B1–B5 = N1–N5 above.
 B6–B10 = N6–N10 (integrity, DSL allowlist, egress audit, review gate, canary).
Phase C — graph + normalization
 C1 Postgres schema: nodes/edges/bitemporal + UID function.
 C2 NormalizedEvent type + adapters (EASM, scanner, DAST, CSPM).
 C3 Merger + dedupe + provenance.
 C4 Graph query API (traverse, blast-radius).
Phase D — orchestration
 D1 Bus topics + schemas. D2 Temporal AssessAsset workflow.
 D3 Safety governor (buckets, adaptive throttle, WAF backoff, kill switch).
 D4 Scope/approval gate. D5 Trigger rules (port→service, webapp→DAST).
Phase E — sensors + fingerprint
 E1 Sensor tiers + registration. E2 Stack/TTL/banner fingerprint → service/os nodes. E3 Planner consumes fingerprint for payload selection.
 E4 Credentialed SSH/WinRM read-only workflow. E5 Cloud metadata merge.
Phase F — risk
 F1 Scoring service with stored factors. F2 Internal-vs-edge differentiation test. F3 Noise rules. F4 Score explainability in reports.
Phase G — validation
 G1 Precision/recall harness per class. G2 DoS-safety load test. G3 Determinism gate. G4 Egress audit in CI.
5. Definition of done
Ports/services/CVEs surface as findings with asset linkage; Nuclei runs from in-house templates with verified integrity; every asset is one graph node regardless of source; identical CVE scores materially differently internal vs edge; no scan exceeds its budget; tsc + suite green.

6. Anti-regression
 No engine reports ran with zero input and no reason.
 covered requires evidence.
 Port/service results always reach a consumer.
 Template without # source: fails CI.
 Throttle halves on 429/503.
 UID stable across sources for the same asset.
7. Risks
Graph sprawl — cap node types, require an adapter per source.
Scan-induced DoS — governor before new engines, not after.
Template noise — 40 curated beats 8,000 cloned.
False CVEs from banners — version backports; keep medium confidence.
Scope drift — approvals mandatory for CIDR/domain expansion.