1. Foundations
1.1 Signed scope manifest
manifest_id: mf_01H...
signer: secops@example.com
valid: { from: 2026-11-01T00:00Z, to: 2026-11-08T00:00Z }
domains: [vwad.owasp.org]
cidrs: [203.0.113.0/28]
ports: { include: [80,443,8080,8443], exclude: [22] }
classes: [hygiene, tls, template, dast-safe]
flags:
  origin_discovery_authorized: false
  direct_origin_probing_authorized: false
kill_switch: global
Enforced at the bus ingress, not the scanner. Out-of-scope events are rejected with blocked_by_scope.

1.2 Shared-IP scope guard
Anycast IPs serve many tenants. Rule: on an IP classified edge, scan only the manifest-permitted ports and attribute to (hostname, vantage), never to the bare IP.

1.3 Vantage and surface
Every observation carries vantage ∈ {edge, origin, unknown}. Every finding carries surface ∈ {edge, origin, unknown}. Edge observations never become origin findings.

1.4 Degradation as a first-class outcome
Resolver denial, CT/whois/crt.sh failure ⇒ engine.degraded. Dependants ⇒ NOT_EXECUTED_DEGRADED(reason). Never clean.

2. Architecture
flowchart TD
  M[Signed scope manifest] --> B{Scope gate at bus}
  B -->|in scope| T1[(asset.discovered)]
  B -->|out| REJ[blocked_by_scope]

  T1 --> EC[Edge classifier<br/>quorum model]
  EC --> T2[(edge.classified)]
  T2 -->|edge| SP[Shared-IP guard<br/>proxied-port policy]
  T2 -->|direct| FP

  SP --> FP[Fingerprint + capability tags]
  FP --> PS[Payload selector<br/>preconditions]
  PS --> GOV[Governor: buckets/breaker/AIMD]
  GOV --> PR[Probe executor]
  PR --> VAL[Evidence + validation gate]
  VAL -->|pass| T3[(finding.validated)]
  VAL -->|fail| T4[(finding.suppressed)]
  VAL --> REC[Count reconciler]

  T3 --> G[(Asset graph<br/>bitemporal)]
  T3 --> TKT[Ticket if confirmed+threshold]
  G --> RISK[Incremental risk]
  G --> COV[Coverage ledger]

  ORIG[Origin resolver + verify<br/>Host/SNI compare] -.->|authorized only| T2
  GOV --> GS[(governor.signal)]
  PR --> DEG[engine.degraded]
2.1 Component responsibility matrix
Component	Owns	Must never
Scope gate	admission	touch network
Edge classifier	vendor+confidence	classify on one weak signal
Shared-IP guard	port policy on edge	port-scan beyond manifest
Fingerprint	tags+confidence	assert origin from edge data
Payload selector	probe choice	fuzz without preconditions
Governor	rate/backoff	crash the run
Validator	evidence gate	promote heuristics
Reconciler	count truth	let deltas go unexplained
Coverage ledger	honest state	call degraded "clean"
3. Topics and schemas
13 topics: asset.discovered, service.observed, edge.classified, origin.candidate, origin.verified, fingerprint.resolved, probe.requested, probe.completed, finding.candidate, finding.validated, finding.suppressed, engine.degraded, governor.signal.

Partition key asset_uid; idempotency key sha256(topic|asset_uid|probe_class|vantage); schema registry with BACKWARD compatibility.

// edge.classified v1
message EdgeClassified {
  string asset_uid = 1;
  string vendor = 2;            // cloudflare|akamai|fastly|cloudfront|azurefd|none
  float  confidence = 3;        // 0..1
  repeated Signal signals = 4;
  string feed_version = 5;
  bool   feed_stale = 6;        // true => DEGRADED
  string vantage = 7;
  int64  observed_at = 8;
}
message Signal { string kind = 1; string value = 2; float weight = 3; }
// probe.completed v1
message ProbeCompleted {
  string asset_uid = 1;
  string probe_class = 2;
  Outcome outcome = 3;          // canonical enum
  int32  inputs_used = 4;       // 0 => NO_OP_SUSPECT
  int64  duration_ms = 5;
  string vantage = 6;
  repeated string evidence_refs = 7;
}
enum Outcome {
  RAN_FINDINGS = 0; RAN_CLEAN = 1; SKIPPED_NOT_APPLICABLE = 2;
  SKIPPED_NO_CREDENTIALS = 3; NOT_EXECUTED_DEGRADED = 4;
  NO_OP_SUSPECT = 5; FAILED = 6;
}
4. Temporal workflow
@workflow.defn
class AssessAsset:
    @workflow.run
    async def run(self, req: AssessRequest) -> AssessResult:
        edge = await workflow.execute_activity(classify_edge, req, start_to_close_timeout=t(30))
        if edge.vendor != "none":
            await workflow.execute_activity(guard_shared_ip, req, edge)
        if edge.feed_stale:
            await workflow.execute_activity(emit_degraded, "edge_feed_stale")

        fp = await workflow.execute_activity(fingerprint, req, retry=3, backoff=2.0)
        plan = await workflow.execute_activity(select_payloads, fp, req.classes)

        results = []
        for step in plan.steps:                       # fan-out capped
            if self.depth > MAX_DEPTH: break
            results.append(await workflow.execute_activity(
                run_probe, step, retry=2, start_to_close_timeout=t(120)))

        val = await workflow.execute_activity(validate_batch, results)
        await workflow.execute_activity(persist_graph, val)
        await workflow.execute_activity(reconcile_counts, val)
        return val
Loop controllers: MAX_DEPTH=3, MAX_FANOUT=25, visited set keyed hash(asset, service, class, tech_version, vantage), TTL 15 min with heartbeat, per-scan budget ceiling, event dedupe, convergence stop on zero new nodes/edges.

Trade-off: Temporal gives durability and replay at the cost of an SDK dependency (against the zero-dep ADR). Recommend Temporal as a sidecar profile, not a replacement, until native clients are justified.

5. Fingerprinting
Ingestion takes TCP/IP stack features (TTL, window, options order, MSS) and banners. Confidence model:

conf = 0.35·stack_consistency + 0.30·banner_specificity
     + 0.20·vendor_corroboration − 0.40·edge_penalty
edge_penalty applies when vantage == edge: CDN terminates TCP, so TTL and window are the edge's, not the origin's. Edge-derived OS hints cap at candidate.

Capability mapper emits (tag, provenance, confidence): runtime:php, server:nginx, db:postgres, auth:jwt, api:graphql, edge:cloudflare.

6. Payload selector
Policy table with preconditions — the rule that stops blind fuzzing:

Family	Requires	Intensity
sqli-error	≥1 param	low
xss-reflect	≥1 param or form	low
traversal	param named file/path/page	low
graphql-introspect	api:graphql tag	low
jwt-tamper	auth:jwt tag + token observed	low
generic-hygiene	always	passive
No param and no form ⇒ SKIPPED_NOT_APPLICABLE with reason. Unknown stack ⇒ generic-hygiene only.

7. Safety governor (exists — extend)
Add: per-IP bucket stricter than per-host on shared edges; AIMD halving on 429/503, p95 > 3× baseline, or WAF signature; profile shift active→passive→discovery-only; governor.signal emission; resume after cooldown. WAF block pages detected by signature plus structural similarity to the block template, never recorded as evidence.

8. edgectx/ package
edgectx/
  detect/classifier.py      # weighted quorum
  detect/signatures/*.yaml  # versioned vendor packs
  detect/ipranges.py        # refresh job + staleness TTL
  suppress/rules/*.yaml     # declarative rules
  suppress/engine.py
  origin/resolver.py        # candidate + verify
  origin/verify.py          # Host+SNI compare
  models.py
8.1 Quorum rule
def classify(signals: list[Signal], feed) -> EdgeVerdict:
    score = sum(s.weight for s in signals if s.kind != "favicon")
    favicon = any(s.kind == "favicon" for s in signals)
    strong = sum(1 for s in signals if s.weight >= 0.30)
    if feed.stale: score *= 0.7
    if strong == 0 and not (favicon and score >= 0.5):
        return EdgeVerdict("none", score, signals)      # favicon alone never wins
    vendor = argmax_vendor(signals)
    return EdgeVerdict(vendor, min(score, 1.0), signals)
8.2 Suppression rules
# suppress/rules/cloudflare-proxied-ports.yaml
id: cf-proxied-http-8080
version: 3
when:
  edge.vendor: cloudflare
  edge.confidence: ">=0.75"
  finding.raw_id: port-open
  finding.port: [8080, 8443, 2052, 2082, 2086, 2095]
then:
  action: reclassify
  to: { category: informational, label: edge-proxy-behavior }
  reason: "Port in Cloudflare proxied set; terminated at edge, not origin"
audit: always
# suppress/rules/edge-unverified-service.yaml
id: edge-unverified-9200
version: 1
when:
  edge.vendor: { not: none }
  finding.raw_id: [port-open, service-identified]
  finding.port: { not_in: "$vendor.proxied_ports" }
then:
  action: downgrade
  to: { status: candidate, tag: edge-unverified }
  require: origin_verified_or_second_probe
8.3 Origin verification
Connect to candidate with correct Host and SNI; compare cert SHA-256, <title> hash, body SHA-256 and header set against the edge response. Match ⇒ origin.verified; mismatch ⇒ rejected. Human approves candidates before probing.

9. Validation and reconciliation
confirmed requires a reproducible artefact. Heuristics cap at candidate. "Management interface" needs a login page, admin banner, or panel marker — a 301 is never evidence. High severity needs a second independent probe (different shape or different edge IP).

Reconciliation record per scan:

{ "engine_totals": 21, "final": 16,
  "deltas": [ {"kind":"dedup","n":2,"why":"same service via 2 edge IPs"},
              {"kind":"suppress","n":3,"rule":"cf-proxied-http-8080"} ],
  "balanced": true }
Unbalanced ⇒ scan ASSESSMENT_FAILED.

10. Graph
Nodes: Domain, IP, Host, Port, Service, OS, WebApp, Certificate, CDN/Edge, OriginCandidate, Finding, CoverageGap. UID sha256(type|canonical) → base32. Edges carry vantage, surface, confidence.

MERGE (i:IP {uid:$ip_uid}) SET i.vantage=$vantage
MERGE (h:Host {uid:$host_uid})
MERGE (h)-[r:RESOLVES_TO {vantage:$vantage, observed_at:$ts}]->(i)
MERGE (e:Edge {uid:$edge_uid}) SET e.vendor=$vendor, e.confidence=$conf
MERGE (h)-[:FRONTED_BY {confidence:$conf}]->(e)
Risk multiplies reachability × exposure × criticality × blast × validated severity × confidence, with compensating controls and KEV/EPSS. Origin-only exposure scores higher than edge-only.

11. Coverage ledger
Worked example (vwad.owasp.org, edge-fronted static):

Category	Required tasks	Outcome	Verdict
A02	headers, cookie, methods, TLS	RAN_FINDINGS	partial (edge only)
A01	paths, IDOR, redirect	redirect SKIPPED_NOT_APPLICABLE	partial
A03	SCA	NOT_EXECUTED_DEGRADED (no bundle)	partial
A05	reflection	NO_OP_SUSPECT (1 ms, 0 inputs)	partial
A07	auth	SKIPPED_NOT_APPLICABLE (no form)	not_assessed
covered requires every required task RAN_* with valid inputs. Plus an explicit "origin not assessed" gap whenever surface is edge-only.

12. Reporting
Sections: Confirmed; Candidate/Needs review; Suppressed (reasons); Informational inventory with edge-proxy-behavior subsection; Coverage and limitations. Every finding labelled surface. Rescan diff: new / resolved / regressed / suppressed. One canonical model → JSON, HTML, PDF.

13. Test plan
Negative tests (mandatory): favicon alone must not classify edge; 9200 on edge must be candidate/edge-unverified; 301 on 8080 must not be a finding; WAF block page must not be evidence; stale feed must lower confidence and emit DEGRADED.

Golden fixture from vwad.owasp.org asserts: 8080/8443 management findings suppressed or reclassified informational; port-8080 medium not a vulnerability; header/HSTS capped Low/Medium; DNS/CT/whois failure ⇒ NOT_EXECUTED_DEGRADED; 1 ms reflection ⇒ NO_OP_SUSPECT; coverage not covered; counts reconcile.

Plus chaos (resolver failure, 429 storm, stale feed) and golden-file regression.

14. Trade-offs and risk register
Decision	For	Against	Mitigation
Aggressive suppression	kills noise	hides real exposure	every rule needs a negative test + analyst override with feedback
Active origin discovery	real backend truth	scope/legal risk, hits unapproved IPs	off by default, manifest flag, human approval per candidate
Edge-only scanning	WAF-mediated reality	misses origin-only flaws	always emit "origin not assessed"
Temporal/Kafka native	durability, scale	breaks zero-dep ADR	sidecar profile, opt-in
Favicon as signal	cheap	collides across sites	quorum rule
Human review stays mandatory: suppression-rule activation, origin-candidate approval, exploit-class enablement, severity-override sign-off, coverage-verdict override.

15. TASK MASTER
Completed work is not relisted. Only the delta.

P0 — stop the live FP (blocks release)
 EDGE-01 edgectx/detect multi-signal classifier + quorum rule. Accept: favicon-only does not classify; 2 weak signals do not; one strong signal does.
 EDGE-02 vendor signature packs + IP-range feed with staleness TTL and DEGRADED emission. Accept: stale feed lowers confidence and emits engine.degraded.
 EDGE-03 vantage on observations, surface on findings. Accept: edge observation can never produce surface=origin.
 EDGE-04 shared-IP scope guard: manifest port subset on edge IPs. Accept: edge IP with non-manifest port is not scanned.
 EDGE-05 suppression engine + Cloudflare proxied-port rule. Accept: 8080/8443 on Cloudflare → informational edge-proxy-behavior; 9200 → candidate edge-unverified; 301 alone never a finding.
 EDGE-06 severity calibration: static/form-less/unauthenticated caps header and HSTS at Low/Medium. Accept: fixture asserts the cap.
P1 — honesty
 HON-01 engine.degraded + NOT_EXECUTED_DEGRADED end-to-end.
 HON-02 NO_OP_SUSPECT when inputs=0 or duration < 5 ms.
 HON-03 coverage ledger rewrite over the canonical enum; covered needs all required tasks valid.
 HON-04 count reconciliation record; unbalanced ⇒ ASSESSMENT_FAILED.
P2 — origin
 ORIG-01 candidate resolver (manifest, supplied, authorized passive only).
 ORIG-02 Host+SNI verification with fingerprint compare.
 ORIG-03 human approval gate before origin probing.
 ORIG-04 origin-lockdown unreachable ⇒ coverage limitation, never clean.
P3 — platform
 PLT-01 13-topic bus + Avro/Protobuf schemas + registry.
 PLT-02 Temporal sidecar workflow replacing the in-process machine.
 PLT-03 suppression DSL + audit + review gate.
 PLT-04 Mermaid + responsibility matrix in ARCHITECTURE.
 PLT-05 vwad golden fixture + the five negative tests.
 PLT-06 edge-proxy-behavior report section; diff gains suppressed.
Added / removed against the project line
Added: EDGE-04 shared-IP guard (not in the brief, required by anycast reality); HON-02 no-op detection; ORIG-04 lockdown gap. Removed/deferred: native Kafka client (ADR holds, HTTP proxy sufficient); multi-CDN simultaneous classification (single-vendor first); ASN/BGP lookup (offline ASN table first, live BGP later).

16. Definition of done
Classifier with quorum; vantage/surface everywhere; Cloudflare 8080/8443 informational; 9200 candidate; header/HSTS capped; degradation visible; ledger honest; counts reconcile; golden fixture green; five negative tests green.

17. Risks
Over-suppression → negative test per rule, override + weight feedback.
Origin probing scope → manifest flag + human approval.
Feed staleness → TTL + DEGRADED, never silent.
Golden fixture drift → pin the fixture, regenerate deliberately.