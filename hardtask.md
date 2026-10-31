tasks.md — harden the Phase A–G delivery
Validation of HANDTASK.md (2026-10-31, commit range 93b4261→90de41e) against the platform's own invariants. Corrective tasks only — Phases A–G are largely real and the handover is unusually candid. But several "complete" claims rest on unit tests rather than live behaviour, and three fixes are precision/recall trade-offs that can hide vulnerabilities.

0. Validation verdict
Credit where due
A-I1 is the answer to the original complaint. normalizeLocator's :\d+$ regex was stripping :port off ip:port, collapsing every port on a host into one fingerprint. That is exactly why the TNEB scan reported no open ports. Correct diagnosis, correct fix.
A-I2 (middlebox SYN-ACK artifact) and A-I3 (variant-hunter was a no-op) are honest, non-obvious catches. B-I1–B-I4 show real debugging rather than assumption.
Section 5 DoD is met on paper; the suite grew to 253 with tsc clean.
What is weaker than the handover implies
#	Concern	Why it matters
W1	"zero-byte connect answers no longer count as open"	Real services (SSH, Redis, some MySQL) connect and stay quiet until a protocol prompt. Dropping them trades phantom ports for missed real ports
W2	"≥5 ports returning an identical response are suppressed"	A real host behind a load balancer can serve 5+ identical responses legitimately. Blanket suppression can erase true surface
W3	AC16 extended to permit false_positive seeds	If a planted ground-truth vuln gets auto-rejected, that is a recall bug being reclassified as correct behaviour
W4	E-I2 "TTL fingerprinting impossible in Node userspace"	True for node:net, but the repo ships a Python data plane and could shell out to ping. Claim is likely overstated
W5	F: "no CVSS data in the pipeline"	The headline 25× internal-vs-edge test is a formula unit test with synthetic CVSS, not a real CVE from a real scan. Risk base is severity-derived in practice
W6	N6 hash pinned from the same download	Pinning a self-computed hash proves stability, not authenticity. nuclei publishes checksums.txt; not compared against it
W7	C: Postgres schema verified by manual smoke test	001_asset_graph.sql is a design artifact — the app still writes SQLite and no test exercises the SQL
W8	G-I2 profile vs profileId	Wrong field silently defaults to standard-active; documented rather than fixed
W9	"ci.yml will fire on the next push"	CI is unproven; the # source: gate has never executed
W10	E4 "not implementable in stdlib"	Shelling out to system ssh is viable and would unblock credentialed checks
1. Invariants for this phase
I1–I15 hold. Add:

I16 No silent precision/recall trade. Any suppression rule must have a counter-test proving it does not drop a known-open port.
I17 Recall floor. Ground-truth true positives must never be auto-rejected; a rejection of a planted finding fails CI unless explicitly allow-listed with a reason.
I18 Provenance of supply chain. Pinned artefacts verify against a published checksum, not a self-computed one.
2. Tasks
Phase H — port-detection correctness (P0)
H1 Re-introduce zero-byte connects as open (unverified), then classify: after connect, wait a bounded interval for a banner; if none, send a protocol-appropriate nudge. Emit info with confidence: low rather than dropping. Accept: fixture with a silent TCP listener yields a finding; middlebox fixture still yields no phantom high-severity ports.

H2 Identical-response suppression: raise threshold to configurable (default 8), require identical status + body hash + header set, and never suppress ports in a curated critical list (22/443/3306/3389/5432/6379/9200/27017). Accept: 6-port identical fixture still reports ports; 33-port middlebox suppresses.

H3 Split port-scan-interference into its own severity band and surface the suppressed count in the scan detail. Accept: report shows "N ports suppressed".

H4 Recall-floor test: every port in fixtures/vuln-app/truth.json must appear as a finding on every run (I17). Accept: deleting a port from output fails CI.

Phase I — verification honesty (P0)
I1 Track auto-rejections per scan; if a ground-truth TP is rejected, fail with a diff. Accept: forcing verifyByType to reject a planted header finding fails the suite.

I2 Separate rejected_by_verification from human false_positive in the model so reporting does not conflate them.

I3 Publish a per-scan recall and precision number in the JSON report from the harness, so drift is visible without reading tests.

Phase J — supply chain (P1)
J1 Compare the pinned nuclei hash against the published checksums.txt for the release; fail closed on absence (I18).
J2 Record the template pack digest (sha256 of index.json + sorted template hashes) in every nuclei finding's provenance.
J3 Sign or pin the template pack version and require a bump commit for changes.
Phase K — API + CI truth (P1)
K1 Accept both profile and profileId; 400 on unknown profile instead of defaulting. Accept: {profileId: 'nope'} returns 400, not a silent standard-active scan.
K2 Land a green CI run on a GitHub runner; capture the run URL in the handover.
K3 Add a deliberate failing template (no # source:) to prove the gate blocks.
Phase L — real enrichment (P1)
L1 Offline CVSS/EPSS snapshot ingestion keyed by CVE; risk base uses real values, falls back to severity with an explicit base_source field. Accept: a finding with a known CVE carries base_source: epss and a non-synthetic base.
L2 Compute blastFactor from real graph fan-out during live scans; keep neutral 1.0 only when the graph has no edges for the asset. Accept: two assets, same CVE, differing fan-out ⇒ differing score from live data.
L3 Re-run the 25× worked example end-to-end through a scan, not just the unit test.
Phase M — capability unblocking (P2)
M1 E4 via shell-out to system ssh/ssh-keygen (read-only command set, bounded output). Accept: fixture container assessed with a key; patch level lands on the host node.
M2 TTL/OS: implement ICMP or UDP-probe TTL in the Python data plane; delete the "impossible" claim from docs if it works.
M3 Make 001_asset_graph.sql CI-tested against the postgres:16 container; fail on schema drift.
M4 OOB: localhost callback mode so internal targets are unblocked without public DNS.
Phase N — docs truthfulness (P2)
N1 Rewrite section 5 DoD to distinguish "unit-tested" from "live-verified".
N2 Correct E-I2 and E4 claims per M2/M1 outcomes.
N3 Record in LIMITATIONS.md that risk base is severity-derived until L1 lands.
3. Sequencing
H1 → H2 → H4 (stop the recall bleed) → I1 → I2 → I3 (make verification honest) → gate: recall floor green → J1 → K1 → K2 → K3 → L1 → L2 → L3 → M1 → M2 → M3 → M4 → N1 → N3.

Do not start L before I. A richer score on a shrunken finding set measures nothing.

4. Definition of done
Zero-byte and identical-response rules both have counter-tests; planted TP rejection fails CI; nuclei hash verified against published checksums; profileId no longer silently defaults; a green runner CI exists; risk base is real for CVE-bearing findings; recall and precision appear in every report.

5. Anti-regression
 No suppression rule without a counter-test (I16).
 Ground-truth TP never auto-rejected (I17).
 Pinned artefact verified against published checksum (I18).
 Unknown profile is a 400, never a default.
 Middlebox fixture still yields no phantom ports after H1/H2.
 Governor ceilings unchanged by any of the above.
6. Risks
H1 without H2 re-opens the phantom-port flood. Land them together.
Recall floors can be gamed by narrowing the fixture set; grow truth.json, never shrink.
Shelling out to ssh reintroduces subprocess handling — reuse the existing adapter tree-kill and timeout discipline, not a fresh spawn path.

tasks.md — exploit proof, RoE, retest, reporting
Derived from adv.md (SekurAI validation), scoped down. Deliberately excluded: auto-remediation / PR generation (AD-S3) and multi-agent role orchestration (AD-S8). Everything below works inside the existing single-loop engine.

0. Scope decisions
Dropped	Why it's out	Consequence
Auto-remediation (PRs)	needs repo host integration, branch strategy, patch-quality gates; large surface for marginal gain early	findings stay actionable, human writes the fix
Multi-agent orchestration	role handoffs add failure modes; the single loop already decides-next	keep one planner, add depth not roles
Kept, and why: authorisation model (E1) because exploit proof makes requests state-changing; exploit tier (E2) because confirmed is too weak to be a finding; retest (E3) because a fix that isn't verified is a guess; report (E4) because output must be usable outside the tool.

1. Invariants
I1–I18 hold. Add:

I19 State-changing is opt-in. A target with no permitted_classes runs read-only; exploit steps are gated per class, default off.
I20 Authorisation before action. No exploit step outside an active engagement window.
I21 Exploit reversibility. Every exploit step records what it changed and whether it is safe to repeat.
I22 Retest narrows, never widens. A retest touches only the finding's locator.
2. Tasks
E1 — Engagement / RoE model (do first)
Turn the boolean approved flag into a real authorisation artefact.

E1.1 engagement entity: scope[], window{start,end}, contacts{technical,emergency}, emergency_stop, rate_ceiling, permitted_classes[], signer, attestation_ref.
E1.2 Enforce at the executor: window check, class check, ceiling override. Violations record blocked_by_roe — never a silent skip.
E1.3 POST /api/engagements, GET /api/engagements/:id, POST /api/engagements/:id/stop.
E1.4 Emergency stop aborts all in-flight scans for the engagement within one loop iteration.
Accept: scan outside window refused with reason; class outside list recorded blocked_by_roe; stop halts a running scan within one iteration.
Risk: friction on first use — provide a read-only default engagement template.
E2 — Exploit tier
Promote confirmed to a demonstrated-impact tier. Bounded, reversible, per class.

E2.1 exploit status above confirmed; requires an impact artefact.
E2.2 Per-class exploiters, each ≤3 requests, each reversible: SQLi → version()/current_user; SSRF → canary fetch; traversal → read a known-safe file; IDOR → return a second principal's object; XSS reflection → marker execution proof (static); open redirect → 302 to canary.
E2.3 Impact statement template per class; exploit transcript stored as first-class evidence with request/response pair and observed delta.
E2.4 Payload guard gains a safe-exploit tier; anything above it stays confirmed and says so in the finding.
E2.5 Classes without an exploiter must not claim exploit — explicit exploit_unavailable reason.
Accept: each implemented class yields an impact artefact on a fixture; a class without exploiter reports the reason; reverting a fixture fix flips exploit to fail.
Risk: writes on the target (login attempts, IDOR fetches) — log every one.
E3 — Fix-triggered retest
E3.1 POST /api/targets/:id/retest with a locator filter, plus optional webhook (push) endpoint mapping changed paths → findings.
E3.2 Retest runs only matching findings, same engine + verifier, same evidence shape, tagged retest.
E3.3 Pass → fixed with retest evidence; fail → regressed, reopened at previous severity.
E3.4 Debounce: cap retests per target per hour; coalesce bursts.
Accept: retest of a fixed locator closes it with evidence; unfixed stays open; 11 rapid triggers produce ≤ configured cap.
Risk: retest storms — debounce is not optional.
E4 — Deliverable report profile
Second profile beside the technical one. Client-ready, unattended.

E4.1 report?format=deliverable — exec summary, methodology, scope/RoE, findings ordered by risk with impact + PoC + remediation, retest status, coverage and explicit not-tested section, appendix.
E4.2 Blocked without a signed engagement: clear reason, not an empty PDF.
E4.3 Every finding shows its evidence grade and exploit status.
Accept: renders from a completed scan with zero manual fields; missing RoE blocks with a stated reason; not-tested section lists unrun classes.
Risk: over-claiming — not-tested must be as loud as findings.
E5 — Compliance evidence mapping
E5.1 Map tasks/findings to a control set (ASVS, WSTG ids, PCI where applicable).
E5.2 Export evidence pack with timestamps, retest status, coverage verdicts.
Accept: coverage matrix carries control ids; export produces the pack; unmapped controls appear as gaps, not omissions.
E6 — Human escalation queue
E6.1 escalate flag on findings needing judgement (business logic, chained impact, ambiguous authz).
E6.2 Queue with context payload: asset, chain, evidence, why escalated.
E6.3 Escalated findings excluded from auto-close on retest.
Accept: escalation carries context; retest pass does not close an escalated finding.
3. Sequencing
E1 → E2 → E3 → E4 → E5 → E6

E1 before E2 is mandatory — E2 introduces state-changing requests. E3 before E4 because a deliverable claiming "fixed" needs retest evidence to exist first.

4. Definition of done
Engagement window and class list enforced at the executor; exploit transcripts with impact on every exploit-capable class; retest closes and reopens with evidence; deliverable report renders unattended and states what wasn't tested; control mapping exports; escalation queue works and blocks auto-close.

5. Anti-regression
 No exploit outside an active window (I20).
 Every exploit step records reversibility (I21).
 Retest touches only the filtered locator (I22).
 blocked_by_roe never renders as skipped or pass.
 Not-tested section always present in the deliverable.
 Loop still terminates by closure/budget.
6. Risks
State change on production — E1 gate + per-class opt-in + logged writes.
Exploit false confidence — an impact artefact that is actually the app's normal behaviour; require a baseline comparison before claiming impact.
Report theatre — a polished PDF over a thin scan reads as authority; keep the not-tested section prominent.
Retest scope creep — always filter by locator; never "just re-run everything".