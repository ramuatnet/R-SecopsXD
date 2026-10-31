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