# TASK-COMPLETION.md — consolidated completion record for all work orders

Status date: 2026-10-31. Branch: main. Latest commit: `82d71ef`.
Suite: **279/279** (`npm test`). CI: **green on GitHub runners** — latest:
https://github.com/ramuatnet/R-SecopsXD/actions/runs/41189922135

Work orders covered (in delivery order):

| Work order | Scope | Status |
|---|---|---|
| newtask.md | EASM maturity: infra recon, in-house Nuclei, asset graph, orchestration, risk | ✅ complete |
| hardtask.md | Corrective: port-detection correctness, verification honesty, supply chain, API/CI truth, real enrichment | ✅ complete |
| newtasks.md | E1–E6: engagement/RoE, exploit tier, retest, deliverable report, controls, escalation | ✅ complete |

The three task files deliberately excluded (and remain excluded): auto-remediation/PR generation,
multi-agent orchestration, Temporal/Kafka-native deployment (zero-runtime-dependency ADR), E4 SSH
at fleet scale, real-cloud E5, public OOB host. See LIMITATIONS.md.

---

## 1. newtask.md — EASM maturity (Phases A–F + wiring)

### Phase A — stop the bleeding (V1–V8) ✅
| Task | Delivered | Evidence |
|---|---|---|
| A1 port results as findings | Per-port `port-open` findings, exposure-class severity (info/medium/high) | unit: `portSeverity` classes; live: TNEB 443+80, htcnxt 443+80 |
| A2 engine ordering + honest skips | Verification stage before variant-hunter; `notExecutedReason` on empty surface | e2e AC12/AC16; unit guards |
| A3 asset-discovery retry | Parallel sources, hard caps ≤8s, public-resolver fallback (1.1.1.1/8.8.8.8/9.9.9.9) | unit `resolveWithFallback`; live 30.7s → 8s |
| A4 coverage honesty | `RAN_CLEAN` state — all-tasks-executed + zero findings never reads "covered" | unit coverage tests; AC21 |
| A5 endpoint-discovery | All crawled pages, extension-less module scripts, cap 16 | unit + e2e |

Issues found & fixed at this stage:
- **A-I1 (root cause of the original complaint)**: `normalizeLocator`'s `:\d+$` regex stripped
  `:port` from `ip:port` locators — every port on a host collapsed into one dedupe fingerprint.
  Fixed (strip only when the locator contains `/`), regression-tested.
- **A-I2**: TNEB's edge intermittently SYN-ACKs and answers HTTP block pages on every port —
  the "Elasticsearch 9200 high" was a middlebox artifact. Fixed with the zero-byte guard +
  uniform-response suppression (`port-scan-interference` finding).
- **A-I3**: variant-hunter was a no-op stub. Now a real mutation hunter with seeds from a
  dedicated verification stage.

### Phase B — in-house Nuclei (N1–N10) ✅
- 41 curated templates across 6 OWASP category dirs, each with `# source:` citation + CWE;
  `npm run lint:templates` gate (required keys, unique ids, matcher type+part, ≤3 requests,
  DSL allowlist, payload cap 40, pack-digest pin).
- Runner: per-template `-t`, capability gating from the crawl (`graphql` requires observed
  GraphQL surface), `-duc -jsonl -silent`, deny-listed tags.
- **Binary pinned**: nuclei v3.11.1, two-stage authenticity (published checksums.txt match +
  binary hash), fail closed. Verified live: our download matches the official
  `nuclei_3.11.1_checksums.txt` (`bb6cb9ff…`).
- Canary: parser mapping always; binary execution canary when installed.
- Live proof: positive control detects planted `.git/config` + `.env` with correct severity/CWE;
  clean fixture → zero false positives; external-dast scan found the real `/assets/` directory
  listing (CWE-548) on the vuln-app fixture.

### Phase C — unified asset graph (C1–C4) ✅
- Bitemporal graph store (nodes/edges closed-never-deleted), deterministic source-independent
  UIDs (`<type>:<base32(sha256(type|canonical))>`), OCSF-aligned NormalizedEvent pipeline with
  per-source adapters (EASM/scanner/DAST/CSPM), merger deduping on
  (class_uid, asset_uid, observable-hash) with raw-severity preservation, blast-radius query.
- Postgres deployment: `db/postgres/001_asset_graph.sql` applied to a live postgres:16 container
  (ltree + GIST); schema drift gate runs in CI via a postgres service container.
- Wired into scan finalize; live-validated (vuln-app scan → 18 nodes / 16 edges / 17 events,
  cross-scan dedupe proven).

### Phase D — orchestration (D1–D5) ✅
- SafetyGovernor live on the HTTP client: per-host buckets, gentle/normal/aggressive ceilings
  (100/500/2000 requests/scan via `OWASP_SCAN_PROFILE`), adaptive throttle on 429/503, kill
  switches, sensor circuit breaker. G2 load test: gentle throttles a 120-request burst to ceiling.
- Scope/approval gate (I13), six-topic bus (in-process + **Redpanda `KafkaHttpBus` adapter proven
  over a real broker**), AssessAsset 9-step state machine (retries + reverse compensation),
  trigger rules (web port → DAST plan; DB port → approval.gate, never auto-scan), dispatcher
  closing the discovery→action loop (approved targets only, 1h dedupe).

### Phase E/F — planner + risk ✅
- Fingerprint → capability → payload families (Tomcat → manager probes; databases alert-only);
  planner live in path-probe.
- Risk = Base × Reachability × Exposure × Criticality × Blast with every factor stored;
  spec worked example verified (identical CVE → 100 edge vs 4 isolated = 25×); noise rules
  (2-of-3 confirmation, EPSS backlog, CVE dedupe keep-max).

---

## 2. hardtask.md — corrective phases (H–N) ✅

### Phase H — port-detection correctness (P0) ✅
- H1: connect-with-no-protocol-answer = `open (unverified)` at info/low — quiet services
  (SSH/Redis) survive; middleboxes cannot inflate severity.
- H2: suppression threshold 8 + full-signature identity (status + headers + body); critical ports
  (22/443/3306/3389/5432/6379/9200/27017) never suppressed.
- H3: interference at low severity + "N ports suppressed" in scan detail.
- H4: truth.json grown (V13 port 8899); recall-floor test owns its listener.
- I16 counter-tests (8/8): silent listener → finding; 6 identical → reported; 8 identical →
  suppressed; differing status/headers survive; critical ports exempt; middlebox → zero phantom highs.

### Phase I — verification honesty (P0) ✅
- I1: auto-rejection tracking + `findTruePositiveRejections` guard (planted TP rejection detectable).
- I2: `rejected_by_verification` distinct from human `false_positive`.
- I3: `scoreAgainstTruth` harness; `quality` (recall/precision) in JSON **and HTML** reports.

### Phase J — supply chain (P1) ✅
- J1/I18: two-stage authenticity (published checksums.txt + binary hash), fail closed.
- J2: pack digest in every nuclei finding's provenance.
- J3: `templates/pack-version.json` pin — lint fails on drift (bump commit required).

### Phase K — API + CI truth (P1) ✅
- K1: `profile`/`profileId` both accepted; missing/unknown = 400, never silent default.
- K2: CI green on GitHub runners (multiple runs; latest in the header).
- K3: gate-negative step on the runner (plants a bad template, asserts lint blocks).

### Phase L — real enrichment (P1) ✅
- L1: offline CVSS/EPSS snapshot (12 advisories, dated) — CVE findings carry `base_source:
  epss|cvss` with real bases; severity fallback explicit.
- L2: reports take graph fan-out for blast; neutral only without graph data.
- L3: worked-example chain proven through the report pipeline.

### Phase M — capability unblocking (P2) ✅
- M1: credentialed SSH sensor (system ssh, read-only allowlist) — live container inventory
  (kernel/OS/port 2222/62 packages) merged with `credentialed` provenance.
- M2: TTL OS hypothesis via system ping (Windows host: TTL=128 → Windows) — the "impossible in
  Node" claim rescinded.
- M3: DDL drift gate — `001_asset_graph.sql` applied to a throwaway schema on the live
  postgres:16 **in CI** (service container); exactly three tables asserted.
- M4: OOB localhost callback mode proven end-to-end (confirmed critical blind-SSRF, CWE-918).

### Phase N — docs truthfulness (P2) ✅
- LIMITATIONS.md records every honest boundary; DoD distinguishes unit-tested vs live-verified.

---

## 3. newtasks.md — engagement, exploit tier, retest, reporting (E1–E6) ✅

### E1 — Engagement / RoE ✅
- Engagement entity (migration 008): scope, window, contacts, emergency stop, rate ceiling,
  permitted exploit classes, signer, attestation.
- Enforcement at the executor: window refusal (`blocked_by_roe`), per-scan rate-ceiling bucket,
  exploit-class gate; read-only default when no engagement registered (I19/I20).
- APIs: `POST /api/engagements`, `GET /api/engagements/:id`, `POST /api/engagements/:id/stop`
  (aborts in-flight scans in scope).
- Evidence: window refusal test, blocked-class test (counted, never silent), emergency-stop test.

### E2 — Exploit tier ✅
- `exploited` status above `confirmed` with first-class impact artefact (impact/reversibility/
  request count/observed delta) + transcript evidence (E2.3).
- Six per-class exploiters, each ≤3 requests, each reversible (I21): SQLi
  (`UNION SELECT version(), current_user`), SSRF (OOB canary), traversal (known-safe
  `/etc/hostname`), IDOR (unauthenticated re-fetch), XSS reflection (static unencoded proof),
  open redirect (canary follow-through).
- Safe-exploit payload allowlist (E2.4) — allowlist wins over destructive patterns.
- `exploit_unavailable` for unproven classes (E2.5).
- Evidence: inline-fixture e2e produces artefacts for all four HTTP-observable classes with
  baseline comparison; unavailable path proven on a clean fixture.

### E3 — Fix-triggered retest ✅
- `POST /api/targets/:id/retest` with locator filter (I22 — touches only the finding's locator).
- Same verifier re-observes: rejected → **fixed** (retest evidence persisted); confirmed →
  **regressed** (reopened, same severity); inconclusive → stays open.
- Debounce: 5 retests/hour/target — 11 rapid triggers produce ≤5 executions (E3.4).
- Evidence: dynamic fixture flipped to hardened → retest closes with evidence; unfixed stays open.

### E4 — Deliverable report ✅
- `report?format=deliverable`: client-ready HTML — scope & RoE table, methodology, findings
  ordered by risk (impact + PoC + evidence grade + exploit status + retest + control ids),
  coverage, and a **loud not-tested section**.
- `400 blocked_by_roe` without a signed engagement (signer + attestation required) — a stated
  reason, never an empty report.

### E5 — Compliance evidence mapping ✅
- Chapter-level ASVS/WSTG/PCI mapping per OWASP category;
  `report?format=evidence-pack` exports timestamps + retest status + coverage verdicts with
  control ids; unmapped categories surface as gaps.

### E6 — Human escalation queue ✅
- `POST /api/scans/:id/findings/:fid/escalate` (reason + context) and `GET /api/escalations`.
- Escalated findings are excluded from retest auto-close (verified: retest state unchanged).

---

## 4. Issues found and fixed during delivery (consolidated, by work order)

### newtask.md
1. **Locator normalizer collapsed ports** — `:\d+$` stripped `:port` from `ip:port`; fixed with a
   contains-`/` guard; regression test asserts two ports never share a fingerprint.
2. **Middlebox SYN-ACK artifacts** — zero-byte guard + uniform-response suppression.
3. **variant-hunter no-op** — verification stage + seed injection.
4. **nuclei v3 matcher trap** — `part: status` silently breaks status matchers; generator +
   linter fixed, pack regenerated.
5. **Lowercase `cwe-538`** — CWE parsing made case-insensitive.
6. **GraphStore attribute clobbering** — edge assertions re-upserted endpoint nodes with empty
   attributes; upsert now MERGES attributes/provenance.
7. **httpRecon hang on silently-filtered ports** — timeout must resolve the promise.
8. **Governor hard-refusal starved scans** — `acquireWait` (rate waits, ceilings refuse).

### hardtask.md
9. **Runner environment assumptions** — GitHub runners run a real sshd on 22 (never assert zero
   high findings; phantom = unverified claim with class severity) and nothing on 8899 (tests own
   their listeners).
10. **re.sub escape regression** — replacement strings re-interpreted `\\r\\n` into real newlines;
    span-based replacement used instead.

### newtasks.md
11. **Engagement scope must use the target ID** — name-based scope silently didn't match the
    window gate (caught by the refusal test).
12. **Open-redirect canary must survive redirect-following** — canary lives on the seed origin's
    own `/rsec-canary` path; landing there proves the redirect end-to-end.
13. **E6.3 assertion semantics** — escalated finding's retest state must be *unchanged*, not
    `undefined` (earlier retest rounds legitimately wrote evidence).
14. **RetestService scan selection** — latest completed scan *for the target*, not globally.

---

## 5. Verification summary

- **Test suite**: 279/279 (unit + integration + e2e; includes ground-truth recall/precision
  fixtures, recall floors, counter-tests for every suppression rule, egress audit).
- **CI**: GitHub Actions on every push/PR — postgres:16 service container (DDL drift gate +
  wire-protocol PoC execute on the runner), template lint + gate-negative step, typecheck,
  canary, full suite. Latest green runs:
  - https://github.com/ramuatnet/R-SecopsXD/actions/runs/41189922135 (E1–E6)
  - https://github.com/ramuatnet/R-SecopsXD/actions/runs/41181210447 (hardtask closing pass)
  - https://github.com/ramuatnet/R-SecopsXD/actions/runs/41180373200 (first fully green H–N run)
- **Live validations**: www.htcnxt.ai, TNEB (www.tnebnet.org), zmail.htcinc.com, vuln-app and
  hardened fixtures, dockerized sshd/Redpanda/Postgres.

## 6. Remaining items — external inputs only (documented, not faked)

1. **Temporal worker** — needs `@temporalio/sdk` (zero-dep ADR); AssessAsset state machine is the
   same workflow in-process.
2. **Kafka-native client** — the Redpanda HTTP-proxy adapter is the zero-dep path; a native
   protocol client would break the ADR.
3. **E4 at fleet scale** — vault-managed keys, many hosts (PoC proves one container).
4. **E5 against real cloud** — same code, needs IMDS/cloud-credential reachability.
5. **T4.7 public OOB host** — DNS + egress for blind-SSRF callbacks on public targets.
6. **L1 advisory snapshot refresh** — operational cadence (12 CVEs dated 2026-10-31).
7. **Postgres as primary store** — schema deployed and writable (stdlib wire client, trust-auth
   PoC); production needs SCRAM support or the `pg` driver (ADR decision).

## 7. Operational quick reference

- Server: `http://127.0.0.1:7788`, token in `data/auth-token.txt`, `OWASP_ALLOW_PUBLIC_TARGETS=1`
  for public targets, `OWASP_SCAN_PROFILE=gentle|normal|aggressive` for ceilings.
- Containers: `rsec-postgres` (:5433), `rsec-sshd` (:2224, key `.ssh-poc/`), `rsec-redpanda`
  (:9092/:8082), DVWA stack.
- Commands: `npm run lint:templates` · `node scripts/packDigest.ts --check` · `npm run canary` ·
  `npm test` · `npx tsc --noEmit`.
- Key finding IDs: `port-open`, `port-scan-interference`, `root-fetch-blocked`, `host-discovered`,
  `service-identified`, `os-hint`, `asset-ct-logs`, `zone-transfer-possible`, `variant-reflection`,
  `blind-ssrf-oob`, `rsec-*` (nuclei pack).
- New in E1–E6: `POST /api/engagements` · `POST /api/engagements/:id/stop` ·
  `POST /api/targets/:id/retest` · `POST /api/scans/:id/findings/:fid/escalate` ·
  `GET /api/escalations` · `report?format=deliverable` · `report?format=evidence-pack`.
