# HANDTASK.md — newtask.md handover: what was done, what was not, issues at each stage

Status date: 2026-10-31. Branch: main. Suite: **253/253** (`npm test`), tsc clean,
`lint:templates` OK, canary OK (parser + binary integrity). Commits in order:
`93b4261` (Phases A+B) → `3bfc0ec` (Phases C–F) → `cb7fb0b` (wiring) → `90de41e` (pending items).

---

## Phase A — stop the bleeding (A1–A5) — ✅ COMPLETE

### What was done
- **A1**: per-port findings (`port-open`, locator `ip:port`) with exposure-class severity —
  info for normal web ports, medium for risky-by-default app/dev ports (3000/5000/7001/8000/8008/
  8080/8081/8888/9000/9090), high for databases/remote-access/cluster APIs reachable at the edge
  (21/23/135/139/445/3389/5900/2375/2376/3306/5432/6379/6443/9200/11211/27017/5984).
  `host-resolved` locator changed to the hostname so it no longer dedupe-merges with `host-discovered`.
- **A2**: a verification stage (verifyByType + applyVerification, audited) runs BEFORE
  variant-hunter; seeds injected via `ctx.seedFindings`; variant-hunter became a real mutation
  hunter (`variant-reflection` findings) instead of a stub. reflection/redirect/endpoint-discovery
  return `notExecutedReason` on empty surface — "ran 0ms" is impossible now.
- **A3**: asset-discovery sources run in parallel with hard caps (CT 8s, DNS 6s, whois 6s) plus a
  public-resolver fallback chain (1.1.1.1 / 8.8.8.8 / 9.9.9.9).
- **A4**: coverage gained the `RAN_CLEAN` state — all-tasks-executed + zero findings never reads
  "covered"; the note states ran-but-empty explicitly; legacy verdict downgraded to partial.
- **A5**: endpoint-discovery scans bundles from ALL crawled pages, accepts extension-less module
  scripts, bundle cap 8→16.

### Issues identified at this stage
| # | Issue | Root cause | Fix |
|---|---|---|---|
| A-I1 | TNEB scan showed "16 findings" but only 2 in the table | `normalizeLocator`'s file-line-number regex (`:\d+$`) **also stripped `:port` from `ip:port` locators** — every port finding on one host collapsed into a single dedupe fingerprint | strip only when the locator contains `/`; regression test asserts two ports never share a fingerprint |
| A-I2 | A scan reported "Elasticsearch 9200 open (high)" on TNEB, then it disappeared next scan | **TNEB's edge intermittently SYN-ACKs (and answers HTTP block pages on) every probed port** — a middlebox artifact | zero-byte connect answers no longer count as open; ≥5 ports returning an identical response are suppressed and reported as one honest `port-scan-interference` finding. Direct probe confirmed 9200 closed; true surface is 443+80 |
| A-I3 | variant-hunter was a no-op ("run verification first") reading seeds from a hacky `ctx.crawl` channel | verification never ran in the linear path | dedicated post-loop verification stage + `seedFindings` context field |
| A-I4 | AC16 e2e broke after the verification stage | verified-rejected seeds legitimately carry status `false_positive` | AC16 invariant extended (audited rejection is correct platform behavior) |

### Not done
- Nothing. A1–A5 acceptance criteria all met and live-validated on TNEB (scan `caddc637`: 443+80
  only, no phantom ports, 8 honest findings).

---

## Phase B — in-house Nuclei (B1–B10) — ✅ COMPLETE (execution now live)

### What was done
- **N1/N4**: `templates/` pack — 41 curated YAML templates across 6 category dirs
  (sensitive-exposure, admin-consoles, api-surface, cors, default-credentials, verbose-errors),
  every template with `# source:` citation + CWE + `rsec` tag; `index.json` maps template →
  required capability.
- **N2**: adapter runs ONLY the in-house pack (per-template `-t`), `-jsonl -silent -duc -etags
  dos,fuzz,brute-force,intrusive,destructive`, rate limits; findings mapped to the standard model.
- **N3/N7/N9**: `npm run lint:templates` — required keys, unique ids, `# source:` gate, matcher
  type+part, ≤3 requests, DSL allowlist (no `code:`/javascript, payload cap 40), index consistency.
- **N5**: capability gating — graphql templates require observed GraphQL surface; unknown = skip (I8).
- **N6**: `templates/nuclei-pin.json` — nuclei **v3.11.1 pinned with SHA-256
  (73d5e5b0…49b480)**; adapter verifies version + hash at startup, fails closed on mismatch.
- **N10**: `npm run canary` — parser canary always; execution canary when binary + fixture present.
- **B2 execution**: nuclei v3.11.1 official release installed (no Go toolchain on host — release
  binary downloaded from GitHub, hashed, pinned, placed on PATH).

### Issues identified at this stage
| # | Issue | Root cause | Fix |
|---|---|---|---|
| B-I1 | Positive control (planted `.git/config`) produced **0 matches** through the real binary | nuclei v3 **silently breaks** status matchers that declare `part: status` — isolated by A/B template test | status matchers carry no `part:`; generator fixed, pack regenerated, linter exempts `type: status` from the part rule |
| B-I2 | CWE came through as `undefined` on real matches | nuclei emits `classification.cwe-id` **lowercase** (`cwe-538`); parser regex was case-sensitive | `/CWE-(\d+)/i` |
| B-I3 | Doc-comment glob `templates/**/*.yaml` terminated a `/* */` comment (`*/` inside) | shell/TS parsing | reworded comment |
| B-I4 | Windows path separators broke the linter's index comparison (`\` vs `/` in index.json) | `path.join` on win32 | normalize both sides to forward slashes |

### Not done
- Nothing within reach. ZAP remains honestly unavailable (not installed) — recorded per scan.

---

## Phase C — graph + normalization (C1–C4) — ✅ COMPLETE

### What was done
- Closed vocabularies: 19 node types, 10 edge types (`src/graph/types.ts`).
- Deterministic source-independent UIDs: `<type>:<base32(sha256(type|canonical_identity))>`
  (`src/graph/uid.ts`) — the same asset from DNS, CT and port scans collapses to one node.
- Bitemporal GraphStore over SQLite (migration 007): upserts idempotent per (type, identity);
  `valid_from`/`valid_to`/`observed_at`; **nothing deleted, only closed**; re-observation re-opens
  while history is retained; bounded traverse + fanout.
- NormalizedEvent pipeline (OCSF-aligned) with one adapter per source family — EASM, scanner, DAST,
  CSPM (routing by provenance engine; cloud-bucket by rawId).
- Merger/EventStore: dedupe key `(class_uid, asset_uid, observable_hash)`; **raw severity of the
  first source is never overwritten**; normalized severity ratchets up; provenance merges;
  `times_seen` counter.
- Blast-radius query (`src/graph/query.ts`) + sync seam wired into scan finalize (never breaks a
  scan; audited as `graph.synced`).
- **Postgres deployment**: `db/postgres/001_asset_graph.sql` (ltree adjacency + GIST, partial
  open-edge indexes, recursive blast-radius CTE) — applied cleanly to a postgres:16 container
  (`rsec-postgres`, localhost:5433); dedupe unique index and FK verified by insert/reject smoke test.

### Issues identified at this stage
| # | Issue | Root cause | Fix |
|---|---|---|---|
| C-I1 | Node 24 strip-only TS rejects parameter properties (`constructor(private x)`) | known runtime limitation | explicit field declarations everywhere (recurred in Phase D's TokenBucket) |
| C-I2 | `exactOptionalPropertyTypes` rejected explicit `undefined` on optional fields | strict config | `T \| undefined` unions and conditional spreads |
| C-I3 | node:sqlite row casts fail strict TS (`Record<string, SQLOutputValue>` → typed row) | sqlite typing | `as unknown as Row[]` bridge |
| C-I4 | `Finding` carries `detectedAt`, not `firstSeen/lastSeen` | adapter assumed otherwise | adapters use `detectedAt` |

### Not done
- The app still **writes to SQLite**; the Postgres deployment proves the schema but no pg driver is
  implemented (that was T10.1 from the earlier program — needs a driver, which the zero-runtime-dep
  constraint currently forbids; a thin `pg` exception would be an explicit ADR decision).

---

## Phase D — orchestration (D1–D5) — ✅ COMPLETE (in-process deployment)

### What was done
- **D3 SafetyGovernor**: global + per-asset token buckets; gentle/normal/aggressive profiles
  (1/5/20 rps per asset; 100/500/2000 request ceilings per scan; `OWASP_SCAN_PROFILE`); adaptive
  throttle (429/503 or >3s latency halves the rate with exponential backoff, 10% recovery on
  success); kill switch per target + global; per-sensor circuit breaker (3 failures → open 60s).
  **Live on the scan path** via a `GovernorBinding` on `ScopedHttpClient`.
- **D4 ScopeGate**: explicit approval records for domains/origins/CIDRs (I13); subdomain covered by
  approved parent; approval recorded authoritatively at `startScan`.
- **D1 Bus**: six canonical topics with typed envelopes; in-process pub/sub now; Kafka/Redpanda
  maps 1:1 later.
- **D2 AssessAsset**: 9-step state machine (resolve → fingerprint → classify → plan → safety-gate →
  execute → normalize → score → notify), retry 3×/200ms, reverse-order compensation on abort,
  governor-bound safety-gate step. Temporal port = one activity per step.
- **D5 triggers + dispatcher**: port-open findings evaluate trigger rules; `ScanRequestDispatcher`
  auto-starts scans for approved registered targets only — never while a scan is active for that
  target, never more than one per hour per target; DB/management ports and unapproved origins emit
  `approval.gate` and are never auto-scanned.

### Issues identified at this stage
| # | Issue | Root cause | Fix |
|---|---|---|---|
| D-I1 | **Governor hard-refusal starved active scans** — e2e AC12 failed with 5 ground-truth probes "missed" because rate-bucket refusals returned blocked results | `acquire` refused instead of waiting | `acquireWait` (bounded 30s): rate-limit refusals WAIT; kill switch / scan ceiling / breaker refuse hard. DoS-safety preserved via ceilings, which the G2 load test proves |
| D-I2 | Loop-runaway risk in the closed loop (scan → port finding → trigger → scan) | naive subscriber | active-scan check + 1h per-target window; non-web ports (e.g. 8899) correctly produce no scan request at all |
| D-I3 | Route-handler wrapper for scope approval fought the router types | wrong integration point | scope approval moved into `startScan` (authoritative: a started scan = approved scope) |

### Not done
- **Kafka/Redpanda + Temporal deployment** — the zero-runtime-dependency constraint (ADR D1) rules
  out a JavaScript Kafka client; the in-process bus and state machine are drop-in compatible when
  the constraint is relaxed or a sidecar bridge is deployed. Not faked.

---

## Phase E — sensors + fingerprint (E1–E5) — ✅ E1 registration + E2/E3 COMPLETE

### What was done
- **E3 planner**: fingerprint → capability tags → payload families (Tomcat → manager paths +
  `rsec-tomcat` templates; PHP/GraphQL/Elasticsearch/Docker/K8s each mapped; databases/SMB/RDP/VNC
  **alert-only — zero probes**; unknown → generic pack only, I8). Wired LIVE into path-probe
  (product from crawl Server/X-Powered-By headers; verified: `insecure-express-clone → families
  [node], +2 paths`).
- **E2**: `os-hint` findings become `os` graph nodes with `ip runs os` edges (banner-derived,
  low confidence by design).
- **E1 registration half**: `SensorRegistry` — three tiers (external / internal / cloud-readonly)
  with validation, capability declaration, heartbeats (5-min staleness), claim counting,
  capability-based pick (round-robin by claims), and each sensor becomes a `sensor` graph node.

### Issues identified at this stage
| # | Issue | Root cause | Fix |
|---|---|---|---|
| E-I1 | "database family is alert-only" test failed initially | database family still had an engine attached | engines:[] for non-HTTP families |
| E-I2 | TTL-based OS fingerprinting is impossible in Node userspace | no raw-socket IP header access | honest banner-derived hints only; TTL heuristic confined to the CIDR internal-scan path where hop count is ~0 |

### Not done
- **E1 deployment half** (actual sensor containers per VPC/egress) — needs hosting infrastructure.
- **E4 credentialed SSH/WinRM read-only workflow** — needs target credentials + reachability; an
  SSH client is also not implementable within the zero-dep constraint.
- **E5 cloud metadata merge** — needs cloud API credentials.

---

## Phase F — risk (F1–F4) — ✅ COMPLETE

### What was done
- `src/risk/risk.ts`: Risk = Base × Reachability × Exposure × Criticality × Blast, clamped 0–100,
  **every factor stored**. Base = max(CVSS/10, EPSS×1.4, VPR/10) floored 0.05.
- Spec worked example verified as a permanent test: identical CVE (CVSS 9.8, EPSS 0.6) →
  **100 at the edge vs 4 on an isolated internal box (25×)**.
- Noise rules (F3): `confirmationGate` (2-of-3 signals), `isBacklog` (EPSS<0.01 + unreachable),
  `dedupeCveObservations` (keep max score per (asset, cve)).
- Explainability (F4): every finding in the JSON and HTML reports carries its risk object (score,
  band, five factors, confirmation signals, backlog flag) + `riskSummary` bands. `src/risk/attach.ts`
  computes severity-based base (no CVSS data in the pipeline — stated in the code), public/internal
  exposure via `isPublicTarget`, and neutral blast (1.0) when no graph fan-out measurement exists.

### Issues identified at this stage
| # | Issue | Root cause | Fix |
|---|---|---|---|
| F-I1 | Internal box scored 16–20 instead of the spec's ~4 | the spec's "isolated internal CI box" uses exposure **0.25 (air-gapped)**, not 0.55 (internal) | worked example corrected to the spec's exact factors |
| F-I2 | Blast factor didn't reproduce the spec's 0.6@fanout-1 and 1.2@fanout-4 | first formula was linear in log with wrong intercept | log-fit `0.155 + 0.445·log2(1+fanout)`, capped 1.5 |
| F-I3 | Report-only risk scored critical findings ~14 (too low) | blastFactor(0)=0.155 applied when no graph fan-out exists | neutral 1.0 when fan-out unknown; graph-derived factor when measured |
| F-I4 | Float equality assertion failed (`9.8/10`) | IEEE representation | approx comparison |

### Not done
- EPSS/CVSS enrichment needs an advisory-data source (offline list exists for services; per-CVE
  EPSS would need a feed). The risk model degrades honestly to severity-based base.

---

## Phase G — validation (G1–G4) — ✅ COMPLETE

### What was done
- **G1**: `precisionRecallByClass` — per-class P/R/F1 harness with tests.
- **G2**: governor load test — gentle profile throttles a 120-request burst to the ceiling; blocked
  requests are honest; counters exact; kill-switch immediate.
- **G3**: determinism gate — planner output, trigger decisions and UIDs proven byte-stable.
- **G4**: `.github/workflows/ci.yml` — lint:templates → tsc → canary → full suite on push/PR
  (template without `# source:` fails the gate; the nuclei argv egress audit runs inside the suite).

### Issues identified at this stage
| # | Issue | Root cause | Fix |
|---|---|---|---|
| G-I1 | Source-review e2e timed out at 90s under host load (Docker Desktop starting) | semgrep/trivy legitimately take ~76s idle, longer loaded | `waitForScan` budget 90s→180s |
| G-I2 | **API gotcha**: `POST /api/scans` takes `profile`, NOT `profileId` — the wrong field silently defaults to standard-active | handler field name | documented here; scans re-run with the correct field |

---

## Cross-cutting status (section 5 Definition of done)

| DoD line | Status |
|---|---|
| Ports/services/CVEs surface as findings with asset linkage | ✅ (A1 + per-port findings + graph linkage) |
| Nuclei runs from in-house templates with verified integrity | ✅ (pinned binary, fail-closed, live matches) |
| Every asset is one graph node regardless of source | ✅ (UID collapse, tested) |
| Identical CVE scores materially differently internal vs edge | ✅ (25× test) |
| No scan exceeds its budget | ✅ (governor live on the client path, G2-tested) |
| tsc + suite green | ✅ 253/253 |

**Anti-regression (section 6)**: all six invariants hold and are test-enforced except "template
without `# source:` fails **CI**", which is wired (`ci.yml`) but has not yet executed on a GitHub
runner — it will fire on the next push.

---

## Remaining items — all require external inputs (documented, not faked)

1. **Kafka/Redpanda + Temporal deployment** — needs infrastructure; blocked additionally by the
   zero-runtime-dependency ADR for a JS Kafka client (sidecar bridge or ADR change required).
2. **E1 deployment half** — sensor containers per egress/VPC/cloud position.
3. **E4** — SSH/WinRM target credentials + network reachability (also not implementable in stdlib).
4. **E5** — cloud API credentials for metadata merge.
5. **T4.7 OOB** — public DNS + HTTP endpoint for blind-SSRF callbacks.
6. **Optional**: per-CVE EPSS/CVSS feed for risk base enrichment; a `pg` driver ADR decision if the
   Postgres store should become the primary writer.

## Operational notes

- Server: `http://127.0.0.1:7788`, token in `data/auth-token.txt`; `OWASP_ALLOW_PUBLIC_TARGETS=1`
  required for public targets; `OWASP_SCAN_PROFILE` selects governor ceilings.
- Containers running: `rsec-postgres` (postgres:16, port 5433, password `postgres`), DVWA stack.
- vuln-app fixture: `npm run fixture:vuln` (port 8899). nuclei binary on PATH via WindowsApps.
- Useful commands: `npm run lint:templates`, `npm run canary`, `npm test`, `npx tsc --noEmit`.
- Key finding IDs to know: `port-open`, `port-scan-interference`, `root-fetch-blocked`,
  `host-discovered`, `service-identified`, `os-hint`, `asset-ct-logs`, `zone-transfer-possible`,
  `variant-reflection`, `rsec-*` (nuclei templates).

---

## PoC evidence — remaining items implemented and proven (2026-10-31, this section)

Each remaining item was attacked with the platform's existing patterns (external tooling via
runProcess, Docker deployment, protocol emulation). All PoCs are **permanent, guarded tests**
(`test/unit/poc-evidence.test.ts` + `test/unit/oob-loop.test.ts`): they run against the real
infrastructure when present and skip honestly when it is absent — never a fake pass.
Suite after PoCs: **258/258**.

### D1 — real Kafka-compatible broker + `KafkaHttpBus` adapter ✅ PROVEN
- Deployment: Redpanda container with PandaProxy enabled (`rsec-redpanda`, ports 9092/8082); the six
  canonical topics created (`discovery.asset`, `scan.request`, `scan.result`, `finding.normalized`,
  `risk.changed`, `approval.gate`).
- Adapter: `src/bus/kafkaHttp.ts` — implements the platform `Bus` interface using **only `fetch`**
  (zero-dependency ADR holds) over the Confluent REST Proxy v2 wire protocol (JSON v2 content
  types, consumer groups with earliest reset, per-subscriber instances, best-effort cleanup).
- Evidence: `broker topics: discovery.asset, scan.request, …` listed from the broker; envelope
  published → `{"offsets":[{"partition":0,"offset":0}]}` → consumed back byte-identical:
  `consumed via real broker: [{"findingId":"FND-A01-TEST","severity":"high"}]`. Permanent test green.
- Issue found: the Redpanda container segfaulted (exit 139) in overprovisioned 1G config under
  WSL2 — redeployed with `--memory 2G --reserve-memory 0M`, stable since. The test's skip-guard
  handled the outage honestly between restarts.

### E4 — credentialed SSH sensor ✅ PROVEN
- Deployment: `rsec-sshd` container (linuxserver/openssh-server, key-only auth, port 2224) with a
  generated ed25519 PoC keypair (`.ssh-poc/`, gitignored).
- Adapter: `src/orchestration/sshSensor.ts` — **fixed read-only allowlist** (kernel, os-release,
  listening ports, package inventory, uptime) executed via the OS `ssh` binary through runProcess
  (no shell, argument array, timeout/abort). Nothing operator-supplied is ever executed.
- Evidence (live run against the container): `kernel: Linux 6.18.54.1-microsoft-standard-WSL2`,
  `os: Alpine Linux`, `listening ports: 2222`, `packages: 62 (acl-libs-2.3.2-r1, …)`; inventory
  merged into the graph as a host node with `credentialed: true` + `exposes` edges (3.3: credentialed
  value wins). Permanent test green (skips when sshd/key absent).
- Issue found: `ss … | tail || netstat …` never falls back (pipe exit code) — allowlist commands
  restructured with grouped fallbacks.

### E5 — cloud metadata merge ✅ PROVEN
- Adapter: `src/orchestration/cloudMetadata.ts` — full **AWS IMDSv2 protocol** (PUT token →
  token-authed identity document), endpoint configurable so the same code runs against a local
  IMDSv2 emulation now and the real 169.254.169.254 in-cloud.
- Evidence: token `POC-TOKEN-abc123` issued; identity
  `{accountId:111122223333, region:ap-south-1, instanceId:i-0abc…, instanceType:t3.medium}` fetched;
  merged onto the host node **by the same asset UID** — host attrs became
  `{"cloudAccountId":"111122223333","cloudRegion":"ap-south-1"}` with `member_of` + `runs` edges.
  Permanent test green (self-contained, always runs).
- **Issue found and fixed (real graph bug):** edge assertions re-upserted endpoint nodes with EMPTY
  attributes, **clobbering** previously merged context. `GraphStore.upsertNode` now MERGES
  attributes and provenance on re-observation (correct per 3.3 "results merge into the same host
  node"); regression-covered by the E5 PoC test.

### T4.7 — blind-SSRF OOB correlation loop ✅ PROVEN (loop; public routing remains)
- `test/unit/oob-loop.test.ts`: a fixture with a genuine SSRF sink (`?url=` fetched server-side,
  response blind) is probed by `BlindSsrfProbeEngine`; the fixture's server-side request hits the
  OOB callback server; the probe correlates the unique token.
- Evidence: `res.findings.length === 1`, `rawId: blind-ssrf-oob`, severity `critical`,
  status `confirmed`, CWE 918, evidence names the server-side callback. Permanent test green.
- What this proves: token generation → injection → server-side request → callback → correlation →
  confirmed finding. The ONLY missing piece for public targets remains a publicly reachable callback
  host (DNS + egress) — unchanged and documented.

### C1/T10.1-lite — Postgres writable from the platform ✅ PROVEN
- `src/db/pgWire.ts`: a minimal Postgres **wire-protocol client in stdlib** (`node:net`,
  protocol 3.0 simple query: startup, auth handling, RowDescription/DataRow/CommandComplete/
  ErrorResponse/ReadyForQuery parsing). **Honest limit: TRUST auth only** — the client fails closed
  with a clear error when the server requests SCRAM (verified live); production needs SCRAM
  (implementable with node:crypto) or the `pg` driver (ADR exception).
- Setup: dedicated `pocuser` with a top-of-file trust pg_hba line + grants in the `rsec-postgres`
  container.
- Evidence: node `ip:XVXRXAFSV5` created by the platform's GraphStore and written through the wire
  client (`insert command: INSERT`), read back byte-identical:
  `{"uid":"ip:XVXRXAFSV5","type":"ip","identity":"198.51.100.7",…}`. Permanent test green (skips
  when postgres is down).
- **Issue found and fixed (real client bug):** the ReadyForQuery handler only resolved the CONNECT
  promise — every query hung forever. Fixed: 'Z' resolves the pending query result. (Found because
  the first PoC run hung; the failure mode itself was the honest discovery path.)

### Still not implemented (unchanged, genuinely external)
- **Temporal server deployment** — the state machine is worker-ready but a real Temporal worker
  requires `@temporalio/sdk` (violates the zero-dep ADR); a server-without-worker proves nothing.
- **E4 at real scale** (many hosts, vault-managed keys) — the PoC proves one container via key auth.
- **E5 against real cloud** — same code, needs `169.254.169.254` reachability.
- **T4.7 public callback host** — DNS + egress.
- **Per-CVE EPSS/CVSS feed** — advisory data source.

---

## hardtask.md corrective tasks — implemented (2026-10-31, 306249b)

The W1–W10 concerns and Phases H–N were implemented in the prescribed sequence.

### Phase H — port-detection correctness (P0) ✅
- **H1**: connect-with-no-protocol-answer is now **open (unverified)** — reported at info/low
  confidence with status `untested`, never dropped (W1 resolved: SSH/Redis-style quiet services
  survive; middleboxes cannot inflate severity). Both `scanPort` and the deep-recon path.
- **H2**: suppression threshold **8** (was 5), full-signature identity (status + complete header
  set + body), and **never-suppress** list 22/443/3306/3389/5432/6379/9200/27017 (W2 resolved).
- **H3**: `port-scan-interference` at **low** severity; suppressed count surfaces in scan detail
  ("N ports suppressed as middlebox interception").
- **H4**: truth.json grown with V13 (port 8899); recall-floor test asserts the fixture port
  surfaces on every run.
- Counter-tests (I16): silent-listener fixture → unverified finding; 6-identical-response fixture →
  NOT suppressed; 8-identical → suppressed; differing status/headers survive; critical ports exempt;
  middlebox fixture yields **zero phantom highs**. `test/unit/phase-h.test.ts` — 8/8.

### Phase I — verification honesty (P0) ✅
- **I1**: auto-rejections counted per scan (engine record + audit); `findTruePositiveRejections`
  guard — the e2e asserts no planted TP is auto-rejected, and proves a forced rejection is caught.
- **I2**: `rejected_by_verification` is a distinct ValidationStatus from human `false_positive`
  (W3 resolved); stats carry the counter.
- **I3**: `scoreAgainstTruth` harness; JSON report carries `quality: {recall, precision, basis}`
  (`?truth=fixtures/vuln-app/truth.json` opt-in; basis 'unavailable' otherwise — honest).

### Phase J — supply chain (P1) ✅
- **J1/I18**: two-stage authenticity — the pinned **published-artifact** hash must appear in the
  vendor's committed checksums.txt, and the on-disk binary must match the pinned extracted hash;
  both fail closed. Verified live: our downloaded zip hash `bb6cb9ff…` matches the official
  `nuclei_3.11.1_checksums.txt` (W6 resolved — authenticity, not just stability).
- **J2**: pack digest (sha256 over index.json + all templates) rides in every nuclei finding's
  provenance.
- **J3**: `templates/pack-version.json` pins {version, digest}; lint fails on drift — template
  changes require a bump commit.

### Phase K — API + CI truth (P1) ✅
- **K1**: `profile` and `profileId` both accepted; missing/unknown profile = 400, never a silent
  standard-active (W8 resolved). Tested.
- **K2**: CI is real — runs on GitHub runners; `# source:` gate has executed there (green runs on
  8d49230 and a1342f7). Run URLs in the memory/handover record; the Phases H–N push runs at
  https://github.com/ramuatnet/R-SecopsXD/actions/runs/41179604153.
- **K3**: gate-negative evidence: `lintTemplates(bad)` unit test proves a template without
  `# source:` fails the gate.

### Phase L — real enrichment (P1) ✅
- **L1**: offline advisory snapshot (`src/risk/advisories.ts`, 12 CVEs, dated) — CVE-bearing
  findings carry `base_source: 'epss'|'cvss'` with real bases (Log4Shell → base 1.0 via EPSS 0.976);
  everything else explicit `'severity'` (W5 resolved to the honest extent possible offline).
- **L2**: reports take graph fan-out for the blast factor; neutral only when the graph has no edges.
- **L3**: the worked-example chain runs through the report pipeline in e2e (I3/L3 test asserts
  quality + base_source + blast bounds on a real scan).

### Phase M — capability unblocking (P2) ✅
- **M1**: DONE previously — `CredentialedSshSensor` (system ssh, read-only allowlist) inventories
  the sshd container; patch level lands on the host node (W10 resolved).
- **M2**: TTL OS hypothesis via the **system ping binary** (`src/orchestration/ttlProbe.ts`) —
  proven on this host (TTL=128 → Windows). The "impossible in Node userspace" claim is rescinded
  (W4 resolved); docs corrected.
- **M3**: DDL drift gate — `001_asset_graph.sql` is applied to a throwaway schema on the live
  postgres:16 in a permanent test; exactly three tables asserted (W7 partially resolved: schema
  tested; the app still writes SQLite by design).
- **M4**: localhost OOB callback mode proven (oob-loop test) — internal targets unblocked.

### Phase N — docs truthfulness (P2) ✅
- **N1**: DoD below rewritten to distinguish unit-tested vs live-verified.
- **N2**: E-I2 and E4 claims corrected per M1/M2 outcomes.
- **N3**: `LIMITATIONS.md` records that risk base is severity-derived unless a CVE is in the
  offline snapshot, plus every other honest boundary.

### Definition of done (hardtask.md §4) — verified
- Zero-byte and identical-response rules both have counter-tests ✅ (H1/H2 tests, I16)
- Planted TP rejection detectable/fails ✅ (I1 guard + e2e)
- nuclei hash verified against published checksums ✅ (J1, live match proven)
- profileId no longer silently defaults ✅ (K1)
- A green runner CI exists ✅ (K2 — two green runs + URLs)
- Risk base is real for CVE-bearing findings ✅ (L1, base_source explicit)
- Recall and precision appear in reports (opt-in truth) ✅ (I3)

---

## hardtask.md closing pass — the three letter-level nuances closed (2026-10-31, c31dfb2)

1. **M3 now CI-tested for real**: `ci.yml` runs a `postgres:16` **service container** with ltree +
   the graph DDL applied and a trust `pocuser` provisioned by the workflow itself — the DDL drift
   gate and the Postgres wire-protocol PoC **execute on the runner** (previously they skipped
   there). The setup script was validated against a fresh container before landing:
   `C1 wire write PASS`, `M3 drift gate PASS` from scratch.
2. **K3 runner-visible**: a workflow step plants a template without `# source:`, asserts
   `lintTemplates` finds violations (exit non-zero otherwise), making the gate block visible in
   the run log — in addition to the existing unit test.
3. **I3 every report**: the **HTML** report now renders an Assessment-quality table (recall /
   precision with matched truth IDs when ground truth is supplied via `?truth=`, an honest
   "not computed" line otherwise) and takes graph fan-out for the blast factor, matching the
   JSON report.

CI: **green** on the closing pass — https://github.com/ramuatnet/R-SecopsXD/actions/runs/41181210447
(with the Postgres-backed tests executing for the first time on a runner). Suite: 271/271.

Remaining deliberately-unbuilt (unchanged): Temporal worker (zero-dep ADR), Kafka-native client
(HTTP proxy adapter is the zero-dep path), real-cloud E5, public OOB host (T4.7), advisory snapshot
refresh cadence (L1 operational item).
