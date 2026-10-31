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
