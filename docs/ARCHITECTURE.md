# Architecture

## System overview

```
                        ┌────────────────────────────────────────────────────────┐
                        │                    Node.js 24 process                   │
                        │                                                        │
  browser ──HTTP──▶     │  ┌──────────┐   ┌─────────────┐   ┌──────────────────┐  │
  (loopback only)       │  │ HTTP API │──▶│ Orchestrator │──▶│  Engine registry │  │
                        │  │ + static │   │  (scan jobs) │   └───────┬──────────┘  │
                        │  │ web UI   │   └──────┬──────┘           │             │
                        │  └────┬─────┘          │            ┌─────┴──────────┐  │
                        │       │                │            │ built-in       │  │
                        │  ┌────▼─────┐          │            │ engines (TS)   │  │
                        │  │ SQLite   │◀─────────┤            │ http/crawler/  │  │
                        │  │ (node:   │          │            │ source/dep/    │  │
                        │  │  sqlite) │          │            │ path/auth      │  │
                        │  └──────────┘          │            └─────┬──────────┘  │
                        │                        │            ┌─────▼──────────┐  │
                        │  ┌──────────┐          └──────────▶ │ adapters       │  │
                        │  │ Audit log│                         │ semgrep/trivy/ │  │
                        │  └──────────┘                         │ grype/nuclei/  │  │
                        │                                       │ zap (subproc)  │  │
                        │  ┌──────────┐                         └─────┬──────────┘  │
                        │  │ Safety   │◀── enforced across ────────────┘             │
                        │  │ layer    │    HTTP client + orchestrator                │
                        │  └──────────┘                                               │
                        └────────────────────────────────────────────────────────┘
                             │ (scoped fetch, rate-limited)      │ subprocess JSON
                             ▼                                  ▼
                       approved target                     installed scanners
```

## Module map (all paths under `src/`)

| Module | Responsibility |
|---|---|
| `core/types.ts` | Finding, Evidence, Target, Scan, Profile domain types |
| `core/owasp.ts` | OWASP Top 10:2025 catalog (names, refs, CWEs, automation limits) |
| `core/cweMap.ts` | CWE → OWASP category mapping used to classify external scanner output |
| `core/ids.ts` | Stable finding IDs + dedup fingerprints (SHA-256, base32) |
| `core/redact.ts` | Secret redaction for evidence/logs |
| `safety/guard.ts` | Scope guard: origin matching, redirect hop validation, public-target gate |
| `safety/rateLimiter.ts` | Token-bucket rate limiter per target |
| `safety/payloadGuard.ts` | Refuse destructive payload classes before any request is sent |
| `safety/concurrency.ts` | Global request semaphore |
| `db/database.ts` | `node:sqlite` connection, migrations, repositories |
| `scan/httpClient.ts` | The *only* network egress path; enforces guard/limiter/timeouts; captures redacted evidence |
| `scan/orchestrator.ts` | Scan lifecycle: engines → normalize → dedupe → persist → coverage report |
| `engines/*` | Built-in engines and external adapters behind one interface |
| `reports/*` | JSON / HTML / PDF renderers |
| `api/*` | Router, auth, handlers, validation |
| `server.ts` | Composition root: config, bootstrap, listen (loopback default) |
| `cli/cli.ts` | Headless operation: register/approve/scan/report for automation |

## Data flow of a scan

1. `POST /api/targets` registers an origin (no traffic yet). `POST /api/targets/:id/approve`
   unlocks it (audited).
2. `POST /api/scans {targetId, profile, mode}` → orchestrator creates a `scans` row
   (`running`), resolves the profile to engines.
3. Each engine runs with: the shared scoped `httpClient` (passive engines), a per-engine
   timeout, and an `AbortSignal` for cancellation. Adapter engines spawn subprocesses
   (`json`/`jsonl` output) and normalize findings.
4. Normalization maps every raw finding to the platform model, assigning category (tool
   metadata → CWE → `cweMap`), severity and confidence per documented rules.
5. Deduplication groups findings by fingerprint (category+cwe+asset+evidence locator),
   merging provenance and evidence.
6. Findings are persisted with stable IDs (rescans keep IDs; `firstSeen`/`lastSeen` update).
7. The scan record stores per-engine status (`ran|unavailable|failed|skipped`) and a
   per-category coverage verdict used by UI and reports.

## Key invariants

- **Single network egress point.** Built-in engines cannot issue requests except through
  `scan/httpClient.ts`, which consults the safety layer on every call (URL + redirects).
- **Single DB writer.** All persistence goes through repository functions; audit inserts are
  append-only.
- **No engine writes files** outside its scan workspace (`data/scan-<id>/`), used for adapter
  raw output (kept as provenance, redacted).
- **Every finding is reconstructible**: evidence in the DB + raw engine output on disk.

## Process & runtime model

- One Node process; scans run as concurrent async jobs (max `scans.maxConcurrent`, default 2),
  HTTP requests bounded by a global semaphore (default 8).
- Config from environment (`OWASP_*`) with safe defaults; see `src/config.ts`.
- Data directory `./data` (DB, scan workspaces, generated auth token, reports cache).

## Extension points

- **New engine:** implement `Engine` (id, capabilities, availability, run) and register it; the
  orchestrator, UI engine list, and coverage reporting pick it up automatically.
- **New profile:** declarative entry in `core/profiles.ts`.
- **New report format:** implement `render(scan) → bytes` and register in `reports/registry.ts`.
