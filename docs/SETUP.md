# Setup

## Requirements
- **Node.js ≥ 24** (native TypeScript execution + embedded SQLite). Tested on 24.18.
- That is all for the core platform — zero runtime npm dependencies.
- Optional external scanners (auto-detected, install hints shown in the UI):
  - `semgrep` (`pip install semgrep`) — SAST
  - `trivy` (`winget install AquaSecurity.Trivy`) — SCA/misconfig/secrets
  - `grype` (`winget install anchore.grype`) — SCA
  - `nuclei` (go install / release binary) — template scanning
  - OWASP ZAP (`zap.bat`/`zap.sh` on PATH or default install location) — DAST
- Optional test targets: OWASP Juice Shop / WebGoat / crAPI via Docker (see below).

## Install & run

```bash
npm install          # dev-only: typescript + @types/node (for typechecking)
npm start            # serves http://127.0.0.1:7788
```

On first boot the server prints the **auth token** once and writes it to
`data/auth-token.txt`. The UI asks for it on first load.

## First assessment (60 seconds)

```bash
# 1. start a deliberately vulnerable local target (loopback only)
node fixtures/vuln-app/server.cjs          # http://127.0.0.1:8899

# 2. in the UI (or via CLI):
#    Targets → register http://127.0.0.1:8899 → Approve → Scans → run "Standard active assessment"
# CLI equivalent:
node src/cli/cli.ts target register --name "Local test app" --kind webapp --origin http://127.0.0.1:8899
node src/cli/cli.ts target approve <id from previous command>
node src/cli/cli.ts scan start --target <id> --profile standard-active --mode active --wait
node src/cli/cli.ts findings <scanId>
node src/cli/cli.ts scan report <scanId> --format pdf --out report.pdf
```

`npm run demo` runs an end-to-end demonstration script against the local fixtures.

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `OWASP_HOST` | `127.0.0.1` | Bind host. Non-loopback requires `OWASP_TOKEN` set (refuses otherwise). |
| `OWASP_PORT` | `7788` | Listen port. |
| `OWASP_TOKEN` | generated | Bearer token for the API. |
| `OWASP_DATA_DIR` | `data` | SQLite DB, scan workspaces, token file. |
| `OWASP_ALLOW_PUBLIC_TARGETS` | `false` | Allow registering non-private origins. Only enable with written authorization. |
| `OWASP_RATE_RPS` / `OWASP_RATE_BURST` | `5` / `10` | Per-target token-bucket rate limit. |
| `OWASP_MAX_CONCURRENCY` | `8` | Global concurrent request cap. |
| `OWASP_MAX_CONCURRENT_SCANS` | `2` | Concurrent scans. |
| `OWASP_REQUEST_TIMEOUT_MS` | `15000` | Per-request timeout. |
| `OWASP_ENGINE_TIMEOUT_MS` | `600000` | Per-engine timeout. |
| `OWASP_SCAN_TIMEOUT_MS` | `1800000` | Per-scan timeout. |
| `OWASP_MAX_CRAWL_PAGES` | `30` | Crawl page cap (profiles may set lower). |
| `OWASP_LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` (JSON lines on stdout). |
| `OWASP_SEMGREP_CONFIG` | bundled rules | Semgrep ruleset: `p/owasp-top-ten`, local dir, or YAML file. |

## Tests

```bash
npm run typecheck   # strict TypeScript gate
npm test            # 82 tests: unit + integration + e2e (fixtures spawned automatically)
npm run test:e2e    # ground-truth scans of the vulnerable/hardened fixtures
```

## Demoing against real training apps (optional)

```bash
# OWASP Juice Shop (MIT). Port 3000, binds all interfaces inside Docker Desktop.
docker run --rm -p 3000:3000 bkimminich/juice-shop
node src/cli/cli.ts target register --name "Juice Shop" --kind webapp --origin http://127.0.0.1:3000
node src/cli/cli.ts target approve <id>
node src/cli/cli.ts scan start --target <id> --profile standard-passive --wait
```

WebGoat (GPL-2.0-or-later): `docker run --rm -p 8080:8080 -p 9090:9090 webgoat/webgoat` —
note WebGoat intentionally requires its lesson flow; passive scans only surface its
misconfigurations. crAPI similarly via its docker-compose. These apps are optional
manual-demo targets; the automated test suite uses the built-in deterministic fixtures.

## Data layout

```
data/
  platform.db          # SQLite (targets, scans, findings, triages, audit)
  auth-token.txt       # operator token (regenerate by deleting)
  scan-<id>/           # per-scan workspace: raw adapter output (semgrep.json, zap-report.json)
```
