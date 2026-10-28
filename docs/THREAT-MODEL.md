# Threat Model

Scope: the assessment platform itself ("the tool"), operated locally by an authorized security
engineer. Method: lightweight STRIDE per component, plus abuse cases specific to the fact that
this tool *sends traffic to third-party systems*.

## Assets
1. Scan database (findings, evidence — may contain excerpts of target secrets).
2. Auth token (full control of the tool).
3. The tool's network egress (ability to send HTTP to hosts).
4. Subprocess execution surface (adapters run external binaries with arguments we build).
5. Reports (leave the operator's machine, may contain exploitable details).

## Adversaries
- **A1 Unauthorized remote attacker** — tool bound to network interface.
- **A2 Malicious/compromised target** — responds with redirects, huge bodies, secrets to
  entice storage; or lies about identity to get scanned.
- **A3 Local unprivileged user on shared machine** — reads `data/`.
- **A4 CSRF/drive-by web page** in the operator's browser while the tool UI is open.
- **A5 Supply chain** — malicious npm package or scanner binary.

## STRIDE summary

| Threat | Vector | Mitigation | Residual |
|---|---|---|---|
| Spoofing (A1) | API access | Bearer token on every mutating route; token generated at first boot, stored hashed in DB, printed once; static assets only served unauthenticated | Token is bearer-only (no expiry) — accepted for single-operator tool; rotate by deleting `data/` |
| Tampering (A1/A3) | DB or evidence files | Single-process writer; SQLite in user profile dir; evidence files written under `data/scan-*/` | No at-rest encryption (backlog); operator should disk-encrypt |
| Repudiation | Actions without trace | Append-only audit log (target lifecycle, scans, exports, auth failures, config) with timestamps | Local log only |
| Information disclosure (A3) | `data/` contains evidence excerpts | Central redactor scrubs Authorization/Cookie/Set-Cookie/API keys/JWTs/PEM before storage; body excerpts capped at 2 KB | A determined secret in an unexpected format may survive — documented in LIMITATIONS |
| Denial of service (A2) | Redirect loops, huge responses, slowloris targets | Manual redirect following, max 5 hops, all in-scope; response read cap (256 KB); 15 s request timeout; per-engine and per-scan timeouts; rate limiter + concurrency semaphore | A hostile target can still slow a scan within limits — cancel button + abort signal |
| Elevation of privilege (A4) | CSRF against `POST /api/*` | API requires `Authorization: Bearer` header — a cross-origin page cannot set it (CORS: no cross-origin headers allowed; no credentials mode) | None known |
| Supply chain (A5) | npm deps / scanner binaries | D1: zero runtime deps; scanners are user-installed, version-detected and recorded per finding; adapter subprocess args are constructed from validated allow-listed values (no shell interpolation, `execFile` semantics) | Scanner binaries themselves trusted (documented in LICENSES) |

## Abuse cases specific to scanning

| Abuse | Control |
|---|---|
| Scan a host the operator doesn't own | Two-step registration+approval; approval audited; docs define authorization expectations |
| Scan public internet by mistake | `allowPublicTargets` defaults false — public origins are refused at registration |
| Crawl out of scope via redirects | Redirect guard validates every hop against the approved origin; off-scope hop → blocked + audited |
| Active/destructive testing by default | Passive-only by default; active mode is per-scan, explicit, audited |
| DoS payload execution | Payload guard refuses destructive classes (see `safety/payloadGuard.ts`); Nuclei runs with `dos,fuzz,brute-force` tag deny-list even in active mode; no payload-based HTTP methods beyond GET/POST forms in v1 |
| Resource exhaustion of the target | Token bucket (default 5 rps/burst 10) + page caps (default 30 pages) |
| Findings leaked in reports | Reports include redacted evidence only; marked "confidential" in header |

## Not in scope (v1)
- Multi-tenant operation / RBAC (single operator assumed).
- Network segmentation of the tool (assumes loopback or trusted LAN).
- Exploitation/post-exploitation: the tool stops at evidence of a vulnerability; it never
  executes exploits against targets (no sqlmap/metasploit integration by design).
