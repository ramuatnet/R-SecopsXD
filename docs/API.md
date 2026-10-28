# API Reference

Base URL: `http://127.0.0.1:7788`. All routes except `GET /api/health` and static UI
assets require `Authorization: Bearer <token>`. The token is printed once at first
boot and stored in `data/auth-token.txt`.

Errors are JSON: `{ "error": "<code>", "message": "..." }`. Common codes:
`unauthorized` (401), `invalid_*` (400), `public_target_forbidden` (403),
`not_found` (404), `target_not_approved` (409), `not_cancellable` (409).

## Health

```
GET /api/health          → { ok, name, version, time }   (no auth)
```

## Targets

```
POST /api/targets        { name, kind: "webapp"|"source", origin?, sourcePath?, notes? }
                         → 201 { target }          # registration does NOT allow scanning yet
GET  /api/targets        → { targets: Target[] }
GET  /api/targets/:id    → { target, latestScan?, findings? }   # summary of last completed scan
POST /api/targets/:id/approve → { target }         # separate, audited action
DELETE /api/targets/:id  → { deleted: true }
```

Webapp origins are normalized to `scheme://host:port`. Public-internet origins are
refused with 403 while `OWASP_ALLOW_PUBLIC_TARGETS=false` (default).

## Profiles & engines & catalog

```
GET /api/profiles        → { profiles: [ { id, name, description, targetKinds, maxCrawlPages, passiveEngines, activeEngines, enginePlan } ] }
GET /api/engines         → { engines: [ { id, name, kind, capabilities, modes, targetKinds, availability } ] }
                           # availability: { available, version? } | { available:false, reason, installHint? }
GET /api/owasp           → { categories: [ { code, name, summary, reference, cwes, automation } ] }
```

## Scans

```
POST /api/scans          { targetId, profile, mode: "passive"|"active" }
                         → 202 { scan }            # 409 if target not approved
GET  /api/scans          → { scans: Scan[] }       # newest first
GET  /api/scans/:id      → { scan, findings }
POST /api/scans/:id/cancel → { cancelling: true }  # cooperative; scan status becomes cancelled
GET  /api/scans/:id/findings → { findings }
GET  /api/scans/:id/report?format=json|html|pdf
                         → binary/att download     # JSON is the canonical artifact
```

`mode: "active"` is an explicit, audited choice — active engines are listed as
`skipped` in passive scans.

## Findings triage

```
POST /api/scans/:scanId/findings/:findingId/status
                         { status: "confirmed"|"probable"|"informational"|"false_positive"|"untested", note? }
                         → { finding }
```

Triage decisions are stored **by fingerprint**, so future scans inherit the human
decision (e.g. a marked false positive stays suppressed).

## Audit

```
GET /api/audit           → { entries: [ { id, ts, actor, action, details? } ] }  # newest first, ≤200
```

Recorded actions include: `target.registered|approved|deleted`, `scan.started|
completed|failed|cancelled|cancel_requested`, `finding.triage`, `engine.unavailable`,
`auth.failed`.

## Object shapes (abridged)

**Finding**
```json
{
  "id": "FND-A05-3F9KQ2T7B8",          // stable across rescans
  "fingerprint": "sha256(category|cwe|asset|locator)",
  "title": "…", "category": "A05", "severity": "high", "confidence": "high",
  "status": "confirmed|probable|informational|false_positive|untested",
  "cwe": 79, "cve": "CVE-…", "asset": "http://…", "locator": "/search?q=",
  "engine": "builtin.reflection-probe",
  "evidence": [ { "kind": "http", "request": {...}, "response": {...}, "observation": "…" } ],
  "explanation": "…", "remediation": "…", "references": ["https://…"],
  "detectedAt": "ISO-8601",
  "provenance": [ { "engine": "…", "engineVersion": "…", "rawId": "rule-or-CVE-id", "adapter": false } ]
}
```

**Scan** (abridged): `id, targetId, targetName, profile, mode, status
(queued|running|completed|failed|cancelled), startedAt, finishedAt,
engines: [ { engine, status (ran|unavailable|failed|skipped|cancelled),
findingCount, durationMs, detail?, version? } ], coverage: [ { category, verdict
(covered|partial|manual-only), engines, note } ], stats: { findingsBySeverity,
findingsByStatus, totalFindings, requestsSent, requestsBlocked }, error?`.

Severity is kept strictly separate from confidence; validation status is the
triage lifecycle. Evidence is secret-redacted at capture and again at render.
