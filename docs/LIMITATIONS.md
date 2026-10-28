# Known Limitations

Honest statements about what this platform does **not** do. (See also
CAPABILITY-MATRIX.md for the per-category view and DECISIONS.md D8 for the
no-fabrication policy.)

## Detection

1. **Automated scanning is never proof of safety.** A clean scan means "the executed
   engines found nothing they can see", not "the application is secure".
2. **Authenticated testing is out of scope for v1.** The platform holds no
   credentials and sends no session cookies. Everything behind a login is invisible:
   IDOR across roles, authenticated authorization flaws, session management defects.
   This is the single largest gap; it is backlog item B1.
3. **No dataflow analysis in built-in source checks.** `builtin.source-scan` is regex
   heuristics with `probable` status by definition; expect false negatives (aliased
   sinks) and occasional false positives (test files, non-security checksums). Real
   SAST requires the Semgrep adapter.
4. **Reflection ≠ XSS.** The reflection probe proves unencoded output of a marker,
   which is the precondition for reflected XSS; it does not execute JavaScript.
5. **No TLS protocol analysis.** Cleartext HTTP is observable; weak cipher suites,
   certificate chains and renegotiation issues need dedicated tooling (testssl.sh).
6. **A09 (logging) and A06 (design) are manual-only** for automated scanning, by
   nature. The platform says so in every coverage report rather than pretending.
7. **Coverage verdicts are capability-based, not result-based.** "covered" means an
   engine that can speak to the category ran — not that it found anything, nor that
   it exhausted the category.
8. **ZAP/Nuclei run outside the platform's HTTP client.** Scope is enforced at the
   entry URL; their internal crawling/spawning is trusted to stay on target and their
   behavior is bounded by their own flags (nuclei deny-tags, rate limits). This is a
   documented residual risk in THREAT-MODEL.md.
9. **Evidence redaction is pattern-based.** Known shapes (Authorization/Cookie
   headers, AWS/GitHub/Slack tokens, JWTs, PEM keys, secret-named assignments) are
   redacted; a secret in an unusual encoding could survive redaction. Review evidence
   before sharing reports.

## Operational

10. **Single-operator tool.** One bearer token, no RBAC, no multi-tenancy. The API is
    bind-to-loopback by default; binding non-loopback requires an explicit token and
    is warned against.
11. **SQLite is single-writer.** Concurrent scans are bounded (default 2); heavier
    concurrency needs a server database (BACKLOG B7).
12. **node:sqlite is flagged experimental by Node** — the API used
    (`DatabaseSync` + prepared statements) is stable in practice on Node 24 and
    pinned via `engines`.
13. **Windows spawner caveats.** Scanner binaries are resolved across PATH +
    PATHEXT shims; `.cmd` wrappers are killed via `taskkill /T`. Extremely long
    subprocess chains could leak grandchildren if killed mid-spawn (best effort).
14. **PDF layout is deliberately plain** (Helvetica, text + rules). Complex visuals
    live in the HTML report.
15. **The crawler is link-driven.** SPA routes without `href` links, or pages behind
    POST-only flows, are not discovered.

## Honesty in reports

16. **`unavailable` engines are visible in every report**, but their absence may
    still change the risk picture (e.g. no SCA installed → no CVE findings). The
    executive summary lists them explicitly.
17. **Human triage (false positive) is fingerprint-scoped**, not global by rule: the
    same issue at a different locator is re-surfaced.
