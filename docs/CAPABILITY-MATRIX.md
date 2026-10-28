# Capability Matrix

What each scan mode and engine can honestly detect, per OWASP Top 10:2025 category.
**No category is ever "fully covered" by automated scanning** — every verdict below
carries explicit limits. Sources for category definitions and CWE mappings:
[top10.owasp.org/2025](https://top10.owasp.org/2025/) (verified against the OWASP/Top10
repository, 2025 Final).

Verdict keys: **strong** = deterministic observation or advisory-database match;
**heuristic** = pattern/tpl signal needing human verification; **—** = no automated
check (manual assessment required).

## Per category

| Category | Built-in (webapp, passive) | Built-in (webapp, active) | Semgrep (SAST) | Trivy/Grype (SCA) | Nuclei | ZAP (DAST) | Honest ceiling |
|---|---|---|---|---|---|---|---|
| A01 Broken Access Control | info-exposure in served content (heuristic) | unauthenticated admin/sensitive paths (strong); object-access smoke probe on observed IDs (heuristic) | — | — | exposure templates (heuristic) | access-control alerts, unauthenticated only (heuristic) | IDOR/horizontal escalation across roles, business-logic authorization: **manual** (needs authenticated multi-role testing) |
| A02 Security Misconfiguration | security headers, cookie flags, server banners, directory listings (strong) | exposed .env/.git/backups/actuator (strong) | config patterns (heuristic) | misconfig checks (heuristic) | misconfig templates (strong) | header/cookie alerts (strong) | "correct for this business context" needs review; deep infra config needs deployment-file review |
| A03 Software Supply Chain Failures | — | — | — | **CVE advisory matching on lockfiles (strong)**; inventory always | sensitive-file templates (heuristic) | — | unknown malicious packages, typosquatting, build-pipeline compromise: **manual/process controls** |
| A04 Cryptographic Failures | cleartext transport of credential forms (strong; informational on private targets) | — | weak primitives, disabled TLS verification (heuristic) | — | weak-TLS templates (heuristic, limited) | — | protocol/cipher negotiation flaws need dedicated TLS tooling (testssl.sh etc., not bundled) |
| A05 Injection | — | unencoded reflection of marker in HTML (strong observation; XSS itself probable) | injection sinks, pattern + limited taint (heuristic) | — | non-destructive injection templates (heuristic) | injection alerts, non-destructive set (heuristic) | blind/time-based injection, stored XSS chains, business-logic injection: **manual**; a clean scan does NOT prove absence |
| A06 Insecure Design | — | — | — | — | — | — | **manual-only by nature**; WSTG-BUSL review; platform contributes hygiene signals only |
| A07 Authentication Failures | — | username enumeration via differential responses (strong signal, probable finding); missing login rate limiting via bounded 8-attempt probe (strong signal, probable finding) | hardcoded credentials, auth patterns (heuristic) | secret detection (heuristic) | auth templates, deny-listed tags (heuristic) | session/auth alerts (heuristic) | password policy quality, MFA, credential-stuffing resistance, session fixation: **manual** (needs authenticated testing) |
| A08 Software or Data Integrity Failures | — | — | deserialization sinks (heuristic) | — | — | CSRF/integrity alerts (heuristic) | SRI verification, pipeline signing, reproducible builds: **manual/process** (SRI check planned — BACKLOG) |
| A09 Security Logging & Alerting Failures | — | — | — | — | — | — | **manual-only**; black-box scans cannot observe server logs; needs log-access review |
| A10 Mishandling of Exceptional Conditions | verbose errors/stack traces in observed responses (strong) | error paths discovered by probing (strong when observed) | fail-open patterns (heuristic) | — | error-disclosure templates (heuristic) | info-disclosure alerts (heuristic) | reachability in production flows often needs manual verification |

## Per scan mode

| Mode | What it does | Cannot detect |
|---|---|---|
| `quick-passive` | ≤10 pages crawled with plain GETs; observes headers/cookies/banners/errors/comments | anything requiring probing; anything in source |
| `standard-passive` | same with ≤30 pages | same |
| `standard-active` | passive + bounded path probes (≤20), reflection markers, auth probes (enumeration + 8 attempt rate-limit check), object-access smoke probe | authenticated deep testing; anything destructive (by policy) |
| `external-dast` | standard-active + ZAP quick scan + Nuclei (deny-listed tags) | tools missing → recorded `unavailable`, scan still completes |
| `source-review` | built-in pattern scan + dependency inventory + Semgrep/Trivy/Grype when installed | dataflow-verified vulnerabilities without real SAST; runtime behavior |

## What the platform never does (by design)
- No exploitation, no destructive payloads, no DoS, no brute-force credential guessing
  (payload guard + nuclei deny-tags enforce this; see `src/safety/payloadGuard.ts`).
- No unauthenticated requests to unregistered/unapproved origins.
- No AI-generated findings: every finding is a deterministic observation, an advisory
  match, or a labelled heuristic pattern with evidence a human can re-verify.

## Detection claims are test-backed
Every detection claim marked (strong) for built-in engines is demonstrated by
`test/e2e/scan.test.ts` against `fixtures/vuln-app` with ground truth in
`fixtures/vuln-app/truth.json`, and the negative case by the hardened twin. See
docs/TEST-RESULTS.md for the recorded run.
