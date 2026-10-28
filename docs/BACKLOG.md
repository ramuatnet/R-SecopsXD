# Backlog (prioritized)

P0 = next release, P1 = later, P2 = nice-to-have.

## P0 — closes the biggest honest gaps
- **B1 Authenticated scanning.** Credential profiles per target (vaulted), login-form
  automation, session tracking, role-aware path probes; enables real A01/A07 coverage.
- **B2 Semgrep e2e validation on CI images.** The adapter + bundled offline rules are
  unit-tested; add an e2e path that installs semgrep and runs `source-review` on
  `fixtures/source-project` (like the grype e2e does).
- **B3 ZAP e2e validation** with a ZAP installation (unit-tested parser only today).
- **B4 Precision/recall tracking in reports.** With ground truth available
  (fixtures), compute and display per-scan precision/recall versus truth.json for
  demo scans, and expose an "untested checks" section (WSTG-mapped) per target.

## P1
- **B5 SRI verification engine** (A08): detect external `<script src>` without
  `integrity` attributes; verify SRI hashes of subresources.
- **B6 Secret-redaction unit fuzzing**: property-based tests over random payload
  shapes to harden `core/redact.ts`.
- **B7 Pluggable storage**: extract a repository interface; add PostgreSQL driver for
  team deployments.
- **B8 TLS analysis adapter** (testssl.sh) feeding A04.
- **B9 DAST authenticated session support in ZAP adapter** (session tokens via ZAP API).
- **B10 Rescan diffing**: "new / fixed since last scan" views driven by stable IDs.
- **B11 OpenAPI export** of the API (machine-readable from the router table).
- **B12 SARIF report format** for CI integration (Semgrep/Trivy already emit it;
  consuming/producing makes the platform CI-native).

## P2
- **B13 Dependency Track integration**: push CycloneDX SBOMs (cyclonedx-* tooling) to
  a Dependency-Track instance; ingest project findings.
- **B14 Amass/recon adapter** for pre-scan asset discovery (requires explicit scope
  widening controls).
- **B15 Container/image scan mode** (trivy image, grype docker://) for deployed
  artifact assessment.
- **B16 WSTG-mapped manual test checklist generator** per target (A06/A09 support).
- **B17 Multi-user RBAC + per-target authorization chains** (approval by a second
  account), for team operation.
- **B18 i18n of reports** (UI strings already centralized).

## Deliberately rejected
- Exploitation engines (sqlmap-style) — the platform stops at evidence.
- Shodan/external attack-surface scanning — contradicts the registered-scope model.
