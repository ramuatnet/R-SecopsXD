# Dependency & License Inventory

## This platform

- **License:** MIT (see `LICENSE`).
- **Runtime npm dependencies:** NONE. The runtime uses Node.js standard library only
  (`node:sqlite`, `node:http`, `node:crypto`, `node:child_process`, `node:fs`, fetch).
  This is a deliberate supply-chain decision (docs/DECISIONS.md D1).
- **Dev-only npm dependencies:** `typescript` (Apache-2.0), `@types/node` (MIT).

## Wrapped external scanners (user-installed, detected at runtime)

| Tool | SPDX license | Notes |
|---|---|---|
| Semgrep CLI | LGPL-2.1 | Engine is LGPL; the default rules registry has separate terms — see below. |
| Semgrep rules (`p/owasp-top-ten`, semgrep-rules repo) | **Semgrep Rules License v1.0** (GitHub: NOASSERTION) | Royalty-free **internal use**; no redistribution / no offering as a service; attribution required. The bundled `rules/semgrep/` ruleset in this repo is platform-original MIT content and avoids these terms when used offline. |
| Trivy | Apache-2.0 | Aqua Security. |
| Grype | Apache-2.0 | Anchore. Vulnerability DB downloaded at runtime by grype itself. |
| Nuclei | MIT | ProjectDiscovery. |
| Nuclei templates | MIT | ProjectDiscovery. |
| OWASP ZAP | Apache-2.0 | Checkmarx / OWASP community. Requires Java 11+. |

Wrapped tools are subprocesses: this platform invokes them and normalizes JSON
output; it does not link, embed, or redistribute them. Each finding records the
engine id + version used.

## Reference content used

| Source | License | Use |
|---|---|---|
| OWASP Top 10:2025 (top10.owasp.org, OWASP/Top10 repo) | CC-BY-3.0 | Category names, descriptions, CWE mappings, references (attributed by link in-app). |
| OWASP WSTG v4.2 | CC-BY-SA-4.0 | Mapped check families referenced in reports/docs. |
| OWASP ASVS 5.0.0 | CC-BY-SA-4.0 | Referenced as manual-review framework. |
| OWASP Cheat Sheet Series | CC-BY-SA-4.0 | Remediation reference links in findings. |

## Test fixtures (shipped in repo)

| Fixture | License | Purpose |
|---|---|---|
| `fixtures/vuln-app`, `fixtures/hardened-app`, `fixtures/source-project` | MIT (this repo) | Ground-truth test targets. Loopback-only, never deploy. |
| OWASP Juice Shop (optional demo) | MIT | Optional demo target (not included). |
| WebGoat (optional demo) | GPL-2.0-or-later | Optional demo target (not included). |

## Attribution

OWASP Top 10:2025 category metadata is reproduced/derived from the OWASP Top 10:2025
document set (CC-BY-3.0) with pointers to the canonical pages. This platform is not
affiliated with OWASP; "OWASP Top 10" references the standard's categories.
