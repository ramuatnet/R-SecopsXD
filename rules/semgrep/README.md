# Bundled Semgrep rules (offline fallback)

`rules/semgrep/owasp-basic.yml` is a minimal generic-language ruleset used by
the Semgrep adapter when `OWASP_SEMGREP_CONFIG` is not set. It keeps the
adapter fully functional offline. These rules are platform-original (MIT,
this repository) — they are NOT the Semgrep registry ruleset.

For real coverage, set `OWASP_SEMGREP_CONFIG=p/owasp-top-ten` (requires
network; note the Semgrep Rules License — see docs/LICENSES.md) or point it
at a local checkout of https://github.com/semgrep/semgrep-rules.
