# Remaining Manual Assessments

What still requires a human after the automation program's first increment, per the
task registry (`src/core/tasks.ts`). Each entry lists what the automation *does*
contribute and what evidence a reviewer must produce.

| Task | Category | Why it stays manual | What the platform contributes | Reviewer must produce |
|---|---|---|---|---|
| A01-T04 (residual) | A01 | Multi-ROLE matrix testing needs ≥2 test identities with distinct roles | Authenticated surface mapping now automated with a single test account (A01-T07); unauthenticated probes | Role-matrix test records with ≥2 synthetic identities |
| A03-T04 | A03 | Name heuristics are not evidence of malice; pipeline compromise is a process question | Dependency inventory + CVE findings for source targets | Documented SBOM + provenance review |
| A03-T05 (residual) | A03 | Full deployed-SBOM assessment requires build-system access | Exposed manifest/lockfile detection now automated for web targets (A03-T06) | SBOM of deployed artifacts |
| A04-T03 (residual) | A04 | Exhaustive cipher-suite enumeration beyond handshake-level analysis | TLS handshake analysis automated (cert validity, self-signed, hostname, legacy protocols) | Deep cipher audit (optional testssl.sh) |
| A05-T03 | A05 | Reliable dynamic injection testing requires exploit-level payloads the platform refuses to send by design | Reflection findings as candidate sinks | Authorized injection test records |
| A06-T01 | A06 | Design flaws are not machine-detectable from black-box observation | Hygiene signals (rate limiting, session hygiene) as design-review inputs | WSTG-BUSL/ASVS design review |
| A07-T04 (residual) | A07 | Session expiry/rotation, MFA enforcement, password policy need multi-flow account control | Logout invalidation + JWT forgery now automated with a test account (A07-T05, A04-T05) | Multi-flow session test records |
| A08-T02 | A08 | Artifact signing/provenance/update mechanisms are process-level | SRI + source-map exposure/secret checks for client-side integrity | Pipeline & release assessment |
| A09-T01 | A09 | Server logs and SIEM alerts are invisible to black-box scanning | Nothing (fundamentally unobservable) | Log/SIEM event validation against requirements |

**Standing rule:** these are recorded in every scan's coverage as
`MANUAL_REVIEW_REQUIRED` with the reason — never silently converted to a pass, and
never used to claim a category is secure when they are outstanding.

## New automated capabilities (latest increment)

Logout invalidation (A07-T05), JWT forgery verification (A04-T05), authenticated
surface mapping (A01-T07), open-redirect probing (A01-T08), source-map secret
scanning (A07-T06), and exposed-manifest detection (A03-T06) are now automated,
gated on an encrypted credential profile for the authenticated checks.

