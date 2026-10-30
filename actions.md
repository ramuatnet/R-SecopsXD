actions.md — close the OS / network-level gap
Action plan derived from validated repo state at commit 4ab34cd (2026-10-30). Competitive frame: Black Kite, UpGuard, Bright Security (DAST), standard EASM (Censys, Cortex Xpanse, Defender EASM, CyCognito class).

Every item below is grounded in code that was read, not commit messages. Priority order is deliberate: nothing new gets built until the orphaned scanner is reachable.

0. Validation summary (evidence-based)
Landed and verified working
Capability	Evidence
Autonomous loop wired into scan lifecycle	orchestrator.executeScan branches to runLoopScan when config.loopEnabled && kind === 'webapp'; linear fallback on throw (I11)
Loop telemetry	scan_trace table, readTrace, SSE streams it (T-W4)
Verification hardening	per-type validators; unknown types return inconclusive
Sub-scan hygiene	real triage map + dedupeFindings
Host-header injection	wired inside pathProbe (raw socket, active only)
OOB + blind SSRF	blindSsrfProbe.ts, registered as builtin.blind-ssrf-probe
Evidence/PoC/scoring/RBAC/SARIF/CycloneDX/scheduler	present
Broken or unreachable (the actionable defects)
Defect	Proof
internalScan.ts fully orphaned	not imported by registry.ts; TargetKind = 'webapp' | 'source'; no profile has a cidr kind; createTarget rejects anything else; scanCidr() returns bare PortScanResult[], emits zero RawFinding
blind-ssrf-probe unreachable	registered but absent from every profile's activeEngines and from ACTIVE_PROBE_ENGINES in loop.ts
No service→CVE matching	banner captured, never mapped to versions/advisories
No OS fingerprinting	18-port TCP + HTTP GET banner only
Internal hosts not modelled	no asset node type for hosts/IPs; findings would land with no asset linkage
Commit overstates completion	"all non-Rust tasks complete" while T-X3 is unreachable and T-X5 is assertion-only
1. Competitive parity (honest)
Capability	Black Kite	UpGuard	Bright Security	EASM class	R-SecopsXD now
External asset discovery (DNS/CT/SAN)	yes	yes	—	yes	partial (asmDiscovery)
Port scanning	yes	yes	—	yes	orphaned
Service fingerprint	yes	yes	—	yes	banner string only, orphaned
Service version → CVE	yes	yes	—	yes	no
OS fingerprint	yes	yes	—	yes	no
Internal network scan	limited	no	—	no	orphaned
App-layer DAST (OWASP)	no	no	yes	no	yes, strong
Evidence + reproducible PoC	no	no	partial	no	yes
Autonomous decide-next loop	no	no	partial	no	yes
Third-party risk ratings	yes	yes	no	no	no
Read: R-SecopsXD already beats all four on app-layer depth, evidence and autonomy. It loses entirely on device/OS-level exposure. That is the gap to close — and the orphaned scanner means the gap is wider than the code suggests.

2. Invariants for this phase
Existing I1–I12 hold. Add:

I13 Network egress. Non-HTTP scanning (TCP/UDP) still honours approved scope: a CIDR must be registered + approved; no implicit wide scans.
I14 Port budget. Every network scan is bounded by an explicit port list and concurrency/timeout budget; defaults are safe.
I15 Host findings are findings. Port/service/OS results normalise into the same Finding model with fingerprint, evidence and severity ⊥ confidence — no side channel of raw port dumps.
3. Action items
P0 — Unblock what already exists
A1. Wire internalScan end-to-end

Add 'cidr' to TargetKind (core/types.ts) and to createTarget validation (validate CIDR, private-range default, reject >/24).
New builtin.internal-scan engine wrapper: calls scanCidr, maps each open port to a RawFinding (info severity, CWE-1327/exposure, evidence = {kind:'process'} + banner excerpt).
Register in registry.create + allEngineIds; add an internal-scan profile (targetKinds: ['cidr']).
Add host asset nodes to the target model (asset:host), link findings by asset.
Accept: register 127.0.0.1/32 → approve → scan → open port on a fixture produces ≥1 finding with asset linkage; port budget enforced; >/24 rejected.
A2. Make blind-ssrf-probe reachable

Add to standard-active/external-dast activeEngines and to ACTIVE_PROBE_ENGINES in loop.ts, gated on the OOB server being up.
Accept: fixture blind-SSRF endpoint detected via callback; probe skipped (and recorded, I8) when OOB is down.
A3. Orphan guard in CI

Test that every src/**/*.ts module is reachable from server.ts/cli.ts, and that every registered engine id appears in ≥1 profile.
Accept: deliberately unregistering an engine fails the suite.
P1 — The parity core
A4. Service + version fingerprinting

Replace the blind GET / banner with protocol-aware probes per port (HTTP/S, TLS, SSH, FTP, SMTP, Redis, MySQL, Postgres, Mongo).
Extract product/version strings into structured service + version.
Accept: fixture services fingerprinted with version; unknown services recorded as unknown (never guessed).
A5. Service version → CVE matching

Map (service, version) to advisories via the existing Trivy/Grype adapter path or an offline OSV/NVD snapshot.
Emit cve on the finding; severity from CVSS.
Accept: fixture running an outdated version yields a matching CVE; current version yields none; no version ⇒ no CVE claim (I8).
A6. OS fingerprinting

Passive TTL/TCP-stack heuristics first (no extra packets); optional nmap -O adapter behind availability detection.
Emit os.family / os.version on the host asset, unknown when inconclusive.
Accept: Linux and Windows fixtures distinguished; inconclusive stays unknown.
A7. Unified asset graph

Extend the model with asset:host → asset:service → finding edges; render in the model API and report.
Accept: model endpoint returns host→service→finding traversal for a CIDR scan.
P2 — Depth and realism
A8. UDP + non-HTTP protocols — bounded UDP (DNS/NTP/SNMP) and raw banner grabs; same finding pipeline. Accept: UDP fixture detected. A9. Exposure classification — tag every asset internal / external; feed the existing scoring model's exposure factor. Accept: score differs for identical finding internal vs external. A10. Credentialed host checks — SSH/WinRM read-only version + patch level for authenticated internal depth. Accept: fixture host assessed with credentials. A11. Asset inventory + ownership — first-class asset list per target with labels, so findings roll up by host. Accept: inventory API + rollup report.

P3 — EASM surface parity
A12. CT-log + subdomain expansion into the asset graph with explicit scope-widening approval. Accept: fixture domain tree discovered, approval-gated. A13. Host findings in reports — HTML/PDF/SARIF sections for network assets. Accept: report snapshot contains host section; SARIF rule mapping.

4. Sequencing and gates
A1 → A3 → A2 (unblock + guard) → gate: orphan suite green → A4 → A5 → A6 → A7 (parity core) → gate: precision/recall on host fixtures → A8 → A9 → A10 → A11 → A12 → A13.

Do not start A4 before A1. Building fingerprinting on an unreachable engine repeats the exact mistake this plan exists to fix.

5. Definition of done
cidr target scans end-to-end through the API with findings and asset linkage.
Orphan guard green; every engine reachable from a profile.
Host findings carry service, version, CVE (when known) and exposure class.
No claim in docs that is not reachable in code.
tsc --noEmit + full suite green.
6. Anti-regression
 CIDR requires registration + approval (I13).
 Port/concurrency/timeout budgets enforced (I14).
 Unknown service/OS stays unknown, never guessed (I8).
 Host findings normalise to the standard model (I15).
 No new orphan module (I12/A3).
 Loop still terminates by closure/budget on every e2e.
7. Risk notes
Wide scans. A /24 × 18 ports × timeouts is slow; default to a curated port set and cap concurrency.
Banner ambiguity. Many services speak first only after a protocol prompt — a bare GET / to 3306 misfires; A4 fixes this.
CVE false positives. Version strings lie (backports). Match on exact version ranges and keep confidence medium unless a version banner is unambiguous.
Scope creep. Internal scanning invites "scan the whole estate"; keep registration + approval mandatory.