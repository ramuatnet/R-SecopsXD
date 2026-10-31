# LIMITATIONS — explicit, current as of 2026-10-31

This file exists so no claim outruns its evidence. Everything here is a known
boundary, not a hidden gap. Section references point at hardtask.md.

## Risk scoring
- **Risk base is severity-derived for most findings** (base_source: 'severity').
  Real CVSS/EPSS values apply ONLY to findings carrying a CVE present in the
  offline snapshot (`src/risk/advisories.ts`, snapshot 2026-10-31, 12 entries).
  The 25× internal-vs-edge worked example is proven end-to-end as a FORMULA and
  through the report pipeline — but on synthetic CVEs for most categories
  (L1 will be "fully real" only when the snapshot covers every advisory or a
  live feed lands). (W5/L1)
- **EPSS values are a snapshot** — EPSS shifts daily; refresh
  `src/risk/advisories.ts` periodically. (L1)
- **Blast factor is neutral (1.0) in reports unless the graph has edges for the
  finding's asset node**; live scans attach graph fan-out where it exists (L2).

## Port detection
- **Connect-with-no-protocol-answer ports are reported `unverified`** at
  info/low confidence (H1): a real quiet service (SSH, Redis) and a
  connect-accepting middlebox look identical at TCP level. The
  `port-scan-interference` finding (H2/H3, threshold 8, critical ports exempt)
  tells you when a middlebox is likely the cause. Residual risk: a quiet real
  service behind such a middlebox is suppressed (counter-test exempts 22/443/
  3306/3389/5432/6379/9200/27017 only). (W1/W2)
- Only ~35 TCP ports are probed; UDP (SNMP etc.) is not scanned.

## Verification / statuses
- `rejected_by_verification` (machine) is distinct from `false_positive`
  (human triage) (I2), and the recall floor asserts planted true positives are
  never auto-rejected (I1/I17) — enforced on fixture scans only; arbitrary
  targets have no ground truth.

## Supply chain
- nuclei authenticity is a two-stage chain: pinned published-artifact hash must
  appear in the vendor's committed checksums.txt, and the on-disk binary must
  match the pinned extracted hash (J1/I18). The checksums.txt itself is
  committed at review time — a fully automated freshness check would need
  live re-fetching (deliberately not done offline).
- The template pack digest is pinned (`templates/pack-version.json`, J3); a
  template change without a bump commit fails lint.

## Data plane
- The application writes **SQLite**; the Postgres deployment (`rsec-postgres`
  container) is schema-validated and writable via the stdlib wire client
  (trust-auth PoC user) but is not the primary store. Production Postgres needs
  SCRAM support in the wire client or the `pg` driver (ADR decision). (W7)
- **Kafka**: the `KafkaHttpBus` adapter talks to a real Redpanda broker over
  its HTTP proxy with plain fetch. The Redpanda container segfaulted once in
  1G overprovisioned mode under WSL2 (2G is stable); the test skips honestly
  when the broker is down. No Kafka-native protocol client (zero-dep ADR).
- **Temporal** is not deployed — a worker needs `@temporalio/sdk`, which the
  zero-dependency ADR forbids. The AssessAsset state machine is the same
  workflow, in-process.

## Scanning capabilities
- **SSH credentialed checks (E4)** run via the system `ssh` binary against
  key-auth targets (PoC: one container). No vault integration; no WinRM.
- **TTL OS hypothesis (M2)** comes from the system `ping` binary; remote hosts
  decrement TTL per hop, so it is low confidence by construction.
- **Blind-SSRF OOB correlation** is proven end-to-end on loopback (T4.7 loop
  test); public targets need a publicly reachable callback host before OOB
  findings can fire there.
- Coverage verdicts are evidence-based, but "covered" on real targets still
  means "the executed engines can conclude this" — not "this is secure".
