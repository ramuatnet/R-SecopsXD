# Planted issues (ground truth for source-review mode)

| ID  | File            | Issue                                        | Expected category | Expected CWE | Expected rule id            |
|-----|-----------------|----------------------------------------------|-------------------|--------------|-----------------------------|
| SP-1| src/users.js    | SQL built by string concatenation            | A05               | 89           | sql-concatenation           |
| SP-2| src/auth.js     | Hardcoded credential (API_SECRET)            | A07               | 798          | hardcoded-credential        |
| SP-3| src/auth.js     | MD5 for password hashing                     | A04               | 327          | weak-hash-md5-sha1          |
| SP-4| src/auth.js     | rejectUnauthorized: false                    | A04               | 295          | tls-verification-disabled   |

Dependency inventory (A03): lodash 4.17.15, minimist 1.2.0, node-fetch 2.6.0 — all have
published advisories, used to verify SCA adapters (Trivy/Grype) produce CVE findings when
installed. This code is never executed; do not deploy outside a test rig.
