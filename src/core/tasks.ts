/**
 * Assessment-task registry (automation program Phase 2).
 *
 * Every automatable or by-design-manual check is declared here as data. The
 * coverage layer derives per-task execution status from engine run records and
 * findings — an unexecuted task is never a pass, and manual tasks keep their
 * honest status. Adding a check = adding an entry (+ an engine if new).
 */
import type { OwaspCategory, ScanMode, TargetKind } from './types.ts';

export type TaskStatus =
  | 'AUTOMATED_PASS'
  | 'FINDING_DETECTED'
  | 'MANUAL_REVIEW_REQUIRED'
  | 'NOT_EXECUTED'
  | 'BLOCKED_BY_SCOPE'
  | 'BLOCKED_BY_SAFETY'
  | 'ENGINE_UNAVAILABLE'
  | 'INCONCLUSIVE'
  | 'ERROR';

export interface AssessmentTask {
  id: string;
  category: OwaspCategory;
  title: string;
  description: string;
  engine: string;
  mode: ScanMode;
  targetKinds: TargetKind[];
  strength: 'strong' | 'heuristic';
  /** Substring matched against finding provenance rawId to attribute findings to this task. */
  rawIdPattern?: string | undefined;
  /** By-design human task: never executes, always MANUAL_REVIEW_REQUIRED. */
  manual?: boolean | undefined;
  /** Prerequisites that passive unauthenticated scans cannot satisfy. */
  requires?: Array<'authenticated' | 'external-tool'> | undefined;
  refs: string[];
  evidenceExpectation: string;
}

const W = (path: string): string => `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/${path}`;

export const TASKS: AssessmentTask[] = [
  // ---------- A01 Broken Access Control ----------
  {
    id: 'A01-T01', category: 'A01', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'heuristic',
    title: 'Sensitive information exposure in served content',
    description: 'Detects internal IPs, infrastructure references and internal endpoint paths exposed in served markup (CWE-540 family).',
    rawIdPattern: 'sensitive-html-comments',
    refs: [W('01-Information_Gathering/README')],
    evidenceExpectation: 'HTTP evidence of the disclosing response',
  },
  {
    id: 'A01-T02', category: 'A01', engine: 'builtin.path-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Unauthenticated exposure of administrative/sensitive paths',
    description: 'Bounded probes of common admin and sensitive paths plus robots.txt entries, calibrated against the not-found page.',
    rawIdPattern: 'path-probe:/admin',
    refs: [W('02-Configuration_and_Deployment_Management_Testing/README')],
    evidenceExpectation: 'HTTP evidence of reachable path with distinct content',
  },
  {
    id: 'A01-T03', category: 'A01', engine: 'builtin.path-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'heuristic',
    title: 'Object-level access-control smoke probe (IDOR family)',
    description: 'For resource URLs discovered with numeric ids, requests one sibling id without credentials. Probable by definition; public reference data can legitimately behave this way.',
    rawIdPattern: 'object-access:',
    refs: [W('05-Authorization_Testing/README')],
    evidenceExpectation: 'HTTP evidence of sibling-id response',
  },
  {
    id: 'A01-T04', category: 'A01', engine: 'manual', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong', manual: true, requires: ['authenticated'],
    title: 'Authenticated horizontal/vertical authorization testing',
    description: 'Requires multiple test identities with distinct roles and synthetic records; compare cross-role access. Platform holds no credentials (backlog B1).',
    refs: [W('05-Authorization_Testing/README')],
    evidenceExpectation: 'Role-matrix test results from authenticated sessions',
  },

  {
    id: 'A01-T07', category: 'A01', engine: 'builtin.authenticated-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong', requires: ['authenticated'],
    title: 'Authenticated surface discovery with the authorized test account',
    description: 'Informational inventory of pages served to the test account that deny anonymous access — the reference set for authorization review.',
    rawIdPattern: 'authenticated-surface-map',
    refs: [W('05-Authorization_Testing/README')],
    evidenceExpectation: 'Inventory of anonymously-denied pages (session values redacted)',
  },
  {
    id: 'A01-T05', category: 'A01', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'heuristic',
    title: 'Sensitive data in URL query strings',
    description: 'Flags query parameters whose names suggest credential/session content (CWE-598). Probable: value sensitivity cannot be verified passively.',
    rawIdPattern: 'sensitive-data-in-url',
    refs: [W('04-Authentication_Testing/README')],
    evidenceExpectation: 'Crawled URL evidence with parameter name',
  },
  {
    id: 'A01-T06', category: 'A01', engine: 'builtin.path-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Source map exposure for crawled scripts',
    description: 'Probes sibling .js.map files of crawled scripts; a served map discloses original source code.',
    rawIdPattern: 'source-map-exposed',
    refs: [W('01-Information_Gathering/README')],
    evidenceExpectation: 'HTTP evidence of served map with sources member',
  },

  {
    id: 'A01-T09', category: 'A01', engine: 'builtin.graphql-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'GraphQL introspection exposure (information disclosure)',
    description: 'Same probe as A05-T04, attributed to information exposure under A01.',
    rawIdPattern: 'graphql-introspection-enabled',
    refs: ['https://owasp.org/www-project-api-security/'],
    evidenceExpectation: 'Introspection response evidence',
  },
  {
    id: 'A01-T08', category: 'A01', engine: 'builtin.redirect-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Open redirect probing on discovered redirect parameters',
    description: 'Re-issues discovered redirect parameters pointing at an IETF-reserved marker host (never contacted). Server 30x to the marker = confirmed; client-side redirect = probable.',
    rawIdPattern: 'open-redirect',
    refs: [W('05-Authorization_Testing/README')],
    evidenceExpectation: 'Redirect evidence to the reserved marker host',
  },

  {
    id: 'A02-T07', category: 'A02', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'CSP quality analysis (unsafe-inline / unsafe-eval / permissive object-src)',
    description: 'A present-but-weakened CSP is a confirmed configuration weakness, distinct from a missing header.',
    rawIdPattern: 'csp-weak-directives',
    refs: ['https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'],
    evidenceExpectation: 'CSP header evidence',
  },
  {
    id: 'A02-T08', category: 'A02', engine: 'builtin.graphql-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'GraphQL playground/editor exposure',
    description: 'Detects unauthenticated interactive GraphQL editors at conventional endpoints.',
    rawIdPattern: 'graphql-playground-exposed',
    refs: ['https://owasp.org/www-project-api-security/'],
    evidenceExpectation: 'Playground HTML evidence',
  },

  {
    id: 'A01-T11', category: 'A01', engine: 'builtin.authenticated-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong', requires: ['authenticated'],
    title: 'Cross-role authorization matrix (two test identities)',
    description: 'Pages reachable by the primary account are re-requested with a second-role identity. Secondary access without redirect = broken function-level authorization signature (probable).',
    rawIdPattern: 'cross-role-access',
    refs: [W('05-Authorization_Testing/README')],
    evidenceExpectation: 'Both-role request evidence (session values redacted)',
  },
  {
    id: 'A01-T12', category: 'A01', engine: 'builtin.endpoint-discovery', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Undocumented API endpoint discovery from JavaScript bundles',
    description: 'Extracts API routes from served bundles (informational inventory) and feeds them into the active authorization probes.',
    rawIdPattern: 'undocumented-endpoints-discovered',
    refs: ['https://owasp.org/www-project-api-security/'],
    evidenceExpectation: 'Bundle evidence with extracted endpoint list',
  },
  {
    id: 'A01-T10', category: 'A01', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'heuristic',
    title: 'CSRF exposure: state-changing forms without visible tokens + SameSite-less session',
    description: 'Markup-level signal for cross-site request forgery (CWE-352). Server-side validation cannot be observed — probable.',
    rawIdPattern: 'csrf-exposure',
    refs: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'],
    evidenceExpectation: 'Form markup + cookie evidence',
  },
  // ---------- A03 Software Supply Chain Failures ----------
  {
    id: 'A02-T01', category: 'A02', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Security header configuration (CSP, XCTO, XFO, Referrer-Policy)',
    description: 'Observes presence of defense-in-depth headers on crawled responses.',
    rawIdPattern: 'missing-security-headers',
    refs: ['https://owasp.org/www-project-secure-headers/'],
    evidenceExpectation: 'HTTP response headers from crawled pages',
  },
  {
    id: 'A02-T02', category: 'A02', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Cookie attribute configuration (HttpOnly/Secure/SameSite)',
    description: 'Observes Set-Cookie attributes on crawled responses.',
    rawIdPattern: 'cookie-missing-flags',
    refs: [W('06-Session_Management_Testing/README')],
    evidenceExpectation: 'Set-Cookie evidence with missing attributes',
  },
  {
    id: 'A02-T03', category: 'A02', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Software version disclosure via Server/X-Powered-By banners',
    description: 'Flags version-bearing stack banners (reconnaissance information).',
    rawIdPattern: 'server-banner-disclosure',
    refs: [W('01-Information_Gathering/README')],
    evidenceExpectation: 'Response header evidence',
  },
  {
    id: 'A02-T04', category: 'A02', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Directory listing exposure on crawled paths',
    description: 'Detects generated directory indexes in crawled responses.',
    rawIdPattern: 'directory-listing',
    refs: [W('02-Configuration_and_Deployment_Management_Testing/README')],
    evidenceExpectation: 'HTML evidence of listing page',
  },
  {
    id: 'A02-T05', category: 'A02', engine: 'builtin.path-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Exposed configuration/backup files and admin surfaces',
    description: 'Bounded probes for .env, .git, backups, actuator-style endpoints with content validation.',
    rawIdPattern: 'path-probe:/',
    refs: [W('02-Configuration_and_Deployment_Management_Testing/README')],
    evidenceExpectation: 'HTTP evidence of exposed resource',
  },

  {
    id: 'A02-T06', category: 'A02', engine: 'builtin.http-observation', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'CORS policy configuration',
    description: 'Active check on ACAO-bearing responses: foreign-Origin reflection with credentials (confirmed misconfiguration) and wildcard+credentials combinations.',
    rawIdPattern: 'cors-',
    refs: [W('02-Configuration_and_Deployment_Management_Testing/README')],
    evidenceExpectation: 'Response headers reflecting foreign Origin',
  },

  // ---------- A03 Software Supply Chain Failures ----------
  {
    id: 'A03-T01', category: 'A03', engine: 'builtin.dep-manifest', mode: 'passive',
    targetKinds: ['source'], strength: 'strong',
    title: 'Dependency inventory from manifests/lockfiles',
    description: 'Inventories locked packages; flags missing lockfiles. Inventory is not vulnerability assessment.',
    rawIdPattern: 'dependency-inventory',
    refs: ['https://owasp.org/Top10/2025/en/A03_2025-Software_Supply_Chain_Failures/'],
    evidenceExpectation: 'Dependency evidence with counts',
  },
  {
    id: 'A03-T02', category: 'A03', engine: 'adapter.trivy', mode: 'passive',
    targetKinds: ['source'], strength: 'strong', requires: ['external-tool'],
    title: 'Known CVE matching (Trivy)',
    description: 'Advisory-database matching on lockfiles/manifests.',
    rawIdPattern: '',
    refs: ['https://trivy.dev/'],
    evidenceExpectation: 'CVE advisories with installed/fixed versions',
  },
  {
    id: 'A03-T03', category: 'A03', engine: 'adapter.grype', mode: 'passive',
    targetKinds: ['source'], strength: 'strong', requires: ['external-tool'],
    title: 'Known CVE matching (Grype)',
    description: 'Advisory-database matching on source directories.',
    rawIdPattern: '',
    refs: ['https://github.com/anchore/grype'],
    evidenceExpectation: 'CVE/GHSA advisories with installed/fixed versions',
  },
  {
    id: 'A03-T06', category: 'A03', engine: 'builtin.path-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Exposed dependency manifests/lockfiles on the web target',
    description: 'Probes for publicly retrievable package.json/package-lock.json — supply-chain reconnaissance material.',
    rawIdPattern: 'path-probe:/package',
    refs: ['https://owasp.org/Top10/2025/en/A03_2025-Software_Supply_Chain_Failures/'],
    evidenceExpectation: 'HTTP evidence of exposed manifest',
  },
  {
    id: 'A03-T05', category: 'A03', engine: 'manual', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong', manual: true,
    title: 'SBOM review of the deployed application',
    description: 'A deployed web application has no inspectable lockfile over HTTP; supply-chain assessment of what is actually deployed requires build-system access and an SBOM.',
    refs: ['https://owasp.org/Top10/2025/en/A03_2025-Software_Supply_Chain_Failures/'],
    evidenceExpectation: 'SBOM of deployed artifacts + review record',
  },
  {
    id: 'A03-T04', category: 'A03', engine: 'manual', mode: 'passive',
    targetKinds: ['source'], strength: 'strong', manual: true,
    title: 'Malicious-package / typosquatting judgement and build-pipeline review',
    description: 'Heuristic name scores are not evidence of malice; provenance, signing and pipeline integrity require human review and process controls.',
    refs: ['https://owasp.org/Top10/2025/en/A03_2025-Software_Supply_Chain_Failures/'],
    evidenceExpectation: 'Documented SBOM review and pipeline assessment',
  },

  {
    id: 'A03-T07', category: 'A03', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Vulnerable frontend library versions loaded (curated advisories)',
    description: 'Version fingerprinting from script URLs matched against a curated advisory list (jQuery, Bootstrap). Deterministic version match; exploitability needs review.',
    rawIdPattern: 'js-library-known-vulnerability',
    refs: ['https://owasp.org/Top10/2025/en/A03_2025-Software_Supply_Chain_Failures/'],
    evidenceExpectation: 'Script URL with parsed version',
  },
  // ---------- A04 Cryptographic Failures ----------
  {
    id: 'A04-T01', category: 'A04', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Cleartext transport of credential-bearing forms',
    description: 'Observes password forms delivered over http://. Informational on private targets by design.',
    rawIdPattern: 'cleartext-credential-form',
    refs: ['https://owasp.org/Top10/2025/en/A04_2025-Cryptographic_Failures/'],
    evidenceExpectation: 'HTTP evidence of form over cleartext',
  },
  {
    id: 'A04-T02', category: 'A04', engine: 'builtin.source-scan', mode: 'passive',
    targetKinds: ['source'], strength: 'heuristic',
    title: 'Weak crypto primitives and disabled certificate validation in source',
    description: 'Pattern-level detection (MD5/SHA1, rejectUnauthorized:false). No dataflow analysis.',
    rawIdPattern: 'weak-hash-md5-sha1',
    refs: [W('09-Testing_for_Weak_Cryptography/README')],
    evidenceExpectation: 'File+line evidence',
  },
  {
    id: 'A04-T03', category: 'A04', engine: 'builtin.tls-analysis', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'TLS certificate and protocol analysis (handshake-level)',
    description: 'Deterministic handshake analysis: certificate expiry/self-signing/hostname match, negotiated protocol, legacy-TLS acceptance. Exhaustive cipher enumeration still merits dedicated tooling.',
    rawIdPattern: 'tls-',
    refs: [W('09-Testing_for_Weak_Cryptography/README')],
    evidenceExpectation: 'Handshake evidence (protocol, cipher, certificate fields)',
  },

  {
    id: 'A04-T06', category: 'A04', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'HSTS absence on HTTPS origins',
    description: 'Deterministic observation: HTTPS served without Strict-Transport-Security permits first-request downgrade.',
    rawIdPattern: 'hsts-missing',
    refs: ['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html'],
    evidenceExpectation: 'Response header evidence',
  },

  {
    id: 'A04-T07', category: 'A04', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Mixed content: cleartext subresources on HTTPS pages',
    description: 'HTTPS pages loading http:// scripts/iframes/images (CWE-311).',
    rawIdPattern: 'mixed-content',
    refs: ['https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content'],
    evidenceExpectation: 'HTML evidence of cleartext subresource',
  },
  // ---------- A05 Injection ----------
  {
    id: 'A05-T01', category: 'A05', engine: 'builtin.reflection-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Unencoded reflection of user input (reflected-XSS precondition)',
    description: 'Marker-tag reflection detection on crawled query parameters. Confirms unencoded output; script-context exploitability stays probable.',
    rawIdPattern: 'reflection:',
    refs: [W('07-Input_Validation_Testing/README')],
    evidenceExpectation: 'HTTP evidence of unencoded marker in response',
  },
  {
    id: 'A05-T02', category: 'A05', engine: 'builtin.source-scan', mode: 'passive',
    targetKinds: ['source'], strength: 'heuristic',
    title: 'SQL concatenation and eval patterns in source',
    description: 'Regex heuristics without dataflow analysis; probable status by definition.',
    rawIdPattern: 'sql-concatenation',
    refs: [W('07-Input_Validation_Testing/README')],
    evidenceExpectation: 'File+line evidence',
  },
  {
    id: 'A05-T04', category: 'A05', engine: 'builtin.graphql-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'GraphQL introspection enabled',
    description: 'Bounded read-only introspection probe — full schema disclosure is the reconnaissance gift.',
    rawIdPattern: 'graphql-introspection-enabled',
    refs: ['https://owasp.org/www-project-api-security/'],
    evidenceExpectation: 'Introspection response evidence',
  },
  {
    id: 'A05-T05', category: 'A05', engine: 'builtin.reflection-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'heuristic',
    title: 'Error-based SQL injection differential (single-quote probe vs baseline)',
    description: 'One bounded probe per discovered parameter; database-error differential against the crawled baseline. No data extraction, no blind/time-based testing.',
    rawIdPattern: 'sqli-error-differential',
    refs: [W('07-Input_Validation_Testing/README')],
    evidenceExpectation: 'Baseline + probe response evidence',
  },
  {
    id: 'A05-T03', category: 'A05', engine: 'manual', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong', manual: true, requires: ['authenticated'],
    title: 'Dynamic injection testing beyond bounded reflection (SQLi/NoSQLi/commandi/SSTI/blind)',
    description: 'Reliable dynamic injection testing needs controlled payloads with exploit-level verification; the platform deliberately does not send destructive or exploit payloads. Manual or dedicated authorized DAST tooling.',
    refs: [W('07-Input_Validation_Testing/README')],
    evidenceExpectation: 'Authorized injection test records',
  },

  // ---------- A06 Insecure Design ----------
  {
    id: 'A06-T01', category: 'A06', engine: 'manual', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong', manual: true,
    title: 'Design and threat-model review (trust boundaries, recovery flows, step-up auth)',
    description: 'Design flaws are not machine-detectable from black-box observation. Automation contributes hygiene signals only (e.g. missing rate limiting, filed under A07).',
    refs: [W('10-Business_Logic_Testing/README')],
    evidenceExpectation: 'Structured design review against WSTG-BUSL/ASVS',
  },

  {
    id: 'A06-T02', category: 'A06', engine: 'builtin.openapi-policy', mode: 'passive',
    targetKinds: ['webapp'], strength: 'heuristic',
    title: 'API design-policy signals from exposed OpenAPI/Swagger specifications',
    description: 'When the target exposes a machine-readable spec: reports the exposure and operations declared without authentication requirements. Spec-level signal — enforcement still needs verification.',
    rawIdPattern: 'openapi-',
    refs: [W('03-Identity_Management_Testing/README')],
    evidenceExpectation: 'Spec content evidence with per-operation analysis',
  },

  {
    id: 'A04-T05', category: 'A04', engine: 'builtin.authenticated-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong', requires: ['authenticated'],
    title: 'JWT forgery verification (alg=none / stripped signature) against the live session',
    description: 'When the session token is a JWT, submits forged variants to the protected page with the authorized test account. Confirms actual acceptance, not merely observation.',
    rawIdPattern: 'jwt-forgery-accepted',
    refs: ['https://datatracker.ietf.org/doc/html/rfc8725'],
    evidenceExpectation: 'Forged-token request evidence (session material redacted)',
  },

  // ---------- A07 Authentication Failures ----------
  {
    id: 'A07-T01', category: 'A07', engine: 'builtin.auth-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Username enumeration via differential login responses',
    description: 'Compares normalized responses for nonexistent probe users vs a common username. Probable without a known-valid account.',
    rawIdPattern: 'username-enumeration',
    refs: [W('04-Authentication_Testing/README')],
    evidenceExpectation: 'Differential response evidence',
  },
  {
    id: 'A07-T02', category: 'A07', engine: 'builtin.auth-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Missing rate limiting on authentication endpoint',
    description: 'Bounded 8-attempt failed-login probe observing for 429/lockout responses. No credential guessing.',
    rawIdPattern: 'no-login-rate-limit',
    refs: [W('04-Authentication_Testing/README')],
    evidenceExpectation: 'Probe sequence evidence',
  },
  {
    id: 'A07-T03', category: 'A07', engine: 'builtin.source-scan', mode: 'passive',
    targetKinds: ['source'], strength: 'heuristic',
    title: 'Hardcoded credentials in source',
    description: 'Pattern-level detection of embedded secrets.',
    rawIdPattern: 'hardcoded-credential',
    refs: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
    evidenceExpectation: 'File+line evidence',
  },
  {
    id: 'A07-T04', category: 'A07', engine: 'manual', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong', manual: true, requires: ['authenticated'],
    title: 'Session lifecycle, lockout, MFA and password-policy validation',
    description: 'Requires test accounts and session control; cookie-flag observations do not demonstrate session compromise.',
    refs: [W('06-Session_Management_Testing/README')],
    evidenceExpectation: 'Authenticated session test records',
  },

  {
    id: 'A04-T04', category: 'A04', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'heuristic',
    title: 'JWT handling observation (alg=none, missing expiry)',
    description: 'Passively decodes JWTs served by the target and flags unsigned algorithms and missing exp claims. Observation only — active forgery testing is out of scope without authorized tokens.',
    rawIdPattern: 'jwt-',
    refs: ['https://datatracker.ietf.org/doc/html/rfc8725'],
    evidenceExpectation: 'Redacted token header/payload evidence',
  },

  {
    id: 'A07-T05', category: 'A07', engine: 'builtin.authenticated-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'strong', requires: ['authenticated'],
    title: 'Session invalidation after logout',
    description: 'Reuses the pre-logout session on a protected page after exercising logout. Confirms server-side invalidation behavior with the authorized test account.',
    rawIdPattern: 'session-not-invalidated',
    refs: [W('06-Session_Management_Testing/README')],
    evidenceExpectation: 'Pre/post-logout request evidence (session values redacted)',
  },

  // ---------- A08 Software or Data Integrity Failures ----------
  {
    id: 'A08-T01', category: 'A08', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'External scripts without Subresource Integrity (SRI)',
    description: 'Detects cross-origin <script src> without an integrity attribute on crawled pages.',
    rawIdPattern: 'sri-external-script',
    refs: ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'],
    evidenceExpectation: 'HTML evidence of the script tag',
  },
  {
    id: 'A07-T07', category: 'A07', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'heuristic',
    title: 'Secrets in served JavaScript bundles',
    description: 'Fetches a bounded set of crawled bundles and scans for high-signal secret patterns. Values redacted; probable until verified.',
    rawIdPattern: 'js-bundle-secret',
    refs: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
    evidenceExpectation: 'Redacted matched excerpt from the bundle',
  },
  {
    id: 'A07-T06', category: 'A07', engine: 'builtin.path-probe', mode: 'active',
    targetKinds: ['webapp'], strength: 'heuristic',
    title: 'Secrets embedded in exposed source maps',
    description: 'Scans served .js.map sourcesContent for credential patterns. Values redacted; probable until verified.',
    rawIdPattern: 'source-map-secrets',
    refs: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
    evidenceExpectation: 'Redacted matched line from the map content',
  },
  {
    id: 'A08-T02', category: 'A08', engine: 'manual', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong', manual: true,
    title: 'Pipeline integrity: artifact signing, provenance attestation, update verification',
    description: 'Process-level controls not observable from black-box HTTP; requires repository/CI access and administrator review.',
    refs: ['https://owasp.org/Top10/2025/en/A08_2025-Software_and_Data_Integrity_Failures/'],
    evidenceExpectation: 'Pipeline and release-process assessment',
  },

  // ---------- A09 Security Logging and Alerting Failures ----------
  {
    id: 'A09-T01', category: 'A09', engine: 'manual', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong', manual: true,
    title: 'Server-side logging and alerting effectiveness review',
    description: 'Black-box HTTP observation cannot see what the server logs or whether alerts fire; requires log/SIEM access. Unverified by scans by nature.',
    refs: [W('08-Testing_for_Error_Handling/README')],
    evidenceExpectation: 'Log/SIEM configuration and event validation',
  },

  {
    id: 'A09-T02', category: 'A09', engine: 'builtin.source-scan', mode: 'passive',
    targetKinds: ['source'], strength: 'heuristic',
    title: 'Logging hygiene in source: secrets in logs, log injection',
    description: 'Pattern-level detection of credential-bearing log statements and request data interpolated into logs.',
    rawIdPattern: '-logs',
    refs: ['https://owasp.org/Top10/2025/en/A09_2025-Security_Logging_and_Alerting_Failures/'],
    evidenceExpectation: 'File+line evidence',
  },
  {
    id: 'A09-T03', category: 'A09', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'heuristic',
    title: 'Log-correlation indicators on error responses',
    description: 'Observes correlation/request-id headers on error responses (positive hygiene signal). Does NOT verify that security events are logged or alerted.',
    rawIdPattern: 'log-correlation-header',
    refs: ['https://owasp.org/Top10/2025/en/A09_2025-Security_Logging_and_Alerting_Failures/'],
    evidenceExpectation: 'Error response header evidence',
  },

  // ---------- A10 Mishandling of Exceptional Conditions ----------
  {
    id: 'A10-T01', category: 'A10', engine: 'builtin.http-observation', mode: 'passive',
    targetKinds: ['webapp'], strength: 'strong',
    title: 'Verbose error disclosure in observed responses',
    description: 'Detects stack traces, internal paths and framework exceptions in crawled error responses.',
    rawIdPattern: 'verbose-error-disclosure',
    refs: [W('08-Testing_for_Error_Handling/README')],
    evidenceExpectation: 'HTTP evidence of error page contents',
  },
];

export function tasksForProfile(profileId: string, mode: ScanMode, targetKind: TargetKind): AssessmentTask[] {
  return TASKS.filter((t) => t.targetKinds.includes(targetKind) && t.mode === mode);
}

export function getTask(id: string): AssessmentTask | undefined {
  return TASKS.find((t) => t.id === id);
}
