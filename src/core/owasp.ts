/**
 * OWASP Top 10:2025 (Final) catalog.
 *
 * Category codes, names, CWE lists and canonical URLs verified against the
 * OWASP/Top10 repository (2025/docs/en) and top10.owasp.org/2025 — see
 * docs/CAPABILITY-MATRIX.md for sources. `automation` is the honest
 * per-category statement used in coverage reports and UI; it never claims
 * full automated coverage.
 */
import type { OwaspCategory } from './types.ts';

export interface OwaspCategoryInfo {
  code: OwaspCategory;
  name: string;
  summary: string;
  reference: string;
  /** Official CWE mappings from the 2025 final documents. */
  cwes: number[];
  /** What automated scanning can and cannot conclude for this category. */
  automation: string;
}

export const OWASP_CATEGORIES: Record<OwaspCategory, OwaspCategoryInfo> = {
  A01: {
    code: 'A01',
    name: 'Broken Access Control',
    summary:
      'Restrictions on what authenticated users are allowed to do are not correctly enforced.',
    reference: 'https://top10.owasp.org/2025/en/A01_2025-Broken_Access_Control/',
    cwes: [22, 23, 36, 59, 61, 65, 200, 201, 219, 276, 281, 282, 283, 284, 285, 352, 359, 377, 379, 402, 424, 425, 441, 497, 538, 540, 548, 552, 566, 601, 615, 639, 668, 732, 749, 862, 863, 918, 922, 1275],
    automation:
      'Hardest category to automate. Automated probes detect unauthenticated exposure of ' +
      'sensitive paths and missing authorization on observed endpoints (incl. SSRF/outbound ' +
      'request controls, CWE-918, filed here in 2025). Business-logic IDOR and horizontal ' +
      'privilege escalation require multiple authenticated roles and remain manual (or need ' +
      'ZAP with authenticated sessions).',
  },
  A02: {
    code: 'A02',
    name: 'Security Misconfiguration',
    summary:
      'Missing or incorrect hardening of the application stack, or poorly configured permissions.',
    reference: 'https://top10.owasp.org/2025/en/A02_2025-Security_Misconfiguration/',
    cwes: [5, 11, 13, 15, 16, 260, 315, 489, 526, 547, 611, 614, 776, 942, 1004, 1174],
    automation:
      'Well suited to automation: security headers, cookie flags, directory listings, default ' +
      'pages, verbose banners, exposed config files and XXE-prone parser configs are ' +
      'observable. Whether a configuration is wrong for a specific business context still ' +
      'needs review.',
  },
  A03: {
    code: 'A03',
    name: 'Software Supply Chain Failures',
    summary:
      'Compromised or vulnerable third-party components, build pipelines or dependencies.',
    reference: 'https://top10.owasp.org/2025/en/A03_2025-Software_Supply_Chain_Failures/',
    cwes: [447, 1035, 1104, 1329, 1357, 1395],
    automation:
      'Known-vulnerable and untrusted dependencies are detected by SCA scanners (Trivy/Grype) ' +
      'against advisory databases. Unknown malicious packages, typosquatting judgement and ' +
      'build-pipeline compromise require SBOM review and process controls automation cannot ' +
      'replace.',
  },
  A04: {
    code: 'A04',
    name: 'Cryptographic Failures',
    summary:
      'Failures related to cryptography: weak algorithms, cleartext transmission, hardcoded keys.',
    reference: 'https://top10.owasp.org/2025/en/A04_2025-Cryptographic_Failures/',
    cwes: [261, 296, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 334, 335, 336, 337, 338, 340, 342, 347, 523, 757, 759, 760, 780, 916, 1240, 1241],
    automation:
      'Source scanners detect weak primitives (MD5/SHA1 for passwords, ECB, hardcoded keys, ' +
      'disabled certificate validation); cleartext transmission is observable over HTTP. ' +
      'Protocol-level flaws (weak TLS cipher negotiation) need dedicated TLS tooling not ' +
      'bundled here.',
  },
  A05: {
    code: 'A05',
    name: 'Injection',
    summary:
      'Untrusted data interpreted as code: SQL/NoSQL/OS/LDAP injection, XSS, and related.',
    reference: 'https://top10.owasp.org/2025/en/A05_2025-Injection/',
    cwes: [20, 74, 76, 77, 78, 79, 80, 83, 86, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 103, 104, 112, 113, 114, 115, 116, 129, 159, 470, 493, 500, 564, 610, 643, 644, 917],
    automation:
      'SAST (Semgrep) finds many injection sinks from source code. DAST can confirm reflected ' +
      'XSS/injection with marker-based probes in active mode; blind, time-based and ' +
      'false-positive-prone injection classes need careful manual verification. Absence of a ' +
      'finding does NOT prove absence of injection.',
  },
  A06: {
    code: 'A06',
    name: 'Insecure Design',
    summary:
      'Missing or ineffective control design: threat-modeling gaps, missing trust boundaries.',
    reference: 'https://top10.owasp.org/2025/en/A06_2025-Insecure_Design/',
    cwes: [73, 183, 256, 266, 269, 286, 311, 312, 313, 316, 362, 382, 419, 434, 436, 444, 451, 454, 472, 501, 522, 525, 539, 598, 602, 628, 642, 646, 653, 656, 657, 676, 693, 799, 807, 841, 1021, 1022, 1125],
    automation:
      'Largely manual-only by nature. Automation contributes hygiene signals (missing rate ' +
      'limiting on auth, weak-password policy indicators) and the WSTG/ASVS-linked manual ' +
      'review checklist in reports; design flaws themselves are not machine-detectable.',
  },
  A07: {
    code: 'A07',
    name: 'Authentication Failures',
    summary:
      'Credential stuffing, weak passwords, broken session handling, missing MFA.',
    reference: 'https://top10.owasp.org/2025/en/A07_2025-Authentication_Failures/',
    cwes: [258, 259, 287, 288, 289, 290, 291, 293, 294, 295, 297, 298, 299, 300, 302, 303, 304, 305, 306, 307, 308, 309, 346, 350, 384, 521, 613, 620, 640, 798, 940, 941, 1390, 1391, 1392, 1393],
    automation:
      'Observable automatically: login over cleartext, weak session cookie flags, user ' +
      'enumeration via differential responses, absent rate limiting (bounded probe), hardcoded ' +
      'credentials in source. Password policy quality, MFA correctness and ' +
      'credential-stuffing resistance need authenticated manual testing.',
  },
  A08: {
    code: 'A08',
    name: 'Software or Data Integrity Failures',
    summary:
      'Code/infrastructure/data trusted without integrity verification (unsigned updates, ' +
      'deserialization, missing SRI).',
    reference: 'https://top10.owasp.org/2025/en/A08_2025-Software_and_Data_Integrity_Failures/',
    cwes: [345, 353, 426, 427, 494, 502, 506, 509, 565, 784, 829, 830, 915, 926],
    automation:
      'Detectable signals: external scripts without SRI, unsigned dependency artifacts, ' +
      'insecure deserialization sinks via SAST, CI configs pulling unverified artifacts. ' +
      'Deep pipeline integrity verification (reproducible builds, signing) is process-level ' +
      'and manual.',
  },
  A09: {
    code: 'A09',
    name: 'Security Logging and Alerting Failures',
    summary:
      'Missing, broken or unauditable logging of security-relevant events.',
    reference: 'https://top10.owasp.org/2025/en/A09_2025-Security_Logging_and_Alerting_Failures/',
    cwes: [117, 221, 223, 532, 778],
    automation:
      'Partially detectable: source review can flag absent log statements around auth/crypto ' +
      'paths and log-injection risks; black-box scans can only show what responses disclose, ' +
      'not what the server logs. Verification requires log access — treated as manual.',
  },
  A10: {
    code: 'A10',
    name: 'Mishandling of Exceptional Conditions',
    summary:
      'Errors handled inconsistently: stack traces disclosed, fail-open paths, verbose errors.',
    reference: 'https://top10.owasp.org/2025/en/A10_2025-Mishandling_of_Exceptional_Conditions/',
    cwes: [209, 215, 234, 235, 248, 252, 274, 280, 369, 390, 391, 394, 396, 397, 460, 476, 478, 484, 550, 636, 703, 754, 755, 756],
    automation:
      'Detectable: verbose stack traces/error details in responses (passive on error paths we ' +
      'hit, active when probing parameterized error paths), fail-open patterns in source. ' +
      'Whether an exception path is reachable in a production flow often needs manual ' +
      'verification.',
  },
};

export const ALL_CATEGORIES: OwaspCategory[] = [
  'A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10',
];

export function categoryName(code: OwaspCategory): string {
  return OWASP_CATEGORIES[code].name;
}
