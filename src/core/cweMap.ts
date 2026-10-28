/**
 * CWE → OWASP Top 10:2025 category mapping.
 *
 * Used to classify external scanner findings that carry a CWE but no OWASP tag.
 * The mapping is derived from the per-category CWE lists in `owasp.ts` plus a
 * curated override table for CWEs that appear in multiple categories (first
 * match wins — overrides handle the ambiguous ones explicitly).
 *
 * This is necessarily lossy: CWE→category is many-to-one and context-dependent.
 * Adapted findings keep their original CWE so a reviewer can re-classify.
 */
import { OWASP_CATEGORIES, ALL_CATEGORIES } from './owasp.ts';
import type { OwaspCategory } from './types.ts';

/**
 * Curated overrides for CWEs that are absent from the official 2025 lists or
 * where practice diverges from the official mapping. Every entry is a
 * documented judgment call, not an official mapping.
 */
const OVERRIDES: Record<number, OwaspCategory> = {
  // Not in any official 2025 list: prototype pollution treated as data-integrity failure
  1321: 'A08',
  // CWE-645 (user enumeration) was dropped from the 2025 A07 list but remains
  // the canonical CWE for username-enumeration findings
  645: 'A07',
  // CWE-693 (protection mechanism failure) is what ZAP emits for missing
  // security headers — filed under misconfiguration
  693: 'A02',
  // CWE-16 covered officially; kept for scanners emitting the generic 756
  756: 'A10',
  // CWE-829 (inclusion of functionality from untrusted sphere — external scripts
  // without SRI) is not in the official 2025 lists; filed under integrity (A08)
  829: 'A08',
};

const REVERSE: Map<number, OwaspCategory> = new Map();
for (const cat of ALL_CATEGORIES) {
  for (const cwe of OWASP_CATEGORIES[cat].cwes) {
    if (!REVERSE.has(cwe)) REVERSE.set(cwe, cat);
  }
}
for (const [cwe, cat] of Object.entries(OVERRIDES)) {
  REVERSE.set(Number(cwe), cat);
}

/** Fallback used when a CWE is unknown or absent but the title is suggestive. */
const TITLE_PATTERNS: Array<[RegExp, OwaspCategory]> = [
  [/sql\s*injection/i, 'A05'],
  [/xss|cross.?site.?script/i, 'A05'],
  [/command\s*(injection|execution)/i, 'A05'],
  [/path\s*traversal|directory\s*traversal/i, 'A01'],
  [/open\s*redirect/i, 'A01'],
  [/clickjack/i, 'A02'],
  [/content-security-policy|security\s*header|missing\s*header/i, 'A02'],
  [/directory\s*list/i, 'A02'],
  [/(hardcoded|hard-coded)\s*(secret|password|key|credential)/i, 'A07'],
  [/weak\s*(crypto|cipher|hash|password)/i, 'A04'],
  [/tls|ssl|certificate/i, 'A04'],
  [/outdated|vulnerable\s*(dependency|component|package)|supply\s*chain/i, 'A03'],
  [/deserializ/i, 'A08'],
  [/stack\s*trace|verbose\s*error|error\s*disclosure/i, 'A10'],
  [/rate.?limit|brute.?force|lockout/i, 'A07'],
  [/sri|subresource\s*integrity/i, 'A08'],
  [/log(ging|s)?\s*(absent|missing|failure)/i, 'A09'],
];

export function categoryForCwe(cwe?: number): OwaspCategory | undefined {
  if (cwe === undefined || cwe === null) return undefined;
  return REVERSE.get(cwe);
}

export function categoryForTitle(title: string): OwaspCategory | undefined {
  for (const [re, cat] of TITLE_PATTERNS) {
    if (re.test(title)) return cat;
  }
  return undefined;
}

export function classifyFinding(
  cwe: number | undefined,
  title: string,
  owaspTag?: string,
): OwaspCategory {
  if (owaspTag) {
    const m = /^\s*A(0[1-9]|10)/i.exec(owaspTag) ?? /\bA(0[1-9]|10)\b/i.exec(owaspTag);
    if (m) {
      const code = `A${m[1]}`.toUpperCase() as OwaspCategory;
      // Tool tags without a year are assumed to be the widely-deployed 2021
      // numbering (e.g. semgrep p/owasp-top-ten). Translate 2021 → 2025 where
      // the codes moved. "2025" in the tag disables translation.
      if (!/2025/.test(owaspTag)) {
        const translation: Record<string, OwaspCategory> = {
          A02: 'A04', A03: 'A05', A04: 'A06', A05: 'A02', A06: 'A03',
          // 2021 A10 was SSRF; SSRF sits in the 2025 injection family (A05)
          A10: 'A05',
        };
        const hit = translation[code];
        if (hit) return hit;
      }
      return code;
    }
  }
  return categoryForCwe(cwe) ?? categoryForTitle(title) ?? 'A02';
}

/** Severity normalization from CVSS score or vendor labels. */
export function severityFromCvss(score: number | undefined): import('./types.ts').Severity {
  if (score === undefined || Number.isNaN(score)) return 'medium';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}
