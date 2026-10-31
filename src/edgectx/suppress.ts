/**
 * Suppression engine (edgetask.md EDGE-05, §8.2, PLT-03) — declarative rules
 * applied to findings after dedupe. Every application is audited; rules carry
 * a version and an `active` flag (PLT-03 review gate: an inactive rule never
 * fires). Suppressed findings are never deleted — they are reclassified or
 * downgraded with the rule id recorded.
 *
 * BUILT-IN RULES (§8.2):
 *  cf-proxied-http-8080  v3  Cloudflare + confidence ≥0.75 + port-open on a
 *                            proxied port → informational edge-proxy-behavior
 *  edge-unverified-9200  v1  any edge vendor + port NOT in vendor proxied set
 *                            → downgrade to candidate, tag edge-unverified
 *  redirect-301-not-evidence v1 a bare 301 on a non-web port is never evidence
 */
import type { Finding } from '../core/types.ts';
import type { EdgeVerdict } from './models.ts';

export interface SuppressionRule {
  id: string;
  version: number;
  active: boolean;
  description: string;
  matches: (f: Finding, verdict: EdgeVerdict | undefined) => boolean;
  apply: (f: Finding) => void;
}

/** Vendor → ports the edge terminates itself (Cloudflare proxied set per §8.2). */
export const VENDOR_PROXIED_PORTS: Record<string, number[]> = {
  cloudflare: [80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096],
  cloudfront: [80, 443],
  fastly: [80, 443],
  akamai: [80, 443],
  azurefd: [80, 443],
};

export const SUPPRESSION_RULES: SuppressionRule[] = [
  {
    id: 'cf-proxied-http-8080',
    version: 3,
    active: true,
    description: 'Port in Cloudflare proxied set; terminated at edge, not origin → informational edge-proxy-behavior',
    matches: (f, verdict) =>
      verdict !== undefined && verdict.vendor === 'cloudflare' && verdict.confidence >= 0.75 &&
      rawIdOf(f) === 'port-open' &&
      [8080, 8443, 2052, 2082, 2086, 2095].includes(parsePort(f.locator)),
    apply: (f) => {
      f.severity = 'info';
      f.status = 'informational';
      f.title = `[edge-proxy-behavior] ${f.title}`;
      f.explanation = 'Port in the Cloudflare proxied set; the connection terminates at the edge, not at the origin. Recorded as informational edge-proxy-behavior — not a vulnerability claim.';
      f.references = [...f.references, 'rule:cf-proxied-http-8080@v3'];
    },
  },
  {
    id: 'edge-unverified-9200',
    version: 1,
    active: true,
    description: 'Edge-fronted host, port NOT in the vendor proxied set → downgrade to candidate/edge-unverified (needs origin verification or a second probe)',
    matches: (f, verdict) =>
      verdict !== undefined && verdict.vendor !== 'none' &&
      ['port-open', 'service-identified'].includes(rawIdOf(f)) &&
      !(VENDOR_PROXIED_PORTS[verdict.vendor] ?? []).includes(parsePort(f.locator)),
    apply: (f) => {
      f.status = 'candidate';
      f.confidence = 'low';
      f.title = `[edge-unverified] ${f.title}`;
      f.explanation = 'Observed through an edge/CDN; the port is not in the vendor proxied set, so this may be edge behavior rather than an origin service. Requires origin verification or a second independent probe before escalation.';
      f.references = [...f.references, 'rule:edge-unverified-9200@v1'];
    },
  },
  {
    id: 'redirect-301-not-evidence',
    version: 1,
    active: true,
    description: 'A bare 301/302 on a management-typical port is never evidence of a management interface',
    matches: (f) =>
      rawIdOf(f) === 'management-interface-exposed' &&
      /(301|302)/.test(f.evidence.map((e) => e.kind === 'process' ? e.observation : '').join(' ')),
    apply: (f) => {
      f.severity = 'info';
      f.status = 'informational';
      f.title = `[redirect-not-evidence] ${f.title}`;
      f.explanation = 'The observation is a bare redirect — a 301/302 alone is never evidence of a management interface (edgetask §9).';
      f.references = [...f.references, 'rule:redirect-301-not-evidence@v1'];
    },
  },
];

function rawIdOf(f: Finding): string {
  return f.provenance[0]?.rawId ?? '';
}

function parsePort(locator: string): number {
  const m = /:(\d+)/.exec(locator);
  return m === null ? 0 : Number(m[1]);
}

export interface SuppressionRecord { findingId: string; rule: string; action: string; }
export interface SuppressionResult {
  findings: Finding[];
  records: SuppressionRecord[];
  suppressedCount: number;
  detail: string;
}

/** EDGE-05: apply active rules; audited via the returned records. */
export function applySuppressions(findings: Finding[], verdict: EdgeVerdict | undefined): SuppressionResult {
  const records: SuppressionRecord[] = [];
  let suppressedCount = 0;
  for (const rule of SUPPRESSION_RULES) {
    if (!rule.active) continue;
    for (const f of findings) {
      if (f.escalate !== undefined) continue; // human escalation always wins
      let matched = false;
      try { matched = rule.matches(f, verdict); } catch { matched = false; }
      if (!matched) continue;
      rule.apply(f);
      f.suppressedBy = `${rule.id}@v${rule.version}`;
      records.push({ findingId: f.id, rule: `${rule.id}@v${rule.version}`, action: rule.description });
      suppressedCount++;
    }
  }
  return {
    findings,
    records,
    suppressedCount,
    detail: `suppression: ${suppressedCount} application(s) across ${SUPPRESSION_RULES.filter((r) => r.active).length} active rule(s)`,
  };
}
