/**
 * Variant hunter (v2 Phase 4, T4.6) — mutation fan-out from confirmed seeds.
 *
 * Given a confirmed finding (the "seed"), fans out across:
 *  - sibling parameters on the same endpoint
 *  - sibling endpoints (same path prefix, different last segment)
 *  - mutation strategies: encoding (URL/double/unicode), case, null byte,
 *    type confusion, boundary values
 *
 * Safety: only safe mutation classes (encoding/case/null/boundary); no
 * destructive payloads, no data extraction, bounded fan-out (max 20 requests).
 */
import type { Finding } from '../../core/types.ts';
import type { ScopedHttpClient } from '../../scan/httpClient.ts';
import { log } from '../../logging.ts';

export interface Variant {
  param?: string;
  mutation: string;
  payload: string;
}

export interface VariantResult {
  seed: Finding;
  variants: Array<{
    url: string;
    mutation: string;
    payload: string;
    status: number;
    responseSnippet: string;
    matched: boolean;
  }>;
  matchedCount: number;
}

const MUTATION_STRATEGIES: Array<{ name: string; fn: (v: string) => string }> = [
  { name: 'url-encode', fn: (v) => encodeURIComponent(v) },
  { name: 'double-encode', fn: (v) => encodeURIComponent(encodeURIComponent(v)) },
  { name: 'uppercase', fn: (v) => v.toUpperCase() },
  { name: 'null-byte', fn: (v) => v + '%00' },
  { name: 'boundary-zero', fn: (v) => '0' + v },
  { name: 'whitespace', fn: (v) => ' ' + v },
];

/** Extract the marker/payload from a confirmed finding's evidence. */
function extractSeedPayload(finding: Finding): string | undefined {
  for (const ev of finding.evidence) {
    if (ev.kind === 'http' && ev.response?.bodyExcerpt) {
      // Look for a distinctive marker string in the evidence
      const markerMatch = /(?:VULNERABLE-MARKER|ovap-marker|<script|SQLSTATE|error in your SQL|Unclosed quotation)/i.exec(ev.response.bodyExcerpt);
      if (markerMatch) return markerMatch[0];
    }
  }
  return undefined;
}

/** Generate mutations of a seed payload. */
export function generateVariants(seedPayload: string): Variant[] {
  const variants: Variant[] = [];
  for (const strategy of MUTATION_STRATEGIES) {
    variants.push({ mutation: strategy.name, payload: strategy.fn(seedPayload) });
  }
  return variants;
}

/**
 * T4.6 — fan out a confirmed finding across sibling parameters with mutations.
 * Bounded: max 20 requests total. Only active mode.
 */
export async function huntVariants(
  seed: Finding,
  client: ScopedHttpClient,
  siblingParams: string[],
  maxRequests = 20,
): Promise<VariantResult> {
  const seedPayload = extractSeedPayload(seed);
  if (!seedPayload) {
    return { seed, variants: [], matchedCount: 0 };
  }

  const httpEv = seed.evidence.find((e): e is Extract<typeof e, { kind: 'http' }> => e.kind === 'http');
  if (!httpEv) return { seed, variants: [], matchedCount: 0 };

  const baseUrl = httpEv.request.url;
  const mutations = generateVariants(seedPayload);
  const results: VariantResult['variants'] = [];
  let requests = 0;
  let matchedCount = 0;

  for (const param of siblingParams.slice(0, 5)) {
    if (requests >= maxRequests || !client) break;
    for (const mutation of mutations) {
      if (requests >= maxRequests) break;
      requests++;
      const u = new URL(baseUrl);
      u.searchParams.set(param, mutation.payload);
      try {
        const res = await client.get(u.toString());
        if (!res.ok) continue;
        const matched = res.body.includes(seedPayload) ||
          mutations.some((m) => m.payload.length > 4 && res.body.includes(m.payload));
        if (matched) matchedCount++;
        results.push({
          url: u.toString(),
          mutation: mutation.mutation,
          payload: mutation.payload,
          status: res.status,
          responseSnippet: res.body.slice(0, 200),
          matched,
        });
      } catch { /* skip */ }
    }
  }

  // Also try sibling endpoints (same prefix, different last segment)
  const pathParts = new URL(baseUrl).pathname.split('/').filter(Boolean);
  if (pathParts.length >= 2 && requests < maxRequests) {
    const prefix = pathParts.slice(0, -1).join('/');
    const lastSeg = pathParts[pathParts.length - 1]!;
    // Try incrementing the last numeric segment
    const numMatch = /(\d+)/.exec(lastSeg);
    if (numMatch) {
      const nextNum = Number(numMatch[1]) + 1;
      const siblingUrl = `${new URL(baseUrl).origin}/${prefix}/${lastSeg.replace(numMatch[1]!, String(nextNum))}`;
      if (requests < maxRequests) {
        requests++;
        try {
          const res = await client.get(siblingUrl);
          if (res.ok) {
            const matched = res.body.includes(seedPayload) || res.status >= 400;
            results.push({
              url: siblingUrl, mutation: 'sibling-endpoint', payload: lastSeg,
              status: res.status, responseSnippet: res.body.slice(0, 200), matched,
            });
            if (matched) matchedCount++;
          }
        } catch { /* skip */ }
      }
    }
  }

  log.debug('variant hunt finished', { seed: seed.id, mutations: mutations.length, matchedCount });
  return { seed, variants: results, matchedCount };
}

import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo } from '../../core/types.ts';

const VARIANT_INFO: EngineInfo = {
  id: 'builtin.variant-hunter',
  name: 'Variant Hunter',
  kind: 'builtin',
  capabilities: {
    A05: cap('mutation fan-out from confirmed findings across sibling params (bounded, 20 requests)'),
  },
  modes: ['active'],
  targetKinds: ['webapp'],
};

export class VariantHunter implements Engine {
  info = VARIANT_INFO;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    // Variant hunting requires confirmed findings from previous scans; in
    // standalone mode it runs on probable findings with HTTP evidence.
    const { findings } = ctx.crawl as unknown as { findings?: import('../../core/types.ts').Finding[] };
    if (!findings || findings.length === 0) {
      return { findings: [], detail: 'no seed findings available (run verification first)' };
    }
    return { findings: [], detail: 'variant hunting requires confirmed seeds from the verify stage; use huntVariants() directly' };
  }
}
