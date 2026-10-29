/**
 * Built-in endpoint discovery engine (passive) — spec §4/§7.
 *
 * Fetches same-origin JavaScript bundles discovered in the crawl and extracts
 * API endpoint candidates from fetch/axios/url patterns. The result feeds the
 * other probes (path-probe, authenticated-probe surface map) via
 * ctx.crawl.discoveredEndpoints — SPAs hide their real API surface in bundles,
 * not in links.
 *
 * Discovery is inventory (informational). The discovered endpoints are probed
 * by the active engines with the same safety rules as everything else.
 */
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding } from '../../core/types.ts';

const INFO: EngineInfo = {
  id: 'builtin.endpoint-discovery',
  name: 'JS Bundle Endpoint Discovery',
  kind: 'builtin',
  capabilities: {
    A01: cap('undocumented API endpoint discovery from served JavaScript bundles (informational inventory that feeds active probes)'),
  },
  modes: ['passive', 'active'],
  targetKinds: ['webapp'],
};

const MAX_BUNDLES = 8;
const MAX_ENDPOINTS = 60;

/** Route strings from fetch/axios/url usage plus multi-segment API-path literals. */
const ROUTE_PATTERNS: RegExp[] = [
  /(?:fetch|axios|\burl)\s*[(=:]\s*[`"']([^`"'()\s]+)[`"']/g,
  /[`"'](\/(?:api|rest|v[0-9])\/[A-Za-z0-9_\-/.{}$]+)[`"']/g,
  /[`"'](\/[a-z][a-z0-9_\-]+\/[a-z][A-Za-z0-9_\-/.{}$]+)[`"']/g,
  /[`"'](\/v[0-9][A-Za-z0-9_\-/.{}$]*)["']/g,
];

export function extractEndpoints(bundle: string, origin: string): string[] {
  const out = new Set<string>();
  for (const re of ROUTE_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(bundle)) !== null && out.size < MAX_ENDPOINTS) {
      const raw = m[1]!.trim();
      if (raw === '' || raw.startsWith('#')) continue;
      try {
        const u = new URL(raw, origin);
        if (u.origin !== origin) continue; // third-party URLs are not this app's surface
        if (!u.pathname.startsWith('/')) continue;
        if (/\.(js|css|png|jpe?g|svg|ico|woff2?|map)$/i.test(u.pathname)) continue;
        out.add(u.pathname);
      } catch { /* skip malformed */ }
    }
  }
  return [...out];
}

export class EndpointDiscoveryEngine implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const corpus = ctx.crawl ?? { pages: [], robots: { disallow: [], fetched: false } };
    ctx.crawl = corpus;
    const originHost = new URL(ctx.target.origin).hostname;

    // Collect same-origin bundles from crawled pages (bounded).
    const bundles = new Set<string>();
    for (const page of corpus.pages) {
      const re = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;
      let m: RegExpExecArray | null;
      while ((m = re.exec(page.body)) !== null && bundles.size < MAX_BUNDLES) {
        try {
          const u = new URL(m[1]!, page.url);
          if (u.hostname !== originHost) continue;
          if (u.pathname.endsWith('.js')) bundles.add(u.toString());
        } catch { /* skip malformed */ }
      }
    }

    const endpoints = new Set<string>();
    let fetched = 0;
    for (const bundleUrl of bundles) {
      if (fetched >= MAX_BUNDLES || ctx.signal.aborted) break;
      fetched++;
      const res = await ctx.client.get(bundleUrl);
      if (!res.ok || res.status !== 200) continue;
      for (const e of extractEndpoints(res.body, ctx.target.origin)) endpoints.add(e);
    }

    corpus.discoveredEndpoints = [...endpoints].slice(0, MAX_ENDPOINTS);

    if (endpoints.size === 0) {
      return { findings: [], version: 'builtin', detail: `${fetched} bundle(s) fetched; no API endpoints discovered` };
    }

    const examples = corpus.discoveredEndpoints.slice(0, 10).join(', ');
    const findings: RawFinding[] = [{
      rawId: 'undocumented-endpoints-discovered',
      title: `${endpoints.size} API endpoint(s) discovered from served JavaScript bundles`,
      category: 'A01',
      cwe: 200,
      severity: 'info',
      confidence: 'high',
      status: 'informational',
      asset: ctx.target.origin,
      locator: '/ (JavaScript bundles)',
      evidence: [{
        kind: 'http',
        request: { method: 'GET', url: [...bundles][0] ?? ctx.target.origin, headers: {} },
        response: { status: 200, headers: {}, bodyExcerpt: `endpoints: ${examples}` },
        observation: `Bundle analysis extracted ${endpoints.size} endpoint path(s) that the crawl did not surface as links`,
      }],
      explanation:
        'The served JavaScript bundles reference API endpoints that never appear as page links. These are ' +
        'inventory (informational): they are fed into the active authorization and access-control probes so ' +
        'hidden surface gets tested like visible surface. A large hidden API surface is also a design signal ' +
        'for the security review.',
      remediation:
        'Ensure every discovered endpoint enforces authentication and authorization consistent with its ' +
        'sensitivity, and that undocumented/unversioned endpoints are intentional.',
      references: ['https://owasp.org/www-project-api-security/'],
    }];

    ctx.log('endpoint discovery finished', { bundles: fetched, endpoints: endpoints.size });
    return { findings, version: 'builtin', detail: `${endpoints.size} endpoint(s) from ${fetched} bundle(s)` };
  }
}
