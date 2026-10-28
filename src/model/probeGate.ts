/**
 * Capability Probe Gate (v2 Phase 2, T2.1–T2.4).
 *
 * Ordered, cheap, safe probes that flip capability nodes from unknown →
 * present | absent. Kills the "webapp assumed" bias: every capability the
 * platform acts on must have been probed, with the probe recorded.
 *
 * Safety (T2.4): one bounded request per probe (most are pure observation of
 * the already-crawled corpus), gated by the shared scoped client and capped by
 * budget. "Absence is evidence": an absent probe with its method is itself a
 * recorded result (T2.3).
 */
import type { Database } from '../db/database.ts';
import { TargetModel } from './targetModel.ts';
import type { CrawlPage } from '../engines/types.ts';
import type { Target } from '../core/types.ts';
import type { ScopedHttpClient, RequestStats } from '../scan/httpClient.ts';
import type { ScopeGuard } from '../safety/guard.ts';

export interface ProbeContext {
  target: Target;
  origin: string;
  pages: CrawlPage[];
  client: ScopedHttpClient;
  guard: ScopeGuard;
  signal: AbortSignal;
  log: (msg: string, fields?: Record<string, unknown>) => void;
}

export interface ProbeResult {
  probeId: string;
  capability: string;
  state: 'present' | 'absent' | 'inconclusive';
  evidence: string;
  requestsUsed: number;
}

export interface Probe {
  id: string;
  capability: string;
  /** true = needs a network request; false = observes the crawl corpus only. */
  active: boolean;
  run(ctx: ProbeContext): Promise<ProbeResult>;
}

const OBSERVED = (probeId: string, capability: string, state: 'present' | 'absent' | 'inconclusive', evidence: string): ProbeResult =>
  ({ probeId, capability, state, evidence, requestsUsed: 0 });

function pageText(pages: CrawlPage[]): string {
  return pages.map((p) => p.body).join('\n').slice(0, 200_000);
}

function rootHeaders(pages: CrawlPage[]): Record<string, string> {
  const root = pages.find((p) => new URL(p.url).pathname === '/') ?? pages[0];
  return root?.headers ?? {};
}

// ---------- probe definitions ----------

const PROBES: Probe[] = [
  {
    id: 'probe.http-server', capability: 'http.server', active: false,
    run: async (ctx) => {
      const hit = ctx.pages.some((p) => p.status > 0 && p.status < 600);
      return hit
        ? OBSERVED('probe.http-server', 'http.server', 'present', `${ctx.pages.length} response(s) in corpus`)
        : OBSERVED('probe.http-server', 'http.server', 'absent', 'no responses in corpus');
    },
  },
  {
    id: 'probe.html-frontend', capability: 'frontend.html', active: false,
    run: async (ctx) => {
      const htmlPages = ctx.pages.filter((p) => (p.headers['content-type'] ?? '').includes('text/html') || /<html|<body|<!doctype/i.test(p.body));
      return htmlPages.length > 0
        ? OBSERVED('probe.html-frontend', 'frontend.html', 'present', `${htmlPages.length} HTML page(s)`)
        : OBSERVED('probe.html-frontend', 'frontend.html', 'absent', 'no HTML in corpus');
    },
  },
  {
    id: 'probe.spa-js', capability: 'frontend.spa', active: false,
    run: async (ctx) => {
      const text = pageText(ctx.pages);
      const anchors = (text.match(/<a\s/gi) ?? []).length;
      const scripts = (text.match(/<script\b/gi) ?? []).length;
      if (scripts >= 1 && anchors === 0) {
        return OBSERVED('probe.spa-js', 'frontend.spa', 'present', `${scripts} script tag(s), 0 anchors — client-rendered`);
      }
      if (anchors > 0) return OBSERVED('probe.spa-js', 'frontend.spa', 'absent', `${anchors} server-rendered anchors`);
      return OBSERVED('probe.spa-js', 'frontend.spa', 'inconclusive', 'no scripts and no anchors observed');
    },
  },
  {
    id: 'probe.rest-openapi', capability: 'api.openapi', active: true,
    run: async (ctx) => {
      const fromCorpus = ctx.pages.some((p) => /openapi|swagger/i.test(p.body) && /["']3\.\d|["']2\.0/.test(p.body));
      if (fromCorpus) return OBSERVED('probe.rest-openapi', 'api.openapi', 'present', 'spec referenced in crawled content');
      const res = await ctx.client.get(new URL('/openapi.json', ctx.origin + '/').toString());
      const present = res.ok && res.status === 200 && res.body.includes('"openapi"');
      return {
        probeId: 'probe.rest-openapi', capability: 'api.openapi',
        state: present ? 'present' : 'absent',
        evidence: present ? 'GET /openapi.json returned a valid spec' : 'GET /openapi.json → not a spec',
        requestsUsed: 1,
      };
    },
  },
  {
    id: 'probe.graphql', capability: 'api.graphql', active: true,
    run: async (ctx) => {
      const fromCorpus = ctx.pages.some((p) => /graphiql|graphql/i.test(p.body));
      if (fromCorpus) return OBSERVED('probe.graphql', 'api.graphql', 'present', 'graphql referenced in crawled content');
      const res = await ctx.client.get(new URL('/graphql?query=%7B__typename%7D', ctx.origin + '/').toString());
      const present = res.ok && res.status === 200 && res.body.includes('"data"');
      return {
        probeId: 'probe.graphql', capability: 'api.graphql',
        state: present ? 'present' : 'absent',
        evidence: present ? 'GET /graphql?query={__typename} returned data' : 'GET /graphql → not a GraphQL endpoint',
        requestsUsed: 1,
      };
    },
  },
  {
    id: 'probe.auth-form', capability: 'auth.form', active: false,
    run: async (ctx) => {
      const form = ctx.pages.flatMap((p) => p.forms).find((f) => f.hasPasswordField);
      return form
        ? OBSERVED('probe.auth-form', 'auth.form', 'present', `password form at ${form.action}`)
        : OBSERVED('probe.auth-form', 'auth.form', 'absent', 'no password-bearing form in corpus');
    },
  },
  {
    id: 'probe.session-cookie', capability: 'auth.session-cookie', active: false,
    run: async (ctx) => {
      const sc = ctx.pages.find((p) => (p.headers['set-cookie'] ?? '') !== '');
      return sc
        ? OBSERVED('probe.session-cookie', 'auth.session-cookie', 'present', `Set-Cookie on ${new URL(sc.url).pathname}`)
        : OBSERVED('probe.session-cookie', 'auth.session-cookie', 'absent', 'no Set-Cookie observed');
    },
  },
  {
    id: 'probe.cdn-waf', capability: 'edge.cdn-waf', active: false,
    run: async (ctx) => {
      const h = rootHeaders(ctx.pages);
      const markers = ['cf-ray', 'x-amz-cf-id', 'x-azure-ref', 'x-sucuri-id', 'x-cdn', 'server'];
      const hit = markers.find((k) => k in h);
      if (!hit) return OBSERVED('probe.cdn-waf', 'edge.cdn-waf', 'inconclusive', 'no edge markers in headers');
      const value = (h[hit] ?? '').slice(0, 60);
      const isCdn = ['cf-ray', 'x-amz-cf-id', 'x-azure-ref', 'x-sucuri-id'].includes(hit);
      return OBSERVED('probe.cdn-waf', 'edge.cdn-waf', isCdn ? 'present' : 'inconclusive', `${hit}: ${value}`);
    },
  },
  {
    id: 'probe.cloud-markers', capability: 'cloud.markers', active: false,
    run: async (ctx) => {
      const h = rootHeaders(ctx.pages);
      const text = pageText(ctx.pages);
      const markers: Array<[string, string]> = [
        ['x-amz-request-id', 'AWS'], ['x-amz-id-2', 'AWS'], ['x-ms-request-id', 'Azure'],
        ['x-goog-meta', 'GCP'], ['s3.amazonaws.com', 'AWS S3'], ['blob.core.windows.net', 'Azure Blob'],
        ['amazonaws.com', 'AWS'],
      ];
      const hit = markers.find(([needle]) => h[needle.toLowerCase()] !== undefined || text.includes(needle));
      return hit
        ? OBSERVED('probe.cloud-markers', 'cloud.markers', 'present', `cloud marker: ${hit[1]} (${hit[0]})`)
        : OBSERVED('probe.cloud-markers', 'cloud.markers', 'absent', 'no cloud markers in corpus/headers');
    },
  },
  {
    id: 'probe.websocket', capability: 'api.websocket', active: false,
    run: async (ctx) => {
      const text = pageText(ctx.pages);
      const hit = /wss?:\/\/[^\s"'<]+/.exec(text);
      return hit
        ? OBSERVED('probe.websocket', 'api.websocket', 'present', hit[0].slice(0, 100))
        : OBSERVED('probe.websocket', 'api.websocket', 'absent', 'no ws:// or wss:// references');
    },
  },
  {
    id: 'probe.sitemap', capability: 'surface.sitemap', active: true,
    run: async (ctx) => {
      const res = await ctx.client.get(new URL('/sitemap.xml', ctx.origin + '/').toString());
      const present = res.ok && res.status === 200 && res.body.includes('<urlset');
      return {
        probeId: 'probe.sitemap', capability: 'surface.sitemap',
        state: present ? 'present' : 'absent',
        evidence: present ? 'sitemap.xml served' : 'no sitemap.xml',
        requestsUsed: 1,
      };
    },
  },
];

export const PROBE_CAPABILITIES = [...new Set(PROBES.map((pr) => pr.capability))];

export interface GateResult {
  results: ProbeResult[];
  present: string[];
  absent: string[];
  inconclusive: string[];
  requestsUsed: number;
}

/**
 * Run the ordered probe gate within budget (T2.4). Every result is merged
 * into the Target Model with the probe id as provenance (T2.3: absence is
 * evidence too).
 */
export async function runProbeGate(
  db: Database,
  ctx: ProbeContext,
  budget: { maxProbes: number; maxRequests: number },
  stats: RequestStats,
  capabilities?: string[],
): Promise<GateResult> {
  const model = new TargetModel(db.handle, ctx.target.id);
  const results: ProbeResult[] = [];
  let requestsUsed = 0;

  const ordered = capabilities
    ? PROBES.filter((pr) => capabilities.includes(pr.capability))
    : PROBES;
  for (const probe of ordered) {
    if (results.length >= budget.maxProbes || requestsUsed >= budget.maxRequests || ctx.signal.aborted) break;
    try {
      const r = await probe.run(ctx);
      results.push(r);
      requestsUsed += r.requestsUsed;
      if (r.state !== 'inconclusive') {
        model.set('capability', r.capability, { probe: r.probeId, evidence: r.evidence }, r.probeId, r.state);
      } else {
        model.set('unknown', r.capability, { probe: r.probeId, reason: r.evidence }, r.probeId, 'unknown');
      }
      ctx.log(`gate: ${r.capability} = ${r.state}`, { probe: r.probeId });
    } catch (e) {
      results.push({
        probeId: probe.id, capability: probe.capability, state: 'inconclusive',
        evidence: `probe error: ${e instanceof Error ? e.message : String(e)}`, requestsUsed,
      });
    }
  }

  return {
    results,
    present: results.filter((r) => r.state === 'present').map((r) => r.capability),
    absent: results.filter((r) => r.state === 'absent').map((r) => r.capability),
    inconclusive: results.filter((r) => r.state === 'inconclusive').map((r) => r.capability),
    requestsUsed,
  };
}

