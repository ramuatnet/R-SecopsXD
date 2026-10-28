/**
 * The autonomous loop (v2 Phase 3) — the differentiator.
 *
 * sense → model → decide → act → verify → adapt, terminating by closure or
 * budget (I10). The planner ranks candidate actions by
 * score = P(worth) × information_gain / estimated_cost, safety- and
 * budget-gated, with deterministic tie-breaks (T3.2). Every iteration is
 * traced; findings from `act` are verified before promotion (T5-lite);
 * discovered endpoints feed subsequent actions. Determinism mode: fixed seed
 * + budget ⇒ reproducible trace hash (T3.6).
 *
 * v1 act-layer: existing TS engines (per tasksrd §0 — the Rust data plane
 * plugs in behind the same engine ids later).
 */
import { createHash } from 'node:crypto';
import type { Database } from '../db/database.ts';
import type { TargetModel } from '../model/targetModel.ts';
import type { Finding, RawFinding, Target } from '../core/types.ts';
import type { EngineRegistry } from '../engines/registry.ts';
import type { Config } from '../config.ts';
import type { ScopedHttpClient, RequestStats } from '../scan/httpClient.ts';
import type { ScopeGuard } from '../safety/guard.ts';
import type { ScanContext, CrawlCorpus, CredentialProfile } from '../engines/types.ts';
import { normalizeFinding } from '../scan/normalize.ts';
import { log } from '../logging.ts';

export interface LoopAction {
  id: string;
  type: 'engine' | 'verify' | 'probe' | 'subscan';
  /** engine id for type 'engine'; finding id for 'verify'. */
  target: string;
  reason: string;
  worth: number;       // P(worth) 0..1
  infoGain: number;    // 0..10
  cost: number;        // estimated requests
  score: number;       // computed by decide
}

export interface LoopBudget {
  maxIterations: number;
  maxRequests: number;
  maxMs: number;
  seed: number;
  /** T3.4 fan-out cap: max sub-scans per loop run (default 3). */
  subscanFanout?: number | undefined;
}

export interface LoopTraceEntry {
  iteration: number;
  actionId: string | undefined;
  outcome: string;
  findingCount: number;
  requestsAfter: number;
}

export interface LoopResult {
  iterations: number;
  trace: LoopTraceEntry[];
  findings: Finding[];
  terminatedBy: 'closure' | 'budget';
  traceHash: string;
}

export interface LoopContext {
  db: Database;
  model: TargetModel;
  target: Target;
  mode: 'passive' | 'active';
  registry: EngineRegistry;
  config: Config;
  client: ScopedHttpClient;
  guard: ScopeGuard;
  stats: RequestStats;
  signal: AbortSignal;
  workDir: string;
  crawl: CrawlCorpus;
  credentials?: CredentialProfile | undefined;
  credentialsSecondary?: CredentialProfile | undefined;
}

// ---------- T3.1 planner: candidate generators ----------

export interface PlannerInput {
  model: TargetModel;
  mode: 'passive' | 'active';
  findings: Finding[];
  executedEngines: Set<string>;
  executedProbes: Set<string>;
  /** Sub-scan subtree roots already executed (T3.4 recursion novelty). */
  executedSubscans: Set<string>;
  crawledPaths: Set<string>;
  discoveredEndpoints: string[];
  /** Remaining sub-scan fan-out budget (T3.4 cap). */
  subscanBudget: number;
}

const CAPABILITY_ENGINES: Record<string, string> = {
  'api.graphql': 'builtin.graphql-probe',
  'auth.form': 'builtin.auth-probe',
  'frontend.spa': 'builtin.endpoint-discovery',
  'api.openapi': 'builtin.openapi-policy',
};

const ACTIVE_PROBE_ENGINES = [
  'builtin.path-probe', 'builtin.reflection-probe', 'builtin.auth-probe', 'builtin.redirect-probe',
];

const GATE_CAPABILITIES = [
  'frontend.spa', 'api.openapi', 'api.graphql', 'auth.form', 'edge.cdn-waf', 'cloud.markers', 'surface.sitemap',
];

export function planCandidates(input: PlannerInput): LoopAction[] {
  const candidates: LoopAction[] = [];

  // 0. unknown capabilities → probe them (gate actions, one per capability)
  for (const cap of GATE_CAPABILITIES) {
    if (input.model.state('capability', cap) === 'unknown' && !input.executedProbes.has(`probe:${cap}`)) {
      candidates.push({
        id: `probe:${cap}`, type: 'probe', target: cap,
        reason: `capability ${cap} is unknown`, worth: 0.9, infoGain: 6, cost: 1, score: 0,
      });
    }
  }

  // 1. capability present → run the engine that acts on it (once)
  for (const [cap, engine] of Object.entries(CAPABILITY_ENGINES)) {
    if (input.model.state('capability', cap) === 'present' && !input.executedEngines.has(engine)) {
      candidates.push({
        id: `engine:${engine}`, type: 'engine', target: engine,
        reason: `capability ${cap} present`, worth: 0.95, infoGain: 8, cost: 5, score: 0,
      });
    }
  }

  // 2. active mode → bounded surface probes (once each); auth-probe skipped
  // when auth.form was probed absent (nothing to probe — I8: recorded, not passed)
  if (input.mode === 'active') {
    for (const engine of ACTIVE_PROBE_ENGINES) {
      if (engine === 'builtin.auth-probe' && input.model.state('capability', 'auth.form') === 'absent') {
        continue;
      }
      if (!input.executedEngines.has(engine)) {
        candidates.push({
          id: `engine:${engine}`, type: 'engine', target: engine,
          reason: 'active surface probe', worth: 0.9, infoGain: 7, cost: 6, score: 0,
        });
      }
    }
  }

  // 3. probable findings → verify (independent re-observation)
  for (const f of input.findings.filter((x) => x.status === 'probable' && x.evidence.some((e) => e.kind === 'http'))) {
    candidates.push({
      id: `verify:${f.id}`, type: 'verify', target: f.id,
      reason: `probable finding pending confirmation: ${f.title.slice(0, 60)}`,
      worth: 0.85, infoGain: 5, cost: 1, score: 0,
    });
  }

  // 4. recursion (T3.4): ≥2 discovered endpoints under the same first path
  // segment → sub-scan that subtree with a fresh mini-crawl. Depth is capped
  // at 1 by construction (sub-scan results never feed the planner's endpoint
  // list); fan-out is capped by subscanBudget.
  if (input.subscanBudget > 0) {
    const prefixes = new Map<string, number>();
    for (const ep of input.discoveredEndpoints) {
      const segs = ep.split('/').filter((s) => s !== '');
      if (segs.length >= 1) {
        const prefix = '/' + segs[0]!;
        prefixes.set(prefix, (prefixes.get(prefix) ?? 0) + 1);
      }
    }
    for (const [prefix, count] of [...prefixes.entries()].sort()) {
      if (count >= 2 && !input.executedSubscans.has(prefix) && input.subscanBudget - candidates.filter((c) => c.type === 'subscan').length > 0) {
        candidates.push({
          id: `subscan:${prefix}`, type: 'subscan', target: prefix,
          reason: `${count} endpoint(s) discovered under ${prefix} — subtree not crawled`,
          worth: 0.8, infoGain: 7, cost: 4, score: 0,
        });
      }
    }
  }

  return candidates;
}

/**
 * T3.4 sub-scan: bounded mini-crawl of a subtree root (root + discovered
 * endpoints under it, ≤5 pages) followed by HTTP observation on that corpus.
 * Inherits the loop's scoped client — same rate limits, same scope guard.
 * Sub-scan pages do NOT merge into the main corpus, so sub-scan discoveries
 * cannot spawn further sub-scans (depth cap 1 enforced by construction).
 */
export async function runSubscan(
  ctx: LoopContext,
  root: string,
): Promise<{ pages: Array<{ url: string; status: number; headers: Record<string, string>; body: string }>; findings: Finding[] }> {
  const origin = ctx.target.origin;
  const urls = new Set<string>([new URL(root, origin + '/').toString()]);
  for (const ep of ctx.crawl.discoveredEndpoints ?? []) {
    if (ep === root || ep.startsWith(root + '/')) {
      urls.add(new URL(ep, origin + '/').toString());
    }
    if (urls.size >= 5) break;
  }

  const pages: Array<{ url: string; status: number; headers: Record<string, string>; body: string }> = [];
  for (const url of urls) {
    if (ctx.signal.aborted || pages.length >= 5) break;
    const res = await ctx.client.get(url);
    if (res.ok) {
      pages.push({ url: res.finalUrl, status: res.status, headers: res.headers, body: res.body });
    }
  }
  if (pages.length === 0) return { pages, findings: [] };

  const { HttpObservationEngine } = await import('../engines/builtin/httpObservation.ts');
  const engine = new HttpObservationEngine();
  const subCorpus = {
    pages: pages.map((p) => ({
      url: p.url, status: p.status, headers: p.headers, body: p.body, truncated: false,
      forms: [], links: [],
    })),
    robots: { disallow: [], fetched: false },
  };
  const subCtx: ScanContext = {
    scanId: `subscan${root.replace(/\//g, '-')}`, target: ctx.target, mode: ctx.mode,
    client: ctx.client, guard: ctx.guard, stats: ctx.stats, signal: ctx.signal,
    workDir: ctx.workDir, crawl: subCorpus, log: (m, f) => log.debug(m, f),
  };
  const result = await engine.run(subCtx);
  const findings = (result.findings as import('../core/types.ts').RawFinding[]).map((raw) =>
    normalizeFinding(raw, { target: ctx.target, engineId: 'builtin.http-observation', adapter: false, triages: new Map() }),
  );
  return { pages, findings };
}

// ---------- T3.2 decide: scoring + deterministic tie-break ----------

export function decide(candidates: LoopAction[]): LoopAction | undefined {
  if (candidates.length === 0) return undefined;
  const scored = candidates.map((c) => ({
    ...c,
    score: Math.round(((c.worth * c.infoGain) / Math.max(1, c.cost)) * 1000) / 1000,
  }));
  scored.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
  return scored[0];
}

// ---------- T5-lite verify: independent re-observation ----------

export type VerifyOutcome = 'confirmed' | 'rejected' | 'inconclusive';

export async function verifyFinding(finding: Finding, client: ScopedHttpClient): Promise<VerifyOutcome> {
  const ev = finding.evidence.find((e) => e.kind === 'http');
  if (!ev || ev.kind !== 'http' || ev.request.method !== 'GET') return 'inconclusive';
  const excerpt = ev.response?.bodyExcerpt ?? '';
  if (excerpt.trim() === '') return 'inconclusive';
  try {
    const res = await client.get(ev.request.url);
    if (!res.ok) return 'inconclusive';
    // causal-delta check: the evidence's distinctive content must reproduce
    const marker = excerpt.trim().split('\n')[0]!.slice(0, 60);
    return res.body.includes(marker) ? 'confirmed' : 'rejected';
  } catch {
    return 'inconclusive';
  }
}

// ---------- T3.3 the loop ----------

export async function runLoop(ctx: LoopContext, budget: LoopBudget): Promise<LoopResult> {
  const trace: LoopTraceEntry[] = [];
  const executedEngines = new Set<string>();
  const executedProbes = new Set<string>();
  const executedSubscans = new Set<string>();
  const fanoutCap = budget.subscanFanout ?? 3;
  const findings: Finding[] = [];
  let modelDeltas = 0;
  const startRequests = ctx.stats.sent;
  const started = Date.now();
  let terminatedBy: LoopResult['terminatedBy'] = 'closure';
  let iteration = 0;

  // deterministic PRNG (T3.6): mulberry32
  let prngState = budget.seed >>> 0;
  const rand = (): number => {
    prngState = (prngState + 0x6d2b79f5) | 0;
    let t = prngState;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };

  for (; iteration < budget.maxIterations; iteration++) {
    if (ctx.signal.aborted) { terminatedBy = 'budget'; break; }
    if (Date.now() - started > budget.maxMs) { terminatedBy = 'budget'; break; }
    if (ctx.stats.sent - startRequests >= budget.maxRequests) { terminatedBy = 'budget'; break; }

    // --- sense/model: findings from previous iteration are already merged ---
    const plannerInput = {
      model: ctx.model, mode: ctx.mode, findings,
      executedEngines, executedProbes, executedSubscans,
      crawledPaths: new Set(ctx.crawl.pages.map((p) => new URL(p.url).pathname)),
      discoveredEndpoints: ctx.crawl.discoveredEndpoints ?? [],
      subscanBudget: fanoutCap - executedSubscans.size,
    };
    const candidates = planCandidates(plannerInput);
    if (candidates.length === 0) { terminatedBy = 'closure'; break; } // closure: no action worth taking
    const action = decide(candidates)!;
    if (executedEngines.has(`engine:${action.target}`) && action.type === 'engine') {
      terminatedBy = 'closure'; break; // novelty exhausted
    }

    // --- act ---
    let outcome = 'noop';
    let iterationFindings = 0;

    if (action.type === 'probe') {
      const { runProbeGate } = await import('../model/probeGate.ts');
      const gate = await runProbeGate(ctx.model, {
        target: ctx.target, origin: ctx.target.origin,
        pages: ctx.crawl.pages, client: ctx.client, guard: ctx.guard,
        signal: ctx.signal, log: (m, f) => log.debug(m, f),
      }, { maxProbes: 10, maxRequests: Math.max(0, budget.maxRequests - (ctx.stats.sent - startRequests)) }, [action.target]);
      executedProbes.add(action.id);
      modelDeltas = gate.results.length;
      outcome = gate.results.map((r) => `${r.capability}=${r.state}`).join(', ') || 'no-probe-ran';
    } else if (action.type === 'subscan') {
      const sub = await runSubscan(ctx, action.target);
      executedSubscans.add(action.target);
      findings.push(...sub.findings);
      iterationFindings = sub.findings.length;
      outcome = `sub-scan ${action.target}: ${sub.pages.length} page(s), ${sub.findings.length} finding(s)`;
    } else if (action.type === 'engine') {
      const engine = ctx.registry.create(action.target, ctx.config.maxCrawlPages);
      const availability = engine ? await ctx.registry.availability(action.target) : { available: false, reason: 'unknown engine' };
      if (!engine || !availability.available) {
        executedEngines.add(action.target); // I8: recorded as unavailable, never a pass
        outcome = `engine-unavailable: ${availability.reason ?? ''}`;
      } else {
        const scanCtx: ScanContext = {
          scanId: `loop-${budget.seed}`, target: ctx.target, mode: ctx.mode,
          credentials: ctx.credentials, credentialsSecondary: ctx.credentialsSecondary,
          client: ctx.client, guard: ctx.guard, stats: ctx.stats, signal: ctx.signal,
          workDir: ctx.workDir, crawl: ctx.crawl, log: (m, f) => log.debug(m, f),
        };
        const result = await engine.run(scanCtx);
        executedEngines.add(action.target);
        const creds = ctx.credentials ?? { username: 'loop', password: '' };
        for (const raw of result.findings as RawFinding[]) {
          findings.push(normalizeFinding(raw, {
            target: ctx.target, engineId: action.target,
            engineVersion: result.version ?? availability.version, adapter: false,
            triages: new Map(),
          }));
        }
        void creds;
        iterationFindings = result.findings.length;
        outcome = `${result.findings.length} finding(s)`;
      }
    } else {
      // verify
      const f = findings.find((x) => x.id === action.target);
      if (!f) {
        outcome = 'finding-not-found';
      } else {
        const verdict = await verifyFinding(f, ctx.client);
        if (verdict === 'confirmed' && f.status === 'probable') {
          f.status = 'confirmed';
          outcome = 'promoted-to-confirmed';
        } else if (verdict === 'rejected') {
          f.status = 'false_positive';
          outcome = 'rejected-as-false-positive';
        } else {
          outcome = 'inconclusive-kept-probable';
        }
      }
    }

    // I3: audit per iteration is emitted by the caller via db.audit if desired;
    // the trace itself is the loop audit here.
    void rand; // PRNG reserved for tie-break jitter in extended planners
    trace.push({
      iteration,
      actionId: action.id,
      outcome,
      findingCount: iterationFindings,
      requestsAfter: ctx.stats.sent,
    });
    void modelDeltas;
    log.debug('loop iteration', { iteration, action: action.id, outcome });
    if (process.env.LOOP_DEBUG) console.log('[itr]', iteration, action.id, '→', outcome);
  }

  if (iteration >= budget.maxIterations) terminatedBy = 'budget';

  const traceHash = createHash('sha256')
    .update(JSON.stringify(trace.map((t) => ({ i: t.iteration, a: t.actionId, o: t.outcome, f: t.findingCount }))))
    .digest('hex')
    .slice(0, 16);

  return { iterations: iteration, trace, findings, terminatedBy, traceHash };
}
