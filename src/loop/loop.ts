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
  type: 'engine' | 'verify' | 'probe';
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
  crawledPaths: Set<string>;
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

  return candidates;
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
      executedEngines, executedProbes,
      crawledPaths: new Set(ctx.crawl.pages.map((p) => new URL(p.url).pathname)),
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
      const gate = await runProbeGate(ctx.db, {
        target: ctx.target, origin: ctx.target.origin,
        pages: ctx.crawl.pages, client: ctx.client, guard: ctx.guard,
        signal: ctx.signal, log: (m, f) => log.debug(m, f),
      }, { maxProbes: 10, maxRequests: Math.max(0, budget.maxRequests - (ctx.stats.sent - startRequests)) }, ctx.stats, [action.target]);
      executedProbes.add(action.id);
      modelDeltas = gate.results.length;
      outcome = gate.results.map((r) => `${r.capability}=${r.state}`).join(', ') || 'no-probe-ran';
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
  }

  if (iteration >= budget.maxIterations) terminatedBy = 'budget';

  const traceHash = createHash('sha256')
    .update(JSON.stringify(trace.map((t) => ({ i: t.iteration, a: t.actionId, o: t.outcome, f: t.findingCount }))))
    .digest('hex')
    .slice(0, 16);

  return { iterations: iteration, trace, findings, terminatedBy, traceHash };
}
