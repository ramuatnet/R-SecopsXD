/**
 * Loop runner (T-W1) — bridges the autonomous loop into the scan lifecycle.
 *
 * Builds a LoopContext from the existing scan infrastructure (guard, client,
 * stats, workDir, crawl, credentials), seeds a bounded crawl so
 * discoveredEndpoints is populated, calls runLoop, maps the trace to
 * EngineRunRecord[], runs dedupeFindings → insertFindings, computes
 * coverage, and persists trace entries to the scan_trace table.
 *
 * Linear fallback (I11): if the loop throws, the caller (executeScan) runs
 * the linear plan and records why.
 */
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Config } from '../config.ts';
import type { Database } from '../db/database.ts';
import type { Finding, Target, EngineRunRecord, ScanMode } from '../core/types.ts';
import type { LoopContext, LoopBudget, LoopResult } from '../loop/loop.ts';
import { runLoop as runLoopFn } from '../loop/loop.ts';
import { TargetModel } from '../model/targetModel.ts';
import { runProbeGate } from '../model/probeGate.ts';
import { EngineRegistry } from '../engines/registry.ts';
import { ScopeGuard } from '../safety/guard.ts';
import { RateLimiter } from '../safety/rateLimiter.ts';
import { Semaphore } from '../safety/concurrency.ts';
import { ScopedHttpClient, type RequestStats } from '../scan/httpClient.ts';
import { dedupeFindings } from '../core/ids.ts';
import { computeCoverage } from './coverage.ts';
import { normalizeFinding } from './normalize.ts';
import { CrawlerLiteEngine } from '../engines/builtin/crawlerLite.ts';
import { log } from '../logging.ts';
import { ALL_CATEGORIES } from '../core/owasp.ts';
import type { CoverageReport } from '../core/types.ts';

export interface LoopRunnerDeps {
  db: Database;
  config: Config;
  registry: EngineRegistry;
  /** D3: shared process-wide governor (optional; loop scans honor budgets when present). */
  governor?: import('../safety/governor.ts').SafetyGovernor;
}

export interface LoopScanResult {
  findings: Finding[];
  engineRecords: EngineRunRecord[];
  coverage: CoverageReport[];
  stats: { sent: number; blocked: number };
  terminatedBy: string;
  traceHash: string;
  iterations: number;
}

export async function runLoopScan(
  scanId: string,
  target: Target,
  mode: ScanMode,
  deps: LoopRunnerDeps,
  signal: AbortSignal,
): Promise<LoopScanResult> {
  const { db, config, registry } = deps;
  const workDir = join(config.dataDir, `scan-${scanId}`);
  mkdirSync(workDir, { recursive: true });

  const guard = new ScopeGuard(target.origin, {
    allowPublicTargets: config.allowPublicTargets,
    maxRedirectHops: 5,
  });
  const stats: RequestStats = { sent: 0, blocked: 0 };
  const limiter = new RateLimiter(config.rateLimitPerSecond, config.rateBurst);
  const semaphore = new Semaphore(config.maxConcurrency);
  const governorBinding = deps.governor === undefined ? undefined : {
    acquire: async (assetKey: string) => deps.governor!.acquireWait(assetKey, scanId),
    onResponse: (assetKey: string, status: number, latencyMs: number) => deps.governor!.onResponse(assetKey, status, latencyMs),
  };
  const client = new ScopedHttpClient(guard, limiter, semaphore, {
    timeoutMs: config.requestTimeoutMs, maxRedirectHops: 5,
  }, stats, signal, governorBinding);

  // Seed a bounded crawl so the corpus and discoveredEndpoints are populated
  const crawler = new CrawlerLiteEngine(config.maxCrawlPages);
  const crawl = {
    pages: [] as Array<{ url: string; status: number; headers: Record<string, string>; body: string; truncated: boolean; forms: Array<{ action: string; method: string; fields: string[]; hasPasswordField: boolean }>; links: string[] }>,
    robots: { disallow: [] as string[], fetched: false },
  };
  const crawlCtx = {
    scanId, target, mode, client, guard, stats, signal, workDir,
    crawl, log: (m: string, f?: Record<string, unknown>) => log.debug(m, f),
  };
  await crawler.run(crawlCtx as never);

  // Context-based infrastructure recon (T: host-infra): resolve the target
  // hostname and, in active mode, port-scan the resolved IPs. Runs before the
  // loop so findings join the loop result. Never breaks the scan (I11 spirit).
  const infraStart = Date.now();
  let infraFindings: Finding[] = [];
  let infraRecord: EngineRunRecord = {
    engine: 'builtin.host-infra', status: 'skipped', findingCount: 0,
    durationMs: 0, detail: 'not run',
  };
  try {
    const { HostInfraEngine } = await import('../engines/builtin/hostInfra.ts');
    const infra = new HostInfraEngine();
    const infraResult = await infra.run({
      scanId, target, mode, client, guard, stats, signal, workDir,
      log: (m: string, f?: Record<string, unknown>) => log.debug(m, f),
    } as never);
    infraFindings = infraResult.findings.map((raw) => normalizeFinding(raw, {
      target,
      engineId: 'builtin.host-infra',
      engineVersion: 'builtin',
      adapter: false,
      triages: db.getTriages(),
    }));
    infraRecord = {
      engine: 'builtin.host-infra', status: 'ran',
      findingCount: infraResult.findings.length,
      durationMs: Date.now() - infraStart,
      detail: infraResult.detail, version: 'builtin',
    };
  } catch (e) {
    infraRecord = {
      engine: 'builtin.host-infra', status: 'failed', findingCount: 0,
      durationMs: Date.now() - infraStart,
      detail: e instanceof Error ? e.message : String(e),
    };
  }

  // Probe gate: populate the model before the loop starts
  const model = new TargetModel(db.handle, target.id);
  await runProbeGate(model, {
    target, origin: target.origin, pages: crawl.pages, client, guard,
    signal, log: (m, f) => log.debug(m, f),
  }, { maxProbes: 15, maxRequests: 20 });

  const credentials = target.kind === 'webapp' ? db.getCredentials(target.id) : undefined;
  const credentialsSecondary = target.kind === 'webapp' ? db.getCredentials(target.id, 'secondary') : undefined;

  const loopCtx: LoopContext = {
    db, model, target, mode, registry, config, client, guard,
    stats, signal, workDir, crawl, credentials, credentialsSecondary,
  };

  const budget: LoopBudget = {
    maxIterations: config.loopMaxIterations,
    maxRequests: config.loopMaxRequests,
    maxMs: config.loopMaxMs,
    seed: config.loopSeed,
    subscanFanout: config.loopSubscanFanout,
  };

  const result: LoopResult = await runLoopFn(loopCtx, budget);
  result.findings.push(...infraFindings);

  // Persist trace entries (T-W4)
  for (const entry of result.trace) {
    db.writeTraceEntry(scanId, target.id, {
      iteration: entry.iteration,
      actionId: entry.actionId as string | undefined,
      outcome: entry.outcome,
      findingCount: entry.findingCount,
      requestsAfter: entry.requestsAfter,
    });
  }

  // Map loop findings to engine records
  const engineRecords: EngineRunRecord[] = [
    infraRecord,
    ...result.trace.map((t) => ({
      engine: t.actionId ?? `iteration-${t.iteration}`,
      status: 'ran' as const,
      findingCount: t.findingCount,
      durationMs: 0,
      detail: t.outcome,
    })),
  ];

  // Dedupe and persist
  const deduped = dedupeFindings(result.findings);
  db.insertFindings(scanId, deduped);

  // Coverage
  const rawCoverage = computeCoverage(engineRecords, 'loop', deduped, target.kind, mode, signal.aborted);
  const coverage = ALL_CATEGORIES.map((cat) => rawCoverage.find((c) => c.category === cat)!);

  db.audit({
    actor: 'system', action: 'loop.completed',
    details: {
      scanId, iterations: result.iterations,
      terminatedBy: result.terminatedBy,
      traceHash: result.traceHash,
      findings: deduped.length,
    },
  });

  log.info('loop scan finished', {
    scanId, iterations: result.iterations,
    terminatedBy: result.terminatedBy,
    findings: deduped.length,
    requests: stats.sent,
  });

  return {
    findings: deduped,
    engineRecords,
    coverage,
    stats: { sent: stats.sent, blocked: stats.blocked },
    terminatedBy: result.terminatedBy,
    traceHash: result.traceHash,
    iterations: result.iterations,
  };
}
