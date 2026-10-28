/**
 * Scan orchestrator: owns the scan lifecycle.
 *
 * run flow: create scan row → for each planned engine: availability check,
 * execution (with per-engine timeout + abort), normalization → dedupe →
 * triage → persist → coverage report → finalize. Any error marks the scan
 * failed; cancellation via AbortController flips it to cancelled.
 */
import { randomUUID } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Config } from '../config.ts';
import type { Database } from '../db/database.ts';
import type {
  EngineRunRecord, Finding, Scan, ScanMode, ScanStats, Target,
} from '../core/types.ts';
import { ALL_CATEGORIES } from '../core/owasp.ts';
import { getProfile, enginePlan } from '../core/profiles.ts';
import { ScopeGuard, ScopeError } from '../safety/guard.ts';
import { RateLimiter } from '../safety/rateLimiter.ts';
import { Semaphore } from '../safety/concurrency.ts';
import { ScopedHttpClient, type RequestStats } from './httpClient.ts';
import { normalizeFinding } from './normalize.ts';
import { dedupeFindings } from '../core/ids.ts';
import { computeCoverage } from './coverage.ts';
import { EngineRegistry } from '../engines/registry.ts';
import { abortError } from '../safety/rateLimiter.ts';
import { log } from '../logging.ts';

function emptyStats(): ScanStats {
  return {
    findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    findingsByStatus: { confirmed: 0, probable: 0, informational: 0, false_positive: 0, untested: 0 },
    totalFindings: 0,
    requestsSent: 0,
    requestsBlocked: 0,
  };
}

export class Orchestrator {
  private readonly db: Database;
  private readonly config: Config;
  private readonly registry: EngineRegistry;
  private readonly scanControl = new Map<string, AbortController>();
  private readonly scanSlots: Semaphore;

  constructor(db: Database, config: Config, registry: EngineRegistry) {
    this.db = db;
    this.config = config;
    this.registry = registry;
    this.scanSlots = new Semaphore(config.maxConcurrentScans);
  }

  /**
   * Create and start a scan. Throws (ApiError-shaped ScopeError / validation)
   * when the target is not approved or the profile/mode combination is invalid.
   */
  async startScan(targetId: string, profileId: string, mode: ScanMode): Promise<Scan> {
    const target = this.db.getTarget(targetId);
    if (!target) throw new ScopeError('target not found');
    if (!target.approved) {
      throw new ScopeError('target is not approved: call POST /api/targets/:id/approve first');
    }
    let profile = getProfile(profileId);
    if (!profile) throw new Error(`unknown profile: ${profileId}`);
    if (this.config.maxCrawlPagesExplicit && this.config.maxCrawlPages > profile.maxCrawlPages) {
      profile = { ...profile, maxCrawlPages: this.config.maxCrawlPages };
    }
    if (mode === 'active' && !profile.activeEngines.length && profile.passiveEngines.length) {
      // Passive-only profiles ignore active mode (no error, but record it)
    }
    if (!profile.targetKinds.includes(target.kind)) {
      throw new Error(`profile ${profile.id} does not support target kind ${target.kind}`);
    }

    const scan: Scan = {
      id: randomUUID(),
      targetId: target.id,
      targetName: target.name,
      profile: profile.id,
      mode,
      status: 'queued',
      startedAt: new Date().toISOString(),
      engines: [],
      coverage: [],
      stats: emptyStats(),
    };
    this.db.insertScan(scan);
    this.db.audit({ actor: 'operator', action: 'scan.started', details: { scanId: scan.id, targetId, profileId, mode } });

    // Fire and forget — API returns the queued scan; progress is polled.
    void this.runScan(scan.id, target, profile.id, mode).catch((e) => {
      log.error('scan runner crashed', { scanId: scan.id, error: e instanceof Error ? e.message : String(e) });
    });
    return scan;
  }

  cancelScan(scanId: string): boolean {
    const ctrl = this.scanControl.get(scanId);
    if (!ctrl) return false;
    ctrl.abort();
    return true;
  }

  private async runScan(scanId: string, target: Target, profileId: string, mode: ScanMode): Promise<void> {
    const release = await this.scanSlots.acquire();
    const ctrl = new AbortController();
    this.scanControl.set(scanId, ctrl);
    const started = Date.now();
    try {
      await this.executeScan(scanId, target, profileId, mode, ctrl.signal);
    } catch (e) {
      const aborted = ctrl.signal.aborted;
      const message = e instanceof Error ? e.message : String(e);
      this.db.updateScan(scanId, {
        status: aborted ? 'cancelled' : 'failed',
        finishedAt: new Date().toISOString(),
        error: aborted ? 'cancelled by operator' : message,
      });
      this.db.audit({ actor: 'system', action: aborted ? 'scan.cancelled' : 'scan.failed', details: { scanId, error: message } });
    } finally {
      this.scanControl.delete(scanId);
      release();
      log.info('scan finished', { scanId, durationMs: Date.now() - started });
    }
  }

  private async executeScan(
    scanId: string,
    target: Target,
    profileId: string,
    mode: ScanMode,
    signal: AbortSignal,
  ): Promise<void> {
    this.db.updateScan(scanId, { status: 'running' });

    const profile = getProfile(profileId);
    if (!profile) throw new Error(`unknown profile: ${profileId}`);

    // Scope guard construction can refuse public targets — fails the scan honestly.
    let guard: ScopeGuard;
    if (target.kind === 'webapp') {
      guard = new ScopeGuard(target.origin, {
        allowPublicTargets: this.config.allowPublicTargets,
        maxRedirectHops: 5,
      });
    } else {
      // Source targets need no HTTP scope; a placeholder guard satisfies types.
      guard = new ScopeGuard('http://127.0.0.1:1', { allowPublicTargets: true, maxRedirectHops: 1 });
    }

    const stats: RequestStats = { sent: 0, blocked: 0 };
    const limiter = new RateLimiter(this.config.rateLimitPerSecond, this.config.rateBurst);
    const semaphore = new Semaphore(this.config.maxConcurrency);
    const client = new ScopedHttpClient(guard, limiter, semaphore, {
      timeoutMs: this.config.requestTimeoutMs,
      maxRedirectHops: 5,
    }, stats, signal);

    const workDir = join(this.config.dataDir, `scan-${scanId}`);
    mkdirSync(workDir, { recursive: true });

    const engineRecords: EngineRunRecord[] = [];
    const findings: Finding[] = [];
    const triages = this.db.getTriages();
    const crawlContext = { corpus: undefined as unknown };

    const plan = enginePlan(profile, mode);
    for (const step of plan) {
      if (signal.aborted) break;
      const engine = this.registry.create(step.id, profile.maxCrawlPages);
      if (!engine) {
        engineRecords.push({ engine: step.id, status: 'skipped', findingCount: 0, durationMs: 0, detail: 'unknown engine id' });
        continue;
      }
      if (!step.willRun) {
        engineRecords.push({
          engine: step.id, status: 'skipped', findingCount: 0, durationMs: 0,
          detail: mode === 'passive' ? 'active mode not enabled for this scan' : 'not applicable',
        });
        continue;
      }
      if (engine.info.targetKinds.length > 0 && !engine.info.targetKinds.includes(target.kind)) {
        engineRecords.push({ engine: step.id, status: 'skipped', findingCount: 0, durationMs: 0, detail: `target kind ${target.kind} not supported` });
        continue;
      }

      const availability = await this.registry.availability(step.id);
      if (!availability.available) {
        engineRecords.push({
          engine: step.id, status: 'unavailable', findingCount: 0, durationMs: 0,
          detail: [availability.reason, availability.installHint].filter(Boolean).join(' — '),
          version: availability.version,
        });
        this.db.audit({ actor: 'system', action: 'engine.unavailable', details: { scanId, engine: step.id, reason: availability.reason } });
        continue;
      }

      const credentials = target.kind === 'webapp' ? this.db.getCredentials(target.id) : undefined;
      const credentialsSecondary = target.kind === 'webapp' ? this.db.getCredentials(target.id, 'secondary') : undefined;
      const ctx = {
        scanId,
        target,
        mode,
        credentials,
        credentialsSecondary,
        client,
        guard,
        stats,
        signal,
        workDir,
        crawl: crawlContext.corpus as never,
        log: (msg: string, fields?: Record<string, unknown>) => log.info(`[${step.id}] ${msg}`, { scanId, ...fields }),
      };

      const engineStart = Date.now();
      try {
        const result = await withTimeout(engine.run(ctx), this.config.engineTimeoutMs, step.id, signal);
        crawlContext.corpus = (ctx as { crawl?: unknown }).crawl ?? crawlContext.corpus;
        if (result.notExecutedReason !== undefined) {
          engineRecords.push({
            engine: step.id, status: 'skipped', findingCount: 0,
            durationMs: Date.now() - engineStart, detail: result.notExecutedReason, version: result.version ?? availability.version,
          });
          continue;
        }
        engineRecords.push({
          engine: step.id, status: 'ran', findingCount: result.findings.length,
          durationMs: Date.now() - engineStart, detail: result.detail, version: result.version ?? availability.version,
        });
        for (const raw of result.findings) {
          findings.push(normalizeFinding(raw, {
            target,
            engineId: step.id,
            engineVersion: result.version ?? availability.version,
            adapter: step.id.startsWith('adapter.'),
            triages,
          }));
        }
      } catch (e) {
        const aborted = signal.aborted;
        engineRecords.push({
          engine: step.id, status: aborted ? 'cancelled' : 'failed', findingCount: 0,
          durationMs: Date.now() - engineStart,
          detail: e instanceof Error ? e.message : String(e),
          version: availability.version,
        });
        if (aborted) break;
      }
    }

    // Dedupe across engines (merges provenance), then finalize.
    const deduped = dedupeFindings(findings);
    const finalStats = emptyStats();
    finalStats.requestsSent = stats.sent;
    finalStats.requestsBlocked = stats.blocked;
    for (const f of deduped) {
      finalStats.findingsBySeverity[f.severity]++;
      finalStats.findingsByStatus[f.status]++;
    }
    finalStats.totalFindings = deduped.length;

    const ranRecords = engineRecords;
    const coverage = computeCoverage(ranRecords, profileId, deduped, target.kind, mode, signal.aborted);
    const completedCoverage = ALL_CATEGORIES.map((cat) => coverage.find((c) => c.category === cat)!);

    this.db.insertFindings(scanId, deduped);
    this.db.updateScan(scanId, {
      status: 'completed',
      finishedAt: new Date().toISOString(),
      engines: engineRecords,
      coverage: completedCoverage,
      stats: finalStats,
    });
    this.db.audit({ actor: 'system', action: 'scan.completed', details: { scanId, findings: finalStats.totalFindings } });
  }
}

async function withTimeout<T>(p: Promise<T>, timeoutMs: number, engine: string, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`engine ${engine} exceeded ${timeoutMs}ms`)), timeoutMs);
    const onAbort = () => reject(abortError());
    signal.addEventListener('abort', onAbort, { once: true });
    p.then(
      (v) => { clearTimeout(timer); signal.removeEventListener('abort', onAbort); resolve(v); },
      (e) => { clearTimeout(timer); signal.removeEventListener('abort', onAbort); reject(e); },
    );
  });
}
