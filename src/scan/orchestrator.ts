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
import { verifyByType, applyVerification } from '../verify/verify.ts';
import { runLoopScan } from './loopRunner.ts';
import { GraphStore } from '../graph/graph.ts';
import { EventStore } from '../graph/merger.ts';
import { syncFindingsToGraph } from '../graph/sync.ts';
import { SafetyGovernor } from '../safety/governor.ts';
import { ScopeGate } from '../safety/scopeGate.ts';
import type { Bus } from '../bus/bus.ts';
import { triggerForPort } from '../orchestration/assessAsset.ts';
import type { GovernorBinding } from './httpClient.ts';
import { EngineRegistry } from '../engines/registry.ts';
import { abortError } from '../safety/rateLimiter.ts';
import { log } from '../logging.ts';

function emptyStats(): ScanStats {
  return {
    findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    findingsByStatus: { confirmed: 0, probable: 0, informational: 0, false_positive: 0, rejected_by_verification: 0, untested: 0 },
    totalFindings: 0,
    requestsSent: 0,
    requestsBlocked: 0,
  };
}

export interface OrchestrationDeps {
  /** D1: event bus for discovery.asset / scan.request / approval.gate traffic. */
  bus?: Bus;
  /** D4: scope approvals — required for trigger emission to mean anything. */
  scopeGate?: ScopeGate;
  /** D3: shared process-wide governor (created per-orchestrator when omitted). */
  governor?: SafetyGovernor;
}

export class Orchestrator {
  private readonly db: Database;
  private readonly config: Config;
  private readonly registry: EngineRegistry;
  private readonly scanControl = new Map<string, AbortController>();
  private readonly scanSlots: Semaphore;
  private readonly bus: Bus | undefined;
  private readonly scopeGate: ScopeGate | undefined;
  private readonly governor: SafetyGovernor;

  constructor(db: Database, config: Config, registry: EngineRegistry, deps: OrchestrationDeps = {}) {
    this.db = db;
    this.config = config;
    this.registry = registry;
    this.scanSlots = new Semaphore(config.maxConcurrentScans);
    this.bus = deps.bus;
    this.scopeGate = deps.scopeGate;
    this.governor = deps.governor ?? new SafetyGovernor(config.scanProfile);
  }

  /** Per-scan governor binding (scanId-bound ceilings, assetKey per host). */
  private governorBinding(scanId: string): GovernorBinding {
    return {
      acquire: async (assetKey) => this.governor.acquireWait(assetKey, scanId),
      onResponse: (assetKey, status, latencyMs) => this.governor.onResponse(assetKey, status, latencyMs),
    };
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
    // D4: a started scan on an approved target is the authoritative scope approval.
    if (this.scopeGate !== undefined && target.kind === 'webapp' && target.origin !== '') {
      this.scopeGate.register('origin', target.origin, true);
      this.scopeGate.approve('origin', target.origin, 'scan-started');
    }
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

    // T-W1: branch to the autonomous loop when enabled and applicable;
    // fall back to the linear path on error (I11).
    if (this.config.loopEnabled && target.kind === 'webapp') {
      try {
        const result = await runLoopScan(scanId, target, mode, {
          db: this.db, config: this.config, registry: this.registry, governor: this.governor,
        }, signal);
        this.db.updateScan(scanId, {
          status: 'completed',
          finishedAt: new Date().toISOString(),
          engines: result.engineRecords,
          coverage: result.coverage,
          stats: {
            findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            findingsByStatus: { confirmed: 0, probable: 0, informational: 0, false_positive: 0, rejected_by_verification: 0, untested: 0 },
            totalFindings: result.findings.length,
            requestsSent: result.stats.sent,
            requestsBlocked: result.stats.blocked,
          },
        });
        this.db.audit({ actor: 'system', action: 'scan.completed', details: { scanId, mode: 'loop', findings: result.findings.length, iterations: result.iterations, terminatedBy: result.terminatedBy } });
        return;
      } catch (e) {
        const reason = e instanceof Error ? e.message : String(e);
        log.warn('loop fell back to linear', { scanId, reason });
        this.db.audit({ actor: 'system', action: 'loop.fell_back', details: { scanId, reason } });
        // I11: fall through to linear path below
      }
    }

    // --- linear plan (v0.1 path, also the fallback) ---
    await this.executeLinearScan(scanId, target, profileId, mode, signal);
  }

  private async executeLinearScan(
    scanId: string,
    target: Target,
    profileId: string,
    mode: ScanMode,
    signal: AbortSignal,
  ): Promise<void> {

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
    }, stats, signal, this.governorBinding(scanId));

    const workDir = join(this.config.dataDir, `scan-${scanId}`);
    mkdirSync(workDir, { recursive: true });

    const engineRecords: EngineRunRecord[] = [];
    const findings: Finding[] = [];
    const triages = this.db.getTriages();
    const crawlContext = { corpus: undefined as unknown };

    const plan = enginePlan(profile, mode);
    for (const step of plan) {
      if (signal.aborted) break;
      // A2: variant-hunter runs in a dedicated post-verification stage below.
      if (step.id === 'builtin.variant-hunter') continue;
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

    // A2: verification + variant-hunter stage. Seeds must exist before variant
    // hunting runs, and probes that consumed no input must read "skipped with
    // reason", never "ran 0ms".
    const variantStep = plan.find((s) => s.id === 'builtin.variant-hunter');
    if (variantStep !== undefined) {
      const variantStart = Date.now();
      const record = (status: EngineRunRecord['status'], detail: string, findingCount = 0): void => {
        engineRecords.push({ engine: 'builtin.variant-hunter', status, findingCount, durationMs: Date.now() - variantStart, detail });
      };
      if (!variantStep.willRun) {
        record('skipped', 'active mode not enabled for this scan');
      } else if (signal.aborted) {
        record('skipped', 'scan cancelled before variant stage');
      } else {
        const seeds = findings
          .filter((f) => f.evidence.some((e) => e.kind === 'http') && (f.status === 'probable' || f.status === 'confirmed'))
          .slice(0, 8);
        if (seeds.length === 0) {
          record('skipped', 'no HTTP-evidence findings to seed variant hunting — not applicable to this scan');
        } else {
          // Verify seeds first (bounded) — promotion/refusal is audited.
          // I1 (hardtask.md): auto-rejections are counted and surfaced; the
          // recall floor (I17) asserts in e2e that planted TPs are never here.
          let rejections = 0;
          for (const seed of seeds) {
            if (signal.aborted) break;
            try {
              const report = await verifyByType(seed, client);
              applyVerification(findings, report, (action, details) =>
                this.db.audit({ actor: 'system', action, details: { scanId, ...details } }));
              if (report.verdict === 'rejected') rejections++;
            } catch { /* verification is best-effort; seeds remain probable */ }
          }
          const engine = this.registry.create('builtin.variant-hunter', profile.maxCrawlPages);
          if (engine === undefined) {
            record('skipped', 'unknown engine id');
          } else {
            const availability = await this.registry.availability('builtin.variant-hunter');
            if (!availability.available) {
              record('unavailable', availability.reason ?? 'unavailable');
            } else {
              const vCtx = {
                scanId, target, mode,
                credentials: target.kind === 'webapp' ? this.db.getCredentials(target.id) : undefined,
                credentialsSecondary: target.kind === 'webapp' ? this.db.getCredentials(target.id, 'secondary') : undefined,
                client, guard, stats, signal, workDir,
                crawl: crawlContext.corpus as never,
                seedFindings: seeds,
                log: (msg: string, fields?: Record<string, unknown>) => log.info(`[builtin.variant-hunter] ${msg}`, { scanId, ...fields }),
              };
              try {
                const result = await withTimeout(engine.run(vCtx), this.config.engineTimeoutMs, 'builtin.variant-hunter', signal);
                record('ran', `${result.detail ?? ''}; ${rejections} seed(s) auto-rejected by verification (rejected_by_verification, not human false_positive)`, result.findings.length);
                for (const raw of result.findings) {
                  findings.push(normalizeFinding(raw, {
                    target, engineId: 'builtin.variant-hunter', engineVersion: result.version ?? 'builtin',
                    adapter: false, triages,
                  }));
                }
              } catch (e) {
                record(signal.aborted ? 'cancelled' : 'failed', e instanceof Error ? e.message : String(e));
              }
            }
          }
        }
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
    // C1–C3: feed the unified asset graph (never breaks the scan).
    try {
      const graph = new GraphStore(this.db.handle);
      const events = new EventStore(this.db.handle);
      const stats = syncFindingsToGraph(graph, events, deduped, scanId);
      this.db.audit({ actor: 'system', action: 'graph.synced', details: { scanId, ...stats } });
      // D1/D5: publish discovery events and evaluate trigger rules.
      if (this.bus !== undefined) {
        for (const f of deduped) {
          this.bus.publish('discovery.asset', f.fingerprint, {
            findingId: f.id, category: f.category, severity: f.severity, asset: f.asset, locator: f.locator,
          });
        }
      }
      if (this.bus !== undefined && this.scopeGate !== undefined) {
        for (const f of deduped) {
          if (!f.provenance.some((p) => p.rawId === 'port-open')) continue;
          const m = /^([\d.]+):(\d+)$/.exec(f.locator);
          if (m === null) continue;
          triggerForPort({
            ip: m[1]!, port: Number(m[2]),
            severity: f.severity === 'high' ? 'high' : f.severity === 'medium' ? 'medium' : 'info',
            origin: target.origin, scope: this.scopeGate, bus: this.bus, profile: this.config.scanProfile,
          });
        }
      }
    } catch (e) {
      log.warn('graph sync failed (scan unaffected)', { scanId, error: e instanceof Error ? e.message : String(e) });
    }
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
