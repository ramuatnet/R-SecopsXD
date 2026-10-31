/**
 * Scan-request dispatcher (newtask.md D5 wiring) — closes the
 * discovery→action loop (section 0.3).
 *
 * Subscribes to scan.request envelopes on the bus and dispatches real scans
 * through the orchestrator. Safety rails:
 *  - only DAST requests for APPROVED targets already registered in the DB
 *    (anything else stays an approval.gate event — I13);
 *  - never starts a scan while one is queued/running for the same target;
 *  - rate-limits auto-dispatch per target (minIntervalMs, default 1h) so the
 *    loop cannot run away.
 */
import type { Database } from '../db/database.ts';
import type { Orchestrator } from '../scan/orchestrator.ts';
import type { Bus } from '../bus/bus.ts';
import type { ScanRequest } from './assessAsset.ts';
import { log } from '../logging.ts';

export interface DispatcherDeps {
  bus: Bus;
  orchestrator: Orchestrator;
  db: Database;
  /** Minimum interval between auto-dispatched scans per target (default 1h). */
  minIntervalMs?: number;
}

export class ScanRequestDispatcher {
  private readonly lastAutoScan = new Map<string, number>();
  private stopFn: (() => void) | undefined;
  private readonly deps: DispatcherDeps;

  constructor(deps: DispatcherDeps) {
    this.deps = deps;
  }

  start(): void {
    this.stopFn = this.deps.bus.subscribe<ScanRequest>('scan.request', (env) => {
      void this.handle(env.payload).catch((e) => {
        log.warn('scan-request dispatch failed', { error: e instanceof Error ? e.message : String(e), key: env.key });
      });
    });
    log.info('scan-request dispatcher started');
  }

  stop(): void {
    this.stopFn?.();
    this.stopFn = undefined;
  }

  async handle(req: ScanRequest): Promise<void> {
    if (req.kind !== 'dast' || req.origin === undefined) return;
    const target = this.deps.db.listTargets().find((t) => t.origin === req.origin && t.approved);
    if (target === undefined) {
      log.info('dispatch skipped: no approved target for origin', { origin: req.origin });
      return;
    }
    const active = this.deps.db.listScans(50).find((s) => s.targetId === target.id && (s.status === 'queued' || s.status === 'running'));
    if (active !== undefined) {
      log.info('dispatch skipped: scan already active for target', { targetId: target.id, scanId: active.id });
      return;
    }
    const minInterval = this.deps.minIntervalMs ?? 3_600_000;
    const last = this.lastAutoScan.get(target.id) ?? 0;
    if (Date.now() - last < minInterval) {
      log.info('dispatch skipped: within auto-dispatch window', { targetId: target.id });
      return;
    }
    this.lastAutoScan.set(target.id, Date.now());
    log.info('auto-dispatching scan from scan.request', { targetId: target.id, reason: req.reason, profile: req.profile });
    const scan = await this.deps.orchestrator.startScan(target.id, req.profile === 'gentle' ? 'standard-passive' : 'standard-active', 'active');
    this.deps.bus.publish('scan.result', scan.id, { scanId: scan.id, targetId: target.id, status: scan.status, auto: true });
  }
}
