/**
 * Fix-triggered retest (newtasks.md E3).
 *
 * I22: a retest touches ONLY the finding's own locator — the same verifier
 * (verifyByType) re-observes the exact evidence URL. E6.3: escalated findings
 * are excluded from auto-close. E3.4: debounce — a per-target rolling window
 * caps retest executions; bursts coalesce into refusals.
 *
 * Outcome mapping (E3.3):
 *   verifier rejects the original observation → fixed (retest evidence)
 *   verifier re-confirms                      → regressed (reopened, same severity)
 *   verifier inconclusive / unknown type      → inconclusive (stays open)
 */
import type { Config } from '../config.ts';
import type { Database } from '../db/database.ts';
import type { Finding } from '../core/types.ts';
import { verifyByType } from '../verify/verify.ts';
import { ScopeGuard } from '../safety/guard.ts';
import { RateLimiter } from '../safety/rateLimiter.ts';
import { Semaphore } from '../safety/concurrency.ts';
import { ScopedHttpClient } from '../scan/httpClient.ts';

export interface RetestOutcome {
  findingId: string;
  result: 'fixed' | 'regressed' | 'inconclusive' | 'escalated-skip' | 'debounced';
  note: string;
}

const WINDOW_MS = 3_600_000;

export class RetestService {
  private readonly window: Map<string, number[]> = new Map();
  private readonly db: Database;
  private readonly config: Config;
  private readonly capPerHour: number;

  constructor(db: Database, config: Config, capPerHour = 5) {
    this.db = db;
    this.config = config;
    this.capPerHour = capPerHour;
  }

  private debounceOk(targetId: string): boolean {
    const now = Date.now();
    const stamps = (this.window.get(targetId) ?? []).filter((t) => now - t < WINDOW_MS);
    if (stamps.length >= this.capPerHour) {
      this.window.set(targetId, stamps);
      return false;
    }
    stamps.push(now);
    this.window.set(targetId, stamps);
    return true;
  }

  /** E3.2: retest matching findings only (I22 locator filter). */
  async retest(targetId: string, locatorFilter?: string, signal?: AbortSignal): Promise<RetestOutcome[]> {
    if (!this.debounceOk(targetId)) {
      return [{ findingId: '*', result: 'debounced', note: `retest cap (${this.capPerHour}/hour) reached for this target — coalesce triggers` }];
    }
    const target = this.db.getTarget(targetId);
    if (target === undefined) throw new Error('target not found');

    const guard = new ScopeGuard(target.origin, {
      allowPublicTargets: this.config.allowPublicTargets,
      maxRedirectHops: 5,
    });
    const stats = { sent: 0, blocked: 0 };
    const client = new ScopedHttpClient(
      guard, new RateLimiter(this.config.rateLimitPerSecond, this.config.rateBurst),
      new Semaphore(this.config.maxConcurrency),
      { timeoutMs: this.config.requestTimeoutMs, maxRedirectHops: 5 }, stats, signal,
    );

    const outcomes: RetestOutcome[] = [];
    const latest = this.db.listScans(50).find((s) => s.targetId === targetId && s.status === 'completed');
    if (latest === undefined) throw new Error('no completed scan to retest against');
    const findings = this.db.getFindings(latest.id).filter((f) =>
      locatorFilter === undefined || (f.locator ?? '').includes(locatorFilter));

    for (const f of findings) {
      if (signal?.aborted) break;
      // E6.3: escalated findings are excluded from auto-close on retest.
      if (f.escalate !== undefined) {
        outcomes.push({ findingId: f.id, result: 'escalated-skip', note: `escalated (${f.escalate.reason}) — human judgement required, never auto-closed` });
        continue;
      }
      // I22: the verifier re-observes the finding's own locator only.
      const report = await verifyByType(f, client).catch(() => undefined);
      if (report === undefined) {
        outcomes.push({ findingId: f.id, result: 'inconclusive', note: 'verifier failed' });
        continue;
      }
      if (report.verdict === 'rejected') {
        const retest = { result: 'fixed' as const, at: new Date().toISOString(), note: 'retest: the same verifier no longer observes the issue at this locator', verifier: report.rawId };
        this.applyRetest(latest.id, f, 'fixed', retest);
        outcomes.push({ findingId: f.id, result: 'fixed', note: retest.note });
      } else if (report.verdict === 'confirmed') {
        const retest = { result: 'regressed' as const, at: new Date().toISOString(), note: 'retest: still present — reopened at previous severity', verifier: report.rawId };
        this.applyRetest(latest.id, f, 'regressed', retest);
        outcomes.push({ findingId: f.id, result: 'regressed', note: retest.note });
      } else {
        const retest = { result: 'inconclusive' as const, at: new Date().toISOString(), note: 'retest: verifier inconclusive — stays open', verifier: report.rawId };
        this.applyRetest(latest.id, f, 'inconclusive', retest);
        outcomes.push({ findingId: f.id, result: 'inconclusive', note: retest.note });
      }
    }
    return outcomes;
  }

  private applyRetest(scanId: string, f: Finding, status: 'fixed' | 'regressed' | 'inconclusive', retest: { result: 'fixed' | 'regressed' | 'inconclusive'; at: string; note: string; verifier: string }): void {
    // E3.3: fixed → fixed status; regressed → reopened at previous severity
    // (regressed keeps the pre-retest status — severity/status never widen).
    const newStatus = status === 'fixed' ? 'fixed' as const : f.status;
    this.db.updateFindingStatus(scanId, f.id, newStatus);
    this.db.setFindingEnrichment(scanId, f.id, { retest });
  }
}
