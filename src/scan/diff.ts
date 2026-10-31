/**
 * Rescan diffing — stable finding IDs make this a fingerprint set comparison.
 * Answers the operator's core continuous-assessment question: what is new,
 * what got fixed, what persists.
 */
import type { Finding } from '../core/types.ts';

export interface ScanDiff {
  fromScanId: string;
  toScanId: string;
  /** Findings present in `to` but not in `from` (new since last scan). */
  added: Finding[];
  /** Findings present in `from` but not in `to` (fixed / no longer observed). */
  removed: Finding[];
  /** Findings present in both (persistent — the remediation backlog). */
  unchanged: Finding[];
  /** PLT-06 (edgetask.md): findings reclassified/downgraded by suppression rules. */
  suppressed: Finding[];
}

export function diffScanFindings(from: Finding[], to: Finding[], fromScanId: string, toScanId: string): ScanDiff {
  const fromFps = new Set(from.map((f) => f.fingerprint));
  const toFps = new Set(to.map((f) => f.fingerprint));
  return {
    fromScanId,
    toScanId,
    added: to.filter((f) => !fromFps.has(f.fingerprint)),
    removed: from.filter((f) => !toFps.has(f.fingerprint)),
    unchanged: to.filter((f) => fromFps.has(f.fingerprint)),
    suppressed: to.filter((f) => f.suppressedBy !== undefined),
  };
}
