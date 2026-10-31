/**
 * Context-aware risk scoring (newtask.md F1–F3, section 3.4).
 *
 *   Risk = Base × Reachability × Exposure × Criticality × Blast   (clamped 0–100)
 *
 * Base      = max(CVSS/10, EPSS×1.4, VPR/10), floored at 0.05
 * Reachability = 0.3 isolated · 0.7 same-VPC · 1.0 internet-reachable
 * Exposure  = 1.0 edge · 0.55 internal · 0.25 air-gapped
 * Criticality = asset tier 0.5–1.5
 * Blast     = graph fan-out from this node, capped 1.5
 *
 * Every factor is stored and shown — explainability is a requirement (F4).
 * Identical CVEs score materially differently internal vs edge (F2).
 */

export interface RiskBaseInput { cvss?: number | undefined; epss?: number | undefined; vpr?: number | undefined; }

export type Reachability = 'isolated' | 'same-vpc' | 'internet';
export type Exposure = 'edge' | 'internal' | 'air-gapped';

const REACHABILITY: Record<Reachability, number> = { isolated: 0.3, 'same-vpc': 0.7, internet: 1.0 };
const EXPOSURE: Record<Exposure, number> = { edge: 1.0, internal: 0.55, 'air-gapped': 0.25 };

export function baseScore(b: RiskBaseInput): number {
  const candidates: number[] = [];
  if (b.cvss !== undefined) candidates.push(b.cvss / 10);
  if (b.epss !== undefined) candidates.push(b.epss * 1.4);
  if (b.vpr !== undefined) candidates.push(b.vpr / 10);
  const max = candidates.length > 0 ? Math.max(...candidates) : 0;
  return Math.max(0.05, Math.min(1, max));
}

export function clampTier(tier: number): number {
  return Math.max(0.5, Math.min(1.5, tier));
}

export function blastFactor(fanout: number): number {
  // Log fit to the spec's worked example: fan-out 1 → 0.6, fan-out 4 → ~1.2,
  // capped 1.5. No fan-out means a small blast contribution.
  return Math.min(1.5, 0.155 + 0.445 * Math.log2(1 + Math.max(0, fanout)));
}

export interface RiskInput {
  base: RiskBaseInput;
  reachability: Reachability;
  exposure: Exposure;
  /** Asset tier: 0.5 (low) – 1.5 (crown jewel). */
  criticalityTier: number;
  /** Graph fan-out (open edges) of the asset node. */
  blastFanout: number;
}

export interface RiskResult {
  score: number;
  band: 'critical' | 'high' | 'medium' | 'low';
  factors: { base: number; reachability: number; exposure: number; criticality: number; blast: number };
}

export function computeRisk(input: RiskInput): RiskResult {
  const factors = {
    base: baseScore(input.base),
    reachability: REACHABILITY[input.reachability],
    exposure: EXPOSURE[input.exposure],
    criticality: clampTier(input.criticalityTier),
    blast: blastFactor(input.blastFanout),
  };
  const raw = factors.base * factors.reachability * factors.exposure * factors.criticality * factors.blast;
  const score = Math.round(Math.max(0, Math.min(100, raw * 100)));
  const band = score >= 80 ? 'critical' : score >= 50 ? 'high' : score >= 20 ? 'medium' : 'low';
  return { score, band, factors };
}

// ---------- F3: noise rules ----------

export type Signal = 'advisory' | 'banner-version' | 'active-confirmation';

/**
 * Require 2 of 3 signals before "confirmed": advisory match, banner version,
 * active confirmation. Fewer signals stay "probable".
 */
export function confirmationGate(signals: Signal[]): 'confirmed' | 'probable' {
  const distinct = new Set(signals).size;
  return distinct >= 2 ? 'confirmed' : 'probable';
}

/** EPSS < 0.01 and unreachable ⇒ backlog (deprioritized, not deleted). */
export function isBacklog(epss: number | undefined, reachability: Reachability): boolean {
  return (epss === undefined || epss < 0.01) && reachability !== 'internet';
}

export interface CveObservation { assetUid: string; cve: string; score: number; source: string; }

/** Dedupe by (asset_uid, cve) keeping the max score (F3). */
export function dedupeCveObservations(observations: CveObservation[]): CveObservation[] {
  const byKey = new Map<string, CveObservation>();
  for (const o of observations) {
    const key = `${o.assetUid}|${o.cve}`;
    const existing = byKey.get(key);
    if (existing === undefined || o.score > existing.score) byKey.set(key, o);
  }
  return [...byKey.values()].sort((a, b) => b.score - a.score);
}

/** The worked example from the spec — identical CVE, 24× apart (F2). */
export function workedExample(): { edge: RiskResult; internal: RiskResult; ratio: number } {
  const edge = computeRisk({
    base: { cvss: 9.8, epss: 0.6 },
    reachability: 'internet', exposure: 'edge', criticalityTier: 1.5, blastFanout: 4,
  });
  const internal = computeRisk({
    base: { cvss: 9.8, epss: 0.6 },
    // the spec's CI box: no route (isolated), not internet-facing (0.25), no fan-out
    reachability: 'isolated', exposure: 'air-gapped', criticalityTier: 1.0, blastFanout: 1,
  });
  return { edge, internal, ratio: Math.round(edge.score / Math.max(1, internal.score)) };
}
