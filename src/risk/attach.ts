/**
 * Risk attachment for findings (newtask.md F1/F4) — explainable, per-finding.
 *
 * Base comes from the finding severity (we do not carry per-CVE CVSS/EPSS in
 * the offline pipeline — honest limitation); exposure is derived from whether
 * the asset is public-facing; blast comes from the graph fan-out when a graph
 * store is provided. Every factor is stored and rendered (F4).
 */
import type { Finding } from '../core/types.ts';
import { isPublicTarget } from '../scoring/scoring.ts';
import { blastFactor, confirmationGate, type Signal } from './risk.ts';
import { enrichBase } from './advisories.ts';

export interface FindingRisk {
  score: number;
  band: 'critical' | 'high' | 'medium' | 'low';
  factors: { base: number; reachability: number; exposure: number; criticality: number; blast: number };
  /** L1: where the base came from — real EPSS/CVSS snapshot or severity fallback. */
  baseSource: 'epss' | 'cvss' | 'severity';
  /** F3 noise-rule annotation: which confirmation signals this finding carries. */
  signals: Signal[];
  confirmationGate: 'confirmed' | 'probable';
  backlog: boolean;
}

const SEVERITY_BASE: Record<string, number> = { critical: 1.0, high: 0.9, medium: 0.6, low: 0.3, info: 0.05 };

export function riskForFinding(f: Finding, opts: { fanout?: number; tier?: number; internetReachable?: boolean } = {}): FindingRisk {
  const severityBase = SEVERITY_BASE[f.severity] ?? 0.05;
  // L1 (hardtask.md): CVE-bearing findings use the real offline advisory base
  // (max(CVSS/10, EPSS*1.4) floored at 0.05); everything else stays
  // severity-derived with an explicit base_source.
  const enrich = enrichBase(f.cve, severityBase, (b) => {
    const candidates: number[] = [];
    if (b.cvss !== undefined) candidates.push(b.cvss / 10);
    if (b.epss !== undefined) candidates.push(b.epss * 1.4);
    const max = candidates.length > 0 ? Math.max(...candidates) : 0;
    return Math.max(0.05, Math.min(1, max));
  });
  const base = enrich.base;
  const publicTarget = opts.internetReachable ?? isPublicTarget(f.asset);
  const factors = {
    base,
    reachability: publicTarget ? 1.0 : 0.3,
    exposure: publicTarget ? 1.0 : 0.55,
    criticality: Math.max(0.5, Math.min(1.5, opts.tier ?? 1.0)),
    // Neutral 1.0 when the graph fan-out is unknown (report-only path) —
    // the log-fit blast factor applies only when a graph measurement exists.
    blast: opts.fanout !== undefined ? blastFactor(opts.fanout) : 1.0,
  };
  const score = Math.round(Math.max(0, Math.min(100, factors.base * factors.reachability * factors.exposure * factors.criticality * factors.blast * 100)));
  const signals: Signal[] = [];
  if (f.cve !== undefined || f.cwe !== undefined) signals.push('advisory');
  if (f.provenance.some((p) => (p.rawId ?? '').includes('version') || (p.rawId ?? '').includes('os-hint'))) signals.push('banner-version');
  if (f.status === 'confirmed') signals.push('active-confirmation');
  const rawIds = f.provenance.map((p) => p.rawId ?? '').join(',');
  if (/service-cve|js-library-known-vulnerability/.test(rawIds)) signals.push('banner-version');
  const gate = confirmationGate(signals);
  return {
    score,
    band: score >= 80 ? 'critical' : score >= 50 ? 'high' : score >= 20 ? 'medium' : 'low',
    factors,
    baseSource: enrich.baseSource,
    signals,
    confirmationGate: gate,
    // F3 backlog rule without EPSS data: unconfirmed findings on non-internet assets
    backlog: !publicTarget && f.status !== 'confirmed',
  };
}

/** Attach risk to every finding (pure — returns new objects). */
export function attachRisk(findings: Finding[], opts: { fanoutOf?: (f: Finding) => number } = {}): Array<Finding & { risk: FindingRisk }> {
  return findings.map((f) => {
    const fanout = opts.fanoutOf?.(f);
    return { ...f, risk: riskForFinding(f, fanout !== undefined ? { fanout } : {}) };
  });
}
