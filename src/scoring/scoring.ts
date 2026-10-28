/**
 * Dynamic scoring (v2 Phase 7, T7.1–T7.3).
 *
 * T7.1 score = base severity × exploitability × exposure × context. Raw
 * fields are kept; every score lists its factors (T7.3 explainability).
 * Severity and confidence remain separate (I6).
 */
import type { Finding } from '../core/types.ts';

export interface ScoreFactors {
  baseSeverity: number;       // critical 4, high 3, medium 2, low 1, info 0.5
  exploitability: number;     // verified 1.2, probable 1.0, else 0.8
  exposure: number;           // public 1.2, private/loopback 0.8
  context: number;            // auth-relevant surface +0.1, known tech stack +0.1 (capped 1.2)
}

export interface ScoredFinding {
  finding: Finding;
  score: number;
  factors: ScoreFactors;
  rationale: string;
}

function severityBase(sev: string): number {
  switch (sev) {
    case 'critical': return 4;
    case 'high': return 3;
    case 'medium': return 2;
    case 'low': return 1;
    default: return 0.5;
  }
}

export function isPublicTarget(asset: string): boolean {
  try {
    const h = new URL(asset).hostname;
    return !(h === '127.0.0.1' || h === 'localhost' || h.endsWith('.localhost') ||
      /^10\./.test(h) || /^192\.168\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h));
  } catch {
    return true; // unknown asset shape: treat as exposed
  }
}

/** T7.1 scoring with explainable factors. */
export function scoreFinding(
  finding: Finding,
  opts: { verified?: boolean; publicTarget?: boolean; modelCapabilities?: string[] } = {},
): ScoredFinding {
  const baseSeverity = severityBase(finding.severity);
  const exploitability = opts.verified === true || finding.status === 'confirmed' ? 1.2
    : finding.status === 'probable' ? 1.0
    : finding.status === 'informational' ? 0.8 : 0.6;
  const publicTarget = opts.publicTarget ?? isPublicTarget(finding.asset);
  const exposure = publicTarget ? 1.2 : 0.8;
  const caps = opts.modelCapabilities ?? [];
  const authRelated = /auth|session|cookie|token|redirect|access/i.test(finding.title + finding.category);
  let context = 1;
  if (authRelated && caps.some((c) => /auth|session/.test(c))) context = 1.2;
  else if (authRelated) context = 1.1;

  const score = Math.round(baseSeverity * exploitability * exposure * context * 100) / 100;
  const factors: ScoreFactors = { baseSeverity, exploitability, exposure, context };
  const rationale = [
    `base(${finding.severity})=${baseSeverity}`,
    `exploitability(${finding.status})=${exploitability}`,
    `exposure(${publicTarget ? 'public' : 'private'})=${exposure}`,
    `context=${context}`,
  ].join(' × ');
  return { finding, score, factors, rationale };
}

// ---------- T7.2 risk trend over time ----------

export interface TrendPoint { scanId: string; startedAt: string; bySeverity: Record<string, number>; avgScore?: number }

export function riskTrend(history: Array<{ scanId: string; startedAt: string; findings: Finding[] }>): TrendPoint[] {
  return [...history]
    .sort((a, b) => a.startedAt.localeCompare(b.startedAt))
    .map((h) => {
      const bySeverity: Record<string, number> = {};
      let sum = 0;
      for (const f of h.findings) {
        bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
        sum += scoreFinding(f).score;
      }
      return {
        scanId: h.scanId, startedAt: h.startedAt, bySeverity,
        avgScore: h.findings.length > 0 ? Math.round((sum / h.findings.length) * 100) / 100 : 0,
      };
    });
}
