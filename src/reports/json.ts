/**
 * Canonical JSON report — the machine-readable source of truth.
 */
import type { CoverageReport, Evidence, Finding, Scan } from '../core/types.ts';
import { redactHeaders, redactText } from '../core/redact.ts';
import { riskForFinding } from '../risk/attach.ts';

export interface JsonReport {
  schema: 'owasp-assessment-platform/report';
  version: 1;
  generatedAt: string;
  classification: 'confidential';
  scan: Scan;
  summary: {
    totalFindings: number;
    bySeverity: Record<string, number>;
    byStatus: Record<string, number>;
    enginesRun: string[];
    enginesUnavailable: string[];
  };
  findings: Array<Finding & { risk: ReturnType<typeof riskForFinding> }>;
  /** F4: explainable risk bands over the attached per-finding risk model. */
  riskSummary: Record<string, number>;
  coverage: CoverageReport[];
  disclaimer: string;
}

const DISCLAIMER =
  'Automated findings are evidence-based observations, not proof of exploitability. ' +
  'Severity expresses potential impact; confidence expresses engine certainty; they are independent. ' +
  'Coverage verdicts state what the executed engines can conclude — "manual-only" categories require human assessment. ' +
  'Absence of findings is not proof of absence of vulnerabilities.';

/**
 * Defense-in-depth: evidence is redacted at capture time by the HTTP client,
 * but adapters capture external output — re-redact everything at render time
 * so no report ever carries a secret even if an upstream capture missed one.
 */
export function redactFindingEvidence(f: Finding): Finding {
  const evidence = f.evidence.map((ev): Evidence => {
    switch (ev.kind) {
      case 'http': {
        const redacted: Evidence = {
          ...ev,
          request: { ...ev.request, headers: redactHeaders(ev.request.headers) },
          observation: redactText(ev.observation),
        };
        if (redacted.kind === 'http' && redacted.response) {
          const r = redacted.response;
          redacted.response = {
            status: r.status,
            headers: redactHeaders(r.headers),
          };
          if (r.bodyExcerpt !== undefined) redacted.response.bodyExcerpt = redactText(r.bodyExcerpt);
        }
        return redacted;
      }
      case 'file':
        return { ...ev, excerpt: ev.excerpt !== undefined ? redactText(ev.excerpt) : undefined, observation: redactText(ev.observation) };
      case 'process':
        return { ...ev, stdoutExcerpt: ev.stdoutExcerpt !== undefined ? redactText(ev.stdoutExcerpt) : undefined, observation: redactText(ev.observation) };
      case 'dependency':
        return { ...ev, observation: redactText(ev.observation) };
    }
  });
  return { ...f, evidence };
}

export function buildJsonReport(scan: Scan, findings: Finding[], generatedAt = new Date().toISOString()): JsonReport {
  const bySeverity: Record<string, number> = {};
  const byStatus: Record<string, number> = {};
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byStatus[f.status] = (byStatus[f.status] ?? 0) + 1;
  }
  return {
    schema: 'owasp-assessment-platform/report',
    version: 1,
    generatedAt,
    classification: 'confidential',
    scan,
    summary: {
      totalFindings: findings.length,
      bySeverity,
      byStatus,
      enginesRun: scan.engines.filter((e) => e.status === 'ran').map((e) => e.engine),
      enginesUnavailable: scan.engines.filter((e) => e.status === 'unavailable').map((e) => e.engine),
    },
    findings: findings.map((f) => ({ ...redactFindingEvidence(f), risk: riskForFinding(f) })),
    riskSummary: buildRiskSummary(findings),
    coverage: scan.coverage,
    disclaimer: DISCLAIMER,
  };
}

/** F4: per-band counts over the attached risk model. */
function buildRiskSummary(findings: Finding[]): Record<string, number> {
  const out: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    const band = riskForFinding(f).band;
    out[band] = (out[band] ?? 0) + 1;
  }
  return out;
}

export { DISCLAIMER };
