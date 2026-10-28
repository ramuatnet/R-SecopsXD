/**
 * PDF report: cover page, executive summary, coverage matrix, findings.
 */
import type { CoverageReport, Finding, Scan } from '../core/types.ts';
import { OWASP_CATEGORIES } from '../core/owasp.ts';
import { DISCLAIMER, redactFindingEvidence } from './json.ts';
import { PdfBuilder } from './pdfWriter.ts';

export function buildPdfReport(scan: Scan, rawFindings: Finding[], generatedAt = new Date().toISOString()): Uint8Array {
  const pdf = new PdfBuilder();
  const findings = rawFindings.map(redactFindingEvidence);
  const sorted = [...findings].sort((a, b) => sevRank(b.severity) - sevRank(a.severity));

  // ---- cover ----
  pdf.space(60);
  pdf.text('OWASP Top 10:2025 Vulnerability Assessment', { size: 24, bold: true });
  pdf.space(8);
  pdf.text(`Target: ${scan.targetName}`, { size: 14 });
  pdf.text(`Profile: ${scan.profile}  ·  Mode: ${scan.mode}`, { size: 12 });
  pdf.text(`Scan ID: ${scan.id}`, { size: 12 });
  pdf.text(`Started: ${scan.startedAt}${scan.finishedAt ? `   Finished: ${scan.finishedAt}` : ''}`, { size: 10 });
  pdf.space(10);
  pdf.label('CONFIDENTIAL — authorized assessment output', 'red');
  pdf.space(16);
  pdf.rule(0.6, 1);
  pdf.space(4);
  pdf.text(`Generated ${generatedAt} by owasp-assessment-platform. Evidence excerpts are redacted for secrets. The JSON report is the canonical artifact.`, { size: 9 });

  // ---- executive summary ----
  pdf.space(10);
  pdf.text('Executive summary', { size: 16, bold: true });
  pdf.rule();
  const bySev: Record<string, number> = {};
  const byStatus: Record<string, number> = {};
  for (const f of sorted) {
    bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
    byStatus[f.status] = (byStatus[f.status] ?? 0) + 1;
  }
  pdf.text(`Total findings: ${sorted.length}`, { size: 11, bold: true });
  pdf.text(`Severity — critical: ${bySev.critical ?? 0}, high: ${bySev.high ?? 0}, medium: ${bySev.medium ?? 0}, low: ${bySev.low ?? 0}, info: ${bySev.info ?? 0}`);
  pdf.text(`Validation status — ${Object.entries(byStatus).map(([k, v]) => `${k}: ${v}`).join(', ') || 'none'}`);
  pdf.space(6);
  const ran = scan.engines.filter((e) => e.status === 'ran');
  const unavailable = scan.engines.filter((e) => e.status === 'unavailable' || e.status === 'failed');
  pdf.text(`Engines that ran: ${ran.map((e) => `${e.engine} (${e.findingCount})`).join(', ') || 'none'}`);
  if (unavailable.length > 0) {
    pdf.text(`Unavailable / failed: ${unavailable.map((e) => `${e.engine} — ${e.detail ?? ''}`).join(' | ')}`, { size: 9 });
  }
  pdf.space(6);
  pdf.text(`Requests sent: ${scan.stats.requestsSent}  ·  blocked by safety layer: ${scan.stats.requestsBlocked}`, { size: 9 });

  // ---- coverage matrix ----
  pdf.space(8);
  pdf.text('OWASP Top 10:2025 coverage', { size: 16, bold: true });
  pdf.rule();
  for (const cov of scan.coverage) {
    pdf.ensureSpace(40);
    pdf.text(`${cov.category} — ${OWASP_CATEGORIES[cov.category].name}  [${cov.status ?? cov.verdict}]`, { size: 10.5, bold: true });
    if (cov.tasks && cov.tasks.length > 0) {
      pdf.text(`Tasks: ${cov.tasks.map((t) => `${t.taskId} ${t.status}${t.findings > 0 ? ` (${t.findings})` : ''}`).join(' | ')}`, { size: 8, indent: 10 });
    }
    pdf.text(`${cov.engines.length > 0 ? `Engines: ${cov.engines.join(', ')}. ` : ''}${cov.note}`, { size: 8.5, indent: 10 });
    pdf.space(4);
  }

  // ---- findings ----
  pdf.space(8);
  pdf.text(`Findings (${sorted.length})`, { size: 16, bold: true });
  pdf.rule();
  if (sorted.length === 0) {
    pdf.text('No findings were produced by the executed engines. This is not proof of absence of vulnerabilities — review the coverage matrix above for what was and was not tested.');
  }
  sorted.forEach((f, i) => {
    pdf.ensureSpace(120);
    pdf.space(6);
    pdf.text(`#${i + 1}  ${f.title}`, { size: 12.5, bold: true });
    pdf.label(`${f.category} · ${f.severity} · confidence ${f.confidence} · ${f.status}`, f.severity === 'critical' || f.severity === 'high' ? 'red' : f.severity === 'medium' ? 'amber' : 'gray');
    pdf.text(`Asset: ${f.asset}    Locator: ${f.locator}`, { size: 9 });
    pdf.text(`ID: ${f.id}${f.cwe !== undefined ? `    CWE-${f.cwe}` : ''}${f.cve !== undefined ? `    ${f.cve}` : ''}`, { size: 8.5 });
    pdf.text(`Detected: ${f.detectedAt}   Engine(s): ${f.provenance.map((p) => `${p.engine}${p.rawId ? ` (${p.rawId})` : ''}`).join(', ')}`, { size: 8.5 });
    pdf.space(4);
    pdf.text('Explanation', { size: 9.5, bold: true });
    pdf.text(f.explanation, { size: 9.5, indent: 10 });
    pdf.text('Remediation', { size: 9.5, bold: true });
    pdf.text(f.remediation, { size: 9.5, indent: 10 });
    pdf.text('Evidence', { size: 9.5, bold: true });
    for (const ev of f.evidence.slice(0, 2)) {
      const evText = evidenceText(ev);
      pdf.text(evText, { size: 8, indent: 10 });
    }
    if (f.references.length > 0) {
      pdf.text(`References: ${f.references.slice(0, 3).join(' ; ')}`, { size: 8, indent: 10 });
    }
    pdf.rule(0.9, 0.4, 6);
  });

  // ---- disclaimer ----
  pdf.space(10);
  pdf.text('Honest limitations', { size: 14, bold: true });
  pdf.rule();
  pdf.text(DISCLAIMER, { size: 9 });

  return pdf.finish(`scan ${scan.id.slice(0, 8)} — ${scan.targetName}`);
}

function evidenceText(ev: Finding['evidence'][number]): string {
  switch (ev.kind) {
    case 'http': {
      const req = `REQUEST ${ev.request.method} ${ev.request.url}`;
      const resp = ev.response ? `RESPONSE ${ev.response.status} ${ev.response.bodyExcerpt ?? ''}` : '';
      return `${req}\n${resp}\n${ev.observation}`.slice(0, 700);
    }
    case 'file':
      return `${ev.path}${ev.lineStart ? `:${ev.lineStart}` : ''} — ${ev.excerpt ?? ''}\n${ev.observation}`.slice(0, 700);
    case 'process':
      return `$ ${ev.command}\n${ev.stdoutExcerpt ?? ''}\n${ev.observation}`.slice(0, 700);
    case 'dependency':
      return `${ev.ecosystem}: ${ev.packageName}${ev.installedVersion ? `@${ev.installedVersion}` : ''}${ev.fixedVersion ? ` → fixed ${ev.fixedVersion}` : ''} — ${ev.observation}`.slice(0, 700);
  }
}

function sevRank(s: string): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s] ?? 0;
}

export type { CoverageReport };
