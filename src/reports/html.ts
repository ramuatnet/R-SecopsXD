/**
 * Self-contained HTML report (print-friendly, no external assets).
 */
import type { CoverageReport, Finding, Scan } from '../core/types.ts';
import { riskForFinding } from '../risk/attach.ts';
import { OWASP_CATEGORIES } from '../core/owasp.ts';
import { DISCLAIMER, redactFindingEvidence } from './json.ts';

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

const SEV_BADGE: Record<string, string> = {
  critical: 'badge critical', high: 'badge high', medium: 'badge medium',
  low: 'badge low', info: 'badge info',
};

export function buildHtmlReport(scan: Scan, rawFindings: Finding[], generatedAt = new Date().toISOString()): string {
  const findings = rawFindings.map(redactFindingEvidence);
  const sorted = [...findings].sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  const sev = countBy(sorted, (f) => f.severity);
  let risk: ReturnType<typeof riskForFinding>;
  const status = countBy(sorted, (f) => f.status);
  const ranEngines = scan.engines.filter((e) => e.status === 'ran');
  const unavailable = scan.engines.filter((e) => e.status === 'unavailable' || e.status === 'failed');

  const findingsHtml = sorted.map((f, i) => `
  <section class="finding">
    ${(() => { risk = riskForFinding(f); return ''; })()}
    <h3><span class="num">#${i + 1}</span> ${esc(f.title)}</h3>
    <div class="badges">
      <span class="badge cat">${f.category} · ${esc(OWASP_CATEGORIES[f.category].name)}</span>
      <span class="${SEV_BADGE[f.severity] ?? 'badge info'}">${f.severity}</span>
      <span class="badge conf">confidence: ${f.confidence}</span>
      <span class="badge status">status: ${f.status}</span>
      ${f.cwe !== undefined ? `<span class="badge">CWE-${f.cwe}</span>` : ''}
      ${f.cve !== undefined ? `<span class="badge cve">${esc(f.cve)}</span>` : ''}
      ${f.references.some((r) => /top10\.owasp\.org/.test(r)) ? `<a class="badge ref" href="${esc(f.references.find((r) => /top10\.owasp\.org/.test(r))!)}">OWASP ref</a>` : ''}
    </div>
    <table class="meta">
      <tr><th>Asset</th><td><code>${esc(f.asset)}</code></td></tr>
      <tr><th>Locator</th><td><code>${esc(f.locator)}</code></td></tr>
      <tr><th>Detected</th><td>${esc(f.detectedAt)}</td></tr>
      <tr><th>Stable ID</th><td><code>${esc(f.id)}</code></td></tr>
      <tr><th>Engines</th><td>${esc(f.provenance.map((p) => `${p.engine}${p.rawId ? ` (${p.rawId})` : ''}`).join(', '))}</td></tr>
      <tr><th>Risk</th><td><strong>${risk.score} ${risk.band}</strong> — factors: base ${risk.factors.base} × reachability ${risk.factors.reachability} × exposure ${risk.factors.exposure} × criticality ${risk.factors.criticality} × blast ${risk.factors.blast}${risk.backlog ? ' · <em>backlog</em>' : ''}</td></tr>
    </table>
    <h4>Explanation</h4><p>${esc(f.explanation)}</p>
    <h4>Remediation</h4><p>${esc(f.remediation)}</p>
    <h4>Evidence</h4>
    ${f.evidence.map(evidenceHtml).join('\n')}
    ${f.references.length ? `<h4>References</h4><ul>${f.references.map((r) => `<li><a href="${esc(r)}">${esc(r)}</a></li>`).join('')}</ul>` : ''}
  </section>`).join('\n');

  const coverageRows = scan.coverage.map((c) => {
    const taskLines = (c.tasks ?? []).map((t) =>
      `<div class="task task-${t.status === 'FINDING_DETECTED' ? 'finding' : t.status === 'AUTOMATED_PASS' ? 'pass' : t.status === 'MANUAL_REVIEW_REQUIRED' ? 'manual' : 'blocked'}">` +
      `<code>${esc(t.taskId)}</code> ${esc(t.status)}${t.findings > 0 ? ` <strong>(${t.findings} finding${t.findings > 1 ? 's' : ''})</strong>` : ''} — ${esc(t.title)}</div>`,
    ).join('');
    return `
    <tr class="cov-${c.verdict}">
      <td><strong>${c.category}</strong> ${esc(OWASP_CATEGORIES[c.category].name)}</td>
      <td>${c.status ? `<span class="badge ${c.status === 'COVERED_WITH_EVIDENCE' ? 'ok' : c.status === 'PARTIALLY_COVERED' ? 'warn' : ''}">${esc(c.status)}</span>` : ''}${c.status ? '<br>' : ''}${c.verdict}</td>
      <td>${esc(c.engines.join(', ') || '—')}</td>
      <td class="note">${esc(c.note)}${taskLines ? `<div class="tasks">${taskLines}</div>` : ''}</td>
    </tr>`;
  }).join('');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Assessment report — ${esc(scan.targetName)} — ${esc(scan.id.slice(0, 8))}</title>
<style>
:root { --ink:#1a1d23; --muted:#5c6672; --line:#d8dee6; --bg:#ffffff; --panel:#f6f8fa; }
* { box-sizing: border-box; }
body { font: 14px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: var(--ink); margin: 0; background: var(--bg); }
main { max-width: 960px; margin: 0 auto; padding: 32px 24px 80px; }
h1 { font-size: 26px; margin: 0 0 4px; } h2 { margin-top: 40px; border-bottom: 2px solid var(--line); padding-bottom: 6px; }
h3 { margin-bottom: 6px; } h4 { margin: 14px 0 4px; color: var(--muted); text-transform: uppercase; font-size: 11px; letter-spacing: .06em; }
.confidential { color: #b3261e; font-weight: 700; letter-spacing: .08em; font-size: 11px; }
.meta-grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(220px,1fr)); gap: 10px; margin: 18px 0; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 10px 14px; }
.card .k { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }
.badge { display: inline-block; border-radius: 20px; padding: 1px 10px; font-size: 11px; font-weight: 600; background: #eceff3; margin: 0 6px 4px 0; border: 1px solid var(--line); }
.badge.critical { background:#4a0404; color:#fff; border-color:#4a0404; } .badge.high { background:#b3261e; color:#fff; border-color:#b3261e; }
.badge.medium { background:#e8a33d; color:#231a00; border-color:#e8a33d; } .badge.low { background:#2f6fde; color:#fff; border-color:#2f6fde; }
.badge.info { background:#eceff3; } .badge.cat { background:#e8eaf6; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid var(--line); padding: 6px 9px; text-align: left; vertical-align: top; font-size: 13px; }
th { background: var(--panel); }
td.note { font-size: 12px; color: var(--muted); }
.finding { border: 1px solid var(--line); border-radius: 10px; padding: 16px 18px; margin: 18px 0; page-break-inside: avoid; }
.finding .num { color: var(--muted); font-weight: 500; margin-right: 6px; }
code { background: var(--panel); padding: 1px 5px; border-radius: 4px; font-size: 12px; word-break: break-all; }
pre { background: var(--panel); border: 1px solid var(--line); padding: 10px; border-radius: 6px; overflow-x: auto; font-size: 12px; }
.cov-manual-only td:first-child { color: var(--muted); }
.tasks { margin-top: 8px; border-top: 1px dashed var(--line); padding-top: 6px; }
.task { font-size: 11.5px; margin: 2px 0; color: var(--ink); }
.task code { font-size: 10.5px; }
.task-manual { color: var(--muted); }
.task-blocked { color: #b3261e; }
.task-finding strong { color: #b3261e; }
.disclaimer { margin-top: 40px; padding: 14px; background: #fff8e1; border: 1px solid #e0c36a; border-radius: 8px; font-size: 12.5px; }
footer { margin-top: 24px; color: var(--muted); font-size: 11.5px; }
@media print { .finding { break-inside: avoid; } }
</style></head><body><main>
<div class="confidential">CONFIDENTIAL — authorized-assessment output</div>
<h1>OWASP Top 10:2025 Assessment Report</h1>
<p>Target <strong>${esc(scan.targetName)}</strong> · profile <code>${esc(scan.profile)}</code> · mode <strong>${scan.mode}</strong></p>
<div class="meta-grid">
  <div class="card"><div class="k">Scan ID</div>${esc(scan.id)}</div>
  <div class="card"><div class="k">Started</div>${esc(scan.startedAt)}</div>
  <div class="card"><div class="k">Finished</div>${esc(scan.finishedAt ?? '—')}</div>
  <div class="card"><div class="k">Status</div>${esc(scan.status)}</div>
  <div class="card"><div class="k">Findings</div>${findings.length}</div>
  <div class="card"><div class="k">Requests</div>${scan.stats.requestsSent} sent · ${scan.stats.requestsBlocked} blocked by safety layer</div>
</div>

<h2>Executive summary</h2>
<table>
<tr><th>Severity</th>${['critical', 'high', 'medium', 'low', 'info'].map((s) => `<th>${s}</th>`).join('')}</tr>
<tr><td>Findings</td>${['critical', 'high', 'medium', 'low', 'info'].map((s) => `<td>${sev[s] ?? 0}</td>`).join('')}</tr>
</table>
<table>
<tr><th>Validation status</th><th>Count</th></tr>
${Object.entries(status).map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join('')}
</table>
<p><strong>Engines that ran:</strong> ${ranEngines.map((e) => `${esc(e.engine)} (${e.findingCount} findings)`).join(' · ') || '—'}</p>
${unavailable.length ? `<p><strong>Unavailable / failed engines:</strong> ${unavailable.map((e) => `${esc(e.engine)} — ${esc(e.detail ?? '')}`).join(' · ')}</p>` : ''}

<h2>OWASP Top 10:2025 coverage</h2>
<table>
<tr><th>Category</th><th>Verdict</th><th>Engines</th><th>Limits & notes</th></tr>
${coverageRows}
</table>

<h2>Findings (${findings.length})</h2>
${findingsHtml || '<p>No findings. This does not prove the absence of vulnerabilities — see coverage matrix.</p>'}

<div class="disclaimer"><strong>Honest-limitations notice.</strong> ${esc(DISCLAIMER)}</div>
<footer>Generated ${esc(generatedAt)} by owasp-assessment-platform · evidence redacted for secrets · JSON report is the canonical artifact</footer>
</main></body></html>`;
}

function evidenceHtml(ev: Finding['evidence'][number]): string {
  switch (ev.kind) {
    case 'http':
      return `<pre>${esc(`REQUEST ${ev.request.method} ${ev.request.url}\n${Object.entries(ev.request.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}`)}\n\n${
        ev.response ? esc(`RESPONSE ${ev.response.status}\n${ev.response.bodyExcerpt ?? ''}`) : ''
      }\n\n${esc(ev.observation)}</pre>`;
    case 'file':
      return `<pre>${esc(`${ev.path}${ev.lineStart ? `:${ev.lineStart}` : ''}\n${ev.excerpt ?? ''}\n\n${ev.observation}`)}</pre>`;
    case 'process':
      return `<pre>${esc(`$ ${ev.command}\n${ev.stdoutExcerpt ?? ''}\n\n${ev.observation}`)}</pre>`;
    case 'dependency':
      return `<pre>${esc(`${ev.ecosystem}: ${ev.packageName}${ev.installedVersion ? `@${ev.installedVersion}` : ''}${ev.fixedVersion ? ` → fixed in ${ev.fixedVersion}` : ''}\n${ev.observation}`)}</pre>`;
  }
}

function countBy<T>(arr: T[], key: (t: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const item of arr) out[key(item)] = (out[key(item)] ?? 0) + 1;
  return out;
}

function sevRank(s: string): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s] ?? 0;
}
