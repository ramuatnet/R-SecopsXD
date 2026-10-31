/**
 * Client-ready deliverable report (newtasks.md E4) — second report profile
 * beside the technical one. Renders unattended from a completed scan; BLOCKED
 * without a signed engagement (E4.2); the not-tested section is as loud as the
 * findings (§6 report-theatre risk).
 */
import type { Scan, Finding, Engagement } from '../core/types.ts';
import { riskForFinding } from '../risk/attach.ts';
import { controlsForCategory } from '../compliance/controls.ts';

export interface DeliverableInput {
  scan: Scan;
  findings: Finding[];
  engagement: Engagement | undefined;
  generatedAt?: string;
}

export interface DeliverableOutput { html: string; notTested: string[]; }

const esc = (s: string): string => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

export function buildDeliverableReport(input: DeliverableInput): DeliverableOutput {
  const { scan, engagement } = input;
  const findings = [...input.findings].sort((a, b) => {
    const ra = riskForFinding(a).score;
    const rb = riskForFinding(b).score;
    return rb - ra;
  });

  // E4.1: not-tested section — as loud as the findings (§6).
  const notTested: string[] = [];
  for (const e of scan.engines) {
    if (e.status === 'skipped') notTested.push(`${e.engine}: not run — ${e.detail ?? 'skipped'}`);
    if (e.status === 'unavailable') notTested.push(`${e.engine}: unavailable — ${e.detail ?? ''}`);
    if (e.status === 'failed') notTested.push(`${e.engine}: failed — ${e.detail ?? ''}`);
  }
  for (const c of scan.coverage) {
    const notExecuted = (c.tasks ?? []).filter((t) => t.status === 'NOT_EXECUTED' || t.status === 'ENGINE_UNAVAILABLE' || t.status === 'MANUAL_REVIEW_REQUIRED');
    if (notExecuted.length > 0) {
      notTested.push(`${c.category} ${c.verdict}: ${notExecuted.length} task(s) not executed or requiring manual review`);
    }
  }
  if (engagement !== undefined && engagement.permittedClasses.length === 0) {
    notTested.push('Exploit classes: none permitted by the engagement (read-only) — demonstrated-impact testing not performed');
  }

  const roe = engagement === undefined
    ? '<p class="warn">No signed engagement on record for this scan.</p>'
    : `<table>
<tr><th>Engagement</th><td>${esc(engagement.name)} (${esc(engagement.id.slice(0, 8))})</td></tr>
<tr><th>Scope</th><td>${esc(engagement.scope.join(', '))}</td></tr>
<tr><th>Window</th><td>${esc(engagement.windowStart)} → ${esc(engagement.windowEnd)}</td></tr>
<tr><th>Permitted exploit classes</th><td>${esc(engagement.permittedClasses.join(', ') || 'none (read-only)')}</td></tr>
<tr><th>Signer</th><td>${esc(engagement.signer)} — attestation ${esc(engagement.attestationRef)}</td></tr>
<tr><th>Contacts</th><td>technical: ${esc(engagement.contactsTechnical)} · emergency: ${esc(engagement.contactsEmergency)}</td></tr>
</table>`;

  const findingsHtml = findings.map((f, i) => {
    const risk = riskForFinding(f);
    const controls = controlsForCategory(f.category);
    const evidenceGrade = f.evidence.length > 0 ? `${f.evidence.length} artefact(s) (${[...new Set(f.evidence.map((e) => e.kind))].join('/')})` : 'none';
    const exploitStatus = f.status === 'exploited' && f.exploit !== undefined
      ? `<strong>EXPLOITED</strong> — ${esc(f.exploit.impact)} (${f.exploit.requests} request(s), reversible)`
      : f.exploitUnavailable !== undefined
        ? `exploit_unavailable — ${esc(f.exploitUnavailable)}`
        : f.status === 'confirmed'
          ? 'confirmed — not exploited (class not permitted or no exploiter run)'
          : esc(f.status);
    return `
  <section class="finding">
    <h3><span class="num">#${i + 1}</span> ${esc(f.title)}</h3>
    <div class="badges">
      <span class="badge cat">${f.category}</span>
      <span class="badge ${f.severity}">${f.severity}</span>
      <span class="badge">status: ${esc(f.status)}</span>
      <span class="badge">risk: ${risk.score} ${risk.band}</span>
      ${f.exploit !== undefined ? '<span class="badge high">exploited</span>' : ''}
    </div>
    <table class="meta">
      <tr><th>Asset / locator</th><td><code>${esc(f.asset)}${esc(f.locator)}</code></td></tr>
      <tr><th>Impact</th><td>${f.exploit !== undefined ? esc(f.exploit.impact) : esc(f.explanation)}</td></tr>
      <tr><th>Evidence grade</th><td>${esc(evidenceGrade)} · confidence ${esc(f.confidence)}</td></tr>
      <tr><th>Exploit status</th><td>${exploitStatus}</td></tr>
      <tr><th>PoC</th><td>${f.exploit !== undefined ? `${esc(f.exploit.observedDelta)} (${f.exploit.requests} reversible request(s))` : 'see technical report for request/response evidence'}</td></tr>
      <tr><th>Remediation</th><td>${esc(f.remediation)}</td></tr>
      <tr><th>Retest</th><td>${f.retest !== undefined ? `${esc(f.retest.result)} at ${esc(f.retest.at)} — ${esc(f.retest.note)}` : 'not retested'}</td></tr>
      <tr><th>Controls</th><td>${esc([...controls.asvs, ...controls.wstg, ...controls.pci].join(', ') || 'unmapped (gap)')}</td></tr>
    </table>
  </section>`;
  }).join('\n');

  const html = `<!doctype html>
<html><head><meta charset="utf-8"><title>Security assessment — ${esc(scan.targetName)}</title>
<style>body{font-family:Georgia,serif;margin:2rem;max-width:900px}h2{border-bottom:2px solid #333}table{border-collapse:collapse;width:100%;margin:.5rem 0}td,th{border:1px solid #ccc;padding:.4rem;text-align:left;font-size:.9rem}.badge{padding:.1rem .4rem;border-radius:.2rem;background:#eee;font-size:.8rem}.high{background:#f8c}.warn{background:#ffd}.finding{border:1px solid #ddd;padding:1rem;margin:1rem 0}.not-tested{background:#fff3cd;border:1px solid #d39e00;padding:1rem}</style>
</head><body>
<h1>Security assessment — ${esc(scan.targetName)}</h1>
<p>Scan ${esc(scan.id.slice(0, 8))} · ${esc(scan.profile)} · ${esc(scan.mode)} · generated ${esc(input.generatedAt ?? new Date().toISOString())}</p>

<h2>1. Scope &amp; Rules of Engagement</h2>
${roe}

<h2>2. Methodology</h2>
<p>Executed engines: ${scan.engines.filter((e) => e.status === 'ran').map((e) => esc(e.engine)).join(', ') || 'none'}.
Every finding carries machine-checkable evidence; severity expresses potential impact, confidence
expresses engine certainty, and exploit status (where present) means the impact was actively
demonstrated with reversible, rate-limited requests under the engagement's rules.</p>

<h2>3. Findings (${findings.length})</h2>
${findingsHtml || '<p>No findings.</p>'}

<h2>4. Retest status</h2>
<table><tr><th>Finding</th><th>Retest</th></tr>
${findings.map((f) => `<tr><td>${esc(f.title.slice(0, 60))}</td><td>${f.retest !== undefined ? esc(f.retest.result) : 'not retested'}</td></tr>`).join('')}
</table>

<h2>5. Coverage &amp; not-tested</h2>
<table><tr><th>Category</th><th>Verdict</th><th>Status</th></tr>
${scan.coverage.map((c) => `<tr><td>${esc(c.category)}</td><td>${esc(c.verdict)}</td><td>${esc(c.status ?? '')}</td></tr>`).join('')}
</table>
<div class="not-tested">
<h3>⚠ Not tested / not covered — as important as the findings above</h3>
<ul>${notTested.map((n) => `<li>${esc(n)}</li>`).join('') || '<li>(all planned checks executed)</li>'}</ul>
</div>

<h2>6. Appendix — stable finding IDs</h2>
<ul>${findings.map((f) => `<li><code>${esc(f.id)}</code> — ${esc(f.title.slice(0, 70))}</li>`).join('')}</ul>
<p><em>Absence of findings is not proof of absence of vulnerabilities. Findings are evidence-based
observations; exploit status means demonstrated impact under the signed engagement, never
destructive action.</em></p>
</body></html>`;

  return { html, notTested };
}
