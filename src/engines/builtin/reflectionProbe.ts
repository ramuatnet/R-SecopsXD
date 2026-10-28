/**
 * Built-in reflection probe (ACTIVE MODE ONLY).
 *
 * For every crawled URL that carries query parameters, re-requests it with a
 * benign marker (as plain value and as an HTML tag fragment). A finding is
 * raised only when the marker appears *unencoded* (as a raw tag) in the
 * response — deterministic evidence of missing output encoding. The platform
 * does not execute JavaScript, so reflected XSS itself is labelled probable;
 * what is confirmed is the unencoded reflection.
 */
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding } from '../../core/types.ts';
import { redactText } from '../../core/redact.ts';
import { REFLECTION_MARKER } from '../../safety/payloadGuard.ts';

const INFO: EngineInfo = {
  id: 'builtin.reflection-probe',
  name: 'Input Reflection Probe',
  kind: 'builtin',
  capabilities: {
    A05: cap('unencoded reflection of probe markers; bounded error-based SQLi differential (1 request/param)'),
  },
  modes: ['active'],
  targetKinds: ['webapp'],
};

export class ReflectionProbeEngine implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const findings: RawFinding[] = [];
    const pages = ctx.crawl?.pages ?? [];
    const tagMarker = `"><${REFLECTION_MARKER}>`;

    const seen = new Set<string>();
    for (const page of pages) {
      if (ctx.signal.aborted) break;
      const u = new URL(page.url);
      if ([...u.searchParams.keys()].length === 0) continue;

      for (const param of [...u.searchParams.keys()].slice(0, 5)) {
        const probeUrl = new URL(page.url);
        probeUrl.searchParams.set(param, tagMarker);
        const key = probeUrl.toString();
        if (seen.has(key)) continue;
        seen.add(key);

        const res = await ctx.client.get(probeUrl.toString());
        if (!res.ok) continue;
        const raw = res.body.indexOf(`<${REFLECTION_MARKER}>`);
        if (raw < 0) continue;

        const start = Math.max(0, raw - 120);
        const excerpt = res.body.slice(start, raw + REFLECTION_MARKER.length + 60);
        findings.push({
          rawId: `reflection:${param}`,
          title: `Query parameter "${param}" reflected without output encoding`,
          category: 'A05',
          cwe: 79,
          severity: 'medium',
          confidence: 'high',
          status: 'probable',
          asset: ctx.target.origin,
          locator: `${u.pathname}?${param}=`,
          evidence: [{
            kind: 'http',
            request: { method: 'GET', url: probeUrl.toString(), headers: {} },
            response: { status: res.status, headers: {}, bodyExcerpt: excerpt },
            observation:
              `Marker tag injected into parameter "${param}" appears unencoded in the ` +
              `response HTML (context shown in evidence)`,
          }],
          explanation:
            'User-controlled input from the query string is embedded in the HTML response ' +
            'without encoding: a raw tag fragment injected via the parameter appears verbatim ' +
            'in the response. This is the precondition for reflected XSS (CWE-79, OWASP ' +
            'Top 10:2025 A05 Injection). The platform does not execute JavaScript, so the ' +
            'finding is probable pending confirmation that script context is reachable.',
          remediation:
            'HTML-encode all user input on output (context-appropriate encoding), apply a ' +
            'Content-Security-Policy as defense in depth, and validate input against an ' +
            'allow-list where feasible.',
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
          ],
        });
      }
    }

    // --- Bounded error-based SQLi differential (A05, CWE-89) ---
    // One extra request per parameter (max 3): append a single quote to the
    // original value and compare against the corpus baseline. No data
    // extraction, no time-based blind probes, no union payloads.
    const SQL_ERROR_PATTERNS = [
      /you have an error in your sql syntax/i,
      /sqlstate\[\w+\]/i,
      /warning:\s*\w+_fetch|mysql?_fetch/i,
      /ORA-\d{5}/i,
      /unclosed quotation mark/i,
      /SQLite3?::|SQLITE_ERROR/i,
      /PG::SyntaxError|psql:/i,
      /unterminated string/i,
    ];
    let sqliProbes = 0;
    for (const page of pages) {
      if (sqliProbes >= 3 || ctx.signal.aborted) break;
      const u = new URL(page.url);
      const params = [...u.searchParams.keys()].slice(0, 3);
      for (const param of params) {
        if (sqliProbes >= 3 || ctx.signal.aborted) break;
        sqliProbes++;
        const original = u.searchParams.get(param) ?? '';
        const baselineBad = SQL_ERROR_PATTERNS.some((re) => re.test(page.body));

        const probeUrl = new URL(page.url);
        probeUrl.searchParams.set(param, original + "'");
        const res = await ctx.client.get(probeUrl.toString());
        if (!res.ok) continue;

        const errorHit = SQL_ERROR_PATTERNS.some((re) => re.test(res.body));
        const statusChanged = res.status >= 500 && page.status < 500;
        if ((errorHit && !baselineBad) || (statusChanged && !errorHit && !baselineBad)) {
          findings.push({
            rawId: 'sqli-error-differential',
            title: `SQL error triggered by single-quote probe on parameter "${param}"`,
            category: 'A05',
            cwe: 89,
            severity: 'high',
            confidence: 'medium',
            status: 'probable',
            asset: ctx.target.origin,
            locator: `${u.pathname}?${param}=`,
            evidence: [{
              kind: 'http',
              request: { method: 'GET', url: probeUrl.toString(), headers: {} },
              response: { status: res.status, headers: {}, bodyExcerpt: redactText(res.body.slice(0, 300)) },
              observation: `Baseline request (original value) showed no SQL error; appending a single quote to "${param}" ${errorHit ? 'returned a database error message' : 'changed the response to HTTP ' + res.status}`,
            }],
            explanation:
              'Appending a single quote to the parameter value produced a database error (or a 500 ' +
              'response) that the baseline request did not. This is the classic error-based SQL injection ' +
              'signature (CWE-89). The platform sends exactly one probe per parameter — no data extraction, ' +
              'no stacked queries, no time-based blind testing. Confidence is medium: framework error pages ' +
              'can coincide; confirm by reviewing the query handling for the parameter.',
            remediation:
              'Use parameterized queries/prepared statements for this parameter, disable verbose database ' +
              'errors, and add input validation with an allow-list.',
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
          });
        }
      }
    }

    ctx.log('reflection probe finished', { findings: findings.length });
    return { findings, version: 'builtin' };
  }
}
