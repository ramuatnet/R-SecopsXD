/**
 * Built-in redirect probe engine (ACTIVE) — open-redirect detection (CWE-601).
 *
 * Discovers query parameters whose names suggest redirect handling, re-issues
 * them pointing at the IETF-reserved marker host `ovap-redirect.example`
 * (never resolves; no third party is ever contacted), and classifies:
 *  - 3xx Location to the marker  → confirmed open redirect
 *  - 200 with meta-refresh/JS redirect to the marker → probable
 *
 * The scoped client never follows out-of-scope redirects — the safety layer's
 * block message is itself the evidence of the target-side redirect.
 */
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding } from '../../core/types.ts';

const INFO: EngineInfo = {
  id: 'builtin.redirect-probe',
  name: 'Open Redirect Probe',
  kind: 'builtin',
  capabilities: {
    A01: cap('open-redirect detection on discovered redirect parameters (reserved marker host, never followed)'),
  },
  modes: ['active'],
  targetKinds: ['webapp'],
};

const REDIRECT_PARAMS = [
  'redirect', 'redirect_uri', 'redirect_url', 'return', 'return_to', 'returnto',
  'returnurl', 'next', 'goto', 'dest', 'destination', 'rurl', 'continue', 'url', 'link',
];
const MARKER = 'https://ovap-redirect.example/marker';
const MARKER_HOST = 'ovap-redirect.example';
const MAX_PARAMS = 3;

export class RedirectProbeEngine implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const findings: RawFinding[] = [];
    const candidates: Array<{ url: string; param: string }> = [];
    const seen = new Set<string>();
    for (const p of ctx.crawl?.pages ?? []) {
      if (candidates.length >= MAX_PARAMS) break;
      const u = new URL(p.url);
      for (const param of [...u.searchParams.keys()]) {
        if (!REDIRECT_PARAMS.includes(param.toLowerCase())) continue;
        const probeUrl = new URL(p.url);
        probeUrl.searchParams.set(param, MARKER);
        const key = probeUrl.toString();
        if (seen.has(key)) continue;
        seen.add(key);
        candidates.push({ url: key, param });
        if (candidates.length >= MAX_PARAMS) break;
      }
    }

    for (const { url, param } of candidates) {
      if (ctx.signal.aborted) break;
      const res = await ctx.client.get(url);
      const path = new URL(url).pathname;

      // Case 1: server 30x'd to the marker; the scope guard blocked following it.
      if (!res.ok && 'blocked' in res && res.blocked.includes(MARKER_HOST)) {
        findings.push(this.finding(ctx, path, param, 'confirmed', 'high',
          `Open redirect: ${param} causes a server redirect to an external domain`,
          'The server responded with a redirect whose Location targets the attacker-controlled marker host ' +
          "(observed in the redirect that the platform's scope guard blocked from following). Users following " +
          `crafted links to ${path}?${param}=… land on attacker-chosen domains (CWE-601).`,
          'Validate redirect destinations against an allow-list of trusted origins; use server-side state ' +
          '(redirect IDs) instead of URLs in parameters.',
        ));
        continue;
      }
      if (!res.ok) continue;

      // Case 2: 200 with client-side redirect to the marker.
      const meta = /<meta[^>]+http-equiv\s*=\s*["']refresh["'][^>]+content\s*=\s*["'][^"']*url=(https?:\/\/ovap-redirect\.example[^"']*)/i.exec(res.body);
      const js = /(?:window\.)?location(?:\.href)?\s*=\s*["'](https?:\/\/ovap-redirect\.example[^"']*)["']/i.exec(res.body);
      const clientTarget = meta?.[1] ?? js?.[1];
      if (clientTarget) {
        findings.push(this.finding(ctx, path, param, 'probable', 'medium',
          `Client-side redirect to external domain via ${param} parameter`,
          'The response contains a client-side redirect to the marker host when the parameter is set. ' +
        'Whether this is exploitable depends on how the value reaches the redirect logic (CWE-601).',
        'Encode/allow-list the destination before rendering it into redirect logic.',
        ));
      }
    }

    ctx.log('redirect probe finished', { candidates: candidates.length, findings: findings.length });
    return { findings, version: 'builtin', detail: `${candidates.length} redirect parameter(s) probed with reserved marker host` };
  }

  private finding(
    ctx: ScanContext, path: string, param: string,
    status: 'confirmed' | 'probable', severity: 'high' | 'medium',
    title: string, explanation: string, remediation: string,
  ): RawFinding {
    return {
      rawId: 'open-redirect',
      title: `${title} [${param}]`,
      category: 'A01',
      cwe: 601,
      severity,
      confidence: status === 'confirmed' ? 'high' : 'medium',
      status,
      asset: ctx.target.origin,
      locator: `${path}?${param}=`,
      evidence: [{
        kind: 'http',
        request: { method: 'GET', url: url_(path, param), headers: {} },
        response: { status: 302, headers: {}, bodyExcerpt: '' },
        observation: `Parameter "${param}" set to the reserved marker host ${MARKER_HOST} (never contacted) resulted in a redirect/redirect-instruction to it`,
      }],
      explanation,
      remediation,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html',
        'https://owasp.org/Top10/2025/en/A01_2025-Broken_Access_Control/',
      ],
    };

    function url_(path: string, param: string): string {
      return `${ctx.target.origin}${path}?${param}=${MARKER}`;
    }
  }
}
