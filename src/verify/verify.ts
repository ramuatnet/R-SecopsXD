/**
 * Verification & Validation (v2 Phase 5, T5.1–T5.4).
 *
 * Every `probable` finding can be actively re-tested with an independent
 * method. Outcomes: confirmed | rejected | inconclusive — with rationale and
 * re-check evidence. Promotion to confirmed REQUIRES a verified outcome plus
 * an audit entry (T5.3): probable never silently becomes confirmed.
 *
 * T5.2 differential confirmation: baseline vs mutated requests must show a
 * causal delta (e.g. single-quote error differential for SQLi).
 * T5.4 FP-reduction: negative controls (re-check on hardened responses) feed
 * the measured FP rate.
 */
import type { Finding, RawFinding } from '../core/types.ts';
import type { ScopedHttpClient } from '../scan/httpClient.ts';
import { redactText } from '../core/redact.ts';

export type VerifyVerdict = 'confirmed' | 'rejected' | 'inconclusive';

export interface VerifyReport {
  findingId: string;
  rawId: string;
  verdict: VerifyVerdict;
  rationale: string;
  /** Redacted re-check evidence (the independent observation). */
  recheck: { request: string; observation: string } | undefined;
}

const SQL_ERROR = [
  /you have an error in your sql syntax/i, /sqlstate\[\w+\]/i, /ORA-\d{5}/i,
  /unclosed quotation mark/i, /SQLite3?::/i, /PG::SyntaxError/i, /unterminated string/i,
  /mysql?_fetch/i,
];

function hasSecurityHeaders(headers: Record<string, string>): boolean {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  const csp = lower['content-security-policy'];
  return csp !== undefined && lower['x-content-type-options'] !== undefined &&
    (lower['x-frame-options'] !== undefined || /frame-ancestors/i.test(csp));
}

async function reget(client: ScopedHttpClient, url: string): Promise<{ status: number; headers: Record<string, string>; body: string } | undefined> {
  const res = await client.get(url);
  if (!res.ok) return undefined;
  return { status: res.status, headers: res.headers, body: res.body };
}

/** T5.1 per-type validators — dispatch on the raw engine check id. */
export async function verifyByType(finding: Finding, client: ScopedHttpClient): Promise<VerifyReport> {
  const rawId = finding.provenance[0]?.rawId ?? '';
  const httpEv = finding.evidence.find((e) => e.kind === 'http');
  const url = httpEv && httpEv.kind === 'http' ? httpEv.request.url : finding.asset;
  const base = { findingId: finding.id, rawId };

  const reject = (rationale: string): VerifyReport => ({ ...base, verdict: 'rejected', rationale, recheck: undefined });
  const confirm = (rationale: string, request: string, observation: string): VerifyReport =>
    ({ ...base, verdict: 'confirmed', rationale, recheck: { request, observation } });
  const inc = (rationale: string): VerifyReport => ({ ...base, verdict: 'inconclusive', rationale, recheck: undefined });

  try {
    switch (true) {
      case rawId === 'missing-security-headers': {
        const page = await reget(client, url);
        if (!page) return inc('re-fetch failed');
        if (hasSecurityHeaders(page.headers)) {
          return reject('independent re-fetch observed the previously-missing security headers now present');
        }
        return confirm('independent re-fetch again observed no CSP/XCTO/XFO/Referrer-Policy',
          `GET ${url}`, `headers: ${Object.keys(page.headers).filter((h) => h.startsWith('x-') || h === 'content-security-policy' || h === 'referrer-policy').join(', ') || 'none of the checked headers'}`);
      }
      case rawId === 'hsts-missing': {
        const page = await reget(client, url);
        if (!page) return inc('re-fetch failed');
        if (page.headers['strict-transport-security'] !== undefined) {
          return reject('HSTS header present on re-fetch');
        }
        return confirm('independent re-fetch again observed no Strict-Transport-Security header',
          `GET ${url}`, 'strict-transport-security absent');
      }
      case rawId === 'cookie-missing-flags': {
        const page = await reget(client, url);
        if (!page) return inc('re-fetch failed');
        const sc = page.headers['set-cookie'] ?? '';
        const name = /"([^"]+)"/.exec(finding.title)?.[1] ?? '';
        const cookieLine = sc.split('\n').find((c) => c.startsWith(name)) ?? sc;
        const lacking: string[] = [];
        if (!/httponly/i.test(cookieLine)) lacking.push('HttpOnly');
        if (!/secure/i.test(cookieLine)) lacking.push('Secure');
        if (!/samesite/i.test(cookieLine)) lacking.push('SameSite');
        if (lacking.length === 0) return reject('cookie now carries the previously-missing attributes');
        return confirm(`independent re-fetch again observed the cookie without ${lacking.join('/')}`,
          `GET ${url}`, `Set-Cookie for ${name} lacks ${lacking.join(', ')}`);
      }
      case rawId === 'server-banner-disclosure': {
        const page = await reget(client, url);
        if (!page) return inc('re-fetch failed');
        const banner = page.headers['server'] ?? page.headers['x-powered-by'] ?? '';
        if (banner === '' || !/(\/|v|\s)\d+\.\d+/.test(banner)) return reject('banner no longer discloses a version');
        return confirm('independent re-fetch again observed the version-bearing banner',
          `GET ${url}`, `server: ${banner}`);
      }
      case rawId === 'verbose-error-disclosure':
      case rawId === 'sqli-error-differential': {
        // T5.2 differential: baseline vs probe — error must appear only under mutation
        const m = /\?([^=]+)=/.exec(finding.locator);
        const basePath = m ? `${finding.asset}${finding.locator.split('?')[0]}` : url;
        const baseline = await reget(client, basePath);
        const probeUrl = url.includes("'") ? url : `${url}${url.includes('?') ? '&' : '?'}id=5'`;
        const mutated = await reget(client, probeUrl);
        if (!baseline || !mutated) return inc('differential re-fetch failed');
        const baseBad = SQL_ERROR.some((re) => re.test(baseline.body)) || baseline.status >= 500;
        const mutBad = SQL_ERROR.some((re) => re.test(mutated.body)) || mutated.status >= 500;
        if (mutBad && !baseBad) {
          return confirm('differential confirmed: database error appears only under the mutated request',
            `GET ${probeUrl}`, `mutated status ${mutated.status}, baseline status ${baseline.status}`);
        }
        return reject('differential clean: no causal error delta between baseline and mutated requests');
      }
      case rawId === 'sri-external-script': {
        const page = await reget(client, url);
        if (!page) return inc('re-fetch failed');
        const originHost = new URL(url).hostname;
        const unshielded = /<script\b[^>]*\bsrc\s*=\s*["'](https?:\/\/[^"']+)["'][^>]*>/gi;
        let m: RegExpExecArray | null;
        let still = 0;
        while ((m = unshielded.exec(page.body)) !== null) {
          try {
            const u = new URL(m[1]!);
            if (u.hostname !== originHost && !/\bintegrity\s*=/i.test(m[0])) still++;
          } catch { /* skip */ }
        }
        if (still === 0) return reject('no unshielded external scripts on re-fetch');
        return confirm(`independent re-fetch still observes ${still} unshielded external script(s)`,
          `GET ${url}`, `${still} cross-origin scripts without integrity`);
      }
      case rawId === 'mixed-content': {
        const page = await reget(client, url);
        if (!page) return inc('re-fetch failed');
        const still = (page.body.match(/<(script|iframe|object|embed|img|source)\b[^>]*\b(?:src|data)\s*=\s*["']http:\/\//gi) ?? []).length;
        if (still === 0) return reject('no cleartext subresources on re-fetch');
        return confirm(`independent re-fetch still observes ${still} cleartext subresource(s)`,
          `GET ${url}`, `${still} http:// subresources`);
      }
      default:
        // generic re-observation: the documented observation must reproduce
        return await reobserve(finding, client);
    }
  } catch (e) {
    return inc(`verification error: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/**
 * Generic re-observation for findings without a dedicated validator.
 * T-W3: NEVER promotes on a body-line match alone — that's fragile and
 * produces false positives. Returns inconclusive for unknown types; the
 * per-type validators in verifyByType handle the known types properly.
 */
export async function reobserve(finding: Finding, client: ScopedHttpClient): Promise<VerifyReport> {
  const base = { findingId: finding.id, rawId: finding.provenance[0]?.rawId ?? '' };
  return {
    ...base,
    verdict: 'inconclusive',
    rationale: 'no type-specific validator for this finding type; manual review required (T-W3: body-line matching removed as unreliable)',
    recheck: undefined,
  };
}

// ---------- T5.3 promotion rules + audit ----------

export interface PromotionOutcome {
  findingId: string;
  from: string;
  to: string;
  audited: boolean;
}

/**
 * Apply a verification report to a finding list. Rules:
 *  - confirmed + current probable → status confirmed (promotion, audited)
 *  - rejected → status false_positive (audited)
 *  - inconclusive → status unchanged (never silently promoted)
 * Returns the outcomes for the audit log.
 */
export function applyVerification(
  findings: Finding[],
  report: VerifyReport,
  audit: (action: string, details: Record<string, unknown>) => void,
): PromotionOutcome | undefined {
  const f = findings.find((x) => x.id === report.findingId);
  if (!f) return undefined;
  const from = f.status;
  if (report.verdict === 'confirmed' && f.status === 'probable') {
    f.status = 'confirmed';
    f.evidence.push({
      kind: 'process',
      command: `verify: ${report.rawId}`,
      observation: `${report.rationale}${report.recheck ? ` [${report.recheck.request} → ${report.recheck.observation}]` : ''}`,
    });
    audit('finding.promoted', { findingId: f.id, from, to: 'confirmed', rationale: report.rationale });
    return { findingId: f.id, from, to: 'confirmed', audited: true };
  }
  // I2 (hardtask.md): machine rejections are a distinct status from human
  // false_positive triage — reporting must not conflate them.
  if (report.verdict === 'rejected' && f.status !== 'rejected_by_verification') {
    f.status = 'rejected_by_verification';
    audit('finding.rejected', { findingId: f.id, from, to: 'false_positive', rationale: report.rationale });
    return { findingId: f.id, from, to: 'false_positive', audited: true };
  }
  return { findingId: f.id, from, to: f.status, audited: false };
}

// ---------- T5.4 FP measurement ----------

/** Measured false-positive rate over a verification batch (negative controls). */
export function falsePositiveRate(reports: VerifyReport[]): { rate: number; rejected: number; total: number } {
  const rejected = reports.filter((r) => r.verdict === 'rejected').length;
  const total = reports.filter((r) => r.verdict !== 'inconclusive').length;
  return { rate: total === 0 ? 0 : rejected / total, rejected, total };
}

export function toRawFindingShape(f: Finding): RawFinding {
  return {
    rawId: f.provenance[0]?.rawId ?? '', title: f.title, category: f.category,
    severity: f.severity, confidence: f.confidence, status: f.status,
    asset: f.asset, locator: f.locator, evidence: f.evidence,
    explanation: f.explanation, remediation: f.remediation, references: f.references,
  };
}

// ---------- I1/I17 (hardtask.md): recall floor for auto-rejections ----------

/**
 * Findings auto-rejected by verification whose rawId matches a ground-truth
 * pattern — a planted true positive must NEVER be auto-rejected (I17). The
 * e2e harness asserts this is empty on every fixture scan.
 */
export function findTruePositiveRejections(findings: Array<{ status?: string; title?: string; provenance?: Array<{ rawId?: string }> }>, truthRawIdPatterns: string[]): Array<{ title: string | undefined; rawId: string }> {
  const out: Array<{ title: string | undefined; rawId: string }> = [];
  for (const f of findings) {
    if (f.status !== 'rejected_by_verification') continue;
    for (const p of f.provenance ?? []) {
      const rawId = p.rawId ?? '';
      if (truthRawIdPatterns.some((pat) => rawId.includes(pat))) {
        out.push({ title: f.title, rawId });
        break;
      }
    }
  }
  return out;
}
