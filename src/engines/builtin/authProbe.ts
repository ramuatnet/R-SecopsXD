/**
 * Built-in authentication probe (ACTIVE MODE ONLY).
 *
 * Two bounded, non-destructive checks against the discovered login form:
 *  1. Username enumeration: compares (normalized) login responses for
 *     clearly-nonexistent probe usernames versus a common username with a
 *     wrong password. Differential messaging indicates enumeration (CWE-645).
 *  2. Missing rate limiting: sends 8 bad-credential attempts and observes
 *     whether any 429/lockout response occurs (CWE-307).
 *
 * Never attempts credential guessing with real password lists, never
 * brute-forces: probe usernames are platform markers and passwords are fixed
 * non-secrets.
 */
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding } from '../../core/types.ts';

const INFO: EngineInfo = {
  id: 'builtin.auth-probe',
  name: 'Authentication Probe',
  kind: 'builtin',
  capabilities: {
    A07: cap('username enumeration via differential responses; missing rate limiting on login (bounded)'),
  },
  modes: ['active'],
  targetKinds: ['webapp'],
};

const PROBE_USERS = ['ovap-probe-aa1', 'ovap-probe-bb2'];
const COMMON_USER = 'admin';
const BAD_PASSWORD = 'ovap-not-a-real-password-9f8e7d6c';
const RATE_ATTEMPTS = 8;

export class AuthProbeEngine implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const findings: RawFinding[] = [];
    const login = this.findLoginForm(ctx);
    if (!login) {
      return { findings: [], version: 'builtin', detail: 'no credential-bearing form discovered; auth probes skipped' };
    }

    findings.push(...await this.enumerationCheck(ctx, login));
    findings.push(...await this.rateLimitCheck(ctx, login));

    ctx.log('auth probe finished', { findings: findings.length });
    return { findings, version: 'builtin' };
  }

  private findLoginForm(ctx: ScanContext): { url: string; fields: string[] } | undefined {
    for (const page of ctx.crawl?.pages ?? []) {
      const form = page.forms.find((f) => f.hasPasswordField);
      if (form) return { url: form.action, fields: form.fields };
    }
    // Fall back to conventional /login only if the crawler saw it referenced.
    const known = ctx.crawl?.pages.some((p) => new URL(p.url).pathname === '/login');
    if (known) return { url: new URL('/login', ctx.target.origin).toString(), fields: ['username', 'password'] };
    return undefined;
  }

  private async submit(ctx: ScanContext, login: { url: string; fields: string[] }, username: string): Promise<{ status: number; body: string }> {
    const userField = login.fields.includes('username') ? 'username'
      : login.fields.includes('user') ? 'user'
      : login.fields.includes('email') ? 'email'
      : login.fields[0] ?? 'username';
    const passField = login.fields.find((f) => f !== userField) ?? 'password';
    const res = await ctx.client.postForm(login.url, { [userField]: username, [passField]: BAD_PASSWORD });
    if (!res.ok) return { status: 0, body: '' };
    return { status: res.status, body: res.body };
  }

  /** Normalize a response body for comparison: strip the username itself and markup. */
  private normalize(body: string, username: string): string {
    return body
      .split(username).join('')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }

  private async enumerationCheck(ctx: ScanContext, login: { url: string; fields: string[] }): Promise<RawFinding[]> {
    const baseline: string[] = [];
    for (const u of PROBE_USERS) {
      const r = await this.submit(ctx, login, u);
      baseline.push(this.normalize(r.body, u));
    }
    if (baseline.length < 2) return [];
    const commonRes = await this.submit(ctx, login, COMMON_USER);
    const commonNorm = this.normalize(commonRes.body, COMMON_USER);
    const baselineConsistent = baseline[0] === baseline[1];
    const differs = baselineConsistent && commonNorm !== baseline[0];

    if (!differs) return [];

    return [{
      rawId: 'username-enumeration',
      title: 'Username enumeration via differential login responses',
      category: 'A07',
      cwe: 645,
      severity: 'medium',
      confidence: 'medium',
      status: 'probable',
      asset: ctx.target.origin,
      locator: new URL(login.url).pathname,
      evidence: [
        {
          kind: 'http',
          request: { method: 'POST', url: login.url, headers: {} },
          response: { status: commonRes.status, headers: {}, bodyExcerpt: this.normalize(commonRes.body, COMMON_USER).slice(0, 300) },
          observation: `Login response for common username "${COMMON_USER}" (wrong password) differs from response for nonexistent probe users`,
        },
        {
          kind: 'process',
          command: 'auth-probe enumeration check',
          observation: `Baseline responses for ${PROBE_USERS.length} nonexistent users were identical; common-user response differed`,
        },
      ],
      explanation:
        'The login endpoint responds differently when the username exists (wrong password) ' +
        'than when it does not. An attacker can enumerate valid usernames to focus ' +
        'password-guessing or phishing. The finding is probable: confirmation requires a ' +
        'known-valid username, which the platform deliberately does not possess.',
      remediation:
        'Return an identical generic message ("Invalid credentials") and identical status codes ' +
        'for both cases; equalize response timing; never interpolate the submitted username ' +
        'into error messages.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#authentication-and-error-messages',
      ],
    }];
  }

  private async rateLimitCheck(ctx: ScanContext, login: { url: string; fields: string[] }): Promise<RawFinding[]> {
    let saw429 = 0;
    for (let i = 0; i < RATE_ATTEMPTS; i++) {
      if (ctx.signal.aborted) break;
      const r = await this.submit(ctx, login, `ovap-rate-probe-${i}`);
      if (r.status === 429 || r.status === 423) saw429++;
    }
    if (saw429 > 0) return [];

    return [{
      rawId: 'no-login-rate-limit',
      title: 'No rate limiting observed on authentication endpoint',
      category: 'A07',
      cwe: 307,
      severity: 'medium',
      confidence: 'medium',
      status: 'probable',
      asset: ctx.target.origin,
      locator: new URL(login.url).pathname,
      evidence: [{
        kind: 'process',
        command: `auth-probe rate-limit check (${RATE_ATTEMPTS} failed attempts)`,
        observation: `${RATE_ATTEMPTS} consecutive failed login attempts produced no 429/lockout response`,
      }],
      explanation:
        'Rapid consecutive failed login attempts were accepted without throttling, lockout or ' +
        'CAPTCHA challenges. This allows unlimited password guessing and credential stuffing ' +
        '(CWE-307). Confidence is medium: server-side throttling that responds with normal ' +
        'status codes (e.g. silent delays) cannot be observed by the platform.',
      remediation:
        'Apply rate limiting on authentication endpoints (per account AND per source IP), ' +
        'respond with 429 when exceeded, and consider temporary lockout or step-up ' +
        'authentication after repeated failures.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README',
      ],
    }];
  }
}
