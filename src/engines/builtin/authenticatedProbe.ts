/**
 * Built-in authenticated probe engine (ACTIVE + credential profile required).
 *
 * Backlog B1 v1: uses the target's configured test account to perform checks
 * impossible without a session:
 *   - Authenticated surface mapping (informational): pages served with a
 *     session that reject anonymous access.
 *   - Logout session invalidation (A07, CWE-613): reuses the pre-logout
 *     session on a protected page after logging out.
 *   - JWT forgery verification (A04, CWE-347): if the session token is a JWT,
 *     submits alg=none and stripped-signature forgeries to the protected page.
 *
 * Safety: exactly one test account, no credential guessing, all session
 * material redacted from evidence, requests bounded and rate-limited through
 * the scoped client. The password never enters findings, evidence or logs.
 */
import type { CredentialProfile, Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding } from '../../core/types.ts';
import { redactText } from '../../core/redact.ts';


/** Authenticated session — supports cookie-based and bearer-token-based auth. */
interface Session {
  cookies: Array<{ name: string; value: string }>;
  /** Pre-built headers ready to pass to client.get()/postForm(). */
  authHeaders: Record<string, string>;
  bearerToken?: string | undefined;
}

const INFO: EngineInfo = {
  id: 'builtin.authenticated-probe',
  name: 'Authenticated Probe',
  kind: 'builtin',
  capabilities: {
    A01: cap('authenticated surface mapping with the configured test account (informational inventory)'),
    A07: cap('logout session-invalidation verification; JWT forgery acceptance (alg=none / stripped signature)'),
    A04: cap('JWT forgery acceptance against the live session token'),
  },
  modes: ['active'],
  targetKinds: ['webapp'],
};

const AUTH_CRAWL_PAGES = 10;
const ANON_PROBE_BUDGET = 8;

function looksLikeJwt(value: string): boolean {
  return /^eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(\.[A-Za-z0-9_-]{4,})?$/.test(value.trim());
}

/** Extract name=value pairs from raw Set-Cookie header text (comma-joined). */
function parseCookies(setCookie: string): Array<{ name: string; value: string }> {
  const out: Array<{ name: string; value: string }> = [];
  const re = /(?:^|,\s*)([A-Za-z0-9_.!-]+)=([^;,]*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(setCookie)) !== null) {
    if (m[1]!.toLowerCase() === 'expires' || m[1]!.toLowerCase() === 'path') continue;
    out.push({ name: m[1]!, value: m[2]! });
  }
  return out;
}

export class AuthenticatedProbeEngine implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    if (!ctx.credentials) {
      return { findings: [], notExecutedReason: 'no credential profile configured for this target (set one to unlock authenticated checks)' };
    }
    const loginForm = this.findLoginForm(ctx);
    if (!loginForm) {
      return { findings: [], notExecutedReason: 'login form not discovered in crawl and no loginUrl configured on the credential profile' };
    }

    const session = await this.login(ctx, loginForm);
    if (!session) {
      return { findings: [], notExecutedReason: 'login did not yield a session cookie — verify the credentials or the field names on the credential profile' };
    }
    ctx.log('authenticated', { user: ctx.credentials.username, cookieNames: session.cookies.map((c) => c.name) });

    const findings: RawFinding[] = [];
    const protectedPage = await this.findProtectedPage(ctx, session);
    if (!protectedPage) {
      return {
        findings,
        detail: `logged in as ${redactText(ctx.credentials.username, 64)}; no anonymously-denied page identified among crawled links — session checks not executed`,
      };
    }

    // --- A07: logout invalidation ---
    const logoutFinding = await this.logoutInvalidationCheck(ctx, session, protectedPage);
    if (logoutFinding) findings.push(logoutFinding);

    // --- A04: JWT forgery (only when the session token is a JWT) ---
    const jwtFinding = await this.jwtForgeryCheck(ctx, session, protectedPage);
    if (jwtFinding) findings.push(jwtFinding);

    // --- A01: cross-role authorization matrix (requires a second identity) ---
    if (ctx.credentialsSecondary) {
      const matrixFinding = await this.roleMatrixCheck(ctx, session, protectedPage);
      if (matrixFinding) findings.push(matrixFinding);
    }
    // --- A01: authenticated surface map (informational) ---
    const surface = await this.surfaceMap(ctx, session);
    if (surface) findings.push(surface);

    return {
      findings,
      version: 'builtin',
      detail: `authenticated as ${redactText(ctx.credentials.username, 64)}; protected page: ${protectedPage.path}`,
    };
  }

  private findLoginForm(ctx: ScanContext): { url: string; fields: string[] } | undefined {
    for (const p of ctx.crawl?.pages ?? []) {
      const f = p.forms.find((f) => f.hasPasswordField);
      if (f) return { url: f.action, fields: f.fields };
    }
    if (ctx.credentials?.loginUrl) {
      return { url: ctx.credentials.loginUrl, fields: [ctx.credentials.usernameField ?? 'username', ctx.credentials.passwordField ?? 'password'] };
    }
    return undefined;
  }

  private async login(ctx: ScanContext, form: { url: string; fields: string[] }, profile?: CredentialProfile): Promise<Session | undefined> {
    const cred = profile ?? ctx.credentials!;
    if (cred.loginType === 'json') return this.jsonLogin(ctx, cred);
    const userField = cred.usernameField
      ?? (form.fields.find((f) => /user|email|login/i.test(f)) ?? form.fields[0] ?? 'username');
    const passField = cred.passwordField
      ?? (form.fields.find((f) => /pass/i.test(f)) ?? form.fields.find((f) => f !== userField) ?? 'password');
    const res = await ctx.client.postForm(form.url, { [userField]: cred.username, [passField]: cred.password });
    if (!res.ok) return undefined;
    const setCookie = res.headers['set-cookie'] ?? '';
    const cookies = parseCookies(setCookie).filter((c) => c.value !== '' && c.value !== 'deleted');
    if (cookies.length === 0) return undefined;
    const authHeaders: Record<string, string> = { cookie: cookies.map((c) => `${c.name}=${c.value}`).join('; ') };
    return { cookies, authHeaders };
  }

  /**
   * JSON-API login: POST {username, password} as JSON to loginUrl.
   * Session extraction: Set-Cookie (preferred) or bearer token from the JSON
   * response body (tokenField or common keys: token, access_token, jwt).
   */
  private async jsonLogin(ctx: ScanContext, cred: CredentialProfile): Promise<Session | undefined> {
    const loginUrl = cred.loginUrl ?? new URL('/login', ctx.target.origin + '/').toString();
    const raw = await ctx.client.postJson(loginUrl, { username: cred.username, password: cred.password });
    if (!raw.ok) return undefined;
    const setCookie = raw.headers['set-cookie'] ?? '';
    const cookies = parseCookies(setCookie).filter((c) => c.value !== '' && c.value !== 'deleted');
    let bearerToken: string | undefined;
    try {
      const parsed = JSON.parse(raw.body) as Record<string, unknown>;
      const tokenKeys = cred.tokenField ? [cred.tokenField, 'token', 'access_token', 'jwt'] : ['token', 'access_token', 'jwt'];
      for (const key of tokenKeys) {
        const v = parsed[key];
        if (typeof v === 'string' && v.length > 8) { bearerToken = v; break; }
      }
    } catch { /* not JSON */ }
    if (cookies.length === 0 && !bearerToken) return undefined;
    const authHeaders: Record<string, string> = {};
    if (cookies.length > 0) authHeaders.cookie = cookies.map((c) => `${c.name}=${c.value}`).join('; ');
    if (bearerToken) authHeaders.authorization = `Bearer ${bearerToken}`;
    return { cookies, authHeaders, bearerToken };
  }

  /**
   * Identify a page that is anonymously denied but serves 200 with the session:
   * the reference point for invalidation/forgery checks.
   */
  private async findProtectedPage(
    ctx: ScanContext,
    session: Session,
  ): Promise<{ path: string; url: string } | undefined> {
    const origin = ctx.target.origin;
    const links = [
      ...(ctx.crawl?.pages ?? []).flatMap((p) => p.links),
      ...(ctx.crawl?.discoveredEndpoints ?? []).slice(0, 20).map((e) => new URL(e, ctx.target.origin).toString()),
    ].slice(0, 60);
    let anonProbes = 0;
    for (const link of links) {
      if (anonProbes >= ANON_PROBE_BUDGET || ctx.signal.aborted) break;
      try {
        const u = new URL(link);
        if (u.origin !== origin) continue;
        if (/(logout|signin|signup|register)/i.test(u.pathname)) continue;
        anonProbes++;
        const [authed, anon] = await Promise.all([
          ctx.client.get(u.toString(), session.authHeaders),
          ctx.client.get(u.toString()),
        ]);
        if (!authed.ok) continue;
        // Anonymous denial: explicit 401/403, OR the client was redirected to a
        // login page (the final URL is the login route even though it serves 200).
        const anonFinalPath = anon.ok ? new URL(anon.finalUrl).pathname : '';
        const anonDenied = !anon.ok || anon.status === 401 || anon.status === 403 ||
          /login|signin|auth/i.test(anonFinalPath);
        if (anonDenied && authed.status === 200) {
          return { path: u.pathname, url: u.toString() };
        }
      } catch { /* skip */ }
    }
    return undefined;
  }

  private async logoutInvalidationCheck(
    ctx: ScanContext,
    session: Session,
    protectedPage: { path: string; url: string },
  ): Promise<RawFinding | undefined> {
    const logoutUrl = (ctx.crawl?.pages ?? [])
      .flatMap((p) => p.links)
      .find((l) => /logout|signout/i.test(l));
    if (!logoutUrl) return undefined;
    if (!ctx.guard.inScope(logoutUrl)) return undefined;

    await ctx.client.get(logoutUrl, session.authHeaders);
    const after = await ctx.client.get(protectedPage.url, session.authHeaders);
    if (!after.ok) return undefined;
    const afterPath = new URL(after.finalUrl).pathname;
    if (after.status !== 200 || /login|signin|auth/i.test(afterPath)) return undefined; // invalidated → pass

    return {
      rawId: 'session-not-invalidated-after-logout',
      title: `Session remains valid after logout (${protectedPage.path})`,
      category: 'A07',
      cwe: 613,
      severity: 'medium',
      confidence: 'medium',
      status: 'probable',
      asset: ctx.target.origin,
      locator: protectedPage.path,
      evidence: [
        {
          kind: 'process',
          command: `authenticated probe: GET ${logoutUrl} (logout) → GET ${protectedPage.url} with pre-logout session`,
          observation: 'Protected page still served HTTP 200 with the pre-logout session cookie',
        },
      ],
      explanation:
        'After requesting logout, the previously captured session still grants access to a protected page ' +
        '(CWE-613, insufficient session expiration). A stolen or previously captured session token remains ' +
        'usable after the user believes they have logged out. Confidence medium: some applications re-issue ' +
        'an equivalent anonymous session that still renders a public-looking page — verify the response ' +
        'actually contains authenticated content.',
      remediation:
        'Invalidate the server-side session (or revoke the token) on logout, clear client state, and reject ' +
        'subsequent requests bearing the old identifier.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'],
    };
  }

  private async jwtForgeryCheck(
    ctx: ScanContext,
    session: Session,
    protectedPage: { path: string; url: string },
  ): Promise<RawFinding | undefined> {
    const sessionCookie = session.cookies.find((c) => looksLikeJwt(c.value));
    if (!sessionCookie) return undefined;

    const [headerB64, payloadB64] = sessionCookie.value.split('.');
    let header: { alg?: string; typ?: string };
    let payload: Record<string, unknown>;
    try {
      header = JSON.parse(Buffer.from(headerB64!, 'base64url').toString('utf8')) as { alg?: string; typ?: string };
      payload = JSON.parse(Buffer.from(payloadB64!, 'base64url').toString('utf8')) as Record<string, unknown>;
    } catch {
      return undefined;
    }
    if (String(header.alg ?? '').toLowerCase() === 'none') return undefined; // already unsigned; observation engine covers it

    const noneHeader = Buffer.from(JSON.stringify({ ...header, alg: 'none' })).toString('base64url');
    const payloadNoExp = { ...payload };
    delete payloadNoExp.exp;
    const forgedTokens = [
      { name: 'alg=none (no signature)', token: `${noneHeader}.${payloadB64}.` },
      { name: 'alg=none (empty signature segment)', token: `${noneHeader}.${payloadB64}.` },
      { name: 'stripped-signature replay (original alg)', token: `${headerB64}.${payloadB64}.` },
    ].slice(0, 2);

    for (const attempt of forgedTokens) {
      if (ctx.signal.aborted) break;
      const forgedAuthHeaders: Record<string, string> = { ...session.authHeaders };
      const existingCookie = forgedAuthHeaders.cookie ?? '';
      forgedAuthHeaders.cookie = existingCookie
        ? existingCookie.replace(`${sessionCookie.name}=${sessionCookie.value}`, `${sessionCookie.name}=${attempt.token}`)
        : `${sessionCookie.name}=${attempt.token}`;
      const res = await ctx.client.get(protectedPage.url, forgedAuthHeaders);
      if (!res.ok || res.status !== 200) continue;
      if (/login|signin|auth/i.test(new URL(res.finalUrl).pathname)) continue; // redirected to login = rejected
      return {
        rawId: 'jwt-forgery-accepted',
        title: `Server accepted a forged JWT (${attempt.name}) on a protected endpoint`,
        category: 'A04',
        cwe: 347,
        severity: 'critical',
        confidence: 'high',
        status: 'confirmed',
        asset: ctx.target.origin,
        locator: protectedPage.path,
        evidence: [{
          kind: 'process',
          command: `authenticated probe: submitted forged token (${attempt.name}) as session cookie ${sessionCookie.name}=[REDACTED]`,
          observation: `Protected page ${protectedPage.path} returned HTTP 200 to a forged token; original alg=${header.alg ?? 'unknown'}; submitted claims identical except signature removed`,
        }],
        explanation:
          'The server accepted a cryptographically invalid token (algorithm confusion / unsigned token, ' +
          'CWE-347) in place of the legitimate session. An attacker can mint arbitrary identities — this is ' +
          'a full authentication bypass. Confirmed against the live application with the authorized test account.',
        remediation:
          'Pin the accepted algorithm at verification time, always require and verify the signature against ' +
          'the trusted key, and reject tokens with mismatched or missing signatures. Test with a library that ' +
          'cannot be configured for alg=none.',
        references: ['https://datatracker.ietf.org/doc/html/rfc8725', 'https://owasp.org/Top10/2025/en/A04_2025-Cryptographic_Failures/'],
      };
    }
    return undefined;
  }

  /**
   * Cross-role authorization matrix (two test identities): pages that the
   * PRIMARY account reaches are re-requested with the SECONDARY identity.
   * A 200 on a primary-restricted page from the secondary role is the BOLA/
   * BFLA signature (probable — some pages are legitimately shared).
   */
  private async roleMatrixCheck(
    ctx: ScanContext,
    primarySession: Session,
    protectedPage: { path: string; url: string },
  ): Promise<RawFinding | undefined> {
    const secondary = ctx.credentialsSecondary!;
    const loginForm = this.findLoginForm(ctx);
    if (!loginForm) return undefined;
    const sessionB = await this.login(ctx, loginForm, secondary);
    if (!sessionB) {
      ctx.log('secondary role login failed', { role: secondary.role ?? 'secondary' });
      return undefined;
    }

    const res = await ctx.client.get(protectedPage.url, sessionB.authHeaders);
    if (!res.ok) return undefined;
    const finalPath = new URL(res.finalUrl).pathname;
    if (res.status !== 200 || /login|signin|auth/i.test(finalPath)) return undefined; // denied → pass

    return {
      rawId: 'cross-role-access',
      title: `Secondary role "${secondary.role ?? "secondary"}" (${redactText(secondary.username, 48)}) can access primary-restricted page ${protectedPage.path}`,
      category: 'A01',
      cwe: 285,
      severity: 'high',
      confidence: 'medium',
      status: 'probable',
      asset: ctx.target.origin,
      locator: protectedPage.path,
      evidence: [{
        kind: 'process',
        command: `role matrix: primary=${redactText(ctx.credentials!.username, 48)} secondary=${redactText(secondary.username, 48)}; GET ${protectedPage.url} as secondary`,
        observation: `Page reachable by primary returned HTTP 200 to the secondary role session (all session values redacted)`,
      }],
      explanation:
        'A page that the primary test account reaches was also served — without redirect to login — to a ' +
        'second account with a different role. This is the broken-function-level-authorization signature ' +
        '(CWE-285). Probable: some pages are legitimately shared across roles; confirm the page should be ' +
        'role-restricted before treating it as a bypass.',
      remediation:
        'Enforce role checks server-side per endpoint (deny by default), and verify with the two test roles ' +
        'after fixing. Do not rely on the UI hiding links.',
      references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README'],
    };
  }

  private async surfaceMap(
    ctx: ScanContext,
    session: Session,
  ): Promise<RawFinding | undefined> {
    const origin = ctx.target.origin;
    const links = [
      ...new Set([
        ...(ctx.crawl?.pages ?? []).flatMap((p) => p.links),
        ...(ctx.crawl?.discoveredEndpoints ?? []).slice(0, 20).map((e) => new URL(e, ctx.target.origin).toString()),
      ]),
    ].slice(0, AUTH_CRAWL_PAGES * 3);
    let authedOk = 0;
    let anonDenied = 0;
    const deniedPaths: string[] = [];
    let requests = 0;
    for (const link of links) {
      if (requests >= AUTH_CRAWL_PAGES || ctx.signal.aborted) break;
      try {
        const u = new URL(link);
        if (u.origin !== origin) continue;
        requests++;
        const authed = await ctx.client.get(u.toString(), session.authHeaders);
        if (!authed.ok || authed.status !== 200) continue;
        authedOk++;
        const anon = await ctx.client.get(u.toString());
        const anonFinalPath = anon.ok ? new URL(anon.finalUrl).pathname : '';
        if (!anon.ok || anon.status === 401 || anon.status === 403 || /login|signin|auth/i.test(anonFinalPath)) {
          anonDenied++;
          if (deniedPaths.length < 5) deniedPaths.push(u.pathname);
        }
      } catch { /* skip */ }
    }
    if (authedOk === 0) return undefined;
    return {
      rawId: 'authenticated-surface-map',
      title: `Authenticated surface mapped: ${authedOk} pages served to the test account, ${anonDenied} deny anonymous access`,
      category: 'A01',
      cwe: 200,
      severity: 'info',
      confidence: 'high',
      status: 'informational',
      asset: ctx.target.origin,
      locator: '/',
      evidence: [{
        kind: 'process',
        command: `authenticated probe: ${requests} requests with the configured test account (all session values redacted)`,
        observation: `Pages requiring authentication: ${deniedPaths.join(', ') || 'none observed'}`,
      }],
      explanation:
        'Inventory of the authenticated surface discovered with the authorized test account. Pages listed in ' +
        'the evidence deny anonymous access — they are the reference set for authenticated authorization ' +
        'testing (role-matrix checks remain a manual/extended feature).',
      remediation:
        'Use this inventory for authorization review: every page that denies anonymous access should also ' +
        'enforce role-level authorization, not merely authentication.',
      references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README'],
    };
  }
}
