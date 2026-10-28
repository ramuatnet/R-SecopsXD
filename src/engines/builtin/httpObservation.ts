/**
 * Built-in HTTP observation engine (passive).
 *
 * Analyzes responses captured by crawler-lite (or fetches the origin root
 * itself when no corpus exists). Produces only deterministic,
 * evidence-backed observations: every finding references the exact response
 * it was observed in.
 *
 * Honest limits: cannot observe what the server logs (A09), cannot conclude
 * design flaws (A06), and header presence does not prove correct policy.
 */
import type { Engine, EngineAvailability, EngineRunResult, ScanContext, CrawlPage } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, HttpEvidence, RawFinding } from '../../core/types.ts';
import { isPrivateHost } from '../../safety/guard.ts';
import { redactText } from '../../core/redact.ts';

const INFO: EngineInfo = {
  id: 'builtin.http-observation',
  name: 'HTTP Security Observation',
  kind: 'builtin',
  capabilities: {
    A02: cap('security headers (incl. CSP quality), cookie flags, server banners, directory listings'),
    A04: cap('cleartext transport, HSTS absence, JWT handling observation'),
    A10: cap('verbose error pages / stack traces in observed responses'),
    A01: cap('sensitive information exposure in served content (heuristic)'),
    A08: cap('external scripts without Subresource Integrity (SRI)'),
    A09: cap('log-correlation indicators on error responses (hygiene signal only)', 'heuristic'),
    A07: cap('secrets in served JavaScript bundles (heuristic)'),
  },
  modes: ['passive', 'active'],
  targetKinds: ['webapp'],
};

export class HttpObservationEngine implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const findings: RawFinding[] = [];
    let pages = ctx.crawl?.pages ?? [];
    if (pages.length === 0) {
      // No crawler ran before us — observe at least the origin root.
      const res = await ctx.client.get(ctx.target.origin + '/');
      if (res.ok) {
        pages = [{ url: res.finalUrl, status: res.status, headers: res.headers, body: res.body, truncated: res.truncated, forms: [], links: [] }];
      }
    }

    const publicHost = !isPrivateHost(new URL(ctx.target.origin).hostname);

    const rootPage = pages.find((p) => new URL(p.url).pathname === '/') ?? pages[0];
    if (rootPage) {
      findings.push(...this.headerFindings(ctx, rootPage, publicHost));
      findings.push(...this.cookieFindings(ctx, rootPage));
      findings.push(...this.bannerFindings(ctx, rootPage));
      findings.push(...this.commentFindings(ctx, rootPage));
    }
    for (const page of pages) {
      findings.push(...this.errorFindings(ctx, page));
      findings.push(...this.correlationIdFindings(ctx, page));
      findings.push(...this.jwtFindings(ctx, page));
      findings.push(...this.sensitiveUrlFindings(ctx, page));
      if (page !== rootPage) {
        findings.push(...this.commentFindings(ctx, page));
        findings.push(...this.listingFindings(ctx, page));
      }
    }
    findings.push(...this.cleartextFindings(ctx, pages, publicHost));
    findings.push(...this.sriFindings(ctx, pages));
    findings.push(...this.cspQualityFindings(ctx, pages));
    findings.push(...this.hstsFindings(ctx, pages, publicHost));
    findings.push(...this.csrfFindings(ctx, pages));
    findings.push(...this.mixedContentFindings(ctx, pages));
    findings.push(...this.libraryVersionFindings(ctx, pages));
    findings.push(...await this.jsBundleSecretFindings(ctx, pages));
    if (ctx.mode === 'active') {
      findings.push(...await this.corsFindings(ctx, pages));
    }

    ctx.log('http observation finished', { pages: pages.length, findings: findings.length });
    return { findings, version: 'builtin' };
  }

  private headerFindings(ctx: ScanContext, page: CrawlPage, publicHost: boolean): RawFinding[] {
    const missing: string[] = [];
    const required: Array<[string, string]> = [
      ['content-security-policy', 'Content-Security-Policy'],
      ['x-content-type-options', 'X-Content-Type-Options'],
      ['x-frame-options', 'X-Frame-Options'],
      ['referrer-policy', 'Referrer-Policy'],
    ];
    const cspValue = page.headers['content-security-policy'] ?? '';
    const framingCovered = /frame-ancestors/i.test(cspValue);
    for (const [lower, canonical] of required) {
      if (lower === 'x-frame-options' && framingCovered) continue; // CSP frame-ancestors covers framing
      if (!(lower in page.headers)) missing.push(canonical);
    }
    if (missing.length === 0) return [];
    return [{
      rawId: 'missing-security-headers',
      title: `Missing security headers: ${missing.join(', ')}`,
      category: 'A02',
      cwe: 693,
      severity: publicHost ? 'high' : 'medium',
      confidence: 'high',
      status: 'confirmed',
      asset: ctx.target.origin,
      locator: new URL(page.url).pathname,
      evidence: [pageEvidence(page)],
      explanation:
        'The response does not set ' + missing.join(', ') + '. These headers are ' +
        'defense-in-depth controls against XSS (CSP), MIME sniffing (XCTO), clickjacking ' +
        '(X-Frame-Options) and referrer leakage. Their absence is observed directly on the ' +
        'response captured in the evidence.',
      remediation:
        'Set the missing headers at the web server or application middleware, e.g. ' +
        "Content-Security-Policy: default-src 'self'; X-Content-Type-Options: nosniff; " +
        'X-Frame-Options: DENY; Referrer-Policy: no-referrer. Validate that CSP does not break ' +
        'required functionality before rollout.',
      references: [
        'https://owasp.org/www-project-secure-headers/',
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy',
      ],
    }];
  }

  private cookieFindings(ctx: ScanContext, page: CrawlPage): RawFinding[] {
    const raw = page.headers['set-cookie'] ?? '';
    if (raw === '') return [];
    const findings: RawFinding[] = [];
    for (const cookie of raw.split(/(?=,\s*[^=;,]+=)/)) {
      const name = /^([^=;]+)/.exec(cookie)?.[1]?.trim();
      if (!name || /^(hashtest|probe|ovap)/i.test(name)) continue;
      const lower = cookie.toLowerCase();
      const missingFlags: string[] = [];
      if (!lower.includes('httponly')) missingFlags.push('HttpOnly');
      if (!lower.includes('secure')) missingFlags.push('Secure');
      if (!lower.includes('samesite')) missingFlags.push('SameSite');
      if (missingFlags.length === 0) continue;
      findings.push({
        rawId: 'cookie-missing-flags',
        title: `Cookie "${name}" set without ${missingFlags.join('/')} flag(s)`,
        category: 'A02',
        cwe: 614,
        severity: 'medium',
        confidence: 'high',
        status: 'confirmed',
        asset: ctx.target.origin,
        locator: new URL(page.url).pathname,
        evidence: [{
          kind: 'http',
          request: { method: 'GET', url: page.url, headers: {} },
          response: {
            status: page.status,
            headers: { 'set-cookie': `${name}=[REDACTED-VALUE]; Path=/` },
          },
          observation: `Set-Cookie for "${name}" lacks ${missingFlags.join(', ')}`,
        }],
        explanation:
          `The application sets cookie "${name}" without the ${missingFlags.join(', ')} ` +
          `attribute(s). ${flagImplications(missingFlags)}`,
        remediation: `Set the cookie with ${missingFlags.join('; ')} attributes ` +
          `(SameSite=Lax or Strict for session cookies).`,
        references: [
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie',
          'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
        ],
      });
    }
    return findings;
  }

  private bannerFindings(ctx: ScanContext, page: CrawlPage): RawFinding[] {
    const server = page.headers['server'] ?? '';
    const powered = page.headers['x-powered-by'] ?? '';
    const versioned = /(\/|v|\s)\d+\.\d+/.test(server) || /(\/|v|\s)\d+\.\d+/.test(powered);
    if (server === '' && powered === '') return [];
    if (!versioned && server.toLowerCase() !== 'oss') {
      // Generic banner without version: informational only, skip to keep precision.
      if (!powered) return [];
    }
    return [{
      rawId: 'server-banner-disclosure',
      title: `Server software and version disclosed (${[server, powered].filter(Boolean).join('; ')})`,
      category: 'A01',
      cwe: 200,
      severity: 'low',
      confidence: 'high',
      status: 'confirmed',
      asset: ctx.target.origin,
      locator: new URL(page.url).pathname,
      evidence: [pageEvidence(page)],
      explanation:
        'The Server/X-Powered-By response headers disclose the exact software stack and ' +
        'version. This is reconnaissance information that lets an attacker select known ' +
        'exploits for the specific version. It is an information exposure (CWE-200), which ' +
        'the OWASP Top 10:2025 maps to Broken Access Control.',
      remediation:
        'Remove or genericize the Server header (e.g. Server: web) and remove X-Powered-By. ' +
        'This does not fix any vulnerability but removes easy targeting information.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/README',
      ],
    }];
  }

  private errorFindings(ctx: ScanContext, page: CrawlPage): RawFinding[] {
    if (page.status < 400 && !/[^\n]*at\s+[\w$.]+\s*\(.*:\d+:\d+\)/.test(page.body)) return [];
    const patterns: Array<[RegExp, string]> = [
      [/\bat\s+[\w$.<>:/\\]+\s*\([^)]*:\d+(:\d+)?\)/, 'runtime stack frames'],
      [/Traceback \(most recent call last\)/, 'python traceback'],
      [/(System\.|java\.lang\.)[\w.]*Exception/, 'jvm exception'],
      [/\b(node_modules|\/srv\/|\/app\/|\/home\/\w+\/)[\w\-/.]+\.(js|py|rb|php|ts)/, 'internal file paths'],
    ];
    const matched = patterns.filter(([re]) => re.test(page.body)).map(([, what]) => what);
    if (matched.length === 0) return [];
    const excerpt = page.body.slice(0, 1200);
    return [{
      rawId: 'verbose-error-disclosure',
      title: `Verbose error disclosure (${matched.join(', ')}) on HTTP ${page.status}`,
      category: 'A10',
      cwe: 209,
      severity: 'medium',
      confidence: 'high',
      status: 'confirmed',
      asset: ctx.target.origin,
      locator: new URL(page.url).pathname,
      evidence: [{
        kind: 'http',
        request: { method: 'GET', url: page.url, headers: {} },
        response: { status: page.status, headers: {}, bodyExcerpt: excerpt.slice(0, 800) },
        observation: `HTTP ${page.status} response contains internal error details: ${matched.join(', ')}`,
      }],
      explanation:
        'The application returns internal exception details (stack traces or file paths) to ' +
        'the client. Error details reveal framework versions, file layout and code structure ' +
        'that assist exploitation. OWASP Top 10:2025 categorizes mishandling of exceptional ' +
        'conditions as A10.',
      remediation:
        'Return generic error pages to clients; log full details server-side with correlation ' +
        'IDs. Ensure a global error handler catches exceptions and never renders stack traces.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/README',
      ],
    }];
  }

  private commentFindings(ctx: ScanContext, page: CrawlPage): RawFinding[] {
    const comments = page.body.match(/<!--[\s\S]*?-->/g) ?? [];
    const sensitive: string[] = [];
    const patterns: Array<[RegExp, string]> = [
      [/\b(?:10|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+\b/, 'internal IP address'],
      [/(debug|staging|internal|intranet)[\w\s-]{0,30}(endpoint|host|server|url)/i, 'internal infrastructure reference'],
      [/\/api\/[\w\-/]*(debug|admin|internal)/i, 'internal API endpoint path'],
      [/\b(user|account|team|project)[\w\s-]{0,20}@(?:[\w-]+\.)+[a-z]{2,}\b/i, 'internal email'],
    ];
    for (const c of comments) {
      for (const [re, what] of patterns) {
        if (re.test(c) && !sensitive.includes(what)) sensitive.push(what);
      }
    }
    if (sensitive.length === 0) return [];
    return [{
      rawId: 'sensitive-html-comments',
      title: `Sensitive information in HTML comments (${sensitive.join(', ')})`,
      category: 'A01',
      cwe: 540,
      severity: 'low',
      confidence: 'medium',
      status: 'confirmed',
      asset: ctx.target.origin,
      locator: new URL(page.url).pathname,
      evidence: [{
        kind: 'http',
        request: { method: 'GET', url: page.url, headers: {} },
        response: {
          status: page.status,
          headers: {},
          bodyExcerpt: comments.find((c) => patterns.some(([re]) => re.test(c)))?.slice(0, 400) ?? '',
        },
        observation: `HTML comments disclose: ${sensitive.join(', ')}`,
      }],
      explanation:
        'HTML comments are delivered to every client and frequently contain internal hostnames, ' +
        'IPs, debug endpoints or development notes. This is inclusion of sensitive information ' +
        'in served source code (CWE-540).',
      remediation: 'Strip comments in production builds; never embed infrastructure details in client-served markup.',
      references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/README'],
    }];
  }

  private listingFindings(ctx: ScanContext, page: CrawlPage): RawFinding[] {
    const isListing = /<title>index of[\s\S]*<\/title>/i.test(page.body) ||
      /<h1>index of[\s\S]*<\/h1>/i.test(page.body) ||
      (/directory listing (for|of)/i.test(page.body) && /<a\s+href/i.test(page.body));
    if (!isListing) return [];
    return [{
      rawId: 'directory-listing',
      title: `Directory listing enabled on ${new URL(page.url).pathname}`,
      category: 'A01',
      cwe: 548,
      severity: 'medium',
      confidence: 'high',
      status: 'confirmed',
      asset: ctx.target.origin,
      locator: new URL(page.url).pathname,
      evidence: [pageEvidence(page)],
      explanation:
        'The server exposes a generated index of files in this directory. Attackers can ' +
        'enumerate files (backups, configs, archives) that were never linked. CWE-548, ' +
        'exposure of information through directory listing.',
      remediation: 'Disable autoindex/directory browsing on the web server; return 403/404 for directories.',
      references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README'],
    }];
  }

  private correlationIdFindings(ctx: ScanContext, page: CrawlPage): RawFinding[] {
    if (page.status < 400) return [];
    const corrHeader = Object.keys(page.headers).find((k) =>
      ['x-request-id', 'x-correlation-id', 'correlation-id', 'x-trace-id'].includes(k.toLowerCase()),
    );
    if (!corrHeader) return [];
    return [{
      rawId: 'log-correlation-header',
      title: `Security-relevant errors return a correlation ID (${corrHeader})`,
      category: 'A09',
      cwe: 778,
      severity: 'info',
      confidence: 'high',
      status: 'informational',
      asset: ctx.target.origin,
      locator: new URL(page.url).pathname,
      evidence: [{
        kind: 'http',
        request: { method: 'GET', url: page.url, headers: {} },
        response: { status: page.status, headers: { [corrHeader]: '[REDACTED-ID]' } },
        observation: `HTTP ${page.status} response carries ${corrHeader} — log-correlation indicator (positive hygiene signal)`,
      }],
      explanation:
        'Error responses carry a correlation identifier, which indicates server-side events can be tied to ' +
        'client-visible failures — a positive logging-hygiene signal (CWE-778 context). This does NOT verify ' +
        'that security events are logged, alerted on, or retained; operational alerting effectiveness remains ' +
        'a manual review item.',
      remediation: 'Keep correlation IDs on error paths and ensure they appear in server-side audit events.',
      references: ['https://owasp.org/Top10/2025/en/A09_2025-Security_Logging_and_Alerting_Failures/'],
    }];
  }

  /**
   * CORS misconfiguration (ACTIVE): re-requests ACAO-bearing pages with a
   * foreign Origin; a reflected origin combined with allow-credentials is a
   * confirmed cross-origin data-theft configuration (CWE-942).
   */
  private async corsFindings(ctx: ScanContext, pages: CrawlPage[]): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const foreignOrigin = 'https://ovap-foreign-origin.example';
    let checked = 0;
    for (const page of pages) {
      if (checked >= 3 || ctx.signal.aborted) break;
      const acao = page.headers['access-control-allow-origin'];
      if (acao === undefined) continue;
      checked++;
      const res = await ctx.client.get(page.url, { origin: foreignOrigin });
      if (!res.ok) continue;
      const reflected = (res.headers['access-control-allow-origin'] ?? '').toLowerCase() === foreignOrigin;
      const creds = (res.headers['access-control-allow-credentials'] ?? '').toLowerCase() === 'true';
      if (reflected && creds) {
        findings.push({
          rawId: 'cors-origin-reflection-credentials',
          title: `CORS reflects arbitrary Origin with credentials enabled (${new URL(page.url).pathname})`,
          category: 'A02',
          cwe: 942,
          severity: 'high',
          confidence: 'high',
          status: 'confirmed',
          asset: ctx.target.origin,
          locator: new URL(page.url).pathname,
          evidence: [{
            kind: 'http',
            request: { method: 'GET', url: page.url, headers: { origin: foreignOrigin } },
            response: {
              status: res.status,
              headers: {
                'access-control-allow-origin': foreignOrigin,
                'access-control-allow-credentials': 'true',
              },
            },
            observation: 'Foreign Origin echoed back with Access-Control-Allow-Credentials: true',
          }],
          explanation:
            'The endpoint reflects an attacker-chosen Origin and allows credentialed requests from it, ' +
            "so any website can read authenticated responses from this origin in a victim's browser " +
            '(CWE-942, permissive cross-origin policy with credentials).',
          remediation:
            'Do not reflect the Origin header; maintain an allow-list of trusted origins and emit only ' +
            'those values, and avoid Access-Control-Allow-Credentials for anything not strictly requiring it.',
          references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
        });
      } else if (acao.trim() === '*' && (page.headers['access-control-allow-credentials'] ?? '').toLowerCase() === 'true') {
        findings.push({
          rawId: 'cors-wildcard-credentials',
          title: `CORS wildcard origin combined with credentials header (${new URL(page.url).pathname})`,
          category: 'A02',
          cwe: 942,
          severity: 'low',
          confidence: 'high',
          status: 'confirmed',
          asset: ctx.target.origin,
          locator: new URL(page.url).pathname,
          evidence: [{
            kind: 'http',
            request: { method: 'GET', url: page.url, headers: {} },
            response: { status: res.status, headers: { 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' } },
            observation: 'ACAO:* observed together with Allow-Credentials: true (invalid combination per fetch spec)',
          }],
          explanation:
            'Wildcard CORS with credentials is an invalid combination that browsers refuse; its presence ' +
            'indicates misconfigured CORS middleware. Some clients/workers bypass the refusal, so the ' +
            'configuration should be corrected regardless.',
          remediation: 'Remove the credentials header or use an explicit origin allow-list.',
          references: ['https://fetch.spec.whatwg.org/#http-access-control-allow-origin'],
        });
      }
    }
    return findings;
  }

  /** JWT observation (passive): decode tokens found in bodies/cookies; flag alg=none and missing expiry. */
  private jwtFindings(ctx: ScanContext, page: CrawlPage): RawFinding[] {
    const findings: RawFinding[] = [];
    const tokenRe = /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\b/g;
    const tokens = new Set<string>();
    let m: RegExpExecArray | null;
    while ((m = tokenRe.exec(page.body)) !== null && tokens.size < 3) tokens.add(m[0]);
    const cookieValue = page.headers['set-cookie'] ?? '';
    const cm = tokenRe.exec(cookieValue);
    if (cm) tokens.add(cm[0]);
    for (const token of tokens) {
      let header: { alg?: string } = {};
      let payload: Record<string, unknown> = {};
      try {
        const [h, p] = token.split('.');
        header = JSON.parse(Buffer.from(h!, 'base64url').toString('utf8')) as { alg?: string };
        payload = JSON.parse(Buffer.from(p!, 'base64url').toString('utf8')) as Record<string, unknown>;
      } catch { continue; }
      const redactedToken = `${token.split('.')[0]}.[REDACTED-PAYLOAD].[REDACTED-SIGNATURE]`;
      if (String(header.alg ?? '').toLowerCase() === 'none') {
        findings.push({
          rawId: 'jwt-alg-none-observed',
          title: 'JWT observed with alg=none (unsigned token)',
          category: 'A04',
          cwe: 347,
          severity: 'high',
          confidence: 'medium',
          status: 'probable',
          asset: ctx.target.origin,
          locator: new URL(page.url).pathname,
          evidence: [{
            kind: 'http',
            request: { method: 'GET', url: page.url, headers: {} },
            response: { status: page.status, headers: {}, bodyExcerpt: `token: ${redactedToken} (header claims alg=none)` },
            observation: 'A JWT with alg "none" was served by the application — unsigned tokens must never be trusted for security decisions',
          }],
          explanation:
            'The application served a JWT whose header declares alg=none, i.e. no signature. If the server ' +
            'accepts such tokens for security decisions, anyone can forge identities. The platform observed ' +
            'the token being served (probable): confirming exploitation requires submitting a forged token, ' +
            'which the platform does not do.',
          remediation:
            'Reject alg=none server-side; pin the expected algorithm(s) at verification; rotate any keys if unsigned tokens were accepted.',
          references: ['https://datatracker.ietf.org/doc/html/rfc8725#name-algorithm-verification'],
        });
      }
      if (payload.exp === undefined && (header.alg !== undefined)) {
        findings.push({
          rawId: 'jwt-missing-exp-observed',
          title: 'JWT observed without expiration claim (exp)',
          category: 'A07',
          cwe: 613,
          severity: 'low',
          confidence: 'medium',
          status: 'probable',
          asset: ctx.target.origin,
          locator: new URL(page.url).pathname,
          evidence: [{
            kind: 'http',
            request: { method: 'GET', url: page.url, headers: {} },
            response: { status: page.status, headers: {}, bodyExcerpt: `token header alg=${String(header.alg ?? '?')}; payload claims: ${Object.keys(payload).join(', ') || 'none'} (values redacted)` },
            observation: 'Served JWT payload carries no exp claim — token lifetime cannot be enforced by expiry',
          }],
          explanation:
            'A JWT served by the application contains no expiration claim. Tokens without exp remain valid ' +
            'indefinitely unless separately revoked (CWE-613 insufficient session expiration family).',
          remediation: 'Include a short-lived exp claim on every token and enforce it during verification.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html'],
        });
      }
    }
    return findings;
  }

  /** Sensitive data in query strings (passive, CWE-598). */
  private sensitiveUrlFindings(ctx: ScanContext, page: CrawlPage): RawFinding[] {
    const u = new URL(page.url);
    const sensitiveParam = [...u.searchParams.keys()].find((k) =>
      /(password|passwd|secret|token|apikey|api[_-]?key|session|auth|credential)/i.test(k),
    );
    if (!sensitiveParam || u.searchParams.get(sensitiveParam) === '') return [];
    return [{
      rawId: 'sensitive-data-in-url',
      title: `Sensitive-looking parameter "${sensitiveParam}" passed in the URL query string`,
      category: 'A01',
      cwe: 598,
      severity: 'medium',
      confidence: 'medium',
      status: 'probable',
      asset: ctx.target.origin,
      locator: `${u.pathname}?${sensitiveParam}=`,
      evidence: [{
        kind: 'http',
        request: { method: 'GET', url: `${u.origin}${u.pathname}?${sensitiveParam}=[REDACTED]`, headers: {} },
        response: { status: page.status, headers: {} },
        observation: `Query parameter "${sensitiveParam}" carries a value through the URL (browser history, referer headers, proxy logs)`,
      }],
      explanation:
        'Values passed in URL query strings leak into browser history, Referer headers and intermediary ' +
        'logs (CWE-598). If the parameter carries session or credential material this becomes credential ' +
        "exposure; the platform cannot verify the value's sensitivity, hence probable.",
      remediation: 'Transmit sensitive values in the request body over TLS or in headers; never in URLs.',
      references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README'],
    }];
  }

  /**
   * SRI check, aggregated by ROOT CAUSE (spec §16.1): one finding per unique
   * external script URL, with the affected pages as evidence — not one finding
   * per page. The same template loading an unshielded script on 28 pages is
   * one remediation item, not 28.
   */
  /**
   * CSP quality (passive): a present-but-weak CSP is a real configuration
   * weakness — unsafe-inline/unsafe-eval in script sources negate most of
   * the XSS protection CSP exists to provide.
   */
  private cspQualityFindings(ctx: ScanContext, pages: CrawlPage[]): RawFinding[] {
    const seen = new Set<string>();
    const findings: RawFinding[] = [];
    for (const page of pages) {
      const csp = page.headers['content-security-policy'];
      if (!csp || page.status >= 400) continue;
      const lower = csp.toLowerCase();
      const problems: string[] = [];
      const scriptSrc = /script-src([^;]*)/.exec(lower)?.[1] ?? lower;
      if (scriptSrc.includes('unsafe-inline') && scriptSrc.includes('unsafe-eval')) {
        problems.push("'unsafe-inline' and 'unsafe-eval' allowed in script sources");
      } else if (scriptSrc.includes('unsafe-inline')) {
        problems.push("'unsafe-inline' allowed in script sources");
      } else if (scriptSrc.includes('unsafe-eval')) {
        problems.push("'unsafe-eval' allowed in script sources");
      }
      if (/object-src[^;]*(\*|$)/.test(lower) && !/object-src[^;]*'none'/.test(lower)) {
        problems.push("object-src is permissive (not 'none')");
      }
      const key = problems.sort().join('|');
      if (problems.length === 0 || seen.has(key)) continue;
      seen.add(key);
      findings.push({
        rawId: 'csp-weak-directives',
        title: `Weak Content-Security-Policy: ${problems.join('; ')}`,
        category: 'A02',
        cwe: 79,
        severity: 'medium',
        confidence: 'high',
        status: 'confirmed',
        asset: ctx.target.origin,
        locator: new URL(page.url).pathname,
        evidence: [{
          kind: 'http',
          request: { method: 'GET', url: page.url, headers: {} },
          response: { status: page.status, headers: { 'content-security-policy': csp.slice(0, 300) } },
          observation: `CSP observed with weak directives: ${problems.join('; ')}`,
        }],
        explanation:
          'A Content-Security-Policy is present but weakened: ' + problems.join('; ') + '. These directives ' +
          'allow inline script execution and/or eval(), which negates most of the XSS protection CSP exists ' +
          'to provide. The header gives a false sense of protection while a compromised template or injected ' +
          'script can still execute.',
        remediation:
          "Remove 'unsafe-inline' and 'unsafe-eval' from script-src (use nonces or hashes for required inline " +
          "scripts), set object-src 'none', and iterate with report-only mode before enforcing.",
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'],
      });
    }
    return findings;
  }

  /** HSTS absence on HTTPS targets (passive, deterministic absence observation). */
  private hstsFindings(ctx: ScanContext, pages: CrawlPage[], publicHost: boolean): RawFinding[] {
    const isHttps = new URL(ctx.target.origin).protocol === 'https:';
    if (!isHttps) return [];
    const root = pages.find((p) => new URL(p.url).pathname === '/') ?? pages[0];
    if (!root || root.status >= 400) return [];
    if (root.headers['strict-transport-security'] !== undefined) return [];
    return [{
      rawId: 'hsts-missing',
      title: 'Strict-Transport-Security (HSTS) header not set',
      category: 'A04',
      cwe: 319,
      severity: publicHost ? 'medium' : 'low',
      confidence: 'high',
      status: 'confirmed',
      asset: ctx.target.origin,
      locator: '/',
      evidence: [{
        kind: 'http',
        request: { method: 'GET', url: root.url, headers: {} },
        response: { status: root.status, headers: {} },
        observation: 'HTTPS response observed without a Strict-Transport-Security header',
      }],
      explanation:
        'The site is served over HTTPS but does not send Strict-Transport-Security. A user who types the ' +
        'bare hostname (or follows an http:// link) can be downgraded to cleartext on the first request, ' +
        'exposing cookies and content to interception (CWE-319 family).',
      remediation: "Send Strict-Transport-Security: max-age=31536000; includeSubDomains (add 'preload' only after subdomain review).",
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html'],
    }];
  }

  /**
   * Frontend secret scanning (spec section 4): fetches a bounded set of JavaScript
   * bundles discovered in the crawl and scans them for high-signal secret
   * patterns. Values are redacted; matches are probable pending verification.
   */
  private async jsBundleSecretFindings(ctx: ScanContext, pages: CrawlPage[]): Promise<RawFinding[]> {
    const originHost = new URL(ctx.target.origin).hostname;
    const bundles = new Set<string>();
    for (const page of pages) {
      const re = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;
      let m: RegExpExecArray | null;
      while ((m = re.exec(page.body)) !== null && bundles.size < 8) {
        try {
          const u = new URL(m[1]!, page.url);
          if (u.hostname !== originHost) continue; // third-party vendor bundles are covered by SRI findings
          if (u.pathname.endsWith('.js')) bundles.add(u.toString());
        } catch { /* skip malformed */ }
      }
    }

    const patterns: Array<[RegExp, string]> = [
      [/\bAKIA[0-9A-Z]{16}\b/, 'AWS access key id'],
      [/\bAIza[0-9A-Za-z_-]{35}\b/, 'Google API key'],
      [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/, 'GitHub token'],
      [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'private key material'],
      [/["'](api[_-]?key|apikey|secret|access[_-]?token)["']\s*[:=]\s*["'][A-Za-z0-9+/_-]{16,}["']/i, 'credential-like assignment'],
    ];

    const findings: RawFinding[] = [];
    let fetched = 0;
    for (const bundleUrl of bundles) {
      if (fetched >= 8 || ctx.signal.aborted) break;
      fetched++;
      const res = await ctx.client.get(bundleUrl);
      if (!res.ok || res.status !== 200) continue;
      const hits = new Map<string, { what: string; excerpt: string }>();
      for (const [re, what] of patterns) {
        if (hits.has(what)) continue;
        const m = re.exec(res.body);
        if (m) hits.set(what, { what, excerpt: res.body.slice(Math.max(0, m.index - 40), m.index + 60) });
      }
      for (const { what, excerpt } of hits.values()) {
        findings.push({
          rawId: 'js-bundle-secret',
          title: `Potential ${what} in served JavaScript bundle`,
          category: 'A07',
          cwe: 798,
          severity: 'high',
          confidence: 'medium',
          status: 'probable',
          asset: ctx.target.origin,
          locator: new URL(bundleUrl).pathname,
          evidence: [{
            kind: 'http',
            request: { method: 'GET', url: bundleUrl, headers: {} },
            response: { status: res.status, headers: { 'content-type': res.headers['content-type'] ?? '' }, bodyExcerpt: redactText(excerpt, 200) },
            observation: `Pattern for ${what} matched in the served bundle (value redacted)`,
          }],
          explanation:
            'The served JavaScript bundle contains a string matching a secret pattern. Frontend code is ' +
            'readable by every visitor, so anything embedded there is disclosed (CWE-798). Matches are ' +
            'probable: test/placeholder values and public client identifiers can false-positive — verify ' +
            'the value before treating it as a real credential.',
          remediation:
            'If real: rotate the credential, remove it from the bundle and history, move the call server-side ' +
            'or use a token-exchange flow. If a placeholder: restructure the constant so scanners and reviewers ' +
            'can tell it is not a secret.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
        });
      }
    }
    return findings;
  }

  /**
   * CSRF exposure (passive, heuristic): state-changing POST forms rendered
   * without any visible anti-CSRF token field, combined with a session cookie
   * lacking SameSite. Server-side token validation cannot be observed — hence
   * probable, not confirmed.
   */
  private csrfFindings(ctx: ScanContext, pages: CrawlPage[]): RawFinding[] {
    const sessionLacksSameSite = pages.some((p) => {
      const sc = p.headers['set-cookie'] ?? '';
      return /session|auth|token/i.test(sc) && !/samesite/i.test(sc);
    });
    if (!sessionLacksSameSite) return [];
    const tokenRe = /csrf|_token|authenticity|xsrf|anticsrf/i;
    const findings: RawFinding[] = [];
    const seen = new Set<string>();
    for (const page of pages) {
      for (const form of page.forms) {
        if (seen.has(form.action) || findings.length >= 5) continue;
        if (form.method !== 'post') continue;
        const u = new URL(form.action);
        if (u.origin !== new URL(page.url).origin) continue; // off-site forms (payment gateways etc.) are out of scope
        // token presence is inferred from the form body the crawler captured
        const bodyHasToken = tokenRe.test(page.body.slice(0, page.body.indexOf(form.action) + 2000));
        if (bodyHasToken) continue;
        seen.add(form.action);
        findings.push({
          rawId: 'csrf-exposure',
          title: `State-changing form without visible CSRF protection: ${new URL(form.action).pathname}`,
          category: 'A01',
          cwe: 352,
          severity: 'medium',
          confidence: 'medium',
          status: 'probable',
          asset: ctx.target.origin,
          locator: new URL(form.action).pathname,
          evidence: [{
            kind: 'http',
            request: { method: 'GET', url: page.url, headers: {} },
            response: { status: page.status, headers: {}, bodyExcerpt: `form action=${form.action} fields=${form.fields.join(',')}` },
            observation: 'POST form with no token-like hidden field observed; session cookie also lacks SameSite',
          }],
          explanation:
            'A same-origin POST form was served without any anti-CSRF token field, and the session cookie             lacks the SameSite attribute — the exact combination a cross-site request forgery needs (CWE-352).             Probable: the platform can only observe form markup; server-side token validation or custom             header requirements cannot be ruled out from markup alone.',
          remediation:
            'Add an unpredictable per-session token to every state-changing form and verify it server-side;             additionally set SameSite on session cookies as defense in depth.',
          references: ["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
        });
      }
    }
    return findings;
  }

  /** Mixed content (passive): HTTPS pages loading http:// subresources (CWE-311). */
  private mixedContentFindings(ctx: ScanContext, pages: CrawlPage[]): RawFinding[] {
    const findings: RawFinding[] = [];
    const seen = new Set<string>();
    for (const page of pages) {
      if (new URL(page.url).protocol !== 'https:' || page.status >= 400) continue;
      const subRe = /<(script|iframe|object|embed|img|source)\b[^>]*\b(?:src|data)\s*=\s*["'](http:\/\/[^"']+)["']/gi;
      let m: RegExpExecArray | null;
      const hits = new Set<string>();
      while ((m = subRe.exec(page.body)) !== null && hits.size < 5) {
        hits.add(`${m[1]}:${m[2]}`);
      }
      if (hits.size === 0 || seen.has(page.url)) continue;
      seen.add(page.url);
      const first = [...hits][0]!;
      findings.push({
        rawId: 'mixed-content',
        title: `Mixed content: ${hits.size} http:// subresource(s) on an HTTPS page`,
        category: 'A04',
        cwe: 311,
        severity: 'medium',
        confidence: 'high',
        status: 'confirmed',
        asset: ctx.target.origin,
        locator: new URL(page.url).pathname,
        evidence: [{
          kind: 'http',
          request: { method: 'GET', url: page.url, headers: {} },
          response: { status: page.status, headers: {}, bodyExcerpt: first.slice(0, 200) },
          observation: `HTTPS page loads cleartext subresources (${hits.size} found, e.g. ${first})`,
        }],
        explanation:
          'The HTTPS page loads subresources over unencrypted HTTP. Browsers block active mixed content ' +
          '(scripts) but images and other passive content still load in cleartext and can be substituted or ' +
          "observed in transit (CWE-311). Any cleartext subresource also undermines the page's security context.",
        remediation: "Load every subresource over HTTPS (or protocol-relative bundled assets); add a CSP upgrade-insecure-requests directive as a bridge.",
        references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content'],
      });
    }
    return findings;
  }

  /**
   * JS library version fingerprinting (passive): version-bearing CDN URLs are
   * matched against a small curated advisory list of well-known XSS/prototype-
   * pollution CVEs. Version is deterministic from the URL; exploitability is
   * a review question.
   */
  private libraryVersionFindings(ctx: ScanContext, pages: CrawlPage[]): RawFinding[] {
    const advisories: Array<{ lib: string; re: RegExp; cve: string; fixed: string; at: (v: string) => boolean }> = [
      { lib: 'jQuery', re: /jquery[/\\-]?(\d+\.\d+)(\.\d+)?(?:\.min)?\.js/i, cve: 'CVE-2020-11022', fixed: '3.5.0', at: (v: string) => cmp(v, '3.5.0') < 0 },
      { lib: 'jQuery', re: /jquery[/\\-]?(\d+\.\d+)(\.\d+)?(?:\.min)?\.js/i, cve: 'CVE-2019-11358', fixed: '3.4.0', at: (v: string) => cmp(v, '3.4.0') < 0 },
      { lib: 'Bootstrap', re: /bootstrap[/\\-]?(\d+\.\d+\.\d+)(?:\.min)?\.js/i, cve: 'CVE-2019-8331', fixed: '4.3.1', at: (v: string) => cmp(v, '4.3.1') < 0 },
    ];
    const found = new Map<string, { lib: string; version: string; cve: string; fixed: string; src: string }>();
    for (const page of pages) {
      const re = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;
      let m: RegExpExecArray | null;
      while ((m = re.exec(page.body)) !== null) {
        const src = m[1]!;
        for (const adv of advisories) {
          const vm = adv.re.exec(src);
          if (!vm) continue;
          const version = vm[1] + (vm[2] ?? '');
          if (!adv.at(version)) continue;
          const key = `${adv.lib}:${version}:${adv.cve}`;
          if (!found.has(key)) found.set(key, { lib: adv.lib, version, cve: adv.cve, fixed: adv.fixed, src });
        }
      }
    }
    const findings: RawFinding[] = [];
    for (const { lib, version, cve, fixed, src } of found.values()) {
      findings.push({
        rawId: 'js-library-known-vulnerability',
        title: `Vulnerable ${lib} version ${version} loaded (${cve})`,
        category: 'A03',
        cwe: 1104,
        severity: 'medium',
        confidence: 'high',
        status: 'confirmed',
        asset: ctx.target.origin,
        locator: src.slice(0, 160),
        evidence: [{
          kind: 'http',
          request: { method: 'GET', url: src, headers: {} },
          response: { status: 200, headers: {}, bodyExcerpt: `script src=${src}` },
          observation: `Version ${version} parsed from the URL; ${cve} affects versions fixed in ${fixed}`,
        }],
        explanation:
          'A frontend library with a published vulnerability is loaded at a vulnerable version (version read ' +
          'directly from its URL). ' + cve + ' is fixed in ' + fixed + '. Whether the vulnerable code path is ' +
          'actually exercised depends on usage — the version match is deterministic, exploitability needs review.',
        remediation: `Upgrade ${lib} to ${fixed} or later and verify no code depends on the vulnerable behavior.`,
        references: ['https://owasp.org/Top10/2025/en/A03_2025-Software_Supply_Chain_Failures/'],
      });
    }
    return findings;

    function cmp(a: string, b: string): number {
      const pa = a.split('.').map(Number);
      const pb = b.split('.').map(Number);
      for (let i = 0; i < 3; i++) {
        const d = (pa[i] ?? 0) - (pb[i] ?? 0);
        if (d !== 0) return d;
      }
      return 0;
    }
  }

  private sriFindings(ctx: ScanContext, pages: CrawlPage[]): RawFinding[] {
    const originHost = new URL(ctx.target.origin).hostname;
    const scriptRe = /<script\b[^>]*\bsrc\s*=\s*["'](https?:\/\/[^"']+)["'][^>]*>/gi;
    // script URL → affected pages (bounded evidence per script)
    const unshielded = new Map<string, { host: string; pages: string[]; tag: string }>();
    for (const page of pages) {
      if (page.status >= 400) continue;
      let m: RegExpExecArray | null;
      const seen = new Set<string>();
      while ((m = scriptRe.exec(page.body)) !== null) {
        const tag = m[0];
        const src = m[1]!;
        if (seen.has(src)) continue;
        seen.add(src);
        let host: string;
        try { host = new URL(src).hostname; } catch { continue; }
        if (host === originHost) continue; // same-origin scripts do not need SRI
        if (/\bintegrity\s*=/i.test(tag)) continue;
        const entry = unshielded.get(src) ?? { host, pages: [], tag };
        if (entry.pages.length < 3) entry.pages.push(new URL(page.url).pathname);
        unshielded.set(src, entry);
      }
    }

    const findings: RawFinding[] = [];
    for (const [src, entry] of [...unshielded.entries()].sort().slice(0, 20)) {
      let locator = src;
      try { locator = new URL(src).pathname; } catch { /* keep full URL */ }
      findings.push({
        rawId: 'sri-external-script',
        title: `External script loaded without Subresource Integrity: ${entry.host}${entry.pages.length > 1 ? ` (${entry.pages.length}+ pages)` : ''}`,
        category: 'A08',
        cwe: 829,
        severity: 'medium',
        confidence: 'high',
        status: 'confirmed',
        asset: ctx.target.origin,
        locator,
        evidence: entry.pages.map((p) => ({
          kind: 'http' as const,
          request: { method: 'GET', url: src, headers: {} },
          response: { status: 200, headers: {}, bodyExcerpt: entry.tag.slice(0, 300) },
          observation: `Cross-origin script ${src} served without an integrity attribute on ${p} (deduplicated root-cause evidence)`,
        })),
        explanation:
          'The site loads JavaScript from this third-party origin without a Subresource Integrity ' +
          'attribute on ' + entry.pages.length + ' or more observed pages (root-cause deduplicated: one ' +
          'template fix remediates all occurrences). If that third party or its CDN is compromised, the ' +
          "served script executes in this application's origin — a software/data integrity failure (CWE-829). " +
          'The observation is deterministic; whether the third party is trustworthy is a review question.',
        remediation:
          'Add an integrity="sha384-…" attribute (hash of the exact script content) plus crossorigin="anonymous", ' +
          'or self-host the script so it is covered by your own deployment controls.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'],
      });
    }
    return findings;
  }

  private cleartextFindings(ctx: ScanContext, pages: CrawlPage[], publicHost: boolean): RawFinding[] {
    const findings: RawFinding[] = [];
    for (const page of pages) {
      const u = new URL(page.url);
      if (u.protocol !== 'http:') continue;
      const hasPassword = page.forms.some((f) => f.hasPasswordField) ||
        /<input[^>]*type\s*=\s*["']password["']/i.test(page.body);
      if (!hasPassword) continue;
      findings.push({
        rawId: 'cleartext-credential-form',
        title: 'Cleartext HTTP used to serve a credential-bearing form',
        category: 'A04',
        cwe: 319,
        severity: publicHost ? 'high' : 'low',
        confidence: 'high',
        status: publicHost ? 'confirmed' : 'informational',
        asset: ctx.target.origin,
        locator: new URL(page.url).pathname,
        evidence: [{
          kind: 'http',
          request: { method: 'GET', url: page.url, headers: {} },
          response: { status: page.status, headers: {}, bodyExcerpt: '<input … type="password" … (form served over http://)' },
          observation: `Form with password input served over cleartext http:// at ${page.url}`,
        }],
        explanation:
          'The login form is delivered over unencrypted HTTP, so submitted credentials travel ' +
          'in cleartext and can be intercepted on the network (CWE-319, cleartext ' +
          'transmission of sensitive information; OWASP Top 10:2025 A04). On loopback/private ' +
          'lab targets this is recorded as informational because exposure depends on network ' +
          'context the platform cannot observe.',
        remediation: 'Serve the application over TLS (HTTPS) and redirect all HTTP traffic; set HSTS once TLS is stable.',
        references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
      });
      break; // one observation is enough
    }
    return findings;
  }
}

function flagImplications(missingFlags: string[]): string {
  const implications: string[] = [];
  if (missingFlags.includes('HttpOnly')) {
    implications.push('Without HttpOnly the cookie is readable by JavaScript, increasing the impact of any XSS.');
  }
  if (missingFlags.includes('Secure')) {
    implications.push('Without Secure the cookie may be transmitted over cleartext HTTP.');
  }
  if (missingFlags.includes('SameSite')) {
    implications.push('Without SameSite the cookie is sent on cross-site requests, exposing it to CSRF.');
  }
  return implications.join(' ');
}

/** Build redacted HTTP evidence from a crawled page. */
export function pageEvidence(page: CrawlPage): HttpEvidence {
  return {
    kind: 'http',
    request: { method: 'GET', url: page.url, headers: {} },
    response: {
      status: page.status,
      headers: {},
      bodyExcerpt: page.body.slice(0, 300),
    },
    observation: `GET ${page.url} → ${page.status}`,
  };
}
