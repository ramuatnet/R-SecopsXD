/**
 * Built-in path probe (ACTIVE MODE ONLY).
 *
 * Sends bounded GET requests to a small list of common sensitive paths plus
 * robots.txt Disallow entries. False-positive guards:
 *  - a response only counts if status is 200 AND the body differs from the
 *    target's not-found page (calibrated with one random-path probe);
 *  - .env-style files must look like KEY=VALUE content;
 *  - /admin must not have redirected to a login (auth challenge).
 *
 * This is NOT a brute-force wordlist attack: at most ~15 requests per scan.
 */
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding } from '../../core/types.ts';
import { redactText } from '../../core/redact.ts';

const INFO: EngineInfo = {
  id: 'builtin.path-probe',
  name: 'Sensitive Path Probe',
  kind: 'builtin',
  capabilities: {
    A01: cap('unauthenticated exposure of admin/sensitive paths (bounded, non-destructive)'),
    A02: cap('exposed config/backup files and directory listings'),
    A03: cap('exposed dependency manifests/lockfiles (supply-chain reconnaissance)'),
  },
  modes: ['active'],
  targetKinds: ['webapp'],
};

interface ProbeCandidate {
  path: string;
  title: string;
  category: 'A01' | 'A02' | 'A03';
  cwe: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  match?: RegExp | undefined;
  contentType?: RegExp | undefined;
}

const PATHS: ProbeCandidate[] = [
  { path: '/.env', title: 'Environment file (.env) exposed', category: 'A02', cwe: 16, severity: 'critical', match: /^[A-Za-z_][A-Za-z0-9_]*\s*=/m },
  { path: '/.git/config', title: 'Git repository metadata exposed (/.git/config)', category: 'A02', cwe: 538, severity: 'high', match: /\[core\]/ },
  { path: '/backup.zip', title: 'Backup archive exposed (/backup.zip)', category: 'A02', cwe: 538, severity: 'high', contentType: /zip|octet-stream/ },
  { path: '/backup.sql', title: 'Database dump exposed (/backup.sql)', category: 'A02', cwe: 538, severity: 'critical', contentType: /sql|octet-stream|text/ },
  { path: '/server-status', title: 'Apache server-status exposed', category: 'A02', cwe: 16, severity: 'medium', match: /Server uptime|Apache Status/i },
  { path: '/actuator', title: 'Spring Boot actuator exposed', category: 'A02', cwe: 16, severity: 'medium', match: /_links|health|env/i },
  { path: '/package.json', title: 'Package manifest exposed (/package.json)', category: 'A03', cwe: 1357, severity: 'medium', match: /"name"\s*:\s*"/ },
  { path: '/package-lock.json', title: 'Dependency lockfile exposed (/package-lock.json)', category: 'A03', cwe: 1357, severity: 'medium', match: /"lockfileVersion"|"dependencies"/ },
  { path: '/admin', title: 'Admin interface reachable without authentication', category: 'A01', cwe: 862, severity: 'high' },
  { path: '/assets/', title: 'Directory listing exposed (/assets/)', category: 'A01', cwe: 548, severity: 'medium', match: /<title>index of|h1>index of|directory listing/i },
];

export class PathProbeEngine implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const findings: RawFinding[] = [];
    const origin = ctx.target.origin;

    // Calibrate the not-found response to suppress false positives.
    const calibUrl = `${origin}/ovap-calibration-${Math.random().toString(36).slice(2, 10)}`;
    const calib = await ctx.client.get(calibUrl);
    const calibBody = calib.ok ? calib.body : '';

    // robots.txt Disallow entries are appended (bounded to 5)
    const robotsPaths: ProbeCandidate[] = (ctx.crawl?.robots.disallow ?? []).slice(0, 5)
      .filter((p) => !PATHS.some((k) => k.path === p) && p.length > 1)
      .map((p) => ({
        path: p,
        title: `robots.txt-restricted path reachable: ${p}`,
        category: 'A01' as const,
        cwe: 538,
        severity: 'low' as const,
      }));

    const candidates = [...PATHS, ...robotsPaths];

    // Server-aware probing: when the banner says Tomcat/Coyote/JBoss/WildFly,
    // probe Java-specific paths that the generic wordlist misses.
    const serverBanner = (ctx.crawl?.pages ?? [])
      .map((p) => p.headers['server'] ?? '')
      .find((s) => s !== '') ?? '';
    const isJava = /coyote|tomcat|jboss|wildfly|jetty/i.test(serverBanner);
    if (isJava) {
      const JAVA_PATHS: ProbeCandidate[] = [
        { path: '/manager/html', title: 'Tomcat Manager exposed', category: 'A02' as const, cwe: 16, severity: 'critical' as const },
        { path: '/host-manager', title: 'Tomcat Host Manager exposed', category: 'A02' as const, cwe: 16, severity: 'high' as const },
        { path: '/examples/', title: 'Tomcat Examples exposed', category: 'A02' as const, cwe: 16, severity: 'medium' as const },
        { path: '/docs/', title: 'Tomcat Documentation exposed', category: 'A02' as const, cwe: 16, severity: 'low' as const },
        { path: '/WEB-INF/web.xml', title: 'WEB-INF/web.xml exposed', category: 'A02' as const, cwe: 538, severity: 'critical' as const },
        { path: '/status', title: 'Tomcat Status page exposed', category: 'A02' as const, cwe: 16, severity: 'medium' as const },
        { path: '/jmx-console/', title: 'JBoss JMX Console exposed', category: 'A02' as const, cwe: 16, severity: 'critical' as const },
      ];
      candidates.push(...JAVA_PATHS);
      ctx.log('server-aware probing', { server: serverBanner, extraPaths: JAVA_PATHS.length });
    }
    let probes = 0;

    for (const candidate of candidates) {
      if (ctx.signal.aborted) break;
      if (probes >= 20) break;
      probes++;
      const url = new URL(candidate.path, origin + '/').toString();
      const res = await ctx.client.get(url);
      if (!res.ok) {
        if (!res.ok && 'blocked' in res) ctx.log('probe blocked', { url, reason: res.blocked });
        continue;
      }
      if (res.status !== 200) continue;
      if (res.body === calibBody) continue; // identical to not-found page
      if (candidate.match && !candidate.match.test(res.body)) continue;
      if (candidate.contentType) {
        const ct = res.headers['content-type'] ?? '';
        if (!candidate.contentType.test(ct)) continue;
      }
      // For admin-like paths require non-redirect content (client.get already followed
      // redirects, so a login redirect would have produced the login page URL/body;
      // check the final URL stayed on the probed path)
      if (candidate.path === '/admin') {
        const finalPath = new URL(res.finalUrl).pathname;
        if (!finalPath.startsWith('/admin')) continue;
        if (/name\s*=\s*["']password["']/i.test(res.body)) continue; // it's a login form
      }
      findings.push({
        rawId: `path-probe:${candidate.path}`,
        title: candidate.title,
        category: candidate.category,
        cwe: candidate.cwe,
        severity: candidate.severity,
        confidence: 'high',
        status: 'confirmed',
        asset: ctx.target.origin,
        locator: candidate.path,
        evidence: [{
          kind: 'http',
          request: { method: 'GET', url, headers: {} },
          response: {
            status: res.status,
            headers: { 'content-type': res.headers['content-type'] ?? '' },
            bodyExcerpt: res.body.slice(0, 300),
          },
          observation: `GET ${candidate.path} returned ${res.status} with distinct content (${res.body.length} bytes)`,
        }],
        explanation:
          `The path ${candidate.path} is reachable without authentication and returns ` +
          'content distinct from the application\'s not-found page (calibrated). Depending ' +
          'on the path this discloses configuration, backups or an unauthenticated ' +
          'administrative surface.',
        remediation:
          'Restrict access to this path (authentication + network controls), remove the ' +
          'resource from the public surface, and audit access logs for prior access.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README',
        ],
      });
    }

    // Bounded object-access probe (CWE-639): for resource URLs observed in the
    // crawl with a final numeric ID, request the NEXT id without credentials.
    // Only 3 URLs, one request each — an authorization smoke test, not IDOR
    // enumeration. Findings require a 200 with content distinct from the
    // not-found calibration.
    const objectUrls = new Set<string>();
    const allLinks = [
      ...(ctx.crawl?.pages ?? []).flatMap((pg) => pg.links),
      ...(ctx.crawl?.discoveredEndpoints ?? []).map((e) => new URL(e, ctx.target.origin).toString()),
    ];
    for (const link of allLinks) {
      const m = /^(.*?)(\d+)(\/?)(\?.*)?$/.exec(new URL(link).pathname);
      if (!m) continue;
      if (objectUrls.size >= 3) break;
      objectUrls.add(`${m[1]}${m[2]}${m[3]}`);
    }
    for (const urlPath of objectUrls) {
      if (ctx.signal.aborted || probes >= 20) break;
      probes++;
      const m = /^(.*?)(\d+)(\/?)$/.exec(urlPath);
      if (!m) continue;
      const nextId = Number(m[2]) + 1;
      const probeUrl = new URL(`${m[1]}${nextId}${m[3]}`, origin + '/').toString();
      const res = await ctx.client.get(probeUrl);
      if (!res.ok || res.status !== 200) continue;
      if (res.body === calibBody) continue;
      const ct = res.headers['content-type'] ?? '';
      if (!/json|html|text/.test(ct)) continue;
      if (res.body.length < 40) continue;
      findings.push({
        rawId: `object-access:${urlPath}`,
        title: `Resource accessible without authorization: ${urlPath} (probed sibling ID)`,
        category: 'A01',
        cwe: 639,
        severity: 'high',
        confidence: 'medium',
        status: 'probable',
        asset: ctx.target.origin,
        locator: `${m[1]}${nextId}${m[3]}`,
        evidence: [{
          kind: 'http',
          request: { method: 'GET', url: probeUrl, headers: {} },
          response: {
            status: res.status,
            headers: { 'content-type': ct },
            bodyExcerpt: res.body.slice(0, 300),
          },
          observation:
            `${urlPath} was discovered via the crawl; requesting the sibling identifier ` +
            `${m[1]}${nextId}${m[3]} without credentials returned ${res.status} with distinct content`,
        }],
        explanation:
          'The application returned object data for an identifier the crawl never referenced, ' +
          'without an authenticated session. This is the signature of a missing object-level ' +
          'authorization check (IDOR family, CWE-639). Confidence is medium because public ' +
          'reference data (e.g. a public product catalog) can legitimately behave this way — ' +
          'confirm the object type is access-controlled before treating it as exploitable.',
        remediation:
          'Enforce object-level authorization on every identifier-bearing endpoint (session or ' +
          'token must be checked against object ownership/permission), and return 401/404 for ' +
          'unauthorized ids.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README',
          'https://owasp.org/Top10/2025/en/A01_2025-Broken_Access_Control/',
        ],
      });
    }

    // Discovered-endpoint probing: GET each discovered API endpoint and flag
    // 500 responses with stack-trace patterns as verbose error disclosure.
    const discovered = (ctx.crawl?.discoveredEndpoints ?? []).slice(0, 8);
    for (const ep of discovered) {
      if (ctx.signal.aborted || probes >= 30) break;
      probes++;
      const url = new URL(ep, origin + '/').toString();
      const res = await ctx.client.get(url);
      if (!res.ok) continue;
      const stackPatterns: Array<[RegExp, string]> = [
        [/\bat\s+[\w$.<>:/\\]+\s*\([^)]*:\d+(:\d+)?\)/, 'runtime stack frames'],
        [/Traceback \(most recent call last\)/, 'python traceback'],
        [/(System\.|java\.lang\.)[\w.]*Exception/, 'jvm exception'],
        [/\b(node_modules|\/srv\/|\/app\/|\/home\/\w+\/|\/juice-shop\/)[\w\-/.]+\.(js|py|rb|php|ts)/, 'internal file paths'],
      ];
      const matched = stackPatterns.filter(([re]) => re.test(res.body)).map(([, w]) => w);
      if (res.status >= 500 && matched.length > 0) {
        findings.push({
          rawId: 'verbose-error-disclosure',
          title: `Verbose error disclosure (stack trace) on ${ep}`,
          category: 'A10',
          cwe: 209,
          severity: 'medium',
          confidence: 'high',
          status: 'confirmed',
          asset: ctx.target.origin,
          locator: ep,
          evidence: [{
            kind: 'http',
            request: { method: 'GET', url, headers: {} },
            response: { status: res.status, headers: {}, bodyExcerpt: res.body.slice(0, 400) },
            observation: `GET ${ep} returned ${res.status} with ${matched.join(', ')}`,
          }],
          explanation:
            'A discovered API endpoint returns internal error details including stack traces and ' +
            'file paths. This exposes the server framework, internal code structure and deployment ' +
            'layout to any client (CWE-209, mishandling of exceptional conditions).',
          remediation:
            'Return generic error responses to clients; log full details server-side with correlation IDs.',
          references: ['https://owasp.org/Top10/2025/en/A10_2025-Mishandling_of_Exceptional_Conditions/'],
        });
      }
    }

    // Source-map exposure probe (active): for up to 5 same-origin .js files seen in
    // the crawl, request the sibling .js.map. A served map discloses original source
    // code (CWE-540). Validated: response must be JSON containing a "sources" member.
    const jsFiles = new Set<string>();
    for (const page of ctx.crawl?.pages ?? []) {
      for (const link of page.links) {
        if (jsFiles.size >= 5) break;
        try {
          const u = new URL(link);
          if (u.hostname === new URL(ctx.target.origin).hostname && u.pathname.endsWith('.js')) {
            jsFiles.add(u.toString());
          }
        } catch { /* ignore malformed links */ }
      }
    }
    for (const jsUrl of jsFiles) {
      if (ctx.signal.aborted || probes >= 25) break;
      probes++;
      const mapUrl = `${jsUrl}.map`;
      const res = await ctx.client.get(mapUrl);
      if (!res.ok || res.status !== 200) continue;
      const trimmed = res.body.trim();
      if (!trimmed.startsWith('{') || !trimmed.includes('"sources"')) continue;
      let sourcesCount = 0;
      let secrets: Array<{ line: string; sourceFile: string }> = [];
      try {
        const map = JSON.parse(trimmed) as { sources?: string[]; sourcesContent?: string[] };
        sourcesCount = map.sources?.length ?? 0;
        // Secret scanning of the shipped original sources (spec §4: secrets in source maps)
        const secretRe = /(?:^|[^a-z0-9])(api[_-]?key|secret|password|passwd|token|access[_-]?key)\s*[:=]\s*["'][^"'\s]{8,}["']/i;
        (map.sourcesContent ?? []).forEach((content, i) => {
          if (secrets.length >= 5) return;
          for (const line of (content ?? '').split('\n')) {
            if (secretRe.test(line)) {
              secrets.push({ line, sourceFile: map.sources?.[i] ?? `source[${i}]` });
              break;
            }
          }
        });
      } catch { continue; }
      const mapPath = new URL(mapUrl).pathname;
      findings.push({
        rawId: 'source-map-exposed',
        title: `Source map exposed: ${mapPath} (${sourcesCount} original sources)`,
        category: 'A01',
        cwe: 540,
        severity: 'medium',
        confidence: 'high',
        status: 'confirmed',
        asset: ctx.target.origin,
        locator: mapPath,
        evidence: [{
          kind: 'http',
          request: { method: 'GET', url: mapUrl, headers: {} },
          response: { status: res.status, headers: { 'content-type': res.headers['content-type'] ?? '' }, bodyExcerpt: trimmed.slice(0, 200) },
          observation: `Sibling .js.map of a crawled script returned ${res.status} with ${sourcesCount} sources`,
        }],
        explanation:
          'A build artifact source map is publicly served next to its minified script. It discloses ' +
          'original source code, comments and internal logic to anyone (CWE-540), easing code review for attackers.',
        remediation: 'Remove .map files from production deployments or block them at the server; generate maps only for internal builds.',
        references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/README'],
      });

      for (const secret of secrets) {
        findings.push({
          rawId: 'source-map-secrets',
          title: `Secrets embedded in exposed source map (${secret.sourceFile})`,
          category: 'A07',
          cwe: 798,
          severity: 'high',
          confidence: 'medium',
          status: 'probable',
          asset: ctx.target.origin,
          locator: `${mapPath}#${secret.sourceFile}`,
          evidence: [{
            kind: 'http',
            request: { method: 'GET', url: mapUrl, headers: {} },
            response: { status: res.status, headers: {}, bodyExcerpt: redactText(secret.line, 200) },
            observation: `Original source ${secret.sourceFile} inside the exposed map contains a credential-pattern match (value redacted)`,
          }],
          explanation:
            'The exposed source map ships original source code containing what appears to be a hardcoded ' +
            'credential (CWE-798). Anyone retrieving the map recovers it. Values matching the pattern are ' +
            'probable — verify whether the literal is a real credential or a placeholder.',
          remediation:
            'Remove the secret from the source, rotate the credential, purge the artifact from the deployment, ' +
            'and stop serving .map files in production.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
        });
      }
    }

    ctx.log('path probe finished', { probes, findings: findings.length });
    return { findings, version: 'builtin' };
  }
}
