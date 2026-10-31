/**
 * Tests for the compounding batch: JS endpoint discovery, cross-role matrix,
 * rescan diffing.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpServer, type Server } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EndpointDiscoveryEngine, extractEndpoints } from '../../src/engines/builtin/endpointDiscovery.ts';
import { diffScanFindings } from '../../src/scan/diff.ts';
import { Database } from '../../src/db/database.ts';
import { AuthenticatedProbeEngine } from '../../src/engines/builtin/authenticatedProbe.ts';
import { ScopeGuard } from '../../src/safety/guard.ts';
import { RateLimiter } from '../../src/safety/rateLimiter.ts';
import { Semaphore } from '../../src/safety/concurrency.ts';
import { ScopedHttpClient } from '../../src/scan/httpClient.ts';
import { buildPlatform, type Platform } from '../../src/server.ts';
import type { Config } from '../../src/config.ts';
import type { CrawlPage, ScanContext } from '../../src/engines/types.ts';
import type { Finding, Target } from '../../src/core/types.ts';

// ---------- endpoint extraction (pure) ----------

test('extractEndpoints: fetch/axios/url patterns, same-origin filter, asset filter', () => {
  const bundle = [
    'fetch("/api/internal/users")',
    "axios.get('/v2/reports/export')",
    'const base = url = "/api/orders";',
    'fetch("https://cdn.example.com/vendor.js")',
    "fetch('https://other.example/api/steal')",
    "import './util.js'",
    "fetch('#anchor')",
  ].join('\n');
  const endpoints = extractEndpoints(bundle, 'https://app.example.com');
  assert.ok(endpoints.includes('/api/internal/users'), 'fetch pattern');
  assert.ok(endpoints.includes('/v2/reports/export'), 'axios pattern');
  assert.ok(endpoints.includes('/api/orders'), 'url pattern');
  assert.equal(endpoints.filter((e) => e.startsWith('/api/internal')).length, 1, 'deduped');
  assert.ok(!endpoints.some((e) => e.includes('other.example')), 'third-party URLs excluded');
  assert.ok(!endpoints.some((e) => e.endsWith('.js')), 'asset paths excluded');
});

// ---------- endpoint discovery engine (live) ----------

test('endpoint discovery engine populates corpus and emits inventory finding', async () => {
  const server = createHttpServer((req, res) => {
    if (req.url === '/app.js') {
      res.writeHead(200, { 'content-type': 'application/javascript' });
      res.end('fetch("/api/admin/audit-log");\nfetch("/api/orders/12");');
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<script src="/app.js"></script>');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const guard = new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 });
    const client = new ScopedHttpClient(guard, new RateLimiter(100, 50), new Semaphore(4), { timeoutMs: 3000, maxRedirectHops: 2 }, { sent: 0, blocked: 0 });
    const engine = new EndpointDiscoveryEngine();
    const ctx: ScanContext = {
      scanId: 's', target: { id: 't', name: 'x', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() },
      mode: 'passive', client, guard, stats: { sent: 0, blocked: 0 },
      signal: new AbortController().signal, workDir: '.', log: () => {},
      crawl: { pages: [{ url: `${origin}/`, status: 200, truncated: false, headers: {}, body: '<script src="/app.js"></script>', forms: [], links: [] }], robots: { disallow: [], fetched: false } },
    };
    const res = await engine.run(ctx);
    assert.deepEqual(ctx.crawl!.discoveredEndpoints, ['/api/admin/audit-log', '/api/orders/12']);
    const f = res.findings.find((x) => x.rawId === 'undocumented-endpoints-discovered');
    assert.ok(f, 'inventory finding');
    assert.equal(f!.severity, 'info');
  } finally {
    server.close();
  }
});

// ---------- diff ----------

function fakeFinding(fpSeed: string, title: string): Finding {
  return {
    id: `FND-A01-${fpSeed}`, fingerprint: `fp-${fpSeed}`, title,
    category: 'A01', severity: 'medium', confidence: 'high', status: 'confirmed',
    asset: 'a', locator: '/', engine: 'e', evidence: [], explanation: 'x',
    remediation: 'r', references: [], detectedAt: new Date().toISOString(),
    provenance: [{ engine: 'e', adapter: false }],
  };
}

test('diffScanFindings: added / removed / unchanged by fingerprint', () => {
  const from = [fakeFinding('aaa', 'old issue'), fakeFinding('bbb', 'persistent issue')];
  const to = [fakeFinding('bbb', 'persistent issue'), fakeFinding('ccc', 'new issue')];
  const d = diffScanFindings(from, to, 'scan-from', 'scan-to');
  assert.deepEqual(d.added.map((f) => f.title), ['new issue']);
  assert.deepEqual(d.removed.map((f) => f.title), ['old issue']);
  assert.deepEqual(d.unchanged.map((f) => f.title), ['persistent issue']);
});

// ---------- cross-role matrix (two-role test app) ----------

function twoRoleApp(opts: { secondaryCanAccessAdmin: boolean }): { server: Server; start: () => Promise<void>; close: () => void; port: () => number } {
  const server = createHttpServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    const html = (b: string): void => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(b); };
    const cookieToken = /session=([^;]+)/.exec(req.headers.cookie ?? '')?.[1];
    const role = ((): string | undefined => {
      if (!cookieToken) return undefined;
      try { return (JSON.parse(Buffer.from(cookieToken.split('.')[1]!, 'base64url').toString('utf8')) as { role?: string }).role; } catch { return undefined; }
    })();
    if (url.pathname === '/') {
      return html('<a href="/login">Login</a><a href="/admin">Admin</a><a href="/logout">Logout</a>' +
        '<form action="/login" method="post"><input name="username"><input name="password" type="password"></form>');
    }
    if (url.pathname === '/login' && req.method === 'POST') {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        const f = new URLSearchParams(body);
        const users: Record<string, { pass: string; role: string }> = {
          adminuser: { pass: 'adminpass1', role: 'admin' },
          normaluser: { pass: 'userpass12', role: 'user' },
        };
        const u = users[f.get('username') ?? ''];
        if (u && u.pass === f.get('password')) {
          const token = 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify({ sub: f.get('username'), role: u.role })).toString('base64url') + '.c2lnbmF0dXJlLTEyMzQ1';
          res.setHeader('Set-Cookie', `session=${token}; Path=/; HttpOnly`);
          res.writeHead(302, { location: '/admin' });
          return res.end();
        }
        res.writeHead(401); res.end();
      });
      return;
    }
    if (url.pathname === '/admin') {
      // VULNERABLE variant: any authenticated role reaches /admin; FIXED: admin only
      if (role !== undefined && (opts.secondaryCanAccessAdmin || role === 'admin')) {
        return html('<h1>Admin Panel</h1>');
      }
      res.writeHead(302, { location: '/login' }); return res.end();
    }
    if (url.pathname === '/logout') return html('out');
    res.writeHead(404); res.end();
  });
  return {
    server,
    start: () => new Promise<void>((r) => server.listen(0, '127.0.0.1', r)),
    close: () => server.close(),
    port: () => (server.address() as { port: number }).port,
  };
}

test('cross-role matrix: secondary user accessing admin-only page flagged (vulnerable app)', async () => {
  const app = twoRoleApp({ secondaryCanAccessAdmin: true });
  await app.start();
  const origin = `http://127.0.0.1:${app.port()}`;
  try {
    const guard = new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 });
    const client = new ScopedHttpClient(guard, new RateLimiter(100, 50), new Semaphore(4), { timeoutMs: 3000, maxRedirectHops: 2 }, { sent: 0, blocked: 0 });
    const engine = new AuthenticatedProbeEngine();
    const target: Target = { id: 't', name: 'x', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() };
    const ctx: ScanContext = {
      scanId: 's', target, mode: 'active',
      credentials: { username: 'adminuser', password: 'adminpass1', role: 'primary' },
      credentialsSecondary: { username: 'normaluser', password: 'userpass12', role: 'secondary' },
      client, guard, stats: { sent: 0, blocked: 0 }, signal: new AbortController().signal, workDir: '.',
      log: () => {},
      crawl: { pages: [{ url: `${origin}/`, status: 200, truncated: false, headers: {}, body: '<a href="/admin">Admin</a><a href="/logout">Logout</a>' +
        '<form action="/login" method="post"><input name="username"><input name="password" type="password"></form>',
        forms: [{ action: `${origin}/login`, method: 'post', fields: ['username', 'password'], hasPasswordField: true }],
        links: [`${origin}/admin`, `${origin}/logout`] }], robots: { disallow: [], fetched: false } },
    };
    const res = await engine.run(ctx);
    const f = res.findings.find((x) => x.rawId === 'cross-role-access');
    assert.ok(f, 'cross-role finding');
    assert.equal(f!.category, 'A01');
    assert.equal(f!.cwe, 285);
    assert.match(f!.title, /secondary/);
    assert.ok(!JSON.stringify(res).includes('adminpass1'), 'password never in evidence');
  } finally {
    app.close();
  }
});

test('cross-role matrix: properly-restricted admin produces no finding (hardened app)', async () => {
  const app = twoRoleApp({ secondaryCanAccessAdmin: false });
  await app.start();
  const origin = `http://127.0.0.1:${app.port()}`;
  try {
    const guard = new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 });
    const client = new ScopedHttpClient(guard, new RateLimiter(100, 50), new Semaphore(4), { timeoutMs: 3000, maxRedirectHops: 2 }, { sent: 0, blocked: 0 });
    const engine = new AuthenticatedProbeEngine();
    const target: Target = { id: 't', name: 'x', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() };
    const ctx: ScanContext = {
      scanId: 's', target, mode: 'active',
      credentials: { username: 'adminuser', password: 'adminpass1', role: 'primary' },
      credentialsSecondary: { username: 'normaluser', password: 'userpass12', role: 'secondary' },
      client, guard, stats: { sent: 0, blocked: 0 }, signal: new AbortController().signal, workDir: '.',
      log: () => {},
      crawl: { pages: [{ url: `${origin}/`, status: 200, truncated: false, headers: {}, body: '<a href="/admin">Admin</a><a href="/logout">Logout</a>' +
        '<form action="/login" method="post"><input name="username"><input name="password" type="password"></form>',
        forms: [{ action: `${origin}/login`, method: 'post', fields: ['username', 'password'], hasPasswordField: true }],
        links: [`${origin}/admin`, `${origin}/logout`] }], robots: { disallow: [], fetched: false } },
    };
    const res = await engine.run(ctx);
    assert.equal(res.findings.find((x) => x.rawId === 'cross-role-access'), undefined);
  } finally {
    app.close();
  }
});

// ---------- diff API endpoint ----------

function testConfig(dir: string): Config {
  return {
    host: '127.0.0.1', port: 0, dataDir: dir, token: undefined,
    allowPublicTargets: false, rateLimitPerSecond: 100, rateBurst: 50,
    maxConcurrency: 8, maxConcurrentScans: 2, requestTimeoutMs: 5000,
    engineTimeoutMs: 30_000, scanProfile: 'aggressive' as const, scanTimeoutMs: 60_000, maxCrawlPages: 5, maxCrawlPagesExplicit: false, loopEnabled: false, loopMaxIterations: 40, loopMaxRequests: 800, loopMaxMs: 600000, loopSeed: 0, loopSubscanFanout: 3,
    logLevel: 'error',
  };
}

test('diff API endpoint compares the two latest completed scans', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ovap-diff-'));
  const platform: Platform = buildPlatform(testConfig(dir));
  try {
    const { createRequestHandler } = await import('../../src/server.ts');
    const handler = createRequestHandler(platform);
    const token = platform.token;
    const req = (method: string, path: string, body?: unknown): Request => {
      const init: RequestInit = { method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' } };
      if (body !== undefined) init.body = JSON.stringify(body);
      return new Request(`http://127.0.0.1:7788${path}`, init);
    };

    const target = platform.db.createTarget({ name: 'diff-target', origin: 'http://127.0.0.1:59999', kind: 'webapp', approved: false });
    platform.db.approveTarget(target.id, 'test');

    // two synthetic completed scans with different findings
    const mk = (id: string, fps: string[]): void => {
      platform.db.insertScan({
        id, targetId: target.id, targetName: 'diff-target', profile: 'standard-passive', mode: 'passive',
        status: 'completed', startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(),
        engines: [], coverage: [], stats: {
          findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          findingsByStatus: { confirmed: 0, probable: 0, informational: 0, false_positive: 0, untested: 0 },
          totalFindings: fps.length, requestsSent: 0, requestsBlocked: 0,
        },
      });
      platform.db.insertFindings(id, fps.map((fp) => ({
        id: `FND-A01-${fp.slice(0, 10)}`, fingerprint: fp, title: `finding ${fp}`,
        category: 'A01', severity: 'medium', confidence: 'high', status: 'confirmed',
        asset: origin0, locator: '/', engine: 'e', evidence: [], explanation: 'x',
        remediation: 'r', references: [], detectedAt: new Date().toISOString(),
        provenance: [{ engine: 'e', adapter: false }],
      })));
    };
    const origin0 = 'http://127.0.0.1:59999';
    mk('scan-old-aaaa', ['fp-old-only', 'fp-shared']);
    mk('scan-new-bbbb', ['fp-shared', 'fp-new-only']);

    const res = await handler(req('GET', `/api/targets/${target.id}/diff`));
    assert.equal(res.status, 200);
    const d = await res.json() as { summary: { added: number; removed: number; unchanged: number }; added: Array<{ title: string }> };
    assert.equal(d.summary.added, 1);
    assert.equal(d.summary.removed, 1);
    assert.equal(d.summary.unchanged, 1);
    assert.equal(d.added[0]!.title, 'finding fp-new-only');
  } finally {
    platform.db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('diff API refuses targets with fewer than two completed scans', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ovap-diff2-'));
  const platform: Platform = buildPlatform(testConfig(dir));
  try {
    const { createRequestHandler } = await import('../../src/server.ts');
    const handler = createRequestHandler(platform);
    const t = platform.db.createTarget({ name: 'solo', origin: 'http://127.0.0.1:1', kind: 'webapp', approved: false });
    const res = await handler(new Request(`http://127.0.0.1:7788/api/targets/${t.id}/diff`, {
      headers: { authorization: `Bearer ${platform.token}` },
    }));
    assert.equal(res.status, 409);
  } finally {
    platform.db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
