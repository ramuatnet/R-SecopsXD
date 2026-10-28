/**
 * Tests for the B1/expansion feature set: credential profiles, authenticated
 * probes (logout invalidation, JWT forgery, surface mapping), open-redirect
 * probing, and source-map secret scanning.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpServer, type Server } from 'node:http';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Database } from '../../src/db/database.ts';
import { AuthenticatedProbeEngine } from '../../src/engines/builtin/authenticatedProbe.ts';
import { RedirectProbeEngine } from '../../src/engines/builtin/redirectProbe.ts';
import { PathProbeEngine } from '../../src/engines/builtin/pathProbe.ts';
import { ScopeGuard } from '../../src/safety/guard.ts';
import { RateLimiter } from '../../src/safety/rateLimiter.ts';
import { Semaphore } from '../../src/safety/concurrency.ts';
import { ScopedHttpClient } from '../../src/scan/httpClient.ts';
import type { CrawlPage, ScanContext } from '../../src/engines/types.ts';
import type { Target } from '../../src/core/types.ts';

// ---------- credential profiles ----------

test('credential profiles: encrypted at rest, retrievable, never in target JSON, deleted with target', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ovap-cred-'));
  const db = new Database(dir);
  try {
    const t = db.createTarget({ name: 'app', origin: 'http://127.0.0.1:1', kind: 'webapp', approved: false });
    db.setCredentials(t.id, { username: 'tester', password: 'Sup3rSecret!2026', loginUrl: 'http://127.0.0.1:1/login' });

    // password must not exist in plaintext anywhere in the DB file
    const raw = readFileSync(db.path, 'utf8');
    assert.ok(!raw.includes('Sup3rSecret'), 'password must be encrypted in the DB file');

    const cred = db.getCredentials(t.id)!;
    assert.equal(cred.username, 'tester');
    assert.equal(cred.password, 'Sup3rSecret!2026', 'round-trips for the engine');
    assert.equal(cred.loginUrl, 'http://127.0.0.1:1/login');
    assert.equal(db.hasCredentials(t.id), true);

    db.deleteCredentials(t.id);
    assert.equal(db.hasCredentials(t.id), false);
    assert.equal(db.getCredentials(t.id), undefined);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------- authenticated probe against a test app ----------

/** Test application: login form, STATELESS JWT session (signature NOT verified — the classic alg-confusion vulnerability), logout that does NOT invalidate, protected page. */
function vulnerableApp(): { server: Server; port: number; start: () => Promise<void>; close: () => void } {
  const server = createHttpServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    const html = (body: string): void => {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(`<html><body>${body}</body></html>`);
    };
    const cookieToken = /session=([^;]+)/.exec(req.headers.cookie ?? '')?.[1];

    // VULNERABLE authz: decodes the JWT payload and trusts it WITHOUT verifying the signature
    const authed = ((): boolean => {
      if (!cookieToken) return false;
      try {
        const payload = JSON.parse(Buffer.from(cookieToken.split('.')[1]!, 'base64url').toString('utf8')) as { sub?: string };
        return typeof payload.sub === 'string' && payload.sub.length > 0;
      } catch {
        return false;
      }
    })();

    if (url.pathname === '/' && req.method === 'GET') {
      return html('<a href="/login">Login</a><a href="/dashboard">Dashboard</a><a href="/admin">Admin</a><a href="/logout">Logout</a>' +
        '<form action="/login" method="post"><input name="username"><input name="password" type="password"></form>');
    }
    if (url.pathname === '/login' && req.method === 'POST') {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        const form = new URLSearchParams(body);
        if (form.get('username') === 'tester' && form.get('password') === 'testpass') {
          const token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${Buffer.from(JSON.stringify({ sub: 'tester', role: 'user' })).toString('base64url')}.c2lnbmF0dXJlLTEyMzQ1`;
          res.setHeader('Set-Cookie', `session=${token}; Path=/; HttpOnly`);
          res.writeHead(302, { location: '/dashboard' });
          return res.end();
        }
        res.writeHead(401);
        res.end('bad credentials');
      });
      return;
    }
    if (url.pathname === '/dashboard' || url.pathname === '/admin') {
      if (authed) return html('<h1>Secret Dashboard</h1>');
      res.writeHead(302, { location: '/login' });
      return res.end();
    }
    if (url.pathname === '/logout') {
      // VULNERABLE: stateless token remains valid after logout
      return html('<p>logged out</p>');
    }
    res.writeHead(404); res.end();
  });
  return {
    server,
    get port(): number { return (server.address() as { port: number }).port; },
    start: () => new Promise<void>((r) => server.listen(0, '127.0.0.1', r)),
    close: () => server.close(),
  };
}

function probeCtx(target: Target, client: ScopedHttpClient, pages: CrawlPage[], credentials?: { username: string; password: string }): ScanContext {
  return {
    scanId: 's', target, mode: 'active', credentials,
    client, guard: new ScopeGuard(target.origin, { allowPublicTargets: true, maxRedirectHops: 2 }),
    stats: { sent: 0, blocked: 0 }, signal: new AbortController().signal, workDir: '.',
    log: () => {},
    crawl: { pages, robots: { disallow: [], fetched: false } },
  };
}

function corpusFor(origin: string): CrawlPage[] {
  return [{
    url: `${origin}/`, status: 200, truncated: false,
    headers: { 'content-type': 'text/html' },
    body: '<a href="/login">Login</a><a href="/dashboard">Dashboard</a><a href="/admin">Admin</a><a href="/logout">Logout</a>' +
      '<form action="/login" method="post"><input name="username"><input name="password" type="password"></form>',
    forms: [{ action: `${origin}/login`, method: 'post', fields: ['username', 'password'], hasPasswordField: true }],
    links: [`${origin}/dashboard`, `${origin}/admin`, `${origin}/logout`],
  }];
}

test('authenticated probe: detects JWT forgery acceptance and non-invalidated logout (vulnerable app)', async () => {
  const app = vulnerableApp();
  await app.start();
  const origin = `http://127.0.0.1:${app.port}`;
  const db = new Database(mkdtempSync(join(tmpdir(), 'ovap-auth1-')));
  try {
    const target: Target = { id: 't', name: 'app', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() };
    db.setCredentials(target.id, { username: 'tester', password: 'testpass' });
    const engine = new AuthenticatedProbeEngine();
    const res = await engine.run(probeCtx(target, await clientFor(origin), corpusFor(origin), db.getCredentials(target.id)));

    const ids = res.findings.map((f) => f.rawId);
    assert.ok(ids.includes('jwt-forgery-accepted'), 'alg=none forgery must be accepted by this app');
    const jwt = res.findings.find((f) => f.rawId === 'jwt-forgery-accepted')!;
    assert.equal(jwt.severity, 'critical');
    assert.equal(jwt.status, 'confirmed');
    assert.ok(ids.includes('session-not-invalidated-after-logout'), 'logout must not invalidate in this app');
    const surface = res.findings.find((f) => f.rawId === 'authenticated-surface-map');
    assert.ok(surface, 'surface map emitted');
    assert.equal(surface!.severity, 'info');
    // no password material anywhere
    assert.ok(!JSON.stringify(res).includes('testpass'));
    assert.ok(res.detail?.includes('protected page'));
  } finally {
    app.close();
    db.close();
    rmSync(join(tmpdir(), 'ovap-auth1-'), { recursive: true, force: true });
  }
});

test('authenticated probe: properly-invalidating, signature-verifying app produces no findings', async () => {
  // Hardened variant: logout kills the session; forged tokens rejected.
  const sessions = new Set<string>();
  const server = createHttpServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    const cookieToken = /session=([^;]+)/.exec(req.headers.cookie ?? '')?.[1];
    const html = (body: string): void => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(body); };
    const goodToken = [...sessions][0] ?? '';
    const valid = (t: string | undefined): boolean => t !== undefined && t === goodToken && !t.startsWith('eyJhbGciOiJub25l'); // naive verification
    if (url.pathname === '/' && req.method === 'GET') {
      return html('<a href="/login">Login</a><a href="/dashboard">Dashboard</a><a href="/admin">Admin</a><a href="/logout">Logout</a>' +
        '<form action="/login" method="post"><input name="username"><input name="password" type="password"></form>');
    }
    if (url.pathname === '/login' && req.method === 'POST') {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        const form = new URLSearchParams(body);
        if (form.get('username') === 'tester' && form.get('password') === 'testpass') {
          const token = `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify({ sub: 'tester' })).toString('base64url')}.c2lnbmF0dXJlLTIzNDU2Nzg5MDEyMzQ1Njc4`;
          sessions.add(token);
          res.setHeader('Set-Cookie', `session=${token}; Path=/; HttpOnly`);
          res.writeHead(302, { location: '/dashboard' });
          return res.end();
        }
        res.writeHead(401); res.end();
      });
      return;
    }
    if (url.pathname === '/dashboard' || url.pathname === '/admin') {
      if (valid(cookieToken)) return html('<h1>Secret</h1>');
      res.writeHead(302, { location: '/login' }); return res.end();
    }
    if (url.pathname === '/logout') {
      if (cookieToken) sessions.delete(cookieToken); // FIXED: invalidate
      return html('<p>logged out</p>');
    }
    res.writeHead(404); res.end();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const db = new Database(mkdtempSync(join(tmpdir(), 'ovap-auth2-')));
  try {
    const target: Target = { id: 't', name: 'app', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() };
    db.setCredentials(target.id, { username: 'tester', password: 'testpass' });
    const engine = new AuthenticatedProbeEngine();
    const pages: CrawlPage[] = [{
      url: `${origin}/`, status: 200, truncated: false, headers: { 'content-type': 'text/html' },
      body: '<a href="/dashboard">Dashboard</a>',
      forms: [{ action: `${origin}/login`, method: 'post', fields: ['username', 'password'], hasPasswordField: true }],
      links: [`${origin}/dashboard`, `${origin}/admin`, `${origin}/logout`],
    }];
    const res = await engine.run(probeCtx(target, await clientFor(origin), pages, db.getCredentials(target.id)));
    assert.equal(res.findings.find((f) => f.rawId === 'jwt-forgery-accepted'), undefined, 'verified app rejects forgeries');
    assert.equal(res.findings.find((f) => f.rawId === 'session-not-invalidated-after-logout'), undefined, 'invalidating logout passes');
  } finally {
    server.close();
    db.close();
    rmSync(join(tmpdir(), 'ovap-auth2-'), { recursive: true, force: true });
  }
});

test('authenticated probe reports notExecutedReason when no credentials configured', async () => {
  const engine = new AuthenticatedProbeEngine();
  const target: Target = { id: 't', name: 'app', origin: 'http://127.0.0.1:1', kind: 'webapp', approved: true, createdAt: new Date().toISOString() };
  const res = await engine.run(probeCtx(target, {} as never, []) as never);
  assert.equal(res.findings.length, 0);
  assert.match(res.notExecutedReason ?? '', /no credential profile/);
});

// ---------- open redirect ----------

test('redirect probe: 302 to marker host detected as confirmed open redirect', async () => {
  const server = createHttpServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    const target = url.searchParams.get('next');
    if (target) { res.writeHead(302, { location: target }); return res.end(); }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<a href="/jump?next=/home">jump</a>');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const engine = new RedirectProbeEngine();
    const res = await engine.run(probeCtx(
      { id: 't', name: 'x', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() },
      await clientFor(origin),
      [{ url: `${origin}/jump?next=/home`, status: 200, truncated: false, headers: {}, body: '', forms: [], links: [] }],
    ));
    const f = res.findings.find((x) => x.rawId === 'open-redirect');
    assert.ok(f, 'open redirect finding');
    assert.equal(f!.category, 'A01');
    assert.equal(f!.cwe, 601);
    assert.equal(f!.status, 'confirmed');
    assert.match(f!.title, /\[next\]/);
  } finally {
    server.close();
  }
});

test('redirect probe: non-redirecting parameter produces no finding', async () => {
  const server = createHttpServer((_req, res) => { res.writeHead(200); res.end('ok'); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const engine = new RedirectProbeEngine();
    const res = await engine.run(probeCtx(
      { id: 't', name: 'x', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() },
      await clientFor(origin),
      [{ url: `${origin}/jump?next=/home`, status: 200, truncated: false, headers: {}, body: '', forms: [], links: [] }],
    ));
    assert.equal(res.findings.length, 0);
  } finally {
    server.close();
  }
});

// ---------- source-map secret scanning ----------

test('path probe scans exposed map content for secrets (redacted)', async () => {
  const secretLine = "const API_TOKEN = 'sk-live-zzzz9999yyyy8888';";
  const server = createHttpServer((req, res) => {
    if (req.url === '/assets/app.js.map') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        version: 3, sources: ['src/config.js'],
        sourcesContent: [`export const cfg = {\n${secretLine}\n};`],
        names: [], mappings: 'AAAA',
      }));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/javascript' });
    res.end('1+1');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const engine = new PathProbeEngine();
    const res = await engine.run(probeCtx(
      { id: 't', name: 'x', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() },
      await clientFor(origin),
      [{ url: `${origin}/`, status: 200, truncated: false, headers: {}, body: '', forms: [], links: [`${origin}/assets/app.js`] }],
    ));
    const f = res.findings.find((x) => x.rawId === 'source-map-secrets');
    assert.ok(f, 'secret-in-map finding');
    assert.equal(f!.category, 'A07');
    assert.equal(f!.cwe, 798);
    const evText = JSON.stringify(f!.evidence);
    assert.ok(!evText.includes('sk-live-zzzz9999yyyy8888'), 'secret value redacted from evidence');
    assert.ok(evText.includes('REDACTED'));
  } finally {
    server.close();
  }
});

// ---------- helpers ----------

async function clientFor(origin: string): Promise<ScopedHttpClient> {
  const guard = new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 });
  return new ScopedHttpClient(guard, new RateLimiter(100, 50), new Semaphore(4), { timeoutMs: 3000, maxRedirectHops: 2 }, { sent: 0, blocked: 0 });
}
