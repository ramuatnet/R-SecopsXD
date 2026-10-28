/**
 * Tests for the enterprise-expansion batch: CORS policy, JWT observation,
 * sensitive data in URLs (http-observation) and source-map probing (path-probe).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpServer } from 'node:http';
import { HttpObservationEngine } from '../../src/engines/builtin/httpObservation.ts';
import { PathProbeEngine } from '../../src/engines/builtin/pathProbe.ts';
import { ScopeGuard } from '../../src/safety/guard.ts';
import { RateLimiter } from '../../src/safety/rateLimiter.ts';
import { Semaphore } from '../../src/safety/concurrency.ts';
import { ScopedHttpClient } from '../../src/scan/httpClient.ts';
import type { CrawlPage, ScanContext } from '../../src/engines/types.ts';
import type { Target } from '../../src/core/types.ts';

const TARGET: Target = {
  id: 't', name: 'web', origin: 'http://127.0.0.1:8899', kind: 'webapp',
  approved: true, createdAt: new Date().toISOString(),
};

function ctx(mode: 'passive' | 'active', client: ScopedHttpClient, pages: CrawlPage[]): ScanContext {
  return {
    scanId: 's', target: TARGET, mode,
    client, guard: new ScopeGuard(TARGET.origin, { allowPublicTargets: true, maxRedirectHops: 2 }),
    stats: { sent: 0, blocked: 0 }, signal: new AbortController().signal, workDir: '.',
    log: () => {},
    crawl: { pages, robots: { disallow: [], fetched: false } },
  };
}

function page(over: Partial<CrawlPage> & { url: string }): CrawlPage {
  return { status: 200, headers: {}, body: '<p>x</p>', truncated: false, forms: [], links: [], ...over };
}

const JWT_NONE = `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.${Buffer.from(JSON.stringify({ sub: '1', role: 'admin' })).toString('base64url')}.SIGPARTHERE`;
const JWT_NO_EXP = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${Buffer.from(JSON.stringify({ sub: '2', role: 'user' })).toString('base64url')}.c2lnbmF0dXJlLXZhbHVlLWhlcmUtMTIzNDU2`;

test('JWT observation: alg=none served token flagged (A04, redacted evidence)', async () => {
  const engine = new HttpObservationEngine();
  const res = await engine.run(ctx('passive', {} as never, [
    page({ url: 'http://127.0.0.1:8899/', body: `<script>var t = "${JWT_NONE}";</script>` }),
  ]) as never);
  const f = res.findings.find((x) => x.rawId === 'jwt-alg-none-observed');
  assert.ok(f, 'alg=none finding');
  assert.equal(f!.category, 'A04');
  assert.equal(f!.cwe, 347);
  assert.equal(f!.confidence, 'medium', 'observation only — exploitation not tested');
  // token value must be redacted in stored evidence
  const evText = JSON.stringify(f!.evidence);
  assert.ok(!evText.includes(JWT_NONE), 'full token must not leak into evidence');
});

test('JWT observation: missing exp claim flagged informational (A07)', async () => {
  const engine = new HttpObservationEngine();
  const res = await engine.run(ctx('passive', {} as never, [
    page({ url: 'http://127.0.0.1:8899/', body: JWT_NO_EXP }),
  ]) as never);
  const f = res.findings.find((x) => x.rawId === 'jwt-missing-exp-observed');
  assert.ok(f);
  assert.equal(f!.category, 'A07');
  assert.equal(f!.cwe, 613);
});

test('JWT observation: well-formed exp-bearing tokens produce no finding', async () => {
  const good = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${Buffer.from(JSON.stringify({ sub: '1', exp: 4102444800 })).toString('base64url')}.c2lnbmF0dXJlLXZhbHVlLWhlcmUtMTIzNDU2`;
  const engine = new HttpObservationEngine();
  const res = await engine.run(ctx('passive', {} as never, [
    page({ url: 'http://127.0.0.1:8899/', body: good }),
  ]) as never);
  assert.equal(res.findings.find((x) => x.rawId?.startsWith('jwt-')), undefined);
});

test('SRI root-cause dedup: same unshielded script on N pages yields ONE finding', async () => {
  const engine = new HttpObservationEngine();
  const body = '<script src="https://cdn.example.com/jquery.js"></script>';
  const res = await engine.run(ctx('passive', {} as never, [
    page({ url: 'http://127.0.0.1:8899/a', body }),
    page({ url: 'http://127.0.0.1:8899/b', body }),
    page({ url: 'http://127.0.0.1:8899/c', body }),
  ]) as never);
  const sri = res.findings.filter((x) => x.rawId === 'sri-external-script');
  assert.equal(sri.length, 1, 'one root-cause finding, not one per page');
  const f = sri[0]!;
  assert.match(f.title, /\(3\+ pages\)/);
  assert.equal(f.locator, '/jquery.js', 'locator identifies the script, not a page');
  assert.equal(f.evidence.length, 3, 'all affected pages captured as evidence (capped at 3)');
  // distinct scripts remain distinct findings
  const res2 = await engine.run(ctx('passive', {} as never, [
    page({ url: 'http://127.0.0.1:8899/a', body: body + '<script src="https://cdn.example.com/other.js"></script>' }),
  ]) as never);
  assert.equal(res2.findings.filter((x) => x.rawId === 'sri-external-script').length, 2);
});

test('sensitive data in URLs flagged (A01, CWE-598)', async () => {
  const engine = new HttpObservationEngine();
  const res = await engine.run(ctx('passive', {} as never, [
    page({ url: 'http://127.0.0.1:8899/reset?token=abc123def&x=1' }),
  ]) as never);
  const f = res.findings.find((x) => x.rawId === 'sensitive-data-in-url');
  assert.ok(f);
  assert.equal(f!.category, 'A01');
  assert.equal(f!.cwe, 598);
  // the evidence must not carry the sensitive value
  const evText = JSON.stringify(f!.evidence);
  assert.ok(!evText.includes('abc123def'));
});

test('benign URLs produce no sensitive-URL finding', async () => {
  const engine = new HttpObservationEngine();
  const res = await engine.run(ctx('passive', {} as never, [
    page({ url: 'http://127.0.0.1:8899/search?q=plain+text&page=2' }),
  ]) as never);
  assert.equal(res.findings.find((x) => x.rawId === 'sensitive-data-in-url'), undefined);
});

// ---------- CORS (active mode) ----------

function startServer(handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void): Promise<{ server: import('node:http').Server; port: number; close: () => void }> {
  return new Promise((resolve) => {
    const server = createHttpServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as { port: number }).port;
      resolve({ server, port, close: () => server.close() });
    });
  });
}

async function clientFor(origin: string): Promise<ScopedHttpClient> {
  const guard = new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 });
  return new ScopedHttpClient(guard, new RateLimiter(100, 50), new Semaphore(4), { timeoutMs: 3000, maxRedirectHops: 2 }, { sent: 0, blocked: 0 });
}

test('CORS: foreign-Origin reflection with credentials flagged as confirmed high', async () => {
  const { server, port, close } = await startServer((req, res) => {
    const origin = req.headers.origin as string | undefined;
    res.writeHead(200, {
      'access-control-allow-origin': origin ?? '*',
      'access-control-allow-credentials': 'true',
      'content-type': 'application/json',
    });
    res.end('{"data":1}');
  });
  try {
    const origin = `http://127.0.0.1:${port}`;
    const engine = new HttpObservationEngine();
    const res = await engine.run(ctx('active', await clientFor(origin), [
      page({ url: `${origin}/api/data`, headers: { 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' } }),
    ]) as never);
    const f = res.findings.find((x) => x.rawId === 'cors-origin-reflection-credentials');
    assert.ok(f, 'reflection+credentials finding');
    assert.equal(f!.severity, 'high');
    assert.equal(f!.confidence, 'high');
  } finally {
    close();
  }
});

test('CORS: well-configured endpoint produces no finding', async () => {
  const { server, port, close } = await startServer((req, res) => {
    res.writeHead(200, { 'access-control-allow-origin': 'https://trusted.example' });
    res.end('{}');
  });
  try {
    const origin = `http://127.0.0.1:${port}`;
    const engine = new HttpObservationEngine();
    const res = await engine.run(ctx('active', await clientFor(origin), [
      page({ url: `${origin}/api/data`, headers: { 'access-control-allow-origin': 'https://trusted.example' } }),
    ]) as never);
    assert.equal(res.findings.find((x) => x.rawId?.startsWith('cors-')), undefined);
  } finally {
    close();
  }
});

test('CORS check does not run in passive mode', async () => {
  const engine = new HttpObservationEngine();
  const res = await engine.run(ctx('passive', {} as never, [
    page({ url: 'http://127.0.0.1:8899/api', headers: { 'access-control-allow-origin': '*' } }),
  ]) as never);
  assert.equal(res.findings.find((x) => x.rawId?.startsWith('cors-')), undefined);
});

// ---------- Source maps (active path-probe) ----------

test('source map probe detects served .js.map with sources', async () => {
  const { server, port, close } = await startServer((req, res) => {
    if (req.url === '/assets/app.js.map') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ version: 3, sources: ['src/app.ts'], names: [], mappings: 'AAAA' }));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/javascript' });
    res.end('console.log(1)');
  });
  try {
    const origin = `http://127.0.0.1:${port}`;
    const engine = new PathProbeEngine();
    const res = await engine.run({
      scanId: 's', target: { ...TARGET, origin }, mode: 'active',
      client: await clientFor(origin),
      guard: new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 }),
      stats: { sent: 0, blocked: 0 }, signal: new AbortController().signal, workDir: '.', log: () => {},
      crawl: {
        pages: [page({ url: `${origin}/`, links: [`${origin}/assets/app.js`] })],
        robots: { disallow: [], fetched: false },
      },
    } as never);
    const f = res.findings.find((x) => x.rawId === 'source-map-exposed');
    assert.ok(f, 'source map finding');
    assert.equal(f!.category, 'A01');
    assert.equal(f!.cwe, 540);
    assert.match(f!.locator!, /\.map$/);
  } finally {
    close();
  }
});

test('source map probe ignores 404 maps and non-map JSON', async () => {
  const { server, port, close } = await startServer((req, res) => {
    if (req.url === '/assets/app.js.map') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"not":"a sourcemap"}');
      return;
    }
    res.writeHead(200, { 'content-type': 'application/javascript' });
    res.end('console.log(1)');
  });
  try {
    const origin = `http://127.0.0.1:${port}`;
    const engine = new PathProbeEngine();
    const res = await engine.run({
      scanId: 's', target: { ...TARGET, origin }, mode: 'active',
      client: await clientFor(origin),
      guard: new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 }),
      stats: { sent: 0, blocked: 0 }, signal: new AbortController().signal, workDir: '.', log: () => {},
      crawl: {
        pages: [page({ url: `${origin}/`, links: [`${origin}/assets/app.js`] })],
        robots: { disallow: [], fetched: false },
      },
    } as never);
    assert.equal(res.findings.find((x) => x.rawId === 'source-map-exposed'), undefined);
  } finally {
    close();
  }
});
