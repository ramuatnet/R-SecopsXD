/**
 * Tests for the final expansion batch: CSP quality, HSTS absence,
 * JS bundle secret scanning, GraphQL introspection probing.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpServer } from 'node:http';
import { HttpObservationEngine } from '../../src/engines/builtin/httpObservation.ts';
import { GraphqlProbeEngine } from '../../src/engines/builtin/graphqlProbe.ts';
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

function page(over: Partial<CrawlPage> & { url: string }): CrawlPage {
  return { status: 200, truncated: false, headers: {}, body: '<p>x</p>', forms: [], links: [], ...over };
}

function obsCtx(pages: CrawlPage[]): ScanContext {
  return {
    scanId: 's', target: TARGET, mode: 'passive',
    client: {} as never, guard: {} as never, stats: { sent: 0, blocked: 0 },
    signal: new AbortController().signal, workDir: '.', log: () => {},
    crawl: { pages, robots: { disallow: [], fetched: false } },
  };
}

test('CSP quality: unsafe-inline + unsafe-eval flagged as confirmed weakness', async () => {
  const engine = new HttpObservationEngine();
  const res = await engine.run(obsCtx([
    page({
      url: 'https://127.0.0.1:8899/',
      headers: { 'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' cdn.example.com" },
    }),
  ]) as never);
  const f = res.findings.find((x) => x.rawId === 'csp-weak-directives');
  assert.ok(f, 'weak CSP finding');
  assert.equal(f!.category, 'A02');
  assert.equal(f!.cwe, 79);
  assert.equal(f!.status, 'confirmed');
  assert.match(f!.title, /unsafe-inline/);
});

test('CSP quality: strong CSP produces no finding', async () => {
  const engine = new HttpObservationEngine();
  const res = await engine.run(obsCtx([
    page({
      url: 'https://127.0.0.1:8899/',
      headers: { 'content-security-policy': "default-src 'self'; script-src 'self' nonce-abc; object-src 'none'" },
    }),
  ]) as never);
  assert.equal(res.findings.find((x) => x.rawId === 'csp-weak-directives'), undefined);
});

test('HSTS absence flagged on HTTPS origins; not applicable on HTTP', async () => {
  const engine = new HttpObservationEngine();
  const httpsTarget: Target = { ...TARGET, origin: 'https://127.0.0.1:8899' };
  const httpsCtx = (pages: CrawlPage[]): ScanContext => ({
    ...obsCtx(pages), target: httpsTarget,
  });
  const res = await engine.run(httpsCtx([
    page({ url: 'https://127.0.0.1:8899/' }),
  ]) as never);
  const f = res.findings.find((x) => x.rawId === 'hsts-missing');
  assert.ok(f, 'HSTS finding on https without header');
  assert.equal(f!.category, 'A04');
  assert.equal(f!.cwe, 319);

  const res2 = await engine.run(httpsCtx([
    page({ url: 'https://127.0.0.1:8899/', headers: { 'strict-transport-security': 'max-age=31536000' } }),
  ]) as never);
  assert.equal(res2.findings.find((x) => x.rawId === 'hsts-missing'), undefined);

  // http origin: not applicable
  const res3 = await engine.run(obsCtx([page({ url: 'http://127.0.0.1:8899/' })]) as never);
  assert.equal(res3.findings.find((x) => x.rawId === 'hsts-missing'), undefined);
});

test('JS bundle secrets: AWS key and credential assignments in served bundles detected, values redacted', async () => {
  const bundle = [
    'var cfg = {',
    "  key: 'AKIAIOSFODNN7EXAMPLE',",
    '};',
    'var pub = "not-a-secret";',
  ].join('\n');
  const server = createHttpServer((req, res) => {
    if (req.url === '/assets/app.js') {
      res.writeHead(200, { 'content-type': 'application/javascript' });
      res.end(bundle);
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<script src="/assets/app.js"></script>');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    // engine fetches the bundle itself — needs a real client; use plain fetch via a minimal stub
    const engine = new HttpObservationEngine();
    const stubClient = {
      get: async (url: string) => {
        const res = await fetch(url);
        const body = await res.text();
        const headers: Record<string, string> = {};
        res.headers.forEach((v, k) => { headers[k] = v; });
        return { ok: true, status: res.status, headers, body, truncated: false, finalUrl: url, elapsedMs: 1 };
      },
    };
    const ctx = obsCtx([page({ url: `${origin}/`, body: '<script src="/assets/app.js"></script>' })]);
    (ctx as { client: unknown }).client = stubClient;
    const res = await engine.run(ctx);
    const f = res.findings.find((x) => x.rawId === 'js-bundle-secret');
    assert.ok(f, 'bundle secret finding');
    assert.equal(f!.category, 'A07');
    assert.equal(f!.cwe, 798);
    const evText = JSON.stringify(f!.evidence);
    assert.ok(!evText.includes('AKIAIOSFODNN7EXAMPLE'), 'secret value redacted');
    assert.ok(evText.includes('REDACTED'));
  } finally {
    server.close();
  }
});

test('GraphQL probe: introspection enabled detected as confirmed finding', async () => {
  const server = createHttpServer((req, res) => {
    if (req.url === '/graphql' && req.method === 'POST') {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ data: { __schema: { queryType: { name: 'Query' } } } }));
      });
      return;
    }
    res.writeHead(404); res.end('{}');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const guard = new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 });
    const client = new ScopedHttpClient(guard, new RateLimiter(100, 50), new Semaphore(4), { timeoutMs: 3000, maxRedirectHops: 2 }, { sent: 0, blocked: 0 });
    const engine = new GraphqlProbeEngine();
    const res = await engine.run({
      scanId: 's', target: { id: 't', name: 'x', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() },
      mode: 'active', client, guard, stats: { sent: 0, blocked: 0 },
      signal: new AbortController().signal, workDir: '.', log: () => {},
      crawl: { pages: [], robots: { disallow: [], fetched: false } },
    } as never);
    const f = res.findings.find((x) => x.rawId === 'graphql-introspection-enabled');
    assert.ok(f, 'introspection finding');
    assert.equal(f!.category, 'A01');
    assert.equal(f!.cwe, 200);
    assert.equal(f!.status, 'confirmed');
  } finally {
    server.close();
  }
});

test('GraphQL probe: no GraphQL surface produces no findings', async () => {
  const server = createHttpServer((_req, res) => { res.writeHead(404); res.end('{}'); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const guard = new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 });
    const client = new ScopedHttpClient(guard, new RateLimiter(100, 50), new Semaphore(4), { timeoutMs: 3000, maxRedirectHops: 2 }, { sent: 0, blocked: 0 });
    const engine = new GraphqlProbeEngine();
    const res = await engine.run({
      scanId: 's', target: { id: 't', name: 'x', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() },
      mode: 'active', client, guard, stats: { sent: 0, blocked: 0 },
      signal: new AbortController().signal, workDir: '.', log: () => {},
      crawl: { pages: [], robots: { disallow: [], fetched: false } },
    } as never);
    assert.deepEqual(res.findings, []);
  } finally {
    server.close();
  }
});
