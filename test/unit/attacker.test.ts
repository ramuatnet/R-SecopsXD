/**
 * Tests for the attacker-mindset batch: CSRF exposure, SQLi differential,
 * mixed content, JS library version fingerprinting, XFO FP fix.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpServer } from 'node:http';
import { HttpObservationEngine } from '../../src/engines/builtin/httpObservation.ts';
import { ScopeGuard } from '../../src/safety/guard.ts';
import { RateLimiter } from '../../src/safety/rateLimiter.ts';
import { Semaphore } from '../../src/safety/concurrency.ts';
import { ScopedHttpClient } from '../../src/scan/httpClient.ts';
import type { CrawlPage, ScanContext } from '../../src/engines/types.ts';
import type { Target } from '../../src/core/types.ts';

const TARGET: Target = {
  id: 't', name: 'web', origin: 'https://127.0.0.1:8899', kind: 'webapp',
  approved: true, createdAt: new Date().toISOString(),
};

function page(over: Partial<CrawlPage> & { url: string }): CrawlPage {
  return { status: 200, truncated: false, headers: {}, body: '<p>x</p>', forms: [], links: [], ...over };
}

function obsCtx(pages: CrawlPage[], mode: 'passive' | 'active' = 'passive'): ScanContext {
  return {
    scanId: 's', target: TARGET, mode,
    client: {} as never, guard: {} as never, stats: { sent: 0, blocked: 0 },
    signal: new AbortController().signal, workDir: '.', log: () => {},
    crawl: { pages, robots: { disallow: [], fetched: false } },
  };
}

// ---------- CSRF exposure ----------

test('CSRF: POST form without token + SameSite-less session flagged (A01, probable)', async () => {
  const engine = new HttpObservationEngine();
  const res = await engine.run(obsCtx([
    page({
      url: 'https://127.0.0.1:8899/settings',
      headers: { 'set-cookie': 'session=abc; Path=/' },
      body: '<form action="/settings/save" method="post"><input name="email"></form>',
      forms: [{ action: 'https://127.0.0.1:8899/settings/save', method: 'post', fields: ['email'], hasPasswordField: false }],
    }),
  ]) as never);
  const f = res.findings.find((x) => x.rawId === 'csrf-exposure');
  assert.ok(f, 'csrf finding');
  assert.equal(f!.category, 'A01');
  assert.equal(f!.cwe, 352);
  assert.equal(f!.status, 'probable');
});

test('CSRF: form WITH token field or SameSite cookie produces no finding', async () => {
  const engine = new HttpObservationEngine();
  const withToken = await engine.run(obsCtx([
    page({
      url: 'https://127.0.0.1:8899/settings',
      headers: { 'set-cookie': 'session=abc; Path=/' },
      body: '<form action="/settings/save" method="post"><input type="hidden" name="csrf_token" value="x"><input name="email"></form>',
      forms: [{ action: 'https://127.0.0.1:8899/settings/save', method: 'post', fields: ['csrf_token', 'email'], hasPasswordField: false }],
    }),
  ]) as never);
  assert.equal(withToken.findings.find((x) => x.rawId === 'csrf-exposure'), undefined);

  const sameSite = await engine.run(obsCtx([
    page({
      url: 'https://127.0.0.1:8899/settings',
      headers: { 'set-cookie': 'session=abc; Path=/; SameSite=Lax' },
      body: '<form action="/settings/save" method="post"><input name="email"></form>',
      forms: [{ action: 'https://127.0.0.1:8899/settings/save', method: 'post', fields: ['email'], hasPasswordField: false }],
    }),
  ]) as never);
  assert.equal(sameSite.findings.find((x) => x.rawId === 'csrf-exposure'), undefined);
});

// ---------- mixed content ----------

test('mixed content: https page loading http script flagged (A04, CWE-311)', async () => {
  const engine = new HttpObservationEngine();
  const res = await engine.run(obsCtx([
    page({ url: 'https://127.0.0.1:8899/', body: '<script src="http://cdn.example.com/track.js"></script>' }),
  ]) as never);
  const f = res.findings.find((x) => x.rawId === 'mixed-content');
  assert.ok(f);
  assert.equal(f!.category, 'A04');
  assert.equal(f!.cwe, 311);
  assert.equal(f!.status, 'confirmed');
});

test('mixed content: https-only subresources produce no finding', async () => {
  const engine = new HttpObservationEngine();
  const res = await engine.run(obsCtx([
    page({ url: 'https://127.0.0.1:8899/', body: '<script src="https://cdn.example.com/track.js"></script>' }),
  ]) as never);
  assert.equal(res.findings.find((x) => x.rawId === 'mixed-content'), undefined);
});

// ---------- JS library version fingerprinting ----------

test('library versions: vulnerable jQuery 1.12.4 flagged with CVE-2019-11358', async () => {
  const engine = new HttpObservationEngine();
  const res = await engine.run(obsCtx([
    page({ url: 'https://127.0.0.1:8899/', body: '<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>' }),
  ]) as never);
  const all = res.findings.filter((x) => x.rawId === 'js-library-known-vulnerability');
  assert.ok(all.length >= 1, 'vulnerable jquery finding(s)');
  assert.ok(all.some((f) => f.title.includes('CVE-2019-11358')), 'both jQuery advisories should match 1.12.4');
  assert.ok(all.every((f) => f.category === 'A03' && f.cwe === 1104));
});

test('library versions: patched jQuery 3.6.1 produces no finding (htcnxt case)', async () => {
  const engine = new HttpObservationEngine();
  const res = await engine.run(obsCtx([
    page({ url: 'https://127.0.0.1:8899/', body: '<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.1/jquery.min.js"></script>' }),
  ]) as never);
  assert.equal(res.findings.find((x) => x.rawId === 'js-library-known-vulnerability'), undefined);
});

// ---------- XFO FP fix ----------

test('X-Frame-Options absence with CSP frame-ancestors is NOT flagged (FP fix)', async () => {
  const engine = new HttpObservationEngine();
  const res = await engine.run(obsCtx([
    page({
      url: 'https://127.0.0.1:8899/',
      headers: { 'content-security-policy': "default-src 'self'; frame-ancestors 'self'" },
    }),
  ]) as never);
  const f = res.findings.find((x) => x.rawId === 'missing-security-headers');
  assert.ok(!f || !f.title.includes('X-Frame-Options'), 'XFO must not be flagged when frame-ancestors present');
});

// ---------- SQLi differential (active, local server) ----------

test('SQLi differential: quote probe triggering SQL error flagged (A05, probable)', async () => {
  const server = createHttpServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    const q = url.searchParams.get('id') ?? '';
    if (q.includes("'")) {
      res.writeHead(500, { 'content-type': 'text/html' });
      res.end('<pre>Warning: mysql_fetch_array() expects parameter 1 — You have an error in your SQL syntax</pre>');
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<html><body>Item ${q}</body></html>`);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const guard = new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 });
    const client = new ScopedHttpClient(guard, new RateLimiter(100, 50), new Semaphore(4), { timeoutMs: 3000, maxRedirectHops: 2 }, { sent: 0, blocked: 0 });
    const engine = new HttpObservationEngine();
    // reflection-probe runs the differential; drive it via the engine itself
    const { ReflectionProbeEngine } = await import('../../src/engines/builtin/reflectionProbe.ts');
    const rp = new ReflectionProbeEngine();
    const rpRes = await rp.run({
      scanId: 's', target: { id: 't', name: 'x', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() },
      mode: 'active', client, guard, stats: { sent: 0, blocked: 0 },
      signal: new AbortController().signal, workDir: '.', log: () => {},
      crawl: { pages: [page({ url: `${origin}/item?id=5` })], robots: { disallow: [], fetched: false } },
    } as never);
    const f = rpRes.findings.find((x) => x.rawId === 'sqli-error-differential');
    assert.ok(f, 'SQLi differential finding');
    assert.equal(f!.category, 'A05');
    assert.equal(f!.cwe, 89);
    assert.equal(f!.status, 'probable');
  } finally {
    server.close();
  }
});

test('SQLi differential: parameterized app (no error change) produces no finding', async () => {
  const server = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html><body>Item 5</body></html>');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const { ReflectionProbeEngine } = await import('../../src/engines/builtin/reflectionProbe.ts');
    const rp = new ReflectionProbeEngine();
    const guard = new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 });
    const client = new ScopedHttpClient(guard, new RateLimiter(100, 50), new Semaphore(4), { timeoutMs: 3000, maxRedirectHops: 2 }, { sent: 0, blocked: 0 });
    const res = await rp.run({
      scanId: 's', target: { id: 't', name: 'x', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() },
      mode: 'active', client, guard, stats: { sent: 0, blocked: 0 },
      signal: new AbortController().signal, workDir: '.', log: () => {},
      crawl: { pages: [page({ url: `${origin}/item?id=5` })], robots: { disallow: [], fetched: false } },
    } as never);
    assert.equal(res.findings.find((x) => x.rawId === 'sqli-error-differential'), undefined);
  } finally {
    server.close();
  }
});
