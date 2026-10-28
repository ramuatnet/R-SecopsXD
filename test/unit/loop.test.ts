/**
 * Tests for the autonomous loop (v2 Phase 2 + 3): probe gate, decide scoring,
 * loop termination, determinism, and promotion/rejection behavior.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpServer, type Server } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Database } from '../../src/db/database.ts';
import { TargetModel, mergeEvidence } from '../../src/model/targetModel.ts';
import { runProbeGate } from '../../src/model/probeGate.ts';
import { decide, planCandidates, runLoop, verifyFinding } from '../../src/loop/loop.ts';
import { EngineRegistry } from '../../src/engines/registry.ts';
import { loadConfig } from '../../src/config.ts';
import { ScopeGuard } from '../../src/safety/guard.ts';
import { RateLimiter } from '../../src/safety/rateLimiter.ts';
import { Semaphore } from '../../src/safety/concurrency.ts';
import { ScopedHttpClient } from '../../src/scan/httpClient.ts';
import type { CrawlCorpus, CrawlPage, ScanContext } from '../../src/engines/types.ts';
import type { Finding, Target } from '../../src/core/types.ts';

const TARGET: Target = {
  id: 't-loop', name: 'loop-target', origin: 'http://127.0.0.1:8899', kind: 'webapp',
  approved: true, createdAt: new Date().toISOString(),
};

function clientFor(origin: string): ScopedHttpClient {
  const guard = new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 });
  return new ScopedHttpClient(guard, new RateLimiter(200, 50), new Semaphore(4), { timeoutMs: 3000, maxRedirectHops: 2 }, { sent: 0, blocked: 0 });
}

// ---------- probe gate ----------

test('probe gate: flips unknown capabilities to present/absent with budget', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ovap-gate-'));
  const db = new Database(dir);
  try {
    // SPA-ish corpus: scripts, no anchors, has form + session cookie, no graphql/openapi
    const pages: CrawlPage[] = [{
      url: 'http://127.0.0.1:8899/', status: 200, truncated: false,
      headers: { 'content-type': 'text/html', 'set-cookie': 'session=abc; Path=/', 'x-amz-request-id': 'xyz' },
      body: '<script src="/main.js"></script><script src="/poly.js"></script>' +
        '<form action="/login" method="post"><input type="password" name="pw"></form>',
      forms: [{ action: 'http://127.0.0.1:8899/login', method: 'post', fields: ['pw'], hasPasswordField: true }],
      links: [],
    }];
    const origin = 'http://127.0.0.1:8899';
    const model = new TargetModel(db.handle, 't-gate');
    const gate = await runProbeGate(db, {
      target: TARGET, origin, pages, client: {} as never, guard: {} as never,
      signal: new AbortController().signal, log: () => {},
    }, { maxProbes: 20, maxRequests: 10 }, { sent: 0, blocked: 0 });
    void model;

    // observation-only probes on the synthetic corpus
    const byCap = new Map(gate.results.map((r) => [r.capability, r.state]));
    assert.equal(byCap.get('http.server'), 'present');
    assert.equal(byCap.get('frontend.spa'), 'present');
    assert.equal(byCap.get('auth.form'), 'present');
    assert.equal(byCap.get('auth.session-cookie'), 'present');
    assert.equal(byCap.get('cloud.markers'), 'present', 'x-amz-request-id is a cloud marker');
    // graphql probe: no reference in corpus → falls through to the active GET;
    // origin unreachable in this test → honestly inconclusive (never a false 'absent')
    assert.equal(byCap.get('api.graphql'), 'inconclusive');
    assert.ok(byCap.get('api.openapi') === 'inconclusive' || byCap.get('api.openapi') === 'absent');
    // model updated: unknown flipped
    const m2 = new TargetModel(db.handle, TARGET.id);
    assert.equal(m2.state('capability', 'auth.form'), 'present');
    assert.equal(m2.state('capability', 'frontend.spa'), 'present');
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('probe gate: respects maxProbes budget', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ovap-gate2-'));
  const db = new Database(dir);
  try {
    const gate = await runProbeGate(db, {
      target: TARGET, origin: 'http://127.0.0.1:8899', pages: [], client: {} as never,
      guard: {} as never, signal: new AbortController().signal, log: () => {},
    }, { maxProbes: 3, maxRequests: 10 }, { sent: 0, blocked: 0 });
    assert.equal(gate.results.length, 3, 'stopped at budget');
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------- decide ----------

test('decide: ranks by P*gain/cost with deterministic tie-break', () => {
  const a = { id: 'a', type: 'engine' as const, target: 'x', reason: '', worth: 0.9, infoGain: 8, cost: 5, score: 0 };
  const b = { id: 'b', type: 'verify' as const, target: 'y', reason: '', worth: 0.85, infoGain: 5, cost: 1, score: 0 };
  const winner = decide([a, b]);
  assert.equal(winner!.id, 'b', '0.85*5/1 = 4.25 beats 0.9*8/5 = 1.44');
  const c = { id: 'c', type: 'engine' as const, target: 'z', reason: '', worth: 0.9, infoGain: 8, cost: 5, score: 0 };
  const tied = decide([a, c]);
  assert.equal(tied!.id, 'a', 'deterministic tie-break: lexicographic');
});

// ---------- loop against a real local app ----------

function demoApp(): { server: Server; port: () => number; close: () => void } {
  const server = createHttpServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    if (url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html', server: 'demo/1.0' });
      res.end('<script src="/app.js"></script><h1>Demo</h1>');
      return;
    }
    if (url.pathname === '/app.js') {
      res.writeHead(200, { 'content-type': 'application/javascript' });
      res.end('fetch("/api/items");');
      return;
    }
    if (url.pathname === '/api/items') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('[1,2,3]');
      return;
    }
    res.writeHead(404); res.end();
  });
  return {
    server,
    port: () => (server.address() as { port: number }).port,
    close: () => server.close(),
  };
}

test('loop: terminates by closure, runs capability-driven engines, deterministic trace', async () => {
  const app = demoApp();
  await new Promise<void>((r) => serverListen(app.server, r));
  const origin = `http://127.0.0.1:${app.port()}`;
  const dir = mkdtempSync(join(tmpdir(), 'ovap-loop-'));
  const db = new Database(dir);
  try {
    const model = new TargetModel(db.handle, 't-loop');
    // seed: crawler already ran and found the homepage + app.js link
    const crawl: CrawlCorpus = {
      pages: [pageOf(`${origin}/`, '<script src="/app.js"></script><h1>Demo</h1>')],
      robots: { disallow: [], fetched: false },
    };
    const registry = new EngineRegistry(loadConfig());
    const config = loadConfig();
    const ctx = {
      db, model, target: { ...TARGET, origin }, mode: 'active' as const,
      registry, config, client: clientFor(origin),
      guard: new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 }),
      stats: { sent: 0, blocked: 0 }, signal: new AbortController().signal,
      workDir: dir, crawl, credentials: undefined, credentialsSecondary: undefined,
    };
    const budget = { maxIterations: 12, maxRequests: 60, maxMs: 60_000, seed: 42 };

    const run1 = await runLoop(ctx as never, budget);
    assert.equal(run1.terminatedBy, 'closure', 'loop must terminate by closure (engines run once)');
    assert.ok(run1.iterations >= 3, 'multiple iterations ran');
    // endpoint-discovery must have run because frontend.spa flipped present
    assert.ok(run1.findings.some((f) => f.provenance[0]?.rawId === 'undocumented-endpoints-discovered'),
      'capability-driven engine ran');

    // determinism: identical seed/budget → identical trace hash on a fresh model
    const db2 = new Database(join(dir, 'two.db'));
    const model2 = new TargetModel(db2.handle, 't-loop');
    const crawl2: CrawlCorpus = {
      pages: [pageOf(`${origin}/`, '<script src="/app.js"></script><h1>Demo</h1>')],
      robots: { disallow: [], fetched: false },
    };
    const ctx2 = { ...ctx, db: db2, model: model2, crawl: crawl2, stats: { sent: 0, blocked: 0 } };
    const run2 = await runLoop(ctx2 as never, budget);
    assert.equal(run2.traceHash, run1.traceHash, 'T3.6: fixed seed + budget ⇒ identical trace');
    db2.close();
  } finally {
    app.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('loop: budget exhaustion terminates and is reported honestly', async () => {
  const app = demoApp();
  await new Promise<void>((r) => serverListen(app.server, r));
  const origin = `http://127.0.0.1:${app.port()}`;
  const dir = mkdtempSync(join(tmpdir(), 'ovap-loop2-'));
  const db = new Database(dir);
  try {
    const model = new TargetModel(db.handle, 't-loop');
    const ctx = {
      db, model, target: { ...TARGET, origin }, mode: 'active' as const,
      registry: new EngineRegistry(loadConfig()), config: loadConfig(),
      client: clientFor(origin),
      guard: new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 }),
      stats: { sent: 0, blocked: 0 }, signal: new AbortController().signal,
      workDir: dir,
      crawl: { pages: [pageOf(`${origin}/`, '<script src="/app.js"></script>')], robots: { disallow: [], fetched: false } },
      credentials: undefined, credentialsSecondary: undefined,
    };
    const res = await runLoop(ctx as never, { maxIterations: 1, maxRequests: 60, maxMs: 60_000, seed: 7 });
    assert.equal(res.terminatedBy, 'budget', 'stopped at iteration cap');
    assert.equal(res.iterations, 1);
  } finally {
    app.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

function serverListen(server: Server, cb: () => void): void {
  server.listen(0, '127.0.0.1', cb);
}

function pageOf(url: string, body: string): CrawlPage {
  return { url, status: 200, truncated: false, headers: { 'content-type': 'text/html' }, body, forms: [], links: [] };
}
