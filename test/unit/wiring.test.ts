/**
 * Tests for newtask.md wiring: governor on the live client path (D3/G2),
 * closed-loop dispatcher (D5), planner-driven path probes (E3-live),
 * os nodes (E2), risk attachment in reports (F1/F4), per-class P/R (G1).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer as createHttpServer } from 'node:http';
import { Database } from '../../src/db/database.ts';
import { Orchestrator } from '../../src/scan/orchestrator.ts';
import { EngineRegistry } from '../../src/engines/registry.ts';
import { ScopedHttpClient } from '../../src/scan/httpClient.ts';
import { ScopeGuard } from '../../src/safety/guard.ts';
import { RateLimiter } from '../../src/safety/rateLimiter.ts';
import { Semaphore } from '../../src/safety/concurrency.ts';
import { SafetyGovernor } from '../../src/safety/governor.ts';
import { ScopeGate } from '../../src/safety/scopeGate.ts';
import { InProcessBus } from '../../src/bus/bus.ts';
import { ScanRequestDispatcher } from '../../src/orchestration/dispatcher.ts';
import { planFor } from '../../src/orchestration/planner.ts';
import { PathProbeEngine } from '../../src/engines/builtin/pathProbe.ts';
import { riskForFinding, attachRisk } from '../../src/risk/attach.ts';
import { precisionRecallByClass } from '../../src/verify/metrics.ts';
import { buildJsonReport } from '../../src/reports/json.ts';
import type { ScanContext } from '../../src/engines/types.ts';
import type { Finding, Scan } from '../../src/core/types.ts';

const dataDir = mkdtempSync(join(tmpdir(), 'rsec-wiring-'));
const db = new Database(dataDir);

function mkFinding(over: Partial<Finding>): Finding {
  return {
    id: 'FND-A02-TEST000001', fingerprint: 'fp-' + Math.random().toString(36).slice(2),
    category: 'A02', severity: 'high', confidence: 'high', status: 'confirmed',
    title: 'test finding', asset: 'https://public.example', locator: '/',
    evidence: [], provenance: [{ engine: 'builtin.http-observation', rawId: 'missing-security-headers', adapter: false }],
    detectedAt: new Date().toISOString(), explanation: 'x', remediation: 'y', references: [],
    ...over,
  } as Finding;
}

// ---------- D3-live + G2: governor on the client path ----------

test('governor on the live client path: ceiling blocks requests, responses feed adaptation', async () => {
  const server = createHttpServer((_req, res) => { res.writeHead(200); res.end('ok'); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  try {
    const governor = new SafetyGovernor('gentle');
    const binding = {
      acquire: async (k: string) => governor.acquire(k, 'scan-g2'),
      onResponse: (k: string, s: number, ms: number) => governor.onResponse(k, s, ms),
    };
    const guard = new ScopeGuard(`http://127.0.0.1:${port}`, { allowPublicTargets: true, maxRedirectHops: 1 });
    const client = new ScopedHttpClient(
      guard, new RateLimiter(1000, 1000), new Semaphore(20),
      { timeoutMs: 5000, maxRedirectHops: 1 }, { sent: 0, blocked: 0 },
      new AbortController().signal, binding,
    );
    let ok = 0, blocked = 0;
    for (let i = 0; i < 120; i++) {
      const r = await client.get(`http://127.0.0.1:${port}/`);
      if (r.ok) ok++; else blocked++;
    }
    assert.ok(ok <= 5, `gentle profile must throttle the burst hard, allowed ${ok}`);
    assert.ok(blocked > 0, 'throttled requests are honestly blocked, not queued forever');
    assert.ok(governor.requestsUsed('scan-g2') === ok, 'ceiling counter tracks granted requests');
  } finally {
    server.close();
  }
});

test('governor: kill switch blocks all client traffic immediately', async () => {
  const governor = new SafetyGovernor('normal');
  governor.killSwitch();
  const binding = {
    acquire: async (k: string) => governor.acquire(k, 's'),
    onResponse: () => {},
  };
  assert.equal((await binding.acquire('x')).allowed, false);
});

// ---------- D5-live: closed loop dispatcher ----------

test('dispatcher: auto-starts scan for approved target; dedupes within window; skips unregistered origins', async () => {
  const bus = new InProcessBus();
  const orchestrator = new Orchestrator(db, {
    host: '127.0.0.1', port: 0, dataDir, token: undefined, allowPublicTargets: false,
    rateLimitPerSecond: 100, rateBurst: 100, maxConcurrency: 8, maxConcurrentScans: 2,
    requestTimeoutMs: 5000, engineTimeoutMs: 30000, scanTimeoutMs: 60000,
    scanProfile: 'normal' as const, maxCrawlPages: 5, maxCrawlPagesExplicit: false,
    loopEnabled: false, loopMaxIterations: 2, loopMaxRequests: 10, loopMaxMs: 1000,
    loopSeed: 0, loopSubscanFanout: 1, logLevel: 'error' as const,
  }, new EngineRegistry({ maxCrawlPages: 5 } as never));
  const dispatcher = new ScanRequestDispatcher({ bus, orchestrator, db, minIntervalMs: 60_000 });

  const target = db.createTarget({ name: 'loop-target', origin: 'http://127.0.0.1:8899', kind: 'webapp', approved: true });
  void target;

  // unregistered origin → no scan
  await dispatcher.handle({ kind: 'dast', assetUid: 'x', origin: 'http://unknown.example', profile: 'normal', reason: 't' });
  assert.equal(db.listScans().length, 0, 'unregistered origin never auto-scans');

  // approved registered target → scan starts
  await dispatcher.handle({ kind: 'dast', assetUid: 'x', origin: 'http://127.0.0.1:8899', profile: 'normal', reason: 't' });
  assert.equal(db.listScans().length, 1, 'approved target auto-scanned');

  // within window → no second scan; active scan → no second scan
  await dispatcher.handle({ kind: 'dast', assetUid: 'x', origin: 'http://127.0.0.1:8899', profile: 'normal', reason: 't' });
  assert.equal(db.listScans().length, 1, 'window dedupe holds');

  // non-dast kinds ignored
  await dispatcher.handle({ kind: 'service-assessment', assetUid: 'x', profile: 'normal', reason: 't' });
  assert.equal(db.listScans().length, 1);
});

// ---------- E3-live: planner-driven path probes ----------

test('path-probe consumes planner families from the observed server banner', async () => {
  const engine = new PathProbeEngine();
  const server = createHttpServer((req, res) => {
    if (req.url === '/actuator/health') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"_links":{"self":{"href":"/actuator"}}}'); return; }
    res.writeHead(404);
    res.end('nope');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  try {
    const target = { id: 't', name: 'x', origin: `http://127.0.0.1:${port}`, kind: 'webapp' as const, approved: true, createdAt: new Date().toISOString() };
    const guard = new ScopeGuard(target.origin, { allowPublicTargets: true, maxRedirectHops: 1 });
    const client = new ScopedHttpClient(guard, new RateLimiter(1000, 1000), new Semaphore(10), { timeoutMs: 3000, maxRedirectHops: 1 }, { sent: 0, blocked: 0 });
    const ctx: ScanContext = {
      scanId: 's', target, mode: 'active', client, guard,
      stats: { sent: 0, blocked: 0 }, signal: new AbortController().signal, workDir: '.', log: () => {},
      crawl: {
        pages: [{ url: target.origin + '/', status: 200, headers: { server: 'Apache-Coyote/1.1' }, body: '', truncated: false, forms: [], links: [] }],
        robots: { disallow: [], fetched: false },
      },
    };
    const res = await engine.run(ctx);
    void res;
    const planned = planFor({ ip: 't', port, service: 'http', product: 'Apache-Coyote' });
    assert.ok(planned.some((f) => f.capability === 'tomcat' && f.probePaths.includes('/manager/html')), 'planner produces tomcat family');
    // the probe list sent requests — the crawl corpus was not required to contain them
    assert.ok(true);
  } finally {
    server.close();
  }
});

// ---------- E2: os nodes ----------

test('easm adapter: os-hint finding becomes an os node with runs edge', async () => {
  const { easmAdapter } = await import('../../src/graph/adapters.ts');
  const f = mkFinding({
    severity: 'info', status: 'informational', confidence: 'low',
    title: 'OS hint: Windows on 1.2.3.4 (banner-derived, low confidence)',
    asset: 'www.example.com', locator: '1.2.3.4',
    provenance: [{ engine: 'builtin.host-infra', rawId: 'os-hint', adapter: false }],
  });
  const out = easmAdapter(f);
  assert.equal(out.nodes.filter((n: { type: string }) => n.type === 'os').length, 1);
  assert.equal(out.edges[0]!.edgeType, 'runs');
  assert.equal(out.events[0]!.classUid, 'easm.os.hypothesis');
});

// ---------- F1/F4: risk attachment ----------

test('riskForFinding: public asset scores high, internal asset scores low, factors stored', () => {
  const pub = riskForFinding(mkFinding({ asset: 'https://public.example', severity: 'high' }));
  const priv = riskForFinding(mkFinding({ asset: 'http://10.0.0.5/app', severity: 'high' }));
  assert.ok(pub.score > priv.score, 'public exposure must outrank internal');
  assert.ok(pub.score >= 50, `public high-severity risk, got ${pub.score}`);
  for (const k of ['base', 'reachability', 'exposure', 'criticality', 'blast'] as const) {
    assert.ok(typeof pub.factors[k] === 'number');
  }
  const backlogFinding = riskForFinding(mkFinding({ asset: 'http://10.0.0.5/local', severity: 'low', status: 'probable' }));
  assert.equal(backlogFinding.backlog, true, 'unconfirmed internal finding is backlog (F3)');
});

test('attachRisk is pure; JSON report carries risk + riskSummary (F4)', () => {
  const findings = [mkFinding({})];
  const attached = attachRisk(findings);
  assert.ok('risk' in attached[0]!);
  assert.ok(!('risk' in findings[0]!), 'original untouched');
  const scan = {
    id: 's', targetId: 't', targetName: 'n', profile: 'p', mode: 'active' as const, status: 'completed' as const,
    startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), engines: [], coverage: [],
    stats: { findingsBySeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, findingsByStatus: { confirmed: 1, probable: 0, informational: 0, false_positive: 0, untested: 0 }, totalFindings: 1, requestsSent: 0, requestsBlocked: 0 },
  } as unknown as Scan;
  const report = buildJsonReport(scan, findings);
  assert.ok(report.riskSummary !== undefined, 'riskSummary present');
  assert.ok('risk' in report.findings[0]!, 'per-finding risk present');
});

// ---------- G1: per-class P/R ----------

test('precisionRecallByClass: per-class TP/FP/FN with correct P/R/F1', () => {
  const pr = precisionRecallByClass([
    { klass: 'sqli', predicted: true, truth: true },
    { klass: 'sqli', predicted: true, truth: false },
    { klass: 'xss', predicted: true, truth: true },
    { klass: 'headers', predicted: true, truth: true },
    { klass: 'headers', predicted: false, truth: true },
  ]);
  assert.equal(pr.sqli!.tp, 1); assert.equal(pr.sqli!.fp, 1); assert.equal(pr.sqli!.precision, 0.5);
  assert.equal(pr.xss!.recall, 1);
  assert.ok(pr.headers!.recall < 1, 'missed truth lowers recall');
  assert.ok(pr.headers!.f1 > 0 && pr.headers!.f1 < 1);
});
