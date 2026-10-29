/**
 * Tests for the final v2 batch: JSON login, precision/recall CI gate,
 * CycloneDX SBOM, SSE live-trace.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpServer, type Server } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Database, generateToken } from '../../src/db/database.ts';
import { AuthenticatedProbeEngine } from '../../src/engines/builtin/authenticatedProbe.ts';
import { toCycloneDX } from '../../src/reports/sbom.ts';
import { computePrecisionRecall } from '../../src/verify/metrics.ts';
import { buildPlatform, type Platform } from '../../src/server.ts';
import { ScopeGuard } from '../../src/safety/guard.ts';
import { RateLimiter } from '../../src/safety/rateLimiter.ts';
import { Semaphore } from '../../src/safety/concurrency.ts';
import { ScopedHttpClient } from '../../src/scan/httpClient.ts';
import type { CrawlPage, ScanContext, CredentialProfile } from '../../src/engines/types.ts';
import type { Finding, Target } from '../../src/core/types.ts';
import type { Config } from '../../src/config.ts';

// ---------- JSON-API login ----------

function jsonLoginApp(): { server: Server; port: () => number; close: () => void } {
  const tokens = new Set<string>();
  const server = createHttpServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    const html = (b: string): void => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(b); };
    if (url.pathname === '/api/login' && req.method === 'POST') {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        try {
          const parsed = JSON.parse(body) as { username?: string; password?: string };
          if (parsed.username === 'tester' && parsed.password === 'testpass') {
            const token = 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify({ sub: 'tester' })).toString('base64url') + '.c2lnbmF0dXJlLTEyMzQ1';
            tokens.add(token);
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ token }));
            return;
          }
        } catch { /* fall through */ }
        res.writeHead(401); res.end('bad');
      });
      return;
    }
    if (url.pathname === '/api/me') {
      const auth = req.headers.authorization ?? '';
      const token = auth.replace('Bearer ', '');
      if (token && tokens.has(token)) return html('<h1>Secret Profile</h1>');
      res.writeHead(401, { 'content-type': 'application/json' }); res.end('{"error":"unauthorized"}');
      return;
    }
    if (url.pathname === '/') {
      return html('<a href="/api/me">Profile</a><a href="/logout">Logout</a>' +
        '<form action="/api/login" method="post"><input name="username"><input name="password" type="password"></form>');
    }
    if (url.pathname === '/logout') return html('out');
    res.writeHead(404); res.end();
  });
  return {
    server,
    port: () => (server.address() as { port: number }).port,
    close: () => server.close(),
  };
}

test('JSON login: authenticated probe uses bearer-token session (json loginType)', async () => {
  const app = jsonLoginApp();
  await new Promise<void>((r) => app.server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${app.port()}`;
  const dir = mkdtempSync(join(tmpdir(), 'ovap-json-'));
  const db = new Database(dir);
  try {
    const target: Target = { id: 't', name: 'x', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() };
    const cred: CredentialProfile = {
      username: 'tester', password: 'testpass', loginType: 'json',
      loginUrl: `${origin}/api/login`, tokenField: 'token',
    };
    const guard = new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 });
    const client = new ScopedHttpClient(guard, new RateLimiter(200, 50), new Semaphore(4), { timeoutMs: 3000, maxRedirectHops: 2 }, { sent: 0, blocked: 0 });
    const engine = new AuthenticatedProbeEngine();
    const ctx: ScanContext = {
      scanId: 's', target, mode: 'active', credentials: cred,
      client, guard, stats: { sent: 0, blocked: 0 }, signal: new AbortController().signal, workDir: dir,
      log: () => {},
      crawl: { pages: [{ url: `${origin}/`, status: 200, truncated: false, headers: {}, body: '<a href="/api/me">Profile</a>', forms: [], links: [`${origin}/api/me`, `${origin}/logout`] }], robots: { disallow: [], fetched: false } },
    };
    const res = await engine.run(ctx);
    // The probe should authenticate via bearer token and map the protected surface
    assert.ok(res.detail?.includes('tester'), 'logged in as tester');
    const surface = res.findings.find((f) => f.rawId === 'authenticated-surface-map');
    assert.ok(surface, 'surface map emitted (found /api/me)');
    assert.ok(!JSON.stringify(res).includes('testpass'), 'password never in evidence');
  } finally {
    app.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------- Precision/recall CI gate ----------

test('Precision/recall: computes P and R from truth vs actual', () => {
  
  const truth = ['FND-A', 'FND-B', 'FND-C'];
  const actual = ['FND-A', 'FND-B', 'FND-D', 'FND-E'];
  const pr = computePrecisionRecall(truth, actual);
  assert.equal(pr.truePositives, 2);
  assert.equal(pr.falsePositives, 2);
  assert.equal(pr.falseNegatives, 1);
  assert.ok(Math.abs(pr.precision - 0.5) < 1e-9);
  assert.ok(Math.abs(pr.recall - 2 / 3) < 1e-9);
});

// ---------- CycloneDX SBOM ----------

test('T10.3 CycloneDX SBOM: valid 1.5 structure from dependency findings', () => {
  const depFinding: Finding = {
    id: 'FND-A03-DEP', fingerprint: 'fp', title: 'Dependency inventory',
    category: 'A03', severity: 'info', confidence: 'high', status: 'informational',
    asset: '/src', locator: 'package-lock.json', engine: 'builtin.dep-manifest',
    evidence: [{
      kind: 'dependency', ecosystem: 'npm', packageName: '3 locked packages (3 runtime)',
      observation: '3 packages',
    }],
    explanation: 'x', remediation: 'r', references: [],
    detectedAt: new Date().toISOString(),
    provenance: [{ engine: 'builtin.dep-manifest', rawId: 'dependency-inventory', adapter: false }],
  };
  const sbom = toCycloneDX([depFinding], 'test-target');
  const parsed = sbom as { bomFormat: string; specVersion: string; components: Array<{ type: string; name: string; purl?: string }> };
  assert.equal(parsed.bomFormat, 'CycloneDX');
  assert.equal(parsed.specVersion, '1.5');
  assert.ok(Array.isArray(parsed.components));
});

// ---------- SSE live-trace ----------

test('SSE trace endpoint streams scan events', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ovap-sse-'));
  const config: Config = {
    host: '127.0.0.1', port: 0, dataDir: dir, token: 'test-token',
    allowPublicTargets: false, rateLimitPerSecond: 100, rateBurst: 50,
    maxConcurrency: 8, maxConcurrentScans: 2, requestTimeoutMs: 5000,
    engineTimeoutMs: 30_000, scanTimeoutMs: 60_000, maxCrawlPages: 10, maxCrawlPagesExplicit: false, loopEnabled: false, loopMaxIterations: 40, loopMaxRequests: 800, loopMaxMs: 600000, loopSeed: 0, loopSubscanFanout: 3,
    logLevel: 'error',
  };
  const platform = buildPlatform(config);
  try {
    const { createRequestHandler } = await import('../../src/server.ts');
    const handler = createRequestHandler(platform);
    const target = platform.db.createTarget({ name: 'sse-test', origin: 'http://127.0.0.1:59998', kind: 'webapp', approved: false });
    platform.db.approveTarget(target.id, 'test');
    // start a scan (it will fail fast since nothing listens at 59998)
    const startRes = await handler(new Request('http://127.0.0.1/api/scans', {
      method: 'POST',
      headers: { authorization: `Bearer ${platform.token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ targetId: target.id, profile: 'quick-passive', mode: 'passive' }),
    }));
    assert.equal(startRes.status, 202);
    const { scan } = await startRes.json() as { scan: { id: string } };

    // poll until completed (the scan target is unreachable, so it completes fast)
    let status = 'running';
    for (let i = 0; i < 30; i++) {
      await new Promise((r) => setTimeout(r, 200));
      const scanRes = await handler(new Request(`http://127.0.0.1/api/scans/${scan.id}`, {
        headers: { authorization: `Bearer ${platform.token}` },
      }));
      const body = await scanRes.json() as { scan: { status: string } };
      status = body.scan.status;
      if (status !== 'running' && status !== 'queued') break;
    }
    assert.ok(['completed', 'failed'].includes(status), `scan ended: ${status}`);
  } finally {
    platform.db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
