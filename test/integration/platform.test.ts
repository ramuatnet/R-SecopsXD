/**
 * Integration tests: persistence layer + API surface (handlers exercised
 * through the real request pipeline without opening a socket).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildPlatform, createRequestHandler, type Platform } from '../../src/server.ts';
import type { Config } from '../../src/config.ts';

function testConfig(dir: string): Config {
  return {
    host: '127.0.0.1', port: 0, dataDir: dir, token: undefined,
    allowPublicTargets: false, rateLimitPerSecond: 100, rateBurst: 50,
    maxConcurrency: 8, maxConcurrentScans: 2, requestTimeoutMs: 5000,
    engineTimeoutMs: 30_000, scanTimeoutMs: 60_000, maxCrawlPages: 10, maxCrawlPagesExplicit: false, loopEnabled: false, loopMaxIterations: 40, loopMaxRequests: 800, loopMaxMs: 600000, loopSeed: 0, loopSubscanFanout: 3,
    logLevel: 'error',
  };
}

let platform: Platform;
let handler: (req: Request) => Promise<Response>;
let dir: string;

test.before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'ovap-int-'));
  platform = buildPlatform(testConfig(dir));
  handler = createRequestHandler(platform);
});

test.after(() => {
  platform.db.close();
  rmSync(dir, { recursive: true, force: true });
});

function req(method: string, path: string, body?: unknown, token?: string): Request {
  const headers: Record<string, string> = {};
  if (token) headers.authorization = `Bearer ${token}`;
  const init: RequestInit = { method, headers };
  if (body !== undefined) init.body = JSON.stringify(body);
  return new Request(`http://127.0.0.1:7788${path}`, init);
}

// ---------- auth (AC2) ----------

test('mutating API routes reject missing/invalid tokens', async () => {
  const noToken = await handler(req('POST', '/api/targets', { name: 'x', kind: 'webapp', origin: 'http://127.0.0.1:1' }));
  assert.equal(noToken.status, 401);

  const badToken = await handler(req('GET', '/api/targets', undefined, 'wrong-token'));
  assert.equal(badToken.status, 401);

  const good = await handler(req('GET', '/api/targets', undefined, platform.token));
  assert.equal(good.status, 200);
});

test('health endpoint is unauthenticated', async () => {
  const res = await handler(req('GET', '/api/health'));
  assert.equal(res.status, 200);
  const body = await res.json() as { ok: boolean };
  assert.equal(body.ok, true);
});

test('failed auth attempts are audited', async () => {
  await handler(req('GET', '/api/targets', undefined, 'bad-token-abc'));
  const audit = await (await handler(req('GET', '/api/audit', undefined, platform.token))).json() as { entries: Array<{ action: string }> };
  assert.ok(audit.entries.some((e) => e.action === 'auth.failed'));
});

// ---------- targets lifecycle (AC3) ----------

let targetId = '';

test('register webapp target: origin normalized, approval separate', async () => {
  const res = await handler(req('POST', '/api/targets', {
    name: 'Local Test App', kind: 'webapp', origin: 'http://127.0.0.1:8899/',
  }, platform.token));
  assert.equal(res.status, 201);
  const { target } = await res.json() as { target: { id: string; origin: string; approved: boolean } };
  assert.equal(target.origin, 'http://127.0.0.1:8899');
  assert.equal(target.approved, false);
  targetId = target.id;
});

test('scanning an unapproved target is refused with 409 (AC3)', async () => {
  const res = await handler(req('POST', '/api/scans', {
    targetId, profile: 'quick-passive', mode: 'passive',
  }, platform.token));
  assert.equal(res.status, 409);
  const body = await res.json() as { error: string };
  assert.equal(body.error, 'target_not_approved');
});

test('approve target records approval and audit entry', async () => {
  const res = await handler(req('POST', `/api/targets/${targetId}/approve`, undefined, platform.token));
  assert.equal(res.status, 200);
  const { target } = await res.json() as { target: { approved: boolean; approvedBy: string } };
  assert.equal(target.approved, true);
  const audit = await (await handler(req('GET', '/api/audit', undefined, platform.token))).json() as { entries: Array<{ action: string }> };
  assert.ok(audit.entries.some((e) => e.action === 'target.approved'));
});

test('public-internet target refused while allowPublicTargets=false (AC6)', async () => {
  const res = await handler(req('POST', '/api/targets', {
    name: 'Public', kind: 'webapp', origin: 'https://example.com',
  }, platform.token));
  assert.equal(res.status, 403);
  const body = await res.json() as { error: string };
  assert.equal(body.error, 'public_target_forbidden');
});

test('source target requires sourcePath; unknown profile refused', async () => {
  const missing = await handler(req('POST', '/api/targets', { name: 's', kind: 'source' }, platform.token));
  assert.equal(missing.status, 400);

  const badProfile = await handler(req('POST', '/api/scans', {
    targetId, profile: 'nonexistent', mode: 'passive',
  }, platform.token));
  assert.equal(badProfile.status, 400);
});

// ---------- profiles/engines metadata ----------

test('profiles list includes engine plan and target kinds', async () => {
  const res = await handler(req('GET', '/api/profiles', undefined, platform.token));
  const { profiles } = await res.json() as { profiles: Array<{ id: string; activeEngines: string[] }> };
  assert.ok(profiles.some((p) => p.id === 'standard-active' && p.activeEngines.includes('builtin.path-probe')));
});

test('engines list reports availability for every engine without crashing', async () => {
  const res = await handler(req('GET', '/api/engines', undefined, platform.token));
  assert.equal(res.status, 200);
  const { engines } = await res.json() as { engines: Array<{ id: string; availability: { available: boolean; reason?: string } }> };
  assert.ok(engines.length >= 12);
  for (const e of engines) {
    assert.ok(e.availability, `${e.id} must report availability`);
    if (!e.availability.available) {
      assert.ok(e.availability.reason, `${e.id} unavailable must carry a reason`);
    }
  }
});

test('owasp catalog endpoint exposes honest automation notes', async () => {
  const res = await handler(req('GET', '/api/owasp', undefined, platform.token));
  const { categories } = await res.json() as { categories: Array<{ code: string; automation: string; reference: string }> };
  assert.equal(categories.length, 10);
  for (const c of categories) {
    assert.ok(c.automation.length > 40);
    assert.ok(c.reference.startsWith('https://'));
  }
});

// ---------- scan lifecycle with a failing engine (AC20) ----------

test('scan completes and records engine failure when an engine crashes', async () => {
  // Build an isolated platform whose orchestrator uses a registry stub with a
  // crashing engine, through the public startScan path.
  const { Orchestrator } = await import('../../src/scan/orchestrator.ts');
  const crashing = {
    create: (id: string) => {
      if (id === 'builtin.http-observation') {
        return {
          info: { id, name: id, kind: 'builtin', capabilities: {}, modes: ['passive'], targetKinds: ['webapp'] },
          availability: async () => ({ available: true, version: 'stub' }),
          run: async () => { throw new Error('engine exploded (test)'); },
        };
      }
      return undefined; // unknown → skipped
    },
    allEngineIds: () => ['builtin.http-observation'],
    availability: async () => ({ available: true }),
  };
  const orch = new Orchestrator(
    platform.db,
    testConfig(dir),
    crashing as never,
  );
  const scan = await orch.startScan(targetId, 'quick-passive', 'passive');
  await waitForScan(scan.id);

  const stored = platform.db.getScan(scan.id)!;
  assert.equal(stored.status, 'completed', 'scan completes despite engine failure');
  const obs = stored.engines.find((e) => e.engine === 'builtin.http-observation');
  assert.ok(obs);
  assert.equal(obs.status, 'failed');
  assert.match(obs.detail ?? '', /engine exploded/);
});

// ---------- audit trail (AC10) ----------

test('target register/approve/scan/export produce audit entries', async () => {
  const audit = await (await handler(req('GET', '/api/audit', undefined, platform.token))).json() as { entries: Array<{ action: string }> };
  const actions = audit.entries.map((e) => e.action);
  for (const expected of ['target.registered', 'target.approved', 'scan.started', 'scan.completed']) {
    assert.ok(actions.includes(expected), `missing audit action ${expected}`);
  }
});

// ---------- report endpoint (auth + format) ----------

test('report endpoint requires auth and serves json/html/pdf', async () => {
  const scans = await (await handler(req('GET', '/api/scans', undefined, platform.token))).json() as { scans: Array<{ id: string }> };
  const scanId = scans.scans[0]!.id;

  const noAuth = await handler(req('GET', `/api/scans/${scanId}/report?format=json`));
  assert.equal(noAuth.status, 401);

  for (const format of ['json', 'html', 'pdf']) {
    const res = await handler(req('GET', `/api/scans/${scanId}/report?format=${format}`, undefined, platform.token));
    assert.equal(res.status, 200, format);
    const buf = await res.arrayBuffer();
    assert.ok(buf.byteLength > 500, `${format} report should have content`);
  }

  const bad = await handler(req('GET', `/api/scans/${scanId}/report?format=xml`, undefined, platform.token));
  assert.equal(bad.status, 400);
});

// ---------- helper ----------

async function waitForScan(scanId: string, timeoutMs = 30_000): Promise<void> {
  const start = Date.now();
  for (;;) {
    const scan = platform.db.getScan(scanId);
    if (scan && !['queued', 'running'].includes(scan.status)) return;
    if (Date.now() - start > timeoutMs) throw new Error(`scan ${scanId} did not finish in ${timeoutMs}ms`);
    await new Promise((r) => setTimeout(r, 100));
  }
}
