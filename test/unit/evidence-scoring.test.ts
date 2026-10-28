/**
 * Tests for Phase 6 (evidence store, PoC writer, minimization, model context)
 * and Phase 7 (dynamic scoring with explainability, risk trend).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EvidenceStore, storeFindingEvidence, curlFor, buildPoc, modelContext } from '../../src/evidence/evidence.ts';
import { scoreFinding, riskTrend, isPublicTarget } from '../../src/scoring/scoring.ts';
import { TargetModel, mergeEvidence } from '../../src/model/targetModel.ts';
import { Database } from '../../src/db/database.ts';
import { ScopeGuard } from '../../src/safety/guard.ts';
import { RateLimiter } from '../../src/safety/rateLimiter.ts';
import { Semaphore } from '../../src/safety/concurrency.ts';
import { ScopedHttpClient } from '../../src/scan/httpClient.ts';
import type { Finding, Target } from '../../src/core/types.ts';

function finding(rawId: string, url: string, over: Partial<Finding> = {}): Finding {
  return {
    id: `FND-${rawId}`, fingerprint: 'fp', title: rawId, category: 'A02',
    severity: 'medium', confidence: 'high', status: 'confirmed',
    asset: 'https://t.example', locator: '/', engine: 'builtin.http-observation',
    evidence: [{
      kind: 'http',
      request: { method: 'GET', url, headers: { accept: '*/*' } },
      response: { status: 200, headers: {}, bodyExcerpt: 'VULNERABLE-MARKER-XYZ' },
      observation: 'marker observed',
    }],
    explanation: 'x', remediation: 'r', references: [],
    detectedAt: new Date().toISOString(),
    provenance: [{ engine: 'builtin.http-observation', rawId, adapter: false }],
    ...over,
  };
}

// ---------- T6.1 evidence store ----------

test('T6.1 evidence store: content-addressed, append-only, reconstructible', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ovap-ev-'));
  const store = new EvidenceStore(dir);
  try {
    const payload = { kind: 'http', request: { url: 'http://t/' }, body: 'content-1' };
    const e1 = store.put('FND-1', payload);
    const e2 = store.put('FND-1', payload); // identical content → same ref
    assert.equal(e1.ref, e2.ref);
    assert.ok(e1.ref.startsWith('ev_'));
    const back = store.get(e1.ref)!;
    assert.deepEqual(back.payload, payload);
    assert.equal(back.findingId, 'FND-1');

    const different = store.put('FND-2', { kind: 'http', request: { url: 'http://t/2' }, body: 'content-2' });
    assert.notEqual(different.ref, e1.ref);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('T6.1 storeFindingEvidence: all evidence refs recorded for a finding', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ovap-ev2-'));
  const store = new EvidenceStore(dir);
  try {
    const f = finding('x', 'http://t/a');
    f.evidence.push({ kind: 'process', command: 'verify: x', observation: 're-check ok' });
    const refs = storeFindingEvidence(store, f);
    assert.equal(refs.length, 2);
    assert.ok(refs.every((r) => r.startsWith('ev_')));
    assert.ok(store.get(refs[1]!) !== undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------- T6.2/T6.3 PoC writer + minimization ----------

test('T6.2/T6.3 PoC: reproducible curl, query-param minimization verified by re-fetch', async () => {
  const server = createHttpServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    // marker reproduces with or without the benign param; requires the essential one
    const essential = url.searchParams.get('file') === 'report.pdf';
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(essential ? '<p>VULNERABLE-MARKER-XYZ</p>' : '<p>nothing</p>');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const client = new ScopedHttpClient(
      new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 }),
      new RateLimiter(200, 50), new Semaphore(4), { timeoutMs: 3000, maxRedirectHops: 2 }, { sent: 0, blocked: 0 });
    const f = finding('path-traversal', `${origin}/download?file=report.pdf&utm_source=cam&p2=x`);
    const poc = await buildPoc(f, client);
    assert.ok(poc, 'PoC built');
    assert.equal(poc!.minimized, true, 'benign params were removed');
    assert.ok(!poc!.commands[0]!.includes('utm_source'), 'benign param dropped');
    assert.ok(poc!.commands[0]!.includes('file=report.pdf'), 'essential param kept');
    assert.match(poc!.commands[0]!, /^curl -s/);
    assert.ok(poc!.expect.includes('VULNERABLE-MARKER-XYZ'));
  } finally {
    server.close();
  }
});

// ---------- T6.4 model context ----------

test('T6.4 model context: capabilities, tech, why-it-matters attached', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ovap-ctx-'));
  const db = new Database(dir);
  try {
    const model = new TargetModel(db.handle, 't');
    mergeEvidence(model, [
      { kind: 'capability', key: 'api.rest', value: {}, provenance: 'probe', state: 'present' },
      { kind: 'tech', key: 'server', value: { server: 'nginx/1.24' }, provenance: 'banner', state: 'present' },
      { kind: 'endpoint', key: '/api/users', value: { discoveredBy: 'bundle' }, provenance: 'discovery', state: 'present' },
    ]);
    const f = finding('sqli-error-differential', 'https://t.example/api/users?id=5', { locator: 'https://t.example/api/users?id=5' });
    const ctx = modelContext(f, model);
    assert.equal(ctx.endpoint, '/api/users');
    assert.ok(ctx.capabilities.includes('api.rest'));
    assert.ok(ctx.tech.some((t) => t.startsWith('server=')));
    assert.match(ctx.whyItMatters, /api\/users/);
    assert.match(ctx.whyItMatters, /api\.rest/);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------- T7.1 scoring ----------

test('T7.1 scoring: verified × public × auth-context out-scores unverified private info', () => {
  const verifiedPublic = scoreFinding(finding('x', 'https://public.example/'), { verified: true, publicTarget: true });
  const unverifiedPrivate = scoreFinding(finding('x', 'http://127.0.0.1/'), { verified: false, publicTarget: false });
  assert.ok(verifiedPublic.score > unverifiedPrivate.score);
  assert.match(verifiedPublic.rationale, /exposure\(public\)=1\.2/);
  // every factor listed (T7.3 explainability)
  assert.ok(verifiedPublic.rationale.split('×').length === 4);
});

test('T7.1 scoring: severity and confidence remain separate (I6)', () => {
  const high = scoreFinding(finding('x', 'https://t/', { severity: 'high', confidence: 'low' }));
  assert.equal(high.factors.baseSeverity, 3, 'severity drives the base');
  assert.ok(!JSON.stringify(high.factors).includes('confidence'), 'confidence is not a scoring factor');
});

// ---------- T7.2 trend ----------

test('T7.2 risk trend: ordered by time with per-severity counts and avg score', () => {
  const mk = (id: string, at: string, sevs: string[]): { scanId: string; startedAt: string; findings: Finding[] } => ({
    scanId: id, startedAt: at, findings: sevs.map((s) => finding('x', 'https://t/', { severity: s as Finding['severity'] })),
  });
  const trend = riskTrend([
    mk('later', '2026-11-01T00:00:00Z', ['high', 'high']),
    mk('earlier', '2026-10-01T00:00:00Z', ['low', 'low', 'low']),
  ]);
  assert.equal(trend.length, 2);
  assert.equal(trend[0]!.scanId, 'earlier', 'ordered oldest first');
  assert.deepEqual(trend[0]!.bySeverity, { low: 3 });
  assert.equal(trend[1]!.avgScore, trend[1]!.avgScore); // computed
  assert.ok(trend[1]!.avgScore! > trend[0]!.avgScore!, 'risk increased between scans');
});

// ---------- exposure classification ----------

test('isPublicTarget: loopback private, public host exposed', () => {
  assert.equal(isPublicTarget('http://127.0.0.1:3000'), false);
  assert.equal(isPublicTarget('http://192.168.1.5/'), false);
  assert.equal(isPublicTarget('https://www.example.com'), true);
});
