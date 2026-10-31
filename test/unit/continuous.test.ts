/**
 * Tests for continuous security (T9.1/T9.2) and SARIF export (T10.3).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpServer, type Server } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ScanScheduler, originChanged, deliverWebhook, alertOnNewFindings, toSarif } from '../../src/continuous/continuous.ts';
import { Database } from '../../src/db/database.ts';

test('T9.1 scheduler: fires on interval, stop clears timers', async () => {
  let fires = 0;
  const scheduler = new ScanScheduler({
    intervalMs: 50,
    onFire: async () => { fires++; },
  });
  scheduler.start(['t1', 't2']);
  await new Promise((r) => setTimeout(r, 180));
  scheduler.stop();
  assert.ok(fires >= 2, `two targets × ~3 intervals → fires=${fires}`);
  const before = fires;
  await new Promise((r) => setTimeout(r, 120));
  assert.equal(fires, before, 'stop clears the timers');
});

test('T9.1 scheduler: errors are caught, never crash the interval', async () => {
  let fires = 0;
  const scheduler = new ScanScheduler({
    intervalMs: 40,
    onFire: async (id) => {
      fires++;
      if (id === 'bad') throw new Error('boom');
    },
    onError: () => {},
  });
  scheduler.start(['bad', 'good']);
  await new Promise((r) => setTimeout(r, 150));
  scheduler.stop();
  assert.ok(fires >= 2);
});

test('T9.1 originChanged: first observation stores baseline (no change), different content triggers', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ovap-watch-'));
  const db = new Database(dir);
  let body = 'version-1';
  const server = createHttpServer((_req, res) => { res.writeHead(200); res.end(body); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const client = { get: async (url: string) => ({ ok: true, body, headers: {} }) };
    const first = await originChanged(db, 't1', origin, client);
    assert.equal(first, false, 'first observation stores baseline, no change');
    const same = await originChanged(db, 't1', origin, client);
    assert.equal(same, false, 'unchanged content → no trigger');
    body = 'version-2 completely different';
    const changed = await originChanged(db, 't1', origin, client);
    assert.equal(changed, true, 'content change triggers targeted rescan');
  } finally {
    server.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('T9.2 webhook alerting: payload delivered with findings and score', async () => {
  let received: { body: string } | undefined;
  const hook = createHttpServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      received = { body };
      res.writeHead(200); res.end('ok');
    });
  });
  await new Promise<void>((r) => hook.listen(0, '127.0.0.1', r));
  const hookUrl = `http://127.0.0.1:${(hook.address() as { port: number }).port}/hook`;

  const dir = mkdtempSync(join(tmpdir(), 'ovap-hook-'));
  const db = new Database(dir);
  try {
    const mk = (id: string, fps: string[]): void => {
      db.insertScan({
        id, targetId: 't1', targetName: 'hook-target', profile: 'p', mode: 'passive',
        status: 'completed', startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(),
        engines: [], coverage: [], stats: {
          findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          findingsByStatus: { confirmed: 0, probable: 0, informational: 0, false_positive: 0, untested: 0 , rejected_by_verification: 0 },
          totalFindings: fps.length, requestsSent: 0, requestsBlocked: 0,
        },
      });
      db.insertFindings(id, fps.map((fp) => ({
        id: `FND-${fp}`, fingerprint: fp, title: `finding ${fp}`, category: 'A01',
        severity: 'high', confidence: 'high', status: 'confirmed', asset: 'a', locator: '/',
        engine: 'e', evidence: [], explanation: 'x', remediation: 'r', references: [],
        detectedAt: new Date().toISOString(), provenance: [{ engine: 'e', adapter: false }],
      })));
    };
    mk('old-scan', ['fp-shared', 'fp-removed']);
    mk('new-scan', ['fp-shared', 'fp-new']);

    const { alerted, newCount } = await alertOnNewFindings(db, 't1', (f) => 9.9, hookUrl);
    assert.equal(newCount, 1, 'one new finding (fp-new)');
    assert.equal(alerted, true);
    const payload = JSON.parse(received!.body) as { newFindings: Array<{ title: string; score?: number }> };
    assert.equal(payload.newFindings.length, 1);
    assert.equal(payload.newFindings[0]!.score, 9.9);

    // second alert with no new findings → not sent
    const second = await alertOnNewFindings(db, 't1', undefined, hookUrl);
    assert.equal(second.alerted, false, 'no new findings → no alert');
  } finally {
    hook.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------- T10.3 SARIF ----------

test('T10.3 SARIF export: valid 2.1.0 structure with rules and results', () => {
  const findings = [{
    id: 'FND-A02-TEST', fingerprint: 'fp1', title: 'Missing header', category: 'A02',
    severity: 'high' as const, confidence: 'high' as const, status: 'confirmed' as const,
    asset: 'https://t', locator: '/', engine: 'e', evidence: [], explanation: 'explanation',
    remediation: 'r', references: [], detectedAt: new Date().toISOString(),
    provenance: [{ engine: 'e', rawId: 'missing-header', adapter: false }],
    cwe: 693,
  }];
  const sarif = toSarif(findings as never) as {
    version: string; runs: Array<{
      tool: { driver: { name: string; rules: Array<{ id: string; properties: { 'security-severity': string } }> } };
      results: Array<{ ruleId: string; level: string; partialFingerprints: { fingerprint: string } }>;
    }>;
  };
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0]!.tool.driver.name, 'R-SecopsXD');
  assert.equal(sarif.runs[0]!.results[0]!.level, 'error', 'high → SARIF error');
  assert.equal(sarif.runs[0]!.results[0]!.partialFingerprints.fingerprint, 'fp1', 'stable fingerprint in SARIF');
  const rule = sarif.runs[0]!.tool.driver.rules[0]!;
  assert.equal(rule.properties['security-severity'], '8');
});
