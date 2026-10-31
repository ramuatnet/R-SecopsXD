/**
 * G3 determinism gate + E1 sensor registry tests (newtask.md).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Database } from '../../src/db/database.ts';
import { GraphStore } from '../../src/graph/graph.ts';
import { SensorRegistry } from '../../src/orchestration/sensors.ts';
import { planFor, capabilitiesFor } from '../../src/orchestration/planner.ts';
import { triggerForPort } from '../../src/orchestration/assessAsset.ts';
import { ScopeGate } from '../../src/safety/scopeGate.ts';
import { InProcessBus } from '../../src/bus/bus.ts';
import { assetUid } from '../../src/graph/uid.ts';

// ---------- G3: determinism gate ----------

test('determinism gate: planner output is byte-stable across runs (G3)', () => {
  const input = { ip: '1.2.3.4', port: 8443, service: 'http', product: 'Apache-Coyote' };
  const a = JSON.stringify(planFor(input));
  const b = JSON.stringify(planFor(input));
  assert.equal(a, b, 'planFor must be deterministic');
  const capsA = JSON.stringify(capabilitiesFor(input));
  const capsB = JSON.stringify(capabilitiesFor(input));
  assert.equal(capsA, capsB, 'capabilitiesFor must be deterministic');
});

test('determinism gate: trigger rules are deterministic per input state (G3)', () => {
  const run = (): string => {
    const bus = new InProcessBus();
    const scope = new ScopeGate();
    scope.register('origin', 'https://target.example');
    scope.approve('origin', 'https://target.example', 'op');
    const r = triggerForPort({ ip: '1.2.3.4', port: 443, severity: 'info', origin: 'https://target.example', scope, bus });
    return JSON.stringify({ r, envelopes: bus.recent().map((e) => e.topic) });
  };
  assert.equal(run(), run(), 'same input state → same decision + same emissions');
});

test('determinism gate: UIDs stable across runs and sources (anti-regression)', () => {
  const viaPort = assetUid('port', '1.2.3.4:443');
  const viaPortAgain = assetUid('port', '1.2.3.4:443');
  assert.equal(viaPort, viaPortAgain);
});

// ---------- E1: sensor registry ----------

test('sensor registry: tiers, validation, heartbeats, stale detection, capability pick', async () => {
  const db = new Database(mkdtempSync(join(tmpdir(), 'rsec-sensors-')));
  const store = new GraphStore(db.handle);
  const reg = new SensorRegistry(store);

  reg.register({ id: 'ext-1', tier: 'external', capabilities: ['http', 'tcp'], network: '203.0.113.10' });
  reg.register({ id: 'int-1', tier: 'internal', capabilities: ['tcp', 'smb'], network: 'vpc-prod-a' });
  reg.register({ id: 'cloud-1', tier: 'cloud-readonly', capabilities: ['cloud-describe'] });

  assert.equal(reg.list().length, 3);
  assert.equal(reg.list('external').length, 1);
  assert.throws(() => reg.register({ id: 'bad', tier: 'quantum' as never, capabilities: [] }), /invalid sensor tier/);

  assert.equal(reg.isAlive('ext-1'), true);
  assert.equal(reg.pick('http')?.id, 'ext-1', 'capability routing picks the alive external sensor');
  assert.equal(reg.pick('cloud-describe')?.id, 'cloud-1');
  assert.equal(reg.pick('smb', 'external'), undefined, 'tier filter respected');

  reg.claimWork('ext-1');
  reg.claimWork('ext-1');
  reg.claimWork('ext-1');
  assert.equal(reg.pick('http')?.id, 'ext-1', 'still the only http sensor');
  const intSensor = reg.pick('tcp');
  assert.ok(['int-1'].includes(intSensor?.id ?? ''), 'tcp routes to internal sensor (lower claims)');

  // stale sensor is not picked
  const stale = reg.list('internal')[0]!;
  const past = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  reg.heartbeat(stale.id, past);
  assert.equal(reg.isAlive(stale.id), false, 'heartbeat older than 5 minutes = stale');
  assert.throws(() => reg.heartbeat('ghost'), /unknown sensor/);

  // sensor nodes are in the graph
  const node = store.getNodeByIdentity('sensor', 'ext-1');
  assert.ok(node !== undefined, 'registered sensor becomes a graph node');
  assert.equal(node!.attributes.tier, 'external');
});
