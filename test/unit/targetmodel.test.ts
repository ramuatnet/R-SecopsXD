/**
 * Target Model acceptance tests (v2 Phase 1: T1.1–T1.4).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Database } from '../../src/db/database.ts';
import { TargetModel, mergeEvidence } from '../../src/model/targetModel.ts';
import type { ModelDelta } from '../../src/model/types.ts';

function freshModel(): { db: Database; model: TargetModel; dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'ovap-model-'));
  const db = new Database(dir);
  const model = new TargetModel(db.handle, 'target-1');
  return {
    db, model, dir,
    cleanup: () => { db.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

test('T1.2 tri-state: fresh target has zero present, unknowns implied by absence', () => {
  const m = freshModel();
  try {
    assert.equal(m.model.state('capability', 'api.rest'), 'unknown');
    assert.equal(m.model.nodes().length, 0);
    m.model.set('capability', 'api.rest', { discoveredBy: 'openapi' }, 'test', 'present');
    assert.equal(m.model.state('capability', 'api.rest'), 'present');
  } finally {
    m.cleanup();
  }
});

test('T1.3 merge is idempotent: replaying evidence twice produces zero new deltas', () => {
  const m = freshModel();
  try {
    const evidence = [
      { kind: 'capability' as const, key: 'api.rest', state: 'present' as const, value: { spec: '/openapi.json' }, provenance: 'probe' },
      { kind: 'tech' as const, key: 'server', state: 'present' as const, value: 'nginx', provenance: 'banner' },
    ];
    const first = mergeEvidence(m.model, evidence);
    assert.equal(first.length, 2);
    const second = mergeEvidence(m.model, evidence);
    assert.equal(second.length, 0, 'replay is a no-op');
  } finally {
    m.cleanup();
  }
});

test('T1.3 conflict resolution: presence beats absence regardless of order; newer wins', () => {
  const m = freshModel();
  try {
    mergeEvidence(m.model, [
      { kind: 'capability', key: 'spa', value: {}, provenance: 'p1', state: 'absent' },
    ]);
    assert.equal(m.model.state('capability', 'spa'), 'absent');
    mergeEvidence(m.model, [
      { kind: 'capability', key: 'spa', value: { bundles: 2 }, provenance: 'p2', state: 'present' },
    ]);
    assert.equal(m.model.state('capability', 'spa'), 'present', 'later presence wins');

    // reversed order: present first, then absent — presence must survive
    mergeEvidence(m.model, [
      { kind: 'capability', key: 'graphql', value: {}, provenance: 'p1', state: 'present' },
      { kind: 'capability', key: 'graphql', value: {}, provenance: 'p2', state: 'absent' },
    ]);
    assert.equal(m.model.state('capability', 'graphql'), 'present', 'absent must not override present');
  } finally {
    m.cleanup();
  }
});

test('T1.4 delta chain: hash-chained, and replay reconstructs the model from empty', () => {
  const m = freshModel();
  try {
    m.model.set('capability', 'a', { x: 1 }, 'p', 'present');
    m.model.set('capability', 'b', { y: 2 }, 'p', 'absent');
    m.model.set('capability', 'a', { x: 2 }, 'p2', 'present');
    m.model.delete('capability', 'b', 'cleanup');

    const deltas = m.model.deltas();
    assert.equal(deltas.length, 4);
    // chain integrity: each delta's prevHash equals the previous hash
    assert.equal(deltas[0]!.prevHash, 'genesis');
    for (let i = 1; i < deltas.length; i++) {
      assert.equal(deltas[i]!.prevHash, deltas[i - 1]!.hash);
    }
    const chain = (ds: ModelDelta[]): boolean => ds.every((d, i) => i === 0 || d.prevHash === ds[i - 1]!.hash);
    assert.equal(chain(deltas), true);

    // replay: materialized view must equal the delta stream's effect
    const replayed: Array<Record<string, unknown>> = [];
    for (const d of deltas) {
      if (d.op === 'set') {
        const i = replayed.findIndex((r) => r.key === `cap:${d.key}`);
        if (i >= 0) replayed.splice(i, 1);
        replayed.push({ key: `cap:${d.key}`, state: d.state, value: d.value });
      } else {
        const i = replayed.findIndex((r) => r.key === `cap:${d.key}`);
        if (i >= 0) replayed.splice(i, 1);
      }
    }
    const live = m.model.nodes().filter((n) => n.kind === 'capability');
    assert.equal(replayed.length, live.length);
    for (const r of replayed) {
      const liveNode = live.find((n) => n.key === String(r.key).split(':').slice(1).join(':'));
      assert.ok(liveNode, `replayed node ${r.key} exists live`);
      assert.equal(liveNode!.state, r.state);
      assert.deepEqual(liveNode!.value, r.value);
    }
  } finally {
    m.cleanup();
  }
});
