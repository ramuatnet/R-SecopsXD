/**
 * Tests for newtask.md Phase C (graph + normalization) — C1–C4.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Database } from '../../src/db/database.ts';
import { GraphStore } from '../../src/graph/graph.ts';
import { assetUid, canonicalIdentity, portIdentity, serviceIdentity } from '../../src/graph/uid.ts';
import { EventStore, mergeEvents, observableHash } from '../../src/graph/merger.ts';
import { adapt, sourceFamily, easmAdapter, cspmAdapter, dastAdapter } from '../../src/graph/adapters.ts';
import { syncFindingsToGraph } from '../../src/graph/sync.ts';
import { blastRadius } from '../../src/graph/query.ts';
import type { Finding } from '../../src/core/types.ts';

const dataDir = mkdtempSync(join(tmpdir(), 'rsec-graph-'));
const db = new Database(dataDir);
const store = new GraphStore(db.handle);
const events = new EventStore(db.handle);

function mkFinding(over: Partial<Finding>): Finding {
  return {
    id: 'FND-A01-TEST000001', fingerprint: 'fp-' + Math.random().toString(36).slice(2),
    category: 'A01', severity: 'info', confidence: 'high', status: 'informational',
    title: 'test finding', asset: 'https://target.example', locator: '/',
    evidence: [], provenance: [{ engine: 'builtin.host-infra', rawId: 'host-resolved', adapter: false }],
    detectedAt: new Date().toISOString(), firstSeen: new Date().toISOString(), lastSeen: new Date().toISOString(),
    explanation: 'x', remediation: 'y', references: [],
    ...over,
  } as Finding;
}

// ---------- UID scheme (3.1) ----------

test('assetUid: deterministic, typed prefix, same identity from any source collapses', () => {
  const a = assetUid('ip', '103.234.149.210');
  const b = assetUid('ip', '103.234.149.210');
  assert.equal(a, b, 'same identity = same uid (source-independent)');
  assert.match(a, /^ip:[A-HJ-NP-Z2-9]{10}$/);
  assert.notEqual(assetUid('ip', '1.2.3.4'), assetUid('domain', '1.2.3.4'), 'type is part of the hash');
  assert.equal(canonicalIdentity('webapp', 'https://Target.example:443/'), 'https://target.example');
  assert.equal(canonicalIdentity('domain', 'HTCINC.com.'), 'htcinc.com');
  assert.equal(canonicalIdentity('port', portIdentity('1.2.3.4', 443)), '1.2.3.4:443');
  assert.equal(canonicalIdentity('service', serviceIdentity('1.2.3.4', 443, 'tcp', 'Tomcat')), '1.2.3.4:443:tcp:tomcat');
});

// ---------- bitemporal semantics ----------

test('graph store: nodes never deleted; closeNode sets valid_to; re-observation re-opens', () => {
  const uid = store.upsertNode({ type: 'ip', identity: '10.0.0.1', display: '10.0.0.1', provenance: ['test'] });
  assert.equal(store.getNode(uid)!.validTo, null);
  store.closeNode(uid);
  assert.ok(store.getNode(uid)!.validTo !== null, 'closed node keeps history');
  store.upsertNode({ type: 'ip', identity: '10.0.0.1', display: '10.0.0.1' });
  assert.equal(store.getNode(uid)!.validTo, null, 'fresh assertion re-opens the node');
});

test('graph store: edges are idempotent per (type, src, dst) and update last_seen', () => {
  const dom = { type: 'domain' as const, identity: 'example.com', display: 'example.com' };
  const ip = { type: 'ip' as const, identity: '10.0.0.2', display: '10.0.0.2' };
  const e1 = store.upsertEdge({ edgeType: 'resolves_to', src: dom, dst: ip, provenance: ['t1'] });
  const e2 = store.upsertEdge({ edgeType: 'resolves_to', src: dom, dst: ip, provenance: ['t2'] });
  assert.equal(e1, e2, 'same edge assertion = same uid');
  const edge = store.getEdge(e1)!;
  assert.deepEqual(edge.provenance, ['t2'], 'provenance refreshed on re-observation');
});

// ---------- adapters (C2) ----------

test('adapters: routing by engine/rawId into source families', () => {
  assert.equal(sourceFamily(mkFinding({ provenance: [{ engine: 'builtin.host-infra', rawId: 'port-open', adapter: false }] })), 'easm');
  assert.equal(sourceFamily(mkFinding({ provenance: [{ engine: 'adapter.nuclei', rawId: 'x', adapter: true }] })), 'scanner');
  assert.equal(sourceFamily(mkFinding({ provenance: [{ engine: 'builtin.http-observation', rawId: 'missing-security-headers', adapter: false }] })), 'dast');
  assert.equal(sourceFamily(mkFinding({ provenance: [{ engine: 'builtin.asset-discovery', rawId: 'cloud-bucket-public', adapter: false }] })), 'cspm', 'cloud findings route to CSPM by rawId');
});

test('easm adapter: host-resolved builds domain + ip nodes and resolves_to edges', () => {
  const f = mkFinding({
    asset: 'www.tnebnet.org', locator: 'www.tnebnet.org',
    evidence: [{ kind: 'process', command: 'DNS lookup', observation: '103.234.149.210; 103.234.149.211' }],
    provenance: [{ engine: 'builtin.host-infra', rawId: 'host-resolved', adapter: false }],
  });
  const out = easmAdapter(f);
  assert.equal(out.events.length, 1);
  assert.equal(out.events[0]!.classUid, 'easm.host.resolved');
  assert.equal(out.nodes.filter((n) => n.type === 'ip').length, 2);
  assert.equal(out.edges.filter((e) => e.edgeType === 'resolves_to').length, 2);
});

test('easm adapter: port-open produces port node + exposes edge with asset uid', () => {
  const f = mkFinding({
    asset: 'www.tnebnet.org', locator: '103.234.149.210:9200', severity: 'high',
    provenance: [{ engine: 'builtin.host-infra', rawId: 'port-open', adapter: false }],
  });
  const out = easmAdapter(f);
  assert.equal(out.events[0]!.assetUid, assetUid('port', '103.234.149.210:9200'));
  assert.equal(out.events[0]!.severityRaw, 'high', 'raw severity carried verbatim');
  assert.equal(out.edges[0]!.edgeType, 'exposes');
});

test('dast/cspm adapters emit only NormalizedEvent-shaped outputs', () => {
  const d = dastAdapter(mkFinding({ provenance: [{ engine: 'builtin.http-observation', rawId: 'missing-security-headers', adapter: false }] }));
  assert.equal(d.events[0]!.classUid, 'dast.finding.observed');
  const c = cspmAdapter(mkFinding({ provenance: [{ engine: 'builtin.asset-discovery', rawId: 'cloud-bucket-public', adapter: false }], locator: 'AWS S3: https://x.s3.amazonaws.com/' }));
  assert.equal(c.events[0]!.classUid, 'cspm.bucket.exposed');
  assert.equal(c.edges[0]!.edgeType, 'found_on');
});

// ---------- merger (C3) ----------

test('merger: dedupe by (classUid, assetUid, observable hash); raw severity never overwritten', () => {
  const base = {
    classUid: 'easm.port.open', activityId: 'opened' as const, time: new Date().toISOString(),
    assetUid: assetUid('port', '1.2.3.4:3306'), observables: [{ kind: 'port' as const, value: '3306' }],
    confidence: 'high' as const, severityRaw: 'high', severityNorm: 'high' as const,
    firstSeen: '2026-10-31T00:00:00Z', lastSeen: '2026-10-31T00:00:00Z',
    provenance: [{ engine: 'builtin.host-infra', rawId: 'port-open', adapter: false }],
  };
  const second = {
    ...base, severityRaw: 'info', severityNorm: 'medium' as const,
    firstSeen: '2026-10-30T00:00:00Z', lastSeen: '2026-10-31T02:00:00Z',
    provenance: [{ engine: 'adapter.nuclei', rawId: 'rsec-mysql-exposed' }],
  };
  const merged = mergeEvents([base, second]);
  assert.equal(merged.length, 1, 'same dedupe key merges');
  assert.equal(merged[0]!.severityRaw, 'high', 'raw severity of the FIRST source is preserved');
  assert.equal(merged[0]!.severityNorm, 'high', 'normalized severity takes the max');
  assert.equal(merged[0]!.firstSeen, '2026-10-30T00:00:00Z');
  assert.equal(merged[0]!.lastSeen, '2026-10-31T02:00:00Z');
  assert.equal(merged[0]!.provenance.length, 2, 'provenance merged');
  assert.equal(observableHash([{ kind: 'port', value: '3306' }]), observableHash([{ kind: 'port', value: '3306' }]));
  assert.notEqual(observableHash([{ kind: 'port', value: '3306' }]), observableHash([{ kind: 'port', value: '5432' }]));
});

test('event store: persists, dedupes, and increments times_seen', () => {
  const e = {
    classUid: 'dast.finding.observed', activityId: 'observed' as const, time: new Date().toISOString(),
    assetUid: assetUid('finding', 'fp-unique-1'), observables: [{ kind: 'url' as const, value: '/' }],
    confidence: 'high' as const, severityRaw: 'medium', severityNorm: 'medium' as const,
    firstSeen: new Date().toISOString(), lastSeen: new Date().toISOString(),
    provenance: [{ engine: 'builtin.http-observation', rawId: 'missing-security-headers', scanId: 's1' }],
  };
  const r1 = events.record(e);
  const r2 = events.record({ ...e, lastSeen: new Date().toISOString(), provenance: [{ engine: 'adapter.zap', rawId: 'x', scanId: 's2' }] });
  assert.equal(r1.deduped, false);
  assert.equal(r2.deduped, true);
  const rows = events.list(e.assetUid);
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.times_seen, 2);
  assert.equal(rows[0]!.severity_raw, 'medium');
  assert.equal((JSON.parse(rows[0]!.provenance_json) as unknown[]).length, 2);
});

// ---------- traversal + blast radius (C4) ----------

test('traverse + blast radius: bounded walk from an IP through exposes/runs', () => {
  const ip = { type: 'ip' as const, identity: '10.1.1.1', display: '10.1.1.1' };
  const port = { type: 'port' as const, identity: '10.1.1.1:8080', display: '10.1.1.1:8080' };
  const svc = { type: 'service' as const, identity: serviceIdentity('10.1.1.1', 8080, 'tcp', 'Tomcat'), display: 'Tomcat' };
  store.upsertEdge({ edgeType: 'exposes', src: ip, dst: port, provenance: ['t'] });
  store.upsertEdge({ edgeType: 'runs', src: port, dst: svc, provenance: ['t'] });
  const r = blastRadius(store, assetUid('ip', '10.1.1.1'));
  assert.ok(r.affected.length >= 2, 'port + service reachable');
  assert.ok(r.fanout >= 1);
  assert.ok(r.blastFactor > 0 && r.blastFactor <= 1.5, 'blast factor bounded');
});

// ---------- end-to-end sync seam ----------

test('syncFindingsToGraph: findings land as nodes+edges+events with dedupe on resync', () => {
  const before = store.counts();
  const f1 = mkFinding({
    asset: 'www.tnebnet.org', locator: '103.234.149.210:443',
    provenance: [{ engine: 'builtin.host-infra', rawId: 'port-open', adapter: false }],
  });
  const stats1 = syncFindingsToGraph(store, events, [f1], 'scan-sync-1');
  assert.equal(stats1.findings, 1);
  assert.ok(stats1.nodes >= 2 && stats1.edges >= 1);
  const stats2 = syncFindingsToGraph(store, events, [f1], 'scan-sync-2');
  assert.equal(stats2.deduped, 1, 're-sync of the same observation dedupes to one event');
  const after = store.counts();
  assert.equal(after.nodes - before.nodes, 2, 'ip + port nodes (re-sync does not duplicate)');
});
