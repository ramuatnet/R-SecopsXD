import test from 'node:test';
import assert from 'node:assert/strict';
import { makeFingerprint, makeFindingId, dedupeFindings, normalizeLocator } from '../../src/core/ids.ts';
import type { Finding } from '../../src/core/types.ts';

function fakeFinding(over: Partial<Finding>): Finding {
  return {
    id: 'x', fingerprint: 'x', title: 't', category: 'A05', severity: 'medium',
    confidence: 'high', status: 'probable', asset: 'http://127.0.0.1:3000',
    locator: '/', engine: 'test', evidence: [], explanation: 'e', remediation: 'r',
    references: [], detectedAt: new Date().toISOString(),
    provenance: [{ engine: 'test', adapter: false }],
    ...over,
  };
}

test('fingerprint is deterministic and normalized', () => {
  const a = makeFingerprint('A02', 693, 'http://127.0.0.1:3000', 'http://127.0.0.1:3000/');
  const b = makeFingerprint('A02', 693, 'HTTP://127.0.0.1:3000', 'http://127.0.0.1:3000/?x=1');
  assert.equal(a, b);
  const c = makeFingerprint('A02', 693, 'http://127.0.0.1:3000', '/admin');
  assert.notEqual(a, c);
});

test('finding id stable across calls, includes category', () => {
  const fp = makeFingerprint('A05', 79, 'asset', '/search');
  const id1 = makeFindingId(fp, 'Reflected XSS', 'A05');
  const id2 = makeFindingId(fp, 'reflected xss', 'A05');
  assert.equal(id1, id2);
  assert.match(id1, /^FND-A05-[A-Z2-9]{10}$/);
});

test('normalizeLocator strips query strings and trailing slashes', () => {
  assert.equal(normalizeLocator('http://h/x/?a=1'), '/x');
  assert.equal(normalizeLocator('/x/'), '/x');
});

test('dedupeFindings merges provenance, evidence and max severity', () => {
  const fp = makeFingerprint('A02', 693, 'asset', '/');
  const a = fakeFinding({
    fingerprint: fp, id: 'a', confidence: 'high', severity: 'medium',
    provenance: [{ engine: 'builtin.http-observation', adapter: false, rawId: 'hdr-csp' }],
    evidence: [{ kind: 'http', observation: 'x', request: { method: 'GET', url: 'u', headers: {} } }],
    references: ['https://r1'],
  });
  const b = fakeFinding({
    fingerprint: fp, id: 'b', confidence: 'medium', severity: 'high',
    provenance: [
      { engine: 'builtin.http-observation', adapter: false, rawId: 'hdr-csp' },
      { engine: 'adapter.zap', adapter: true, rawId: '10038' },
    ],
    evidence: [{ kind: 'http', observation: 'y', request: { method: 'GET', url: 'u2', headers: {} } }],
    references: ['https://r2'],
  });
  const merged = dedupeFindings([a, b]);
  assert.equal(merged.length, 1);
  const m = merged[0]!;
  assert.equal(m.id, 'a', 'higher confidence wins identity');
  assert.equal(m.severity, 'high', 'severity raised to max observed');
  assert.equal(m.provenance.length, 2, 'duplicate provenance dropped, new kept');
  assert.equal(m.evidence.length, 2);
  assert.deepEqual([...m.references].sort(), ['https://r1', 'https://r2']);
});

test('dedupeFindings keeps distinct fingerprints apart', () => {
  const a = fakeFinding({ fingerprint: 'f1', id: 'a' });
  const b = fakeFinding({ fingerprint: 'f2', id: 'b' });
  assert.equal(dedupeFindings([a, b]).length, 2);
});

test('false_positive status is never auto-raised by a lower-confidence duplicate', () => {
  const fp = makeFingerprint('A02', 693, 'asset', '/');
  const human = fakeFinding({ fingerprint: fp, id: 'h', confidence: 'low', status: 'false_positive' });
  const auto = fakeFinding({ fingerprint: fp, id: 'a', confidence: 'high', status: 'probable' });
  const merged = dedupeFindings([human, auto]);
  assert.equal(merged.length, 1);
  assert.equal(merged[0]!.status, 'probable');
  assert.equal(merged[0]!.id, 'a', 'auto (higher confidence) is the base record');
});
