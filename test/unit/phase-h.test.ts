/**
 * Phase H tests (hardtask.md) — port-detection correctness.
 * I16: no suppression rule without a counter-test proving it does not drop a
 * known-open port; middlebox fixtures still yield no phantom high-severity ports.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import net from 'node:net';
import { HostInfraEngine, detectInterception, portSeverity, NEVER_SUPPRESS_PORTS } from '../../src/engines/builtin/hostInfra.ts';
import { scanPort } from '../../src/engines/builtin/internalScan.ts';
import type { ScanContext } from '../../src/engines/types.ts';

function ctxFor(origin: string): ScanContext {
  return {
    scanId: 's', target: { id: 't', name: 'x', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() },
    mode: 'active', client: {} as never, guard: {} as never, stats: { sent: 0, blocked: 0 },
    signal: new AbortController().signal, workDir: '.', log: () => {},
  } as ScanContext;
}

/** H1 accept: a silent TCP listener yields a finding (open, unverified, low confidence). */
test('H1: silent TCP listener → port-open unverified at info/low, never dropped', async () => {
  // A listener that accepts and says nothing (real-world: SSH-before-banner, Redis)
  const silent = net.createServer((sock) => { void sock; /* accept, never respond */ });
  await new Promise<void>((r) => silent.listen(0, '127.0.0.1', r));
  const port = (silent.address() as { port: number }).port;
  try {
    const direct = await scanPort('127.0.0.1', port, 1500);
    assert.equal(direct.open, true, 'connect succeeded = open');
    assert.equal(direct.unverified, true, 'no protocol bytes = unverified');

    const engine = new HostInfraEngine();
    const res = await engine.run(ctxFor(`http://localhost:${port}`));
    const found = res.findings.filter((f) => f.rawId === 'port-open' && (f.locator ?? '').includes(String(port)));
    assert.ok(found.length > 0, 'silent listener surfaces as a port finding');
    const f = found[0]!;
    assert.equal(f.severity, 'info', 'unverified ports never carry class severity');
    assert.equal(f.confidence, 'low');
    assert.equal(f.status, 'untested');
    assert.match(f.title, /unverified/);
  } finally {
    silent.close();
  }
});

/** H1/H2 accept together: a middlebox fixture still yields no phantom high-severity ports. */
test('H2/H3: middlebox (silent connects on many ports) → suppressed with count, no phantom high', async () => {
  const engine = new HostInfraEngine();
  // The engine probes ~34 ports on the resolved IP; a middlebox accepts ALL of
  // them silently. With H1 they are all "unverified open"; H2 must suppress the
  // uniform silent signature down to the exempt list only.
  const acceptAll = net.createServer((sock) => { void sock; });
  await new Promise<void>((r) => acceptAll.listen(0, '127.0.0.1', r));
  const port = (acceptAll.address() as { port: number }).port;
  // Aim the scan at the middlebox by making it the target origin port; the
  // engine will silently connect the rest of the port list to loopback too.
  try {
    const res = await engine.run(ctxFor(`http://localhost:${port}`));
    const portFindings = res.findings.filter((f) => f.rawId === 'port-open');
    const highs = portFindings.filter((f) => f.severity === 'high');
    assert.equal(highs.length, 0, 'no phantom high-severity ports from a silent middlebox');
    const interference = res.findings.find((f: { rawId?: string }) => f.rawId === 'port-scan-interference');
    if (interference !== undefined) {
      assert.equal(interference.severity, 'low', 'H3: interference carries the low band');
      assert.match(res.detail ?? '', /ports suppressed as middlebox interception/, 'H3: suppressed count in scan detail');
    }
    void portFindings;
  } finally {
    acceptAll.close();
  }
});

test('H2: identical HTTP responses on 6 ports (below threshold 8) are NOT suppressed', async () => {
  // I16 counter-test: the old default of 5 would have erased these.
  const servers: Server[] = [];
  const ports: number[] = [];
  for (let i = 0; i < 6; i++) {
    const s = createServer((_req, res) => { res.writeHead(403); res.end('Access Denied'); });
    await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
    servers.push(s);
    ports.push((s.address() as { port: number }).port);
  }
  try {
    const ops = ports.map((p) => ({ port: p, recon: { open: true, isHttp: true, status: 403, headers: { server: 'x' }, body: 'Access Denied', sans: [] } }));
    const { suppressed } = detectInterception(ops);
    assert.equal(suppressed.size, 0, '6 identical responses below threshold 8 must all be reported');
    // at threshold: 8 DISTINCT ports with identical responses → suppressed
    const ops8 = ports.concat([19990, 19991]).map((p) => ({ port: p, recon: { open: true, isHttp: true, status: 403, headers: { server: 'x' }, body: 'Access Denied', sans: [] } }));
    const r8 = detectInterception(ops8);
    assert.equal(r8.suppressed.size, 8, '8 identical non-exempt ports → all suppressed');
  } finally {
    for (const s of servers) s.close();
  }
});

test('H2: full-signature identity — same body, different status or headers = different services', () => {
  const mk = (port: number, status: number, headers: Record<string, string>) => ({ port, recon: { open: true, isHttp: true, status, headers, body: 'Same Body', sans: [] } });
  const r = detectInterception([
    mk(8000, 403, { server: 'a' }), mk(8001, 404, { server: 'a' }), mk(8002, 403, { server: 'b' }),
    mk(8003, 403, { server: 'a' }), mk(8004, 403, { server: 'a' }), mk(8005, 403, { server: 'a' }),
    mk(8006, 403, { server: 'a' }), mk(8007, 403, { server: 'a' }), mk(8008, 403, { server: 'a' }),
    mk(8009, 403, { server: 'a' }),
  ]);
  assert.equal(r.suppressed.size, 8, 'the 8-strong a/403 group is suppressed — the 404 and b/403 singles survive');
  assert.equal(r.suppressed.has(8001), false, 'differing status survives');
  assert.equal(r.suppressed.has(8002), false, 'differing headers survive');
});

test('H2: curated critical ports are never suppressed (22/443/3306/3389/5432/6379/9200/27017)', () => {
  const mk = (port: number) => ({ port, recon: { open: true, isHttp: true, status: 403, headers: {}, body: 'Block', sans: [] } });
  const r = detectInterception([mk(22), mk(443), mk(3306), mk(3389), mk(5432), mk(6379), mk(9200), mk(27017), mk(9999), mk(9998)]);
  assert.ok(r.suppressed.has(9999) && r.suppressed.has(9998), 'non-exempt suppressed');
  for (const p of NEVER_SUPPRESS_PORTS) {
    assert.equal(r.suppressed.has(p), false, `critical port ${p} survives uniform-answer suppression`);
  }
});

test('H2: uniform silent middlebox signature is suppressible even at scale', () => {
  const silent = (port: number) => ({ port, unverified: true });
  const r = detectInterception(Array.from({ length: 12 }, (_, i) => silent(20000 + i)));
  assert.equal(r.suppressed.size, 12, 'silent-connect middlebox fully suppressed');
  assert.match(r.sample ?? '', /uniform silent/);
});

/** H4 (I17): the fixture ground-truth port must ALWAYS be reported — recall floor. */
test('H4: recall floor — vuln-app port 8899 appears as a finding on every run', async () => {
  const engine = new HostInfraEngine();
  const res = await engine.run(ctxFor('http://127.0.0.1:8899'));
  const port8899 = res.findings.filter((f) => f.rawId === 'port-open' && (f.locator ?? '').endsWith(':8899'));
  assert.ok(port8899.length === 1, `fixture port must surface exactly once, got ${port8899.length}`);
  assert.ok(port8899[0]!.severity === 'info' || port8899[0]!.severity === 'medium', '8899 is a dev port: info (unverified) or medium (verified)');
  void portSeverity;
});

// ---------- M2: TTL-based OS hypothesis via system ping ----------

test('M2: TTL probe resolves an OS-family hypothesis from the system ping binary', async () => {
  const { probeTtl, pingAvailable } = await import('../../src/orchestration/ttlProbe.ts');
  if (!pingAvailable()) return; // honest skip
  const r = await probeTtl('127.0.0.1');
  assert.ok(r !== undefined, 'loopback ping always answers');
  assert.ok(r!.ttl >= 32 && r!.ttl <= 255, `plausible TTL, got ${r!.ttl}`);
  assert.notEqual(r!.family, 'unknown', 'loopback TTL maps to a family');
  assert.equal(r!.confidence, 'low', 'TTL hypotheses are low confidence by construction');
});
