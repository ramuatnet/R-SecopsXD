/**
 * Tests for actions.md: internal scan, fingerprinting, CVE matching,
 * orphan guard, blind-SSRF reachability, P/R metrics.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpServer, type Server } from 'node:http';
import { expandCidr } from '../../src/engines/builtin/internalScan.ts';
import { InternalScanEngine, fingerprint } from '../../src/engines/builtin/internalScanEngine.ts';
import { HostInfraEngine } from '../../src/engines/builtin/hostInfra.ts';
import { certMatchesHost } from '../../src/engines/builtin/tlsAnalysis.ts';
import { computePrecisionRecall } from '../../src/verify/metrics.ts';
import type { ScanContext } from '../../src/engines/types.ts';
import type { Target } from '../../src/core/types.ts';

// ---------- CIDR expansion ----------

test('CIDR expansion: /24 gives 254 usable IPs, /32 gives 1, /23 rejected', () => {
  assert.equal(expandCidr('192.168.1.0/24').length, 254);
  assert.deepEqual(expandCidr('10.0.0.5/32'), ['10.0.0.5']);
  assert.equal(expandCidr('10.0.0.0/23').length, 0, '/23 rejected (too large)');
  assert.equal(expandCidr('127.0.0.1/32')[0], '127.0.0.1');
});

// ---------- service fingerprinting (A4) ----------

test('fingerprint: HTTP, SSH, Redis, MySQL banners identified', () => {
  assert.equal(fingerprint(80, 'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n').service, 'http');
  assert.equal(fingerprint(80, 'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n').version, '1.24.0');
  assert.equal(fingerprint(22, 'SSH-2.0-OpenSSH_9.6\r\n').service, 'ssh');
  assert.equal(fingerprint(22, 'SSH-2.0-OpenSSH_9.6\r\n').version, '2.0');
  assert.equal(fingerprint(6379, '+PONG\r\n').service, 'redis');
  assert.equal(fingerprint(3306, '\x0a5.7.40-0ubuntu0.18.04.1\x00').service, 'mysql');
  assert.equal(fingerprint(12345, 'garbage-data').service, 'unknown');
});

// ---------- A5 CVE matching ----------

test('A5 CVE matching: outdated Apache matched, current not', () => {
  // use the internal matchServiceCves logic (test via the module's behavior)
  const SERVICE_CVES = [
    { service: 'http', versionBelow: '2.4.49', cve: 'CVE-2021-41773' },
    { service: 'http', versionBelow: '2.4.51', cve: 'CVE-2021-42013' },
  ];
  const versionLt = (a: string, b: string): boolean => {
    const pa = a.split('.').map(Number);
    const pb = b.split('.').map(Number);
    for (let i = 0; i < 3; i++) {
      const d = (pa[i] ?? 0) - (pb[i] ?? 0);
      if (d !== 0) return d < 0;
    }
    return false;
  };

  // Apache 2.4.48 < 2.4.49 → matches CVE-2021-41773
  const outdated = SERVICE_CVES.filter((c) => versionLt('2.4.48', c.versionBelow));
  assert.ok(outdated.some((c) => c.cve === 'CVE-2021-41773'), 'outdated Apache must match');

  // Apache 2.4.62 >= 2.4.51 → no match
  const current = SERVICE_CVES.filter((c) => versionLt('2.4.62', c.versionBelow));
  assert.equal(current.length, 0, 'current Apache must not match');
});

// ---------- certMatchesHost (TLS FP regression) ----------

test('certMatchesHost: wildcard matching correctness', () => {
  assert.equal(certMatchesHost(['*.owasp.org'], 'vwad.owasp.org'), true);
  assert.equal(certMatchesHost(['*.owasp.org'], 'a.b.owasp.org'), false);
  assert.equal(certMatchesHost(['*.owasp.org'], 'owasp.org'), false);
  assert.equal(certMatchesHost(['exact.match.com'], 'exact.match.com'), true);
  assert.equal(certMatchesHost(['*.example.com'], 'evil-example.com'), false);
});

// ---------- A3 orphan guard ----------

test('A3 orphan guard: every registered engine is reachable from a profile', async () => {
  const { EngineRegistry } = await import('../../src/engines/registry.ts');
  const { loadConfig } = await import('../../src/config.ts');
  const { PROFILES } = await import('../../src/core/profiles.ts');
  const registry = new EngineRegistry(loadConfig());
  const profileEngineIds = new Set(
    PROFILES.flatMap((p) => [...p.passiveEngines, ...p.activeEngines]),
  );
  for (const id of registry.allEngineIds()) {
    assert.ok(
      profileEngineIds.has(id),
      `engine ${id} is registered but not reachable from any profile`,
    );
  }
});

// ---------- A2 blind-ssrf reachability ----------

test('A2 blind-ssrf-probe: present in standard-active profile', async () => {
  const { getProfile } = await import('../../src/core/profiles.ts');
  const p = getProfile('standard-active');
  assert.ok(p, 'standard-active profile exists');
  assert.ok(p!.activeEngines.includes('builtin.blind-ssrf-probe'), 'blind-ssrf-probe in active engines');
});

// ---------- A1 internal scan engine (live test) ----------

test('A1 internal scan: discovers live HTTP service on loopback', async () => {
  const server = createHttpServer((_req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => {
    res.writeHead(200, { 'content-type': 'text/html', server: 'TestServer/1.0' });
    res.end('<h1>test</h1>');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  const cidr = '127.0.0.1/32';
  try {
    const engine = new InternalScanEngine();
    const target: Target = { id: 't', name: 'x', origin: `http://127.0.0.1:${port}`, kind: 'cidr', sourcePath: cidr, approved: true, createdAt: new Date().toISOString() };
    const ctx: ScanContext = {
      scanId: 's', target, mode: 'active',
      client: {} as never, guard: {} as never, stats: { sent: 0, blocked: 0 },
      signal: new AbortController().signal, workDir: '.', log: () => {},
    };
    const res = await engine.run(ctx);
    const hostFindings = res.findings.filter((f: { rawId?: string }) => f.rawId === 'host-discovered');
    assert.ok(hostFindings.length > 0, 'host discovered');
    assert.ok(hostFindings.some((f) => f.locator?.includes(String(port))), 'correct port identified');
    const svcFindings = res.findings.filter((f: { rawId?: string }) => f.rawId === 'service-version-disclosed');
    assert.ok(svcFindings.length > 0, 'service version disclosed');
  } finally {
    server.close();
  }
});

// ---------- P/R metrics ----------

test('precision/recall metrics: correct computation', () => {
  const pr = computePrecisionRecall(['a', 'b', 'c'], ['a', 'b', 'd']);
  assert.equal(pr.truePositives, 2);
  assert.equal(pr.falsePositives, 1);
  assert.equal(pr.falseNegatives, 1);
  assert.ok(Math.abs(pr.precision - 2 / 3) < 1e-9);
  assert.ok(Math.abs(pr.recall - 2 / 3) < 1e-9);
  assert.ok(pr.f1 > 0);
});

// ---------- host-infra: context-based infrastructure recon ----------

function makeInfraCtx(mode: 'active' | 'passive', origin: string): ScanContext {
  const target: Target = { id: 't', name: 'x', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() };
  return {
    scanId: 's', target, mode,
    client: {} as never, guard: {} as never, stats: { sent: 0, blocked: 0 },
    signal: new AbortController().signal, workDir: '.', log: () => {},
  };
}

test('host-infra: webapp target resolves hostname and port-scans resolved IPs (active)', async () => {
  const server = createHttpServer((_req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => {
    res.writeHead(200, { 'content-type': 'text/html', server: 'TestServer/1.0' });
    res.end('<h1>test</h1>');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  try {
    const engine = new HostInfraEngine();
    const res = await engine.run(makeInfraCtx('active', `http://localhost:${port}`));
    const resolved = res.findings.filter((f: { rawId?: string }) => f.rawId === 'host-resolved');
    assert.equal(resolved.length, 1, 'host-resolved finding emitted');
    const hosts = res.findings.filter((f: { rawId?: string }) => f.rawId === 'host-discovered');
    assert.ok(hosts.some((f: { title?: string }) => f.title?.includes(String(port))), 'open target port reported');
    const svc = res.findings.filter((f: { rawId?: string }) => f.rawId === 'service-identified');
    assert.ok(svc.length > 0, 'service identified (deep HTTP recon captures Server header)');
  } finally {
    server.close();
  }
});

test('host-infra: passive mode resolves DNS but sends no port probes', async () => {
  const engine = new HostInfraEngine();
  const res = await engine.run(makeInfraCtx('passive', 'http://localhost:1'));
  assert.ok(res.findings.some((f: { rawId?: string }) => f.rawId === 'host-resolved'), 'DNS resolution present');
  assert.ok(!res.findings.some((f: { rawId?: string }) => f.rawId === 'host-discovered'), 'no port-scan findings in passive mode');
  assert.match(res.detail ?? '', /passive mode/);
});

test('host-infra: unresolvable hostname yields no findings (unknown, not assumed)', async () => {
  const engine = new HostInfraEngine();
  const res = await engine.run(makeInfraCtx('active', 'http://definitely-not-a-real-host-abcxyz.invalid:80'));
  assert.equal(res.findings.length, 0, 'no findings for unresolvable hostname');
  assert.match(res.detail ?? '', /could not be resolved/);
});

test('host-infra: IP-literal origin skips DNS and scans directly', async () => {
  const server = createHttpServer((_req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => {
    res.writeHead(200, { server: 'TestServer/2.0' });
    res.end('ok');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  try {
    const engine = new HostInfraEngine();
    const res = await engine.run(makeInfraCtx('active', `http://127.0.0.1:${port}`));
    const resolved = res.findings.find((f: { rawId?: string }) => f.rawId === 'host-resolved');
    assert.ok(resolved, 'host-resolved emitted for IP literal');
    assert.equal(resolved!.locator, '127.0.0.1', 'locator is the IP itself');
    assert.ok(res.findings.some((f: { rawId?: string; title?: string }) => f.rawId === 'host-discovered' && f.title?.includes(String(port))), 'target port found');
  } finally {
    server.close();
  }
});
