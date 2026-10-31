/**
 * T4.7 PoC — blind-SSRF OOB correlation loop, end to end.
 *
 * A fixture with a genuine server-side request forgery (`?url=` is fetched by
 * the server) is probed by BlindSsrfProbeEngine: unique tokens are injected,
 * the fixture's server-side fetch hits the OOB callback server, and the probe
 * correlates the callback into a confirmed critical finding.
 *
 * Public-infrastructure note: the OOB server binds localhost here; on public
 * targets the same loop requires a publicly reachable callback host (T4.7).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { BlindSsrfProbeEngine } from '../../src/engines/builtin/blindSsrfProbe.ts';
import { ScopeGuard } from '../../src/safety/guard.ts';
import { RateLimiter } from '../../src/safety/rateLimiter.ts';
import { Semaphore } from '../../src/safety/concurrency.ts';
import { ScopedHttpClient } from '../../src/scan/httpClient.ts';
import type { ScanContext } from '../../src/engines/types.ts';

test('blind-SSRF: OOB callback correlated into a confirmed finding (T4.7 loop)', async () => {
  // The vulnerable fixture: ?url= is fetched server-side (SSRF sink)
  const fixture = createServer((req, res) => {
    const u = new URL(req.url ?? '/', 'http://localhost');
    const target = u.searchParams.get('url');
    if (target === null) { res.writeHead(200); res.end('index'); return; }
    // server-side request — no response body leaks back (blind)
    const inner = httpRequest(target, () => { res.writeHead(200); res.end('fetched'); });
    inner.on('error', () => { res.writeHead(200); res.end('fetch-error'); });
    inner.end();
  });
  await new Promise<void>((r) => fixture.listen(0, '127.0.0.1', r));
  const port = (fixture.address() as { port: number }).port;
  const origin = `http://127.0.0.1:${port}`;

  const guard = new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 1 });
  const client = new ScopedHttpClient(guard, new RateLimiter(1000, 1000), new Semaphore(10), { timeoutMs: 8000, maxRedirectHops: 1 }, { sent: 0, blocked: 0 });
  const ctx: ScanContext = {
    scanId: 'oob-poc', target: { id: 't', name: 'x', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() },
    mode: 'active', client, guard, stats: { sent: 0, blocked: 0 },
    signal: new AbortController().signal, workDir: '.', log: () => {},
    crawl: {
      pages: [{ url: `${origin}/fetch?url=http://example.com/`, status: 200, headers: {}, body: '', truncated: false, forms: [], links: [] }],
      robots: { disallow: [], fetched: false },
    },
  };

  const engine = new BlindSsrfProbeEngine();
  const res = await engine.run(ctx);
  try {
    assert.match(res.detail ?? '', /1 SSRF probe/, 'one probe was sent');
    assert.equal(res.findings.length, 1, 'the OOB callback was correlated into a finding');
    const f = res.findings[0]!;
    assert.equal(f.rawId, 'blind-ssrf-oob');
    assert.equal(f.severity, 'critical');
    assert.equal(f.status, 'confirmed');
    assert.equal(f.cwe, 918);
    assert.match(f.evidence[0]!.kind === 'process' ? f.evidence[0]!.observation : '', /outbound request\(s\) to our callback server/, 'evidence names the server-side callback');
  } finally {
    fixture.close();
  }
});
