/**
 * Python data-plane tests (v2 Phase 0-py / T0.4 + T4.1-py).
 *
 * The TS EngineBridge spawns engine/rsec_engine.py and the tests mirror the
 * TS httpClient safety tests 1:1 (scope, redirects, redaction, budget).
 * Skips with a visible reason when python is not on PATH.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import { createServer as createHttpServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EngineBridge, type BridgeRequestParams } from '../../src/engine-bridge/bridge.ts';

const PYTHON_AVAILABLE = (() => {
  try {
    execSync('python --version', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
})();

const SCOPE = (origin: string) => ({ origins: [origin], allow_public: true, max_redirect_hops: 5 });
const SAFETY = { rate_per_sec: 200, burst: 50, max_concurrency: 4 };
const BUDGET = { max_requests: 50, max_ms: 30_000 };

function baseParams(origin: string): BridgeRequestParams {
  return {
    scan_id: 'test-scan', action_id: 'test-action',
    scope: SCOPE(origin), safety: SAFETY, budget: BUDGET,
  };
}

test('EngineBridge: ping round-trip and scope-enforced http.get against a local server', async () => {
  const server = createHttpServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    if (url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html', server: 'test/1.0' });
      res.end('<h1>engine test</h1>');
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const bridge = new EngineBridge();
  try {
    bridge.start();
    const pong = await bridge.ping();
    assert.equal(pong.pong, true);
    assert.equal(pong.engine, 'rsec-engine-py');

    const res = await bridge.call('http.get', {
      ...baseParams(origin),
      args: { url: `${origin}/` },
    });
    assert.equal(res.status, 200);
    assert.equal(res.final_url, `${origin}/`);
    assert.ok((res.body ?? '').includes('engine test'));
    assert.equal(res.headers?.server, 'test/1.0');
    bridge.stop();
  } finally {
    server.close();
  }
});

test('engine enforces scope: out-of-scope host blocked (I2 parity with TS guard)', async () => {
  const server = createHttpServer((_req, res) => { res.writeHead(200); res.end('reachable'); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const reachablePort = (server.address() as { port: number }).port;
  const bridge = new EngineBridge();
  try {
    bridge.start();
    // scope pins a DIFFERENT origin; requesting the reachable server must be blocked
    await assert.rejects(
      bridge.call('http.get', {
        ...baseParams('http://127.0.0.1:1'),
        args: { url: `http://127.0.0.1:${reachablePort}/` },
      }),
      (e: Error) => (e as { code?: string }).code === 'scope_blocked',
    );
    bridge.stop();
  } finally {
    server.close();
  }
});

test('engine follows same-origin redirects and blocks out-of-scope hops (I2 parity)', async () => {
  let hops = 0;
  const server = createHttpServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    hops++;
    if (url.pathname === '/redirect-internal') {
      res.writeHead(302, { location: '/final' });
      return res.end();
    }
    if (url.pathname === '/redirect-external') {
      res.writeHead(302, { location: 'http://127.0.0.1:9/x' }); // out of scope (port 9 discard)
      return res.end();
    }
    if (url.pathname === '/final') {
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end('<h1>final</h1>');
    }
    res.writeHead(404); res.end();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const bridge = new EngineBridge();
  try {
    bridge.start();
    const internal = await bridge.call('http.get', {
      ...baseParams(origin), args: { url: `${origin}/redirect-internal` },
    });
    assert.equal(internal.status, 200);
    assert.deepEqual(internal.redirect_chain, [`${origin}/redirect-internal`]);

    await assert.rejects(
      bridge.call('http.get', {
        ...baseParams(origin), args: { url: `${origin}/redirect-external` },
      }),
      (e: Error) => (e as { code?: string }).code === 'scope_blocked',
    );
    bridge.stop();
  } finally {
    server.close();
  }
});

test('engine redacts sensitive headers in captured evidence (I4 parity)', async () => {
  let seenAuth: string | undefined;
  const server = createHttpServer((req, res) => {
    seenAuth = req.headers.authorization;
    res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'session=SECRETVALUE; Path=/' });
    res.end('{"token":"AKIAIOSFODNN7EXAMPLE","ok":true}');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const bridge = new EngineBridge();
  try {
    bridge.start();
    const res = await bridge.call('http.get', {
      ...baseParams(origin),
      args: { url: `${origin}/`, headers: { authorization: 'Bearer live-secret-token-2026' } },
    });
    // server must have received the real header (auth works), engine capture must redact it
    assert.equal(seenAuth, 'Bearer live-secret-token-2026');
    const reqHeaders = (res as unknown as { request_headers?: Record<string, string> }).request_headers ?? {};
    assert.match(reqHeaders.authorization ?? '', /REDACTED/, 'request header redacted in captured evidence');
    assert.ok(!JSON.stringify(res).includes('live-secret-token-2026'), 'the secret value itself must not survive');
    const bodyText = JSON.stringify(res);
    assert.ok(!bodyText.includes('AKIAIOSFODNN7EXAMPLE'), 'AWS key pattern redacted in body');
    assert.ok(!bodyText.includes('SECRETVALUE'), 'set-cookie value redacted');
    bridge.stop();
  } finally {
    server.close();
  }
});

test('engine enforces method policy and request budget (I10/T2.4 parity)', async () => {
  const server = createHttpServer((_req, res) => { res.writeHead(200); res.end('ok'); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const bridge = new EngineBridge();
  try {
    bridge.start();
    // POST is permitted by platform policy
    const post = await bridge.call('http.post', { ...baseParams(origin), args: { url: `${origin}/x`, body: 'a=1' } });
    assert.equal(post.status, 200);
    // DELETE refused (safety_blocked)
    await assert.rejects(
      bridge.call('http.delete', { ...baseParams(origin), args: { url: `${origin}/x` } }),
      (e: Error) => (e as { code?: string }).code === 'safety_blocked',
    );
    // budget: cumulative max_requests across the engine lifetime (the POST above
    // already consumed one send, so the cap of 2 lands on the second GET)
    const budgetParams = { ...baseParams(origin), budget: { max_requests: 2, max_ms: 30_000 } };
    await bridge.call('http.get', { ...budgetParams, args: { url: `${origin}/1` } });
    await assert.rejects(
      bridge.call('http.get', { ...budgetParams, args: { url: `${origin}/2` } }),
      (e: Error) => (e as { code?: string }).code === 'budget_exhausted',
    );
    bridge.stop();
  } finally {
    server.close();
  }
});

test('engine survives unknown methods and reports clean errors (no daemon death)', async () => {
  const server = createHttpServer((_req, res) => { res.writeHead(200); res.end('ok'); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const bridge = new EngineBridge();
  try {
    bridge.start();
    await assert.rejects(
      bridge.call('time.travel', { ...baseParams(origin) }),
      (e: Error) => (e as { code?: string }).code === 'bad_request',
    );
    // engine still alive: ping works after the error
    const pong = await bridge.ping();
    assert.equal(pong.pong, true);
    bridge.stop();
  } finally {
    server.close();
  }
});
