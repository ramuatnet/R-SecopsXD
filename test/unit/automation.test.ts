/**
 * Tests for the automation-program increment: TLS analysis (A04),
 * OpenAPI policy review (A06), A09 logging rules + correlation observation.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpsServer } from 'node:https';
import { createServer as createHttpServer } from 'node:http';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyzeHandshake, TlsAnalysisEngine } from '../../src/engines/builtin/tlsAnalysis.ts';
import { OpenApiPolicyEngine } from '../../src/engines/builtin/openapiPolicy.ts';
import { SourceScanEngine } from '../../src/engines/builtin/sourceScan.ts';
import { ScopeGuard } from '../../src/safety/guard.ts';
import { RateLimiter } from '../../src/safety/rateLimiter.ts';
import { Semaphore } from '../../src/safety/concurrency.ts';
import { ScopedHttpClient } from '../../src/scan/httpClient.ts';
import type { PeerCertificate } from 'node:tls';
import type { Target } from '../../src/core/types.ts';

const CERT = readFileSync(join(import.meta.dirname, '..', '..', 'fixtures', 'certs', 'cert1.pem'), 'utf8');
const KEY = readFileSync(join(import.meta.dirname, '..', '..', 'fixtures', 'certs', 'key1.pem'), 'utf8');

function fakeCert(over: Partial<PeerCertificate> = {}): PeerCertificate {
  return {
    subject: { CN: '127.0.0.1' },
    issuer: { CN: 'Fake CA' },
    subjectaltname: 'DNS:127.0.0.1, IP Address:127.0.0.1',
    valid_from: '2026-01-01T00:00:00Z',
    valid_to: '2027-01-01T00:00:00Z',
    ...over,
  } as PeerCertificate;
}

// ---------- TLS analysis (pure function) ----------

test('TLS analysis flags expired, self-signed, mismatched certs and legacy protocol', () => {
  const now = new Date('2026-10-27T00:00:00Z');
  const expired = analyzeHandshake('shop.example.com', 443, {
    protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384',
    cert: fakeCert({
      valid_to: '2026-10-01T00:00:00Z',
      subject: { CN: 'shop.example.com' }, issuer: { CN: 'Real CA' },
      subjectaltname: 'DNS:shop.example.com',
    }),
  }, now);
  const ids = expired.findings.map((f) => f.rawId);
  assert.ok(ids.includes('tls-cert-expired'), 'expired must be flagged');

  const legacy = analyzeHandshake('shop.example.com', 443, {
    protocol: 'TLSv1.1', cipher: 'ECDHE-RSA-AES128-SHA', cert: fakeCert(),
  }, now);
  assert.ok(legacy.findings.some((f) => f.rawId === 'tls-legacy-protocol'));

  const mismatch = analyzeHandshake('shop.example.com', 443, {
    protocol: 'TLSv1.3', cert: fakeCert({ subjectaltname: 'DNS:other.example.com' }),
  }, now);
  assert.ok(mismatch.findings.some((f) => f.rawId === 'tls-cert-hostname-mismatch'));
});

test('TLS analysis stays quiet on a healthy handshake', () => {
  const now = new Date('2026-10-27T00:00:00Z');
  const clean = analyzeHandshake('shop.example.com', 443, {
    protocol: 'TLSv1.3', cipher: 'TLS_AES_128_GCM_SHA256',
    cert: fakeCert({
      valid_to: '2027-06-01T00:00:00Z',
      subject: { CN: 'shop.example.com' }, issuer: { CN: 'Real CA' },
      subjectaltname: 'DNS:shop.example.com',
    }),
  }, now);
  assert.deepEqual(clean.findings, []);
});

// ---------- TLS engine live smoke test ----------

test('TLS engine performs a real handshake against a local self-signed server', async () => {
  const server = createHttpsServer({ key: KEY, cert: CERT }, (_req, res) => res.end('ok'));
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  try {
    const engine = new TlsAnalysisEngine();
    const ctx = {
      scanId: 's', mode: 'passive' as const,
      target: { id: 't', name: 'x', origin: `https://127.0.0.1:${port}`, kind: 'webapp' as const, approved: true, createdAt: new Date().toISOString() },
      client: {} as never, guard: {} as never, stats: { sent: 0, blocked: 0 },
      signal: new AbortController().signal, workDir: '.', log: () => {},
    };
    const res = await engine.run(ctx as never);
    assert.equal(res.findings.some((f) => f.rawId === 'tls-cert-self-signed'), true, 'self-signed must be detected');
    assert.ok(res.detail?.includes('handshake OK'));
  } finally {
    server.close();
  }
});

test('TLS engine reports not-applicable for plain-HTTP origins', async () => {
  const server = createHttpServer((_req, res) => res.end('ok'));
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  try {
    const engine = new TlsAnalysisEngine();
    const ctx = {
      scanId: 's', mode: 'passive' as const,
      target: { id: 't', name: 'x', origin: `http://127.0.0.1:${port}`, kind: 'webapp' as const, approved: true, createdAt: new Date().toISOString() },
      client: {} as never, guard: {} as never, stats: { sent: 0, blocked: 0 },
      signal: new AbortController().signal, workDir: '.', log: () => {},
    };
    const res = await engine.run(ctx as never);
    assert.equal(res.findings.length, 0);
    assert.match(res.detail ?? '', /plain HTTP/);
  } finally {
    server.close();
  }
});

// ---------- OpenAPI policy ----------

const SPEC = JSON.stringify({
  openapi: '3.0.1',
  info: { title: 'Demo API', version: '1.0' },
  components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } } },
  paths: {
    '/orders': {
      get: { summary: 'list', security: [{ bearerAuth: [] }] },
      post: { summary: 'create', security: [] },
    },
    '/health': { get: { summary: 'ping' } },
  },
});

test('OpenAPI policy engine reports exposed spec and unauthenticated operations', async () => {
  const server = createHttpServer((req, res) => {
    if (req.url === '/openapi.json') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(SPEC);
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end('{}');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  const origin = `http://127.0.0.1:${port}`;
  try {
    const guard = new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 });
    const client = new ScopedHttpClient(guard, new RateLimiter(100, 50), new Semaphore(4), { timeoutMs: 3000, maxRedirectHops: 2 }, { sent: 0, blocked: 0 });
    const engine = new OpenApiPolicyEngine();
    const ctx = {
      scanId: 's', mode: 'passive' as const,
      target: { id: 't', name: 'x', origin, kind: 'webapp' as const, approved: true, createdAt: new Date().toISOString() },
      client, guard, stats: { sent: 0, blocked: 0 },
      signal: new AbortController().signal, workDir: '.', log: () => {},
    };
    const res = await engine.run(ctx);
    const ids = res.findings.map((f) => f.rawId);
    assert.ok(ids.includes('openapi-spec-exposed'), 'spec exposure finding');
    const unauth = res.findings.find((f) => f.rawId === 'openapi-unauthenticated-operations');
    assert.ok(unauth, 'unauthenticated operations finding');
    assert.match(unauth!.title, /2 of 3/);
    assert.equal(unauth!.category, 'A06');
    assert.equal(unauth!.status, 'probable');
  } finally {
    server.close();
  }
});

test('OpenAPI policy engine stays quiet when no spec is exposed', async () => {
  const server = createHttpServer((_req, res) => { res.writeHead(404); res.end('{}'); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  const origin = `http://127.0.0.1:${port}`;
  try {
    const guard = new ScopeGuard(origin, { allowPublicTargets: true, maxRedirectHops: 2 });
    const client = new ScopedHttpClient(guard, new RateLimiter(100, 50), new Semaphore(4), { timeoutMs: 3000, maxRedirectHops: 2 }, { sent: 0, blocked: 0 });
    const engine = new OpenApiPolicyEngine();
    const res = await engine.run({
      scanId: 's', mode: 'passive' as const,
      target: { id: 't', name: 'x', origin, kind: 'webapp' as const, approved: true, createdAt: new Date().toISOString() },
      client, guard, stats: { sent: 0, blocked: 0 },
      signal: new AbortController().signal, workDir: '.', log: () => {},
    } as never);
    assert.deepEqual(res.findings, []);
  } finally {
    server.close();
  }
});

// ---------- A09 source logging rules ----------

test('source scan flags secrets in logs and log injection (A09)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ovap-a09-'));
  try {
    mkdirSync(join(dir, 'src'), { recursive: true });
    writeFileSync(join(dir, 'src', 'logging.js'), [
      "const user = { password: 'hunter2hunter2' };",
      "console.log('login attempt', user.password);",
      "logger.info(`login failed for ${req.query.username}`);",
      "logger.info('benign operational message');",
    ].join('\n'));
    const engine = new SourceScanEngine();
    const target: Target = { id: 't', name: 's', origin: '', kind: 'source', sourcePath: dir, approved: true, createdAt: new Date().toISOString() };
    const res = await engine.run({
      scanId: 's', target, mode: 'passive', client: {} as never, guard: {} as never,
      stats: { sent: 0, blocked: 0 }, signal: new AbortController().signal, workDir: '.', log: () => {},
    } as never);
    const ids = res.findings.map((f) => f.rawId);
    assert.ok(ids.includes('secrets-in-logs'), 'secrets-in-logs rule must fire');
    assert.ok(ids.includes('log-injection'), 'log-injection rule must fire');
    for (const f of res.findings) {
      if (f.rawId === 'secrets-in-logs' || f.rawId === 'log-injection') {
        assert.equal(f.category, 'A09');
        assert.equal(f.evidence[0]!.kind, 'file');
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------- correlation-ID observation (A09 webapp) ----------

test('http observation flags correlation headers on error responses only', async () => {
  const { HttpObservationEngine } = await import('../../src/engines/builtin/httpObservation.ts');
  const engine = new HttpObservationEngine();
  const target: Target = { id: 't', name: 'web', origin: 'http://127.0.0.1:8899', kind: 'webapp', approved: true, createdAt: new Date().toISOString() };
  const mk = (url: string, status: number, headers: Record<string, string>) => ({
    url, status, headers, truncated: false, forms: [], links: [],
    body: '<p>x</p>',
  });
  const ctx = {
    scanId: 's', target, mode: 'passive' as const, client: {} as never, guard: {} as never,
    stats: { sent: 0, blocked: 0 }, signal: new AbortController().signal, workDir: '.', log: () => {},
    crawl: {
      pages: [
        mk('http://127.0.0.1:8899/api/x', 500, { 'x-request-id': 'abc123' }),
        mk('http://127.0.0.1:8899/', 200, { 'x-request-id': 'abc123' }),
      ],
      robots: { disallow: [], fetched: false },
    },
  };
  const res = await engine.run(ctx as never);
  const corr = res.findings.filter((f) => f.rawId === 'log-correlation-header');
  assert.equal(corr.length, 1, 'only the error response is relevant');
  assert.equal(corr[0]!.category, 'A09');
  assert.equal(corr[0]!.severity, 'info');
});

test('TLS wildcard SAN: *.owasp.org matches one-label subdomains only (vwad.owasp.org FP regression)', async () => {
  const { certMatchesHost } = await import('../../src/engines/builtin/tlsAnalysis.ts');
  assert.equal(certMatchesHost(['owasp.org', '*.owasp.org'], 'vwad.owasp.org'), true, 'wildcard matches one label');
  assert.equal(certMatchesHost(['*.owasp.org'], 'a.b.owasp.org'), false, 'wildcard does not match two labels');
  assert.equal(certMatchesHost(['*.owasp.org'], 'owasp.org'), false, 'wildcard does not match apex');
  assert.equal(certMatchesHost(['shop.example.com'], 'shop.example.com'), true, 'exact match');
  assert.equal(certMatchesHost(['*.example.com'], 'evil-example.com'), false, 'no suffix-pretend match');
});
