/**
 * Verification module tests (v2 Phase 5: T5.1–T5.4).
 *
 * Positive + negative per validator; differential confirmation; promotion
 * rules with audit; FP-rate measurement on hardened responses.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpServer, type Server } from 'node:http';
import { verifyByType, applyVerification, falsePositiveRate, reobserve } from '../../src/verify/verify.ts';
import type { Finding } from '../../src/core/types.ts';
import type { ScopedHttpClient } from '../../src/scan/httpClient.ts';

function stubClient(handler: (url: string) => { status: number; headers?: Record<string, string>; body: string }): ScopedHttpClient {
  return {
    get: async (url: string) => {
      const r = handler(url);
      return { ok: true, status: r.status, headers: r.headers ?? {}, body: r.body, truncated: false, finalUrl: url, elapsedMs: 1 };
    },
    postForm: async () => { throw new Error('not used'); },
    request: async () => { throw new Error('not used'); },
  } as never;
}

function finding(rawId: string, url: string, title = rawId): Finding {
  return {
    id: `FND-${rawId}`, fingerprint: 'fp', title, category: 'A02',
    severity: 'medium', confidence: 'high', status: 'probable',
    asset: 'http://t', locator: '/', engine: 'builtin.http-observation',
    evidence: [{
      kind: 'http',
      request: { method: 'GET', url, headers: {} },
      response: { status: 200, headers: {}, bodyExcerpt: '<html>page</html>' },
      observation: 'original observation',
    }],
    explanation: 'x', remediation: 'r', references: [],
    detectedAt: new Date().toISOString(),
    provenance: [{ engine: 'builtin.http-observation', rawId, adapter: false }],
  };
}

const VULN_HEADERS = { 'content-type': 'text/html', server: 'Apache-Coyote/1.1' };
const HARDENED_HEADERS = {
  'content-type': 'text/html',
  'content-security-policy': "default-src 'self'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'strict-transport-security': 'max-age=31536000',
};

test('T5.1 missing-security-headers: confirmed on vulnerable re-fetch, rejected on hardened', async () => {
  const vuln = createHttpServer((_req, res) => { res.writeHead(200, VULN_HEADERS); res.end('<p>x</p>'); });
  await listen(vuln);
  const hardened = createHttpServer((_req, res) => { res.writeHead(200, HARDENED_HEADERS); res.end('<p>x</p>'); });
  await listen(hardened);
  const pv = `http://127.0.0.1:${(vuln.address() as { port: number }).port}`;
  const ph = `http://127.0.0.1:${(hardened.address() as { port: number }).port}`;
  try {
    const c1 = stubClient((u) => (u.startsWith(pv) ? { status: 200, headers: VULN_HEADERS, body: '<p>x</p>' } : { status: 200, headers: HARDENED_HEADERS, body: '<p>x</p>' }));
    const r1 = await verifyByType(finding('missing-security-headers', `${pv}/`), c1);
    assert.equal(r1.verdict, 'confirmed');

    const c2 = stubClient(() => ({ status: 200, headers: HARDENED_HEADERS, body: '<p>x</p>' }));
    const r2 = await verifyByType(finding('missing-security-headers', `${ph}/`), c2);
    assert.equal(r2.verdict, 'rejected');
  } finally { vuln.close(); hardened.close(); }
});

test('T5.1 hsts-missing: confirmed on https without HSTS, rejected with HSTS', async () => {
  const without = createHttpServer((_req, res) => { res.writeHead(200, VULN_HEADERS); res.end('x'); });
  await listen(without);
  const withH = createHttpServer((_req, res) => { res.writeHead(200, { ...HARDENED_HEADERS, 'strict-transport-security': 'max-age=31536000' }); res.end('x'); });
  await listen(withH);
  const p1 = `https://127.0.0.1:${(without.address() as { port: number }).port}`;
  const p2 = `https://127.0.0.1:${(withH.address() as { port: number }).port}`;
  try {
    const c = stubClient((u) => (u.startsWith(p1)
      ? { status: 200, headers: VULN_HEADERS, body: 'x' }
      : { status: 200, headers: { ...HARDENED_HEADERS, 'strict-transport-security': 'max-age=31536000' }, body: 'x' }));
    const r1 = await verifyByType(finding('hsts-missing', `${p1}/`), c);
    assert.equal(r1.verdict, 'confirmed');
    const r2 = await verifyByType(finding('hsts-missing', `${p2}/`), c);
    assert.equal(r2.verdict, 'rejected');
  } finally { without.close(); withH.close(); }
});

test('T5.1 cookie-missing-flags: confirmed when flags still absent', async () => {
  const server = createHttpServer((_req, res) => {
    res.writeHead(200, { 'set-cookie': 'session=abc; Path=/' });
    res.end('x');
  });
  await listen(server);
  const p = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const c = stubClient(() => ({ status: 200, headers: { 'set-cookie': 'session=abc; Path=/' }, body: 'x' }));
    const f = finding('cookie-missing-flags', `${p}/`, 'Cookie "session" set without SameSite flag(s)');
    const r = await verifyByType(f, c);
    assert.equal(r.verdict, 'confirmed');
    assert.match(r.rationale, /SameSite/);
  } finally { server.close(); }
});

test('T5.2 SQLi differential: FP fixture rejected, TP confirmed', async () => {
  // TP: error only under mutation
  const tpServer = createHttpServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    const id = url.searchParams.get('id') ?? '';
    if (id.includes("'")) { res.writeHead(500); res.end('SQLSTATE[HY000] error'); return; }
    res.writeHead(200); res.end('<p>item</p>');
  });
  await listen(tpServer);
  // FP: identical response regardless of mutation
  const fpServer = createHttpServer((_req, res) => { res.writeHead(200); res.end('<p>item</p>'); });
  await listen(fpServer);
  const tp = `http://127.0.0.1:${(tpServer.address() as { port: number }).port}`;
  const fp = `http://127.0.0.1:${(fpServer.address() as { port: number }).port}`;
  try {
    const ctp = stubClient((u) => (u.includes("'")
      ? { status: 500, body: 'You have an error in your SQL syntax' }
      : { status: 200, body: '<p>item</p>' }));
    const r1 = await verifyByType(finding('sqli-error-differential', `${tp}/item?id=5`), ctp);
    assert.equal(r1.verdict, 'confirmed', 'causal delta must confirm');

    const cfp = stubClient(() => ({ status: 200, body: '<p>item</p>' }));
    const r2 = await verifyByType(finding('sqli-error-differential', `${fp}/item?id=5`), cfp);
    assert.equal(r2.verdict, 'rejected', 'no delta must reject');
  } finally { tpServer.close(); fpServer.close(); }
});

test('T5.3 promotion: probable→confirmed only via verification, with audit entries', async () => {
  const f = finding('hsts-missing', 'https://t/');
  const findings = [f];
  const audits: Array<Record<string, unknown>> = [];
  const audit = (action: string, details: Record<string, unknown>): void => { audits.push({ action, ...details }); };

  const server = createHttpServer((_req, res) => { res.writeHead(200, VULN_HEADERS); res.end('x'); });
  await listen(server);
  try {
    const c = stubClient(() => ({ status: 200, headers: VULN_HEADERS, body: 'x' }));
    const report = await verifyByType(f, c);
    assert.equal(report.verdict, 'confirmed');
    const outcome = applyVerification(findings, report, audit);
    assert.equal(outcome?.to, 'confirmed');
    assert.equal(outcome.audited, true);
    assert.equal(f.status, 'confirmed');
    assert.equal(f.evidence.length, 2, 're-check evidence appended');
    assert.ok(audits.some((a) => a.action === 'finding.promoted'));
  } finally { server.close(); }
});

test('T5.3 rejected findings become false_positive with audit; inconclusive never promotes', async () => {
  const f1 = finding('hsts-missing', 'https://t/');
  const f2 = finding('sri-external-script', 'https://t/');
  const findings = [f1, f2];
  const audits: Array<Record<string, unknown>> = [];
  const audit = (action: string, details: Record<string, unknown>): void => { audits.push({ action, ...details }); };

  const hardened = () => ({ status: 200, headers: HARDENED_HEADERS, body: '<p>x</p>' });
  const r1 = await verifyByType(f1, stubClient(hardened));
  const r2 = await reobserve({ ...f2, evidence: [] }, stubClient(hardened));
  const o1 = applyVerification(findings, r1, audit);
  const o2 = applyVerification(findings, r2, audit);
  assert.equal(o1?.to, 'false_positive');
  assert.equal(r2.verdict, 'inconclusive');
  assert.equal(o2?.to, 'probable', 'inconclusive never promotes');
  assert.equal(o2.audited, false);
  assert.ok(audits.some((a) => a.action === 'finding.rejected'));
});

test('T5.4 FP rate: hardened-fixture batch measures rejections (negative controls)', () => {
  const mk = (verdict: 'confirmed' | 'rejected' | 'inconclusive') =>
    ({ findingId: 'f', rawId: 'r', verdict, rationale: '', recheck: undefined });
  const reports = [mk('rejected'), mk('rejected'), mk('confirmed'), mk('inconclusive')];
  const { rate, rejected, total } = falsePositiveRate(reports);
  assert.equal(rejected, 2);
  assert.equal(total, 3, 'inconclusive excluded from the rate');
  assert.ok(Math.abs(rate - 2 / 3) < 1e-9);
});

function listen(server: Server): Promise<void> {
  return new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
}
