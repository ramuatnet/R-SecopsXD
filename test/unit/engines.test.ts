import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePage } from '../../src/engines/builtin/crawlerLite.ts';
import { SourceScanEngine } from '../../src/engines/builtin/sourceScan.ts';
import { DepManifestEngine } from '../../src/engines/builtin/depManifest.ts';
import { HttpObservationEngine, pageEvidence } from '../../src/engines/builtin/httpObservation.ts';
import type { ScanContext, CrawlPage } from '../../src/engines/types.ts';
import type { FileEvidence, RawFinding, Target } from '../../src/core/types.ts';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function fileEv(f: RawFinding): FileEvidence {
  const ev = f.evidence[0]!;
  if (ev.kind !== 'file') throw new Error(`expected file evidence for ${f.rawId}, got ${ev.kind}`);
  return ev;
}

const SOURCE_TARGET: Target = {
  id: 't1', name: 'src', origin: '', kind: 'source',
  sourcePath: join(import.meta.dirname, '..', '..', 'fixtures', 'source-project'),
  approved: true, createdAt: new Date().toISOString(),
};

const WEB_TARGET: Target = {
  id: 't2', name: 'web', origin: 'http://127.0.0.1:8899', kind: 'webapp',
  approved: true, createdAt: new Date().toISOString(),
};

function fakeCtx(over: Partial<ScanContext> = {}): ScanContext {
  return {
    scanId: 's1', target: SOURCE_TARGET, mode: 'passive',
    client: {} as never, guard: {} as never, stats: { sent: 0, blocked: 0 },
    signal: new AbortController().signal, workDir: '.',
    log: () => {},
    ...over,
  };
}

function webCtx(over: Partial<ScanContext> = {}): ScanContext {
  return fakeCtx({ target: WEB_TARGET, ...over });
}

test('parsePage extracts links and forms', () => {
  const page = parsePage('http://127.0.0.1:8899/', `
    <a href="/login">Login</a> <a href="https://external.example/x">Ext</a>
    <a href="/search?q=test">Search</a>
    <form action="/login" method="post"><input name="username"><input name="password" type="password"></form>
  `);
  assert.ok(page.links.some((l) => l === 'http://127.0.0.1:8899/login'));
  assert.ok(page.links.some((l) => l === 'https://external.example/x'));
  assert.equal(page.forms.length, 1);
  const form = page.forms[0]!;
  assert.equal(form.action, 'http://127.0.0.1:8899/login');
  assert.equal(form.method, 'post');
  assert.ok(form.hasPasswordField);
  assert.deepEqual(form.fields, ['username', 'password']);
});

test('source scan detects all planted issues with file+line evidence', async () => {
  const engine = new SourceScanEngine();
  const res = await engine.run(fakeCtx());
  const byRule = new Map(res.findings.map((f) => [f.rawId, f]));

  const sql = byRule.get('sql-concatenation');
  assert.ok(sql, 'sql-concatenation missing');
  assert.equal(sql.category, 'A05');
  assert.equal(sql.cwe, 89);
  assert.match(fileEv(sql).path ?? '', /users.js$/);
  assert.equal(fileEv(sql).lineStart, 6);

  const cred = byRule.get('hardcoded-credential');
  assert.ok(cred, 'hardcoded-credential missing');
  assert.equal(cred.category, 'A07');
  assert.equal(fileEv(cred).lineStart, 5);

  const weak = byRule.get('weak-hash-md5-sha1');
  assert.ok(weak, 'weak-hash missing');
  assert.equal(weak.category, 'A04');

  const tls = byRule.get('tls-verification-disabled');
  assert.ok(tls, 'tls-verification-disabled missing');
  assert.equal(tls.category, 'A04');

  // heuristic posture: probable, not confirmed
  for (const f of res.findings) {
    assert.equal(f.status, 'probable');
    assert.ok(['low', 'medium'].includes(f.confidence ?? 'medium'));
  }
});

test('dep manifest inventories lockfile packages and marks inventory informational', async () => {
  const engine = new DepManifestEngine();
  const res = await engine.run(fakeCtx());
  const inv = res.findings.find((f) => f.rawId === 'dependency-inventory');
  assert.ok(inv);
  assert.equal(inv.category, 'A03');
  assert.equal(inv.status, 'informational');
  const ev = inv.evidence[0]!;
  assert.equal(ev.kind, 'dependency');
  assert.match(ev.observation, /3 locked packages/);
  // lockfile exists, so no missing-lockfile finding
  assert.ok(!res.findings.some((f) => f.rawId === 'no-lockfile'));
});

test('dep manifest warns when package.json exists without lockfile', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ovap-dep-'));
  try {
    writeFileSync(join(dir, 'package.json'), '{"name":"x","dependencies":{"a":"1.0.0"}}');
    const engine = new DepManifestEngine();
    const res = await engine.run(fakeCtx({ target: { ...SOURCE_TARGET, sourcePath: dir } }));
    assert.ok(res.findings.some((f) => f.rawId === 'no-lockfile'));
    assert.ok(res.findings.some((f) => f.rawId === 'dependency-inventory'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function makePage(over: Partial<CrawlPage> & { url: string }): CrawlPage {
  return {
    status: 200, headers: {}, body: '<html></html>', truncated: false, forms: [], links: [],
    ...over,
  };
}

test('http observation detects missing headers, cookies, banner, comments, stack trace', async () => {
  const engine = new HttpObservationEngine();
  const ctx = webCtx({
    crawl: {
      pages: [
        makePage({
          url: 'http://127.0.0.1:8899/',
          headers: {
            'server': 'insecure-express-clone/1.0.0',
            'x-powered-by': 'VulnMode',
            'set-cookie': 'session=deadbeef; Path=/',
            'content-type': 'text/html',
          },
          body: '<!-- BUILD deployed on web-prod-07 (10.20.30.40). Internal debug endpoint: /api/debug/env -->',
        }),
        makePage({
          url: 'http://127.0.0.1:8899/api/users/999',
          status: 500,
          body: '<pre>Error: x at UserService.getProfile (/srv/app/services/user-service.js:214:19)</pre>',
        }),
      ],
      robots: { disallow: [], fetched: true },
    },
  });
  const res = await engine.run(ctx);
  const ids = new Set(res.findings.map((f) => f.rawId));
  assert.ok(ids.has('missing-security-headers'), 'missing-security-headers missing');
  assert.ok(ids.has('cookie-missing-flags'), 'cookie-missing-flags missing');
  assert.ok(ids.has('server-banner-disclosure'), 'banner missing');
  assert.ok(ids.has('sensitive-html-comments'), 'comments missing');
  assert.ok(ids.has('verbose-error-disclosure'), 'error disclosure missing');

  const err = res.findings.find((f) => f.rawId === 'verbose-error-disclosure')!;
  assert.equal(err.category, 'A10');
  assert.equal(err.cwe, 209);
  assert.equal(err.status, 'confirmed');
});

test('http observation: clean responses produce no findings (precision)', async () => {
  const engine = new HttpObservationEngine();
  const ctx = webCtx({
    crawl: {
      pages: [
        makePage({
          url: 'http://127.0.0.1:8899/',
          headers: {
            'content-security-policy': "default-src 'self'",
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'DENY',
            'referrer-policy': 'no-referrer',
            'set-cookie': 'session=x; Path=/; HttpOnly; Secure; SameSite=Lax',
            'content-type': 'text/html',
          },
          body: '<p>Clean page with no secrets</p>',
        }),
        makePage({
          url: 'http://127.0.0.1:8899/api/users/999',
          status: 404,
          body: '{"error":"not_found"}',
        }),
      ],
      robots: { disallow: [], fetched: true },
    },
  });
  const res = await engine.run(ctx);
  assert.deepEqual(res.findings, []);
});

test('http observation: cleartext password form finding on loopback is informational/low', async () => {
  const engine = new HttpObservationEngine();
  const ctx = webCtx({
    crawl: {
      pages: [makePage({
        url: 'http://127.0.0.1:8899/login',
        body: '<form action="/login" method="post"><input name="password" type="password"></form>',
      })],
      robots: { disallow: [], fetched: false },
    },
  });
  const res = await engine.run(ctx);
  const f = res.findings.find((x) => x.rawId === 'cleartext-credential-form');
  assert.ok(f);
  assert.equal(f.category, 'A04');
  assert.equal(f.severity, 'low', 'loopback targets should not be rated high');
  assert.equal(f.status, 'informational');
});

test('pageEvidence caps and observes', () => {
  const ev = pageEvidence(makePage({ url: 'http://h/', status: 200, body: 'x'.repeat(400) }));
  assert.equal(ev.kind, 'http');
  assert.ok((ev.response?.bodyExcerpt ?? '').length <= 400);
  assert.match(ev.observation, /→ 200/);
});

// ---------- honest-unknown: failed fetches never imply absent headers ----------

test('blocked/failed pages (status 0) produce no header-absence findings', async () => {
  const engine = new HttpObservationEngine();
  const blocked: never = { ok: false, blocked: 'redirect blocked: cross-origin redirect denied', url: 'http://127.0.0.1:8899/' } as never;
  const ctx = webCtx({
    client: { get: async (_url: string) => blocked } as never,
    crawl: {
      pages: [
        makePage({ url: 'http://127.0.0.1:8899/', status: 0, headers: {}, body: '', links: [] }),
      ],
      robots: { disallow: [], fetched: false },
    },
  });
  const res = await engine.run(ctx);
  const headerFinds = res.findings.filter((f) => f.rawId === 'missing-security-headers' || f.rawId === 'hsts-not-set');
  assert.equal(headerFinds.length, 0, 'absence must not be inferred from a fetch that never produced a response');
});

test('crawler emits root-fetch-blocked finding when the root fetch is scope-blocked', async () => {
  const { CrawlerLiteEngine } = await import('../../src/engines/builtin/crawlerLite.ts');
  const engine = new CrawlerLiteEngine(20);
  const blocked: never = { ok: false, blocked: 'redirect blocked: cross-origin redirect denied', url: 'http://127.0.0.1:8899/' } as never;
  const client = { get: async (_url: string) => blocked, postForm: async () => blocked, postJson: async () => blocked };
  const guard = { inScope: () => true } as never;
  const ctx = webCtx({ client: client as never, guard, crawl: { pages: [], robots: { disallow: [], fetched: false } } });
  const res = await engine.run(ctx);
  const blockedFindings = res.findings.filter((f) => f.rawId === 'root-fetch-blocked');
  assert.equal(blockedFindings.length, 1, 'exactly one root-fetch-blocked info finding');
  assert.match(blockedFindings[0]!.evidence[0]!.kind === 'process' ? blockedFindings[0]!.evidence[0]!.observation : '', /redirect blocked/);
});

// ---------- EASM: murmur3, CT filtering, AXFR, asset discovery, tech signatures ----------

test('murmur3 x86_32 matches reference vectors', async () => {
  const { murmur3Hex } = await import('../../src/engines/builtin/hostInfra.ts');
  assert.equal(murmur3Hex(''), '00000000');
  assert.equal(murmur3Hex('hello'), '248bfa47', 'shodan favicon-hash compatible mmh3 of "hello"');
});

test('filterCtNames strips wildcards, dedupes, keeps only domain space', async () => {
  const { filterCtNames } = await import('../../src/engines/builtin/assetDiscovery.ts');
  const names = filterCtNames(
    [
      { name_value: '*.htcinc.com\nmail.htcinc.com' },
      { name_value: 'htcinc.com' },
      { name_value: 'evil.example.com' },
      { name_value: 'admin@htcinc.com' },
      { name_value: 'dev.htcinc.com\ndev.htcinc.com' },
    ],
    'htcinc.com',
  );
  assert.deepEqual(names, ['dev.htcinc.com', 'htcinc.com', 'mail.htcinc.com']);
});

test('buildAxfrQuery produces a well-formed AXFR question', async () => {
  const { buildAxfrQuery } = await import('../../src/engines/builtin/assetDiscovery.ts');
  const q = buildAxfrQuery('example.com');
  assert.equal(q[0], 0x2a); // id
  assert.equal(q.readUInt16BE(4), 1); // qdcount
  const idx = q.length - 4;
  assert.equal(q[idx], 0x00); // QTYPE hi
  assert.equal(q[idx + 1], 0xfc); // QTYPE lo = 252 (AXFR)
  assert.equal(q[idx + 2], 0x00); // QCLASS hi
  assert.equal(q[idx + 3], 0x01); // QCLASS lo = IN
  // labels: \x07example\x03com\x00
  assert.ok(q.subarray(12).includes(Buffer.from('\x07example\x03com\x00')));
});

test('registrableDomain extracts last two labels; rejects localhost', async () => {
  const { registrableDomain } = await import('../../src/engines/builtin/assetDiscovery.ts');
  assert.equal(registrableDomain('www.htcinc.com'), 'htcinc.com');
  assert.equal(registrableDomain('a.b.htcnxt.ai'), 'htcnxt.ai');
  assert.equal(registrableDomain('localhost'), undefined);
});

test('asset discovery short-circuits for IP-literal targets (no network)', async () => {
  const { AssetDiscoveryEngine } = await import('../../src/engines/builtin/assetDiscovery.ts');
  const engine = new AssetDiscoveryEngine();
  const res = await engine.run({
    scanId: 's', target: { id: 't', name: 'x', origin: 'http://127.0.0.1:8899', kind: 'webapp', approved: true, createdAt: new Date().toISOString() },
    mode: 'passive', client: {} as never, guard: {} as never, stats: { sent: 0, blocked: 0 },
    signal: new AbortController().signal, workDir: '.', log: () => {},
  } as never);
  assert.equal(res.findings.length, 0);
  assert.match(res.detail ?? '', /IP literal/);
});

test('host-infra identifies tech stack from body/header signatures (live loopback)', async () => {
  const { HostInfraEngine } = await import('../../src/engines/builtin/hostInfra.ts');
  const createHttpServer = (await import('node:http')).createServer;
  const server = createHttpServer((_req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => {
    res.writeHead(200, { 'content-type': 'text/html', 'x-jenkins': '2.440.1' });
    res.end('<html><title>Dashboard [Jenkins]</title></html>');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  try {
    const engine = new HostInfraEngine();
    const res = await engine.run({
      scanId: 's', target: { id: 't', name: 'x', origin: `http://localhost:${port}`, kind: 'webapp', approved: true, createdAt: new Date().toISOString() },
      mode: 'active', client: {} as never, guard: {} as never, stats: { sent: 0, blocked: 0 },
      signal: new AbortController().signal, workDir: '.', log: () => {},
    } as never);
    const identified = res.findings.filter((f: { rawId?: string }) => f.rawId === 'service-identified');
    assert.ok(identified.length > 0, 'service-identified emitted');
    const obs = identified[0]!.evidence[0]!.kind === 'process' ? identified[0]!.evidence[0]!.observation : '';
    assert.match(obs, /Jenkins/i);
    const mgmt = res.findings.filter((f: { rawId?: string }) => f.rawId === 'management-interface-exposed');
    assert.ok(mgmt.length > 0, 'management interface flagged for Jenkins signature');
  } finally {
    server.close();
  }
});
