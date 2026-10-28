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
