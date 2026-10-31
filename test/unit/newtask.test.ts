/**
 * Tests for newtask.md: Phase A (port surfacing, honest skips, coverage
 * honesty) and Phase B (in-house nuclei pack: args audit, gating, linter).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { portSeverity } from '../../src/engines/builtin/hostInfra.ts';
import { VariantHunter } from '../../src/engines/builtin/variantHunter.ts';
import { ReflectionProbeEngine } from '../../src/engines/builtin/reflectionProbe.ts';
import { RedirectProbeEngine } from '../../src/engines/builtin/redirectProbe.ts';
import { EndpointDiscoveryEngine } from '../../src/engines/builtin/endpointDiscovery.ts';
import { computeCoverage } from '../../src/scan/coverage.ts';
import {
  buildNucleiArgs, gateTemplates, inferCapabilities, loadTemplateIndex, NucleiAdapter,
} from '../../src/engines/adapters/nuclei.ts';
import { lintTemplates } from '../../scripts/lint-templates.ts';
import type { ScanContext } from '../../src/engines/types.ts';
import type { Finding } from '../../src/core/types.ts';

function emptyCtx(origin: string, over: Partial<ScanContext> = {}): ScanContext {
  return {
    scanId: 's', target: { id: 't', name: 'x', origin, kind: 'webapp', approved: true, createdAt: new Date().toISOString() },
    mode: 'active', client: {} as never, guard: {} as never, stats: { sent: 0, blocked: 0 },
    signal: new AbortController().signal, workDir: '.', log: () => {},
    ...over,
  } as ScanContext;
}

// ---------- A1: port severity classes ----------

test('portSeverity: DB/remote-access ports are high, app/dev ports medium, web ports info', () => {
  for (const p of [21, 23, 445, 3389, 3306, 5432, 6379, 6443, 9200, 11211, 27017, 2375, 5900]) {
    assert.equal(portSeverity(p), 'high', `port ${p} must be high`);
  }
  for (const p of [3000, 5000, 7001, 8000, 8080, 8081, 8888, 9000, 9090]) {
    assert.equal(portSeverity(p), 'medium', `port ${p} must be medium`);
  }
  for (const p of [80, 443, 12345]) {
    assert.equal(portSeverity(p), 'info', `port ${p} must be info`);
  }
});

// ---------- A2: honest skips ----------

test('variant-hunter without seeds records notExecutedReason (never ran-0ms)', async () => {
  const res = await new VariantHunter().run(emptyCtx('http://127.0.0.1:8899'));
  assert.equal(res.findings.length, 0);
  assert.match(res.notExecutedReason ?? '', /no seed findings/);
});

test('reflection probe on empty corpus records notExecutedReason', async () => {
  const res = await new ReflectionProbeEngine().run(emptyCtx('http://127.0.0.1:8899', { crawl: { pages: [], robots: { disallow: [], fetched: false } } }));
  assert.match(res.notExecutedReason ?? '', /no crawl surface/);
});

test('redirect probe with no redirect params records notExecutedReason', async () => {
  const res = await new RedirectProbeEngine().run(emptyCtx('http://127.0.0.1:8899', {
    crawl: { pages: [{ url: 'http://127.0.0.1:8899/', status: 200, headers: {}, body: '', truncated: false, forms: [], links: [] }], robots: { disallow: [], fetched: false } },
  }));
  assert.match(res.notExecutedReason ?? '', /not applicable/);
});

test('endpoint discovery on empty corpus records notExecutedReason', async () => {
  const res = await new EndpointDiscoveryEngine().run(emptyCtx('http://127.0.0.1:8899', { crawl: { pages: [], robots: { disallow: [], fetched: false } } }));
  assert.match(res.notExecutedReason ?? '', /no crawl surface/);
});

// ---------- A4: coverage honesty ----------

test('coverage: all-clean category becomes RAN_CLEAN and never claims covered', () => {
  const engines = [
    { engine: 'builtin.http-observation', status: 'ran' as const, findingCount: 0, durationMs: 1 },
  ];
  const cov = computeCoverage(engines, 'standard-passive', [], 'webapp', 'passive');
  const a02 = cov.find((c) => c.category === 'A02')!;
  assert.equal(a02.status, 'RAN_CLEAN', 'zero findings + all tasks ran = RAN_CLEAN');
  assert.notEqual(a02.verdict, 'covered', 'RAN_CLEAN must never read covered');
  assert.match(a02.note, /ran-but-empty/);
});

test('coverage: category with attributed findings still reads COVERED_WITH_EVIDENCE', () => {
  const engines = [{ engine: 'builtin.http-observation', status: 'ran' as const, findingCount: 2, durationMs: 1 }];
  const finding = {
    id: 'f1', category: 'A02', severity: 'medium', status: 'confirmed', title: 't', asset: 'a', locator: '/',
    evidence: [], provenance: [{ engine: 'builtin.http-observation', rawId: 'missing-security-headers' }],
    firstSeen: new Date().toISOString(), lastSeen: new Date().toISOString(),
  } as unknown as Finding;
  const cov = computeCoverage(engines, 'standard-passive', [finding], 'webapp', 'passive');
  const a02 = cov.find((c) => c.category === 'A02')!;
  assert.equal(a02.status, 'COVERED_WITH_EVIDENCE');
  assert.equal(a02.verdict, 'covered');
});

// ---------- Phase B: nuclei pack ----------

test('buildNucleiArgs: exactly one -u target, in-house templates only, audit-friendly', () => {
  const args = buildNucleiArgs('http://target.example', 'active', ['A01-sensitive-exposure/rsec-git-config-exposure.yaml']);
  const uCount = args.filter((a) => a === '-u').length;
  assert.equal(uCount, 1, 'exactly one -u (egress audit N8)');
  assert.equal(args[args.indexOf('-u') + 1], 'http://target.example');
  assert.ok(args.includes('-jsonl') && args.includes('-silent') && args.includes('-duc'));
  assert.ok(args.includes('-etags'));
  assert.ok(!args.includes('-lfl'), 'no bulk list mode');
  // every -t value must be an in-house template path
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-t') assert.match(args[i + 1] ?? '', /templates|\.yaml$/);
  }
  const passive = buildNucleiArgs('http://target.example', 'passive', []);
  assert.ok(passive.includes('-passive'));
});

test('template gating: graphql templates run only when capability confirmed (N5)', async () => {
  const index = await loadTemplateIndex();
  const graphql = index.templates.filter((t) => (t.requires ?? []).includes('graphql'));
  assert.ok(graphql.length > 0, 'pack contains capability-gated templates');

  const noCaps = gateTemplates(index.templates, inferCapabilities(undefined));
  assert.ok(!noCaps.some((t) => t.id.startsWith('rsec-graphql')), 'gated templates excluded without capability');
  const withCaps = gateTemplates(index.templates, inferCapabilities({
    pages: [], robots: { disallow: [], fetched: false }, discoveredEndpoints: ['/graphql/query'],
  } as never));
  assert.ok(withCaps.some((t) => t.id.startsWith('rsec-graphql')), 'gated templates included with confirmed capability');
});

test('linter: full pack passes; synthetic violations are caught', () => {
  const packViolations = lintTemplates(join(import.meta.dirname, '..', '..', 'templates'));
  assert.equal(packViolations.filter((v) => v.rule !== 'index-entry' && v.rule !== 'index-parse').length, 0, JSON.stringify(packViolations));

  const bad = mkdtempSync(join(tmpdir(), 'rsec-lint-'));
  writeFileSync(join(bad, 'rsec-bad.yaml'), `id: rsec-bad
info:
  name: bad
  tags: not-rsec-tag
http:
  - method: GET
    path:
      - "{{BaseURL}}/x"
    matchers:
      - type: word
        words:
          - "a"
`);
  const v = lintTemplates(bad);
  const rules = new Set(v.map((x) => x.rule));
  assert.ok(rules.has('source-citation'), 'missing # source must fail (N9)');
  assert.ok(rules.has('required-severity'), 'missing severity must fail');
  assert.ok(rules.has('matcher-part'), 'matcher without part must fail (N3)');
  assert.ok(rules.has('index-parse'), 'missing index.json must fail');
});

test('parseEvents: canned nuclei JSONL maps rawId/severity/cwe/locator (parser canary)', () => {
  const jsonl = JSON.stringify({
    'template-id': 'rsec-git-config-exposure',
    info: { name: 'Exposed .git/config', severity: 'high', classification: { 'cwe-id': ['CWE-538'] } },
    host: 'http://x', 'matched-at': 'http://x/.git/config',
  });
  const findings = NucleiAdapter.parseEvents(jsonl + '\nnoise\n', 'http://x', 'test');
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.rawId, 'rsec-git-config-exposure');
  assert.equal(findings[0]!.severity, 'high');
  assert.equal(findings[0]!.cwe, 538);
  assert.equal(findings[0]!.locator, '/.git/config');
});

// ---------- V1 root cause: ip:port locators must never lose their port ----------

test('normalizeLocator preserves host:port, strips file line numbers (V1 regression)', async () => {
  const { normalizeLocator, makeFingerprint } = await import('../../src/core/ids.ts');
  assert.equal(normalizeLocator('103.234.149.210:9200'), '103.234.149.210:9200', 'port must survive');
  assert.equal(normalizeLocator('103.234.149.210:3306'), '103.234.149.210:3306', 'different port = different locator');
  assert.notEqual(
    makeFingerprint('A01', undefined, 'www.example', '103.234.149.210:9200'),
    makeFingerprint('A01', undefined, 'www.example', '103.234.149.210:3306'),
    'two open ports on one host must never share a fingerprint',
  );
  assert.equal(normalizeLocator('src/app.js:42'), 'src/app.js', 'file line numbers still stripped');
});
