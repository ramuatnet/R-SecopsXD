/**
 * Tests for evidence-based coverage (automation program Phases 2 + 13) and
 * the SRI integrity check (A08 quick win).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { computeCoverage, computeCoverageV1 } from '../../src/scan/coverage.ts';
import { TASKS } from '../../src/core/tasks.ts';
import type { EngineRunRecord, Finding } from '../../src/core/types.ts';

function eng(engine: string, status: EngineRunRecord['status']): EngineRunRecord {
  return { engine, status, findingCount: 0, durationMs: 1 };
}

function finding(engine: string, rawId: string, category: Finding['category'] = 'A02'): Finding {
  return {
    id: 'FND-' + category + '-TESTTESTTE', fingerprint: 'fp', title: 't', category,
    severity: 'medium', confidence: 'high', status: 'confirmed', asset: 'a', locator: '/',
    engine, evidence: [], explanation: 'e', remediation: 'r', references: [],
    detectedAt: new Date().toISOString(),
    provenance: [{ engine, rawId, adapter: false }],
  };
}

test('task registry: every category has at least one task and unique ids', () => {
  const ids = new Set(TASKS.map((t) => t.id));
  assert.equal(ids.size, TASKS.length, 'task ids must be unique');
  for (const cat of ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'] as const) {
    assert.ok(TASKS.some((t) => t.category === cat), `${cat} must have tasks`);
  }
  // by-design manual tasks always map to MANUAL_REVIEW_REQUIRED (tested below)
  assert.ok(TASKS.some((t) => t.manual), 'registry must declare honest manual tasks');
});

test('passive scan with clean engines: executed tasks AUTOMATED_PASS, manual stay MANUAL_REVIEW_REQUIRED', () => {
  const coverage = computeCoverage(
    [eng('builtin.crawler-lite', 'ran'), eng('builtin.http-observation', 'ran')],
    'standard-passive', [], 'webapp', 'passive',
  );
  const a02 = coverage.find((c) => c.category === 'A02')!;
  assert.equal(a02.status, 'COVERED_WITH_EVIDENCE',
    'all mandatory passive A02 tasks ran clean (active task is outside the passive profile scope)');
  const t01 = a02.tasks!.find((t) => t.taskId === 'A02-T01')!;
  assert.equal(t01.status, 'AUTOMATED_PASS', 'clean run of headers task');
  assert.ok(a02.note.includes('scope') || a02.note.includes('not applicable') || a02.note.includes('manual'),
    'scope limitation must be stated in the note');
  const a06 = coverage.find((c) => c.category === 'A06')!;
  assert.equal(a06.status, 'MANUAL_REVIEW_REQUIRED');
  assert.equal(a06.tasks![0]!.status, 'MANUAL_REVIEW_REQUIRED', 'by-design manual task stays manual');
  // backward-compat verdict still present
  assert.ok(['covered', 'partial', 'manual-only'].includes(a02.verdict));
});

test('finding attribution: matching rawIdPattern flips task to FINDING_DETECTED', () => {
  const coverage = computeCoverage(
    [eng('builtin.http-observation', 'ran')],
    'quick-passive',
    [finding('builtin.http-observation', 'cookie-missing-flags')],
    'webapp', 'passive',
  );
  const a02 = coverage.find((c) => c.category === 'A02')!;
  const cookieTask = a02.tasks!.find((t) => t.taskId === 'A02-T02')!;
  assert.equal(cookieTask.status, 'FINDING_DETECTED');
  assert.equal(cookieTask.findings, 1);
  const headerTask = a02.tasks!.find((t) => t.taskId === 'A02-T01')!;
  assert.equal(headerTask.status, 'AUTOMATED_PASS', 'unmatched task still ran clean');
});

test('unavailable engine → ENGINE_UNAVAILABLE, never a pass', () => {
  const coverage = computeCoverage(
    [eng('builtin.crawler-lite', 'ran'), eng('builtin.http-observation', 'unavailable')],
    'quick-passive', [], 'webapp', 'passive',
  );
  const a02 = coverage.find((c) => c.category === 'A02')!;
  const t01 = a02.tasks!.find((t) => t.taskId === 'A02-T01')!;
  assert.equal(t01.status, 'ENGINE_UNAVAILABLE');
  assert.equal(a02.status, 'MANUAL_REVIEW_REQUIRED');
});

test('failed engine → ERROR, category ASSESSMENT_FAILED when nothing else executed', () => {
  const coverage = computeCoverage(
    [eng('builtin.http-observation', 'failed')],
    'quick-passive', [], 'webapp', 'passive',
  );
  const a10 = coverage.find((c) => c.category === 'A10')!;
  assert.equal(a10.tasks![0]!.status, 'ERROR');
  assert.equal(a10.status, 'ASSESSMENT_FAILED');
});

test('active tasks are NOT_EXECUTED in passive scans', () => {
  const coverage = computeCoverage(
    [eng('builtin.crawler-lite', 'ran'), eng('builtin.http-observation', 'ran')],
    'standard-passive', [], 'webapp', 'passive',
  );
  const a05 = coverage.find((c) => c.category === 'A05')!;
  assert.equal(a05.status, 'MANUAL_REVIEW_REQUIRED',
    'passive webapp scan cannot assess A05; only the by-design manual task applies');
  assert.ok(a05.tasks!.every((t) => t.status === 'MANUAL_REVIEW_REQUIRED'),
    'only manual tasks are required for passive A05');
  const a03 = coverage.find((c) => c.category === 'A03')!;
  assert.equal(a03.status, 'PARTIALLY_COVERED',
    'A03: library-version task executed passively; deployed-SBOM review remains manual');
});

test('active scan with findings: A07 tasks report detection and full execution', () => {
  const coverage = computeCoverage(
    [
      eng('builtin.crawler-lite', 'ran'), eng('builtin.http-observation', 'ran'),
      eng('builtin.path-probe', 'ran'), eng('builtin.reflection-probe', 'ran'), eng('builtin.auth-probe', 'ran'),
    ],
    'standard-active',
    [
      finding('builtin.auth-probe', 'username-enumeration', 'A07'),
      finding('builtin.auth-probe', 'no-login-rate-limit', 'A07'),
    ],
    'webapp', 'active',
  );
  const a07 = coverage.find((c) => c.category === 'A07')!;
  const enumerated = a07.tasks!.filter((t) => t.status === 'FINDING_DETECTED');
  assert.equal(enumerated.length, 2);
  const a05 = coverage.find((c) => c.category === 'A05')!;
  const reflection = a05.tasks!.find((t) => t.taskId === 'A05-T01')!;
  assert.equal(reflection.status, 'AUTOMATED_PASS', 'ran clean without reflections');
});

test('no coverage inflation: v2 verdict never claims more than v1 (backward compatibility)', () => {
  const RANK: Record<string, number> = { 'covered': 2, 'partial': 1, 'manual-only': 0 };
  const engines = [eng('builtin.crawler-lite', 'ran'), eng('builtin.http-observation', 'ran')];
  const v1 = computeCoverageV1(engines, 'quick-passive');
  const v2 = computeCoverage(engines, 'quick-passive', [], 'webapp', 'passive');
  for (const entry of v1) {
    const v2entry = v2.find((c) => c.category === entry.category)!;
    assert.ok(
      RANK[v2entry.verdict]! <= RANK[entry.verdict]!,
      `${entry.category}: v2 verdict ${v2entry.verdict} must not claim more than v1 ${entry.verdict}`,
    );
  }
});

// ---------- SRI (A08 quick win) ----------

test('SRI check: external script without integrity detected; with integrity or same-origin not', async () => {
  const { HttpObservationEngine } = await import('../../src/engines/builtin/httpObservation.ts');
  const engine = new HttpObservationEngine();
  const target = {
    id: 't2', name: 'web', origin: 'http://127.0.0.1:8899', kind: 'webapp' as const,
    approved: true, createdAt: new Date().toISOString(),
  };
  const stubClient = {
    get: async (url: string) => ({ ok: true, status: 200, headers: { 'content-type': 'application/javascript' }, body: '1+1', truncated: false, finalUrl: url, elapsedMs: 1 }),
  };
  const ctx = {
    scanId: 's', target, mode: 'passive' as const, client: stubClient as never, guard: {} as never,
    stats: { sent: 0, blocked: 0 }, signal: new AbortController().signal, workDir: '.', log: () => {},
    crawl: {
      pages: [{
        url: 'http://127.0.0.1:8899/', status: 200, truncated: false, forms: [], links: [],
        headers: { 'content-type': 'text/html' },
        body:
          '<script src="https://cdn.example.com/jquery.js"></script>' +
          '<script src="https://cdn.example.com/ok.js" integrity="sha384-xyz" crossorigin="anonymous"></script>' +
          '<script src="/local.js"></script>' +
          '<script src="https://cdn.example.com/jquery.js"></script>',
      }],
      robots: { disallow: [], fetched: false },
    },
  };
  const res = await engine.run(ctx);
  const sri = res.findings.filter((f) => f.rawId === 'sri-external-script');
  assert.equal(sri.length, 1, 'one unique unshielded external script (deduped, same-origin excluded, integrity excluded)');
  assert.equal(sri[0]!.category, 'A08');
  assert.equal(sri[0]!.cwe, 829);
});
