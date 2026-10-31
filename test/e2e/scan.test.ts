/**
 * End-to-end ground-truth tests.
 *
 * Spawns the vulnerable and hardened fixture apps, scans them through the
 * real orchestrator, and asserts detection against fixtures/vuln-app/truth.json
 * (recall), absence of findings on the hardened twin (precision), stable IDs
 * across rescans, and source-mode detection against PLANTED.md.
 *
 * External SCA (grype) runs for real when installed; otherwise the test is
 * skipped with a visible reason (AC15 requires the capability, not a
 * specific binary).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { buildPlatform, type Platform } from '../../src/server.ts';
import type { Config } from '../../src/config.ts';
import type { Finding, Scan } from '../../src/core/types.ts';

const ROOT = join(import.meta.dirname, '..', '..');
const VULN_PORT = 8899;
const CLEAN_PORT = 8898;
const VULN_ORIGIN = `http://127.0.0.1:${VULN_PORT}`;
const CLEAN_ORIGIN = `http://127.0.0.1:${CLEAN_PORT}`;

let platform: Platform;
let dir: string;
const children: ChildProcess[] = [];

async function startFixture(script: string, port: number): Promise<void> {
  const child = spawn(process.execPath, [script], {
    env: { ...process.env, PORT: String(port) },
    stdio: 'ignore',
  });
  children.push(child);
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/`);
      if (res.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`fixture on port ${port} did not start`);
}

function testConfig(): Config {
  return {
    host: '127.0.0.1', port: 0, dataDir: dir, token: undefined,
    allowPublicTargets: false, rateLimitPerSecond: 100, rateBurst: 50,
    maxConcurrency: 8, maxConcurrentScans: 2, requestTimeoutMs: 5000,
    engineTimeoutMs: 60_000, scanProfile: 'aggressive' as const, scanTimeoutMs: 120_000, maxCrawlPages: 10, maxCrawlPagesExplicit: false, loopEnabled: false, loopMaxIterations: 40, loopMaxRequests: 800, loopMaxMs: 600000, loopSeed: 0, loopSubscanFanout: 3,
    logLevel: 'error',
  };
}

async function scanTarget(origin: string, profile: string, mode: 'passive' | 'active', name: string): Promise<{ scan: Scan; findings: Finding[] }> {
  const target = platform.db.createTarget({ name, origin, kind: 'webapp', approved: false });
  platform.db.approveTarget(target.id, 'e2e');
  const scan = await platform.orchestrator.startScan(target.id, profile, mode);
  const final = await waitForScan(scan.id);
  const findings = platform.db.getFindings(scan.id);
  assert.equal(final.status, 'completed', `scan failed: ${final.error ?? ''}`);
  return { scan: final, findings };
}

async function waitForScan(scanId: string, timeoutMs = 90_000): Promise<Scan> {
  const start = Date.now();
  for (;;) {
    const scan = platform.db.getScan(scanId);
    if (scan && !['queued', 'running'].includes(scan.status)) return scan;
    if (Date.now() - start > timeoutMs) throw new Error(`scan ${scanId} timeout`);
    await new Promise((r) => setTimeout(r, 200));
  }
}

/** Truth matcher: does any finding satisfy the truth item? */
function matchTruth(item: { match: { cwe?: number; locatorContains?: string; titleContains?: string }; category: string }, findings: Finding[]): Finding | undefined {
  return findings.find((f) => {
    if (f.category !== item.category) return false;
    if (item.match.cwe !== undefined && f.cwe !== item.match.cwe) return false;
    if (item.match.locatorContains !== undefined && !f.locator.includes(item.match.locatorContains)) return false;
    if (item.match.titleContains !== undefined && !f.title.toLowerCase().includes(item.match.titleContains.toLowerCase())) return false;
    return true;
  });
}

interface TruthFile {
  items: Array<{ id: string; name: string; category: string; mode: 'passive' | 'active'; match: { cwe?: number; locatorContains?: string; titleContains?: string } }>;
}

test.before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'ovap-e2e-'));
  platform = buildPlatform(testConfig());
  await startFixture(join(ROOT, 'fixtures', 'vuln-app', 'server.cjs'), VULN_PORT);
  await startFixture(join(ROOT, 'fixtures', 'hardened-app', 'server.cjs'), CLEAN_PORT);
});

test.after(() => {
  for (const c of children) c.kill();
  platform.db.close();
  rmSync(dir, { recursive: true, force: true });
});

const truth: TruthFile = JSON.parse(readFileSync(join(ROOT, 'fixtures', 'vuln-app', 'truth.json'), 'utf8')) as TruthFile;

// ---------------- passive recall (AC11) ----------------

test('passive scan detects all passive ground-truth items (AC11)', async () => {
  const { findings } = await scanTarget(VULN_ORIGIN, 'quick-passive', 'passive', 'vuln-app');
  const passiveItems = truth.items.filter((i) => i.mode === 'passive');
  const missed: string[] = [];
  for (const item of passiveItems) {
    const hit = matchTruth(item, findings);
    if (!hit) missed.push(`${item.id} (${item.name})`);
  }
  assert.deepEqual(missed, [], `passive detection misses: ${missed.join('; ')}`);
});

// ---------------- active recall (AC12) ----------------

let activeScanId = '';
let activeFindings: Finding[] = [];

test('active scan detects all active ground-truth items (AC12)', async () => {
  const { scan, findings } = await scanTarget(VULN_ORIGIN, 'standard-active', 'active', 'vuln-app');
  activeScanId = scan.id;
  activeFindings = findings;
  const activeItems = truth.items.filter((i) => i.mode === 'active');
  const missed: string[] = [];
  for (const item of activeItems) {
    const hit = matchTruth(item, findings);
    if (!hit) missed.push(`${item.id} (${item.name})`);
  }
  assert.deepEqual(missed, [], `active detection misses: ${missed.join('; ')}`);
});

test('active engines report as ran; passive rerun skipped marker for active engines', async () => {
  const scan = activeScanId ? platform.db.getScan(activeScanId)! : undefined;
  assert.ok(scan);
  const ran = scan.engines.filter((e) => e.status === 'ran').map((e) => e.engine);
  for (const expected of ['builtin.crawler-lite', 'builtin.http-observation', 'builtin.path-probe', 'builtin.reflection-probe', 'builtin.auth-probe']) {
    assert.ok(ran.includes(expected), `${expected} should have run in active mode`);
  }
});

// ---------------- finding model invariants (AC16, AC17) ----------------

test('every finding carries the complete model (AC16)', () => {
  for (const f of activeFindings) {
    assert.match(f.id, /^FND-A\d\d-[A-Z2-9]{10}$/, `stable id format for ${f.title}`);
    assert.ok(f.fingerprint.length === 64);
    assert.ok(f.title.length > 5);
    assert.ok(f.evidence.length > 0, `evidence required for ${f.title}`);
    assert.ok(f.explanation.length > 30);
    assert.ok(f.remediation.length > 20);
    assert.ok(f.detectedAt);
    assert.ok(f.provenance.length > 0 && f.provenance[0]!.engine);
    // A2 added an audit-backed verification stage: rejected seeds read false_positive.
    assert.ok(['confirmed', 'probable', 'informational', 'false_positive'].includes(f.status));
  }
});

test('rescan keeps stable IDs for the same issues (AC17)', async () => {
  const { findings: first } = await scanTarget(VULN_ORIGIN, 'quick-passive', 'passive', 'vuln-app-stable');
  const { findings: second } = await scanTarget(VULN_ORIGIN, 'quick-passive', 'passive', 'vuln-app-stable-2');
  const firstIds = new Set(first.map((f) => f.id));
  for (const f of second) {
    assert.ok(firstIds.has(f.id), `finding ${f.title} changed ID across rescans`);
  }
});

// ---------------- precision on hardened twin (AC13) ----------------

test('hardened twin produces no confirmed medium+ findings (AC13)', async () => {
  const passive = await scanTarget(CLEAN_ORIGIN, 'quick-passive', 'passive', 'hardened-app');
  const active = await scanTarget(CLEAN_ORIGIN, 'standard-active', 'active', 'hardened-app');
  const offenders = [...passive.findings, ...active.findings].filter(
    (f) => f.status === 'confirmed' && ['critical', 'high', 'medium'].includes(f.severity),
  );
  assert.deepEqual(offenders.map((f) => `${f.title} [${f.severity}/${f.status}]`), [],
    'hardened app must not yield confirmed medium+ findings');
});

// ---------------- coverage honesty (AC21) ----------------

test('scan coverage marks manual-only categories and never full automation claims (AC21)', async () => {
  const { scan } = await scanTarget(VULN_ORIGIN, 'quick-passive', 'passive', 'vuln-app-cov');
  assert.equal(scan.coverage.length, 10);
  const manualOnly = scan.coverage.filter((c) => c.verdict === 'manual-only').map((c) => c.category);
  // Post-automation-program expectations for a PASSIVE webapp scan:
  // - A05 remains manual-only (no passive automated tasks for webapps)
  // - A03 gained strong passive coverage (library version fingerprinting) but the
  //   deployed-SBOM review keeps it partial; A07 heuristic (bundle secrets) likewise.
  assert.ok(manualOnly.includes('A05'), 'A05 must be manual-only in passive webapp scans');
  const byCat = new Map(scan.coverage.map((c) => [c.category, c]));
  const a03 = byCat.get('A03')!;
  assert.equal(a03.status, 'PARTIALLY_COVERED', 'A03 partial: lib versions automated, SBOM manual');
  for (const cat of ['A06', 'A07', 'A09'] as const) {
    const c = byCat.get(cat)!;
    assert.ok(['PARTIALLY_COVERED', 'MANUAL_REVIEW_REQUIRED'].includes(c.status ?? ''),
      `${cat} must stay below COVERED_WITH_EVIDENCE (manual core remains)`);
  }
  for (const cat of ['A01', 'A02', 'A08'] as const) {
    const c = byCat.get(cat)!;
    assert.ok(['PARTIALLY_COVERED', 'COVERED_WITH_EVIDENCE', 'MANUAL_REVIEW_REQUIRED'].includes(c.status ?? ''));
  }
  for (const c of scan.coverage) {
    assert.ok(c.note.length > 40, 'coverage notes must carry honest limitation text');
    assert.ok(!/fully detect|complete coverage/i.test(c.note));
    assert.ok(Array.isArray(c.tasks) && c.tasks.length > 0, 'every category must expose its task-level evidence');
  }
});

// ---------------- source review mode (AC14) ----------------

test('source review detects all planted source issues (AC14)', async () => {
  const target = platform.db.createTarget({
    name: 'source-project', origin: '', kind: 'source',
    sourcePath: join(ROOT, 'fixtures', 'source-project'), approved: false,
  });
  platform.db.approveTarget(target.id, 'e2e');
  const scan = await platform.orchestrator.startScan(target.id, 'source-review', 'passive');
  const final = await waitForScan(scan.id);
  assert.equal(final.status, 'completed');
  const findings = platform.db.getFindings(scan.id);

  const byRule = new Map<string, Finding[]>();
  for (const f of findings) {
    const rule = f.provenance[0]?.rawId ?? '';
    byRule.set(rule, [...(byRule.get(rule) ?? []), f]);
  }
  const sql = byRule.get('sql-concatenation');
  assert.ok(sql && sql.length === 1, 'SP-1 sql concatenation');
  assert.equal(sql![0]!.category, 'A05');
  assert.match(sql![0]!.evidence[0]!.kind === 'file' ? sql![0]!.evidence[0]!.path : '', /users\.js$/);

  const cred = byRule.get('hardcoded-credential');
  assert.ok(cred && cred.length === 1, 'SP-2 hardcoded credential');
  assert.equal(cred![0]!.category, 'A07');

  assert.ok(byRule.get('weak-hash-md5-sha1'), 'SP-3 weak hash');
  assert.ok(byRule.get('tls-verification-disabled'), 'SP-4 TLS verification disabled');

  const inventory = findings.find((f) => f.provenance[0]?.rawId === 'dependency-inventory');
  assert.ok(inventory, 'dependency inventory present');
  assert.equal(inventory!.status, 'informational');
});

// ---------------- SCA adapter against real tool (AC15) ----------------

test('grype/SCA findings appear in the source-review scan when the tool is available (AC15)', async () => {
  // Reuse the latest source-project scan: the source-review profile includes
  // adapter.grype. A dedicated grype run would re-check its (large) DB.
  let target = platform.db.listTargets().find((t) => t.name === 'source-project');
  if (!target) {
    target = platform.db.createTarget({
      name: 'source-project', origin: '', kind: 'source',
      sourcePath: join(ROOT, 'fixtures', 'source-project'), approved: false,
    });
    platform.db.approveTarget(target.id, 'e2e');
    const started = await platform.orchestrator.startScan(target.id, 'source-review', 'passive');
    await waitForScan(started.id);
  }
  const scan = platform.db.latestCompletedScanForTarget(target.id)!;
  const grypeRun = scan.engines.find((e) => e.engine === 'adapter.grype');

  if (!grypeRun || grypeRun.status !== 'ran') {
    const detail = grypeRun?.detail ?? 'engine not present';
    console.log(`SKIP evidence: grype did not run — status=${grypeRun?.status ?? 'absent'} detail=${detail}`);
    return; // visible skip, not a silent pass
  }

  const findings = platform.db.getFindings(scan.id).filter((f) => f.engine === 'adapter.grype' || f.provenance.some((p) => p.engine === 'adapter.grype'));
  assert.ok(grypeRun.findingCount > 0, 'grype ran but produced no findings');
  const lodash = findings.find((f) => f.locator === 'lodash@4.17.15');
  assert.ok(lodash, 'lodash 4.17.15 must be flagged with a CVE');
  assert.equal(lodash.category, 'A03');
  assert.ok(lodash.cve?.startsWith('CVE-') || lodash.provenance[0]?.rawId?.startsWith('GHSA-'), `CVE/GHSA id present: cve=${lodash.cve} rawId=${lodash.provenance[0]?.rawId}`);
  assert.ok(findings.some((f) => f.locator === 'minimist@1.2.0'), 'minimist flagged');
  assert.ok(findings.some((f) => f.locator === 'node-fetch@2.6.0'), 'node-fetch flagged');
});
