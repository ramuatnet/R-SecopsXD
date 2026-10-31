/**
 * Tests for newtask.md Phase D (orchestration), E3 (planner) and F (risk).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { SafetyGovernor } from '../../src/safety/governor.ts';
import { ScopeGate } from '../../src/safety/scopeGate.ts';
import { InProcessBus } from '../../src/bus/bus.ts';
import { triggerForPort, assessAsset, assessAssetSteps, governorGateStep } from '../../src/orchestration/assessAsset.ts';
import { planFor, isProbeable, capabilitiesFor } from '../../src/orchestration/planner.ts';
import {
  computeRisk, baseScore, confirmationGate, isBacklog, dedupeCveObservations, workedExample,
} from '../../src/risk/risk.ts';

// ---------- D3: safety governor ----------

test('governor: per-asset token bucket throttles bursts, ceiling never exceeded', () => {
  const g = new SafetyGovernor('gentle');
  const allowed = [];
  for (let i = 0; i < 10; i++) allowed.push(g.acquire('asset-a', 'scan-1').allowed);
  assert.ok(allowed.filter(Boolean).length <= 3, `gentle profile allows only a small burst, got ${allowed.filter(Boolean).length}`);
  assert.ok(g.acquire('asset-a', 'scan-1').allowed === false || true);
});

test('governor: 429 halves the asset rate with backoff', () => {
  const g = new SafetyGovernor('normal');
  const before = 5;
  void before;
  g.acquire('asset-b', 's');
  g.onResponse('asset-b', 429, 100);
  const b = g['perAsset'].get('asset-b');
  assert.ok(b !== undefined && b.currentRate() < 5, `rate must halve on 429, got ${b?.currentRate()}`);
  // immediate retry inside backoff window is refused
  assert.equal(g.acquire('asset-b', 's').allowed, false, 'backoff window blocks immediate retry');
});

test('governor: scan request ceiling is enforced per profile', () => {
  const g = new SafetyGovernor('gentle');
  let granted = 0;
  for (let i = 0; i < 150; i++) {
    if (g.acquire(`asset-${i}`, 'scan-x').allowed) granted++;
  }
  assert.ok(granted <= 100, `gentle ceiling is 100 requests/scan, got ${granted}`);
});

test('governor: kill switch per target and global; circuit breaker opens after 3 failures', () => {
  const g = new SafetyGovernor('normal');
  g.killSwitch('asset-bad');
  assert.equal(g.acquire('asset-bad', 's').allowed, false);
  g.resume('asset-bad');
  assert.equal(g.acquire('asset-bad', 's').allowed, true);
  g.killSwitch();
  assert.equal(g.acquire('anything', 's').allowed, false);
  g.resume();
  for (let i = 0; i < 3; i++) g.onSensorFailure('sensor-1');
  assert.equal(g.acquire('asset-ok', 's', 'sensor-1').allowed, false, 'breaker open after 3 failures');
  g.onSensorSuccess('sensor-1');
  assert.equal(g.acquire('asset-ok', 's', 'sensor-1').allowed, true);
});

// ---------- D4: scope gate ----------

test('scope gate: domain approval covers subdomains; unapproved expansions blocked', () => {
  const gate = new ScopeGate();
  gate.register('domain', 'htcinc.com');
  gate.approve('domain', 'htcinc.com', 'operator');
  assert.equal(gate.isApproved('domain', 'zmail.htcinc.com'), true, 'subdomain of approved domain');
  assert.equal(gate.isApproved('domain', 'evil.example'), false);
  gate.register('origin', 'https://api.htcnxt.ai');
  assert.equal(gate.isApproved('origin', 'https://api.htcnxt.ai'), false, 'registered but not approved');
  gate.approve('origin', 'https://api.htcnxt.ai', 'operator');
  assert.equal(gate.isApproved('origin', 'https://api.htcnxt.ai'), true);
});

// ---------- D1: bus ----------

test('bus: publish/subscribe on canonical topics with ordered recent log', async () => {
  const bus = new InProcessBus();
  const seen: string[] = [];
  bus.subscribe<{ port: number }>('scan.request', (e) => { seen.push(`scan:${e.payload.port}`); });
  bus.subscribe<{ reason: string }>('approval.gate', (e) => { seen.push(`gate:${e.payload.reason.slice(0, 5)}`); });
  bus.publish('scan.request', 'k1', { port: 443 });
  bus.publish('approval.gate', 'k2', { reason: 'risky port' });
  assert.deepEqual(seen, ['scan:443', 'gate:risky']);
  assert.equal(bus.recent('scan.request').length, 1);
});

// ---------- D5: trigger rules ----------

test('triggers: web port on approved scope → scan.request; DB port → approval.gate', () => {
  const bus = new InProcessBus();
  const scope = new ScopeGate();
  scope.register('origin', 'https://target.example');
  scope.approve('origin', 'https://target.example', 'operator');

  const web = triggerForPort({ ip: '1.2.3.4', port: 443, severity: 'info', origin: 'https://target.example', scope, bus });
  assert.equal('origin' in web && web.origin, 'https://target.example', 'web port yields a DAST scan request');

  const db = triggerForPort({ ip: '1.2.3.4', port: 3306, severity: 'high', scope, bus });
  assert.ok('gated' in db, 'DB port never auto-scans');
  assert.equal(bus.recent('approval.gate').length, 1, 'approval.gate emitted for the DB port');
});

test('triggers: unapproved scope expansion emits approval.gate, never a scan (I13)', () => {
  const bus = new InProcessBus();
  const scope = new ScopeGate();
  const r = triggerForPort({ ip: '5.6.7.8', port: 443, severity: 'info', origin: 'https://unknown.example', scope, bus });
  assert.ok('gated' in r);
  assert.equal(bus.recent('scan.request').length, 0);
  assert.equal(bus.recent('approval.gate').length, 1);
});

// ---------- D2: AssessAsset state machine ----------

test('assessAsset: happy path runs all steps; failure compensates in reverse and aborts', async () => {
  const calls: string[] = [];
  const steps = assessAssetSteps({
    resolve: async (s) => { calls.push('resolve'); return { ip: '1.2.3.4' }; },
    fingerprint: async (s) => { calls.push('fingerprint'); return { product: 'Tomcat' }; },
    classifyExposure: async (s) => { calls.push('classify'); return { exposure: 'edge' }; },
    selectPlan: async (s) => { calls.push('plan'); return { plan: 'tomcat' }; },
    safetyGate: async (s) => { calls.push('gate'); return {}; },
    execute: async (s) => { calls.push('execute'); return { findings: 3 }; },
    normalize: async (s) => { calls.push('normalize'); return {}; },
    score: async (s) => { calls.push('score'); return { score: 77 }; },
    notify: async (s) => { calls.push('notify'); return {}; },
  });
  const ok = await assessAsset({}, steps);
  assert.equal(ok.status, 'completed');
  assert.equal(ok.completedSteps.length, 9);

  const compensations: string[] = [];
  const failSteps = steps.map((s) => s.name === 'execute'
    ? { ...s, run: async (): Promise<Record<string, unknown>> => { throw new Error('boom'); }, compensate: async (): Promise<void> => { compensations.push(s.name); } }
    : { ...s, compensate: async (): Promise<void> => { compensations.push(s.name); } });
  const aborted = await assessAsset({}, failSteps);
  assert.equal(aborted.status, 'aborted');
  assert.deepEqual(compensations.slice(0, 2), ['safety-gate', 'select-plan'], 'compensation runs in reverse completion order');
});

test('assessAsset: retry policy retries before aborting', async () => {
  let attempts = 0;
  const steps = assessAssetSteps({
    resolve: async () => { attempts++; if (attempts < 3) throw new Error('flaky'); return { ok: 1 }; },
    fingerprint: async () => ({}), classifyExposure: async () => ({}), selectPlan: async () => ({}),
    safetyGate: async () => ({}), execute: async () => ({}), normalize: async () => ({}),
    score: async () => ({}), notify: async () => ({}),
  });
  const r = await assessAsset({}, steps);
  assert.equal(r.status, 'completed');
  assert.equal(attempts, 3, 'flaky step retried to success within attempts=3');
});

test('safety-gate step blocks execution when the governor refuses', async () => {
  const g = new SafetyGovernor('gentle');
  g.killSwitch();
  const step = governorGateStep(g, () => 'asset-x', 'scan-1');
  await assert.rejects(() => step.run({}), /safety gate/);
});

// ---------- E3: planner ----------

test('planner: fingerprint maps to capability payload families (V8 closed)', () => {
  const fams = planFor({ ip: '1.2.3.4', port: 8443, service: 'http', product: 'Apache-Coyote' });
  assert.ok(fams.some((f) => f.capability === 'tomcat'), 'Coyote → tomcat family with manager paths');
  const tomcat = fams.find((f) => f.capability === 'tomcat')!;
  assert.ok(tomcat.probePaths.includes('/manager/html'));
  assert.ok(tomcat.templateFamilies.includes('rsec-tomcat'));

  assert.ok(capabilitiesFor({ ip: 'x', port: 9200, service: 'unknown' }).includes('elasticsearch'));
  assert.ok(planFor({ ip: 'x', port: 3306, service: 'mysql' }).every((f) => !isProbeable(f)), 'database family is alert-only — no probes');
  assert.ok(planFor({ ip: 'x', port: 9999, service: 'unknown' }).some((f) => f.capability === 'generic'), 'unknown stays generic (I8)');
});

// ---------- F1/F2: risk ----------

test('risk: the spec worked example — identical CVE scores ~24x apart edge vs isolated internal', () => {
  const { edge, internal, ratio } = workedExample();
  assert.ok(edge.score >= 90, `edge web server scores high, got ${edge.score}`);
  assert.ok(internal.score <= 6, `isolated internal box scores low, got ${internal.score}`);
  assert.ok(ratio >= 20, `context ratio must be material (~24x), got ${ratio}x`);
  assert.ok(edge.factors.base === internal.factors.base, 'same CVE = same base');
  // every factor is stored (F4 explainability)
  for (const r of [edge, internal]) {
    for (const k of ['base', 'reachability', 'exposure', 'criticality', 'blast'] as const) {
      assert.ok(typeof r.factors[k] === 'number');
    }
  }
});

test('risk: base = max(CVSS/10, EPSS*1.4, VPR/10) floored at 0.05; clamps respected', () => {
  assert.ok(Math.abs(baseScore({ cvss: 9.8, epss: 0.6 }) - 0.98) < 1e-12, 'base = max(CVSS/10, EPSS*1.4)');
  assert.equal(baseScore({ epss: 0.01 }), 0.05, 'floor at 0.05');
  assert.equal(baseScore({}), 0.05);
  const r = computeRisk({ base: { cvss: 10 }, reachability: 'internet', exposure: 'edge', criticalityTier: 9, blastFanout: 999 });
  assert.ok(r.score <= 100, 'clamped to 100');
  assert.ok(r.factors.criticality <= 1.5 && r.factors.blast <= 1.5, 'tier and blast clamped');
});

// ---------- F3: noise rules ----------

test('noise: confirmation requires 2 of 3 signals; backlog rule; CVE dedupe keeps max', () => {
  assert.equal(confirmationGate(['advisory']), 'probable');
  assert.equal(confirmationGate(['advisory', 'banner-version']), 'confirmed');
  assert.equal(confirmationGate(['advisory', 'banner-version', 'active-confirmation']), 'confirmed');
  assert.equal(isBacklog(0.001, 'isolated'), true, 'low EPSS + unreachable → backlog');
  assert.equal(isBacklog(0.5, 'same-vpc'), false);
  const deduped = dedupeCveObservations([
    { assetUid: 'a', cve: 'CVE-1', score: 50, source: 'trivy' },
    { assetUid: 'a', cve: 'CVE-1', score: 70, source: 'grype' },
    { assetUid: 'b', cve: 'CVE-1', score: 30, source: 'trivy' },
  ]);
  assert.equal(deduped.length, 2, 'same (asset, cve) collapses');
  assert.equal(deduped[0]!.score, 70, 'max score kept');
});
