/**
 * Adapter parsing tests using captured/sample tool outputs — no binaries
 * required. These pin the normalization contract of each adapter.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { SemgrepAdapter } from '../../src/engines/adapters/semgrep.ts';
import { TrivyAdapter } from '../../src/engines/adapters/trivy.ts';
import { GrypeAdapter } from '../../src/engines/adapters/grype.ts';
import { NucleiAdapter } from '../../src/engines/adapters/nuclei.ts';
import { ZapAdapter } from '../../src/engines/adapters/zap.ts';

// ---- semgrep sample (captured shape) ----

const SEMGREP_SAMPLE = {
  results: [
    {
      check_id: 'python.lang.security.audit.md5-used',
      path: 'src/auth.py',
      start: { line: 12, col: 5 },
      end: { line: 12, col: 30 },
      extra: {
        message: 'Detected MD5 hash function\nConsider SHA-256 or a password-specific KDF.',
        severity: 'WARNING',
        lines: 'hashlib.md5(password).hexdigest()',
        metadata: {
          cwe: ['CWE-327: Use of a Broken or Risky Cryptographic Algorithm'],
          owasp: ['A02:2021 - Cryptographic Failures'],
          confidence: 'HIGH',
        },
      },
    },
  ],
  errors: [],
};

test('semgrep parse maps severity/cwe/owasp-tag (2021 → 2025 translation)', () => {
  const findings = SemgrepAdapter.parseReport(SEMGREP_SAMPLE as never);
  assert.equal(findings.length, 1);
  const f = findings[0]!;
  assert.equal(f.rawId, 'python.lang.security.audit.md5-used');
  assert.equal(f.cwe, 327);
  assert.equal(f.category, 'A04', '2021 A02 crypto tag must translate to 2025 A04');
  assert.equal(f.severity, 'medium');
  assert.equal(f.confidence, 'high');
  assert.equal(f.status, 'probable');
  assert.match(f.locator ?? '', /src\/auth\.py:12/);
  assert.match(f.references?.[0] ?? '', /semgrep\.dev/);
});

// ---- trivy sample ----

const TRIVY_SAMPLE = {
  Results: [
    {
      Target: 'package-lock.json',
      Class: 'lang-pkgs',
      Type: 'npm',
      Vulnerabilities: [
        {
          VulnerabilityID: 'CVE-2020-8203',
          PkgName: 'lodash',
          InstalledVersion: '4.17.15',
          FixedVersion: '4.17.19',
          Severity: 'HIGH',
          Title: 'lodash prototype pollution',
          Description: 'Prototype pollution vulnerability in lodash zipObjectDeep.',
          PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2020-8203',
          CweIds: ['CWE-1321'],
        },
      ],
      Misconfigurations: [
        {
          ID: 'AVD-NPM-0001',
          Title: 'Lockfile integrity not verified',
          Severity: 'MEDIUM',
          Description: 'Dependency integrity is not verified.',
          Resolution: 'Use npm ci with lockfile integrity checks.',
          CauseMetadata: { StartLine: 3, EndLine: 3, FilePath: 'package-lock.json' },
        },
      ],
      Secrets: [
        {
          RuleID: 'aws-access-key-id',
          Severity: 'CRITICAL',
          Title: 'AWS Access Key ID',
          Match: 'AKIAIOSFODNN7EXAMPLE',
          StartLine: 10,
          EndLine: 10,
        },
      ],
    },
  ],
};

test('trivy parse maps vulnerability → A03 with CVE and fix version', () => {
  const findings = TrivyAdapter.parseReport(TRIVY_SAMPLE as never);
  const vuln = findings.find((f) => f.rawId === 'CVE-2020-8203')!;
  assert.ok(vuln);
  assert.equal(vuln.category, 'A03');
  assert.equal(vuln.cve, 'CVE-2020-8203');
  assert.equal(vuln.severity, 'high');
  assert.equal(vuln.confidence, 'high');
  assert.equal(vuln.status, 'confirmed');
  const ev = vuln.evidence[0]!;
  assert.equal(ev.kind, 'dependency');
  if (ev.kind === 'dependency') {
    assert.equal(ev.packageName, 'lodash');
    assert.equal(ev.fixedVersion, '4.17.19');
  }
});

test('trivy parse maps misconfig (file+line) and secrets (redacted match)', () => {
  const findings = TrivyAdapter.parseReport(TRIVY_SAMPLE as never);
  const misconf = findings.find((f) => f.rawId === 'AVD-NPM-0001')!;
  assert.ok(misconf);
  assert.equal(misconf.status, 'probable');
  assert.equal(misconf.evidence[0]!.kind, 'file');
  if (misconf.evidence[0]!.kind === 'file') assert.equal(misconf.evidence[0]!.lineStart, 3);

  const secret = findings.find((f) => f.rawId === 'aws-access-key-id')!;
  assert.ok(secret);
  assert.equal(secret.category, 'A07');
  const evText = JSON.stringify(secret.evidence);
  assert.ok(!evText.includes('AKIAIOSFODNN7EXAMPLE'), 'secret match text must be redacted');
  assert.ok(evText.includes('REDACTED'));
});

// ---- grype sample ----

const GRYPE_SAMPLE = {
  matches: [
    {
      vulnerability: {
        id: 'CVE-2021-23337',
        severity: 'High',
        description: 'Command injection in lodash.',
        cvss: [{ metrics: { baseScore: 7.2 } }],
        fix: { versions: ['4.17.21'] },
      },
      artifact: {
        name: 'lodash',
        version: '4.17.15',
        type: 'npm',
        locations: [{ path: 'package-lock.json', line: 10 }],
      },
    },
  ],
};

test('grype parse maps cvss score and fix version', () => {
  const findings = GrypeAdapter.parseReport(GRYPE_SAMPLE as never);
  assert.equal(findings.length, 1);
  const f = findings[0]!;
  assert.equal(f.cve, 'CVE-2021-23337');
  assert.equal(f.severity, 'high', 'cvss 7.2 → high');
  const ev = f.evidence[0]!;
  assert.equal(ev.kind, 'dependency');
  if (ev.kind === 'dependency') assert.equal(ev.fixedVersion, '4.17.21');
});

// ---- nuclei sample ----

const NUCLEI_LINE = JSON.stringify({
  'template-id': 'exposed-git-config',
  info: {
    name: 'Git Config Exposure',
    severity: 'high',
    description: '.git/config file exposed',
    reference: ['https://example.com/ref'],
    classification: { 'cve-id': [], 'cwe-id': ['CWE-538'] },
  },
  host: 'http://127.0.0.1:8899',
  'matched-at': 'http://127.0.0.1:8899/.git/config',
  type: 'http',
});

test('nuclei parseEvents maps JSONL to findings', () => {
  const findings = NucleiAdapter.parseEvents(`${NUCLEI_LINE}\nnot-json\n\n`, 'http://127.0.0.1:8899', 'nuclei -u x');
  assert.equal(findings.length, 1, 'malformed lines skipped');
  const f = findings[0]!;
  assert.equal(f.rawId, 'exposed-git-config');
  assert.equal(f.cwe, 538);
  assert.equal(f.category, 'A01', 'CWE-538 official 2025 mapping');
  assert.equal(f.severity, 'high');
  assert.equal(f.locator, '/.git/config');
  assert.equal(f.evidence[0]!.kind, 'process');
});

// ---- zap sample ----

const ZAP_REPORT = {
  site: 'http://127.0.0.1:8899',
  alerts: [
    {
      pluginid: '10038',
      alert: 'Content Security Policy (CSP) Header Not Set',
      riskcode: '2',
      confidence: '2',
      cweid: '693',
      url: 'http://127.0.0.1:8899/',
      param: '',
      evidence: '',
      description: 'CSP header missing.',
      solution: 'Set a CSP header.',
      reference: 'https://owasp.org/www-project-web-security-testing-guide/',
    },
    {
      pluginid: '10098',
      alert: 'Cross-Domain Misconfiguration',
      riskcode: '1',
      confidence: '1',
      cweid: '942',
      url: 'http://127.0.0.1:8899/api',
      description: 'Permissive CORS.',
      solution: 'Restrict origins.',
    },
    {
      pluginid: '40012',
      alert: 'Cross Site Scripting (Reflected XSS)',
      riskcode: '3',
      confidence: '3',
      cweid: '79',
      url: 'http://127.0.0.1:8899/search',
      param: 'q',
      evidence: '<script>',
      description: 'XSS.',
      solution: 'Encode output.',
    },
  ],
};

test('zap parse maps risk/confidence codes and dedupe-friendly locators', () => {
  const findings = ZapAdapter.parseReport(ZAP_REPORT as never, 'http://127.0.0.1:8899', 'zap -cmd', 0);
  assert.equal(findings.length, 3);
  const csp = findings.find((f) => f.rawId === 'zap-10038')!;
  assert.ok(csp);
  assert.equal(csp.severity, 'medium', 'riskcode 2 → medium');
  assert.equal(csp.confidence, 'medium');
  assert.equal(csp.category, 'A02', 'CWE-693 override');
  assert.equal(csp.locator, '/');

  const xss = findings.find((f) => f.rawId === 'zap-40012')!;
  assert.equal(xss.severity, 'high', 'riskcode 3 → high');
  assert.equal(xss.category, 'A05', 'CWE-79 → injection family');
  assert.match(xss.title, /\[q\]/, 'parameter surfaced in title');
});

test('cross-engine dedupe: builtin + zap CSP alerts on same asset merge', async () => {
  const { dedupeFindings } = await import('../../src/core/ids.ts');
  const { makeFindingId } = await import('../../src/core/ids.ts');
  const { normalizeFinding } = await import('../../src/scan/normalize.ts');
  const target = {
    id: 't', name: 'app', origin: 'http://127.0.0.1:8899', kind: 'webapp' as const,
    approved: true, createdAt: new Date().toISOString(),
  };
  const triages = new Map();
  const builtin = normalizeFinding({
    rawId: 'missing-security-headers', title: 'Missing security headers: Content-Security-Policy',
    category: 'A02', cwe: 693, severity: 'medium', confidence: 'high', status: 'confirmed',
    asset: 'http://127.0.0.1:8899', locator: '/',
    evidence: [], explanation: 'e', remediation: 'r', references: [],
  }, { target, engineId: 'builtin.http-observation', adapter: false, triages });
  const zapRaw = ZapAdapter.parseReport(ZAP_REPORT as never, 'http://127.0.0.1:8899', 'zap -cmd', 0);
  const zap = normalizeFinding(zapRaw.find((f) => f.rawId === 'zap-10038')!, {
    target, engineId: 'adapter.zap', adapter: true, triages,
  });
  // locators must be identical for the fingerprint to merge
  assert.equal(builtin.locator, zap.locator);
  assert.equal(builtin.category, zap.category);
  assert.equal(builtin.cwe, zap.cwe);
  const merged = dedupeFindings([builtin, zap]);
  assert.equal(merged.length, 1, 'same issue from two engines merges');
  const m = merged[0]!;
  assert.equal(m.provenance.length, 2, 'both engines recorded');
  assert.ok(m.provenance.some((p) => p.engine === 'adapter.zap'));
  assert.ok(m.id.startsWith('FND-A02-'));
});
